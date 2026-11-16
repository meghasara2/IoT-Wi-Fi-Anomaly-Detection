"""
Cloud Synchronization Worker Daemon.
File: src/cloud_sync_worker.py

Purpose:
  Background synchronization worker that continuously drains the durable
  local SQLite outbox (cloud_sync_outbox) and asynchronously delivers
  telemetry to Supabase PostgreSQL via the connection pooler.

Operational Principles:
  1. Non-Blocking: Runs in an isolated background thread or independent process.
  2. Crash Resilience: Handles pooler disconnects, timeouts, and transaction failures cleanly.
  3. Strict PoLP: Uses the dedicated 'iot_collector' login via PostgreSQL pooler.
     The collector password is used EXCLUSIVELY as a PostgreSQL password.
  4. Idempotency & Immutability:
     - Mutable tables (collector_status, device_registry, unknown_device_obs): ON CONFLICT DO UPDATE.
     - Immutable tables (traffic windows, alerts, sensors, attacks): ON CONFLICT DO NOTHING.
  5. Foreign-Key Dependency Ordering: Parent records are always inserted before dependent records
     (collector_status -> live_traffic_windows -> live_alerts / live_attack_events).
  6. Pluggable Transport: Supports both live PostgreSQL pooler transport and mock transports for tests.
  7. Zero Secret Logging: Passwords and sensitive DSNs are NEVER logged or exposed.
"""

import datetime
import json
import logging
import os
import sqlite3
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

_HERE = Path(__file__).resolve().parent
_PROJECT_ROOT = _HERE.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

try:
    from dotenv import load_dotenv
    _env_path = _PROJECT_ROOT / ".env"
    if _env_path.exists():
        load_dotenv(dotenv_path=_env_path)
    else:
        load_dotenv()
except ImportError:
    pass

try:
    import psycopg2
    from psycopg2 import extras
    PSYCOPG2_AVAILABLE = True
except ImportError:
    psycopg2 = None
    extras = None
    PSYCOPG2_AVAILABLE = False

try:
    from src.cloud_sync_outbox import (
        OutboxPriority,
        OutboxStatus,
        enforce_queue_capacity,
        fetch_pending_batch,
        get_outbox_metrics,
        init_outbox_schema,
        mark_delivered,
        mark_in_flight,
        mark_retry_failed,
        prune_delivered,
        recover_stale_in_flight,
    )
except ModuleNotFoundError:
    from cloud_sync_outbox import (
        OutboxPriority,
        OutboxStatus,
        enforce_queue_capacity,
        fetch_pending_batch,
        get_outbox_metrics,
        init_outbox_schema,
        mark_delivered,
        mark_in_flight,
        mark_retry_failed,
        prune_delivered,
        recover_stale_in_flight,
    )

logger = logging.getLogger("CloudSyncWorker")

# Strict Foreign-Key Dependency Order: Parents precede children
TABLE_DEPENDENCY_ORDER: List[str] = [
    "collector_status",        # Level 0 parent: run_id
    "device_registry",        # Level 0 parent: mac_address
    "station_pseudonym_map",  # Level 0 parent: mac_address
    "live_traffic_windows",   # Level 1: depends on collector_status(run_id); parent of alerts/attacks (window_id)
    "unknown_device_obs",     # Level 1: depends on collector_status(run_id)
    "live_sensor_telemetry",  # Level 1: depends on collector_status(run_id)
    "live_pir_events",        # Level 1: depends on collector_status(run_id)
    "live_alerts",            # Level 2: depends on live_traffic_windows(window_id), collector_status(run_id)
    "live_attack_events",     # Level 2: depends on collector_status(run_id), live_traffic_windows(window_id)
]

# Legacy PostgREST HTTP compatibility config (used by mock test harnesses)
TABLE_CONFLICT_CONFIG: Dict[str, Dict[str, str]] = {
    "collector_status": {"on_conflict": "run_id", "prefer": "resolution=merge-duplicates"},
    "device_registry": {"on_conflict": "mac_address", "prefer": "resolution=merge-duplicates"},
    "unknown_device_obs": {"on_conflict": "run_id,observed_mac", "prefer": "resolution=merge-duplicates"},
    "live_traffic_windows": {"on_conflict": "run_id,client_mac,bin_start_epoch", "prefer": "resolution=ignore-duplicates"},
    "live_alerts": {"on_conflict": "window_id", "prefer": "resolution=ignore-duplicates"},
    "live_sensor_telemetry": {"on_conflict": "run_id,physical_node_id,sequence_num", "prefer": "resolution=ignore-duplicates"},
    "live_pir_events": {"on_conflict": "run_id,physical_node_id,sequence_num", "prefer": "resolution=ignore-duplicates"},
    "live_attack_events": {"on_conflict": "event_uuid", "prefer": "resolution=ignore-duplicates"},
    "station_pseudonym_map": {"on_conflict": "mac_address", "prefer": "resolution=ignore-duplicates"},
}


class DefaultNoneDict(dict):
    """Dictionary that returns None for missing keys, safely mapping to PostgreSQL NULL."""
    def __missing__(self, key):
        return None


class CloudSyncWorker:
    """
    Background worker that reliably synchronizes queued telemetry from
    the local SQLite outbox to Supabase Cloud via PostgreSQL connection pooler.
    """

    def __init__(
        self,
        db_path: Path,
        pooler_host: Optional[str] = None,
        pooler_port: Optional[int] = None,
        db_name: Optional[str] = None,
        collector_user: Optional[str] = None,
        collector_password: Optional[str] = None,
        sslmode: Optional[str] = None,
        batch_size: int = 50,
        poll_interval_sec: float = 1.0,
        db_timeout_sec: float = 10.0,
        db_transport: Optional[Callable[[str, List[Dict[str, Any]]], Tuple[bool, str]]] = None,
        # Legacy PostgREST arguments (supported for backward-compatible test harnesses):
        supabase_url: Optional[str] = None,
        supabase_key: Optional[str] = None,
        http_transport: Optional[Any] = None,
    ):
        self.db_path = Path(db_path)
        
        # PostgreSQL Pooler Settings
        self.pooler_host = (
            pooler_host
            or os.getenv("SUPABASE_POOLER_HOST")
            or os.getenv("COLLECTOR_DB_HOST")
            or "aws-1-ap-south-1.pooler.supabase.com"
        )
        self.pooler_port = int(
            pooler_port
            or os.getenv("SUPABASE_POOLER_PORT")
            or os.getenv("COLLECTOR_DB_PORT")
            or 5432
        )
        self.db_name = (
            db_name
            or os.getenv("SUPABASE_DB_NAME")
            or os.getenv("COLLECTOR_DB_NAME")
            or "postgres"
        )
        self.collector_user = (
            collector_user
            or os.getenv("SUPABASE_COLLECTOR_USER")
            or os.getenv("COLLECTOR_DB_USER")
            or "iot_collector.cwqumhtzeiqrfhlesksw"
        )
        if supabase_url == "" and supabase_key == "" and collector_password is None and collector_user is None:
            self.collector_password = ""
        else:
            self.collector_password = (
                collector_password
                or os.getenv("SUPABASE_COLLECTOR_PASSWORD")
                or os.getenv("COLLECTOR_DB_PASSWORD")
                or ""
            )
        self.sslmode = sslmode or os.getenv("SUPABASE_SSLMODE", "require")
        
        self.batch_size = batch_size
        self.poll_interval_sec = poll_interval_sec
        self.db_timeout_sec = db_timeout_sec
        
        # Pluggable Transports
        self.db_transport = db_transport
        self.http_transport = http_transport
        self.supabase_url = (supabase_url or os.getenv("SUPABASE_URL", "")).rstrip("/")
        self.supabase_key = supabase_key or os.getenv("SUPABASE_COLLECTOR_KEY", "")

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Diagnostic state
        self.total_delivered = 0
        self.total_failures = 0
        self.consecutive_failures = 0
        self.last_sync_time: Optional[float] = None
        self.last_error: Optional[str] = None
        self.is_connected = False

    def is_configured(self) -> bool:
        """Returns True if valid database or test transport credentials are present."""
        if self.db_transport is not None or self.http_transport is not None:
            return True
        return bool(self.pooler_host and self.collector_user and self.collector_password)

    def _get_connection(self) -> sqlite3.Connection:
        """Opens a local SQLite connection configured with WAL and timeout."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        return conn

    def _get_pg_connection(self):
        """
        Opens a live connection to the Supabase PostgreSQL pooler using psycopg2.
        Credentials are never logged.
        """
        if not PSYCOPG2_AVAILABLE:
            raise RuntimeError("psycopg2 is not installed. Please install psycopg2-binary.")
        
        # Avoid logging passwords; safe connection logging
        logger.debug(
            f"Connecting to PostgreSQL pooler: host={self.pooler_host} "
            f"port={self.pooler_port} db={self.db_name} user={self.collector_user}"
        )
        
        return psycopg2.connect(
            host=self.pooler_host,
            port=self.pooler_port,
            dbname=self.db_name,
            user=self.collector_user,
            password=self.collector_password,
            sslmode=self.sslmode,
            connect_timeout=int(self.db_timeout_sec),
        )

    def start(self) -> None:
        """Starts the background worker thread."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="CloudSyncWorkerThread",
            daemon=True,
        )
        self._thread.start()
        logger.info("CloudSyncWorker started in background thread.")

    def stop(self, timeout_sec: float = 5.0) -> None:
        """Signals the worker to stop and waits for the thread to exit."""
        self._stop_event.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=timeout_sec)
        logger.info("CloudSyncWorker stopped.")

    def sync_once(self) -> int:
        """
        Executes a single synchronization cycle.
        Returns the number of records delivered in this cycle.
        Preserves strict foreign key dependency ordering across tables.
        """
        if not self.is_configured():
            return 0

        conn = self._get_connection()
        try:
            init_outbox_schema(conn)
            # 1. Recover stale in-flight records on startup
            recover_stale_in_flight(conn, timeout_sec=120.0)

            # 2. Fetch highest-priority pending batch
            batch = fetch_pending_batch(conn, limit=self.batch_size)
            if not batch:
                return 0

            # 3. Mark items IN_FLIGHT
            outbox_ids = [item["outbox_id"] for item in batch]
            mark_in_flight(conn, outbox_ids)

            # 4. Group by table_name
            by_table: Dict[str, List[Dict[str, Any]]] = {}
            for item in batch:
                t = item["table_name"]
                by_table.setdefault(t, []).append(item)

            # 5. Sort tables strictly by foreign-key dependency order
            # (Parents: collector_status -> windows -> children: alerts, attacks)
            sorted_table_names = sorted(
                by_table.keys(),
                key=lambda t: TABLE_DEPENDENCY_ORDER.index(t) if t in TABLE_DEPENDENCY_ORDER else 999
            )

            delivered_count = 0
            for table_name in sorted_table_names:
                items = by_table[table_name]
                item_ids = [it["outbox_id"] for it in items]
                
                success, error_msg = self._transmit_table_batch(table_name, items)
                if success:
                    mark_delivered(conn, item_ids)
                    delivered_count += len(item_ids)
                    self.consecutive_failures = 0
                    self.is_connected = True
                    self.last_sync_time = time.time()
                else:
                    self.total_failures += len(item_ids)
                    self.consecutive_failures += 1
                    self.is_connected = False
                    self.last_error = error_msg
                    for it_id in item_ids:
                        mark_retry_failed(conn, it_id, error_msg)

            self.total_delivered += delivered_count

            # 6. Housekeeping: enforce bounds & prune delivered records
            enforce_queue_capacity(conn, max_capacity=5000)
            prune_delivered(conn, retention_sec=86400.0)

            return delivered_count
        finally:
            conn.close()

    def _transmit_table_batch(
        self, table_name: str, items: List[Dict[str, Any]]
    ) -> Tuple[bool, str]:
        """
        Transmits a batch of records destined for a single table.
        Routes to mock test transport if configured, else executes parameterized
        PostgreSQL statements via the connection pooler.
        """
        # 1. Custom / Mock DB Transport for unit tests
        if self.db_transport is not None:
            return self.db_transport(table_name, items)

        # 2. Legacy Mock HTTP Transport adapter (for existing PostgREST test mocks)
        if self.http_transport is not None:
            return self._transmit_via_http_transport(table_name, items)

        # 3. Live PostgreSQL Pooler Transport
        return self._transmit_via_postgres(table_name, items)

    def _transmit_via_postgres(
        self, table_name: str, items: List[Dict[str, Any]]
    ) -> Tuple[bool, str]:
        """
        Executes parameterized INSERT ... ON CONFLICT statements over PostgreSQL driver.
        - Mutable tables use ON CONFLICT DO UPDATE.
        - Immutable evidence tables use ON CONFLICT DO NOTHING.
        """
        if not PSYCOPG2_AVAILABLE:
            return False, "psycopg2 driver unavailable"

        query_sql = self._build_sql_for_table(table_name)
        if not query_sql:
            return False, f"Unsupported table destination: {table_name}"

        try:
            with self._get_pg_connection() as pg_conn:
                with pg_conn.cursor() as cur:
                    for item in items:
                        payload = DefaultNoneDict(dict(item["payload"]))
                        # Guarantee valid captured_at for sensor telemetry and PIR events
                        if table_name in ("live_sensor_telemetry", "live_pir_events"):
                            if not payload.get("captured_at"):
                                epoch = payload.get("sensor_epoch")
                                if epoch is not None and isinstance(epoch, (int, float)) and epoch > 0:
                                    payload["captured_at"] = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc).isoformat()
                                else:
                                    payload["captured_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

                        # Adapt JSON fields for PostgreSQL jsonb
                        if "evidence_json" in payload and payload["evidence_json"] is not None:
                            ev = payload["evidence_json"]
                            if isinstance(ev, (dict, list)):
                                payload["evidence_json"] = json.dumps(ev)
                        if "missing_fields_json" in payload and payload["missing_fields_json"] is not None:
                            mf = payload["missing_fields_json"]
                            if isinstance(mf, (dict, list)):
                                payload["missing_fields_json"] = json.dumps(mf)
                        
                        cur.execute(query_sql, payload)
                pg_conn.commit()
            return True, ""

        except psycopg2.IntegrityError as e:
            # Foreign key or unique violation - child records can retry on next cycle
            err_msg = f"PostgreSQL IntegrityError (Constraint/FK): {str(e)[:300]}"
            logger.warning(err_msg)
            return False, err_msg
        except psycopg2.OperationalError as e:
            # Pooler disconnect, timeout, or authentication failure
            err_msg = f"PostgreSQL OperationalError (Pooler/Connection): {str(e)[:300]}"
            logger.warning(err_msg)
            return False, err_msg
        except Exception as e:
            err_msg = f"PostgreSQL Transmission Error: {str(e)[:300]}"
            logger.error(err_msg, exc_info=True)
            return False, err_msg

    def _build_sql_for_table(self, table_name: str) -> Optional[str]:
        """
        Returns the parameterized SQL statement with exact ON CONFLICT semantics
        matching the PostgreSQL schema and role permissions.
        """
        if table_name == "collector_status":
            return """
            INSERT INTO collector_status (
                run_id, started_at, last_heartbeat, interface_index, interface_name, serial_port,
                status, stop_reason, packets_parsed, windows_emitted, sensor_records
            ) VALUES (
                %(run_id)s, %(started_at)s, %(last_heartbeat)s, %(interface_index)s, %(interface_name)s, %(serial_port)s,
                %(status)s, %(stop_reason)s, %(packets_parsed)s, %(windows_emitted)s, %(sensor_records)s
            )
            ON CONFLICT (run_id) DO UPDATE SET
                last_heartbeat = EXCLUDED.last_heartbeat,
                interface_index = COALESCE(EXCLUDED.interface_index, collector_status.interface_index),
                interface_name = COALESCE(EXCLUDED.interface_name, collector_status.interface_name),
                serial_port = COALESCE(EXCLUDED.serial_port, collector_status.serial_port),
                status = EXCLUDED.status,
                stop_reason = EXCLUDED.stop_reason,
                packets_parsed = EXCLUDED.packets_parsed,
                windows_emitted = EXCLUDED.windows_emitted,
                sensor_records = EXCLUDED.sensor_records,
                updated_at = clock_timestamp();
            """

        elif table_name == "device_registry":
            return """
            INSERT INTO device_registry (
                mac_address, node_id, device_type, label, last_seen, notes
            ) VALUES (
                %(mac_address)s, %(node_id)s, %(device_type)s, %(label)s, %(last_seen)s, %(notes)s
            )
            ON CONFLICT (mac_address) DO UPDATE SET
                node_id = EXCLUDED.node_id,
                device_type = EXCLUDED.device_type,
                label = EXCLUDED.label,
                last_seen = EXCLUDED.last_seen,
                notes = COALESCE(EXCLUDED.notes, device_registry.notes);
            """

        elif table_name == "unknown_device_obs":
            return """
            INSERT INTO unknown_device_obs (
                run_id, observed_mac, first_seen_utc, last_seen_utc, observation_count, acknowledged
            ) VALUES (
                %(run_id)s, %(observed_mac)s, %(first_seen_utc)s, %(last_seen_utc)s,
                %(observation_count)s, %(acknowledged)s
            )
            ON CONFLICT (run_id, observed_mac) DO UPDATE SET
                last_seen_utc = EXCLUDED.last_seen_utc,
                observation_count = EXCLUDED.observation_count;
            """

        elif table_name == "station_pseudonym_map":
            return """
            INSERT INTO station_pseudonym_map (
                mac_address, pseudonym_id
            ) VALUES (
                %(mac_address)s, %(pseudonym_id)s
            )
            ON CONFLICT (mac_address) DO NOTHING;
            """

        elif table_name == "live_traffic_windows":
            return """
            INSERT INTO live_traffic_windows (
                window_id, run_id, client_mac, node_id, node_type, data_label,
                bin_start_epoch, bin_end_epoch, window_center_epoch,
                window_start_utc, window_end_utc, packet_count,
                mean_IAT, IAT_std, packet_rate, mean_packet_size, packet_size_std,
                score_primary, pred_primary, score_timing, pred_timing, timing_status,
                pred_dual, dual_reason
            ) VALUES (
                %(window_id)s, %(run_id)s, %(client_mac)s, %(node_id)s, %(node_type)s, %(data_label)s,
                %(bin_start_epoch)s, %(bin_end_epoch)s, %(window_center_epoch)s,
                %(window_start_utc)s, %(window_end_utc)s, %(packet_count)s,
                %(mean_IAT)s, %(IAT_std)s, %(packet_rate)s, %(mean_packet_size)s, %(packet_size_std)s,
                %(score_primary)s, %(pred_primary)s, %(score_timing)s, %(pred_timing)s, %(timing_status)s,
                %(pred_dual)s, %(dual_reason)s
            )
            ON CONFLICT (run_id, client_mac, bin_start_epoch) DO NOTHING;
            """

        elif table_name == "live_alerts":
            return """
            INSERT INTO live_alerts (
                window_id, run_id, client_mac, node_id, bin_start_epoch,
                window_start_utc, dual_reason, score_primary, score_timing,
                packet_rate, mean_packet_size, packet_count, acknowledged
            ) VALUES (
                %(window_id)s, %(run_id)s, %(client_mac)s, %(node_id)s, %(bin_start_epoch)s,
                %(window_start_utc)s, %(dual_reason)s, %(score_primary)s, %(score_timing)s,
                %(packet_rate)s, %(mean_packet_size)s, %(packet_count)s, %(acknowledged)s
            )
            ON CONFLICT (window_id) DO NOTHING;
            """

        elif table_name == "live_sensor_telemetry":
            return """
            INSERT INTO live_sensor_telemetry (
                run_id, physical_node_id, logical_node_id, sequence_num,
                uptime_ms, temperature_c, humidity_pct, dht_valid,
                captured_at, sensor_epoch
            ) VALUES (
                %(run_id)s, %(physical_node_id)s, %(logical_node_id)s, %(sequence_num)s,
                %(uptime_ms)s, %(temperature_c)s, %(humidity_pct)s, %(dht_valid)s,
                %(captured_at)s, %(sensor_epoch)s
            )
            ON CONFLICT (run_id, physical_node_id, sequence_num) DO NOTHING;
            """

        elif table_name == "live_pir_events":
            return """
            INSERT INTO live_pir_events (
                run_id, physical_node_id, logical_node_id, sequence_num,
                uptime_ms, motion_detected, captured_at, sensor_epoch
            ) VALUES (
                %(run_id)s, %(physical_node_id)s, %(logical_node_id)s, %(sequence_num)s,
                %(uptime_ms)s, %(motion_detected)s, %(captured_at)s, %(sensor_epoch)s
            )
            ON CONFLICT (run_id, physical_node_id, sequence_num) DO NOTHING;
            """

        elif table_name == "live_attack_events":
            return """
            INSERT INTO live_attack_events (
                event_uuid, run_id, window_id, timestamp_epoch, timestamp_utc,
                category, status, severity, confidence, source_mac,
                target_ip, evidence_json, missing_fields_json,
                recommended_action, acknowledged
            ) VALUES (
                %(event_uuid)s, %(run_id)s, %(window_id)s, %(timestamp_epoch)s, %(timestamp_utc)s,
                %(category)s, %(status)s, %(severity)s, %(confidence)s, %(source_mac)s,
                %(target_ip)s, %(evidence_json)s, %(missing_fields_json)s,
                %(recommended_action)s, %(acknowledged)s
            )
            ON CONFLICT (event_uuid) DO NOTHING;
            """

        return None

    def _transmit_via_http_transport(
        self, table_name: str, items: List[Dict[str, Any]]
    ) -> Tuple[bool, str]:
        """Adapter for existing PostgREST mock test harnesses."""
        payloads = []
        for it in items:
            p = dict(it["payload"])
            if table_name in ("live_sensor_telemetry", "live_pir_events"):
                if not p.get("captured_at"):
                    epoch = p.get("sensor_epoch")
                    if epoch is not None and isinstance(epoch, (int, float)) and epoch > 0:
                        p["captured_at"] = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc).isoformat()
                    else:
                        p["captured_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            payloads.append(p)

        config = TABLE_CONFLICT_CONFIG.get(table_name, {})
        on_conflict = config.get("on_conflict")
        prefer_header = config.get("prefer", "resolution=ignore-duplicates")

        endpoint = f"{self.supabase_url}/rest/v1/{table_name}"
        if on_conflict:
            endpoint = f"{endpoint}?on_conflict={on_conflict}"

        headers = {
            "apikey": self.supabase_key,
            "Authorization": f"Bearer {self.supabase_key}",
            "Content-Type": "application/json",
            "Prefer": prefer_header,
        }

        try:
            resp = self.http_transport("POST", endpoint, headers, payloads)
            if resp.status_code in (200, 201, 204):
                return True, ""
            return False, f"HTTP {resp.status_code}: {resp.text[:300]}"
        except Exception as e:
            return False, f"HTTP Transport Error: {str(e)[:300]}"

    def _run_loop(self) -> None:
        """Continuous background execution loop."""
        conn = self._get_connection()
        try:
            init_outbox_schema(conn)
        finally:
            conn.close()

        while not self._stop_event.is_set():
            try:
                delivered = self.sync_once()
                if delivered == 0:
                    self._stop_event.wait(self.poll_interval_sec)
            except Exception as e:
                logger.error(f"Error in sync worker loop: {e}", exc_info=True)
                self.last_error = str(e)
                self._stop_event.wait(self.poll_interval_sec * 2)

    def get_status(self) -> Dict[str, Any]:
        """Returns worker health and delivery metrics without exposing secrets."""
        status = {
            "configured": self.is_configured(),
            "connected": self.is_connected,
            "running": self._thread is not None and self._thread.is_alive(),
            "pooler_host": self.pooler_host,
            "pooler_port": self.pooler_port,
            "collector_user": self.collector_user,
            "total_delivered": self.total_delivered,
            "total_failures": self.total_failures,
            "consecutive_failures": self.consecutive_failures,
            "last_sync_time": self.last_sync_time,
            "last_error": self.last_error,
        }
        if self.db_path.exists():
            try:
                conn = self._get_connection()
                try:
                    status["outbox_metrics"] = get_outbox_metrics(conn)
                finally:
                    conn.close()
            except Exception as e:
                status["outbox_metrics_error"] = str(e)
        return status
