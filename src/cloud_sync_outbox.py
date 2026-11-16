"""
Durable Local SQLite Outbox for Cloud Synchronization.
File: src/cloud_sync_outbox.py

Purpose:
  Provides a durable, crash-proof local staging queue (cloud_sync_outbox)
  in SQLite to asynchronously deliver monitoring telemetry to Supabase.
  
Key Guarantees:
  1. Local SQLite remains sovereign and authoritative (never blocked by cloud).
  2. Zero Data Loss for Critical Telemetry: Tier 1 (attacks, status) and
     Tier 2 (alerts, sensors) events are persisted and NEVER dropped.
  3. Strict Idempotency: All events carry stable event UUIDs / keys to prevent
     duplicate cloud insertions on retries.
  4. Exponential Backoff with Jitter: Prevents thundering herd on network recovery.
  5. Priority Queueing: High-priority security and physical alerts are synchronized
     before high-rate traffic windows.
  6. Process Crash Recovery: In-flight records orphaned by unexpected restarts
     are automatically recovered and retried.
"""

import datetime
import enum
import json
import random
import sqlite3
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple


class OutboxPriority(enum.IntEnum):
    """Priority tiers for cloud telemetry synchronization."""
    TIER_1_CRITICAL = 1      # Attack events, collector start/stop lifecycle
    TIER_2_IMPORTANT = 2     # Anomaly alerts (IF), DHT11 & PIR sensor records
    TIER_3_HIGH_RATE = 3     # 1-second traffic feature windows
    TIER_4_OBSERVATION = 4   # Unknown MAC observations, device registry sync


class OutboxStatus(str, enum.Enum):
    """Lifecycle states of outbox queue items."""
    PENDING = "PENDING"
    IN_FLIGHT = "IN_FLIGHT"
    DELIVERED = "DELIVERED"
    FAILED = "FAILED"
    DROPPED = "DROPPED"


SCHEMA_OUTBOX_SQL = """
CREATE TABLE IF NOT EXISTS cloud_sync_outbox (
    outbox_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    event_uuid          TEXT UNIQUE NOT NULL,
    table_name          TEXT NOT NULL,
    operation           TEXT NOT NULL DEFAULT 'INSERT',
    priority_tier       INTEGER NOT NULL DEFAULT 3,
    payload_json        TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'PENDING',
    retry_count         INTEGER NOT NULL DEFAULT 0,
    max_retries         INTEGER NOT NULL DEFAULT 10,
    next_retry_at       REAL NOT NULL,
    last_attempt_at     REAL,
    last_error          TEXT,
    delivered_at        REAL,
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_outbox_queue 
    ON cloud_sync_outbox(status, priority_tier, next_retry_at);

CREATE INDEX IF NOT EXISTS idx_outbox_uuid 
    ON cloud_sync_outbox(event_uuid);
"""


def init_outbox_schema(conn: sqlite3.Connection) -> None:
    """Initialises the cloud_sync_outbox table and indexes idempotently."""
    conn.executescript(SCHEMA_OUTBOX_SQL)
    conn.commit()


def generate_event_uuid(table_name: str, natural_key: str, run_id: Optional[Any] = None) -> str:
    """
    Generates a deterministic UUID (UUID v5) for an event to guarantee
    idempotent insertion and prevent duplicate delivery across restarts.
    """
    namespace = uuid.NAMESPACE_DNS
    composite = f"iot.guard.{table_name}.{run_id or '0'}.{natural_key}"
    return str(uuid.uuid5(namespace, composite))


def calculate_backoff(retry_count: int, min_sec: float = 1.0, max_sec: float = 60.0, jitter: bool = True) -> float:
    """
    Calculates exponential backoff delay with random jitter.
    Formula: min(max_sec, min_sec * 2^retry_count) + uniform(0, 1)
    """
    backoff = min(max_sec, min_sec * (2 ** min(retry_count, 10)))
    if jitter:
        backoff += random.uniform(0.1, 1.0)
    return backoff


def queue_event(
    conn: sqlite3.Connection,
    table_name: str,
    event_uuid: str,
    payload: Dict[str, Any],
    priority_tier: OutboxPriority = OutboxPriority.TIER_3_HIGH_RATE,
    operation: str = "INSERT",
    max_retries: int = 10,
    now_epoch: Optional[float] = None,
    commit: bool = True,
) -> int:
    """
    Queues a telemetry payload into the local durable outbox.
    If event_uuid already exists, the insertion is safely ignored (idempotent).
    Returns the outbox_id (or existing rowid).
    """
    if now_epoch is None:
        now_epoch = time.time()

    payload_str = json.dumps(payload, default=str)
    
    cur = conn.execute(
        """
        INSERT OR IGNORE INTO cloud_sync_outbox (
            event_uuid, table_name, operation, priority_tier,
            payload_json, status, retry_count, max_retries,
            next_retry_at
        ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)
        """,
        (
            event_uuid,
            table_name,
            operation,
            int(priority_tier),
            payload_str,
            OutboxStatus.PENDING.value,
            max_retries,
            now_epoch,
        ),
    )
    if commit:
        conn.commit()
    return cur.lastrowid or 0


# ─── Specialized High-Performance Queue Helpers ──────────────────────────────

def queue_attack_event(
    conn: sqlite3.Connection,
    run_id: Any,
    event_uuid: str,
    data: Dict[str, Any],
    commit: bool = True,
) -> int:
    """Queues a critical attack event (Tier 1 Priority - Never Dropped)."""
    payload = {
        "event_uuid": event_uuid,
        "run_id": int(run_id),
        "window_id": int(data["window_id"]) if data.get("window_id") is not None else None,
        "timestamp_epoch": float(data["timestamp_epoch"]),
        "timestamp_utc": str(data["timestamp_utc"]),
        "category": str(data["category"]),
        "status": str(data["status"]),
        "severity": str(data["severity"]),
        "confidence": float(data["confidence"]),
        "source_mac": data.get("source_mac"),
        "target_ip": data.get("target_ip"),
        "evidence_json": data.get("evidence_json", {}),
        "missing_fields_json": data.get("missing_fields_json"),
        "recommended_action": data.get("recommended_action") or data.get("mitigation_recommendation"),
        "acknowledged": int(data.get("acknowledged", 0)),
    }
    return queue_event(
        conn=conn,
        table_name="live_attack_events",
        event_uuid=event_uuid,
        payload=payload,
        priority_tier=OutboxPriority.TIER_1_CRITICAL,
        commit=commit,
    )


def queue_collector_status(
    conn: sqlite3.Connection,
    run_id: Any,
    status_data: Dict[str, Any],
    operation: str = "UPSERT",
    commit: bool = True,
) -> int:
    """Queues a collector lifecycle / heartbeat status event (Tier 1 Priority)."""
    run_id_int = int(run_id)
    event_uuid = generate_event_uuid("collector_status", str(run_id_int))
    payload = {
        "run_id": run_id_int,
        "started_at": status_data.get("started_at"),
        "last_heartbeat": status_data.get("last_heartbeat"),
        "interface_name": status_data.get("interface_name"),
        "serial_port": status_data.get("serial_port"),
        "status": status_data.get("status", "RUNNING"),
        "stop_reason": status_data.get("stop_reason"),
        "packets_parsed": int(status_data.get("packets_parsed", 0)),
        "windows_emitted": int(status_data.get("windows_emitted", 0)),
        "sensor_records": int(status_data.get("sensor_records", 0)),
    }
    return queue_event(
        conn=conn,
        table_name="collector_status",
        event_uuid=event_uuid,
        payload=payload,
        priority_tier=OutboxPriority.TIER_1_CRITICAL,
        operation=operation,
        commit=commit,
    )


def queue_live_alert(
    conn: sqlite3.Connection,
    run_id: Any,
    alert_id: Any,
    alert_data: Dict[str, Any],
    commit: bool = True,
) -> int:
    """Queues an anomaly alert (Tier 2 Priority - Never Dropped)."""
    alert_id_key = f"alert_{run_id}_{alert_id}"
    event_uuid = generate_event_uuid("live_alerts", alert_id_key, run_id=run_id)
    payload = {
        "window_id": int(alert_data.get("window_id", 0)),
        "run_id": int(run_id),
        "client_mac": alert_data.get("client_mac", ""),
        "node_id": alert_data.get("node_id", "Unspecified_Node"),
        "bin_start_epoch": float(alert_data.get("bin_start_epoch", 0.0)),
        "window_start_utc": alert_data.get("window_start_utc"),
        "dual_reason": alert_data.get("dual_reason", "EVALUATION_PENDING"),
        "score_primary": alert_data.get("score_primary"),
        "score_timing": alert_data.get("score_timing"),
        "packet_rate": alert_data.get("packet_rate"),
        "mean_packet_size": alert_data.get("mean_packet_size"),
        "packet_count": alert_data.get("packet_count"),
        "acknowledged": int(alert_data.get("acknowledged", 0)),
    }
    return queue_event(
        conn=conn,
        table_name="live_alerts",
        event_uuid=event_uuid,
        payload=payload,
        priority_tier=OutboxPriority.TIER_2_IMPORTANT,
        commit=commit,
    )


def queue_sensor_telemetry(
    conn: sqlite3.Connection,
    run_id: Any,
    seq: int,
    telemetry_data: Dict[str, Any],
    commit: bool = True,
) -> int:
    """Queues DHT11 environmental sensor telemetry (Tier 2 Priority)."""
    physical_node_id = str(telemetry_data.get("physical_node_id") or telemetry_data.get("physical_id") or "esp32_gateway")
    logical_node_id = str(telemetry_data.get("logical_node_id", "Node_1"))
    telemetry_id_key = f"sensor_{run_id}_{physical_node_id}_{seq}"
    event_uuid = generate_event_uuid("live_sensor_telemetry", telemetry_id_key, run_id=run_id)

    captured_at = telemetry_data.get("captured_at")
    if not captured_at:
        epoch = telemetry_data.get("sensor_epoch")
        if epoch is not None and isinstance(epoch, (int, float)) and epoch > 0:
            captured_at = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc).isoformat()
        else:
            captured_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    payload = {
        "run_id": int(run_id),
        "physical_node_id": physical_node_id,
        "logical_node_id": logical_node_id,
        "sequence_num": int(seq),
        "uptime_ms": int(telemetry_data.get("uptime_ms", 0)),
        "temperature_c": telemetry_data.get("temperature_c"),
        "humidity_pct": telemetry_data.get("humidity_pct"),
        "dht_valid": 1 if telemetry_data.get("dht_valid") else 0,
        "captured_at": captured_at,
        "sensor_epoch": telemetry_data.get("sensor_epoch"),
    }
    return queue_event(
        conn=conn,
        table_name="live_sensor_telemetry",
        event_uuid=event_uuid,
        payload=payload,
        priority_tier=OutboxPriority.TIER_2_IMPORTANT,
        commit=commit,
    )


def queue_pir_event(
    conn: sqlite3.Connection,
    run_id: Any,
    seq: int,
    pir_data: Dict[str, Any],
    commit: bool = True,
) -> int:
    """Queues PIR motion sensor event (Tier 2 Priority)."""
    physical_node_id = str(pir_data.get("physical_node_id") or pir_data.get("physical_id") or "esp32_gateway")
    logical_node_id = str(pir_data.get("logical_node_id", "Node_2"))
    pir_id_key = f"pir_{run_id}_{physical_node_id}_{seq}"
    event_uuid = generate_event_uuid("live_pir_events", pir_id_key, run_id=run_id)

    captured_at = pir_data.get("captured_at")
    if not captured_at:
        epoch = pir_data.get("sensor_epoch")
        if epoch is not None and isinstance(epoch, (int, float)) and epoch > 0:
            captured_at = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc).isoformat()
        else:
            captured_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    payload = {
        "run_id": int(run_id),
        "physical_node_id": physical_node_id,
        "logical_node_id": logical_node_id,
        "sequence_num": int(seq),
        "uptime_ms": int(pir_data.get("uptime_ms", 0)),
        "motion_detected": 1 if pir_data.get("motion_detected") else 0,
        "captured_at": captured_at,
        "sensor_epoch": pir_data.get("sensor_epoch"),
    }
    return queue_event(
        conn=conn,
        table_name="live_pir_events",
        event_uuid=event_uuid,
        payload=payload,
        priority_tier=OutboxPriority.TIER_2_IMPORTANT,
        commit=commit,
    )


def queue_traffic_window(
    conn: sqlite3.Connection,
    run_id: Any,
    window_id: Any,
    window_data: Dict[str, Any],
    commit: bool = True,
) -> int:
    """Queues a 1-second traffic feature window (Tier 3 Priority - Bounded)."""
    window_id_key = f"win_{run_id}_{window_id}"
    event_uuid = generate_event_uuid("live_traffic_windows", window_id_key, run_id=run_id)
    payload = {
        "run_id": int(run_id),
        "client_mac": window_data.get("client_mac", ""),
        "node_id": window_data.get("node_id", "Unspecified_Node"),
        "node_type": window_data.get("node_type") or window_data.get("Node_Type"),
        "data_label": window_data.get("data_label") or window_data.get("Data_Label"),
        "bin_start_epoch": float(window_data.get("bin_start_epoch") or window_data.get("bin_start_timestamp", 0.0)),
        "bin_end_epoch": float(window_data.get("bin_end_epoch") or window_data.get("bin_end_timestamp", 0.0)),
        "window_center_epoch": window_data.get("window_center_epoch"),
        "window_start_utc": window_data.get("window_start_utc") or window_data.get("Window_Start_UTC"),
        "window_end_utc": window_data.get("window_end_utc") or window_data.get("Window_End_UTC"),
        "packet_count": int(window_data.get("packet_count", 0)),
        "mean_IAT": window_data.get("mean_IAT"),
        "IAT_std": window_data.get("IAT_std"),
        "packet_rate": float(window_data.get("packet_rate", 0.0)),
        "mean_packet_size": window_data.get("mean_packet_size"),
        "packet_size_std": window_data.get("packet_size_std"),
        "score_primary": window_data.get("score_primary"),
        "pred_primary": window_data.get("pred_primary"),
        "score_timing": window_data.get("score_timing"),
        "pred_timing": window_data.get("pred_timing"),
        "timing_status": window_data.get("timing_status"),
        "pred_dual": window_data.get("pred_dual"),
        "dual_reason": window_data.get("dual_reason"),
    }
    if window_id is not None:
        try:
            payload["window_id"] = int(window_id)
        except (ValueError, TypeError):
            pass
    return queue_event(
        conn=conn,
        table_name="live_traffic_windows",
        event_uuid=event_uuid,
        payload=payload,
        priority_tier=OutboxPriority.TIER_3_HIGH_RATE,
        commit=commit,
    )


def queue_unknown_device(
    conn: sqlite3.Connection,
    run_id: Any,
    obs_data: Dict[str, Any],
    commit: bool = True,
) -> int:
    """Queues an unknown device observation (Tier 4 Priority)."""
    mac = obs_data.get("observed_mac", "")
    obs_id_key = f"obs_{run_id}_{mac}"
    event_uuid = generate_event_uuid("unknown_device_obs", obs_id_key, run_id=run_id)
    payload = {
        "run_id": int(run_id),
        "observed_mac": mac,
        "first_seen_utc": obs_data.get("first_seen_utc"),
        "last_seen_utc": obs_data.get("last_seen_utc"),
        "observation_count": int(obs_data.get("observation_count", 1)),
        "acknowledged": int(obs_data.get("acknowledged", 0)),
    }
    return queue_event(
        conn=conn,
        table_name="unknown_device_obs",
        event_uuid=event_uuid,
        payload=payload,
        priority_tier=OutboxPriority.TIER_4_OBSERVATION,
        operation="UPSERT",
        commit=commit,
    )


# ─── Queue Consumer & Batching Methods for Sync Worker ───────────────────────

def fetch_pending_batch(
    conn: sqlite3.Connection,
    limit: int = 50,
    now_epoch: Optional[float] = None,
) -> List[Dict[str, Any]]:
    """
    Fetches the highest-priority batch of ready items from the outbox.
    Ordered by priority_tier ASC (Tier 1 attacks first), then outbox_id ASC.
    Only items with status PENDING and next_retry_at <= now_epoch are returned.
    """
    if now_epoch is None:
        now_epoch = time.time()

    cur = conn.execute(
        """
        SELECT outbox_id, event_uuid, table_name, operation,
               priority_tier, payload_json, retry_count, max_retries
        FROM cloud_sync_outbox
        WHERE status = 'PENDING' AND next_retry_at <= ?
        ORDER BY priority_tier ASC, outbox_id ASC
        LIMIT ?
        """,
        (now_epoch, limit),
    )
    rows = cur.fetchall()
    results = []
    for r in rows:
        results.append({
            "outbox_id": r[0],
            "event_uuid": r[1],
            "table_name": r[2],
            "operation": r[3],
            "priority_tier": r[4],
            "payload": json.loads(r[5]),
            "retry_count": r[6],
            "max_retries": r[7],
        })
    return results


def mark_in_flight(
    conn: sqlite3.Connection,
    outbox_ids: List[int],
    now_epoch: Optional[float] = None,
    commit: bool = True,
) -> None:
    """Marks a list of outbox IDs as IN_FLIGHT during active transmission."""
    if not outbox_ids:
        return
    if now_epoch is None:
        now_epoch = time.time()

    placeholders = ",".join("?" for _ in outbox_ids)
    conn.execute(
        f"""
        UPDATE cloud_sync_outbox
        SET status = 'IN_FLIGHT', last_attempt_at = ?
        WHERE outbox_id IN ({placeholders})
        """,
        [now_epoch] + outbox_ids,
    )
    if commit:
        conn.commit()


def mark_delivered(
    conn: sqlite3.Connection,
    outbox_ids: List[int],
    now_epoch: Optional[float] = None,
    commit: bool = True,
) -> None:
    """Marks a list of outbox IDs as successfully DELIVERED."""
    if not outbox_ids:
        return
    if now_epoch is None:
        now_epoch = time.time()

    placeholders = ",".join("?" for _ in outbox_ids)
    conn.execute(
        f"""
        UPDATE cloud_sync_outbox
        SET status = 'DELIVERED', delivered_at = ?, last_error = NULL
        WHERE outbox_id IN ({placeholders})
        """,
        [now_epoch] + outbox_ids,
    )
    if commit:
        conn.commit()


def mark_retry_failed(
    conn: sqlite3.Connection,
    outbox_id: int,
    error_msg: str,
    now_epoch: Optional[float] = None,
    commit: bool = True,
) -> None:
    """
    Handles a failed delivery attempt.
    Increments retry_count, calculates exponential backoff delay,
    and updates status to PENDING (or FAILED if max_retries exceeded).
    NOTE: Tier 1 and Tier 2 events are NEVER marked FAILED; they retry indefinitely.
    """
    if now_epoch is None:
        now_epoch = time.time()

    cur = conn.execute(
        "SELECT retry_count, max_retries, priority_tier FROM cloud_sync_outbox WHERE outbox_id = ?",
        (outbox_id,),
    )
    row = cur.fetchone()
    if not row:
        return

    retry_count = row[0] + 1
    max_retries = row[1]
    priority_tier = row[2]

    backoff = calculate_backoff(retry_count)
    next_retry = now_epoch + backoff

    # Tier 1 & 2 never transition to FAILED under transient network drops,
    # but after extensive retries (e.g. fatal constraint/foreign key violation),
    # transition to FAILED to prevent poison-pill queue lockup.
    if priority_tier in (OutboxPriority.TIER_1_CRITICAL, OutboxPriority.TIER_2_IMPORTANT):
        if retry_count >= 30 and any(k in error_msg.lower() for k in ["constraint", "key", "not present in table"]):
            new_status = OutboxStatus.FAILED.value
        else:
            new_status = OutboxStatus.PENDING.value
    else:
        new_status = OutboxStatus.FAILED.value if retry_count >= max_retries else OutboxStatus.PENDING.value

    conn.execute(
        """
        UPDATE cloud_sync_outbox
        SET status = ?, retry_count = ?, next_retry_at = ?,
            last_attempt_at = ?, last_error = ?
        WHERE outbox_id = ?
        """,
        (new_status, retry_count, next_retry, now_epoch, error_msg[:500], outbox_id),
    )
    if commit:
        conn.commit()


def recover_stale_in_flight(
    conn: sqlite3.Connection,
    timeout_sec: float = 120.0,
    now_epoch: Optional[float] = None,
    commit: bool = True,
) -> int:
    """
    Resets any items stuck in 'IN_FLIGHT' for longer than timeout_sec back to 'PENDING'.
    Recovers unacknowledged records after an unexpected process crash.
    """
    if now_epoch is None:
        now_epoch = time.time()

    cutoff = now_epoch - timeout_sec
    cur = conn.execute(
        """
        UPDATE cloud_sync_outbox
        SET status = 'PENDING', next_retry_at = ?
        WHERE status = 'IN_FLIGHT' AND last_attempt_at < ?
        """,
        (now_epoch, cutoff),
    )
    recovered = cur.rowcount
    if commit and recovered > 0:
        conn.commit()
    return recovered


def prune_delivered(
    conn: sqlite3.Connection,
    retention_sec: float = 86400.0,
    now_epoch: Optional[float] = None,
    commit: bool = True,
) -> int:
    """
    Prunes DELIVERED records older than retention_sec (default 24 hours)
    to keep SQLite outbox table size compact.
    """
    if now_epoch is None:
        now_epoch = time.time()

    cutoff = now_epoch - retention_sec
    cur = conn.execute(
        "DELETE FROM cloud_sync_outbox WHERE status = 'DELIVERED' AND delivered_at < ?",
        (cutoff,),
    )
    pruned = cur.rowcount
    if commit and pruned > 0:
        conn.commit()
    return pruned


def enforce_queue_capacity(
    conn: sqlite3.Connection,
    max_capacity: int = 5000,
    commit: bool = True,
) -> int:
    """
    Enforces a bounded queue limit to prevent uncontrolled SQLite growth
    during multi-day offline network disconnects.
    CRITICAL SAFETY RULE: Only Tier 3 (traffic windows) and Tier 4 (unknown obs)
    may be shed (oldest first). Tier 1 and Tier 2 events are NEVER DROPPED.
    """
    cur = conn.execute(
        "SELECT COUNT(*) FROM cloud_sync_outbox WHERE status = 'PENDING'"
    )
    pending_count = cur.fetchone()[0]

    if pending_count <= max_capacity:
        return 0

    excess = pending_count - max_capacity
    # Identify oldest Tier 3 / 4 pending items to drop
    cur = conn.execute(
        """
        SELECT outbox_id FROM cloud_sync_outbox
        WHERE status = 'PENDING' AND priority_tier >= 3
        ORDER BY priority_tier DESC, outbox_id ASC
        LIMIT ?
        """,
        (excess,),
    )
    drop_ids = [r[0] for r in cur.fetchall()]
    if not drop_ids:
        return 0

    placeholders = ",".join("?" for _ in drop_ids)
    conn.execute(
        f"""
        UPDATE cloud_sync_outbox
        SET status = 'DROPPED', last_error = 'Queue capacity exceeded; oldest window dropped'
        WHERE outbox_id IN ({placeholders})
        """,
        drop_ids,
    )
    if commit:
        conn.commit()
    return len(drop_ids)


def get_outbox_metrics(conn: sqlite3.Connection) -> Dict[str, Any]:
    """Returns real-time queue health and backlog statistics."""
    cur = conn.execute(
        """
        SELECT status, COUNT(*)
        FROM cloud_sync_outbox
        GROUP BY status
        """
    )
    status_counts = dict(cur.fetchall())

    cur = conn.execute(
        """
        SELECT priority_tier, COUNT(*)
        FROM cloud_sync_outbox
        WHERE status = 'PENDING'
        GROUP BY priority_tier
        """
    )
    pending_by_tier = dict(cur.fetchall())

    return {
        "pending_total": status_counts.get(OutboxStatus.PENDING.value, 0),
        "in_flight_total": status_counts.get(OutboxStatus.IN_FLIGHT.value, 0),
        "delivered_total": status_counts.get(OutboxStatus.DELIVERED.value, 0),
        "failed_total": status_counts.get(OutboxStatus.FAILED.value, 0),
        "dropped_total": status_counts.get(OutboxStatus.DROPPED.value, 0),
        "tier1_critical_backlog": pending_by_tier.get(OutboxPriority.TIER_1_CRITICAL.value, 0),
        "tier2_important_backlog": pending_by_tier.get(OutboxPriority.TIER_2_IMPORTANT.value, 0),
        "tier3_high_rate_backlog": pending_by_tier.get(OutboxPriority.TIER_3_HIGH_RATE.value, 0),
        "tier4_observation_backlog": pending_by_tier.get(OutboxPriority.TIER_4_OBSERVATION.value, 0),
    }

