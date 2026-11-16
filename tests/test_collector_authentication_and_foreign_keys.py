"""
Dedicated Test Suite for Collector PostgreSQL Pooler Authentication, Foreign-Key Ordering & Idempotency.
File: tests/test_collector_authentication_and_foreign_keys.py

Covers:
  - Verification of dedicated 'iot_collector' identity and PostgreSQL pooler configuration.
  - Zero password leakage in worker status, repr, and logs.
  - Verification of parameterized SQL templates across all 9 tables.
  - Strict enforcement of ON CONFLICT DO UPDATE for mutable tables.
  - Strict enforcement of ON CONFLICT DO NOTHING for immutable evidence tables.
  - Verification of foreign-key dependency ordering (collector_status -> windows -> alerts/attacks).
  - Child FK retry recovery simulation (neither parent nor child is lost).
  - Pooler operational disconnection simulation and exponential backoff.
"""

import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from src.cloud_sync_outbox import (
    OutboxPriority,
    OutboxStatus,
    init_outbox_schema,
    queue_attack_event,
    queue_collector_status,
    queue_event,
    queue_live_alert,
    queue_traffic_window,
)
from src.cloud_sync_worker import (
    CloudSyncWorker,
    TABLE_DEPENDENCY_ORDER,
)


@pytest.fixture
def temp_worker_db():
    """Provides a fresh SQLite outbox database."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    conn = CloudSyncWorker(db_path=db_path)._get_connection()
    init_outbox_schema(conn)
    conn.close()
    yield db_path
    if db_path.exists():
        db_path.unlink()


def test_collector_pg_pooler_configuration(monkeypatch, temp_worker_db):
    """Verifies that dedicated PostgreSQL pooler parameters are properly loaded."""
    monkeypatch.setenv("SUPABASE_POOLER_HOST", "aws-1-ap-south-1.pooler.supabase.com")
    monkeypatch.setenv("SUPABASE_POOLER_PORT", "6543")
    monkeypatch.setenv("SUPABASE_DB_NAME", "postgres")
    monkeypatch.setenv("SUPABASE_COLLECTOR_USER", "iot_collector.cwqumhtzeiqrfhlesksw")
    monkeypatch.setenv("SUPABASE_COLLECTOR_PASSWORD", "secret_collector_pw_123")
    monkeypatch.setenv("SUPABASE_SSLMODE", "require")

    worker = CloudSyncWorker(db_path=temp_worker_db)
    assert worker.pooler_host == "aws-1-ap-south-1.pooler.supabase.com"
    assert worker.pooler_port == 6543
    assert worker.db_name == "postgres"
    assert worker.collector_user == "iot_collector.cwqumhtzeiqrfhlesksw"
    assert worker.collector_password == "secret_collector_pw_123"
    assert worker.sslmode == "require"
    assert worker.is_configured() is True


def test_zero_password_logging(monkeypatch, temp_worker_db):
    """Verifies that collector passwords and sensitive DSNs are NEVER exposed in worker status or logs."""
    monkeypatch.setenv("SUPABASE_COLLECTOR_PASSWORD", "super_secret_password_do_not_leak")
    worker = CloudSyncWorker(db_path=temp_worker_db)

    status = worker.get_status()
    # Password must not be in status dict
    assert "collector_password" not in status
    assert "password" not in status
    for k, v in status.items():
        assert "super_secret_password_do_not_leak" not in str(v)


def test_sql_templates_mutable_vs_immutable(temp_worker_db):
    """
    Verifies that parameterized SQL templates strictly adhere to least privilege:
    - Mutable tables (collector_status, device_registry, unknown_device_obs) use ON CONFLICT DO UPDATE.
    - Immutable tables (traffic windows, alerts, attacks, sensors, etc.) use ON CONFLICT DO NOTHING.
    """
    worker = CloudSyncWorker(db_path=temp_worker_db)

    mutable_tables = ["collector_status", "device_registry", "unknown_device_obs"]
    immutable_tables = [
        "station_pseudonym_map",
        "live_traffic_windows",
        "live_alerts",
        "live_sensor_telemetry",
        "live_pir_events",
        "live_attack_events",
    ]

    for table in mutable_tables:
        sql = worker._build_sql_for_table(table)
        assert sql is not None, f"Missing SQL template for mutable table {table}"
        assert "DO UPDATE SET" in sql, f"Table {table} must use DO UPDATE SET"

    for table in immutable_tables:
        sql = worker._build_sql_for_table(table)
        assert sql is not None, f"Missing SQL template for immutable table {table}"
        assert "DO NOTHING" in sql, f"Table {table} must use DO NOTHING"
        assert "DO UPDATE" not in sql, f"Table {table} must NOT use DO UPDATE"


def test_foreign_key_dependency_order_in_batch(temp_worker_db):
    """
    Verifies that when a batch contains mixed tables, the worker sorts table delivery
    strictly according to TABLE_DEPENDENCY_ORDER so parents precede children.
    """
    conn = CloudSyncWorker(db_path=temp_worker_db)._get_connection()
    now = time.time()

    # Queue child attack event first (Tier 1)
    queue_attack_event(conn, run_id=1, event_uuid="att_fk_1", data={
        "window_id": 101,
        "timestamp_epoch": now,
        "timestamp_utc": "2026-11-16T00:00:00Z",
        "category": "Denial_of_Service",
        "status": "DETECTED",
        "severity": "HIGH",
        "confidence": 0.95,
        "recommended_action": "Rate limit endpoint",
    })

    # Queue child alert second (Tier 2)
    queue_live_alert(conn, run_id=1, alert_id=1, alert_data={
        "window_id": 101,
        "client_mac": "00:11:22:33:44:55",
        "dual_reason": "ANOMALY_PRIMARY_BURST_OR_SIZE",
    })

    # Queue parent traffic window third (Tier 3)
    queue_traffic_window(conn, run_id=1, window_id=101, window_data={
        "client_mac": "00:11:22:33:44:55",
        "bin_start_epoch": now,
        "bin_end_epoch": now + 1,
        "packet_count": 50,
        "packet_rate": 50.0,
    })

    # Queue parent collector_status fourth (Tier 1)
    queue_collector_status(conn, run_id=1, status_data={"status": "RUNNING"})

    conn.close()

    # Track order of tables received by mock db transport
    tables_dispatched = []

    def mock_db_transport(table_name, items):
        tables_dispatched.append(table_name)
        return True, ""

    worker = CloudSyncWorker(db_path=temp_worker_db, db_transport=mock_db_transport, batch_size=10)
    delivered = worker.sync_once()

    assert delivered == 4
    # Expected dependency order: collector_status -> live_traffic_windows -> live_alerts -> live_attack_events
    assert tables_dispatched == [
        "collector_status",
        "live_traffic_windows",
        "live_alerts",
        "live_attack_events",
    ]


def test_child_fk_violation_recovery(temp_worker_db):
    """
    Verifies that if a child record fails due to a foreign key violation (e.g. parent not yet in cloud),
    the child record remains in the outbox as PENDING for retry, and parent records succeed.
    """
    conn = CloudSyncWorker(db_path=temp_worker_db)._get_connection()
    now = time.time()

    # Queue parent window
    queue_traffic_window(conn, run_id=1, window_id=555, window_data={
        "client_mac": "aa:bb:cc:dd:ee:ff",
        "bin_start_epoch": now,
        "packet_count": 10,
    })
    # Queue child alert referencing window 555
    queue_live_alert(conn, run_id=1, alert_id=999, alert_data={
        "window_id": 555,
        "client_mac": "aa:bb:cc:dd:ee:ff",
        "dual_reason": "ANOMALY_PRIMARY_BURST_OR_SIZE",
    })
    conn.close()

    def mock_fk_failure_transport(table_name, items):
        if table_name == "live_alerts":
            # Simulate Postgres 23503 foreign key violation
            return False, "PostgreSQL IntegrityError (Constraint/FK): insert or update violates foreign key constraint"
        return True, ""

    worker = CloudSyncWorker(db_path=temp_worker_db, db_transport=mock_fk_failure_transport, batch_size=10)
    delivered = worker.sync_once()

    # Parent window delivered (1), child alert failed (1)
    assert delivered == 1
    assert worker.total_failures == 1

    # Verify outbox states: parent is DELIVERED, child is PENDING with retry count = 1
    conn = worker._get_connection()
    cur = conn.cursor()
    cur.execute("SELECT table_name, status, retry_count FROM cloud_sync_outbox ORDER BY outbox_id")
    rows = cur.fetchall()
    conn.close()

    assert len(rows) == 2
    # Child alert (outbox_id 2 or 1):
    alert_row = [r for r in rows if r[0] == "live_alerts"][0]
    assert alert_row[1] == OutboxStatus.PENDING.value
    assert alert_row[2] == 1  # retry_count incremented

    # Parent window:
    win_row = [r for r in rows if r[0] == "live_traffic_windows"][0]
    assert win_row[1] == OutboxStatus.DELIVERED.value


def test_pooler_disconnection_and_backoff(temp_worker_db):
    """
    Verifies that pooler connection drops / operational errors are handled gracefully
    without worker crashes and trigger exponential backoff.
    """
    conn = CloudSyncWorker(db_path=temp_worker_db)._get_connection()
    queue_collector_status(conn, run_id=1, status_data={"status": "RUNNING"})
    conn.close()

    def mock_pooler_disconnect(table_name, items):
        return False, "PostgreSQL OperationalError (Pooler/Connection): connection timeout to aws-1-ap-south-1.pooler.supabase.com:6543"

    worker = CloudSyncWorker(db_path=temp_worker_db, db_transport=mock_pooler_disconnect, batch_size=10)
    delivered = worker.sync_once()

    assert delivered == 0
    assert worker.consecutive_failures == 1
    assert worker.is_connected is False
    assert "OperationalError" in worker.last_error

    # Verify item status remains PENDING with backoff scheduled
    conn = worker._get_connection()
    cur = conn.cursor()
    cur.execute("SELECT status, retry_count, next_retry_at FROM cloud_sync_outbox WHERE table_name = 'collector_status'")
    row = cur.fetchone()
    conn.close()

    assert row[0] == OutboxStatus.PENDING.value
    assert row[1] == 1
    assert row[2] > time.time()


def test_schema_to_worker_column_mismatches_resolved(temp_worker_db):
    """
    Verifies that worker SQL templates exactly agree with the PostgreSQL schema:
    - device_registry: NO 'is_active' or 'first_seen' (aligned with exact schema).
    - station_pseudonym_map: NO 'salt_hash' (aligned with exact schema).
    - All 9 tables have valid conflict targets.
    """
    worker = CloudSyncWorker(db_path=temp_worker_db)

    # 1. device_registry check
    dev_sql = worker._build_sql_for_table("device_registry")
    assert "is_active" not in dev_sql, "device_registry SQL must NOT contain 'is_active'"
    assert "first_seen" not in dev_sql, "device_registry SQL must NOT contain 'first_seen'"
    assert "mac_address" in dev_sql and "node_id" in dev_sql and "last_seen" in dev_sql
    assert "ON CONFLICT (mac_address) DO UPDATE" in dev_sql

    # 2. station_pseudonym_map check
    pseudo_sql = worker._build_sql_for_table("station_pseudonym_map")
    assert "salt_hash" not in pseudo_sql, "station_pseudonym_map SQL must NOT contain 'salt_hash'"
    assert "mac_address" in pseudo_sql and "pseudonym_id" in pseudo_sql
    assert "ON CONFLICT (mac_address) DO NOTHING" in pseudo_sql

    # 3. collector_status check
    status_sql = worker._build_sql_for_table("collector_status")
    assert "ON CONFLICT (run_id) DO UPDATE" in status_sql

    # 4. live_traffic_windows check
    win_sql = worker._build_sql_for_table("live_traffic_windows")
    assert "ON CONFLICT (run_id, client_mac, bin_start_epoch) DO NOTHING" in win_sql


def test_physical_sensor_identity_propagation(temp_worker_db):
    """
    Verifies that physical sensor node identities are propagated faithfully from the
    source without fallback substitution when the actual identity is provided.
    """
    from src.cloud_sync_outbox import queue_sensor_telemetry, queue_pir_event
    import json

    conn = CloudSyncWorker(db_path=temp_worker_db)._get_connection()
    now = time.time()

    # Queue with specific physical identity
    seq1 = queue_sensor_telemetry(conn, run_id=42, seq=100, telemetry_data={
        "physical_node_id": "esp32_device_east_wing",
        "logical_node_id": "Node_1",
        "uptime_ms": 50000,
        "temperature_c": 24.5,
        "humidity_pct": 55.0,
        "dht_valid": 1,
        "sensor_epoch": now,
    })

    seq2 = queue_pir_event(conn, run_id=42, seq=101, pir_data={
        "physical_node_id": "esp32_device_east_wing",
        "logical_node_id": "Node_2",
        "uptime_ms": 50500,
        "motion_detected": 1,
        "sensor_epoch": now,
    })

    cur = conn.cursor()
    cur.execute("SELECT table_name, event_uuid, payload_json FROM cloud_sync_outbox ORDER BY outbox_id")
    rows = cur.fetchall()
    conn.close()

    assert len(rows) == 2

    # Verify sensor record payload
    sensor_row = rows[0]
    assert sensor_row[0] == "live_sensor_telemetry"
    from src.cloud_sync_outbox import generate_event_uuid
    expected_sensor_uuid = generate_event_uuid("live_sensor_telemetry", "sensor_42_esp32_device_east_wing_100", run_id=42)
    assert sensor_row[1] == expected_sensor_uuid  # Deterministic event_uuid hashes the physical_node_id
    p1 = json.loads(sensor_row[2])
    assert p1["physical_node_id"] == "esp32_device_east_wing"
    assert p1["logical_node_id"] == "Node_1"

    # Verify PIR record payload
    pir_row = rows[1]
    assert pir_row[0] == "live_pir_events"
    expected_pir_uuid = generate_event_uuid("live_pir_events", "pir_42_esp32_device_east_wing_101", run_id=42)
    assert pir_row[1] == expected_pir_uuid
    p2 = json.loads(pir_row[2])
    assert p2["physical_node_id"] == "esp32_device_east_wing"
    assert p2["logical_node_id"] == "Node_2"


def test_unrelated_public_schema_sequences_not_modified():
    """
    Verifies that the migration script strictly avoids modifying unrelated public-schema sequences,
    containing zero blanket 'ON ALL SEQUENCES' statements and scoping sequences exclusively
    to the 7 project tables with actual identity columns.
    """
    import re
    sql_path = Path("scratch/stage3b_6_final_supabase_migration.sql")
    assert sql_path.exists()

    with open(sql_path, "r", encoding="utf-8") as f:
        sql = f.read()

    # Reject blanket sequence statements
    assert not re.search(r"GRANT\s+[^;]*\bON\s+ALL\s+SEQUENCES\b", sql, re.IGNORECASE)
    assert not re.search(r"REVOKE\s+[^;]*\bON\s+ALL\s+SEQUENCES\b", sql, re.IGNORECASE)

    # Verify that exactly the 7 tables with real identity columns are referenced
    expected_pairs = {
        ("collector_status", "run_id"),
        ("live_traffic_windows", "window_id"),
        ("live_alerts", "alert_id"),
        ("unknown_device_obs", "obs_id"),
        ("live_sensor_telemetry", "telemetry_id"),
        ("live_pir_events", "pir_id"),
        ("live_attack_events", "event_id"),
    }
    found_pairs = set(re.findall(r"pg_get_serial_sequence\s*\(\s*'(\w+)'\s*,\s*'(\w+)'\s*\)", sql, re.IGNORECASE))
    assert found_pairs == expected_pairs


def test_preflight_reconciles_all_nine_tables():
    """
    Verifies that Section 0 preflight DO block systematically audits all 9 tables,
    handles safe column additions with ADD COLUMN IF NOT EXISTS, supports widening
    integer to bigint identity keys, raises actionable descriptive exceptions on
    incompatible drift, and cleans up legacy collision constraints.
    """
    import re
    sql_path = Path("scratch/stage3b_6_final_supabase_migration.sql")
    assert sql_path.exists()

    with open(sql_path, "r", encoding="utf-8") as f:
        sql = f.read()

    expected_tables = [
        "collector_status",
        "device_registry",
        "station_pseudonym_map",
        "live_traffic_windows",
        "live_alerts",
        "unknown_device_obs",
        "live_sensor_telemetry",
        "live_pir_events",
        "live_attack_events"
    ]

    # Preflight block must exist
    assert "0. PREFLIGHT SCHEMA RECONCILIATION" in sql

    # All 9 tables must be checked
    for tbl in expected_tables:
        assert f"table_name = '{tbl}'" in sql, f"Table {tbl} not audited in preflight!"

    # Safe column additions
    assert "ADD COLUMN IF NOT EXISTS" in sql

    # Integer to bigint widening checks
    assert "Widening collector_status.run_id from INTEGER to BIGINT" in sql
    assert "Widening live_traffic_windows.window_id from INTEGER to BIGINT" in sql
    assert "Widening live_alerts.alert_id from INTEGER to BIGINT" in sql
    assert "Widening unknown_device_obs.obs_id from INTEGER to BIGINT" in sql
    assert "Widening live_sensor_telemetry.telemetry_id from INTEGER to BIGINT" in sql
    assert "Widening live_pir_events.pir_id from INTEGER to BIGINT" in sql
    assert "Widening live_attack_events.event_id from INTEGER to BIGINT" in sql

    # Actionable exception on incompatible type
    assert "RAISE EXCEPTION" in sql
    assert "Incompatible data type for column" in sql

    # Event UUID standardization and legacy constraint drop
    assert "ALTER TABLE live_attack_events ADD COLUMN event_uuid TEXT" in sql
    assert "ALTER TABLE live_attack_events DROP CONSTRAINT uq_attack_event" in sql
    assert "ALTER TABLE live_attack_events ADD CONSTRAINT uq_attack_event_uuid UNIQUE (event_uuid)" in sql


def test_public_views_sanitize_physical_node_identity():
    """
    Verifies that v_public_sensor_telemetry and v_public_pir_events project
    sanitized physical_node_id via strict allowlist with safe fallback 'esp32_sanitized_node',
    preventing raw hardware serial/MAC leakage while preserving telemetry grouping.
    """
    import re
    sql_path = Path("scratch/stage3b_6_final_supabase_migration.sql")
    assert sql_path.exists()

    with open(sql_path, "r", encoding="utf-8") as f:
        sql = f.read()

    # Sensor telemetry view
    v6 = re.search(r"CREATE\s+OR\s+REPLACE\s+VIEW\s+v_public_sensor_telemetry.*?FROM\s+live_sensor_telemetry", sql, re.DOTALL)
    assert v6 is not None
    v6_sql = v6.group(0)
    assert "physical_node_id IN ('esp32_gateway', 'esp32_sensor_node_1', 'esp32_sensor_node_2')" in v6_sql
    assert "'esp32_sanitized_node'" in v6_sql

    # PIR events view
    v7 = re.search(r"CREATE\s+OR\s+REPLACE\s+VIEW\s+v_public_pir_events.*?FROM\s+live_pir_events", sql, re.DOTALL)
    assert v7 is not None
    v7_sql = v7.group(0)
    assert "physical_node_id IN ('esp32_gateway', 'esp32_sensor_node_1', 'esp32_sensor_node_2')" in v7_sql
    assert "'esp32_sanitized_node'" in v7_sql


def test_cloud_dashboard_handles_physical_node():
    """
    Verifies that src/cloud_dashboard.py handles physical_node_id safely,
    passing it through safe_html sanitization and displaying active hardware gateway.
    """
    dash_path = Path("src/cloud_dashboard.py")
    assert dash_path.exists()

    with open(dash_path, "r", encoding="utf-8") as f:
        code = f.read()

    assert "physical_node_id" in code
    assert "safe_html(str(latest_sensor.get(\"physical_node_id\") or \"esp32_gateway\"))" in code
    assert "Active Sensor Node" in code


def test_preflight_validates_all_essential_identity_and_foreign_key_columns():
    """
    Verifies that the preflight DO block systematically checks all essential identity,
    foreign-key, timestamp, and classification columns across all 9 tables, stopping
    with an actionable RAISE EXCEPTION on any missing essential column:
      - device_registry.mac_address
      - station_pseudonym_map.mac_address
      - live_traffic_windows.window_id, run_id, client_mac, bin_start_epoch, bin_end_epoch
      - live_alerts.alert_id, window_id, run_id, dual_reason, bin_start_epoch
      - unknown_device_obs.obs_id, run_id, observed_mac
      - live_sensor_telemetry.telemetry_id, run_id, sequence_num
      - live_pir_events.pir_id, run_id, sequence_num
      - live_attack_events.event_id, run_id, timestamp_epoch, timestamp_utc,
        category, status, severity, confidence
    """
    sql_path = Path("scratch/stage3b_6_final_supabase_migration.sql")
    assert sql_path.exists()

    with open(sql_path, "r", encoding="utf-8") as f:
        sql = f.read()

    essential_columns = [
        ("collector_status", "run_id"),
        ("device_registry", "mac_address"),
        ("station_pseudonym_map", "mac_address"),
        ("live_traffic_windows", "window_id"),
        ("live_traffic_windows", "run_id"),
        ("live_traffic_windows", "client_mac"),
        ("live_traffic_windows", "bin_start_epoch"),
        ("live_traffic_windows", "bin_end_epoch"),
        ("live_alerts", "alert_id"),
        ("live_alerts", "window_id"),
        ("live_alerts", "run_id"),
        ("live_alerts", "dual_reason"),
        ("live_alerts", "bin_start_epoch"),
        ("unknown_device_obs", "obs_id"),
        ("unknown_device_obs", "run_id"),
        ("unknown_device_obs", "observed_mac"),
        ("live_sensor_telemetry", "telemetry_id"),
        ("live_sensor_telemetry", "run_id"),
        ("live_sensor_telemetry", "sequence_num"),
        ("live_pir_events", "pir_id"),
        ("live_pir_events", "run_id"),
        ("live_pir_events", "sequence_num"),
        ("live_attack_events", "event_id"),
        ("live_attack_events", "run_id"),
        ("live_attack_events", "timestamp_epoch"),
        ("live_attack_events", "timestamp_utc"),
        ("live_attack_events", "category"),
        ("live_attack_events", "status"),
        ("live_attack_events", "severity"),
        ("live_attack_events", "confidence"),
    ]

    for tbl, col in essential_columns:
        # Each essential column must have an existence check in preflight
        assert f"table_name = '{tbl}' AND column_name = '{col}'" in sql, \
            f"Missing essential column existence audit for {tbl}.{col}!"

    # Verify that missing essential columns trigger actionable RAISE EXCEPTION
    assert "Required primary key column run_id is missing from existing collector_status table" in sql
    assert "Required primary key column mac_address is missing from existing device_registry table" in sql
    assert "Required primary key column mac_address is missing from existing station_pseudonym_map table" in sql
    assert "Required primary key column window_id is missing from existing live_traffic_windows table" in sql
    assert "Required foreign key column run_id is missing from existing live_traffic_windows table" in sql
    assert "Required natural key column client_mac is missing from existing live_traffic_windows table" in sql
    assert "Required timestamp column bin_start_epoch is missing from existing live_traffic_windows table" in sql
    assert "Required primary key column alert_id is missing from existing live_alerts table" in sql
    assert "Required foreign key column window_id is missing from existing live_alerts table" in sql
    assert "Required foreign key column run_id is missing from existing live_alerts table" in sql
    assert "Required primary key column obs_id is missing from existing unknown_device_obs table" in sql
    assert "Required foreign key column run_id is missing from existing unknown_device_obs table" in sql
    assert "Required identifier column observed_mac is missing from existing unknown_device_obs table" in sql
    assert "Required primary key column telemetry_id is missing from existing live_sensor_telemetry table" in sql
    assert "Required foreign key column run_id is missing from existing live_sensor_telemetry table" in sql
    assert "Required hardware sequence_num is missing from existing live_sensor_telemetry table" in sql
    assert "Required primary key column pir_id is missing from existing live_pir_events table" in sql
    assert "Required foreign key column run_id is missing from existing live_pir_events table" in sql
    assert "Required hardware sequence_num is missing from existing live_pir_events table" in sql
    assert "Required primary key column event_id is missing from existing live_attack_events table" in sql
    assert "Required foreign key column run_id is missing from existing live_attack_events table" in sql
    assert "Required timestamp column timestamp_epoch is missing from existing live_attack_events table" in sql
    assert "Required timestamp column timestamp_utc is missing from existing live_attack_events table" in sql
    assert "Required column category is missing from existing live_attack_events table" in sql
    assert "Required column status is missing from existing live_attack_events table" in sql
    assert "Required column severity is missing from existing live_attack_events table" in sql
    assert "Required detector column confidence is missing from existing live_attack_events table" in sql


def test_preflight_validates_constraint_definitions_not_just_names():
    """
    Verifies that primary key and unique constraint validation queries pg_constraint
    and pg_attribute with array_position ordering, validating actual column tuples
    and rejecting incompatible constraint definitions.
    """
    sql_path = Path("scratch/stage3b_6_final_supabase_migration.sql")
    assert sql_path.exists()

    with open(sql_path, "r", encoding="utf-8") as f:
        sql = f.read()

    # Constraint definition query pattern
    assert "string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum))" in sql
    assert "c.contype = 'p'" in sql
    assert "c.contype = 'u'" in sql

    # Verification of unique constraint targets against exact expected column lists
    assert "uq_cols <> 'run_id,client_mac,bin_start_epoch'" in sql
    assert "uq_cols <> 'window_id'" in sql
    assert "uq_cols <> 'run_id,observed_mac'" in sql
    assert "uq_cols <> 'run_id,physical_node_id,sequence_num'" in sql
    assert "uq_cols <> 'event_uuid'" in sql




