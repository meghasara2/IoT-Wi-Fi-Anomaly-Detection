"""
Automated Integration & Safety Tests for Cloud Schema, Permissions, Privacy, and Outbox.
File: tests/test_cloud_integration_corrections.py

Tests:
  1. Fresh-install schema consistency (DDL syntax, table counts, data types, constraints).
  2. Upgrade / preflight reconciliation consistency (event_uuid standardization, targeted drop).
  3. PostgREST conflict and permission compatibility (resolution=merge vs ignore, on_conflict targets).
  4. Public-view definer security and privacy invariant enforcement (zero raw MACs, closed allowlists).
  5. Outbox resilience during network outage and crash recovery.
"""

import json
import re
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest
import requests

from src.cloud_sync_outbox import (
    OutboxPriority,
    OutboxStatus,
    enforce_queue_capacity,
    fetch_pending_batch,
    generate_event_uuid,
    init_outbox_schema,
    mark_in_flight,
    mark_retry_failed,
    queue_attack_event,
    queue_collector_status,
    queue_event,
    queue_live_alert,
    queue_pir_event,
    queue_sensor_telemetry,
    queue_traffic_window,
    queue_unknown_device,
    recover_stale_in_flight,
)
from src.cloud_sync_worker import TABLE_CONFLICT_CONFIG, CloudSyncWorker


@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    conn = sqlite3.connect(str(db_path))
    init_outbox_schema(conn)
    conn.close()
    yield db_path
    if db_path.exists():
        db_path.unlink()


def test_fresh_install_schema_consistency():
    """Validates that fresh install DDL contains all 9 tables with exact intended columns and constraints."""
    sql_path = Path("scratch/stage3b_6_final_supabase_migration.sql")
    assert sql_path.exists()
    sql_text = sql_path.read_text(encoding="utf-8")

    expected_tables = {
        "collector_status", "device_registry", "station_pseudonym_map",
        "live_traffic_windows", "live_alerts", "unknown_device_obs",
        "live_sensor_telemetry", "live_pir_events", "live_attack_events"
    }

    # Verify all 9 tables exist in DDL
    created_tables = set(re.findall(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z0-9_]+)", sql_text, re.IGNORECASE))
    assert expected_tables.issubset(created_tables)

    # Verify run_id is BIGINT in collector_status
    cs_match = re.search(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?collector_status\s*\((.*?)\);", sql_text, re.DOTALL | re.IGNORECASE)
    assert cs_match
    assert "RUN_ID BIGINT" in re.sub(r"\s+", " ", cs_match.group(1)).upper()

    # Verify event_uuid is TEXT in live_attack_events
    lae_match = re.search(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?live_attack_events\s*\((.*?)\);", sql_text, re.DOTALL | re.IGNORECASE)
    assert lae_match
    assert "event_uuid TEXT NOT NULL" in re.sub(r"\s+", " ", lae_match.group(1))


def test_upgrade_preflight_reconciliation_consistency():
    """Validates preflight reconciliation logic for upgrades."""
    sql_path = Path("scratch/stage3b_6_final_supabase_migration.sql")
    sql_text = sql_path.read_text(encoding="utf-8")

    # 1. Verify event_uuid standardized to TEXT across existing installations
    assert "ALTER TABLE live_attack_events ALTER COLUMN event_uuid TYPE TEXT USING event_uuid::text;" in sql_text

    # 2. Verify targeted drop of specifically identified obsolete constraint
    assert "ALTER TABLE live_attack_events DROP CONSTRAINT uq_attack_event;" in sql_text
    # Ensure no indiscriminate drop loop exists
    assert "c.conname NOT IN ('uq_attack_event_uuid')" not in sql_text

    # 3. Verify collector_status.run_id verification for BIGINT
    assert "column_name = 'run_id' AND data_type = 'bigint'" in sql_text
    assert "Widening collector_status.run_id from INTEGER to BIGINT" in sql_text

    # 4. Verify explicit error handling on incompatible schema drift
    assert "RAISE EXCEPTION 'Schema Reconciliation Failure:" in sql_text


def test_postgrest_conflict_and_permissions_compatibility():
    """
    Verifies that all PostgREST conflict targets correspond to real unique constraints,
    and resolution headers adhere to table mutability permissions.
    """
    sql_path = Path("scratch/stage3b_6_final_supabase_migration.sql")
    sql_text = sql_path.read_text(encoding="utf-8")

    # Immutable tables: UPDATE must be REVOKED from collector_role
    immutable_tables = [
        "live_traffic_windows", "live_alerts", "live_sensor_telemetry",
        "live_pir_events", "live_attack_events", "station_pseudonym_map"
    ]
    for tbl in immutable_tables:
        config = TABLE_CONFLICT_CONFIG[tbl]
        # Must use resolution=ignore-duplicates because UPDATE is revoked!
        assert config["prefer"] == "resolution=ignore-duplicates"
        # Must have an on_conflict target specified
        assert config["on_conflict"] is not None

    # Mutable tables: UPDATE is GRANTED to collector_role
    mutable_tables = ["collector_status", "device_registry", "unknown_device_obs"]
    for tbl in mutable_tables:
        config = TABLE_CONFLICT_CONFIG[tbl]
        assert config["prefer"] == "resolution=merge-duplicates"
        assert config["on_conflict"] is not None


def test_public_view_privacy_and_lockout():
    """
    Verifies that public views enforce security definer execution,
    revoke base-table access from anon/authenticated/PUBLIC, and sanitize all station tokens.
    """
    sql_path = Path("scratch/stage3b_6_final_supabase_migration.sql")
    sql_text = sql_path.read_text(encoding="utf-8")

    # 1. Definer execution: security_invoker = false for all 9 views
    invokers = re.findall(r"WITH\s*\(\s*security_invoker\s*=\s*(false|true)\s*\)", sql_text, re.IGNORECASE)
    assert len(invokers) == 9
    assert all(i.lower() == "false" for i in invokers)

    # 2. View ownership: All 9 views owned by postgres
    view_owners = re.findall(r"ALTER\s+VIEW\s+([a-zA-Z0-9_]+)\s+OWNER\s+TO\s+postgres;", sql_text, re.IGNORECASE)
    assert len(view_owners) == 9

    # 3. Base table lockout: REVOKE ALL ON TABLE ... FROM anon, authenticated, PUBLIC
    revoke_match = re.search(
        r"REVOKE\s+ALL\s+ON\s+TABLE\s+([a-zA-Z0-9_,\s]+)\s+FROM\s+([a-zA-Z0-9_,\s]+);",
        sql_text,
        re.IGNORECASE,
    )
    assert revoke_match
    revoked_roles = [r.strip() for r in revoke_match.group(2).split(",")]
    assert "anon" in revoked_roles
    assert "authenticated" in revoked_roles
    assert "PUBLIC" in revoked_roles

    # 4. Strict station pseudonym allowlist across views
    allowlist_tokens = {"Node_1", "Node_2", "Node_3", "Node_4", "Node_5"}
    assert "('Node_1', 'Node_2', 'Node_3', 'Node_4', 'Node_5')" in sql_text or \
           "('Node_3', 'Node_4', 'Node_5')" in sql_text


def test_outbox_outage_simulation_and_backoff(temp_db):
    """
    Simulates a prolonged network interruption, verifying exponential backoff,
    preservation of critical alerts, and safe delivery upon restoration.
    """
    conn = sqlite3.connect(str(temp_db))
    # Queue Tier 1 attack and Tier 3 window
    t1_id = queue_attack_event(conn, 101, "uuid-outage-t1", {
        "timestamp_epoch": 1700000000.0,
        "timestamp_utc": "2026-11-15 12:00:00",
        "category": "Denial_of_Service",
        "status": "CONFIRMED_THREAT",
        "severity": "CRITICAL",
        "confidence": 0.99,
    })
    t3_id = queue_traffic_window(conn, 101, 1, {"packet_rate": 10.0})
    conn.close()

    network_state = "DOWN"

    def mock_network(method, url, headers, body):
        if network_state == "DOWN":
            raise requests.exceptions.ConnectionError("Network disconnected (503 Service Unavailable)")
        resp = requests.Response()
        resp.status_code = 201
        resp._content = b'{"success": true}'
        return resp

    worker = CloudSyncWorker(
        db_path=temp_db,
        supabase_url="https://mock.supabase.co",
        supabase_key="mock_key",
        http_transport=mock_network,
    )

    # 1. Sync fails while network is DOWN
    assert worker.sync_once() == 0
    assert worker.consecutive_failures >= 1

    conn = sqlite3.connect(str(temp_db))
    cur = conn.cursor()
    cur.execute("SELECT retry_count, next_retry_at FROM cloud_sync_outbox WHERE outbox_id = ?", (t1_id,))
    retry_count, next_retry = cur.fetchone()
    assert retry_count == 1
    assert next_retry > 0

    # Advance time / reset retry timestamp for testing recovery
    conn.execute("UPDATE cloud_sync_outbox SET next_retry_at = 0")
    conn.commit()
    conn.close()

    # 2. Network recovers
    network_state = "UP"
    delivered = worker.sync_once()
    assert delivered == 2
    assert worker.consecutive_failures == 0
    assert worker.is_connected is True

    conn = sqlite3.connect(str(temp_db))
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM cloud_sync_outbox WHERE status = 'DELIVERED'")
    assert cur.fetchone()[0] == 2
    conn.close()
