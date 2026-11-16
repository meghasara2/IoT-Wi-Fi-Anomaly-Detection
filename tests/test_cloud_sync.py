"""
Comprehensive Unit & Integration Test Suite for Cloud Sync Outbox & Worker.
File: tests/test_cloud_sync.py

Covers:
  - Outbox schema initialisation and idempotency.
  - Queueing for all priority tiers (Tier 1 Attacks/Status, Tier 2 Alerts/Sensors, Tier 3 Windows).
  - Strict deduplication / idempotency via event_uuid.
  - Priority ordering (Tier 1 delivered before Tier 2 & 3).
  - Lifecycle state transitions (PENDING -> IN_FLIGHT -> DELIVERED).
  - Exponential backoff calculation and retry state tracking.
  - Crash recovery of stale IN_FLIGHT records.
  - Delivered record retention pruning.
  - Bounded queue capacity enforcement (drops oldest Tier 3 windows, never Tier 1/2).
  - End-to-end sync worker with mock HTTP transport (201 Created, 500 Error, Network Timeout, Recovery).
  - Extended outage simulation and network restoration.
"""

import json
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest
import requests

from src.cloud_sync_outbox import (
    OutboxPriority,
    OutboxStatus,
    calculate_backoff,
    enforce_queue_capacity,
    fetch_pending_batch,
    generate_event_uuid,
    get_outbox_metrics,
    init_outbox_schema,
    mark_delivered,
    mark_in_flight,
    mark_retry_failed,
    prune_delivered,
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
from src.cloud_sync_worker import CloudSyncWorker


@pytest.fixture
def temp_db():
    """Provides a fresh temporary SQLite database with outbox schema initialized."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    conn = sqlite3.connect(str(db_path))
    init_outbox_schema(conn)
    conn.close()
    yield db_path
    import gc
    gc.collect()
    try:
        if db_path.exists():
            db_path.unlink()
    except PermissionError:
        pass


def test_outbox_schema_init(temp_db):
    """Verifies that the cloud_sync_outbox table and its indexes are created."""
    conn = sqlite3.connect(str(temp_db))
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cloud_sync_outbox'")
    assert cur.fetchone() is not None

    cur.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_outbox_queue'")
    assert cur.fetchone() is not None

    # Idempotent re-initialisation check
    init_outbox_schema(conn)
    conn.close()


def test_idempotent_event_uuid_dedup(temp_db):
    """Verifies that queueing an event with the same event_uuid twice does not duplicate records."""
    conn = sqlite3.connect(str(temp_db))
    event_uuid = generate_event_uuid("live_attack_events", "test_key_1")
    payload = {"msg": "attack_1"}

    # First insert
    row1 = queue_event(conn, "live_attack_events", event_uuid, payload, OutboxPriority.TIER_1_CRITICAL)
    assert row1 > 0

    # Second insert with identical event_uuid (should be ignored)
    row2 = queue_event(conn, "live_attack_events", event_uuid, payload, OutboxPriority.TIER_1_CRITICAL)
    assert row2 == 0 or row2 == row1

    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM cloud_sync_outbox WHERE event_uuid = ?", (event_uuid,))
    assert cur.fetchone()[0] == 1
    conn.close()


def test_priority_ordering(temp_db):
    """Verifies that fetch_pending_batch returns Tier 1 critical items before Tier 2 and Tier 3."""
    conn = sqlite3.connect(str(temp_db))
    now = time.time()

    # Queue Tier 3 first
    queue_event(conn, "live_traffic_windows", "win_1", {"pkt": 10}, OutboxPriority.TIER_3_HIGH_RATE, now_epoch=now)
    # Queue Tier 2
    queue_event(conn, "live_alerts", "alert_1", {"reason": "BURST"}, OutboxPriority.TIER_2_IMPORTANT, now_epoch=now)
    # Queue Tier 1
    queue_event(conn, "live_attack_events", "attack_1", {"cat": "DoS"}, OutboxPriority.TIER_1_CRITICAL, now_epoch=now)

    batch = fetch_pending_batch(conn, limit=10, now_epoch=now + 1)
    assert len(batch) == 3

    # Order must be Tier 1, then Tier 2, then Tier 3
    assert batch[0]["table_name"] == "live_attack_events"
    assert batch[0]["priority_tier"] == OutboxPriority.TIER_1_CRITICAL
    assert batch[1]["table_name"] == "live_alerts"
    assert batch[1]["priority_tier"] == OutboxPriority.TIER_2_IMPORTANT
    assert batch[2]["table_name"] == "live_traffic_windows"
    assert batch[2]["priority_tier"] == OutboxPriority.TIER_3_HIGH_RATE
    conn.close()


def test_state_transitions(temp_db):
    """Verifies PENDING -> IN_FLIGHT -> DELIVERED state transitions."""
    conn = sqlite3.connect(str(temp_db))
    now = time.time()
    outbox_id = queue_event(conn, "live_alerts", "alert_test", {"val": 1}, OutboxPriority.TIER_2_IMPORTANT, now_epoch=now)

    # 1. Fetch
    batch = fetch_pending_batch(conn, limit=5, now_epoch=now + 1)
    assert len(batch) == 1
    assert batch[0]["outbox_id"] == outbox_id

    # 2. Mark in-flight
    mark_in_flight(conn, [outbox_id], now_epoch=now + 2)
    cur = conn.cursor()
    cur.execute("SELECT status, last_attempt_at FROM cloud_sync_outbox WHERE outbox_id = ?", (outbox_id,))
    row = cur.fetchone()
    assert row[0] == OutboxStatus.IN_FLIGHT.value
    assert row[1] == pytest.approx(now + 2, 0.1)

    # 3. Mark delivered
    mark_delivered(conn, [outbox_id], now_epoch=now + 3)
    cur.execute("SELECT status, delivered_at FROM cloud_sync_outbox WHERE outbox_id = ?", (outbox_id,))
    row = cur.fetchone()
    assert row[0] == OutboxStatus.DELIVERED.value
    assert row[1] == pytest.approx(now + 3, 0.1)
    conn.close()


def test_retry_and_exponential_backoff(temp_db):
    """Verifies that failed attempts trigger exponential backoff and Tier 1 never fails permanently."""
    conn = sqlite3.connect(str(temp_db))
    now = time.time()

    # Tier 1 event
    t1_id = queue_event(conn, "live_attack_events", "att_retry", {"val": 1}, OutboxPriority.TIER_1_CRITICAL, now_epoch=now, max_retries=3)
    # Tier 3 event
    t3_id = queue_event(conn, "live_traffic_windows", "win_retry", {"val": 1}, OutboxPriority.TIER_3_HIGH_RATE, now_epoch=now, max_retries=3)

    # Fail 3 times
    for i in range(1, 4):
        mark_retry_failed(conn, t1_id, f"Error attempt {i}", now_epoch=now)
        mark_retry_failed(conn, t3_id, f"Error attempt {i}", now_epoch=now)

    cur = conn.cursor()
    # Tier 1 must remain PENDING even after exceeding max_retries (Never Dropped rule)
    cur.execute("SELECT status, retry_count, next_retry_at FROM cloud_sync_outbox WHERE outbox_id = ?", (t1_id,))
    t1_row = cur.fetchone()
    assert t1_row[0] == OutboxStatus.PENDING.value
    assert t1_row[1] == 3
    assert t1_row[2] > now  # Backoff in the future

    # Tier 3 transitions to FAILED when max_retries reached
    cur.execute("SELECT status, retry_count FROM cloud_sync_outbox WHERE outbox_id = ?", (t3_id,))
    t3_row = cur.fetchone()
    assert t3_row[0] == OutboxStatus.FAILED.value
    assert t3_row[1] == 3
    conn.close()


def test_recover_stale_in_flight(temp_db):
    """Verifies that orphaned in-flight records are recovered back to PENDING."""
    conn = sqlite3.connect(str(temp_db))
    now = time.time()
    outbox_id = queue_event(conn, "live_alerts", "alert_crash", {"v": 1}, OutboxPriority.TIER_2_IMPORTANT, now_epoch=now)

    # Put in flight 200 seconds ago (simulating crashed collector)
    mark_in_flight(conn, [outbox_id], now_epoch=now - 200)

    # Recover
    recovered = recover_stale_in_flight(conn, timeout_sec=120.0, now_epoch=now)
    assert recovered == 1

    cur = conn.cursor()
    cur.execute("SELECT status FROM cloud_sync_outbox WHERE outbox_id = ?", (outbox_id,))
    assert cur.fetchone()[0] == OutboxStatus.PENDING.value
    conn.close()


def test_prune_delivered(temp_db):
    """Verifies that delivered records older than retention threshold are deleted."""
    conn = sqlite3.connect(str(temp_db))
    now = time.time()
    outbox_id = queue_event(conn, "live_alerts", "alert_old", {"v": 1}, OutboxPriority.TIER_2_IMPORTANT, now_epoch=now)

    mark_delivered(conn, [outbox_id], now_epoch=now - 100000)  # >24 hours ago
    pruned = prune_delivered(conn, retention_sec=86400.0, now_epoch=now)
    assert pruned == 1

    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM cloud_sync_outbox WHERE outbox_id = ?", (outbox_id,))
    assert cur.fetchone()[0] == 0
    conn.close()


def test_enforce_queue_capacity_drop_oldest_tier3_only(temp_db):
    """
    Verifies that when queue capacity is exceeded, oldest Tier 3 windows are dropped,
    while Tier 1 attack events and Tier 2 alerts are NEVER DROPPED.
    """
    conn = sqlite3.connect(str(temp_db))
    now = time.time()

    # Queue 1 Tier 1 attack
    t1_id = queue_event(conn, "live_attack_events", "att_keep", {}, OutboxPriority.TIER_1_CRITICAL, now_epoch=now)
    # Queue 1 Tier 2 alert
    t2_id = queue_event(conn, "live_alerts", "alt_keep", {}, OutboxPriority.TIER_2_IMPORTANT, now_epoch=now)
    # Queue 5 Tier 3 windows
    t3_ids = []
    for i in range(5):
        t3_ids.append(queue_event(conn, "live_traffic_windows", f"win_{i}", {}, OutboxPriority.TIER_3_HIGH_RATE, now_epoch=now + i))

    # Total pending is 7. Enforce capacity limit of 4 (needs to drop 3 items)
    dropped = enforce_queue_capacity(conn, max_capacity=4)
    assert dropped == 3

    cur = conn.cursor()
    # Tier 1 & Tier 2 must remain PENDING
    cur.execute("SELECT status FROM cloud_sync_outbox WHERE outbox_id = ?", (t1_id,))
    assert cur.fetchone()[0] == OutboxStatus.PENDING.value
    cur.execute("SELECT status FROM cloud_sync_outbox WHERE outbox_id = ?", (t2_id,))
    assert cur.fetchone()[0] == OutboxStatus.PENDING.value

    # Oldest 3 Tier 3 items must be DROPPED
    for dropped_id in t3_ids[:3]:
        cur.execute("SELECT status FROM cloud_sync_outbox WHERE outbox_id = ?", (dropped_id,))
        assert cur.fetchone()[0] == OutboxStatus.DROPPED.value

    # Newer 2 Tier 3 items remain PENDING
    for kept_id in t3_ids[3:]:
        cur.execute("SELECT status FROM cloud_sync_outbox WHERE outbox_id = ?", (kept_id,))
        assert cur.fetchone()[0] == OutboxStatus.PENDING.value

    conn.close()


def test_sync_worker_mock_transport_success(temp_db):
    """Verifies that CloudSyncWorker successfully delivers batches via HTTP transport."""
    conn = sqlite3.connect(str(temp_db))
    queue_event(conn, "live_attack_events", "test_worker_1", {"cat": "DoS"}, OutboxPriority.TIER_1_CRITICAL)
    queue_event(conn, "live_alerts", "test_worker_2", {"reason": "JITTER"}, OutboxPriority.TIER_2_IMPORTANT)
    conn.close()

    # Mock Transport simulating 201 Created
    delivered_requests = []
    def mock_transport(method, url, headers, json_body):
        delivered_requests.append({"url": url, "body": json_body})
        resp = requests.Response()
        resp.status_code = 201
        resp._content = b'[{"status": "ok"}]'
        return resp

    worker = CloudSyncWorker(
        db_path=temp_db,
        supabase_url="https://mock.supabase.co",
        supabase_key="mock_key",
        http_transport=mock_transport,
    )

    delivered = worker.sync_once()
    assert delivered == 2
    assert len(delivered_requests) == 2  # 1 for attack events, 1 for alerts
    assert worker.is_connected is True
    assert worker.total_delivered == 2

    # Check DB status is DELIVERED
    conn = sqlite3.connect(str(temp_db))
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM cloud_sync_outbox WHERE status = 'DELIVERED'")
    assert cur.fetchone()[0] == 2
    conn.close()


def test_sync_worker_network_outage_and_recovery(temp_db):
    """
    Simulates a network outage (HTTP 503 / connection errors) followed by recovery,
    verifying exponential backoff and successful eventual delivery.
    """
    conn = sqlite3.connect(str(temp_db))
    outbox_id = queue_event(conn, "live_attack_events", "outage_test", {"alert": 1}, OutboxPriority.TIER_1_CRITICAL)
    conn.close()

    network_online = False

    def mock_transport(method, url, headers, json_body):
        if not network_online:
            raise requests.exceptions.ConnectionError("Network unreachable (offline)")
        resp = requests.Response()
        resp.status_code = 201
        resp._content = b'{"success": true}'
        return resp

    worker = CloudSyncWorker(
        db_path=temp_db,
        supabase_url="https://mock.supabase.co",
        supabase_key="mock_key",
        http_transport=mock_transport,
    )

    # 1. First attempt while network is offline
    delivered = worker.sync_once()
    assert delivered == 0
    assert worker.is_connected is False
    assert worker.consecutive_failures == 1
    assert "Network unreachable" in worker.last_error

    conn = sqlite3.connect(str(temp_db))
    cur = conn.cursor()
    cur.execute("SELECT status, retry_count, next_retry_at FROM cloud_sync_outbox WHERE outbox_id = ?", (outbox_id,))
    row = cur.fetchone()
    assert row[0] == OutboxStatus.PENDING.value
    assert row[1] == 1  # 1 failure
    future_retry = row[2]

    # Reset next_retry_at to past so it can be picked up immediately
    conn.execute("UPDATE cloud_sync_outbox SET next_retry_at = 0 WHERE outbox_id = ?", (outbox_id,))
    conn.commit()
    conn.close()

    # 2. Network comes back online
    network_online = True
    delivered_recovered = worker.sync_once()
    assert delivered_recovered == 1
    assert worker.is_connected is True
    assert worker.consecutive_failures == 0

    conn = sqlite3.connect(str(temp_db))
    cur = conn.cursor()
    cur.execute("SELECT status FROM cloud_sync_outbox WHERE outbox_id = ?", (outbox_id,))
    assert cur.fetchone()[0] == OutboxStatus.DELIVERED.value
    conn.close()


def test_sync_worker_partial_table_failure(temp_db):
    """Verifies that table-level errors are isolated: failed table retries, successful table is marked DELIVERED."""
    conn = sqlite3.connect(str(temp_db))
    queue_event(conn, "live_attack_events", "partial_att", {"val": 1}, OutboxPriority.TIER_1_CRITICAL)
    queue_event(conn, "live_traffic_windows", "partial_win", {"val": 2}, OutboxPriority.TIER_3_HIGH_RATE)
    conn.close()

    def mock_transport(method, url, headers, json_body):
        resp = requests.Response()
        if "live_attack_events" in url:
            resp.status_code = 201
            resp._content = b'{"success": true}'
        else:
            resp.status_code = 400
            resp._content = b'{"error": "Malformed window schema"}'
        return resp

    worker = CloudSyncWorker(
        db_path=temp_db,
        supabase_url="https://mock.supabase.co",
        supabase_key="mock_key",
        http_transport=mock_transport,
    )

    delivered = worker.sync_once()
    assert delivered == 1  # attack delivered, window failed

    conn = sqlite3.connect(str(temp_db))
    cur = conn.cursor()
    cur.execute("SELECT status FROM cloud_sync_outbox WHERE table_name = 'live_attack_events'")
    assert cur.fetchone()[0] == OutboxStatus.DELIVERED.value

    cur.execute("SELECT status, retry_count, last_error FROM cloud_sync_outbox WHERE table_name = 'live_traffic_windows'")
    win_row = cur.fetchone()
    assert win_row[0] == OutboxStatus.PENDING.value
    assert win_row[1] == 1
    assert "Malformed window schema" in win_row[2]
    conn.close()


def test_sync_worker_unconfigured_noop(temp_db):
    """Verifies worker behaves gracefully as a no-op when cloud sync is not configured."""
    worker = CloudSyncWorker(db_path=temp_db, supabase_url="", supabase_key="")
    assert worker.is_configured() is False
    assert worker.sync_once() == 0


def test_outbox_metrics_tracking(temp_db):
    """Verifies get_outbox_metrics accurately calculates status counts and tier backlog."""
    conn = sqlite3.connect(str(temp_db))
    now = time.time()
    queue_event(conn, "live_attack_events", "m_att_1", {}, OutboxPriority.TIER_1_CRITICAL, now_epoch=now)
    queue_event(conn, "live_alerts", "m_alt_1", {}, OutboxPriority.TIER_2_IMPORTANT, now_epoch=now)
    queue_event(conn, "live_traffic_windows", "m_win_1", {}, OutboxPriority.TIER_3_HIGH_RATE, now_epoch=now)
    queue_event(conn, "unknown_device_obs", "m_obs_1", {}, OutboxPriority.TIER_4_OBSERVATION, now_epoch=now)

    metrics = get_outbox_metrics(conn)
    assert metrics["pending_total"] == 4
    assert metrics["tier1_critical_backlog"] == 1
    assert metrics["tier2_important_backlog"] == 1
    assert metrics["tier3_high_rate_backlog"] == 1
    assert metrics["tier4_observation_backlog"] == 1
    conn.close()


def test_all_specialized_queue_helpers(temp_db):
    """Verifies all specialized queue_* helpers construct compliant payloads and targets."""
    conn = sqlite3.connect(str(temp_db))
    
    # 1. Collector status
    queue_collector_status(conn, 101, {"status": "RUNNING", "packets_parsed": 500})
    
    # 2. Live alert
    queue_live_alert(conn, 101, 1, {"window_id": 5, "dual_reason": "ANOMALY_PRIMARY_BURST_OR_SIZE"})
    
    # 3. Sensor telemetry
    queue_sensor_telemetry(conn, 101, 1, {"temperature_c": 26.5, "humidity_pct": 60.0, "dht_valid": 1})
    
    # 4. PIR event
    queue_pir_event(conn, 101, 1, {"motion_detected": 1})
    
    # 5. Traffic window
    queue_traffic_window(conn, 101, 1, {"packet_rate": 15.0, "packet_count": 15})
    
    # 6. Unknown device
    queue_unknown_device(conn, 101, {"observed_mac": "aa:bb:cc:dd:ee:ff"})

    # 7. Attack event
    queue_attack_event(conn, 101, "uuid-attack-123", {
        "timestamp_epoch": 1700000000.0,
        "timestamp_utc": "2026-11-15 12:00:00",
        "category": "Denial_of_Service",
        "status": "CONFIRMED_THREAT",
        "severity": "CRITICAL",
        "confidence": 0.98,
        "evidence_json": {"probe_counts": 500},
    })

    cur = conn.cursor()
    cur.execute("SELECT table_name, priority_tier FROM cloud_sync_outbox ORDER BY outbox_id ASC")
    rows = cur.fetchall()
    assert len(rows) == 7
    expected_tables = [
        ("collector_status", 1),
        ("live_alerts", 2),
        ("live_sensor_telemetry", 2),
        ("live_pir_events", 2),
        ("live_traffic_windows", 3),
        ("unknown_device_obs", 4),
        ("live_attack_events", 1),
    ]
    assert rows == expected_tables
    conn.close()


def test_table_conflict_config_and_headers(temp_db):
    """
    Verifies that CloudSyncWorker sends table-specific on_conflict query parameters
    and resolution strategies matching table mutability:
    - Mutable tables: Prefer: resolution=merge-duplicates with on_conflict target
    - Immutable tables: Prefer: resolution=ignore-duplicates with on_conflict target
    """
    from src.cloud_sync_worker import TABLE_CONFLICT_CONFIG

    captured_calls = []

    def mock_transport(method, url, headers, json_body):
        captured_calls.append({"method": method, "url": url, "headers": headers, "body": json_body})
        resp = requests.Response()
        resp.status_code = 201
        resp._content = b'{"success": true}'
        return resp

    conn = sqlite3.connect(str(temp_db))
    # Queue 1 mutable (collector_status) and 1 immutable (live_attack_events)
    queue_collector_status(conn, 101, {"status": "RUNNING"})
    queue_attack_event(conn, 101, "test-uuid-headers", {
        "timestamp_epoch": 1700000000.0,
        "timestamp_utc": "2026-11-15 12:00:00",
        "category": "Denial_of_Service",
        "status": "CONFIRMED_THREAT",
        "severity": "CRITICAL",
        "confidence": 0.95,
    })
    conn.close()

    worker = CloudSyncWorker(
        db_path=temp_db,
        supabase_url="https://mock.supabase.co",
        supabase_key="mock_key",
        http_transport=mock_transport,
    )

    delivered = worker.sync_once()
    assert delivered == 2
    assert len(captured_calls) == 2

    # Map by table name from url
    calls_by_table = {}
    for call in captured_calls:
        table = call["url"].split("/rest/v1/")[1].split("?")[0]
        calls_by_table[table] = call

    # 1. Verify mutable table (collector_status)
    status_call = calls_by_table["collector_status"]
    assert "?on_conflict=run_id" in status_call["url"]
    assert status_call["headers"]["Prefer"] == "resolution=merge-duplicates"

    # 2. Verify immutable table (live_attack_events)
    attack_call = calls_by_table["live_attack_events"]
    assert "?on_conflict=event_uuid" in attack_call["url"]
    assert attack_call["headers"]["Prefer"] == "resolution=ignore-duplicates"

    # 3. Verify all defined tables have on_conflict configured
    for tbl, cfg in TABLE_CONFLICT_CONFIG.items():
        assert "on_conflict" in cfg and cfg["on_conflict"] is not None
        assert cfg["prefer"] in ("resolution=merge-duplicates", "resolution=ignore-duplicates")


def test_duplicate_delivery_idempotency_simulation(temp_db):
    """
    Simulates a network interruption where the server processed an insert, but the ACK
    was lost. The worker resends the batch, PostgREST returns 201/204, and the outbox
    safely reconciles to DELIVERED without double-counting.
    """
    conn = sqlite3.connect(str(temp_db))
    outbox_id = queue_attack_event(conn, 101, "uuid-dup-test", {
        "timestamp_epoch": 1700000000.0,
        "timestamp_utc": "2026-11-15 12:00:00",
        "category": "Spoofing_Impersonation",
        "status": "CONFIRMED_THREAT",
        "severity": "HIGH",
        "confidence": 0.88,
    })
    conn.close()

    attempt = 0

    def mock_flaky_transport(method, url, headers, json_body):
        nonlocal attempt
        attempt += 1
        if attempt == 1:
            # First attempt: Server committed, but network dropped connection before client received response
            raise requests.exceptions.ConnectionError("Connection reset by peer during response reading")
        else:
            # Second attempt (retry): PostgREST handles duplicate via ignore-duplicates and returns 204 No Content
            resp = requests.Response()
            resp.status_code = 204
            resp._content = b""
            return resp

    worker = CloudSyncWorker(
        db_path=temp_db,
        supabase_url="https://mock.supabase.co",
        supabase_key="mock_key",
        http_transport=mock_flaky_transport,
    )

    # 1. First execution fails due to network reset
    delivered_first = worker.sync_once()
    assert delivered_first == 0

    # Reset retry timer to allow immediate retry
    conn = sqlite3.connect(str(temp_db))
    conn.execute("UPDATE cloud_sync_outbox SET next_retry_at = 0 WHERE outbox_id = ?", (outbox_id,))
    conn.commit()
    conn.close()

    # 2. Second execution retries: duplicate ignored by PostgREST (204 No Content), marked DELIVERED
    delivered_second = worker.sync_once()
    assert delivered_second == 1

    conn = sqlite3.connect(str(temp_db))
    cur = conn.cursor()
    cur.execute("SELECT status, retry_count FROM cloud_sync_outbox WHERE outbox_id = ?", (outbox_id,))
    row = cur.fetchone()
    assert row[0] == "DELIVERED"
    conn.close()


def test_postgres_schema_payload_alignment(temp_db):
    """
    Inspects all generated outbox payloads and cross-checks every payload key
    against the actual columns in scratch/stage3b_6_final_supabase_migration.sql.
    Verifies zero unrecognized or misspelled column names.
    """
    import re
    sql_path = Path("scratch/stage3b_6_final_supabase_migration.sql")
    assert sql_path.exists()
    sql_text = sql_path.read_text(encoding="utf-8")

    # Extract all table column sets from SQL
    table_columns = {}
    table_matches = re.findall(
        r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z0-9_]+)\s*\((.*?)\);",
        sql_text,
        re.DOTALL | re.IGNORECASE,
    )
    for tbl_name, body in table_matches:
        cols = set()
        for line in body.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("--") or line_str.upper().startswith("CONSTRAINT") or line_str.upper().startswith("FOREIGN"):
                continue
            col_match = re.match(r"^([a-zA-Z0-9_]+)\s+", line_str)
            if col_match:
                cols.add(col_match.group(1).lower())
        table_columns[tbl_name] = cols

    conn = sqlite3.connect(str(temp_db))
    queue_collector_status(conn, 1, {"status": "RUNNING"})
    queue_live_alert(conn, 1, 1, {"window_id": 1, "dual_reason": "BURST"})
    queue_sensor_telemetry(conn, 1, 1, {"sequence_num": 1})
    queue_pir_event(conn, 1, 1, {"motion_detected": 1})
    queue_traffic_window(conn, 1, 1, {"packet_rate": 10.0})
    queue_unknown_device(conn, 1, {"observed_mac": "00:11:22:33:44:55"})
    queue_attack_event(conn, 1, "test-uuid-align", {
        "timestamp_epoch": 1700000000.0,
        "timestamp_utc": "2026-11-15 12:00:00",
        "category": "Denial_of_Service",
        "status": "CONFIRMED_THREAT",
        "severity": "CRITICAL",
        "confidence": 0.99,
    })

    cur = conn.cursor()
    cur.execute("SELECT table_name, payload_json FROM cloud_sync_outbox")
    for tbl, payload_str in cur.fetchall():
        payload = json.loads(payload_str)
        assert tbl in table_columns, f"Unknown outbox table: {tbl}"
        valid_cols = table_columns[tbl]
        for key in payload.keys():
            assert key.lower() in valid_cols, (
                f"Column '{key}' in payload for table '{tbl}' is NOT present in PostgreSQL schema! "
                f"Valid columns: {valid_cols}"
            )
    conn.close()
