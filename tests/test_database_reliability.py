"""
Database Write Reliability and Transaction Safety Tests (Stage 6.5.4)
File: tests/test_database_reliability.py

Verifies DEF-65-07 corrections:
  1. Transient SQLite locked/busy error followed by successful write.
  2. Persistent lock failure exhausting the retry limit.
  3. Non-transient database errors not being retried.
  4. Atomic rollback when alert persistence fails after window insertion.
  5. No duplicate records after retry.
  6. Correct windows_emitted count after failure and recovery.
  7. Correct sensor_records count after failure and recovery.
  8. Sensor telemetry remains functional after a transient database failure.
  9. Attack cooldown and event persistence remain consistent across failure/recovery.
  10. Worker supervision and collector behavior remain intact during DB errors.
"""

import sqlite3
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.init_live_database import init_live_database, get_live_db_connection
from src.live_collector import (
    LiveCollector,
    is_transient_db_lock_error,
    _insert_traffic_window,
    _insert_alert,
    _insert_attack_event,
    _insert_sensor_telemetry,
)
from src.attack_detector import (
    AttackCategory,
    AttackDetectionResult,
    DetectionStatus,
    Severity,
)


@pytest.fixture
def temp_db(tmp_path: Path) -> Path:
    db_file = tmp_path / "test_reliability.db"
    init_live_database(db_file, overwrite=True)
    return db_file


@pytest.fixture
def sample_window() -> Dict[str, Any]:
    return {
        "client_mac": "ca:34:ea:92:d3:9e",
        "node_id": "Node_3",
        "Node_Type": "Phone_Client",
        "Data_Label": "real_observed_traffic",
        "bin_start_timestamp": 1000.0,
        "bin_end_timestamp": 1001.0,
        "window_center_epoch": 1000.5,
        "Window_Start_UTC": "2026-11-10 12:00:00",
        "Window_End_UTC": "2026-11-10 12:00:01",
        "packet_count": 10,
        "mean_IAT": 0.1,
        "IAT_std": 0.02,
        "packet_rate": 10.0,
        "mean_packet_size": 250.0,
        "packet_size_std": 15.0,
        "score_primary": 0.25,
        "pred_primary": 1,
        "score_timing": 0.15,
        "pred_timing": 1,
        "timing_status": "ACTIVE",
        "pred_dual": 1,
        "dual_reason": "NORMAL_INLIER",
    }


@pytest.fixture
def anomalous_window(sample_window: Dict[str, Any]) -> Dict[str, Any]:
    w = dict(sample_window)
    w["pred_dual"] = -1
    w["pred_primary"] = -1
    w["dual_reason"] = "ANOMALY_PRIMARY_BURST_OR_SIZE"
    return w


def _create_collector(db_path: Path) -> LiveCollector:
    c = LiveCollector(
        interface_index=1,
        serial_port="COM6",
        db_path=db_path,
        no_sensors=False,
    )
    # Seed a run_id directly
    conn = get_live_db_connection(db_path)
    try:
        cur = conn.execute(
            "INSERT INTO collector_status (interface_index, status) VALUES (1, 'RUNNING')"
        )
        conn.commit()
        c._run_id = cur.lastrowid
    finally:
        conn.close()
    c._attack_table_present = True
    c.db_retry_initial_delay_sec = 0.01  # accelerate tests
    c.db_retry_backoff_factor = 2.0
    c.db_max_retries = 2
    return c


# ─────────────────────────────────────────────────────────────────────────────
# 1. Transient SQLite Locked Error Followed by Successful Write
# ─────────────────────────────────────────────────────────────────────────────
def test_transient_locked_error_followed_by_successful_write(temp_db, sample_window):
    collector = _create_collector(temp_db)
    attempts = 0
    orig_get_conn = get_live_db_connection

    def fail_once_then_succeed(path, read_only=False):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise sqlite3.OperationalError("database is locked")
        return orig_get_conn(path, read_only=read_only)

    with patch("src.live_collector.get_live_db_connection", side_effect=fail_once_then_succeed):
        success = collector._persist_window_with_retry(
            scored=sample_window,
            new_unknown=[],
            dos_results=[],
            stream_results=[],
            client_mac="ca:34:ea:92:d3:9e",
        )

    assert success is True
    assert attempts == 2
    assert collector.stats["windows_emitted"] == 1
    assert collector.stats["db_transient_write_retries"] == 1
    assert collector.stats["db_window_write_failures"] == 0

    # Verify row actually in database
    conn = get_live_db_connection(temp_db)
    try:
        cur = conn.execute("SELECT COUNT(*) FROM live_traffic_windows WHERE run_id = ?", (collector._run_id,))
        assert cur.fetchone()[0] == 1
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# 2. Persistent Lock Failure Exhausts Retry Limit
# ─────────────────────────────────────────────────────────────────────────────
def test_persistent_lock_failure_exhausts_retry_limit(temp_db, sample_window):
    collector = _create_collector(temp_db)
    attempts = 0

    def always_locked(path, read_only=False):
        nonlocal attempts
        attempts += 1
        raise sqlite3.OperationalError("database is locked")

    with patch("src.live_collector.get_live_db_connection", side_effect=always_locked):
        success = collector._persist_window_with_retry(
            scored=sample_window,
            new_unknown=[],
            dos_results=[],
            stream_results=[],
            client_mac="ca:34:ea:92:d3:9e",
        )

    assert success is False
    assert attempts == 3  # 1 initial + 2 retries
    assert collector.stats["windows_emitted"] == 0
    assert collector.stats["db_window_write_failures"] == 1
    assert collector.stats["db_transient_write_retries"] == 0

    # Database remains empty
    conn = get_live_db_connection(temp_db)
    try:
        cur = conn.execute("SELECT COUNT(*) FROM live_traffic_windows WHERE run_id = ?", (collector._run_id,))
        assert cur.fetchone()[0] == 0
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# 3. Non-Transient Database Errors Not Retried
# ─────────────────────────────────────────────────────────────────────────────
def test_non_transient_database_errors_not_retried(temp_db, sample_window):
    collector = _create_collector(temp_db)
    attempts = 0

    def non_transient_error(path, read_only=False):
        nonlocal attempts
        attempts += 1
        raise sqlite3.OperationalError("no such table: live_traffic_windows")

    with patch("src.live_collector.get_live_db_connection", side_effect=non_transient_error):
        success = collector._persist_window_with_retry(
            scored=sample_window,
            new_unknown=[],
            dos_results=[],
            stream_results=[],
            client_mac="ca:34:ea:92:d3:9e",
        )

    assert success is False
    assert attempts == 1  # Never retried!
    assert collector.stats["windows_emitted"] == 0
    assert collector.stats["db_window_write_failures"] == 1
    assert collector.stats["db_transient_write_retries"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# 4. Atomic Rollback When Alert Persistence Fails After Window Insertion
# ─────────────────────────────────────────────────────────────────────────────
def test_atomic_rollback_when_alert_persistence_fails(temp_db, anomalous_window):
    collector = _create_collector(temp_db)

    def fail_alert_insert(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked during alert insert")

    with patch("src.live_collector._insert_alert", side_effect=fail_alert_insert):
        success = collector._persist_window_with_retry(
            scored=anomalous_window,
            new_unknown=[],
            dos_results=[],
            stream_results=[],
            client_mac="ca:34:ea:92:d3:9e",
        )

    assert success is False
    # Atomic rollback ensures live_traffic_windows does NOT contain an orphaned row
    conn = get_live_db_connection(temp_db)
    try:
        cur_w = conn.execute("SELECT COUNT(*) FROM live_traffic_windows WHERE run_id = ?", (collector._run_id,))
        assert cur_w.fetchone()[0] == 0

        cur_a = conn.execute("SELECT COUNT(*) FROM live_alerts WHERE run_id = ?", (collector._run_id,))
        assert cur_a.fetchone()[0] == 0
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# 5. No Duplicate Records After Retry
# ─────────────────────────────────────────────────────────────────────────────
def test_no_duplicate_records_after_retry(temp_db, anomalous_window):
    collector = _create_collector(temp_db)
    dos_res = AttackDetectionResult(
        category=AttackCategory.DOS,
        status=DetectionStatus.CONFIRMED_THREAT,
        severity=Severity.HIGH,
        evidence={"verdict": "Volumetric flood", "packet_rate": 500.0},
        missing_fields=[],
        confidence=0.95,
        timestamp=1000.0,
        recommended_action="Rate limit client.",
    )

    commit_attempts = 0
    orig_connect = get_live_db_connection

    class ConnectionWrapper:
        def __init__(self, real_conn):
            self._real = real_conn

        def commit(self):
            nonlocal commit_attempts
            commit_attempts += 1
            if commit_attempts == 1:
                raise sqlite3.OperationalError("database is locked on commit")
            return self._real.commit()

        def rollback(self):
            return self._real.rollback()

        def close(self):
            return self._real.close()

        def execute(self, *args, **kwargs):
            return self._real.execute(*args, **kwargs)

        def __getattr__(self, item):
            return getattr(self._real, item)

    def fail_first_commit(path, read_only=False):
        real_conn = orig_connect(path, read_only=read_only)
        return ConnectionWrapper(real_conn)

    with patch("src.live_collector.get_live_db_connection", side_effect=fail_first_commit):
        success = collector._persist_window_with_retry(
            scored=anomalous_window,
            new_unknown=["00:aa:bb:cc:dd:ee"],
            dos_results=[dos_res],
            stream_results=[],
            client_mac="ca:34:ea:92:d3:9e",
        )

    assert success is True
    assert commit_attempts == 2
    assert collector.stats["windows_emitted"] == 1
    assert collector.stats["alerts_generated"] == 1
    assert collector.stats["unknown_devices_seen"] == 1
    assert collector.stats["attack_events_flagged"] == 1

    conn = get_live_db_connection(temp_db)
    try:
        # Exactly one window
        cur = conn.execute("SELECT COUNT(*) FROM live_traffic_windows WHERE run_id = ?", (collector._run_id,))
        assert cur.fetchone()[0] == 1

        # Exactly one alert
        cur = conn.execute("SELECT COUNT(*) FROM live_alerts WHERE run_id = ?", (collector._run_id,))
        assert cur.fetchone()[0] == 1

        # Exactly one unknown device
        cur = conn.execute("SELECT COUNT(*) FROM unknown_device_obs WHERE run_id = ?", (collector._run_id,))
        assert cur.fetchone()[0] == 1

        # Exactly one attack event
        cur = conn.execute("SELECT COUNT(*) FROM live_attack_events WHERE run_id = ?", (collector._run_id,))
        assert cur.fetchone()[0] == 1
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# 6. Correct windows_emitted Count After Failure and Recovery
# ─────────────────────────────────────────────────────────────────────────────
def test_correct_windows_emitted_count_after_failure_and_recovery(temp_db, sample_window):
    collector = _create_collector(temp_db)

    # Window 1: Persistent failure
    with patch("src.live_collector.get_live_db_connection", side_effect=sqlite3.OperationalError("database is locked")):
        assert collector._persist_window_with_retry(sample_window, [], [], [], "ca:34:ea:92:d3:9e") is False
    assert collector.stats["windows_emitted"] == 0
    assert collector.stats["db_window_write_failures"] == 1

    # Window 2: Transient failure, then succeeds on retry
    attempts = 0
    orig_conn = get_live_db_connection

    def fail_once(path, read_only=False):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise sqlite3.OperationalError("database is locked")
        return orig_conn(path, read_only=read_only)

    with patch("src.live_collector.get_live_db_connection", side_effect=fail_once):
        assert collector._persist_window_with_retry(sample_window, [], [], [], "ca:34:ea:92:d3:9e") is True
    assert collector.stats["windows_emitted"] == 1
    assert collector.stats["db_transient_write_retries"] == 1

    # Window 3: Immediate success
    assert collector._persist_window_with_retry(sample_window, [], [], [], "ca:34:ea:92:d3:9e") is True
    assert collector.stats["windows_emitted"] == 2

    # Database count matches collector stats exactly
    conn = get_live_db_connection(temp_db)
    try:
        cur = conn.execute("SELECT COUNT(*) FROM live_traffic_windows WHERE run_id = ?", (collector._run_id,))
        assert cur.fetchone()[0] == 2
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# 7. Correct sensor_records Count After Failure and Recovery
# ─────────────────────────────────────────────────────────────────────────────
def test_correct_sensor_records_count_after_failure_and_recovery(temp_db):
    collector = _create_collector(temp_db)
    payload_1 = {"node": "esp32_gateway", "seq": 1, "uptime_ms": 1000, "dht11": {"valid": 1, "temp_c": 24.5, "humidity": 55.0}, "pir": {"motion": 0}}
    payload_2 = {"node": "esp32_gateway", "seq": 2, "uptime_ms": 2000, "dht11": {"valid": 1, "temp_c": 24.6, "humidity": 55.2}, "pir": {"motion": 1}}
    payload_3 = {"node": "esp32_gateway", "seq": 3, "uptime_ms": 3000, "dht11": {"valid": 1, "temp_c": 24.7, "humidity": 55.4}, "pir": {"motion": 0}}

    # Sensor 1: Persistent failure
    with patch("src.live_collector.get_live_db_connection", side_effect=sqlite3.OperationalError("database is locked")):
        assert collector._persist_sensor_with_retry(payload_1, 1000.0) is False
    assert collector.stats["sensor_records"] == 0
    assert collector.stats["db_sensor_write_failures"] == 1

    # Sensor 2: Transient failure, then succeeds on retry
    attempts = 0
    orig_conn = get_live_db_connection

    def fail_once(path, read_only=False):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise sqlite3.OperationalError("database is locked")
        return orig_conn(path, read_only=read_only)

    with patch("src.live_collector.get_live_db_connection", side_effect=fail_once):
        assert collector._persist_sensor_with_retry(payload_2, 2000.0) is True
    assert collector.stats["sensor_records"] == 1
    assert collector.stats["db_transient_write_retries"] == 1

    # Sensor 3: Immediate success
    assert collector._persist_sensor_with_retry(payload_3, 3000.0) is True
    assert collector.stats["sensor_records"] == 2

    # Database count matches collector stats
    conn = get_live_db_connection(temp_db)
    try:
        cur = conn.execute("SELECT COUNT(*) FROM live_sensor_telemetry WHERE run_id = ?", (collector._run_id,))
        assert cur.fetchone()[0] == 2
        cur_pir = conn.execute("SELECT COUNT(*) FROM live_pir_events WHERE run_id = ?", (collector._run_id,))
        assert cur_pir.fetchone()[0] == 2
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# 8. Sensor Telemetry Remains Functional After Transient DB Failure
# ─────────────────────────────────────────────────────────────────────────────
def test_sensor_telemetry_functional_after_transient_failure(temp_db):
    collector = _create_collector(temp_db)
    line = '{"node":"esp32_gateway","seq":10,"uptime_ms":10000,"dht11":{"valid":1,"temp_c":25.0,"humidity":60.0},"pir":{"motion":1}}'

    attempts = 0
    orig_conn = get_live_db_connection

    def fail_once(path, read_only=False):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise sqlite3.OperationalError("database is locked")
        return orig_conn(path, read_only=read_only)

    with patch("src.live_collector.get_live_db_connection", side_effect=fail_once):
        ret = collector.process_serial_line(line)

    assert ret == "SENSOR_TELEMETRY"
    assert collector.stats["sensor_records"] == 1
    assert collector.stats["db_transient_write_retries"] == 1

    # Ingesting the same sequence again is ignored without crashing
    ret2 = collector.process_serial_line(line)
    assert ret2 == "SENSOR_TELEMETRY"
    assert collector.stats["sensor_records"] == 2

    conn = get_live_db_connection(temp_db)
    try:
        # Duplicate sequence ignored by UNIQUE constraint
        cur = conn.execute("SELECT COUNT(*) FROM live_sensor_telemetry WHERE run_id = ?", (collector._run_id,))
        assert cur.fetchone()[0] == 1
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# 9. Attack Cooldown and Event Persistence Remain Consistent Across Failure
# ─────────────────────────────────────────────────────────────────────────────
def test_attack_cooldown_and_event_persistence_consistency(temp_db, anomalous_window):
    collector = _create_collector(temp_db)
    collector.dos_cooldown_seconds = 60.0

    dos_res = AttackDetectionResult(
        category=AttackCategory.DOS,
        status=DetectionStatus.CONFIRMED_THREAT,
        severity=Severity.HIGH,
        evidence={"verdict": "Volumetric flood", "packet_rate": 500.0},
        missing_fields=[],
        confidence=0.95,
        timestamp=1000.0,
        recommended_action="Rate limit client.",
    )

    # 1. Permanent DB failure on window 1 -> cooldown MUST NOT be registered
    with patch("src.live_collector.get_live_db_connection", side_effect=sqlite3.OperationalError("database is locked")):
        assert collector._persist_window_with_retry(
            scored=anomalous_window,
            new_unknown=[],
            dos_results=[dos_res],
            stream_results=[],
            client_mac="ca:34:ea:92:d3:9e",
        ) is False

    dos_key = (collector._run_id, "ca:34:ea:92:d3:9e", None, AttackCategory.DOS.value)
    assert dos_key not in collector._dos_dedup_cache

    # 2. Subsequent window succeeds -> attack event is NOT suppressed, commits, and registers cooldown
    assert collector._persist_window_with_retry(
        scored=anomalous_window,
        new_unknown=[],
        dos_results=[dos_res],
        stream_results=[],
        client_mac="ca:34:ea:92:d3:9e",
    ) is True

    assert dos_key in collector._dos_dedup_cache
    assert collector.stats["attack_events_flagged"] == 1

    # 3. Third window immediately after -> suppressed by cooldown
    assert collector._persist_window_with_retry(
        scored=anomalous_window,
        new_unknown=[],
        dos_results=[dos_res],
        stream_results=[],
        client_mac="ca:34:ea:92:d3:9e",
    ) is True

    assert collector.stats["attack_events_cooldown_suppressed"] == 1
    assert collector.stats["attack_events_flagged"] == 1  # Unchanged!


# ─────────────────────────────────────────────────────────────────────────────
# 10. Worker Supervision and Collector Behavior Remain Intact During DB Errors
# ─────────────────────────────────────────────────────────────────────────────
def test_worker_supervision_and_collector_behavior_intact(temp_db):
    collector = _create_collector(temp_db)
    collector._net_thread = MagicMock(is_alive=lambda: True)
    collector._serial_thread = MagicMock(is_alive=lambda: True)

    # Heartbeat during transient DB error does not crash or corrupt state
    with patch("src.live_collector.get_live_db_connection", side_effect=sqlite3.OperationalError("database is locked")):
        collector._heartbeat()

    assert collector._status == "RUNNING"
    assert collector._net_worker_failed is False
    assert collector._serial_worker_failed is False

    # Immediate shutdown wait responsiveness
    start_time = time.monotonic()
    collector.db_retry_initial_delay_sec = 10.0  # long delay
    collector._stop_event.set()  # signal shutdown

    # Retry should immediately abort wait
    success = collector._persist_window_with_retry(
        scored={"client_mac": "test"},
        new_unknown=[],
        dos_results=[],
        stream_results=[],
        client_mac="test",
    )
    elapsed = time.monotonic() - start_time
    assert elapsed < 1.0
    assert success is False


# ─────────────────────────────────────────────────────────────────────────────
# 11. PRAGMA busy_timeout Configured on Every Connection (Stage 6.5.4.1)
# ─────────────────────────────────────────────────────────────────────────────
def test_pragma_busy_timeout_configured_on_every_connection_for_window(temp_db, sample_window):
    collector = _create_collector(temp_db)
    observed_timeouts = []
    orig_conn = get_live_db_connection

    class TrackingWrapper:
        def __init__(self, real):
            self._real = real

        def execute(self, sql, *args, **kwargs):
            res = self._real.execute(sql, *args, **kwargs)
            if "PRAGMA busy_timeout" in sql and "=" in sql:
                cur = self._real.execute("PRAGMA busy_timeout;")
                observed_timeouts.append(cur.fetchone()[0])
            return res

        def commit(self):
            return self._real.commit()

        def rollback(self):
            return self._real.rollback()

        def close(self):
            return self._real.close()

        def __getattr__(self, name):
            return getattr(self._real, name)

    def inspect_conn(path, read_only=False):
        conn = orig_conn(path, read_only=read_only)
        return TrackingWrapper(conn)

    with patch("src.live_collector.get_live_db_connection", side_effect=inspect_conn):
        success = collector._persist_window_with_retry(
            scored=sample_window,
            new_unknown=[],
            dos_results=[],
            stream_results=[],
            client_mac="ca:34:ea:92:d3:9e",
        )

    assert success is True
    assert len(observed_timeouts) >= 1
    assert all(t == 250 for t in observed_timeouts)


def test_pragma_busy_timeout_configured_on_every_connection_for_sensor(temp_db):
    collector = _create_collector(temp_db)
    payload = {"node": "esp32_gateway", "seq": 99, "uptime_ms": 99000, "dht11": {"valid": 1, "temp_c": 22.0, "humidity": 45.0}, "pir": {"motion": 0}}
    observed_timeouts = []
    orig_conn = get_live_db_connection

    class TrackingWrapper:
        def __init__(self, real):
            self._real = real

        def execute(self, sql, *args, **kwargs):
            res = self._real.execute(sql, *args, **kwargs)
            if "PRAGMA busy_timeout" in sql and "=" in sql:
                cur = self._real.execute("PRAGMA busy_timeout;")
                observed_timeouts.append(cur.fetchone()[0])
            return res

        def commit(self):
            return self._real.commit()

        def rollback(self):
            return self._real.rollback()

        def close(self):
            return self._real.close()

        def __getattr__(self, name):
            return getattr(self._real, name)

    def inspect_conn(path, read_only=False):
        conn = orig_conn(path, read_only=read_only)
        return TrackingWrapper(conn)

    with patch("src.live_collector.get_live_db_connection", side_effect=inspect_conn):
        success = collector._persist_sensor_with_retry(payload, time.time())

    assert success is True
    assert len(observed_timeouts) >= 1
    assert all(t == 250 for t in observed_timeouts)


# ─────────────────────────────────────────────────────────────────────────────
# 12. Failure While Setting PRAGMA Handled Safely and Connection Closed
# ─────────────────────────────────────────────────────────────────────────────
def test_pragma_failure_handled_safely_and_connection_closed(temp_db, sample_window):
    collector = _create_collector(temp_db)
    closed_connections = []
    orig_conn = get_live_db_connection

    class FailPragmaWrapper:
        def __init__(self, real):
            self._real = real

        def execute(self, sql, *args, **kwargs):
            if "PRAGMA busy_timeout" in sql:
                raise sqlite3.OperationalError("simulated pragma failure")
            return self._real.execute(sql, *args, **kwargs)

        def commit(self):
            return self._real.commit()

        def rollback(self):
            return self._real.rollback()

        def close(self):
            closed_connections.append(True)
            return self._real.close()

        def __getattr__(self, name):
            return getattr(self._real, name)

    def fail_pragma(path, read_only=False):
        conn = orig_conn(path, read_only=read_only)
        return FailPragmaWrapper(conn)

    with patch("src.live_collector.get_live_db_connection", side_effect=fail_pragma):
        success = collector._persist_window_with_retry(
            scored=sample_window,
            new_unknown=[],
            dos_results=[],
            stream_results=[],
            client_mac="ca:34:ea:92:d3:9e",
        )

    assert success is False
    assert len(closed_connections) >= 1  # Guaranteed closed
    assert collector.stats["windows_emitted"] == 0
    assert collector.stats["db_window_write_failures"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# 13. Real SQLite Database File Lock Timing Measurement (No Mocks)
# ─────────────────────────────────────────────────────────────────────────────
def test_real_sqlite_file_lock_elapsed_time_bounded(tmp_path, sample_window):
    """
    Directly locks a real SQLite database file using an external transaction
    and measures actual wall-clock elapsed time. Verifies the timeout is bounded
    to ~900ms rather than 30+ seconds.
    """
    db_file = tmp_path / "real_lock_test.db"
    init_live_database(db_file, overwrite=True)

    collector = LiveCollector(
        interface_index=1,
        serial_port="COM6",
        db_path=db_file,
        no_sensors=False,
    )
    conn_setup = get_live_db_connection(db_file)
    cur = conn_setup.execute("INSERT INTO collector_status (interface_index, status) VALUES (1, 'RUNNING')")
    conn_setup.commit()
    collector._run_id = cur.lastrowid
    conn_setup.close()

    collector.db_busy_timeout_ms = 250
    collector.db_retry_initial_delay_sec = 0.05
    collector.db_retry_backoff_factor = 2.0
    collector.db_max_retries = 2

    # Open connection 1 in exclusive transaction mode to lock the DB
    lock_conn = get_live_db_connection(db_file)
    lock_conn.execute("BEGIN EXCLUSIVE;")

    try:
        t0 = time.monotonic()
        # Attempt window persistence while DB is locked
        success = collector._persist_window_with_retry(
            scored=sample_window,
            new_unknown=[],
            dos_results=[],
            stream_results=[],
            client_mac="ca:34:ea:92:d3:9e",
        )
        t1 = time.monotonic()
        elapsed = t1 - t0

        assert success is False
        assert collector.stats["windows_emitted"] == 0
        assert collector.stats["db_window_write_failures"] == 1
        # Bounded between ~0.6s and ~2.5s (accounting for Windows I/O latency)
        # and strictly under 5.0s (never stalls for 30s!)
        assert 0.4 < elapsed < 4.0, f"Expected bounded duration around 1s, got {elapsed:.2f}s"

    finally:
        lock_conn.rollback()
        lock_conn.close()

    # Now that the lock is released, subsequent write succeeds immediately
    success_after = collector._persist_window_with_retry(
        scored=sample_window,
        new_unknown=[],
        dos_results=[],
        stream_results=[],
        client_mac="ca:34:ea:92:d3:9e",
    )
    assert success_after is True
    assert collector.stats["windows_emitted"] == 1

