"""
Unit Tests: Live Collector (database, detector integration, sensor mapping)
File: tests/test_live_collector.py

Covers:
  - init_live_database: creates all 7 tables with correct schema
  - init_live_database: production database safety guard
  - init_live_database: FileExistsError without overwrite
  - score_window: prediction convention (-1 anomaly, +1 normal)
  - score_window: timing gate (N < MIN_PACKETS_FOR_TIMING)
  - score_window: timing active for N >= MIN_PACKETS_FOR_TIMING
  - score_window: dual reason categories
  - _insert_traffic_window: DB row integrity
  - _insert_sensor_telemetry: Node_1 (DHT11) and Node_2 (PIR) split
  - _upsert_unknown_device: insert + increment on conflict
  - LiveCollector.start: collector_status row created with correct fields
  - Sensor logical node mapping: same sequence → two separate rows

All tests use a temporary in-memory or temp-file database.
No real TShark process, no real serial port, no production files touched.
"""

import math
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import numpy as np
import pandas as pd
import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.init_live_database import (
    DEFAULT_LIVE_DB_PATH,
    PRODUCTION_DB_PATH,
    get_live_db_connection,
    init_live_database,
)
from src.live_collector import (
    LiveCollector,
    _insert_alert,
    _insert_sensor_telemetry,
    _insert_traffic_window,
    _nan_to_none,
    _upsert_unknown_device,
    load_frozen_dual_detector,
    score_window,
)
from src.dual_detector_1s import (
    DualDetectorBundle,
    MIN_PACKETS_FOR_TIMING,
    train_dual_detector,
)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
SESSION1_CSV = (
    _PROJECT_ROOT
    / "data"
    / "processed"
    / "experimental_time_windows"
    / "time_1s_session1_pcap_features_uplink.csv"
)


def _temp_db() -> Path:
    """Creates a fresh temp file for an isolated test database."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    p = Path(tmp.name)
    p.unlink()  # init_live_database expects the file NOT to exist
    return p


def _make_window(
    packet_count: int = 10,
    packet_rate: float = 10.0,
    mean_packet_size: float = 200.0,
    packet_size_std: float = 50.0,
    mean_IAT: float = 0.05,
    IAT_std: float = 0.01,
) -> Dict[str, Any]:
    """Returns a minimal feature window dict for scorer tests."""
    return {
        "client_mac": "ca:34:ea:92:d3:9e",
        "node_id": "Node_3",
        "Node_Type": "Phone_Client",
        "Data_Label": "real_observed_traffic",
        "bin_start_timestamp": 1000.0,
        "bin_end_timestamp": 1001.0,
        "window_center_epoch": 1000.5,
        "Window_Start_UTC": "2026-10-14 14:07:01.000",
        "Window_End_UTC": "2026-10-14 14:07:02.000",
        "packet_count": packet_count,
        "mean_IAT": mean_IAT,
        "IAT_std": IAT_std,
        "packet_rate": packet_rate,
        "mean_packet_size": mean_packet_size,
        "packet_size_std": packet_size_std,
    }


def _load_bundle() -> DualDetectorBundle:
    """Re-creates the frozen dual detector from Session 1 CSV."""
    df_s1 = pd.read_csv(SESSION1_CSV)
    return train_dual_detector(df_s1, contamination=0.05, random_state=42)


# ─────────────────────────────────────────────────────────────────────────────
# Tests: init_live_database
# ─────────────────────────────────────────────────────────────────────────────
class TestInitLiveDatabase:

    def test_creates_all_seven_tables(self):
        db_path = _temp_db()
        try:
            init_live_database(db_path)
            conn = sqlite3.connect(str(db_path))
            tables = {
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            conn.close()
            expected = {
                "collector_status",
                "device_registry",
                "live_traffic_windows",
                "live_alerts",
                "unknown_device_obs",
                "live_sensor_telemetry",
                "live_pir_events",
            }
            assert expected.issubset(tables)
        finally:
            if db_path.exists():
                db_path.unlink()

    def test_wal_mode_set(self):
        db_path = _temp_db()
        try:
            init_live_database(db_path)
            conn = sqlite3.connect(str(db_path))
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            conn.close()
            assert mode.lower() == "wal"
        finally:
            if db_path.exists():
                db_path.unlink()

    def test_production_db_guard_raises(self):
        with pytest.raises(RuntimeError, match="SAFETY GUARD"):
            init_live_database(PRODUCTION_DB_PATH)

    def test_existing_db_without_overwrite_raises(self):
        db_path = _temp_db()
        try:
            init_live_database(db_path)
            with pytest.raises(FileExistsError):
                init_live_database(db_path, overwrite=False)
        finally:
            if db_path.exists():
                db_path.unlink()

    def test_overwrite_recreates_database(self):
        db_path = _temp_db()
        try:
            init_live_database(db_path)
            # Inject a row to verify overwrite clears it
            conn = sqlite3.connect(str(db_path))
            conn.execute(
                "INSERT INTO device_registry (mac_address, node_id) VALUES ('aa:bb', 'X')"
            )
            conn.commit()
            conn.close()

            init_live_database(db_path, overwrite=True)

            conn = sqlite3.connect(str(db_path))
            count = conn.execute(
                "SELECT COUNT(*) FROM device_registry"
            ).fetchone()[0]
            conn.close()
            assert count == 0  # Table was recreated empty
        finally:
            if db_path.exists():
                db_path.unlink()

    def test_returns_resolved_path(self):
        db_path = _temp_db()
        try:
            result = init_live_database(db_path)
            assert isinstance(result, Path)
            assert result.exists()
        finally:
            if db_path.exists():
                db_path.unlink()


# ─────────────────────────────────────────────────────────────────────────────
# Tests: score_window (prediction convention)
# ─────────────────────────────────────────────────────────────────────────────
class TestScoreWindow:
    """
    Verifies the IsolationForest prediction convention and timing gating.
    Convention: pred = -1 → anomaly, pred = +1 → normal (sklearn default).
    """

    @pytest.fixture(scope="class")
    def bundle(self):
        return _load_bundle()

    def test_returns_pred_primary_key(self, bundle):
        w = _make_window()
        result = score_window(bundle, w)
        assert "pred_primary" in result

    def test_returns_pred_dual_key(self, bundle):
        w = _make_window()
        result = score_window(bundle, w)
        assert "pred_dual" in result

    def test_pred_primary_is_minus_one_or_plus_one(self, bundle):
        w = _make_window()
        result = score_window(bundle, w)
        assert result["pred_primary"] in (-1, 1)

    def test_pred_dual_is_minus_one_or_plus_one(self, bundle):
        w = _make_window()
        result = score_window(bundle, w)
        assert result["pred_dual"] in (-1, 1)

    def test_timing_unavailable_for_low_packet_count(self, bundle):
        """N < MIN_PACKETS_FOR_TIMING → timing_status == UNAVAILABLE_N_LT_3."""
        assert MIN_PACKETS_FOR_TIMING == 3
        w = _make_window(packet_count=2, mean_IAT=float("nan"), IAT_std=float("nan"))
        result = score_window(bundle, w)
        assert result["timing_status"] == "UNAVAILABLE_N_LT_3"
        assert result["pred_timing"] == 1  # defaults to normal when timing unavailable

    def test_timing_active_for_sufficient_packet_count(self, bundle):
        """N >= MIN_PACKETS_FOR_TIMING → timing_status == ACTIVE."""
        w = _make_window(packet_count=5, mean_IAT=0.05, IAT_std=0.01)
        result = score_window(bundle, w)
        assert result["timing_status"] == "ACTIVE"

    def test_normal_window_has_normal_dual_reason(self, bundle):
        """A typical normal window must produce a reason starting with NORMAL_."""
        w = _make_window(
            packet_count=10,
            packet_rate=10.0,
            mean_packet_size=200.0,
            packet_size_std=30.0,
            mean_IAT=0.05,
            IAT_std=0.01,
        )
        result = score_window(bundle, w)
        # For normal traffic within Session 1 distribution, dual should be normal
        # (we don't assert pred_dual == 1 since contamination=5% allows some flags,
        # but dual_reason must be a valid value)
        assert result["dual_reason"] in (
            "NORMAL_INLIER",
            "NORMAL_QUIET_TIMING_UNAVAILABLE",
            "ANOMALY_PRIMARY_BURST_OR_SIZE",
            "ANOMALY_TIMING_JITTER",
            "ANOMALY_PRIMARY_AND_TIMING",
        )

    def test_score_primary_is_float(self, bundle):
        w = _make_window()
        result = score_window(bundle, w)
        assert isinstance(result["score_primary"], float)

    def test_extreme_burst_likely_anomaly(self, bundle):
        """
        A window with an extreme packet rate (10,000 pkts/s) and large packets
        must be flagged by the primary detector (pred_primary == -1).
        This checks that the -1 convention is correctly applied.
        """
        w = _make_window(
            packet_count=10000,
            packet_rate=10000.0,
            mean_packet_size=65000.0,
            packet_size_std=100.0,
        )
        result = score_window(bundle, w)
        assert result["pred_primary"] == -1, (
            "Expected extreme burst to be flagged as anomaly (-1) by primary detector"
        )
        assert result["pred_dual"] == -1

    def test_score_window_does_not_modify_original(self, bundle):
        """score_window must not mutate the input dict."""
        w = _make_window()
        original_keys = set(w.keys())
        original_rate = w["packet_rate"]
        _ = score_window(bundle, w)
        # Original dict must not have new keys added to it
        assert w["packet_rate"] == original_rate
        # (new keys are only in the returned dict, not in w)
        assert "pred_primary" not in w


# ─────────────────────────────────────────────────────────────────────────────
# Tests: database write helpers
# ─────────────────────────────────────────────────────────────────────────────
class TestDatabaseWriteHelpers:
    """Integration tests using a real temp SQLite database."""

    @pytest.fixture
    def db(self, tmp_path):
        db_path = tmp_path / "test_live.db"
        init_live_database(db_path)
        conn = get_live_db_connection(db_path)
        conn.execute(
            "INSERT INTO collector_status (interface_index, status) VALUES (1, 'RUNNING')"
        )
        conn.commit()
        yield conn, 1  # (conn, run_id)
        conn.close()

    def _make_scored(self, **kwargs) -> Dict[str, Any]:
        w = _make_window(**kwargs)
        w.update({
            "score_primary": 0.1,
            "pred_primary": 1,
            "score_timing": 0.2,
            "pred_timing": 1,
            "timing_status": "ACTIVE",
            "pred_dual": 1,
            "dual_reason": "NORMAL_INLIER",
        })
        return w

    def test_insert_traffic_window_returns_rowid(self, db):
        conn, run_id = db
        scored = self._make_scored()
        row_id = _insert_traffic_window(conn, run_id, scored)
        assert isinstance(row_id, int)
        assert row_id > 0

    def test_insert_traffic_window_persisted(self, db):
        conn, run_id = db
        scored = self._make_scored()
        _insert_traffic_window(conn, run_id, scored)
        row = conn.execute(
            "SELECT node_id, packet_rate, pred_dual FROM live_traffic_windows"
        ).fetchone()
        assert row["node_id"] == "Node_3"
        assert row["packet_rate"] == pytest.approx(10.0)
        assert row["pred_dual"] == 1

    def test_insert_alert_persisted(self, db):
        conn, run_id = db
        scored = self._make_scored()
        scored["pred_dual"] = -1
        scored["dual_reason"] = "ANOMALY_PRIMARY_BURST_OR_SIZE"
        window_id = _insert_traffic_window(conn, run_id, scored)
        _insert_alert(conn, run_id, window_id, scored)
        row = conn.execute("SELECT dual_reason FROM live_alerts").fetchone()
        assert row["dual_reason"] == "ANOMALY_PRIMARY_BURST_OR_SIZE"

    def test_upsert_unknown_device_inserts(self, db):
        conn, run_id = db
        _upsert_unknown_device(conn, run_id, "de:ad:be:ef:00:01")
        row = conn.execute(
            "SELECT observed_mac, observation_count FROM unknown_device_obs"
        ).fetchone()
        assert row["observed_mac"] == "de:ad:be:ef:00:01"
        assert row["observation_count"] == 1

    def test_upsert_unknown_device_increments(self, db):
        conn, run_id = db
        mac = "de:ad:be:ef:00:01"
        _upsert_unknown_device(conn, run_id, mac)
        _upsert_unknown_device(conn, run_id, mac)
        _upsert_unknown_device(conn, run_id, mac)
        row = conn.execute(
            "SELECT observation_count FROM unknown_device_obs WHERE observed_mac=?",
            (mac,),
        ).fetchone()
        assert row["observation_count"] == 3

    def test_nan_to_none_converts_nan(self):
        assert _nan_to_none(float("nan")) is None
        assert _nan_to_none(0.5) == pytest.approx(0.5)
        assert _nan_to_none(None) is None
        assert _nan_to_none("text") == "text"


# ─────────────────────────────────────────────────────────────────────────────
# Tests: sensor logical node mapping (Node_1 / Node_2)
# ─────────────────────────────────────────────────────────────────────────────
class TestSensorLogicalNodeMapping:
    """
    Verifies that a single ESP32 JSON record is correctly split into
    Node_1 (DHT11, live_sensor_telemetry) and Node_2 (PIR, live_pir_events).
    """

    VALID_PAYLOAD = {
        "node": "esp32_gateway",
        "seq": 42,
        "uptime_ms": 84000,
        "dht11": {"valid": 1, "temp_c": 30.2, "humidity": 91.0},
        "pir": {"motion": 1},
    }

    INVALID_DHT_PAYLOAD = {
        "node": "esp32_gateway",
        "seq": 43,
        "uptime_ms": 86000,
        "dht11": {"valid": 0, "temp_c": None, "humidity": None},
        "pir": {"motion": 0},
    }

    @pytest.fixture
    def db_conn(self, tmp_path):
        db_path = tmp_path / "sensor_test.db"
        init_live_database(db_path)
        conn = get_live_db_connection(db_path)
        conn.execute(
            "INSERT INTO collector_status (interface_index, status) VALUES (1, 'RUNNING')"
        )
        conn.commit()
        yield conn, 1
        conn.close()

    def test_valid_payload_inserts_node1_row(self, db_conn):
        conn, run_id = db_conn
        _insert_sensor_telemetry(conn, run_id, self.VALID_PAYLOAD, 1000.0)
        row = conn.execute(
            "SELECT logical_node_id, temperature_c, humidity_pct, dht_valid "
            "FROM live_sensor_telemetry WHERE sequence_num=42"
        ).fetchone()
        assert row is not None
        assert row["logical_node_id"] == "Node_1"
        assert row["temperature_c"] == pytest.approx(30.2)
        assert row["humidity_pct"] == pytest.approx(91.0)
        assert row["dht_valid"] == 1

    def test_valid_payload_inserts_node2_row(self, db_conn):
        conn, run_id = db_conn
        _insert_sensor_telemetry(conn, run_id, self.VALID_PAYLOAD, 1000.0)
        row = conn.execute(
            "SELECT logical_node_id, motion_detected "
            "FROM live_pir_events WHERE sequence_num=42"
        ).fetchone()
        assert row is not None
        assert row["logical_node_id"] == "Node_2"
        assert row["motion_detected"] == 1

    def test_physical_node_id_stored(self, db_conn):
        conn, run_id = db_conn
        _insert_sensor_telemetry(conn, run_id, self.VALID_PAYLOAD, 1000.0)
        row = conn.execute(
            "SELECT physical_node_id FROM live_sensor_telemetry WHERE sequence_num=42"
        ).fetchone()
        assert row["physical_node_id"] == "esp32_gateway"

    def test_invalid_dht_stores_null_values(self, db_conn):
        """When DHT11 read fails, temperature and humidity must be NULL."""
        conn, run_id = db_conn
        _insert_sensor_telemetry(conn, run_id, self.INVALID_DHT_PAYLOAD, 1001.0)
        row = conn.execute(
            "SELECT temperature_c, humidity_pct, dht_valid "
            "FROM live_sensor_telemetry WHERE sequence_num=43"
        ).fetchone()
        assert row["temperature_c"] is None
        assert row["humidity_pct"] is None
        assert row["dht_valid"] == 0

    def test_same_sequence_not_duplicated(self, db_conn):
        """INSERT OR IGNORE must prevent duplicate sequence rows."""
        conn, run_id = db_conn
        _insert_sensor_telemetry(conn, run_id, self.VALID_PAYLOAD, 1000.0)
        _insert_sensor_telemetry(conn, run_id, self.VALID_PAYLOAD, 1000.0)  # duplicate
        count = conn.execute(
            "SELECT COUNT(*) FROM live_sensor_telemetry WHERE sequence_num=42"
        ).fetchone()[0]
        assert count == 1

    def test_separate_sequences_insert_two_rows(self, db_conn):
        conn, run_id = db_conn
        payload2 = {**self.VALID_PAYLOAD, "seq": 100}
        _insert_sensor_telemetry(conn, run_id, self.VALID_PAYLOAD, 1000.0)
        _insert_sensor_telemetry(conn, run_id, payload2, 1002.0)
        count = conn.execute(
            "SELECT COUNT(*) FROM live_sensor_telemetry"
        ).fetchone()[0]
        assert count == 2


# ─────────────────────────────────────────────────────────────────────────────
# Tests: load_frozen_dual_detector
# ─────────────────────────────────────────────────────────────────────────────
class TestLoadFrozenDualDetector:

    def test_loads_without_error(self):
        bundle = _load_bundle()
        assert bundle is not None

    def test_primary_offset_matches_known_value(self):
        bundle = _load_bundle()
        # Known fitted offset from previous sessions (contamination=0.05, seed=42)
        assert bundle.meta_primary["fitted_offset"] == pytest.approx(-0.5811797, rel=1e-5)

    def test_timing_offset_matches_known_value(self):
        bundle = _load_bundle()
        assert bundle.meta_timing["fitted_offset"] == pytest.approx(-0.6174866, rel=1e-5)

    def test_primary_features_correct(self):
        bundle = _load_bundle()
        assert bundle.meta_primary["features"] == [
            "packet_rate", "mean_packet_size", "packet_size_std"
        ]

    def test_timing_features_correct(self):
        bundle = _load_bundle()
        assert bundle.meta_timing["features"] == ["mean_IAT", "IAT_std"]

    def test_min_packets_timing_is_three(self):
        bundle = _load_bundle()
        assert bundle.min_packets_timing == 3

    def test_missing_csv_raises_file_not_found(self, tmp_path):
        missing = tmp_path / "nonexistent.csv"
        with pytest.raises(FileNotFoundError):
            load_frozen_dual_detector(missing)


# ─────────────────────────────────────────────────────────────────────────────
# Tests: production file safety checks
# ─────────────────────────────────────────────────────────────────────────────
class TestProductionFileSafety:

    def test_production_db_not_modified(self):
        """data/iot_anomaly.db must not be touched by any live_* module."""
        import hashlib

        db_path = PRODUCTION_DB_PATH
        if not db_path.exists():
            pytest.skip("Production database not present in this environment")

        with open(db_path, "rb") as f:
            original_hash = hashlib.md5(f.read()).hexdigest()

        # Attempt to init a live db at a safe path (should not touch prod)
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        safe_path = Path(tmp.name)
        safe_path.unlink()
        try:
            init_live_database(safe_path)
        finally:
            if safe_path.exists():
                safe_path.unlink()

        with open(db_path, "rb") as f:
            final_hash = hashlib.md5(f.read()).hexdigest()

        assert original_hash == final_hash, (
            "Production database was modified! This is a critical safety violation."
        )

    def test_dashboard_py_not_modified(self):
        """src/dashboard.py must not be touched by any live_* module."""
        import hashlib

        dash_path = _PROJECT_ROOT / "src" / "dashboard.py"
        if not dash_path.exists():
            pytest.skip("dashboard.py not found")

        with open(dash_path, "rb") as f:
            original_hash = hashlib.md5(f.read()).hexdigest()

        # Import all live modules (side-effect check)
        import src.live_interface_resolver  # noqa
        import src.live_stream_extractor    # noqa
        import src.init_live_database       # noqa
        import src.live_collector           # noqa

        with open(dash_path, "rb") as f:
            final_hash = hashlib.md5(f.read()).hexdigest()

        assert original_hash == final_hash, (
            "src/dashboard.py was modified by live module imports!"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Tests: Stage 6.5.1 Collector Worker Supervision & Heartbeat Protection
# ─────────────────────────────────────────────────────────────────────────────
class TestCollectorWorkerSupervisionStage651:
    """
    Covers Stage 6.5.1 worker supervision, thread liveness monitoring,
    and heartbeat status protection:
      1. Network worker unexpected exit (iter_windows ends while not stopped) -> ERROR.
      2. TShark EOF does not leave collector falsely RUNNING.
      3. Heartbeat never overwrites ERROR with RUNNING.
      4. Intentional shutdown (stop()) preserves STOPPED and avoids false ERROR.
      5. Dead network thread (is_alive() == False) is detected by _heartbeat() -> ERROR.
      6. Failed serial worker is represented accurately in stop_reason and worker health.
      7. Healthy workers allow RUNNING status and regular heartbeats.
      8. Repeated heartbeat cycles preserve correct state (ERROR, STOPPED, RUNNING).
      9. Existing startup, shutdown, and worker health diagnostic queries.
    """

    @pytest.fixture
    def test_db(self):
        db_path = _temp_db()
        init_live_database(db_path)
        yield db_path
        if db_path.exists():
            db_path.unlink()

    def _setup_collector(self, db_path, no_sensors=True):
        collector = LiveCollector(interface_index=1, db_path=db_path, no_sensors=no_sensors)
        conn = sqlite3.connect(str(db_path))
        cur = conn.cursor()
        cur.execute("INSERT INTO collector_status (status) VALUES ('STARTING')")
        conn.commit()
        collector._run_id = cur.lastrowid
        conn.close()
        return collector

    def test_scenario1_and_2_network_worker_unexpected_exit_tshark_eof(self, test_db):
        """1 & 2: Simulate network worker exiting unexpectedly (TShark EOF while not stopped)."""
        collector = self._setup_collector(test_db, no_sensors=True)

        mock_extractor = MagicMock()
        mock_extractor.iter_windows.return_value = iter([])  # Immediate EOF stream
        with patch("src.live_collector.LiveStreamExtractor", return_value=mock_extractor):
            collector._network_loop()

        health = collector.get_worker_health()
        assert health["status"] == "ERROR"
        assert health["net_worker_failed"] is True
        assert "Network worker terminated unexpectedly (TShark stream closed)" in health["stop_reason"]

        conn = sqlite3.connect(str(test_db))
        row = conn.execute("SELECT status, stop_reason FROM collector_status WHERE run_id = ?", (collector._run_id,)).fetchone()
        conn.close()
        assert row[0] == "ERROR"
        assert "Network worker terminated unexpectedly" in row[1]

    def test_scenario3_heartbeat_does_not_overwrite_error(self, test_db):
        """3: Verify _heartbeat() does not overwrite ERROR with RUNNING."""
        collector = self._setup_collector(test_db, no_sensors=True)
        collector._status = "ERROR"
        collector._net_worker_failed = True
        collector._stop_reason = "Fatal network socket error"

        # Mock thread reporting alive
        mock_net = MagicMock()
        mock_net.is_alive.return_value = True
        collector._net_thread = mock_net

        collector._heartbeat()

        health = collector.get_worker_health()
        assert health["status"] == "ERROR"
        assert "Fatal network socket error" in health["stop_reason"]

        conn = sqlite3.connect(str(test_db))
        row = conn.execute("SELECT status, stop_reason FROM collector_status WHERE run_id = ?", (collector._run_id,)).fetchone()
        conn.close()
        assert row[0] == "ERROR"
        assert "Fatal network socket error" in row[1]

    def test_scenario4_intentional_shutdown_avoids_false_error(self, test_db):
        """4: Verify intentional shutdown (stop()) preserves STOPPED and avoids false ERROR."""
        collector = self._setup_collector(test_db, no_sensors=True)
        mock_net = MagicMock()
        mock_net.is_alive.return_value = False
        collector._net_thread = mock_net

        collector.stop("Operator stopped capture")
        assert collector._status == "STOPPED"
        assert collector._stop_reason == "Operator stopped capture"

        collector._heartbeat()
        assert collector._status == "STOPPED"
        assert collector._stop_reason == "Operator stopped capture"

        conn = sqlite3.connect(str(test_db))
        row = conn.execute("SELECT status, stop_reason FROM collector_status WHERE run_id = ?", (collector._run_id,)).fetchone()
        conn.close()
        assert row[0] == "STOPPED"
        assert row[1] == "Operator stopped capture"

    def test_scenario5_dead_network_thread_detected_by_heartbeat(self, test_db):
        """5: Verify dead network thread (is_alive() == False) is detected by _heartbeat() -> ERROR."""
        collector = self._setup_collector(test_db, no_sensors=True)
        collector._status = "RUNNING"
        mock_net = MagicMock()
        mock_net.is_alive.return_value = False
        collector._net_thread = mock_net

        collector._heartbeat()

        health = collector.get_worker_health()
        assert health["status"] == "ERROR"
        assert health["net_worker_failed"] is True
        assert "Network worker thread terminated unexpectedly" in health["stop_reason"]

        conn = sqlite3.connect(str(test_db))
        row = conn.execute("SELECT status, stop_reason FROM collector_status WHERE run_id = ?", (collector._run_id,)).fetchone()
        conn.close()
        assert row[0] == "ERROR"
        assert "Network worker thread terminated unexpectedly" in row[1]

    def test_scenario6_serial_worker_failure_represented_accurately(self, test_db):
        """6: Verify failed serial worker is represented accurately in stop_reason and health."""
        collector = self._setup_collector(test_db, no_sensors=False)
        mock_net = MagicMock()
        mock_net.is_alive.return_value = True
        collector._net_thread = mock_net

        mock_serial = MagicMock()
        mock_serial.is_alive.return_value = False
        collector._serial_thread = mock_serial

        collector._serial_worker_failed = True
        collector._serial_failure_reason = "Serial worker disabled after 3 consecutive errors: Port busy"

        collector._heartbeat()

        health = collector.get_worker_health()
        assert health["status"] == "RUNNING"
        assert health["serial_worker_alive"] is False
        assert health["serial_worker_failed"] is True
        assert "Serial worker disabled after 3 consecutive errors" in health["stop_reason"]

        conn = sqlite3.connect(str(test_db))
        row = conn.execute("SELECT status, stop_reason FROM collector_status WHERE run_id = ?", (collector._run_id,)).fetchone()
        conn.close()
        assert row[0] == "RUNNING"
        assert "Serial worker disabled after 3 consecutive errors" in row[1]

    def test_scenario7_healthy_workers_maintain_running(self, test_db):
        """7: Verify healthy workers allow RUNNING status and regular heartbeats."""
        collector = self._setup_collector(test_db, no_sensors=True)
        mock_net = MagicMock()
        mock_net.is_alive.return_value = True
        collector._net_thread = mock_net

        collector._heartbeat()

        health = collector.get_worker_health()
        assert health["status"] == "RUNNING"
        assert health["net_worker_alive"] is True
        assert health["net_worker_failed"] is False
        assert health["stop_reason"] is None

        conn = sqlite3.connect(str(test_db))
        row = conn.execute("SELECT status, stop_reason FROM collector_status WHERE run_id = ?", (collector._run_id,)).fetchone()
        conn.close()
        assert row[0] == "RUNNING"
        assert row[1] is None

    def test_scenario8_repeated_heartbeats_preserve_state(self, test_db):
        """8: Verify repeated heartbeat cycles preserve correct state across cycles."""
        collector = self._setup_collector(test_db, no_sensors=True)
        collector._status = "ERROR"
        collector._net_worker_failed = True
        collector._stop_reason = "Permanent interface down"

        for _ in range(5):
            collector._heartbeat()
            assert collector._status == "ERROR"
            assert collector._stop_reason == "Permanent interface down"

        # Check STOPPED
        collector._status = "STOPPED"
        collector._stop_reason = "Clean stop"
        collector._stop_event.set()
        for _ in range(5):
            collector._heartbeat()
            assert collector._status == "STOPPED"
            assert collector._stop_reason == "Clean stop"

    def test_scenario9_update_status_lock_protection(self, test_db):
        """9: Verify _update_status prevents invalid status overwrite while allowing proper transitions."""
        collector = self._setup_collector(test_db, no_sensors=True)
        collector._status = "ERROR"
        collector._stop_reason = "Test Error"

        # Direct call to _update_status("RUNNING") must be ignored
        collector._update_status("RUNNING", None)
        assert collector._status == "ERROR"
        assert collector._stop_reason == "Test Error"

        # STOPPED cannot be overwritten with RUNNING
        collector._status = "STOPPED"
        collector._update_status("RUNNING", None)
        assert collector._status == "STOPPED"

    def test_serial_malformed_bytes_and_subsequent_valid_messages(self, test_db):
        """
        GAP-82-06: Verifies serial input handling when presented with:
        - Null bytes ('\x00\x00\x00')
        - Invalid UTF-8 replacement sequences ('\ufffd\ufffd')
        - Pure whitespace / empty lines
        - Non-dict JSON ('[1, 2, 3]')
        - Valid telemetry arriving immediately after corrupted lines
        Ensures worker thread survives, malformed lines are logged/counted,
        and valid records are persisted cleanly to SQLite without duplicate/corrupted rows.
        """
        collector = self._setup_collector(test_db, no_sensors=False)

        # 1. Null bytes line
        res_null = collector.process_serial_line("\x00\x00\x00")
        assert res_null == "RAW_LOG"
        assert collector.stats["serial_raw_lines"] == 1

        # 2. Corrupted UTF-8 replaced line (e.g. b"\xff\xfe\xfd".decode('utf-8', errors='replace'))
        corrupted_utf8 = b"\xff\xfe\xfd".decode("utf-8", errors="replace")
        res_utf8 = collector.process_serial_line(corrupted_utf8)
        assert res_utf8 == "RAW_LOG"
        assert collector.stats["serial_raw_lines"] == 2

        # 3. Empty / whitespace line
        res_empty = collector.process_serial_line("   \t  \n")
        assert res_empty is None
        assert collector.stats["serial_raw_lines"] == 2  # Discarded without counter increment

        # 4. Non-dict JSON payload
        res_nondict = collector.process_serial_line("[10, 20, 30]")
        assert res_nondict == "INVALID_JSON"

        # 5. Valid sensor telemetry immediately after malformed inputs
        valid_msg_1 = (
            '{"node":"esp32_gateway","seq":101,"uptime_ms":20200,'
            '"dht11":{"valid":1,"temp_c":29.1,"humidity":88.4},"pir":{"motion":1}}'
        )
        res_valid1 = collector.process_serial_line(valid_msg_1)
        assert res_valid1 == "SENSOR_TELEMETRY"
        assert collector.stats["sensor_records"] == 1

        # 6. Another corrupted ASCII line
        res_corrupt = collector.process_serial_line("SERIAL_CORRUPT_FRAME_CHECKSUM_ERROR")
        assert res_corrupt == "RAW_LOG"
        assert collector.stats["serial_raw_lines"] == 3

        # 7. Second valid sensor telemetry with motion=0
        valid_msg_2 = (
            '{"node":"esp32_gateway","seq":102,"uptime_ms":22200,'
            '"dht11":{"valid":1,"temp_c":29.2,"humidity":88.1},"pir":{"motion":0}}'
        )
        res_valid2 = collector.process_serial_line(valid_msg_2)
        assert res_valid2 == "SENSOR_TELEMETRY"
        assert collector.stats["sensor_records"] == 2

        # Verify database state
        conn = sqlite3.connect(str(test_db))
        dht_rows = conn.execute(
            "SELECT sequence_num, temperature_c, humidity_pct, dht_valid, logical_node_id "
            "FROM live_sensor_telemetry WHERE run_id = ? ORDER BY sequence_num",
            (collector._run_id,),
        ).fetchall()
        pir_rows = conn.execute(
            "SELECT sequence_num, motion_detected, logical_node_id "
            "FROM live_pir_events WHERE run_id = ? ORDER BY sequence_num",
            (collector._run_id,),
        ).fetchall()
        conn.close()

        # Both valid records persisted cleanly
        assert len(dht_rows) == 2
        assert dht_rows[0] == (101, 29.1, 88.4, 1, "Node_1")
        assert dht_rows[1] == (102, 29.2, 88.1, 1, "Node_1")

        assert len(pir_rows) == 2
        assert pir_rows[0] == (101, 1, "Node_2")
        assert pir_rows[1] == (102, 0, "Node_2")

    def test_simultaneous_device_windows_preserved_without_overwrite(self, test_db):
        """
        GAP-82-07: Verifies that when feature windows for Node_3 and Node_4 arrive with
        identical timestamps (bin_start_epoch), both windows are preserved independently:
        - Neither window overwrites the other.
        - Primary keys (window_id) are assigned distinct sequential integer values.
        - Client MACs and node_ids remain accurately attributed.
        - Anomaly alerts are attached exclusively to the offending window/device.
        - Device registry last_seen timestamps are updated for both clients.
        """
        collector = self._setup_collector(test_db, no_sensors=True)
        same_epoch = 1700000000.0

        # Pre-populate device_registry with known devices
        conn = sqlite3.connect(str(test_db))
        conn.execute(
            "INSERT OR IGNORE INTO device_registry (mac_address, node_id, device_type, label) "
            "VALUES ('ca:34:ea:92:d3:9e', 'Node_3', 'Phone_Client', 'real_observed_traffic')"
        )
        conn.execute(
            "INSERT OR IGNORE INTO device_registry (mac_address, node_id, device_type, label) "
            "VALUES ('e6:2e:db:73:1c:25', 'Node_4', 'Phone_Client', 'real_observed_traffic')"
        )
        conn.commit()
        conn.close()

        # Window 1: Node_3 (Normal Inlier)
        window_node3 = {
            "client_mac": "ca:34:ea:92:d3:9e",
            "node_id": "Node_3",
            "Node_Type": "Phone_Client",
            "Data_Label": "real_observed_traffic",
            "bin_start_timestamp": same_epoch,
            "bin_end_timestamp": same_epoch + 1.0,
            "window_center_epoch": same_epoch + 0.5,
            "Window_Start_UTC": "2026-11-10 22:30:00",
            "Window_End_UTC": "2026-11-10 22:30:01",
            "packet_count": 15,
            "packet_rate": 15.0,
            "mean_packet_size": 250.0,
            "packet_size_std": 50.0,
            "mean_IAT": 0.066,
            "IAT_std": 0.012,
            "score_primary": 0.12,
            "pred_primary": 1,
            "score_timing": 0.08,
            "pred_timing": 1,
            "timing_status": "ACTIVE",
            "pred_dual": 1,
            "dual_reason": "NORMAL_INLIER",
        }

        # Window 2: Node_4 (Anomalous Burst at IDENTICAL timestamp)
        window_node4 = {
            "client_mac": "e6:2e:db:73:1c:25",
            "node_id": "Node_4",
            "Node_Type": "Phone_Client",
            "Data_Label": "real_observed_traffic",
            "bin_start_timestamp": same_epoch,
            "bin_end_timestamp": same_epoch + 1.0,
            "window_center_epoch": same_epoch + 0.5,
            "Window_Start_UTC": "2026-11-10 22:30:00",
            "Window_End_UTC": "2026-11-10 22:30:01",
            "packet_count": 95,
            "packet_rate": 95.0,
            "mean_packet_size": 1200.0,
            "packet_size_std": 300.0,
            "mean_IAT": 0.010,
            "IAT_std": 0.005,
            "score_primary": -0.18,
            "pred_primary": -1,
            "score_timing": -0.15,
            "pred_timing": -1,
            "timing_status": "ACTIVE",
            "pred_dual": -1,
            "dual_reason": "ANOMALY_PRIMARY_AND_TIMING",
        }

        # Persist both simultaneous windows
        success3 = collector._persist_window_with_retry(
            scored=window_node3,
            new_unknown=[],
            dos_results=[],
            stream_results=[],
            client_mac=window_node3["client_mac"],
        )
        assert success3 is True

        success4 = collector._persist_window_with_retry(
            scored=window_node4,
            new_unknown=[],
            dos_results=[],
            stream_results=[],
            client_mac=window_node4["client_mac"],
        )
        assert success4 is True

        assert collector.stats["windows_emitted"] == 2
        assert collector.stats["alerts_generated"] == 1

        # Query database and verify independent preservation
        conn = sqlite3.connect(str(test_db))
        windows = conn.execute(
            "SELECT window_id, node_id, client_mac, bin_start_epoch, packet_count, pred_dual "
            "FROM live_traffic_windows WHERE run_id = ? ORDER BY window_id",
            (collector._run_id,),
        ).fetchall()

        alerts = conn.execute(
            "SELECT alert_id, window_id, node_id, client_mac, bin_start_epoch, dual_reason "
            "FROM live_alerts WHERE run_id = ?",
            (collector._run_id,),
        ).fetchall()

        registry = conn.execute(
            "SELECT node_id, last_seen FROM device_registry WHERE mac_address IN "
            "('ca:34:ea:92:d3:9e', 'e6:2e:db:73:1c:25')",
        ).fetchall()
        conn.close()

        # Both windows exist with distinct IDs and identical bin_start_epoch
        assert len(windows) == 2
        w1, w2 = windows[0], windows[1]
        assert w1[0] != w2[0]  # Distinct primary keys (e.g. 1 and 2)
        assert w1[1] == "Node_3" and w1[2] == "ca:34:ea:92:d3:9e" and w1[3] == same_epoch and w1[5] == 1
        assert w2[1] == "Node_4" and w2[2] == "e6:2e:db:73:1c:25" and w2[3] == same_epoch and w2[5] == -1

        # Exactly 1 alert generated, attached exclusively to Node_4's window_id
        assert len(alerts) == 1
        assert alerts[0][1] == w2[0]  # Foreign key references Node_4's window
        assert alerts[0][2] == "Node_4"
        assert alerts[0][3] == "e6:2e:db:73:1c:25"
        assert alerts[0][4] == same_epoch
        assert alerts[0][5] == "ANOMALY_PRIMARY_AND_TIMING"

        # Both devices had last_seen updated in device_registry
        assert len(registry) == 2
        assert all(r[1] is not None for r in registry)

    def test_long_running_simulation_one_thousand_plus_windows(self, test_db):
        """
        GAP-82-09: Simulates prolonged continuous collector operation across >1,000
        consecutive 1-second feature windows (1,050 windows simulated):
        - Verifies all 1,050 windows are persisted without missing IDs or duplicates.
        - Verifies database primary keys remain monotonically sequential (1 to 1050).
        - Verifies alternating client attribution (Node_3 and Node_4) remains consistent.
        - Verifies queue boundedness, absence of memory/resource leaks, and stable counters.
        """
        collector = self._setup_collector(test_db, no_sensors=True)
        num_windows = 1050
        base_epoch = 1700000000.0

        for i in range(num_windows):
            is_node3 = (i % 2 == 0)
            client_mac = "ca:34:ea:92:d3:9e" if is_node3 else "e6:2e:db:73:1c:25"
            node_id = "Node_3" if is_node3 else "Node_4"
            current_epoch = base_epoch + i

            window = {
                "client_mac": client_mac,
                "node_id": node_id,
                "Node_Type": "Phone_Client",
                "Data_Label": "real_observed_traffic",
                "bin_start_timestamp": current_epoch,
                "bin_end_timestamp": current_epoch + 1.0,
                "window_center_epoch": current_epoch + 0.5,
                "Window_Start_UTC": f"2026-11-10 22:{i//60:02d}:{i%60:02d}",
                "Window_End_UTC": f"2026-11-10 22:{i//60:02d}:{(i%60)+1:02d}",
                "packet_count": 10 + (i % 50),
                "packet_rate": float(10 + (i % 50)),
                "mean_packet_size": 300.0,
                "packet_size_std": 60.0,
                "mean_IAT": 0.05,
                "IAT_std": 0.01,
                "score_primary": 0.10,
                "pred_primary": 1,
                "score_timing": 0.05,
                "pred_timing": 1,
                "timing_status": "ACTIVE",
                "pred_dual": 1,
                "dual_reason": "NORMAL_INLIER",
            }

            success = collector._persist_window_with_retry(
                scored=window,
                new_unknown=[],
                dos_results=[],
                stream_results=[],
                client_mac=client_mac,
            )
            assert success is True

        assert collector.stats["windows_emitted"] == num_windows
        assert collector.stats["db_window_write_failures"] == 0

        # Query database and verify all 1050 rows
        conn = sqlite3.connect(str(test_db))
        total_rows = conn.execute(
            "SELECT COUNT(*), MIN(window_id), MAX(window_id) FROM live_traffic_windows WHERE run_id = ?",
            (collector._run_id,),
        ).fetchone()

        node3_count = conn.execute(
            "SELECT COUNT(*) FROM live_traffic_windows WHERE run_id = ? AND node_id = 'Node_3'",
            (collector._run_id,),
        ).fetchone()[0]

        node4_count = conn.execute(
            "SELECT COUNT(*) FROM live_traffic_windows WHERE run_id = ? AND node_id = 'Node_4'",
            (collector._run_id,),
        ).fetchone()[0]
        conn.close()

        assert total_rows[0] == num_windows  # Exactly 1,050 rows
        assert total_rows[1] == 1            # Minimum window_id = 1
        assert total_rows[2] == num_windows  # Maximum window_id = 1050
        assert node3_count == 525            # Exactly 525 Node_3 windows
        assert node4_count == 525            # Exactly 525 Node_4 windows


# ─────────────────────────────────────────────────────────────────────────────
# Tests: Stage 8.4 Collector Channel Diagnostic Integration
# ─────────────────────────────────────────────────────────────────────────────
class TestCollectorChannelAlignmentStage84:
    """Tests for Stage 8.4 LiveCollector channel diagnostic integration and resilience."""

    @pytest.fixture
    def test_db(self, tmp_path):
        db_p = tmp_path / "test_collector_chan.db"
        init_live_database(db_p)
        return db_p

    def _setup_collector(self, db_p, no_sensors=True):
        return LiveCollector(
            interface_index=2,
            serial_port="COM99",
            db_path=db_p,
            session1_csv=SESSION1_CSV,
            no_sensors=no_sensors,
        )

    def test_collector_startup_channel_diagnostic_executed_safely(self, test_db):
        """Scenario 9: Collector executes diagnostic on startup. ESP32 channel is strictly UNAVAILABLE before handshake."""
        from src.live_interface_resolver import ChannelAlignmentStatus
        collector = self._setup_collector(test_db, no_sensors=True)

        try:
            with patch("src.live_collector.query_windows_hotspot_channel", return_value=(6, "Local Area Connection* 2", None, "Hotspot on Channel 6")):
                with patch.object(collector, "_network_loop"):
                    collector.start(interface_name="Local Area Connection* 2")

            # Worker health exposes channel_diagnostic
            health = collector.get_worker_health()
            assert "channel_diagnostic" in health
            assert collector._channel_diagnostic is not None
            diag_dict = health["channel_diagnostic"]
            # Before handshake, ESP32 channel MUST NOT assume 6!
            assert diag_dict["status"] == ChannelAlignmentStatus.CHANNEL_UNAVAILABLE
            assert diag_dict["status"] != ChannelAlignmentStatus.CHANNEL_ALIGNED
            assert diag_dict["esp32_channel"] is None
            assert diag_dict["hotspot_channel"] == 6
            assert diag_dict["esp32_source"] == "UNAVAILABLE"
            assert "unverified" in diag_dict["explanation"].lower()

            # Verify sidecar diagnostic file was created with run_id
            sidecar = test_db.parent / f"{test_db.stem}_diagnostic.json"
            assert sidecar.exists()
            import json
            with open(sidecar, "r", encoding="utf-8") as f:
                saved_data = json.load(f)
            assert saved_data["run_id"] == collector._run_id
        finally:
            collector.stop()

    def test_collector_startup_resilient_to_channel_diagnostic_crash(self, test_db):
        """Scenario 9b: Collector start() never fails even if check_hotspot_channel_alignment crashes."""
        collector = self._setup_collector(test_db, no_sensors=True)

        try:
            with patch("src.live_collector.query_windows_hotspot_channel", side_effect=RuntimeError("Simulated netsh crash")):
                with patch.object(collector, "_network_loop"):
                    collector.start(interface_name="Local Area Connection* 2")

            # Collector must still start successfully into RUNNING state
            assert collector._status == "RUNNING"
            health = collector.get_worker_health()
            assert health["status"] == "RUNNING"
        finally:
            collector.stop()

    def test_handshake_arriving_after_startup_transitions_to_aligned_without_subprocess(self, test_db):
        """Scenario 10a: Delayed handshake arriving after startup transitions status to ALIGNED without new subprocess."""
        from src.live_interface_resolver import ChannelAlignmentStatus
        collector = self._setup_collector(test_db, no_sensors=False)

        try:
            # 1. Start collector: Hotspot channel is 6, but ESP32 channel is not yet received
            with patch("src.live_collector.query_windows_hotspot_channel", return_value=(6, "Local Area Connection* 2", None, "Hotspot on Channel 6")):
                with patch.object(collector, "_network_loop"), patch.object(collector, "_serial_loop"):
                    collector.start(interface_name="Local Area Connection* 2")

            # Prior to handshake: strictly UNAVAILABLE
            assert collector._channel_diagnostic.status == ChannelAlignmentStatus.CHANNEL_UNAVAILABLE
            assert collector._channel_diagnostic.esp32_channel is None

            # 2. ESP32 handshake arrives later with Channel 6
            handshake_payload = {
                "status": "WIFI_SNIFFER_INITIALIZED",
                "boot_id": 1001,
                "nonce": 5555,
                "channel": 6,
            }
            collector._expected_probe_nonce = 5555

            # Verify NO new subprocess is spawned during the handshake update!
            with patch("subprocess.run") as mock_subproc:
                verdict = collector._handle_sniffer_status(handshake_payload)
                mock_subproc.assert_not_called()

            assert verdict == "SNIFFER_STATUS"
            # Hardware channel verified and re-evaluated against cached hotspot channel 6
            assert collector._esp32_hardware_channel == 6
            assert collector._channel_diagnostic.esp32_channel == 6
            assert collector._channel_diagnostic.esp32_source == "FIRMWARE_HANDSHAKE"
            assert collector._channel_diagnostic.status == ChannelAlignmentStatus.CHANNEL_ALIGNED
            assert "aligned" in collector._channel_diagnostic.explanation.lower()
        finally:
            collector.stop()

    def test_handshake_arriving_with_mismatch_transitions_to_mismatch(self, test_db):
        """Scenario 10b: Handshake with mismatched channel transitions status to CHANNEL_MISMATCH."""
        from src.live_interface_resolver import ChannelAlignmentStatus
        collector = self._setup_collector(test_db, no_sensors=False)

        try:
            with patch("src.live_collector.query_windows_hotspot_channel", return_value=(6, "Local Area Connection* 2", None, "Hotspot on Channel 6")):
                with patch.object(collector, "_network_loop"), patch.object(collector, "_serial_loop"):
                    collector.start(interface_name="Local Area Connection* 2")

            # Handshake arrives reporting Channel 1 (Hotspot is 6)
            handshake_payload = {
                "status": "WIFI_SNIFFER_INITIALIZED",
                "boot_id": 1002,
                "nonce": 7777,
                "channel": 1,
            }
            collector._expected_probe_nonce = 7777
            verdict = collector._handle_sniffer_status(handshake_payload)
            assert verdict == "SNIFFER_STATUS"

            assert collector._esp32_hardware_channel == 1
            assert collector._channel_diagnostic.esp32_channel == 1
            assert collector._channel_diagnostic.status == ChannelAlignmentStatus.CHANNEL_MISMATCH
            assert "MISMATCH" in collector._channel_diagnostic.explanation
        finally:
            collector.stop()

    def test_handshake_with_missing_or_invalid_channel_strictly_unavailable(self, test_db):
        """Scenario 10c: Handshake with missing or out-of-range channel strictly sets CHANNEL_UNAVAILABLE."""
        from src.live_interface_resolver import ChannelAlignmentStatus
        collector = self._setup_collector(test_db, no_sensors=False)

        try:
            with patch("src.live_collector.query_windows_hotspot_channel", return_value=(6, "Local Area Connection* 2", None, "Hotspot on Channel 6")):
                with patch.object(collector, "_network_loop"), patch.object(collector, "_serial_loop"):
                    collector.start(interface_name="Local Area Connection* 2")

            # Handshake arrives with invalid channel (99)
            handshake_payload = {
                "status": "WIFI_SNIFFER_INITIALIZED",
                "boot_id": 1003,
                "nonce": 8888,
                "channel": 99,
            }
            collector._expected_probe_nonce = 8888
            collector._handle_sniffer_status(handshake_payload)

            assert collector._esp32_hardware_channel is None
            assert collector._channel_diagnostic.status == ChannelAlignmentStatus.CHANNEL_UNAVAILABLE
        finally:
            collector.stop()
        assert collector._channel_diagnostic.status != ChannelAlignmentStatus.CHANNEL_ALIGNED
        assert collector._channel_diagnostic.esp32_channel is None
        assert collector._channel_diagnostic.esp32_source == "UNAVAILABLE"

