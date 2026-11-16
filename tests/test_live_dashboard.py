"""
Stage 6.4.2 Validation: Live Dashboard Status Accuracy and ESP32 Diagnostics Tests.

Covers the 12 required test scenarios:
  1. Latest-session selection excludes events from previous runs.
  2. Explicit run-ID selection still works.
  3. DHT11-only activity does not establish Deauth telemetry availability.
  4. Missing Wi-Fi management telemetry produces INSUFFICIENT TELEMETRY.
  5. Replay remains insufficient when only generic packet counts exist.
  6. Replay becomes eligible for evaluation only when actual hash/nonce evidence exists.
  7. Spoofing does not become operational based only on generic packet activity.
  8. Valid IP-to-MAC evidence is handled correctly (both registry mappings and observed IP traffic).
  9. Stale heartbeat overrides a misleading RUNNING status.
 10. Missing or invalid heartbeat is handled conservatively.
 11. Archived sessions are identified correctly.
 12. Existing empty-database and SQL-error handling remains unchanged.
"""

import datetime
import sqlite3
import pytest
from pathlib import Path
from typing import Dict, Any, Optional

from src.init_live_database import init_live_database, get_live_db_connection
from src.live_dashboard import (
    CATEGORY_CONFIG,
    _is_heartbeat_stale,
    compute_attack_category_status,
    fetch_esp32_sniffer_diagnostics,
    fetch_attack_events,
    fetch_stored_channel_diagnostic,
    render_diagnostics,
)


@pytest.fixture
def clean_db(tmp_path) -> Path:
    """Creates a temporary initialized live monitoring database."""
    db_file = tmp_path / "test_dashboard_monitoring.db"
    init_live_database(db_file)
    return db_file


def _seed_collector_status(
    conn: sqlite3.Connection,
    run_id: int = 1,
    status: str = "RUNNING",
    serial_port: Optional[str] = "COM6",
    last_heartbeat: Any = "AUTO",
    packets_parsed: int = 100,
):
    if last_heartbeat == "AUTO":
        if status == "RUNNING":
            last_heartbeat = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        else:
            last_heartbeat = "2026-11-10 10:00:00"

    conn.execute(
        """
        INSERT INTO collector_status (run_id, status, serial_port, packets_parsed, last_heartbeat)
        VALUES (?, ?, ?, ?, ?)
        """,
        (run_id, status, serial_port, packets_parsed, last_heartbeat),
    )


def _seed_window(
    conn: sqlite3.Connection,
    run_id: int = 1,
    win_id: int = 1,
    packet_count: int = 20,
):
    conn.execute(
        """
        INSERT INTO live_traffic_windows (
            window_id, run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch,
            packet_count, packet_rate
        ) VALUES (?, ?, '00:11:22:33:44:55', 'Node_1', 1000.0, 1001.0, ?, ?)
        """,
        (win_id, run_id, packet_count, float(packet_count)),
    )


def _seed_sensor(
    conn: sqlite3.Connection,
    run_id: int = 1,
    tel_id: int = 1,
    sensor_epoch: float = 1700000000.0,
):
    conn.execute(
        """
        INSERT INTO live_sensor_telemetry (
            telemetry_id, run_id, physical_node_id, logical_node_id,
            sequence_num, uptime_ms, sensor_epoch
        ) VALUES (?, ?, 'ESP32_01', 'Node_1', ?, 5000, ?)
        """,
        (tel_id, run_id, tel_id, sensor_epoch),
    )


def _seed_attack_event(
    conn: sqlite3.Connection,
    event_id: int,
    run_id: int = 1,
    category: str = "Denial_of_Service",
    status: str = "CONFIRMED_THREAT",
    severity: str = "HIGH",
    confidence: float = 0.90,
    evidence_json: str = "{}",
    source_mac: Optional[str] = None,
    target_ip: Optional[str] = None,
):
    conn.execute(
        """
        INSERT INTO live_attack_events (
            event_id, run_id, category, status, severity, confidence,
            timestamp_epoch, timestamp_utc, evidence_json, source_mac, target_ip
        ) VALUES (?, ?, ?, ?, ?, ?, 1700000000.0, '2026-11-10 12:00:00', ?, ?, ?)
        """,
        (event_id, run_id, category, status, severity, confidence, evidence_json, source_mac, target_ip),
    )


def _seed_device(
    conn: sqlite3.Connection,
    mac: str = "00:11:22:33:44:55",
    ip: Optional[str] = "192.168.137.50",
    dev_name: str = "IoT_Device",
):
    cols = [col[1] for col in conn.execute("PRAGMA table_info(device_registry)").fetchall()]
    if "ip_address" not in cols:
        conn.execute("ALTER TABLE device_registry ADD COLUMN ip_address TEXT")

    conn.execute(
        """
        INSERT OR REPLACE INTO device_registry (mac_address, node_id, device_type, label, ip_address)
        VALUES (?, 'Node_1', 'Phone_Client', ?, ?)
        """,
        (mac, dev_name, ip),
    )


class TestLiveDashboardStatusAccuracyStage642:
    """Stage 6.4.2 test suite verifying the 12 required dashboard status and accuracy scenarios."""

    def test_01_latest_session_excludes_previous_run_events(self, clean_db):
        """1. When run_id=None (Latest Session), alerts from prior runs are excluded from current status."""
        conn = get_live_db_connection(clean_db)
        try:
            # Run 1: Historical run with confirmed DoS attack
            _seed_collector_status(conn, run_id=1, status="STOPPED", last_heartbeat="2026-11-10 08:00:00")
            _seed_window(conn, run_id=1, win_id=1, packet_count=50)
            _seed_attack_event(
                conn, event_id=101, run_id=1, category="Denial_of_Service",
                status="CONFIRMED_THREAT", severity="HIGH", confidence=0.95
            )

            # Run 2: Latest active run with clean traffic and no attacks
            now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            _seed_collector_status(conn, run_id=2, status="RUNNING", last_heartbeat=now_str)
            for i in range(5):
                _seed_window(conn, run_id=2, win_id=200 + i, packet_count=20)
            conn.commit()

            # Calling with run_id=None must resolve to effective_run_id=2
            statuses = compute_attack_category_status(conn, run_id=None)
            assert statuses["dos"]["effective_run_id"] == 2
            assert statuses["dos"]["is_live"] is True
            assert statuses["dos"]["status"] == "NO ALERT OBSERVED"
            assert statuses["dos"]["detected_count"] == 0
        finally:
            conn.close()

    def test_02_explicit_run_id_selection_works(self, clean_db):
        """2. Explicit run-ID selection targets historical session and flags its alerts."""
        conn = get_live_db_connection(clean_db)
        try:
            _seed_collector_status(conn, run_id=1, status="STOPPED", last_heartbeat="2026-11-10 08:00:00")
            _seed_window(conn, run_id=1, win_id=1, packet_count=50)
            _seed_attack_event(
                conn, event_id=101, run_id=1, category="Denial_of_Service",
                status="CONFIRMED_THREAT", severity="HIGH", confidence=0.95
            )

            now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            _seed_collector_status(conn, run_id=2, status="RUNNING", last_heartbeat=now_str)
            for i in range(5):
                _seed_window(conn, run_id=2, win_id=200 + i, packet_count=20)
            conn.commit()

            # Explicitly select run_id=1
            statuses = compute_attack_category_status(conn, run_id=1)
            assert statuses["dos"]["effective_run_id"] == 1
            assert statuses["dos"]["is_live"] is False
            assert statuses["dos"]["status"] == "DETECTED"
            assert statuses["dos"]["detected_count"] == 1
            assert "[Archived Session #1]" in statuses["dos"]["sub"]
        finally:
            conn.close()

    def test_03_dht11_activity_does_not_establish_deauth_telemetry(self, clean_db):
        """3. Environmental DHT11 sensor records alone do NOT prove 802.11 sniffer is operational."""
        conn = get_live_db_connection(clean_db)
        try:
            _seed_collector_status(conn, run_id=1, status="RUNNING", serial_port="COM6")
            for i in range(5):
                _seed_window(conn, run_id=1, win_id=i + 1, packet_count=20)
            # Physical sensor records present
            _seed_sensor(conn, run_id=1, tel_id=1)
            _seed_sensor(conn, run_id=1, tel_id=2)
            conn.commit()

            statuses = compute_attack_category_status(conn, run_id=1)
            # Deauth must NOT show NO ALERT OBSERVED; it must report INSUFFICIENT TELEMETRY
            assert statuses["deauth"]["status"] == "INSUFFICIENT TELEMETRY"
            assert "ESP32 802.11 sniffer telemetry unavailable" in statuses["deauth"]["sub"]
        finally:
            conn.close()

    def test_04_missing_wifi_mgmt_telemetry_produces_insufficient(self, clean_db):
        """4. Missing 802.11 management frames strictly report INSUFFICIENT TELEMETRY."""
        conn = get_live_db_connection(clean_db)
        try:
            _seed_collector_status(conn, run_id=1, status="RUNNING", serial_port=None)
            _seed_window(conn, run_id=1, win_id=1, packet_count=10)
            _seed_attack_event(
                conn, event_id=1, run_id=1, category="Deauthentication_Disassociation_Abuse",
                status="INSUFFICIENT_TELEMETRY", severity="NONE", confidence=0.0
            )
            conn.commit()

            statuses = compute_attack_category_status(conn, run_id=1)
            assert statuses["deauth"]["status"] == "INSUFFICIENT TELEMETRY"
        finally:
            conn.close()

    def test_05_replay_insufficient_with_only_generic_packet_counts(self, clean_db):
        """5. Replay status remains INSUFFICIENT TELEMETRY even if generic network traffic exists."""
        conn = get_live_db_connection(clean_db)
        try:
            _seed_collector_status(conn, run_id=1, status="RUNNING", serial_port="COM6")
            for i in range(10):
                _seed_window(conn, run_id=1, win_id=i + 1, packet_count=50)
            conn.commit()

            statuses = compute_attack_category_status(conn, run_id=1)
            assert statuses["replay"]["status"] == "INSUFFICIENT TELEMETRY"
            assert "Cryptographic nonces/payload hashes required" in statuses["replay"]["sub"]
        finally:
            conn.close()

    def test_06_replay_eligible_only_with_actual_hash_or_nonce_evidence(self, clean_db):
        """6. Replay reports NO ALERT OBSERVED or DETECTED only when actual cryptographic nonces/hashes exist."""
        conn = get_live_db_connection(clean_db)
        try:
            _seed_collector_status(conn, run_id=1, status="RUNNING", serial_port="COM6")
            for i in range(5):
                _seed_window(conn, run_id=1, win_id=i + 1, packet_count=20)

            # Subcase A: Baseline non-attack record with crypto telemetry
            _seed_attack_event(
                conn, event_id=50, run_id=1, category="Replay_Attack",
                status="NO_EVIDENCE", severity="NONE", confidence=0.0,
                evidence_json='{"payload_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}'
            )
            conn.commit()

            statuses = compute_attack_category_status(conn, run_id=1)
            assert statuses["replay"]["status"] == "NO ALERT OBSERVED"
            assert "tracking active" in statuses["replay"]["sub"]

            # Subcase B: Confirmed threat flagged
            _seed_attack_event(
                conn, event_id=51, run_id=1, category="Replay_Attack",
                status="CONFIRMED_THREAT", severity="HIGH", confidence=0.92,
                evidence_json='{"payload_hash": "duplicate_hash", "observed_delta_ms": 420.0}'
            )
            conn.commit()

            statuses_detected = compute_attack_category_status(conn, run_id=1)
            assert statuses_detected["replay"]["status"] == "DETECTED"
            assert statuses_detected["replay"]["detected_count"] == 1
        finally:
            conn.close()

    def test_07_spoofing_insufficient_without_ip_to_mac_registry(self, clean_db):
        """7. Spoofing does not report operational status without registered IP-to-MAC baseline or observed IP traffic."""
        conn = get_live_db_connection(clean_db)
        try:
            _seed_collector_status(conn, run_id=1, status="RUNNING", serial_port="COM6")
            for i in range(5):
                _seed_window(conn, run_id=1, win_id=i + 1, packet_count=30)
            # device_registry has no IP and live_attack_events has no observed IP traffic
            conn.commit()

            statuses = compute_attack_category_status(conn, run_id=1)
            assert statuses["spoofing"]["status"] == "INSUFFICIENT TELEMETRY"
            assert "Requires registered IP-to-MAC baseline mapping" in statuses["spoofing"]["sub"]
        finally:
            conn.close()

    def test_08_valid_ip_to_mac_evidence_handled_correctly(self, clean_db):
        """8. When IP-to-MAC registry or IP traffic observations are available, Spoofing reports NO ALERT OBSERVED or DETECTED."""
        conn = get_live_db_connection(clean_db)
        try:
            _seed_collector_status(conn, run_id=1, status="RUNNING", serial_port="COM6")
            for i in range(5):
                _seed_window(conn, run_id=1, win_id=i + 1, packet_count=30)
            
            # Subcase A: Operational via device_registry IP mapping
            _seed_device(conn, mac="AA:BB:CC:11:22:33", ip="192.168.137.50")
            conn.commit()

            statuses_reg = compute_attack_category_status(conn, run_id=1)
            assert statuses_reg["spoofing"]["status"] == "NO ALERT OBSERVED"
            assert "1 registered IPs" in statuses_reg["spoofing"]["sub"]

            # Subcase B: Threat flagged
            _seed_attack_event(
                conn, event_id=70, run_id=1, category="Spoofing_Impersonation",
                status="CONFIRMED_THREAT", severity="HIGH", confidence=0.88,
                evidence_json='{"conflicting_mac": "AA:BB:CC:99:99:99"}',
                source_mac="AA:BB:CC:99:99:99", target_ip="192.168.137.50"
            )
            conn.commit()

            statuses_detected = compute_attack_category_status(conn, run_id=1)
            assert statuses_detected["spoofing"]["status"] == "DETECTED"
            assert statuses_detected["spoofing"]["detected_count"] == 1
        finally:
            conn.close()

    def test_09_stale_heartbeat_overrides_running_status(self, clean_db):
        """9. Collector marked RUNNING with last_heartbeat > 60s reports MONITORING UNAVAILABLE."""
        conn = get_live_db_connection(clean_db)
        try:
            # Heartbeat is 120 seconds old
            stale_hb = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=120)).strftime("%Y-%m-%d %H:%M:%S")
            _seed_collector_status(conn, run_id=1, status="RUNNING", serial_port="COM6", last_heartbeat=stale_hb)
            for i in range(5):
                _seed_window(conn, run_id=1, win_id=i + 1, packet_count=20)
            conn.commit()

            statuses = compute_attack_category_status(conn, run_id=1)
            for key in ["dos", "port_scan", "spoofing", "deauth", "replay"]:
                assert statuses[key]["status"] == "MONITORING UNAVAILABLE"
                assert "heartbeat stale" in statuses[key]["sub"].lower()
                assert statuses[key]["border_cls"] == "neutral-border"

            diag = fetch_esp32_sniffer_diagnostics(conn, run_id=1)
            assert diag["connection_status"] == "Heartbeat Stale / Inactive"
        finally:
            conn.close()

    def test_10_missing_or_invalid_heartbeat_handled_conservatively(self, clean_db):
        """10. Missing or unparseable heartbeats safely override RUNNING to MONITORING UNAVAILABLE."""
        conn = get_live_db_connection(clean_db)
        try:
            # Subcase A: last_heartbeat is NULL
            _seed_collector_status(conn, run_id=1, status="RUNNING", serial_port="COM6", last_heartbeat=None)
            conn.commit()

            statuses = compute_attack_category_status(conn, run_id=1)
            assert statuses["dos"]["status"] == "MONITORING UNAVAILABLE"
            assert "missing or unparseable" in statuses["dos"]["sub"].lower()

            # Subcase B: last_heartbeat is corrupted string
            conn.execute("UPDATE collector_status SET last_heartbeat = 'corrupted_timestamp' WHERE run_id = 1")
            conn.commit()

            statuses_corrupt = compute_attack_category_status(conn, run_id=1)
            assert statuses_corrupt["dos"]["status"] == "MONITORING UNAVAILABLE"
            assert "missing or unparseable" in statuses_corrupt["dos"]["sub"].lower()
        finally:
            conn.close()

    def test_11_archived_sessions_identified_correctly(self, clean_db):
        """11. Archived or stopped sessions are accurately tagged as inactive archived context."""
        conn = get_live_db_connection(clean_db)
        try:
            _seed_collector_status(conn, run_id=42, status="STOPPED", serial_port="COM6", last_heartbeat="2026-11-10 09:00:00")
            for i in range(5):
                _seed_window(conn, run_id=42, win_id=i + 1, packet_count=20)
            _seed_attack_event(
                conn, event_id=420, run_id=42, category="Denial_of_Service",
                status="CONFIRMED_THREAT", severity="HIGH", confidence=0.91
            )
            conn.commit()

            statuses = compute_attack_category_status(conn, run_id=42)
            assert statuses["dos"]["is_live"] is False
            assert statuses["dos"]["effective_run_id"] == 42
            assert "[Archived Session #42]" in statuses["dos"]["sub"]

            diag = fetch_esp32_sniffer_diagnostics(conn, run_id=42)
            assert diag["connection_status"] == "Archived / Inactive"
        finally:
            conn.close()

    def test_12_empty_database_and_sql_error_handling(self, clean_db):
        """12. Empty database, None connection, closed connection, and partial payloads handled safely."""
        # A. Empty database
        conn = get_live_db_connection(clean_db)
        try:
            statuses = compute_attack_category_status(conn)
            for key in ["dos", "port_scan", "spoofing", "deauth", "replay"]:
                assert statuses[key]["status"] == "MONITORING UNAVAILABLE"
        finally:
            conn.close()

        # B. None connection
        statuses_none = compute_attack_category_status(None)
        for key in ["dos", "port_scan", "spoofing", "deauth", "replay"]:
            assert statuses_none[key]["status"] == "MONITORING UNAVAILABLE"

        diag_none = fetch_esp32_sniffer_diagnostics(None)
        assert diag_none["connection_status"] == "Disconnected"
        assert diag_none["serial_port"] == "Unavailable"

        # C. Closed connection
        closed_conn = sqlite3.connect(":memory:")
        closed_conn.close()
        statuses_closed = compute_attack_category_status(closed_conn)
        for key in ["dos", "port_scan", "spoofing", "deauth", "replay"]:
            assert statuses_closed[key]["status"] == "MONITORING UNAVAILABLE"

        # D. Partial sniffer summary payload without KeyError
        partial_summary = {
            "boot_id": 101,
            "cumulative": {"rx_total": 450, "enqueued": 420},
        }
        diag_partial = fetch_esp32_sniffer_diagnostics(None, in_memory_summary=partial_summary)
        assert diag_partial["boot_id"] == "101"
        assert diag_partial["raw_callbacks"] == "450"
        assert diag_partial["valid_frames"] == "420"
        assert diag_partial["tb_suppressed"] in ("Not reported", "Unavailable (in-memory only)")

    def test_13_sensor_monitoring_when_all_dht11_readings_invalid(self, clean_db):
        """
        GAP-82-08: Verifies dashboard sensor handling when every DHT11 record has dht_valid=0:
        - fetch_sensor_telemetry returns DataFrame where dht_valid=0 and temperature/humidity are NULL.
        - Verifies that invalid readings are not presented as valid measurements (valid_cnt=0, valid_pct=0.0%).
        - Verifies PIR motion detection records remain completely independent and functional.
        - Verifies render_sensor_monitoring executes without crashing and renders unavailable indicators.
        """
        from unittest.mock import MagicMock, patch
        import pandas as pd
        from src.live_dashboard import fetch_sensor_telemetry, fetch_pir_events, render_sensor_monitoring

        conn = get_live_db_connection(clean_db)
        _seed_collector_status(conn, run_id=1, status="RUNNING")

        # Insert 5 DHT11 records with dht_valid = 0 (temperature and humidity are NULL)
        for seq in range(1, 6):
            conn.execute(
                """
                INSERT INTO live_sensor_telemetry
                    (run_id, physical_node_id, logical_node_id, sequence_num, uptime_ms,
                     temperature_c, humidity_pct, dht_valid, sensor_epoch)
                VALUES (1, 'esp32_gateway', 'Node_1', ?, ?, NULL, NULL, 0, ?)
                """,
                (seq, seq * 2000, 1000.0 + seq * 2.0),
            )

        # Insert 5 valid PIR motion records (independent physical sensing)
        for seq in range(1, 6):
            conn.execute(
                """
                INSERT INTO live_pir_events
                    (run_id, physical_node_id, logical_node_id, sequence_num, uptime_ms,
                     motion_detected, sensor_epoch)
                VALUES (1, 'esp32_gateway', 'Node_2', ?, ?, ?, ?)
                """,
                (seq, seq * 2000, 1 if seq % 2 == 1 else 0, 1000.0 + seq * 2.0),
            )
        conn.commit()

        # 1. Verify telemetry fetch query
        df_dht = fetch_sensor_telemetry(conn, run_id=1)
        df_pir = fetch_pir_events(conn, run_id=1)

        assert len(df_dht) == 5
        assert (df_dht["dht_valid"] == 0).all()
        assert df_dht["temperature_c"].isna().all()
        assert df_dht["humidity_pct"].isna().all()

        valid_cnt = df_dht["dht_valid"].sum()
        assert valid_cnt == 0
        valid_pct = (valid_cnt / len(df_dht) * 100.0) if len(df_dht) > 0 else 0.0
        assert valid_pct == 0.0

        # PIR events remain functional and independent
        assert len(df_pir) == 5
        assert df_pir["motion_detected"].sum() == 3  # sequences 1, 3, 5

        # 2. Verify render_sensor_monitoring execution with mocked streamlit UI
        mock_st = MagicMock()
        created_cols = []

        def fake_columns(spec):
            n = spec if isinstance(spec, int) else len(spec)
            cols = [MagicMock() for _ in range(n)]
            created_cols.extend(cols)
            return cols

        mock_st.columns.side_effect = fake_columns

        with patch("src.live_dashboard.st", mock_st):
            render_sensor_monitoring(conn, run_id=1)

        # Check that metric calls on st.metric rendered '—' (unavailable dash)
        found_dash_temp = False
        found_dash_hum = False
        found_zero_reliability = False

        for call in mock_st.metric.call_args_list:
            args, _ = call
            if "Latest Temperature" in args[0]:
                assert args[1] == "—"  # Verified: renders dash, not numeric
                found_dash_temp = True
            elif "Latest Relative Humidity" in args[0]:
                assert args[1] == "—"  # Verified: renders dash, not numeric
                found_dash_hum = True
            elif "DHT11 Read Reliability" in args[0]:
                assert args[1] == "0.0%"
                found_zero_reliability = True

        assert found_dash_temp is True
        assert found_dash_hum is True
        assert found_zero_reliability is True

        conn.close()

    def test_14_fetch_stored_channel_diagnostic_aligned_and_mismatch(self, clean_db):
        """Verify fetch_stored_channel_diagnostic parses sidecar JSON accurately."""
        import json
        diag_file = clean_db.parent / f"{clean_db.stem}_diagnostic.json"
        data = {
            "status": "CHANNEL_ALIGNED",
            "esp32_channel": 6,
            "hotspot_channel": 6,
            "interface_name": "Local Area Connection* 2",
            "esp32_source": "FIRMWARE_HANDSHAKE",
            "timestamp": 1700000000.0,
            "explanation": "Verified aligned",
        }
        with open(diag_file, "w", encoding="utf-8") as f:
            json.dump(data, f)

        res = fetch_stored_channel_diagnostic(clean_db)
        assert res is not None
        assert res["status"] == "CHANNEL_ALIGNED"
        assert res["esp32_channel"] == 6
        assert res["hotspot_channel"] == 6

    def test_15_fetch_stored_channel_diagnostic_missing_file_returns_none(self, clean_db):
        """Verify missing diagnostic file returns None without error."""
        diag_file = clean_db.parent / f"{clean_db.stem}_diagnostic.json"
        if diag_file.exists():
            diag_file.unlink()

        res = fetch_stored_channel_diagnostic(clean_db)
        assert res is None
        assert fetch_stored_channel_diagnostic(None) is None

    def test_16_render_diagnostics_renders_aligned_without_subprocess(self, clean_db):
        """Verify render_diagnostics displays verified ALIGNED status and executes NO subprocess."""
        import json
        from unittest.mock import MagicMock, patch

        diag_file = clean_db.parent / f"{clean_db.stem}_diagnostic.json"
        data = {
            "status": "CHANNEL_ALIGNED",
            "esp32_channel": 6,
            "hotspot_channel": 6,
            "interface_name": "Local Area Connection* 2",
            "esp32_source": "FIRMWARE_HANDSHAKE",
            "timestamp": 1700000000.0,
            "explanation": "Verified alignment on Channel 6",
        }
        with open(diag_file, "w", encoding="utf-8") as f:
            json.dump(data, f)

        conn = get_live_db_connection(clean_db)
        mock_st = MagicMock()
        mock_st.columns.side_effect = lambda spec: [MagicMock() for _ in range(spec if isinstance(spec, int) else len(spec))]

        with patch("subprocess.run") as mock_subproc:
            with patch("src.live_dashboard.st", mock_st):
                render_diagnostics(conn, db_path=clean_db)

            # Strict Verification: No subprocess spawned on dashboard render
            mock_subproc.assert_not_called()

        # Check rendered markdown contains ALIGNED
        found_aligned = any("ALIGNED (Channel 6)" in str(call) for call in mock_st.markdown.call_args_list)
        assert found_aligned is True
        conn.close()

    def test_17_render_diagnostics_renders_unavailable_when_no_stored_diagnostic(self, clean_db):
        """Verify render_diagnostics displays UNAVAILABLE when no verified record exists."""
        from unittest.mock import MagicMock, patch

        diag_file = clean_db.parent / f"{clean_db.stem}_diagnostic.json"
        if diag_file.exists():
            diag_file.unlink()

        conn = get_live_db_connection(clean_db)
        mock_st = MagicMock()
        mock_st.columns.side_effect = lambda spec: [MagicMock() for _ in range(spec if isinstance(spec, int) else len(spec))]

        with patch("subprocess.run") as mock_subproc:
            with patch("src.live_dashboard.st", mock_st):
                render_diagnostics(conn, db_path=clean_db)

            mock_subproc.assert_not_called()

        # Check rendered markdown contains UNAVAILABLE (Neutral Status)
        found_unavail = any("UNAVAILABLE (Neutral Status)" in str(call) for call in mock_st.markdown.call_args_list)
        assert found_unavail is True
        # Never displays green aligned
        found_aligned = any("ALIGNED (Channel 6)" in str(call) for call in mock_st.markdown.call_args_list)
        assert found_aligned is False
        conn.close()

    def test_18_stale_sidecar_from_previous_session_rejected(self, clean_db):
        """Verify stale diagnostic from a previous run_id is rejected and never renders ALIGNED."""
        import json
        from unittest.mock import MagicMock, patch

        diag_file = clean_db.parent / f"{clean_db.stem}_diagnostic.json"
        # Stale cache written by Run #10
        data = {
            "status": "CHANNEL_ALIGNED",
            "esp32_channel": 6,
            "hotspot_channel": 6,
            "interface_name": "Local Area Connection* 2",
            "esp32_source": "FIRMWARE_HANDSHAKE",
            "run_id": 10,
            "timestamp": 1700000000.0,
            "explanation": "Old verified alignment from Run #10",
        }
        with open(diag_file, "w", encoding="utf-8") as f:
            json.dump(data, f)

        # Active database status is Run #11
        conn = get_live_db_connection(clean_db)
        conn.execute(
            """
            INSERT INTO collector_status (run_id, status, interface_name)
            VALUES (11, 'RUNNING', 'Local Area Connection* 2')
            """
        )
        conn.commit()

        # 1. fetch_stored_channel_diagnostic flags stale session
        diag_parsed = fetch_stored_channel_diagnostic(clean_db, current_run_id=11)
        assert diag_parsed is not None
        assert diag_parsed["status"] == "CHANNEL_UNAVAILABLE"
        assert diag_parsed.get("is_stale") is True
        assert diag_parsed["esp32_channel"] is None
        assert "Run #10" in diag_parsed["explanation"]

        # 2. render_diagnostics strictly refuses to show ALIGNED for stale cache
        mock_st = MagicMock()
        mock_st.columns.side_effect = lambda spec: [MagicMock() for _ in range(spec if isinstance(spec, int) else len(spec))]

        with patch("subprocess.run") as mock_subproc:
            with patch("src.live_dashboard.st", mock_st):
                render_diagnostics(conn, db_path=clean_db)
            mock_subproc.assert_not_called()

        found_stale_unavail = any("UNAVAILABLE (Stale Session Cache)" in str(call) for call in mock_st.markdown.call_args_list)
        assert found_stale_unavail is True
        found_aligned = any("ALIGNED (Channel 6)" in str(call) for call in mock_st.markdown.call_args_list)
        assert found_aligned is False
        conn.close()

    def test_19_sidecar_missing_run_id_rejected_when_current_run_active(self, clean_db):
        """Verify sidecar with missing run_id is rejected as stale and cannot render ALIGNED."""
        import json
        from unittest.mock import MagicMock, patch

        diag_file = clean_db.parent / f"{clean_db.stem}_diagnostic.json"
        # Sidecar has ALIGNED status but lacks run_id key entirely
        data = {
            "status": "CHANNEL_ALIGNED",
            "esp32_channel": 6,
            "hotspot_channel": 6,
            "interface_name": "Local Area Connection* 2",
            "esp32_source": "FIRMWARE_HANDSHAKE",
            "timestamp": 1700000000.0,
            "explanation": "Verified alignment on Channel 6",
        }
        with open(diag_file, "w", encoding="utf-8") as f:
            json.dump(data, f)

        conn = get_live_db_connection(clean_db)
        conn.execute(
            """
            INSERT INTO collector_status (run_id, status, interface_name)
            VALUES (42, 'RUNNING', 'Local Area Connection* 2')
            """
        )
        conn.commit()

        # 1. fetch_stored_channel_diagnostic flags missing run_id as stale
        diag_parsed = fetch_stored_channel_diagnostic(clean_db, current_run_id=42)
        assert diag_parsed is not None
        assert diag_parsed["status"] == "CHANNEL_UNAVAILABLE"
        assert diag_parsed.get("is_stale") is True
        assert diag_parsed["esp32_channel"] is None
        assert "missing, null, or invalid type" in diag_parsed["explanation"]

        # 2. render_diagnostics strictly refuses to show ALIGNED
        mock_st = MagicMock()
        mock_st.columns.side_effect = lambda spec: [MagicMock() for _ in range(spec if isinstance(spec, int) else len(spec))]
        with patch("subprocess.run") as mock_subproc:
            with patch("src.live_dashboard.st", mock_st):
                render_diagnostics(conn, db_path=clean_db)
            mock_subproc.assert_not_called()

        found_aligned = any("ALIGNED (Channel 6)" in str(call) for call in mock_st.markdown.call_args_list)
        assert found_aligned is False
        found_stale = any("UNAVAILABLE (Stale Session Cache)" in str(call) for call in mock_st.markdown.call_args_list)
        assert found_stale is True
        conn.close()

    def test_20_sidecar_null_run_id_rejected_when_current_run_active(self, clean_db):
        """Verify sidecar with null run_id is rejected as stale and cannot render ALIGNED."""
        import json
        from unittest.mock import MagicMock, patch

        diag_file = clean_db.parent / f"{clean_db.stem}_diagnostic.json"
        data = {
            "status": "CHANNEL_ALIGNED",
            "esp32_channel": 6,
            "hotspot_channel": 6,
            "interface_name": "Local Area Connection* 2",
            "esp32_source": "FIRMWARE_HANDSHAKE",
            "run_id": None,
            "timestamp": 1700000000.0,
            "explanation": "Verified alignment on Channel 6",
        }
        with open(diag_file, "w", encoding="utf-8") as f:
            json.dump(data, f)

        conn = get_live_db_connection(clean_db)
        conn.execute(
            """
            INSERT INTO collector_status (run_id, status, interface_name)
            VALUES (42, 'RUNNING', 'Local Area Connection* 2')
            """
        )
        conn.commit()

        diag_parsed = fetch_stored_channel_diagnostic(clean_db, current_run_id=42)
        assert diag_parsed is not None
        assert diag_parsed["status"] == "CHANNEL_UNAVAILABLE"
        assert diag_parsed.get("is_stale") is True
        assert diag_parsed["esp32_channel"] is None

        mock_st = MagicMock()
        mock_st.columns.side_effect = lambda spec: [MagicMock() for _ in range(spec if isinstance(spec, int) else len(spec))]
        with patch("subprocess.run") as mock_subproc:
            with patch("src.live_dashboard.st", mock_st):
                render_diagnostics(conn, db_path=clean_db)
            mock_subproc.assert_not_called()

        found_aligned = any("ALIGNED (Channel 6)" in str(call) for call in mock_st.markdown.call_args_list)
        assert found_aligned is False
        conn.close()

    def test_21_sidecar_malformed_run_id_rejected_when_current_run_active(self, clean_db):
        """Verify sidecar with malformed/string/boolean run_id is rejected as stale."""
        import json

        diag_file = clean_db.parent / f"{clean_db.stem}_diagnostic.json"
        for malformed in ["42", True, [42], {"id": 42}]:
            data = {
                "status": "CHANNEL_ALIGNED",
                "esp32_channel": 6,
                "hotspot_channel": 6,
                "interface_name": "Local Area Connection* 2",
                "esp32_source": "FIRMWARE_HANDSHAKE",
                "run_id": malformed,
                "timestamp": 1700000000.0,
                "explanation": "Verified alignment on Channel 6",
            }
            with open(diag_file, "w", encoding="utf-8") as f:
                json.dump(data, f)

            diag_parsed = fetch_stored_channel_diagnostic(clean_db, current_run_id=42)
            assert diag_parsed is not None, f"Failed for {malformed!r}"
            assert diag_parsed["status"] == "CHANNEL_UNAVAILABLE", f"Failed for {malformed!r}"
            assert diag_parsed.get("is_stale") is True, f"Failed for {malformed!r}"
            assert diag_parsed["esp32_channel"] is None, f"Failed for {malformed!r}"

    def test_22_sidecar_valid_matching_run_id_accepted_and_aligned(self, clean_db):
        """Verify sidecar with valid matching run_id is accepted and renders ALIGNED."""
        import json
        from unittest.mock import MagicMock, patch

        diag_file = clean_db.parent / f"{clean_db.stem}_diagnostic.json"
        data = {
            "status": "CHANNEL_ALIGNED",
            "esp32_channel": 6,
            "hotspot_channel": 6,
            "interface_name": "Local Area Connection* 2",
            "esp32_source": "FIRMWARE_HANDSHAKE",
            "run_id": 42,
            "timestamp": 1700000000.0,
            "explanation": "Live verified alignment on Channel 6",
        }
        with open(diag_file, "w", encoding="utf-8") as f:
            json.dump(data, f)

        conn = get_live_db_connection(clean_db)
        conn.execute(
            """
            INSERT INTO collector_status (run_id, status, interface_name)
            VALUES (42, 'RUNNING', 'Local Area Connection* 2')
            """
        )
        conn.commit()

        # 1. fetch_stored_channel_diagnostic returns data untouched
        diag_parsed = fetch_stored_channel_diagnostic(clean_db, current_run_id=42)
        assert diag_parsed is not None
        assert diag_parsed["status"] == "CHANNEL_ALIGNED"
        assert diag_parsed["run_id"] == 42
        assert diag_parsed["esp32_channel"] == 6
        assert diag_parsed.get("is_stale") is not True

        # 2. render_diagnostics renders ALIGNED
        mock_st = MagicMock()
        mock_st.columns.side_effect = lambda spec: [MagicMock() for _ in range(spec if isinstance(spec, int) else len(spec))]
        with patch("subprocess.run") as mock_subproc:
            with patch("src.live_dashboard.st", mock_st):
                render_diagnostics(conn, db_path=clean_db)
            mock_subproc.assert_not_called()

        found_aligned = any("ALIGNED (Channel 6)" in str(call) for call in mock_st.markdown.call_args_list)
        assert found_aligned is True
        conn.close()

    def test_23_sidecar_no_active_current_run_id_preserves_behaviour(self, clean_db):
        """Verify when current_run_id is None, existing intended behaviour is safely preserved."""
        import json

        diag_file = clean_db.parent / f"{clean_db.stem}_diagnostic.json"
        data = {
            "status": "CHANNEL_ALIGNED",
            "esp32_channel": 6,
            "hotspot_channel": 6,
            "interface_name": "Local Area Connection* 2",
            "esp32_source": "FIRMWARE_HANDSHAKE",
            "timestamp": 1700000000.0,
            "explanation": "Historical alignment",
        }
        with open(diag_file, "w", encoding="utf-8") as f:
            json.dump(data, f)

        res = fetch_stored_channel_diagnostic(clean_db, current_run_id=None)
        assert res is not None
        assert res["status"] == "CHANNEL_ALIGNED"
        assert res["esp32_channel"] == 6
        assert res.get("is_stale") is not True
