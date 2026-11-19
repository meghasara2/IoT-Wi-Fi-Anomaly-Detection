"""
Live Collector & Attack Detection Engine Integration Test Suite
File: tests/test_live_collector_attack_integration.py

Verifies seamless, safe integration of the explainable NetworkAttackDetector
into the live TShark streaming and database ingestion pipeline:
  1. Safe, non-destructive migration adds live_attack_events table.
  2. Extended TShark command builder appends transport fields.
  3. Extended TShark line parser correctly extracts ports, flags, and sequence numbers.
  4. PacketObservation streaming buffer accumulates and drains observations thread-safely.
  5. LiveCollector writes attack detection events into live_attack_events.
  6. Isolation Forest scoring remains 100% frozen and decoupled from attack events.
  7. Read-only database query helper fetch_attack_events returns DataFrame cleanly.
  8. Safety constraints: production files untouched, RSSI un-fabricated.
"""

import json
import math
import sqlite3
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import pytest
import pandas as pd

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))
_SRC_DIR = _PROJECT_ROOT / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

try:
    from src.attack_detector import (
        AttackCategory,
        DetectionStatus,
        Severity,
        PacketObservation,
        WindowTrafficObservation,
        AttackDetectionResult,
        NetworkAttackDetector,
        RSSIMeasurement,
        resolve_gateway_mac,
    )
    from src.init_live_database import (
        init_live_database,
        migrate_live_database,
        get_live_db_connection,
    )
    from src.live_stream_extractor import (
        build_tshark_command,
        _parse_tshark_line,
        _RawPacket,
        LiveStreamExtractor,
    )
    from src.live_collector import (
        _insert_attack_event,
        score_window,
        load_frozen_dual_detector,
        DEFAULT_SESSION1_PATH,
        LiveCollector,
        validate_wifi_mgmt_event,
        validate_wifi_mgmt_summary,
        validate_sniffer_status,
    )
    from src.live_dashboard import fetch_attack_events
except ModuleNotFoundError:
    from attack_detector import (
        AttackCategory,
        DetectionStatus,
        Severity,
        PacketObservation,
        WindowTrafficObservation,
        AttackDetectionResult,
        NetworkAttackDetector,
        RSSIMeasurement,
        resolve_gateway_mac,
    )
    from init_live_database import (
        init_live_database,
        migrate_live_database,
        get_live_db_connection,
    )
    from live_stream_extractor import (
        build_tshark_command,
        _parse_tshark_line,
        _RawPacket,
        LiveStreamExtractor,
    )
    from live_collector import (
        _insert_attack_event,
        score_window,
        load_frozen_dual_detector,
        DEFAULT_SESSION1_PATH,
        LiveCollector,
        validate_wifi_mgmt_event,
        validate_wifi_mgmt_summary,
        validate_sniffer_status,
    )
    from live_dashboard import fetch_attack_events


@pytest.fixture
def temp_db(tmp_path) -> Path:
    """Creates a temporary live monitoring database."""
    db_file = tmp_path / "test_live_monitoring.db"
    init_live_database(db_file)
    return db_file


def _seed_run(conn: sqlite3.Connection) -> int:
    """Creates a test collector_status row satisfying foreign key constraints."""
    cur = conn.execute(
        "INSERT INTO collector_status (interface_index, status) VALUES (1, 'RUNNING')"
    )
    conn.commit()
    return cur.lastrowid


# =============================================================================
# 1. Database Schema & Migration Tests
# =============================================================================

class TestDatabaseMigration:

    def test_live_attack_events_table_created(self, temp_db):
        """Verifies that live_attack_events table exists with required columns."""
        conn = get_live_db_connection(temp_db)
        try:
            cur = conn.execute("PRAGMA table_info(live_attack_events)")
            cols = {row["name"] for row in cur.fetchall()}
            expected = {
                "event_id", "run_id", "window_id", "timestamp_epoch", "timestamp_utc",
                "category", "status", "severity", "confidence", "source_mac", "target_ip",
                "evidence_json", "missing_fields_json", "recommended_action", "acknowledged", "created_at"
            }
            assert expected.issubset(cols)
        finally:
            conn.close()

    def test_non_destructive_migration_preserves_records(self, temp_db):
        """Migrating an existing database must preserve all historical traffic and sensor rows."""
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            # Seed a traffic window
            conn.execute(
                """
                INSERT INTO live_traffic_windows (
                    run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch,
                    packet_count, packet_rate
                ) VALUES (?, 'ca:34:ea:92:d3:9e', 'Node_3', 1000.0, 1001.0, 10, 10.0)
                """,
                (run_id,),
            )
            conn.commit()
        finally:
            conn.close()

        # Run non-destructive migration
        success = migrate_live_database(temp_db)
        assert success is True

        # Verify existing record still exists
        conn = get_live_db_connection(temp_db)
        try:
            cnt = conn.execute("SELECT COUNT(*) FROM live_traffic_windows").fetchone()[0]
            assert cnt == 1
        finally:
            conn.close()


# =============================================================================
# 2. TShark Command & Extended Field Parsing Tests
# =============================================================================

class TestTSharkFieldParsing:

    def test_build_tshark_command_includes_transport_fields(self):
        """Extended command builder must include tcp/udp ports, flags, and sequence fields."""
        cmd = build_tshark_command(interface_index=2, include_extended_attack_fields=True)
        assert "-e" in cmd
        assert "tcp.srcport" in cmd
        assert "udp.srcport" in cmd
        assert "tcp.dstport" in cmd
        assert "udp.dstport" in cmd
        assert "tcp.flags" in cmd
        assert "tcp.seq" in cmd

    def test_parse_tshark_line_legacy_eight_fields(self):
        """Legacy 8-field lines (from offline mocks) must parse cleanly with None for extended fields."""
        line = "1\t1000.5\t200\tca:34:ea:92:d3:9e\t00:15:5d:01:02:03\t192.168.137.201\t192.168.137.1\tTCP\n"
        pkt = _parse_tshark_line(line)
        assert pkt is not None
        assert pkt.timestamp == 1000.5
        assert pkt.packet_size == 200
        assert pkt.eth_src == "ca:34:ea:92:d3:9e"
        assert pkt.src_port is None
        assert pkt.dst_port is None

    def test_parse_tshark_line_extended_fields_tcp(self):
        """Extended lines with TCP ports, SYN flag, and seq number must parse properly."""
        # 14 fields: frame, time, len, eth_src, eth_dst, ip_src, ip_dst, proto, tcp_sp, udp_sp, tcp_dp, udp_dp, flags, seq
        line = "42\t1005.0\t60\tca:34:ea:92:d3:9e\t00:15:5d:01:02:03\t192.168.137.201\t192.168.137.1\tTCP\t54321\t\t80\t\t0x0002\t100001\n"
        pkt = _parse_tshark_line(line)
        assert pkt is not None
        assert pkt.src_port == 54321
        assert pkt.dst_port == 80
        assert pkt.tcp_flags == "0x0002"
        assert pkt.tcp_seq == 100001

        obs = pkt.to_observation()
        assert isinstance(obs, PacketObservation)
        assert obs.src_port == 54321
        assert obs.dst_port == 80
        assert obs.protocol_seq_num == 100001

    def test_parse_tshark_line_extended_fields_udp(self):
        """Extended lines with UDP DNS traffic (port 53) must parse cleanly."""
        line = "55\t1006.0\t84\tca:34:ea:92:d3:9e\t00:15:5d:01:02:03\t192.168.137.201\t8.8.8.8\tDNS\t\t58900\t\t53\t\t\n"
        pkt = _parse_tshark_line(line)
        assert pkt is not None
        assert pkt.src_port == 58900
        assert pkt.dst_port == 53
        assert pkt.tcp_flags is None
        assert pkt.tcp_seq is None


# =============================================================================
# 3. Packet Observation Streaming Buffer Tests
# =============================================================================

class TestLiveStreamExtractorBuffer:

    def test_drain_recent_packets_clears_buffer(self):
        """drain_recent_packets() must return accumulated observations and clear the internal buffer."""
        extractor = LiveStreamExtractor(interface_index=1)
        raw1 = _parse_tshark_line("1\t1000.0\t100\tca:34:ea:92:d3:9e\t00:15:5d:01:02:03\t192.168.137.201\t192.168.137.1\tTCP\t50000\t\t80\t\t\t\n")
        raw2 = _parse_tshark_line("2\t1000.1\t120\tca:34:ea:92:d3:9e\t00:15:5d:01:02:03\t192.168.137.201\t192.168.137.1\tTCP\t50000\t\t443\t\t\t\n")

        with extractor._pkt_lock:
            extractor._recent_packet_observations.append(raw1.to_observation())
            extractor._recent_packet_observations.append(raw2.to_observation())

        drained = extractor.drain_recent_packets()
        assert len(drained) == 2
        assert drained[0].dst_port == 80
        assert drained[1].dst_port == 443

        # Second drain must be empty
        assert len(extractor.drain_recent_packets()) == 0

    def test_buffer_overflow_drop_accounting_and_telemetry_degradation(self):
        """
        Safety requirement: When buffer exceeds capacity, older packets are dropped,
        the drop count is explicitly recorded, and telemetry degradation is honestly flagged.
        """
        extractor = LiveStreamExtractor(interface_index=1, max_packet_buffer=5)
        assert extractor.get_buffer_telemetry_status()["is_lossless"] is True

        # Append 8 packets to a buffer of capacity 5
        with extractor._pkt_lock:
            for i in range(8):
                raw = _parse_tshark_line(
                    f"{i}\t{1000.0 + i * 0.1}\t100\tca:34:ea:92:d3:9e\t00:15:5d:01:02:03\t192.168.137.201\t192.168.137.1\tTCP\t50000\t\t{80 + i}\t\t\t\n"
                )
                obs = raw.to_observation()
                if len(extractor._recent_packet_observations) >= extractor.max_packet_buffer:
                    excess = (len(extractor._recent_packet_observations) - extractor.max_packet_buffer) + 1
                    del extractor._recent_packet_observations[:excess]
                    extractor._dropped_packet_count += excess
                    extractor.stats["packets_dropped_buffer_overflow"] += excess
                    extractor._telemetry_degraded = True
                extractor._recent_packet_observations.append(obs)

        status = extractor.get_buffer_telemetry_status()
        assert status["buffered_packets"] == 5
        assert status["dropped_packets"] == 3
        assert status["is_lossless"] is False
        assert status["telemetry_degraded"] is True
        assert extractor.stats["packets_dropped_buffer_overflow"] == 3

        # The 5 packets remaining must be the latest ones (ports 83, 84, 85, 86, 87)
        drained = extractor.drain_recent_packets()
        assert len(drained) == 5
        assert [p.dst_port for p in drained] == [83, 84, 85, 86, 87]

        # After draining, buffer is empty but drop history remains honest
        after_status = extractor.get_buffer_telemetry_status()
        assert after_status["buffered_packets"] == 0
        assert after_status["dropped_packets"] == 3
        assert after_status["is_lossless"] is False

    def test_concurrent_drain_and_append(self):
        """
        Verifies thread safety under concurrent appending and draining.
        No packets should be corrupted or lost (barring capacity overflow).
        """
        import threading
        extractor = LiveStreamExtractor(interface_index=1, max_packet_buffer=1000)
        total_packets = 100
        drained_all = []
        stop_producer = threading.Event()

        def producer():
            for i in range(total_packets):
                raw = _parse_tshark_line(
                    f"{i}\t{1000.0 + i * 0.01}\t100\tca:34:ea:92:d3:9e\t00:15:5d:01:02:03\t192.168.137.201\t192.168.137.1\tTCP\t50000\t\t{1000 + i}\t\t\t\n"
                )
                with extractor._pkt_lock:
                    extractor._recent_packet_observations.append(raw.to_observation())
                time.sleep(0.001)
            stop_producer.set()

        def consumer():
            while not stop_producer.is_set():
                pkts = extractor.drain_recent_packets()
                if pkts:
                    drained_all.extend(pkts)
                time.sleep(0.002)
            # Final drain
            drained_all.extend(extractor.drain_recent_packets())

        t_prod = threading.Thread(target=producer)
        t_cons = threading.Thread(target=consumer)
        t_prod.start()
        t_cons.start()
        t_prod.join()
        t_cons.join()

        assert len(drained_all) == total_packets
        # Verify sequence of dst_ports is monotonically increasing with no duplicates
        ports = [p.dst_port for p in drained_all]
        assert ports == sorted(ports)
        assert len(set(ports)) == total_packets

    def test_multiple_windows_evaluated_exactly_once(self):
        """
        When multiple per-MAC windows are yielded for the same time tick,
        the first window drains recent packets while the second receives an empty batch.
        Packets are never evaluated twice.
        """
        extractor = LiveStreamExtractor(interface_index=1)
        raw1 = _parse_tshark_line("1\t1000.0\t100\tca:34:ea:92:d3:9e\t00:15:5d:01:02:03\t192.168.137.201\t192.168.137.1\tTCP\t50000\t\t80\t\t\t\n")
        raw2 = _parse_tshark_line("2\t1000.1\t120\tda:34:ea:92:d3:9f\t00:15:5d:01:02:03\t192.168.137.202\t192.168.137.1\tTCP\t50001\t\t443\t\t\t\n")

        with extractor._pkt_lock:
            extractor._recent_packet_observations.append(raw1.to_observation())
            extractor._recent_packet_observations.append(raw2.to_observation())

        # First window drain (Node 1)
        batch_window_1 = extractor.drain_recent_packets()
        assert len(batch_window_1) == 2

        # Second window drain immediately follows (Node 2)
        batch_window_2 = extractor.drain_recent_packets()
        assert len(batch_window_2) == 0

        # Total unique packet evaluations across both windows is exactly 2
        all_evaluated = batch_window_1 + batch_window_2
        assert len(all_evaluated) == 2


# =============================================================================
# 4. Collector Attack Event Ingestion & Isolation Forest Invariance
# =============================================================================

class TestCollectorAttackIntegration:

    def test_insert_attack_event_persists_in_sqlite(self, temp_db):
        """_insert_attack_event() must persist structured detection result with valid JSON."""
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            res = AttackDetectionResult(
                category=AttackCategory.PORT_SCAN,
                status=DetectionStatus.SUSPICIOUS,
                severity=Severity.HIGH,
                evidence={"distinct_ports_count": 12, "sample_ports": [21, 22, 80, 443]},
                missing_fields=[],
                confidence=0.85,
                timestamp=1000.0,
                recommended_action="Inspect host 192.168.137.201 for scanning utilities.",
            )
            event_id = _insert_attack_event(
                conn=conn,
                run_id=run_id,
                window_id=None,
                result=res,
                source_mac="ca:34:ea:92:d3:9e",
                target_ip="192.168.137.1",
            )
            assert event_id > 0

            # Verify row contents
            row = conn.execute("SELECT * FROM live_attack_events WHERE event_id = ?", (event_id,)).fetchone()
            assert row["category"] == "Reconnaissance_Port_Scan"
            assert row["status"] == "SUSPICIOUS"
            assert row["severity"] == "HIGH"
            assert row["confidence"] == pytest.approx(0.85)
            assert row["source_mac"] == "ca:34:ea:92:d3:9e"
            evidence_read = json.loads(row["evidence_json"])
            assert evidence_read["distinct_ports_count"] == 12
        finally:
            conn.close()

    def test_fetch_attack_events_read_only_mode(self, temp_db):
        """fetch_attack_events() must read from live_attack_events in read-only mode."""
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            res = AttackDetectionResult(
                category=AttackCategory.DOS,
                status=DetectionStatus.SUSPICIOUS,
                severity=Severity.MEDIUM,
                evidence={"consecutive_windows": 3, "current_rate_pps": 85.0},
                missing_fields=[],
                confidence=0.75,
                timestamp=1001.0,
                recommended_action="Monitor destination host bandwidth.",
            )
            _insert_attack_event(conn, run_id=run_id, window_id=None, result=res)
        finally:
            conn.close()

        # Connect in read-only mode (identical to dashboard)
        ro_conn = get_live_db_connection(temp_db, read_only=True)
        try:
            df = fetch_attack_events(ro_conn)
            assert not df.empty
            assert len(df) == 1
            assert df["category"].iloc[0] == "Denial_of_Service"
            assert df["status"].iloc[0] == "SUSPICIOUS"
        finally:
            ro_conn.close()

    def test_frozen_isolation_forest_scoring_remains_unchanged(self):
        """
        Safety invariant: scoring a standard feature window with the frozen bundle
        must yield the exact same decision scores and inlier/outlier classifications.
        """
        bundle = load_frozen_dual_detector(DEFAULT_SESSION1_PATH)
        sample_window = {
            "client_mac": "ca:34:ea:92:d3:9e",
            "node_id": "Node_3",
            "packet_rate": 5.0,
            "mean_packet_size": 250.0,
            "packet_size_std": 20.0,
            "packet_count": 5,
            "mean_IAT": 0.20,
            "IAT_std": 0.05,
        }
        scored = score_window(bundle, sample_window)
        assert scored["pred_dual"] == 1
        assert scored["dual_reason"] == "NORMAL_INLIER"
        assert isinstance(scored["score_primary"], float)
        assert isinstance(scored["score_timing"], float)

    def test_collector_gateway_mac_argument_and_normalization(self, tmp_path):
        """
        Verifies that --gateway-mac passes the exact verified Hotspot gateway MAC
        (36:6f:24:d2:34:3d) to NetworkAttackDetector with consistent normalization
        across colons, hyphens, uppercase, and whitespace.
        """
        test_db = tmp_path / "test_gw.db"
        init_live_database(test_db)

        # 1. Exact lowercase colon
        c1 = LiveCollector(interface_index=5, db_path=test_db, gateway_mac="36:6f:24:d2:34:3d", no_sensors=True)
        assert c1.gateway_mac == "36:6f:24:d2:34:3d"
        assert c1.attack_detector.spoofing_detector.gateway_mac == "36:6f:24:d2:34:3d"

        # 2. Uppercase hyphen
        c2 = LiveCollector(interface_index=5, db_path=test_db, gateway_mac="36-6F-24-D2-34-3D", no_sensors=True)
        assert c2.gateway_mac == "36:6f:24:d2:34:3d"
        assert c2.attack_detector.spoofing_detector.gateway_mac == "36:6f:24:d2:34:3d"

        # 3. Whitespace & mixed case
        c3 = LiveCollector(interface_index=5, db_path=test_db, gateway_mac="  36:6F:24:D2:34:3D  ", no_sensors=True)
        assert c3.gateway_mac == "36:6f:24:d2:34:3d"
        assert c3.attack_detector.spoofing_detector.gateway_mac == "36:6f:24:d2:34:3d"

        # 4. Legitimate vs rogue evaluation
        p_legit = PacketObservation(
            timestamp=1000.0, packet_size=60,
            eth_src="36:6f:24:d2:34:3d", eth_dst="ca:34:ea:92:d3:9e",
            ip_src="192.168.137.1", ip_dst="192.168.137.201"
        )
        res_legit = c1.attack_detector.spoofing_detector.evaluate(p_legit)
        assert res_legit.status == DetectionStatus.NO_EVIDENCE
        assert res_legit.evidence["is_gateway"] is True

        p_rogue = PacketObservation(
            timestamp=1000.0, packet_size=60,
            eth_src="00:11:22:33:44:55", eth_dst="ca:34:ea:92:d3:9e",
            ip_src="192.168.137.1", ip_dst="192.168.137.201"
        )
        res_rogue = c1.attack_detector.spoofing_detector.evaluate(p_rogue)
        assert res_rogue.status == DetectionStatus.SUSPICIOUS
        assert res_rogue.evidence["authorized_gateway_mac"] == "36:6f:24:d2:34:3d"
        assert res_rogue.evidence["offending_mac"] == "00:11:22:33:44:55" 

    def test_collector_attributes_port_scan_to_scanner_mac_and_target_host(self, temp_db):
        """
        When a port scan is detected in recent packets, the collector must record the scanner's
        MAC and target host in live_attack_events rather than the feature window's client_mac.
        """
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            res = AttackDetectionResult(
                category=AttackCategory.PORT_SCAN,
                status=DetectionStatus.SUSPICIOUS,
                severity=Severity.MEDIUM,
                evidence={
                    "verdict": "Reconnaissance / scanning pattern observed",
                    "details": [{
                        "src_ip": "192.168.137.150",
                        "source_mac": "00:0c:29:ab:cd:ef",
                        "distinct_ports_count": 8,
                        "sample_hosts": ["192.168.137.1"],
                        "distinct_hosts_count": 1,
                        "is_vertical_scan": True,
                        "is_horizontal_sweep": False,
                    }],
                },
                missing_fields=[],
                confidence=0.85,
                timestamp=1000.0,
                recommended_action="Investigate host 192.168.137.150.",
            )

            primary = res.evidence["details"][0]
            evt_src_mac = primary.get("source_mac")
            evt_target_ip = primary.get("sample_hosts", [None])[0]

            event_id = _insert_attack_event(
                conn=conn,
                run_id=run_id,
                window_id=None,
                result=res,
                source_mac=evt_src_mac,
                target_ip=evt_target_ip,
            )
            assert event_id is not None

            cur = conn.execute("SELECT source_mac, target_ip, category, status FROM live_attack_events WHERE event_id = ?", (event_id,))
            row = cur.fetchone()
            assert row["source_mac"] == "00:0c:29:ab:cd:ef"
            assert row["target_ip"] == "192.168.137.1"
            assert row["category"] == "Reconnaissance_Port_Scan"
            assert row["status"] == "SUSPICIOUS"
        finally:
            conn.close()

    def test_stream_scan_missing_mac_persists_null_never_client_mac(self, temp_db):
        """
        Stage 1.1 Requirement: When a stream-level port scan is detected from packets lacking
        an Ethernet source MAC, the collector must persist NULL into live_attack_events and
        NEVER fall back to the unrelated client feature-window MAC.
        """
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(interface_index=1, db_path=temp_db, no_sensors=True)
            collector._run_id = run_id
            collector._attack_table_present = True

            client_window_mac = "ca:34:ea:92:d3:9e"  # Innocent client window
            scored = {
                "client_mac": client_window_mac,
                "node_id": "Node_3",
                "ip_dst": "142.250.190.46",  # Unrelated destination
                "packet_rate": 5.0,
            }

            # Scan finding without MAC
            scan_result = AttackDetectionResult(
                category=AttackCategory.PORT_SCAN,
                status=DetectionStatus.SUSPICIOUS,
                severity=Severity.MEDIUM,
                evidence={
                    "verdict": "Reconnaissance / scanning pattern observed",
                    "details": [{
                        "src_ip": "192.168.137.150",
                        "source_mac": None,  # Missing source MAC!
                        "distinct_ports_count": 8,
                        "sample_hosts": ["192.168.137.1"],
                        "distinct_hosts_count": 1,
                        "is_vertical_scan": True,
                        "is_horizontal_sweep": False,
                    }],
                },
                missing_fields=[],
                confidence=0.80,
                timestamp=1000.0,
                recommended_action="Investigate host 192.168.137.150.",
            )

            # Seed a feature window to satisfy foreign key constraint
            cur_win = conn.execute(
                "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
                "VALUES (?, ?, 'Node_3', 1000.0, 1001.0, 5, 5.0)",
                (run_id, client_window_mac),
            )
            win_id = cur_win.lastrowid

            inserted = collector._persist_attack_results(
                db=conn,
                window_id=win_id,
                dos_results=[],
                stream_results=[scan_result],
                client_mac=client_window_mac,
                scored=scored,
            )
            assert inserted == 1

            cur = conn.execute("SELECT source_mac, target_ip, category, status FROM live_attack_events WHERE run_id = ?", (run_id,))
            row = cur.fetchone()
            assert row is not None
            assert row["source_mac"] is None  # Persisted as SQL NULL!
            assert row["source_mac"] != client_window_mac  # Never fell back to innocent client!
            assert row["target_ip"] == "192.168.137.1"     # Target from finding, not scored["ip_dst"]
            assert row["target_ip"] != "142.250.190.46"
        finally:
            conn.close()

    def test_two_simultaneous_scanners_persisted_independently(self, temp_db):
        """
        Stage 1.1 Requirement: When multiple independent scanners are detected in the same batch,
        the collector must persist each distinct scanner finding separately with its own source IP,
        source MAC, and target host.
        """
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(interface_index=1, db_path=temp_db, no_sensors=True)
            collector._run_id = run_id
            collector._attack_table_present = True

            client_window_mac = "ca:34:ea:92:d3:9e"
            scored = {"client_mac": client_window_mac, "node_id": "Node_3", "ip_dst": "57.144.212.199"}

            # Attack result containing TWO independent scanner findings
            scan_result = AttackDetectionResult(
                category=AttackCategory.PORT_SCAN,
                status=DetectionStatus.SUSPICIOUS,
                severity=Severity.HIGH,
                evidence={
                    "verdict": "Reconnaissance / scanning pattern observed",
                    "details": [
                        {
                            "src_ip": "192.168.137.150",
                            "source_mac": "00:0c:29:ab:cd:ef",
                            "distinct_ports_count": 8,
                            "sample_hosts": ["192.168.137.1"],
                            "distinct_hosts_count": 1,
                            "is_vertical_scan": True,
                            "is_horizontal_sweep": False,
                            "destination_scope": "LAN (192.168.137.0/24)",
                        },
                        {
                            "src_ip": "192.168.137.160",
                            "source_mac": "00:0c:29:11:22:33",
                            "distinct_ports_count": 1,
                            "sample_hosts": ["192.168.137.201"],
                            "distinct_hosts_count": 6,
                            "is_vertical_scan": False,
                            "is_horizontal_sweep": True,
                            "destination_scope": "LAN (192.168.137.0/24)",
                        },
                    ],
                },
                missing_fields=[],
                confidence=0.88,
                timestamp=1000.0,
                recommended_action="Investigate multiple hosts.",
            )

            # Seed a feature window to satisfy foreign key constraint
            cur_win = conn.execute(
                "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
                "VALUES (?, ?, 'Node_3', 1000.0, 1001.0, 5, 5.0)",
                (run_id, client_window_mac),
            )
            win_id = cur_win.lastrowid

            inserted = collector._persist_attack_results(
                db=conn,
                window_id=win_id,
                dos_results=[],
                stream_results=[scan_result],
                client_mac=client_window_mac,
                scored=scored,
            )
            assert inserted == 2

            cur = conn.execute("SELECT source_mac, target_ip, evidence_json FROM live_attack_events WHERE run_id = ? ORDER BY event_id ASC", (run_id,))
            rows = cur.fetchall()
            assert len(rows) == 2

            # Finding 1
            assert rows[0]["source_mac"] == "00:0c:29:ab:cd:ef"
            assert rows[0]["target_ip"] == "192.168.137.1"
            assert rows[0]["source_mac"] != client_window_mac
            ev1 = json.loads(rows[0]["evidence_json"])
            assert ev1["details"][0]["src_ip"] == "192.168.137.150"

            # Finding 2
            assert rows[1]["source_mac"] == "00:0c:29:11:22:33"
            assert rows[1]["target_ip"] == "192.168.137.201"
            assert rows[1]["source_mac"] != client_window_mac
            ev2 = json.loads(rows[1]["evidence_json"])
            assert ev2["details"][0]["src_ip"] == "192.168.137.160"
        finally:
            conn.close()

    def test_stream_findings_do_not_use_window_ip_dst(self, temp_db):
        """
        Stage 1.1 Requirement: Stream findings without target hosts must persist NULL
        and must never associate with the feature window's unrelated scored['ip_dst'].
        """
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(interface_index=1, db_path=temp_db, no_sensors=True)
            collector._run_id = run_id
            collector._attack_table_present = True

            client_window_mac = "ca:34:ea:92:d3:9e"
            scored = {"client_mac": client_window_mac, "node_id": "Node_3", "ip_dst": "8.8.8.8"}

            # Finding with empty sample_hosts
            scan_result = AttackDetectionResult(
                category=AttackCategory.PORT_SCAN,
                status=DetectionStatus.SUSPICIOUS,
                severity=Severity.LOW,
                evidence={
                    "verdict": "Reconnaissance / scanning pattern observed",
                    "details": [{
                        "src_ip": "192.168.137.170",
                        "source_mac": "00:0c:29:55:66:77",
                        "distinct_ports_count": 2,
                        "sample_hosts": [],  # No target host available
                        "distinct_hosts_count": 0,
                        "is_vertical_scan": False,
                        "is_horizontal_sweep": False,
                    }],
                },
                missing_fields=[],
                confidence=0.50,
                timestamp=1000.0,
                recommended_action="Monitor host 192.168.137.170.",
            )

            # Seed a feature window to satisfy foreign key constraint
            cur_win = conn.execute(
                "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
                "VALUES (?, ?, 'Node_3', 1000.0, 1001.0, 5, 5.0)",
                (run_id, client_window_mac),
            )
            win_id = cur_win.lastrowid

            inserted = collector._persist_attack_results(
                db=conn,
                window_id=win_id,
                dos_results=[],
                stream_results=[scan_result],
                client_mac=client_window_mac,
                scored=scored,
            )
            assert inserted == 1

            cur = conn.execute("SELECT source_mac, target_ip FROM live_attack_events WHERE run_id = ?", (run_id,))
            row = cur.fetchone()
            assert row is not None
            assert row["source_mac"] == "00:0c:29:55:66:77"
            assert row["target_ip"] is None  # Persisted as NULL!
            assert row["target_ip"] != "8.8.8.8"  # Never associated with window's unrelated ip_dst!
        finally:
            conn.close()


# =============================================================================
# 5. Safety Invariants & Telemetry Honesty
# =============================================================================

class TestCollectorExplicitMigrationSafety:

    def test_collector_startup_does_not_auto_migrate(self, tmp_path):
        """
        Safety requirement: LiveCollector must NOT automatically migrate or modify
        an existing database on startup. Migration requires explicit --migrate-db.
        """
        from src.live_collector import LiveCollector
        from src.init_live_database import migrate_live_database

        # Create a database WITHOUT live_attack_events
        legacy_db = tmp_path / "legacy_live.db"
        conn = sqlite3.connect(legacy_db)
        conn.execute("""
            CREATE TABLE collector_status (
                run_id INTEGER PRIMARY KEY AUTOINCREMENT,
                start_time_utc TEXT,
                status TEXT
            )
        """)
        conn.close()

        # Instantiate collector
        collector = LiveCollector(
            interface_index=1,
            db_path=legacy_db,
            no_sensors=True,
        )

        # Check that table is absent and flag is False
        conn = sqlite3.connect(legacy_db)
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='live_attack_events'")
        assert cur.fetchone() is None
        conn.close()

        # Now run explicit migration
        success = migrate_live_database(legacy_db)
        assert success is True

        # Verify table exists only AFTER explicit migration
        conn = sqlite3.connect(legacy_db)
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='live_attack_events'")
        assert cur.fetchone() is not None
        conn.close()


class TestSafetyAndTelemetryHonesty:

    def test_missing_rssi_is_none_never_zero(self):
        """Safety requirement #7: RSSI must remain None and never 0.0 or fabricated."""
        assert RSSIMeasurement.validate(None) is None
        assert RSSIMeasurement.validate(0.0) is None
        assert RSSIMeasurement.validate(1.0) is None
        assert RSSIMeasurement.validate(-65.0) == -65.0

    def test_deauth_detector_reports_insufficient_telemetry_honestly(self):
        """Safety requirement #6: Missing 802.11 management frames must report INSUFFICIENT_TELEMETRY."""
        detector = NetworkAttackDetector()
        packets = [
            PacketObservation(
                timestamp=1000.0,
                packet_size=100,
                eth_src="ca:34:ea:92:d3:9e",
                eth_dst="00:15:5d:01:02:03",
                ip_src="192.168.137.201",
                ip_dst="192.168.137.1",
            )
        ]
        results = detector.evaluate_packet_stream(packets)
        deauth_res = [r for r in results if r.category == AttackCategory.DEAUTH_FLOOD][0]
        assert deauth_res.status == DetectionStatus.INSUFFICIENT_TELEMETRY
        assert "wlan_fc_type_subtype" in deauth_res.missing_fields
        assert deauth_res.confidence == 0.0

    def test_production_database_path_safety(self):
        """Safety requirement #1: Attempting to initialize production database raises RuntimeError."""
        from src.init_live_database import _safety_check, PRODUCTION_DB_PATH
        with pytest.raises(RuntimeError) as exc_info:
            _safety_check(PRODUCTION_DB_PATH)
        assert "SAFETY GUARD" in str(exc_info.value)


# =============================================================================
# 6. Stage 1.2: Port Scan Event Deduplication Tests
# =============================================================================

class TestPortScanDeduplication:

    def _make_port_scan_result(
        self,
        src_ip: str = "192.168.137.150",
        source_mac: Optional[str] = "00:0c:29:ab:cd:ef",
        sample_ports: Optional[List[int]] = None,
        sample_hosts: Optional[List[str]] = None,
        is_vertical: bool = True,
        is_horizontal: bool = False,
        scope: str = "LAN (192.168.137.0/24)",
        timestamp: float = 1000.0,
    ) -> AttackDetectionResult:
        ports = sample_ports if sample_ports is not None else [80, 81, 82, 83, 84, 85, 86, 87]
        hosts = sample_hosts if sample_hosts is not None else ["192.168.137.1"]
        return AttackDetectionResult(
            category=AttackCategory.PORT_SCAN,
            status=DetectionStatus.SUSPICIOUS,
            severity=Severity.MEDIUM,
            evidence={
                "verdict": "Reconnaissance / scanning pattern observed",
                "details": [{
                    "src_ip": src_ip,
                    "source_mac": source_mac,
                    "sample_ports": ports,
                    "sample_hosts": hosts,
                    "distinct_ports_count": len(ports),
                    "distinct_hosts_count": len(hosts),
                    "is_vertical_scan": is_vertical,
                    "is_horizontal_sweep": is_horizontal,
                    "destination_scope": scope,
                }],
            },
            missing_fields=[],
            confidence=0.85,
            timestamp=timestamp,
            recommended_action=f"Investigate host {src_ip}.",
        )

    def test_same_finding_repeated_within_cooldown_creates_single_row(self, temp_db):
        """Test 1: Identical finding repeated within 10-second cooldown must create exactly one database row."""
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(interface_index=1, db_path=temp_db, no_sensors=True, port_scan_cooldown_seconds=10.0)
            collector._run_id = run_id
            collector._attack_table_present = True

            cur_win = conn.execute(
                "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
                "VALUES (?, 'ca:34:ea:92:d3:9e', 'Node_3', 1000.0, 1001.0, 5, 5.0)",
                (run_id,),
            )
            win_id = cur_win.lastrowid
            scored = {"client_mac": "ca:34:ea:92:d3:9e", "ip_dst": "142.250.190.46"}

            res = self._make_port_scan_result(timestamp=1000.0)

            # First emission
            ins1 = collector._persist_attack_results(conn, win_id, [], [res], "ca:34:ea:92:d3:9e", scored)
            assert ins1 == 1

            # Second emission within cooldown
            ins2 = collector._persist_attack_results(conn, win_id, [], [res], "ca:34:ea:92:d3:9e", scored)
            assert ins2 == 0
            assert collector.stats["attack_events_cooldown_suppressed"] == 1

            # Third emission within cooldown
            ins3 = collector._persist_attack_results(conn, win_id, [], [res], "ca:34:ea:92:d3:9e", scored)
            assert ins3 == 0
            assert collector.stats["attack_events_cooldown_suppressed"] == 2

            cur = conn.execute("SELECT COUNT(*) FROM live_attack_events WHERE run_id = ?", (run_id,))
            assert cur.fetchone()[0] == 1
        finally:
            conn.close()

    def test_same_finding_emitted_after_cooldown_creates_new_row(self, temp_db):
        """Test 2: Same finding emitted after cooldown expiration must create a new database row."""
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            # Short cooldown (0.05s) to test expiration without sleeping 10 seconds
            collector = LiveCollector(interface_index=1, db_path=temp_db, no_sensors=True, port_scan_cooldown_seconds=0.05)
            collector._run_id = run_id
            collector._attack_table_present = True

            cur_win = conn.execute(
                "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
                "VALUES (?, 'ca:34:ea:92:d3:9e', 'Node_3', 1000.0, 1001.0, 5, 5.0)",
                (run_id,),
            )
            win_id = cur_win.lastrowid
            scored = {"client_mac": "ca:34:ea:92:d3:9e", "ip_dst": "142.250.190.46"}

            res = self._make_port_scan_result(timestamp=1000.0)

            # Emission 1
            ins1 = collector._persist_attack_results(conn, win_id, [], [res], "ca:34:ea:92:d3:9e", scored)
            assert ins1 == 1

            # Sleep past 50ms cooldown (100ms provides generous margin on Windows timer resolution)
            time.sleep(0.1)

            # Emission 2
            ins2 = collector._persist_attack_results(conn, win_id, [], [res], "ca:34:ea:92:d3:9e", scored)
            assert ins2 == 1

            cur = conn.execute("SELECT COUNT(*) FROM live_attack_events WHERE run_id = ?", (run_id,))
            assert cur.fetchone()[0] == 2
        finally:
            conn.close()


    def test_two_simultaneous_scanners_create_two_independent_rows(self, temp_db):
        """Test 3: Two distinct simultaneous scanners must never be merged by deduplication."""
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(interface_index=1, db_path=temp_db, no_sensors=True, port_scan_cooldown_seconds=10.0)
            collector._run_id = run_id
            collector._attack_table_present = True

            cur_win = conn.execute(
                "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
                "VALUES (?, 'ca:34:ea:92:d3:9e', 'Node_3', 1000.0, 1001.0, 5, 5.0)",
                (run_id,),
            )
            win_id = cur_win.lastrowid
            scored = {"client_mac": "ca:34:ea:92:d3:9e"}

            res1 = self._make_port_scan_result(src_ip="192.168.137.150", source_mac="00:0c:29:ab:cd:ef")
            res2 = self._make_port_scan_result(src_ip="192.168.137.160", source_mac="00:0c:29:11:22:33")

            ins1 = collector._persist_attack_results(conn, win_id, [], [res1], "ca:34:ea:92:d3:9e", scored)
            ins2 = collector._persist_attack_results(conn, win_id, [], [res2], "ca:34:ea:92:d3:9e", scored)
            assert ins1 == 1
            assert ins2 == 1

            cur = conn.execute("SELECT source_mac, target_ip FROM live_attack_events WHERE run_id = ? ORDER BY event_id ASC", (run_id,))
            rows = cur.fetchall()
            assert len(rows) == 2
            assert rows[0]["source_mac"] == "00:0c:29:ab:cd:ef"
            assert rows[1]["source_mac"] == "00:0c:29:11:22:33"
        finally:
            conn.close()

    def test_same_scanner_with_different_destination_port_creates_separate_row(self, temp_db):
        """Test 4: Same scanner probing a different destination port creates a separate row."""
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(interface_index=1, db_path=temp_db, no_sensors=True, port_scan_cooldown_seconds=10.0)
            collector._run_id = run_id
            collector._attack_table_present = True

            cur_win = conn.execute(
                "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
                "VALUES (?, 'ca:34:ea:92:d3:9e', 'Node_3', 1000.0, 1001.0, 5, 5.0)",
                (run_id,),
            )
            win_id = cur_win.lastrowid
            scored = {"client_mac": "ca:34:ea:92:d3:9e"}

            res_port80 = self._make_port_scan_result(src_ip="192.168.137.150", sample_ports=[80])
            res_port443 = self._make_port_scan_result(src_ip="192.168.137.150", sample_ports=[443])

            ins1 = collector._persist_attack_results(conn, win_id, [], [res_port80], "ca:34:ea:92:d3:9e", scored)
            ins2 = collector._persist_attack_results(conn, win_id, [], [res_port443], "ca:34:ea:92:d3:9e", scored)
            assert ins1 == 1
            assert ins2 == 1

            cur = conn.execute("SELECT COUNT(*) FROM live_attack_events WHERE run_id = ?", (run_id,))
            assert cur.fetchone()[0] == 2
        finally:
            conn.close()


    def test_same_scanner_with_materially_different_target_host_set_creates_separate_row(self, temp_db):
        """Test 5: Same scanner targeting a materially different target host creates a separate row."""
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(interface_index=1, db_path=temp_db, no_sensors=True, port_scan_cooldown_seconds=10.0)
            collector._run_id = run_id
            collector._attack_table_present = True

            cur_win = conn.execute(
                "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
                "VALUES (?, 'ca:34:ea:92:d3:9e', 'Node_3', 1000.0, 1001.0, 5, 5.0)",
                (run_id,),
            )
            win_id = cur_win.lastrowid
            scored = {"client_mac": "ca:34:ea:92:d3:9e"}

            res_host1 = self._make_port_scan_result(src_ip="192.168.137.150", sample_hosts=["192.168.137.1"])
            res_host2 = self._make_port_scan_result(src_ip="192.168.137.150", sample_hosts=["192.168.137.201"])

            ins1 = collector._persist_attack_results(conn, win_id, [], [res_host1], "ca:34:ea:92:d3:9e", scored)
            ins2 = collector._persist_attack_results(conn, win_id, [], [res_host2], "ca:34:ea:92:d3:9e", scored)
            assert ins1 == 1
            assert ins2 == 1

            cur = conn.execute("SELECT COUNT(*) FROM live_attack_events WHERE run_id = ?", (run_id,))
            assert cur.fetchone()[0] == 2
        finally:
            conn.close()


    def test_missing_source_mac_still_deduplicates_correctly(self, temp_db):
        """Test 6: Missing source MAC does not prevent deduplication and persists as SQL NULL."""
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(interface_index=1, db_path=temp_db, no_sensors=True, port_scan_cooldown_seconds=10.0)
            collector._run_id = run_id
            collector._attack_table_present = True

            cur_win = conn.execute(
                "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
                "VALUES (?, 'ca:34:ea:92:d3:9e', 'Node_3', 1000.0, 1001.0, 5, 5.0)",
                (run_id,),
            )
            win_id = cur_win.lastrowid
            scored = {"client_mac": "ca:34:ea:92:d3:9e"}

            res_nomac = self._make_port_scan_result(src_ip="192.168.137.150", source_mac=None)

            # First emission
            ins1 = collector._persist_attack_results(conn, win_id, [], [res_nomac], "ca:34:ea:92:d3:9e", scored)
            assert ins1 == 1

            # Second emission within cooldown
            ins2 = collector._persist_attack_results(conn, win_id, [], [res_nomac], "ca:34:ea:92:d3:9e", scored)
            assert ins2 == 0
            assert collector.stats["attack_events_cooldown_suppressed"] == 1

            cur = conn.execute("SELECT source_mac, COUNT(*) FROM live_attack_events WHERE run_id = ?", (run_id,))
            row = cur.fetchone()
            assert row[0] is None  # Preserved as SQL NULL
            assert row[1] == 1     # Exactly 1 row in DB
        finally:
            conn.close()

    def test_different_collector_runs_do_not_share_deduplication_state(self, temp_db):
        """Test 7: Different collector runs must not inherit or share deduplication state."""
        conn = get_live_db_connection(temp_db)
        try:
            run1_id = _seed_run(conn)
            run2_id = _seed_run(conn)

            collector = LiveCollector(interface_index=1, db_path=temp_db, no_sensors=True, port_scan_cooldown_seconds=10.0)
            collector._attack_table_present = True

            cur_win1 = conn.execute(
                "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
                "VALUES (?, 'ca:34:ea:92:d3:9e', 'Node_3', 1000.0, 1001.0, 5, 5.0)",
                (run1_id,),
            )
            win1_id = cur_win1.lastrowid

            cur_win2 = conn.execute(
                "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
                "VALUES (?, 'ca:34:ea:92:d3:9e', 'Node_3', 2000.0, 2001.0, 5, 5.0)",
                (run2_id,),
            )
            win2_id = cur_win2.lastrowid
            scored = {"client_mac": "ca:34:ea:92:d3:9e"}

            res = self._make_port_scan_result(src_ip="192.168.137.150")

            # Run 1 emission
            collector._run_id = run1_id
            ins1 = collector._persist_attack_results(conn, win1_id, [], [res], "ca:34:ea:92:d3:9e", scored)
            assert ins1 == 1

            # Run 2 emission of identical finding within 10s: must NOT be suppressed
            collector._run_id = run2_id
            ins2 = collector._persist_attack_results(conn, win2_id, [], [res], "ca:34:ea:92:d3:9e", scored)
            assert ins2 == 1

            cur1 = conn.execute("SELECT COUNT(*) FROM live_attack_events WHERE run_id = ?", (run1_id,))
            assert cur1.fetchone()[0] == 1
            cur2 = conn.execute("SELECT COUNT(*) FROM live_attack_events WHERE run_id = ?", (run2_id,))
            assert cur2.fetchone()[0] == 1
        finally:
            conn.close()

    def test_failed_database_insertion_does_not_mark_fingerprint_emitted(self, temp_db):
        """Test 8: Database insertion failure must not mark the fingerprint as emitted in cache."""
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(interface_index=1, db_path=temp_db, no_sensors=True, port_scan_cooldown_seconds=10.0)
            collector._run_id = run_id
            collector._attack_table_present = True

            cur_win = conn.execute(
                "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
                "VALUES (?, 'ca:34:ea:92:d3:9e', 'Node_3', 1000.0, 1001.0, 5, 5.0)",
                (run_id,),
            )
            win_id = cur_win.lastrowid
            scored = {"client_mac": "ca:34:ea:92:d3:9e"}
            res = self._make_port_scan_result(src_ip="192.168.137.150")

            # Create a closed connection to simulate DB error
            closed_conn = sqlite3.connect(temp_db)
            closed_conn.close()

            with pytest.raises(Exception):
                collector._persist_attack_results(closed_conn, win_id, [], [res], "ca:34:ea:92:d3:9e", scored)

            # Fingerprint was NOT cached
            assert len(collector._port_scan_dedup_cache) == 0

            # Subsequent call with healthy connection succeeds
            ins = collector._persist_attack_results(conn, win_id, [], [res], "ca:34:ea:92:d3:9e", scored)
            assert ins == 1
            assert len(collector._port_scan_dedup_cache) == 1

            cur = conn.execute("SELECT COUNT(*) FROM live_attack_events WHERE run_id = ?", (run_id,))
            assert cur.fetchone()[0] == 1
        finally:
            conn.close()

    def test_dos_event_persistence_remains_unchanged(self, temp_db):
        """Test 9: DoS event persistence must remain unaffected by port scan deduplication."""
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(
                interface_index=1,
                db_path=temp_db,
                no_sensors=True,
                port_scan_cooldown_seconds=10.0,
                dos_cooldown_seconds=0.0,
            )
            collector._run_id = run_id
            collector._attack_table_present = True

            cur_win1 = conn.execute(
                "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
                "VALUES (?, 'ca:34:ea:92:d3:9e', 'Node_3', 1000.0, 1001.0, 5, 5.0)",
                (run_id,),
            )
            win1_id = cur_win1.lastrowid
            cur_win2 = conn.execute(
                "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
                "VALUES (?, 'ca:34:ea:92:d3:9e', 'Node_3', 1001.0, 1002.0, 5, 5.0)",
                (run_id,),
            )
            win2_id = cur_win2.lastrowid
            scored = {"client_mac": "ca:34:ea:92:d3:9e", "ip_dst": "192.168.137.1"}

            dos_res = AttackDetectionResult(
                category=AttackCategory.DOS,
                status=DetectionStatus.SUSPICIOUS,
                severity=Severity.HIGH,
                evidence={"consecutive_windows": 3, "current_rate_pps": 80.0},
                missing_fields=[],
                confidence=0.80,
                timestamp=1000.0,
                recommended_action="Inspect destination host.",
            )

            # Two successive DoS calls: both must be persisted
            ins1 = collector._persist_attack_results(conn, win1_id, [dos_res], [], "ca:34:ea:92:d3:9e", scored)
            ins2 = collector._persist_attack_results(conn, win2_id, [dos_res], [], "ca:34:ea:92:d3:9e", scored)
            assert ins1 == 1
            assert ins2 == 1

            cur = conn.execute("SELECT COUNT(*) FROM live_attack_events WHERE category = 'Denial_of_Service' AND run_id = ?", (run_id,))
            assert cur.fetchone()[0] == 2
        finally:
            conn.close()


# =============================================================================
# Stage 2: DoS Detector & Fleet Surge Integration Tests
# =============================================================================

class TestDoSIntegration:
    """
    Verifies Stage 2 DoS detector integration:
      1. Alert cooldown suppresses duplicate alerts within cooldown window.
      2. Expired cooldown allows subsequent alerts to be persisted.
      3. Different sources and target IPs persist independently.
      4. Live fleet surge aggregation suppresses multi-device surge alerts.
      5. Genuine isolated single-device DoS floods are correctly flagged as SUSPICIOUS.
    """

    def test_dos_alert_cooldown_suppresses_duplicate_events(self, temp_db):
        """DoS alert deduplication: repeated alerts for same client and target within 60s cooldown create 1 row."""
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(
                interface_index=1,
                db_path=temp_db,
                no_sensors=True,
                dos_cooldown_seconds=60.0,
            )
            collector._run_id = run_id
            collector._attack_table_present = True

            cur_win1 = conn.execute(
                "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
                "VALUES (?, 'ca:34:ea:92:d3:9e', 'Node_3', 1000.0, 1001.0, 80, 80.0)",
                (run_id,),
            )
            win1_id = cur_win1.lastrowid
            cur_win2 = conn.execute(
                "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
                "VALUES (?, 'ca:34:ea:92:d3:9e', 'Node_3', 1001.0, 1002.0, 80, 80.0)",
                (run_id,),
            )
            win2_id = cur_win2.lastrowid
            scored = {"client_mac": "ca:34:ea:92:d3:9e", "ip_dst": "192.168.137.1"}

            dos_res = AttackDetectionResult(
                category=AttackCategory.DOS,
                status=DetectionStatus.SUSPICIOUS,
                severity=Severity.HIGH,
                evidence={"consecutive_windows": 3, "current_rate_pps": 80.0, "target_ip": "192.168.137.1"},
                missing_fields=[],
                confidence=0.80,
                timestamp=1000.0,
                recommended_action="Inspect destination host.",
            )

            ins1 = collector._persist_attack_results(conn, win1_id, [dos_res], [], "ca:34:ea:92:d3:9e", scored)
            ins2 = collector._persist_attack_results(conn, win2_id, [dos_res], [], "ca:34:ea:92:d3:9e", scored)

            assert ins1 == 1
            assert ins2 == 0
            assert collector.stats["attack_events_cooldown_suppressed"] == 1

            cur = conn.execute("SELECT COUNT(*) FROM live_attack_events WHERE category = 'Denial_of_Service' AND run_id = ?", (run_id,))
            assert cur.fetchone()[0] == 1
        finally:
            conn.close()

    def test_dos_alert_cooldown_expiration_creates_new_row(self, temp_db):
        """DoS alert deduplication: after cooldown expires, new alert is persisted."""
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(
                interface_index=1,
                db_path=temp_db,
                no_sensors=True,
                dos_cooldown_seconds=0.05,
            )
            collector._run_id = run_id
            collector._attack_table_present = True

            cur_win1 = conn.execute(
                "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
                "VALUES (?, 'ca:34:ea:92:d3:9e', 'Node_3', 1000.0, 1001.0, 80, 80.0)",
                (run_id,),
            )
            win1_id = cur_win1.lastrowid
            cur_win2 = conn.execute(
                "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
                "VALUES (?, 'ca:34:ea:92:d3:9e', 'Node_3', 1001.0, 1002.0, 80, 80.0)",
                (run_id,),
            )
            win2_id = cur_win2.lastrowid
            scored = {"client_mac": "ca:34:ea:92:d3:9e", "ip_dst": "192.168.137.1"}

            dos_res = AttackDetectionResult(
                category=AttackCategory.DOS,
                status=DetectionStatus.SUSPICIOUS,
                severity=Severity.HIGH,
                evidence={"consecutive_windows": 3, "current_rate_pps": 80.0, "target_ip": "192.168.137.1"},
                missing_fields=[],
                confidence=0.80,
                timestamp=1000.0,
                recommended_action="Inspect destination host.",
            )

            ins1 = collector._persist_attack_results(conn, win1_id, [dos_res], [], "ca:34:ea:92:d3:9e", scored)
            assert ins1 == 1

            time.sleep(0.08)  # Wait for 0.05s cooldown to expire (margin for Windows timer resolution)

            ins2 = collector._persist_attack_results(conn, win2_id, [dos_res], [], "ca:34:ea:92:d3:9e", scored)
            assert ins2 == 1

            cur = conn.execute("SELECT COUNT(*) FROM live_attack_events WHERE category = 'Denial_of_Service' AND run_id = ?", (run_id,))
            assert cur.fetchone()[0] == 2
        finally:
            conn.close()

    def test_different_sources_and_targets_independent_in_dos_cooldown(self, temp_db):
        """Different client MACs and different target IPs are tracked independently in DoS cooldown."""
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(
                interface_index=1,
                db_path=temp_db,
                no_sensors=True,
                dos_cooldown_seconds=60.0,
            )
            collector._run_id = run_id
            collector._attack_table_present = True

            cur_win = conn.execute(
                "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
                "VALUES (?, 'ca:34:ea:92:d3:9e', 'Node_3', 1000.0, 1001.0, 80, 80.0)",
                (run_id,),
            )
            win_id = cur_win.lastrowid

            dos_res = AttackDetectionResult(
                category=AttackCategory.DOS,
                status=DetectionStatus.SUSPICIOUS,
                severity=Severity.HIGH,
                evidence={"consecutive_windows": 3, "current_rate_pps": 80.0},
                missing_fields=[],
                confidence=0.80,
                timestamp=1000.0,
                recommended_action="Inspect destination host.",
            )

            # Client A targeting Gateway
            ins1 = collector._persist_attack_results(
                conn, win_id, [dos_res], [], "ca:34:ea:92:d3:9e",
                {"client_mac": "ca:34:ea:92:d3:9e", "ip_dst": "192.168.137.1"}
            )
            # Client A targeting IoT node (different target)
            ins2 = collector._persist_attack_results(
                conn, win_id, [dos_res], [], "ca:34:ea:92:d3:9e",
                {"client_mac": "ca:34:ea:92:d3:9e", "ip_dst": "192.168.137.201"}
            )
            # Client B targeting Gateway (different source MAC)
            ins3 = collector._persist_attack_results(
                conn, win_id, [dos_res], [], "da:11:22:33:44:55",
                {"client_mac": "da:11:22:33:44:55", "ip_dst": "192.168.137.1"}
            )

            assert ins1 == 1
            assert ins2 == 1
            assert ins3 == 1

            cur = conn.execute("SELECT COUNT(*) FROM live_attack_events WHERE category = 'Denial_of_Service' AND run_id = ?", (run_id,))
            assert cur.fetchone()[0] == 3
        finally:
            conn.close()

    def test_collector_fleet_surge_aggregation_in_live_loop(self):
        """Fleet surge aggregation in LiveCollector: multi-device surge in live loop suppresses DoS alert."""
        collector = LiveCollector(
            interface_index=1,
            no_sensors=True,
            dos_rate_threshold=60.0,
        )

        now = 1000.0
        # Simulate active devices in recent fleet cache
        devs = [
            ("aa:bb:cc:dd:ee:01", "Node_1", "192.168.137.101"),
            ("aa:bb:cc:dd:ee:02", "Node_2", "192.168.137.102"),
            ("aa:bb:cc:dd:ee:03", "Node_3", "192.168.137.103"),
        ]

        # All 3 devices experience simultaneous surge (> 60 PPS)
        for mac, node, ip in devs:
            obs = WindowTrafficObservation(
                bin_start_epoch=now,
                node_id=node,
                mac_address=mac,
                packet_count=100,
                packet_rate=100.0,
                total_bytes=80000,
                ip_src=ip,
                ip_dst="192.168.137.1",
            )
            # Add to fleet cache (as done in _network_loop)
            collector._recent_fleet_windows[mac.lower()] = obs

        # Evaluate target node 1 with fleet observations
        target_mac = "aa:bb:cc:dd:ee:01"
        target_obs = collector._recent_fleet_windows[target_mac]
        fleet_obs = [
            w for w in collector._recent_fleet_windows.values()
            if abs(w.bin_start_epoch - target_obs.bin_start_epoch) <= 1.0
        ]

        results = collector.attack_detector.evaluate_traffic_window(target_obs, fleet_windows=fleet_obs)
        assert len(results) == 1
        assert results[0].category == AttackCategory.DOS
        assert results[0].status == DetectionStatus.NO_EVIDENCE
        assert results[0].evidence["verdict"] == "Legitimate network-wide surge"
        assert results[0].evidence["surging_devices"] == 3
        assert results[0].evidence["fleet_ratio"] == 1.0

    def test_genuine_single_device_dos_not_suppressed_by_fleet_logic(self):
        """Single device surging while peer devices are idle correctly triggers SUSPICIOUS DoS."""
        collector = LiveCollector(
            interface_index=1,
            no_sensors=True,
            dos_rate_threshold=60.0,
        )

        now = 1000.0
        # Node 1 and Node 2 are idle
        for mac, node, ip in [
            ("aa:bb:cc:dd:ee:02", "Node_2", "192.168.137.102"),
            ("aa:bb:cc:dd:ee:03", "Node_3", "192.168.137.103"),
        ]:
            collector._recent_fleet_windows[mac.lower()] = WindowTrafficObservation(
                bin_start_epoch=now,
                node_id=node,
                mac_address=mac,
                packet_count=5,
                packet_rate=5.0,
                total_bytes=1000,
                ip_src=ip,
                ip_dst="192.168.137.1",
            )

        attacker_mac = "aa:bb:cc:dd:ee:01"
        target_ip = "192.168.137.1"

        # Attacker surges over 3 consecutive windows
        for i in range(3):
            obs = WindowTrafficObservation(
                bin_start_epoch=now + i,
                node_id="Node_1",
                mac_address=attacker_mac,
                packet_count=100,
                packet_rate=100.0,
                total_bytes=80000,
                ip_src="192.168.137.101",
                ip_dst=target_ip,
            )
            collector._recent_fleet_windows[attacker_mac.lower()] = obs
            fleet_obs = [
                w for w in collector._recent_fleet_windows.values()
                if abs(w.bin_start_epoch - obs.bin_start_epoch) <= 1.0
            ]
            results = collector.attack_detector.evaluate_traffic_window(obs, fleet_windows=fleet_obs)

        # On 3rd window, should trigger SUSPICIOUS DoS
        assert len(results) == 1
        assert results[0].category == AttackCategory.DOS
        assert results[0].status == DetectionStatus.SUSPICIOUS
        assert results[0].evidence["verdict"] == "Sustained local infrastructure flood"
        assert results[0].evidence["target_ip"] == target_ip


# =============================================================================
# 11. Spoofing Detection & Cooldown Integration Tests (Stage 3.1)
# =============================================================================

class TestSpoofingIntegration:

    def test_repeated_identical_spoofing_findings_within_cooldown_persist_once(self, temp_db):
        """
        Stage 3.1: Repeated identical spoofing findings within the cooldown window (default 60s)
        must only be persisted once in the database, with subsequent occurrences counted
        as cooldown-suppressed in collector stats.
        """
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(
                interface_index=1,
                db_path=temp_db,
                no_sensors=True,
                spoofing_cooldown_seconds=60.0,
            )
            collector._run_id = run_id
            collector._attack_table_present = True

            cur_win = conn.execute(
                "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
                "VALUES (?, 'ca:34:ea:92:d3:9e', 'Node_3', 1000.0, 1001.0, 10, 10.0)",
                (run_id,),
            )
            win_id = cur_win.lastrowid
            scored = {"client_mac": "ca:34:ea:92:d3:9e"}

            spoof_res = AttackDetectionResult(
                category=AttackCategory.SPOOFING,
                status=DetectionStatus.SUSPICIOUS,
                severity=Severity.HIGH,
                evidence={
                    "verdict": "Hotspot Gateway IP Impersonation detected",
                    "claimed_ip": "192.168.137.1",
                    "offending_mac": "00:aa:bb:cc:dd:ee",
                    "is_randomized_mac": False,
                },
                missing_fields=[],
                confidence=0.85,
                timestamp=1000.0,
                recommended_action="Investigate offending device.",
            )

            # Persist 3 times in rapid succession
            ins1 = collector._persist_attack_results(conn, win_id, [], [spoof_res], "ca:34:ea:92:d3:9e", scored)
            ins2 = collector._persist_attack_results(conn, win_id, [], [spoof_res], "ca:34:ea:92:d3:9e", scored)
            ins3 = collector._persist_attack_results(conn, win_id, [], [spoof_res], "ca:34:ea:92:d3:9e", scored)

            assert ins1 == 1
            assert ins2 == 0
            assert ins3 == 0
            assert collector.stats["attack_events_flagged"] == 1
            assert collector.stats["attack_events_cooldown_suppressed"] == 2

            cur = conn.execute(
                "SELECT COUNT(*) FROM live_attack_events WHERE category = 'Spoofing_Impersonation' AND run_id = ?",
                (run_id,),
            )
            assert cur.fetchone()[0] == 1
        finally:
            conn.close()

    def test_same_spoofing_finding_after_cooldown_expiry_persists_new_row(self, temp_db):
        """
        Stage 3.1: After spoofing_cooldown_seconds has expired, the same spoofing finding
        must be persisted as a new row in live_attack_events.
        """
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(
                interface_index=1,
                db_path=temp_db,
                no_sensors=True,
                spoofing_cooldown_seconds=0.05,
            )
            collector._run_id = run_id
            collector._attack_table_present = True

            cur_win = conn.execute(
                "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
                "VALUES (?, 'ca:34:ea:92:d3:9e', 'Node_3', 1000.0, 1001.0, 10, 10.0)",
                (run_id,),
            )
            win_id = cur_win.lastrowid
            scored = {"client_mac": "ca:34:ea:92:d3:9e"}

            spoof_res = AttackDetectionResult(
                category=AttackCategory.SPOOFING,
                status=DetectionStatus.SUSPICIOUS,
                severity=Severity.HIGH,
                evidence={
                    "verdict": "Hotspot Gateway IP Impersonation detected",
                    "claimed_ip": "192.168.137.1",
                    "offending_mac": "00:aa:bb:cc:dd:ee",
                    "is_randomized_mac": False,
                },
                missing_fields=[],
                confidence=0.85,
                timestamp=1000.0,
                recommended_action="Investigate offending device.",
            )

            ins1 = collector._persist_attack_results(conn, win_id, [], [spoof_res], "ca:34:ea:92:d3:9e", scored)
            assert ins1 == 1

            # Wait for cooldown to expire (margin for Windows 15.6ms timer resolution)
            time.sleep(0.08)

            ins2 = collector._persist_attack_results(conn, win_id, [], [spoof_res], "ca:34:ea:92:d3:9e", scored)
            assert ins2 == 1
            assert collector.stats["attack_events_flagged"] == 2
            assert collector.stats["attack_events_cooldown_suppressed"] == 0

            cur = conn.execute(
                "SELECT COUNT(*) FROM live_attack_events WHERE category = 'Spoofing_Impersonation' AND run_id = ?",
                (run_id,),
            )
            assert cur.fetchone()[0] == 2
        finally:
            conn.close()

    def test_different_source_macs_remain_independent_in_spoofing_cooldown(self, temp_db):
        """
        Stage 3.1: Two distinct offending MACs targeting the same gateway IP must
        remain independent and both persist without suppressing each other.
        """
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(
                interface_index=1,
                db_path=temp_db,
                no_sensors=True,
                spoofing_cooldown_seconds=60.0,
            )
            collector._run_id = run_id
            collector._attack_table_present = True

            cur_win = conn.execute(
                "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
                "VALUES (?, 'ca:34:ea:92:d3:9e', 'Node_3', 1000.0, 1001.0, 10, 10.0)",
                (run_id,),
            )
            win_id = cur_win.lastrowid
            scored = {"client_mac": "ca:34:ea:92:d3:9e"}

            res_mac_a = AttackDetectionResult(
                category=AttackCategory.SPOOFING,
                status=DetectionStatus.SUSPICIOUS,
                severity=Severity.HIGH,
                evidence={
                    "verdict": "Hotspot Gateway IP Impersonation detected",
                    "claimed_ip": "192.168.137.1",
                    "offending_mac": "00:aa:bb:cc:dd:01",
                    "is_randomized_mac": False,
                },
                missing_fields=[],
                confidence=0.85,
                timestamp=1000.0,
                recommended_action="Investigate offending device A.",
            )
            res_mac_b = AttackDetectionResult(
                category=AttackCategory.SPOOFING,
                status=DetectionStatus.SUSPICIOUS,
                severity=Severity.HIGH,
                evidence={
                    "verdict": "Hotspot Gateway IP Impersonation detected",
                    "claimed_ip": "192.168.137.1",
                    "offending_mac": "00:aa:bb:cc:dd:02",
                    "is_randomized_mac": False,
                },
                missing_fields=[],
                confidence=0.85,
                timestamp=1000.0,
                recommended_action="Investigate offending device B.",
            )

            ins_a = collector._persist_attack_results(conn, win_id, [], [res_mac_a], "ca:34:ea:92:d3:9e", scored)
            ins_b = collector._persist_attack_results(conn, win_id, [], [res_mac_b], "ca:34:ea:92:d3:9e", scored)

            assert ins_a == 1
            assert ins_b == 1
            assert collector.stats["attack_events_flagged"] == 2
            assert collector.stats["attack_events_cooldown_suppressed"] == 0

            cur = conn.execute(
                "SELECT source_mac FROM live_attack_events WHERE category = 'Spoofing_Impersonation' AND run_id = ? ORDER BY event_id ASC",
                (run_id,),
            )
            rows = [r["source_mac"] for r in cur.fetchall()]
            assert rows == ["00:aa:bb:cc:dd:01", "00:aa:bb:cc:dd:02"]
        finally:
            conn.close()

    def test_different_target_ips_remain_independent_in_spoofing_cooldown(self, temp_db):
        """
        Stage 3.1: The same offending MAC conflicting on different target IPs must
        persist independently without suppressing each other.
        """
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(
                interface_index=1,
                db_path=temp_db,
                no_sensors=True,
                spoofing_cooldown_seconds=60.0,
            )
            collector._run_id = run_id
            collector._attack_table_present = True

            cur_win = conn.execute(
                "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
                "VALUES (?, 'ca:34:ea:92:d3:9e', 'Node_3', 1000.0, 1001.0, 10, 10.0)",
                (run_id,),
            )
            win_id = cur_win.lastrowid
            scored = {"client_mac": "ca:34:ea:92:d3:9e"}

            res_ip1 = AttackDetectionResult(
                category=AttackCategory.SPOOFING,
                status=DetectionStatus.SUSPICIOUS,
                severity=Severity.HIGH,
                evidence={
                    "verdict": "Conflicting IP-to-MAC binding detected",
                    "ip_address": "192.168.137.101",
                    "current_mac": "00:aa:bb:cc:dd:ee",
                    "previous_mac": "00:11:22:33:44:55",
                },
                missing_fields=[],
                confidence=0.85,
                timestamp=1000.0,
                recommended_action="Investigate host.",
            )
            res_ip2 = AttackDetectionResult(
                category=AttackCategory.SPOOFING,
                status=DetectionStatus.SUSPICIOUS,
                severity=Severity.HIGH,
                evidence={
                    "verdict": "Conflicting IP-to-MAC binding detected",
                    "ip_address": "192.168.137.102",
                    "current_mac": "00:aa:bb:cc:dd:ee",
                    "previous_mac": "00:11:22:33:44:66",
                },
                missing_fields=[],
                confidence=0.85,
                timestamp=1000.0,
                recommended_action="Investigate host.",
            )

            ins1 = collector._persist_attack_results(conn, win_id, [], [res_ip1], "ca:34:ea:92:d3:9e", scored)
            ins2 = collector._persist_attack_results(conn, win_id, [], [res_ip2], "ca:34:ea:92:d3:9e", scored)

            assert ins1 == 1
            assert ins2 == 1
            assert collector.stats["attack_events_flagged"] == 2
            assert collector.stats["attack_events_cooldown_suppressed"] == 0

            cur = conn.execute(
                "SELECT target_ip FROM live_attack_events WHERE category = 'Spoofing_Impersonation' AND run_id = ? ORDER BY event_id ASC",
                (run_id,),
            )
            rows = [r["target_ip"] for r in cur.fetchall()]
            assert rows == ["192.168.137.101", "192.168.137.102"]
        finally:
            conn.close()

    def test_failed_database_insertion_does_not_register_spoofing_cooldown(self, temp_db):
        """
        Stage 3.1: If database insertion fails (e.g. closed connection or DB error),
        the fingerprint must NOT be registered in the cooldown cache, allowing a subsequent
        valid retry to persist successfully.
        """
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(
                interface_index=1,
                db_path=temp_db,
                no_sensors=True,
                spoofing_cooldown_seconds=60.0,
            )
            collector._run_id = run_id
            collector._attack_table_present = True

            cur_win = conn.execute(
                "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
                "VALUES (?, 'ca:34:ea:92:d3:9e', 'Node_3', 1000.0, 1001.0, 10, 10.0)",
                (run_id,),
            )
            win_id = cur_win.lastrowid
            scored = {"client_mac": "ca:34:ea:92:d3:9e"}

            spoof_res = AttackDetectionResult(
                category=AttackCategory.SPOOFING,
                status=DetectionStatus.SUSPICIOUS,
                severity=Severity.HIGH,
                evidence={
                    "verdict": "Hotspot Gateway IP Impersonation detected",
                    "claimed_ip": "192.168.137.1",
                    "offending_mac": "00:aa:bb:cc:dd:ee",
                    "is_randomized_mac": False,
                },
                missing_fields=[],
                confidence=0.85,
                timestamp=1000.0,
                recommended_action="Investigate offending device.",
            )

            # Create a broken/closed connection to force DB insertion failure
            broken_conn = sqlite3.connect(":memory:")
            broken_conn.close()

            # Attempt persistence on closed connection -> raises sqlite3.ProgrammingError
            with pytest.raises(sqlite3.ProgrammingError):
                collector._persist_attack_results(broken_conn, win_id, [], [spoof_res], "ca:34:ea:92:d3:9e", scored)

            # Cooldown cache should NOT contain the key
            norm_mac = "00:aa:bb:cc:dd:ee"
            norm_ip = "192.168.137.1"
            key = (run_id, norm_mac, norm_ip, AttackCategory.SPOOFING.value)
            assert key not in collector._spoofing_dedup_cache

            # Now retry with valid connection; it MUST succeed and persist
            ins = collector._persist_attack_results(conn, win_id, [], [spoof_res], "ca:34:ea:92:d3:9e", scored)
            assert ins == 1
            assert key in collector._spoofing_dedup_cache
        finally:
            conn.close()

    def test_new_run_clears_spoofing_cache(self, temp_db):
        """
        Stage 3.1: A new collector run clears the in-memory spoofing cooldown cache,
        allowing the same finding to be recorded in the new run without suppression.
        """
        conn = get_live_db_connection(temp_db)
        try:
            run_id_1 = _seed_run(conn)
            collector = LiveCollector(
                interface_index=1,
                db_path=temp_db,
                no_sensors=True,
                spoofing_cooldown_seconds=60.0,
            )
            collector._run_id = run_id_1
            collector._attack_table_present = True

            cur_win = conn.execute(
                "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
                "VALUES (?, 'ca:34:ea:92:d3:9e', 'Node_3', 1000.0, 1001.0, 10, 10.0)",
                (run_id_1,),
            )
            win_id = cur_win.lastrowid
            scored = {"client_mac": "ca:34:ea:92:d3:9e"}

            spoof_res = AttackDetectionResult(
                category=AttackCategory.SPOOFING,
                status=DetectionStatus.SUSPICIOUS,
                severity=Severity.HIGH,
                evidence={
                    "verdict": "Hotspot Gateway IP Impersonation detected",
                    "claimed_ip": "192.168.137.1",
                    "offending_mac": "00:aa:bb:cc:dd:ee",
                    "is_randomized_mac": False,
                },
                missing_fields=[],
                confidence=0.85,
                timestamp=1000.0,
                recommended_action="Investigate offending device.",
            )

            ins1 = collector._persist_attack_results(conn, win_id, [], [spoof_res], "ca:34:ea:92:d3:9e", scored)
            assert ins1 == 1

            # Second emission within run 1 is suppressed
            ins2 = collector._persist_attack_results(conn, win_id, [], [spoof_res], "ca:34:ea:92:d3:9e", scored)
            assert ins2 == 0

            # Start Run 2: simulate run change and cache clear as done in start()
            run_id_2 = _seed_run(conn)
            collector._run_id = run_id_2
            with collector._dedup_lock:
                collector._port_scan_dedup_cache.clear()
                collector._dos_dedup_cache.clear()
                collector._spoofing_dedup_cache.clear()

            cur_win2 = conn.execute(
                "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
                "VALUES (?, 'ca:34:ea:92:d3:9e', 'Node_3', 1002.0, 1003.0, 10, 10.0)",
                (run_id_2,),
            )
            win_id_2 = cur_win2.lastrowid

            # In Run 2, same finding must persist without being suppressed by Run 1
            ins3 = collector._persist_attack_results(conn, win_id_2, [], [spoof_res], "ca:34:ea:92:d3:9e", scored)
            assert ins3 == 1

            cur1 = conn.execute(
                "SELECT COUNT(*) FROM live_attack_events WHERE category = 'Spoofing_Impersonation' AND run_id = ?",
                (run_id_1,),
            )
            assert cur1.fetchone()[0] == 1

            cur2 = conn.execute(
                "SELECT COUNT(*) FROM live_attack_events WHERE category = 'Spoofing_Impersonation' AND run_id = ?",
                (run_id_2,),
            )
            assert cur2.fetchone()[0] == 1
        finally:
            conn.close()


# =============================================================================
# 10. Stage 4.3.1: Python Serial Message Routing and Interleaved Stream Tests
# =============================================================================

class TestSerialMessageRoutingStage431:
    """
    Comprehensive synthetic test suite for Stage 4.3.1 Python-side serial routing:
      1. Preserves existing sensor telemetry validation and SQLite persistence.
      2. Validates and routes 'wifi_mgmt' events to bounded inter-thread queue.
      3. Verifies 'wifi_mgmt' events never reach sensor validate_payload().
      4. Validates and tracks cumulative 'wifi_mgmt_summary' metrics separately.
      5. Handles probe / request-nonce handshake and stale-response rejection.
      6. Safely handles malformed lines, missing fields, invalid ranges, and queue-full.
      7. Guarantees 100% fidelity under interleaved sensor, sniffer, and debug streams.
    """

    def test_valid_sensor_message_routing_and_insertion(self, temp_db):
        """Valid sensor JSON is routed to validate_payload and persisted to SQLite."""
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(
                interface_index=1,
                serial_port="COM99",
                db_path=temp_db,
                session1_csv=DEFAULT_SESSION1_PATH,
            )
            collector._run_id = run_id

            sensor_line = json.dumps({
                "node": "esp32_gateway",
                "seq": 101,
                "uptime_ms": 20450,
                "dht11": {"valid": 1, "temp_c": 24.8, "humidity": 55.2},
                "pir": {"motion": 1},
            })

            res = collector.process_serial_line(sensor_line)
            assert res == "SENSOR_TELEMETRY"
            assert collector.stats["sensor_records"] == 1
            assert collector.stats["sensor_payloads_invalid"] == 0

            # Verify persisted in live_sensor_telemetry
            cur = conn.execute(
                "SELECT physical_node_id, sequence_num, temperature_c, humidity_pct "
                "FROM live_sensor_telemetry WHERE run_id = ? AND sequence_num = 101",
                (run_id,),
            )
            row = cur.fetchone()
            assert row is not None
            assert row[0] == "esp32_gateway"
            assert row[1] == 101
            assert abs(row[2] - 24.8) < 1e-4
            assert abs(row[3] - 55.2) < 1e-4

            # Verify persisted in live_pir_events
            cur_pir = conn.execute(
                "SELECT motion_detected FROM live_pir_events WHERE run_id = ? AND sequence_num = 101",
                (run_id,),
            )
            pir_row = cur_pir.fetchone()
            assert pir_row is not None
            assert pir_row[0] == 1
        finally:
            conn.close()

    def test_invalid_sensor_message_rejection(self, temp_db):
        """Invalid sensor telemetry is caught by validate_payload and rejected."""
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(
                interface_index=1,
                serial_port="COM99",
                db_path=temp_db,
                session1_csv=DEFAULT_SESSION1_PATH,
            )
            collector._run_id = run_id

            # Temperature 150.0 C is out of plausible range (-10 to 60 C)
            invalid_sensor_line = json.dumps({
                "node": "esp32_gateway",
                "seq": 102,
                "uptime_ms": 22450,
                "dht11": {"valid": 1, "temp_c": 150.0, "humidity": 55.2},
                "pir": {"motion": 0},
            })

            res = collector.process_serial_line(invalid_sensor_line)
            assert res == "INVALID_SENSOR"
            assert collector.stats["sensor_records"] == 0
            assert collector.stats["sensor_payloads_invalid"] == 1

            # Verify nothing inserted in DB
            cur = conn.execute("SELECT COUNT(*) FROM live_sensor_telemetry WHERE run_id = ?", (run_id,))
            assert cur.fetchone()[0] == 0
        finally:
            conn.close()

    def test_valid_wifi_mgmt_routed_to_queue(self, temp_db):
        """Valid wifi_mgmt event is parsed and placed into _wifi_mgmt_queue without touching sensors."""
        collector = LiveCollector(
            interface_index=1,
            serial_port="COM99",
            db_path=temp_db,
            session1_csv=DEFAULT_SESSION1_PATH,
        )

        wifi_line = json.dumps({
            "type": "wifi_mgmt",
            "boot_id": 184920,
            "seq": 1,
            "uptime_ms": 12050,
            "subtype": 12,
            "reason": 2,
            "ta": "aa:bb:cc:dd:ee:ff",
            "da": "11:22:33:44:55:66",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "rssi": -65,
        })

        res = collector.process_serial_line(wifi_line)
        assert res == "WIFI_MGMT_ENQUEUED"
        assert collector.stats["wifi_mgmt_events_parsed"] == 1
        assert collector.stats["wifi_mgmt_events_pushed"] == 1
        assert collector.stats["sensor_records"] == 0
        assert collector._wifi_mgmt_queue.qsize() == 1

        queued = collector._wifi_mgmt_queue.get_nowait()
        assert queued["seq"] == 1
        assert queued["subtype"] == 12
        assert queued["ta"] == "aa:bb:cc:dd:ee:ff"
        assert queued["rssi"] == -65

    def test_wifi_mgmt_not_passed_to_sensor_validator(self, temp_db):
        """Wi-Fi management frames are intercepted before reaching the strict sensor validate_payload path."""
        from unittest.mock import patch

        collector = LiveCollector(
            interface_index=1,
            serial_port="COM99",
            db_path=temp_db,
            session1_csv=DEFAULT_SESSION1_PATH,
        )

        wifi_line = json.dumps({
            "type": "wifi_mgmt",
            "boot_id": 184920,
            "seq": 2,
            "uptime_ms": 13000,
            "subtype": 10,
            "reason": 3,
            "ta": "aa:bb:cc:dd:ee:ff",
            "da": "ff:ff:ff:ff:ff:ff",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "rssi": -72,
        })

        with patch("src.live_collector.validate_payload") as mock_validate:
            res = collector.process_serial_line(wifi_line)
            assert res == "WIFI_MGMT_ENQUEUED"
            # Crucial assertion: validate_payload must NOT be called for wifi_mgmt events
            mock_validate.assert_not_called()

    def test_valid_wifi_mgmt_summary_routed_separately(self, temp_db):
        """wifi_mgmt_summary reports are routed to summary snapshot and compute deltas."""
        collector = LiveCollector(
            interface_index=1,
            serial_port="COM99",
            db_path=temp_db,
            session1_csv=DEFAULT_SESSION1_PATH,
        )

        summary_line_1 = json.dumps({
            "type": "wifi_mgmt_summary",
            "boot_id": 184920,
            "summary_seq": 1,
            "uptime_ms": 1000,
            "window_ms": 1000,
            "cumulative": {
                "rx_total": 50,
                "tb_suppressed": 40,
                "queue_dropped": 0,
                "enqueued": 10,
                "uart_accepted": 10,
                "uart_failed": 0,
            },
        })

        res1 = collector.process_serial_line(summary_line_1)
        assert res1 == "WIFI_SUMMARY"
        assert collector.stats["wifi_mgmt_summaries_parsed"] == 1
        assert collector._wifi_mgmt_queue.empty()
        assert collector._last_summary_snapshot is not None
        assert collector._last_summary_snapshot["window_delta"]["rx_total"] == 50

        summary_line_2 = json.dumps({
            "type": "wifi_mgmt_summary",
            "boot_id": 184920,
            "summary_seq": 2,
            "uptime_ms": 2000,
            "window_ms": 1000,
            "cumulative": {
                "rx_total": 120,
                "tb_suppressed": 100,
                "queue_dropped": 0,
                "enqueued": 20,
                "uart_accepted": 20,
                "uart_failed": 0,
            },
        })

        res2 = collector.process_serial_line(summary_line_2)
        assert res2 == "WIFI_SUMMARY"
        assert collector.stats["wifi_mgmt_summaries_parsed"] == 2
        # Verify delta computation: 120 - 50 = 70 rx_total
        assert collector._last_summary_snapshot["window_delta"]["rx_total"] == 70
        assert collector._last_summary_snapshot["window_delta"]["enqueued"] == 10

    def test_malformed_wifi_event_rejected_and_counted(self, temp_db):
        """Malformed Wi-Fi events are rejected safely without crashing the collector."""
        collector = LiveCollector(
            interface_index=1,
            serial_port="COM99",
            db_path=temp_db,
            session1_csv=DEFAULT_SESSION1_PATH,
        )

        # Missing required 'subtype' key
        malformed_line = json.dumps({
            "type": "wifi_mgmt",
            "boot_id": 184920,
            "seq": 1,
            "uptime_ms": 12050,
            "reason": 2,
            "ta": "aa:bb:cc:dd:ee:ff",
            "da": "11:22:33:44:55:66",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "rssi": -65,
        })

        res = collector.process_serial_line(malformed_line)
        assert res == "MALFORMED_WIFI_MGMT"
        assert collector.stats["wifi_mgmt_malformed"] == 1
        assert collector._wifi_mgmt_queue.empty()

    def test_missing_required_fields_handled_safely(self):
        """validate_wifi_mgmt_event fails safely on each missing required key."""
        base_valid = {
            "type": "wifi_mgmt",
            "boot_id": 100,
            "seq": 1,
            "uptime_ms": 1000,
            "subtype": 12,
            "reason": 2,
            "ta": "aa:bb:cc:dd:ee:ff",
            "da": "11:22:33:44:55:66",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "rssi": -60,
        }
        is_ok, msg = validate_wifi_mgmt_event(base_valid)
        assert is_ok and msg == "OK"

        for k in base_valid.keys():
            incomplete = dict(base_valid)
            del incomplete[k]
            is_valid, err_msg = validate_wifi_mgmt_event(incomplete)
            if k == "bssid":
                assert is_valid
                assert err_msg == "OK"
            else:
                assert not is_valid
                assert "Missing required key" in err_msg or "Expected type" in err_msg

    def test_invalid_field_types_and_out_of_range_rejected(self):
        """validate_wifi_mgmt_event enforces strict field types and physical ranges."""
        base = {
            "type": "wifi_mgmt",
            "boot_id": 100,
            "seq": 1,
            "uptime_ms": 1000,
            "subtype": 12,
            "reason": 2,
            "ta": "aa:bb:cc:dd:ee:ff",
            "da": "11:22:33:44:55:66",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "rssi": -60,
        }

        # Subtype 8 (Beacon) is not allowed (only 10=Disassoc, 12=Deauth)
        bad_subtype = dict(base, subtype=8)
        assert not validate_wifi_mgmt_event(bad_subtype)[0]

        # Negative sequence number
        bad_seq = dict(base, seq=-5)
        assert not validate_wifi_mgmt_event(bad_seq)[0]

        # Boolean in place of integer (isinstance(True, int) check)
        bad_bool_seq = dict(base, seq=True)
        assert not validate_wifi_mgmt_event(bad_bool_seq)[0]

        # Invalid MAC address string
        bad_mac = dict(base, ta="not-a-valid-mac")
        assert not validate_wifi_mgmt_event(bad_mac)[0]

        # Out-of-range positive RSSI
        bad_rssi = dict(base, rssi=10)
        assert not validate_wifi_mgmt_event(bad_rssi)[0]

        # Out-of-range low RSSI (-200 dBm)
        bad_low_rssi = dict(base, rssi=-200)
        assert not validate_wifi_mgmt_event(bad_low_rssi)[0]

        # Valid null reason (Protected Management Frame)
        valid_pmf = dict(base, reason=None)
        assert validate_wifi_mgmt_event(valid_pmf)[0]

    def test_full_wifi_queue_handled_without_blocking(self, temp_db):
        """When _wifi_mgmt_queue reaches max capacity (256), excess events are dropped without blocking."""
        collector = LiveCollector(
            interface_index=1,
            serial_port="COM99",
            db_path=temp_db,
            session1_csv=DEFAULT_SESSION1_PATH,
        )

        # Pre-fill queue to capacity (256 items)
        for i in range(256):
            collector._wifi_mgmt_queue.put_nowait({"mock_item": i})

        assert collector._wifi_mgmt_queue.full()

        overflow_line = json.dumps({
            "type": "wifi_mgmt",
            "boot_id": 184920,
            "seq": 9999,
            "uptime_ms": 50000,
            "subtype": 12,
            "reason": 2,
            "ta": "aa:bb:cc:dd:ee:ff",
            "da": "11:22:33:44:55:66",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "rssi": -65,
        })

        # Process the 257th event
        start_time = time.monotonic()
        res = collector.process_serial_line(overflow_line)
        elapsed = time.monotonic() - start_time

        # Must return immediately without blocking
        assert elapsed < 0.1
        assert res == "WIFI_MGMT_QUEUE_FULL"
        assert collector.stats["wifi_mgmt_queue_dropped"] == 1

    def test_probe_handshake_validation(self, temp_db):
        """Sniffer probe handshake validates expected nonce and rejects stale/mismatched responses."""
        collector = LiveCollector(
            interface_index=1,
            serial_port="COM99",
            db_path=temp_db,
            session1_csv=DEFAULT_SESSION1_PATH,
        )

        # 1. Host initiates probe
        sent_nonce = collector.send_sniffer_probe(ser=None, nonce=42042)
        assert sent_nonce == 42042
        assert collector.stats["sniffer_probe_requests_sent"] == 1
        assert collector._expected_probe_nonce == 42042

        # 2. Firmware echoes matching nonce
        valid_status_line = json.dumps({
            "status": "WIFI_SNIFFER_INITIALIZED",
            "boot_id": 777,
            "nonce": 42042,
            "channel": 6,
        })
        res1 = collector.process_serial_line(valid_status_line)
        assert res1 == "SNIFFER_STATUS"
        assert collector.active_boot_id == 777
        assert collector._session_established is True
        assert collector.stats["sniffer_status_responses_received"] == 1

        # 3. Subsequent probe with new nonce
        collector.send_sniffer_probe(ser=None, nonce=99999)

        # 4. Firmware emits delayed response with OLD nonce
        stale_status_line = json.dumps({
            "status": "WIFI_SNIFFER_INITIALIZED",
            "boot_id": 777,
            "nonce": 42042,
            "channel": 6,
        })
        res2 = collector.process_serial_line(stale_status_line)
        assert res2 == "STALE_SNIFFER_STATUS"
        assert collector.stats["sniffer_stale_probe_responses_dropped"] == 1
        assert collector.stats["sniffer_nonce_mismatches"] == 1

    def test_duplicate_and_stale_wifi_mgmt_events(self, temp_db):
        """Duplicate sequence numbers and stale pre-reboot events are detected and dropped."""
        collector = LiveCollector(
            interface_index=1,
            serial_port="COM99",
            db_path=temp_db,
            session1_csv=DEFAULT_SESSION1_PATH,
        )
        collector.active_boot_id = 500

        valid_evt = json.dumps({
            "type": "wifi_mgmt",
            "boot_id": 500,
            "seq": 10,
            "uptime_ms": 1000,
            "subtype": 12,
            "reason": 2,
            "ta": "aa:bb:cc:dd:ee:ff",
            "da": "11:22:33:44:55:66",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "rssi": -60,
        })

        # First delivery succeeds
        res1 = collector.process_serial_line(valid_evt)
        assert res1 == "WIFI_MGMT_ENQUEUED"

        # Duplicate delivery with same sequence number is dropped
        res2 = collector.process_serial_line(valid_evt)
        assert res2 == "DUPLICATE_WIFI_MGMT"
        assert collector.stats["wifi_mgmt_duplicate_events"] == 1

        # Stale event from old session (boot_id 400 != active 500)
        stale_evt = json.dumps({
            "type": "wifi_mgmt",
            "boot_id": 400,
            "seq": 11,
            "uptime_ms": 500,
            "subtype": 12,
            "reason": 2,
            "ta": "aa:bb:cc:dd:ee:ff",
            "da": "11:22:33:44:55:66",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "rssi": -60,
        })
        res3 = collector.process_serial_line(stale_evt)
        assert res3 == "STALE_WIFI_MGMT"
        assert collector.stats["wifi_mgmt_stale_events"] == 1

    def test_interleaved_sensor_and_wifi_messages(self, temp_db):
        """Sensor, Wi-Fi management, summary, and debug lines stream concurrently without cross-talk."""
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(
                interface_index=1,
                serial_port="COM99",
                db_path=temp_db,
                session1_csv=DEFAULT_SESSION1_PATH,
            )
            collector._run_id = run_id
            collector.active_boot_id = 100

            stream = [
                # 1. Boot announcement
                '{"status":"ESP32_TELEMETRY_INITIALIZED","baud":115200}',
                # 2. Sensor reading 1
                '{"node":"esp32_gateway","seq":1,"uptime_ms":2000,"dht11":{"valid":1,"temp_c":22.5,"humidity":48.0},"pir":{"motion":0}}',
                # 3. Wi-Fi deauth event 1
                '{"type":"wifi_mgmt","boot_id":100,"seq":1,"uptime_ms":2100,"subtype":12,"reason":2,"ta":"aa:bb:cc:dd:ee:ff","da":"11:22:33:44:55:66","bssid":"aa:bb:cc:dd:ee:ff","rssi":-62}',
                # 4. Wi-Fi deauth event 2
                '{"type":"wifi_mgmt","boot_id":100,"seq":2,"uptime_ms":2150,"subtype":12,"reason":2,"ta":"aa:bb:cc:dd:ee:ff","da":"11:22:33:44:55:66","bssid":"aa:bb:cc:dd:ee:ff","rssi":-63}',
                # 5. Raw debug print from firmware
                '[DEBUG] Channel 6 promiscuous rx active',
                # 6. Periodic summary
                '{"type":"wifi_mgmt_summary","boot_id":100,"summary_seq":1,"uptime_ms":3000,"window_ms":1000,"cumulative":{"rx_total":2,"tb_suppressed":0,"queue_dropped":0,"enqueued":2,"uart_accepted":2,"uart_failed":0}}',
                # 7. Sensor reading 2
                '{"node":"esp32_gateway","seq":2,"uptime_ms":4000,"dht11":{"valid":1,"temp_c":22.7,"humidity":48.5},"pir":{"motion":1}}',
                # 8. Wi-Fi disassoc event 3
                '{"type":"wifi_mgmt","boot_id":100,"seq":3,"uptime_ms":4100,"subtype":10,"reason":8,"ta":"aa:bb:cc:dd:ee:ff","da":"ff:ff:ff:ff:ff:ff","bssid":"aa:bb:cc:dd:ee:ff","rssi":-68}',
            ]

            results = [collector.process_serial_line(line) for line in stream]

            expected_routes = [
                "BOOT_ANNOUNCEMENT",
                "SENSOR_TELEMETRY",
                "WIFI_MGMT_ENQUEUED",
                "WIFI_MGMT_ENQUEUED",
                "RAW_LOG",
                "WIFI_SUMMARY",
                "SENSOR_TELEMETRY",
                "WIFI_MGMT_ENQUEUED",
            ]
            assert results == expected_routes

            # Exact counter verification:
            assert collector.stats["sensor_records"] == 2
            assert collector.stats["wifi_mgmt_events_pushed"] == 3
            assert collector.stats["wifi_mgmt_summaries_parsed"] == 1
            assert collector.stats["serial_raw_lines"] == 1
            assert collector.stats["wifi_mgmt_malformed"] == 0
            assert collector._wifi_mgmt_queue.qsize() == 3

            # Database check: exactly 2 sensor records and 2 PIR records persisted
            cur_sens = conn.execute("SELECT COUNT(*) FROM live_sensor_telemetry WHERE run_id = ?", (run_id,))
            assert cur_sens.fetchone()[0] == 2
            cur_pir = conn.execute("SELECT COUNT(*) FROM live_pir_events WHERE run_id = ?", (run_id,))
            assert cur_pir.fetchone()[0] == 2
        finally:
            conn.close()


# =============================================================================
# Stage 4.3.2: Deauthentication / Disassociation Detector Integration Tests
# =============================================================================

class TestDeauthDetectorIntegrationStage432:
    """
    Verifies Stage 4.3.2 deauthentication detector integration into LiveCollector:
      1. Correct PacketObservation field mapping from ESP32 JSON payload.
      2. Valid deauthentication events (subtype 12) reach detector and flag flood.
      3. Valid disassociation events (subtype 10) reach detector and flag flood.
      4. Protected frames: reason code set to None (never fabricated), size=42.
      5. Unprotected frames with null reason: preserved as None.
      6. Stale boot ID rejection during queue drain.
      7. Duplicate sequence rejection in serial router.
      8. Invalid and unsupported events safely rejected without crashing.
      9. Empty queue does not block network packet processing.
      10. Queue processing exceptions handled safely without terminating loop.
      11. Deauth cooldown deduplication suppresses repeated findings within window.
      12. Cooldown expiration allows new deauth alert row to persist.
      13. Frame count below flood threshold reports NO_EVIDENCE without alert row.
    """

    def test_packet_observation_field_mapping(self, temp_db):
        """All PacketObservation fields are mapped accurately from validated ESP32 wifi_mgmt payload."""
        collector = LiveCollector(
            interface_index=1,
            db_path=temp_db,
            no_sensors=True,
        )
        payload = {
            "type": "wifi_mgmt",
            "boot_id": 42,
            "seq": 105,
            "uptime_ms": 12500,
            "subtype": 12,
            "reason": 2,
            "ta": "00:11:22:33:44:55",
            "da": "66:77:88:99:aa:bb",
            "bssid": "00:11:22:33:44:55",
            "rssi": -65,
            "timestamp": 1700000000.5,
        }
        obs = collector._map_wifi_mgmt_to_observation(payload)
        assert obs is not None
        assert obs.timestamp == 1700000000.5
        # Frame length not provided in payload -> must be 0 sentinel (never nominal 26 or 42)
        assert obs.packet_size == 0
        assert obs.eth_src == "00:11:22:33:44:55"
        assert obs.eth_dst == "66:77:88:99:aa:bb"
        assert obs.ip_src is None
        assert obs.ip_dst is None
        assert obs.protocol == "802.11"
        assert obs.src_port is None
        assert obs.dst_port is None
        assert obs.tcp_flags is None
        assert obs.wlan_fc_type_subtype == 12
        assert obs.wlan_reason_code == 2
        assert obs.wlan_bssid == "00:11:22:33:44:55"
        # ESP32 event seq (105) is NOT 802.11 MAC sequence number -> protocol_seq_num MUST be None
        assert obs.protocol_seq_num is None
        assert obs.payload_hash is None
        assert obs.nonce is None
        assert obs.rssi_dbm == -65.0
        assert collector.stats["wifi_mgmt_deauth_events_mapped"] == 1

    def test_valid_deauth_event_reaches_detector_and_persists_flood(self, temp_db):
        """Valid deauth burst (subtype 12) drained from queue triggers SUSPICIOUS flood and persists row."""
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(
                interface_index=1,
                db_path=temp_db,
                no_sensors=True,
                deauth_cooldown_seconds=60.0,
            )
            collector._run_id = run_id
            collector._attack_table_present = True
            collector.active_boot_id = 100

            # Enqueue 8 deauth events within 1.0 second window
            for i in range(8):
                collector._wifi_mgmt_queue.put_nowait({
                    "type": "wifi_mgmt",
                    "boot_id": 100,
                    "seq": i + 1,
                    "uptime_ms": 1000 + i * 50,
                    "subtype": 12,
                    "reason": 7,
                    "ta": "00:11:22:33:44:55",
                    "da": "ff:ff:ff:ff:ff:ff",
                    "bssid": "00:11:22:33:44:55",
                    "rssi": -62,
                    "timestamp": 1000.0 + i * 0.05,
                })

            assert collector._wifi_mgmt_queue.qsize() == 8

            # Drain queue into observations
            obs_list = collector._drain_wifi_mgmt_queue(window_epoch=1000.0)
            assert len(obs_list) == 8
            assert collector.stats["wifi_mgmt_events_drained"] == 8
            assert collector.stats["wifi_mgmt_deauth_events_mapped"] == 8

            # Evaluate through unified attack detector
            stream_results = collector.attack_detector.evaluate_packet_stream(obs_list)
            deauth_results = [r for r in stream_results if r.category == AttackCategory.DEAUTH_FLOOD]
            assert len(deauth_results) == 1
            res = deauth_results[0]
            assert res.status == DetectionStatus.SUSPICIOUS
            assert res.severity == Severity.HIGH
            assert res.evidence["details"][0]["frame_count_in_window"] == 8
            assert res.evidence["details"][0]["bssid"] == "00:11:22:33:44:55"

            # Persist attack results
            scored = {"client_mac": "00:11:22:33:44:55"}
            inserted = collector._persist_attack_results(conn, None, [], stream_results, "00:11:22:33:44:55", scored)
            assert inserted == 1
            assert collector.stats["attack_events_flagged"] == 1

            # Verify SQLite row
            cur = conn.execute(
                "SELECT category, status, severity, source_mac, target_ip, confidence FROM live_attack_events WHERE run_id = ?",
                (run_id,),
            )
            row = cur.fetchone()
            assert row is not None
            assert row["category"] == AttackCategory.DEAUTH_FLOOD.value
            assert row["status"] == "SUSPICIOUS"
            assert row["severity"] == "HIGH"
            assert row["source_mac"] == "00:11:22:33:44:55"
            assert row["target_ip"] is None
            assert row["confidence"] >= 0.70
        finally:
            conn.close()

    def test_valid_disassoc_event_reaches_detector_and_persists_flood(self, temp_db):
        """Valid disassociation burst (subtype 10) triggers SUSPICIOUS flood and persists row."""
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(
                interface_index=1,
                db_path=temp_db,
                no_sensors=True,
                deauth_cooldown_seconds=60.0,
            )
            collector._run_id = run_id
            collector._attack_table_present = True
            collector.active_boot_id = 100

            # Enqueue 6 disassociation events within 1.0s window
            for i in range(6):
                collector._wifi_mgmt_queue.put_nowait({
                    "type": "wifi_mgmt",
                    "boot_id": 100,
                    "seq": i + 1,
                    "uptime_ms": 2000 + i * 50,
                    "subtype": 10,
                    "reason": 8,
                    "ta": "aa:bb:cc:dd:ee:ff",
                    "da": "ff:ff:ff:ff:ff:ff",
                    "bssid": "aa:bb:cc:dd:ee:ff",
                    "rssi": -58,
                    "timestamp": 2000.0 + i * 0.05,
                })

            obs_list = collector._drain_wifi_mgmt_queue(window_epoch=2000.0)
            assert len(obs_list) == 6
            assert collector.stats["wifi_mgmt_disassoc_events_mapped"] == 6

            stream_results = collector.attack_detector.evaluate_packet_stream(obs_list)
            deauth_results = [r for r in stream_results if r.category == AttackCategory.DEAUTH_FLOOD]
            assert len(deauth_results) == 1
            res = deauth_results[0]
            assert res.status == DetectionStatus.SUSPICIOUS
            assert res.severity == Severity.HIGH
            assert res.evidence["details"][0]["frame_count_in_window"] == 6

            scored = {"client_mac": "aa:bb:cc:dd:ee:ff"}
            inserted = collector._persist_attack_results(conn, None, [], stream_results, "aa:bb:cc:dd:ee:ff", scored)
            assert inserted == 1

            cur = conn.execute(
                "SELECT category, source_mac FROM live_attack_events WHERE run_id = ?",
                (run_id,),
            )
            row = cur.fetchone()
            assert row["category"] == AttackCategory.DEAUTH_FLOOD.value
            assert row["source_mac"] == "aa:bb:cc:dd:ee:ff"
        finally:
            conn.close()

    def test_protected_frame_reason_code_is_none(self, temp_db):
        """Protected management frames (PMF) treat encrypted reason code as opaque None and set size=42."""
        collector = LiveCollector(
            interface_index=1,
            db_path=temp_db,
            no_sensors=True,
        )
        payload = {
            "type": "wifi_mgmt",
            "boot_id": 1,
            "seq": 10,
            "uptime_ms": 5000,
            "subtype": 12,
            "is_protected": 1,
            "reason": 999,  # Encrypted dummy bytes from hardware
            "ta": "00:11:22:33:44:55",
            "da": "66:77:88:99:aa:bb",
            "bssid": "00:11:22:33:44:55",
            "rssi": -70,
        }
        obs = collector._map_wifi_mgmt_to_observation(payload)
        assert obs is not None
        assert obs.wlan_reason_code is None
        # Unmeasured frame length must be 0 sentinel (never nominal 42)
        assert obs.packet_size == 0

    def test_unprotected_frame_with_null_reason_code(self, temp_db):
        """Unprotected frames where firmware reason code is unavailable preserve wlan_reason_code as None."""
        collector = LiveCollector(
            interface_index=1,
            db_path=temp_db,
            no_sensors=True,
        )
        payload = {
            "type": "wifi_mgmt",
            "boot_id": 1,
            "seq": 11,
            "uptime_ms": 5100,
            "subtype": 12,
            "is_protected": 0,
            "reason": None,
            "ta": "00:11:22:33:44:55",
            "da": "66:77:88:99:aa:bb",
            "bssid": "00:11:22:33:44:55",
            "rssi": -72,
        }
        obs = collector._map_wifi_mgmt_to_observation(payload)
        assert obs is not None
        assert obs.wlan_reason_code is None
        # Unmeasured frame length must be 0 sentinel (never nominal 26)
        assert obs.packet_size == 0

    def test_stale_boot_id_rejection_in_drain(self, temp_db):
        """Events in queue with boot_id not matching active_boot_id are dropped as stale."""
        collector = LiveCollector(
            interface_index=1,
            db_path=temp_db,
            no_sensors=True,
        )
        collector.active_boot_id = 500

        # Put event with stale boot_id 400
        collector._wifi_mgmt_queue.put_nowait({
            "type": "wifi_mgmt",
            "boot_id": 400,
            "seq": 1,
            "uptime_ms": 1000,
            "subtype": 12,
            "reason": 2,
            "ta": "00:11:22:33:44:55",
            "da": "66:77:88:99:aa:bb",
            "bssid": "00:11:22:33:44:55",
            "rssi": -60,
        })

        obs = collector._drain_wifi_mgmt_queue()
        assert len(obs) == 0
        assert collector.stats["wifi_mgmt_stale_events"] == 1
        assert collector.stats["wifi_mgmt_events_drained"] == 1

    def test_duplicate_sequence_rejection_in_serial_router(self, temp_db):
        """Duplicate sequence numbers within a session are dropped before queue entry."""
        collector = LiveCollector(
            interface_index=1,
            db_path=temp_db,
            no_sensors=True,
        )
        collector.active_boot_id = 600

        line = json.dumps({
            "type": "wifi_mgmt",
            "boot_id": 600,
            "seq": 77,
            "uptime_ms": 2000,
            "subtype": 12,
            "reason": 2,
            "ta": "00:11:22:33:44:55",
            "da": "66:77:88:99:aa:bb",
            "bssid": "00:11:22:33:44:55",
            "rssi": -60,
        })

        res1 = collector.process_serial_line(line)
        assert res1 == "WIFI_MGMT_ENQUEUED"
        assert collector._wifi_mgmt_queue.qsize() == 1

        res2 = collector.process_serial_line(line)
        assert res2 == "DUPLICATE_WIFI_MGMT"
        assert collector.stats["wifi_mgmt_duplicate_events"] == 1
        assert collector._wifi_mgmt_queue.qsize() == 1

    def test_invalid_event_rejection(self, temp_db):
        """Malformed MACs and unsupported 802.11 subtypes are safely dropped without crashing."""
        collector = LiveCollector(
            interface_index=1,
            db_path=temp_db,
            no_sensors=True,
        )

        # 1. Invalid MAC
        bad_mac_payload = {
            "type": "wifi_mgmt",
            "boot_id": 1,
            "seq": 1,
            "uptime_ms": 100,
            "subtype": 12,
            "reason": 1,
            "ta": "not_a_valid_mac",
            "da": "00:11:22:33:44:55",
            "bssid": "00:11:22:33:44:55",
            "rssi": -60,
        }
        obs1 = collector._map_wifi_mgmt_to_observation(bad_mac_payload)
        assert obs1 is None
        assert collector.stats["wifi_mgmt_malformed"] == 1

        # 2. Unsupported subtype (e.g. 0 = Beacon, 8 = Probe Request)
        beacon_payload = {
            "type": "wifi_mgmt",
            "boot_id": 1,
            "seq": 2,
            "uptime_ms": 200,
            "subtype": 8,  # Probe Request
            "reason": None,
            "ta": "00:11:22:33:44:55",
            "da": "ff:ff:ff:ff:ff:ff",
            "bssid": "00:11:22:33:44:55",
            "rssi": -60,
        }
        obs2 = collector._map_wifi_mgmt_to_observation(beacon_payload)
        assert obs2 is None
        assert collector.stats["wifi_mgmt_dropped_unsupported_subtype"] == 1

        # 3. Non-dict input
        obs3 = collector._map_wifi_mgmt_to_observation("not_a_dict")
        assert obs3 is None

    def test_empty_queue_does_not_block_network_processing(self, temp_db):
        """Draining an empty queue returns immediately in non-blocking fashion without delay."""
        collector = LiveCollector(
            interface_index=1,
            db_path=temp_db,
            no_sensors=True,
        )
        assert collector._wifi_mgmt_queue.empty()

        t_start = time.monotonic()
        obs = collector._drain_wifi_mgmt_queue()
        elapsed = time.monotonic() - t_start

        assert obs == []
        assert elapsed < 0.01  # Must return immediately (<10ms)

    def test_queue_processing_exceptions_do_not_terminate_loop(self, temp_db):
        """Corrupt or exceptional objects in queue are caught safely without raising exceptions."""
        collector = LiveCollector(
            interface_index=1,
            db_path=temp_db,
            no_sensors=True,
        )
        # Put corrupt non-dict object
        collector._wifi_mgmt_queue.put_nowait(12345)
        # Put None object
        collector._wifi_mgmt_queue.put_nowait(None)

        obs = collector._drain_wifi_mgmt_queue()
        assert obs == []
        assert collector.stats["wifi_mgmt_malformed"] == 2

    def test_deauth_cooldown_deduplication(self, temp_db):
        """Repeated deauth flood findings for the same BSSID within cooldown window create exactly 1 row."""
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(
                interface_index=1,
                db_path=temp_db,
                no_sensors=True,
                deauth_cooldown_seconds=60.0,
            )
            collector._run_id = run_id
            collector._attack_table_present = True

            deauth_res = AttackDetectionResult(
                category=AttackCategory.DEAUTH_FLOOD,
                status=DetectionStatus.SUSPICIOUS,
                severity=Severity.HIGH,
                evidence={
                    "verdict": "802.11 Deauthentication flood detected",
                    "details": [{"bssid": "00:11:22:33:44:55", "frame_count_in_window": 12}],
                },
                missing_fields=[],
                confidence=0.95,
                timestamp=1000.0,
                recommended_action="Inspect physical environment.",
            )
            scored = {"client_mac": "00:11:22:33:44:55"}

            # First emit succeeds
            ins1 = collector._persist_attack_results(conn, None, [], [deauth_res], "00:11:22:33:44:55", scored)
            assert ins1 == 1

            # Second emit within 60s cooldown is suppressed
            ins2 = collector._persist_attack_results(conn, None, [], [deauth_res], "00:11:22:33:44:55", scored)
            assert ins2 == 0
            assert collector.stats["attack_events_cooldown_suppressed"] == 1

            # Distinct BSSID emits independently
            deauth_res_diff = AttackDetectionResult(
                category=AttackCategory.DEAUTH_FLOOD,
                status=DetectionStatus.SUSPICIOUS,
                severity=Severity.HIGH,
                evidence={
                    "verdict": "802.11 Deauthentication flood detected",
                    "details": [{"bssid": "aa:bb:cc:dd:ee:ff", "frame_count_in_window": 10}],
                },
                missing_fields=[],
                confidence=0.90,
                timestamp=1000.0,
                recommended_action="Inspect physical environment.",
            )
            ins3 = collector._persist_attack_results(conn, None, [], [deauth_res_diff], "aa:bb:cc:dd:ee:ff", scored)
            assert ins3 == 1
            assert collector.stats["attack_events_flagged"] == 2

            cur = conn.execute(
                "SELECT COUNT(*) FROM live_attack_events WHERE category = ? AND run_id = ?",
                (AttackCategory.DEAUTH_FLOOD.value, run_id),
            )
            assert cur.fetchone()[0] == 2
        finally:
            conn.close()

    def test_deauth_cooldown_expiration_creates_new_row(self, temp_db):
        """After deauth_cooldown_seconds expires, the same BSSID flood finding persists a new row."""
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(
                interface_index=1,
                db_path=temp_db,
                no_sensors=True,
                deauth_cooldown_seconds=0.05,
            )
            collector._run_id = run_id
            collector._attack_table_present = True

            deauth_res = AttackDetectionResult(
                category=AttackCategory.DEAUTH_FLOOD,
                status=DetectionStatus.SUSPICIOUS,
                severity=Severity.HIGH,
                evidence={
                    "verdict": "802.11 Deauthentication flood detected",
                    "details": [{"bssid": "00:11:22:33:44:55", "frame_count_in_window": 8}],
                },
                missing_fields=[],
                confidence=0.90,
                timestamp=1000.0,
                recommended_action="Inspect physical environment.",
            )
            scored = {"client_mac": "00:11:22:33:44:55"}

            ins1 = collector._persist_attack_results(conn, None, [], [deauth_res], "00:11:22:33:44:55", scored)
            assert ins1 == 1

            # Wait for 0.05s cooldown to expire (margin for Windows 15.6ms timer resolution)
            time.sleep(0.08)

            ins2 = collector._persist_attack_results(conn, None, [], [deauth_res], "00:11:22:33:44:55", scored)
            assert ins2 == 1
            assert collector.stats["attack_events_flagged"] == 2

            cur = conn.execute(
                "SELECT COUNT(*) FROM live_attack_events WHERE category = ? AND run_id = ?",
                (AttackCategory.DEAUTH_FLOOD.value, run_id),
            )
            assert cur.fetchone()[0] == 2
        finally:
            conn.close()

    def test_deauth_flood_below_threshold_reports_no_evidence(self, temp_db):
        """Frame counts below threshold (e.g. 2 frames < 5) report NO_EVIDENCE and are not persisted."""
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(
                interface_index=1,
                db_path=temp_db,
                no_sensors=True,
            )
            collector._run_id = run_id
            collector._attack_table_present = True

            # Only 2 deauth frames
            pkts = [
                PacketObservation(
                    timestamp=1000.0 + i * 0.1,
                    packet_size=26,
                    eth_src="00:11:22:33:44:55",
                    eth_dst="ff:ff:ff:ff:ff:ff",
                    protocol="802.11",
                    wlan_fc_type_subtype=12,
                    wlan_reason_code=2,
                    wlan_bssid="00:11:22:33:44:55",
                )
                for i in range(2)
            ]

            stream_results = collector.attack_detector.evaluate_packet_stream(pkts)
            deauth_results = [r for r in stream_results if r.category == AttackCategory.DEAUTH_FLOOD]
            assert len(deauth_results) == 1
            assert deauth_results[0].status == DetectionStatus.NO_EVIDENCE
            assert deauth_results[0].severity == Severity.NONE

            scored = {"client_mac": "00:11:22:33:44:55"}
            inserted = collector._persist_attack_results(conn, None, [], stream_results, "00:11:22:33:44:55", scored)
            assert inserted == 0
            assert collector.stats["attack_events_flagged"] == 0

            cur = conn.execute("SELECT COUNT(*) FROM live_attack_events WHERE run_id = ?", (run_id,))
            assert cur.fetchone()[0] == 0
        finally:
            conn.close()

    def test_esp32_event_sequence_not_mapped_to_protocol_sequence_num(self, temp_db):
        """
        Correction 1: The ESP32 event 'seq' field is an internal firmware admission / dispatch counter,
        NOT an 802.11 MAC Sequence Control number.
        - Must NOT be mapped to PacketObservation.protocol_seq_num (remains None).
        - When actual 802.11 MAC sequence is explicitly provided (wlan_seq), it is mapped.
        - ReplayDetector must report INSUFFICIENT_TELEMETRY without fabricated sequence numbers.
        """
        collector = LiveCollector(
            interface_index=1,
            db_path=temp_db,
            no_sensors=True,
        )

        # 1. ESP32 payload with internal admission seq=54321
        payload_internal_seq = {
            "type": "wifi_mgmt",
            "boot_id": 1,
            "seq": 54321,
            "uptime_ms": 3000,
            "subtype": 12,
            "reason": 2,
            "ta": "00:11:22:33:44:55",
            "da": "66:77:88:99:aa:bb",
            "bssid": "00:11:22:33:44:55",
            "rssi": -65,
        }
        obs1 = collector._map_wifi_mgmt_to_observation(payload_internal_seq)
        assert obs1 is not None
        # Must NOT map seq=54321 to protocol_seq_num
        assert obs1.protocol_seq_num is None

        # Replay detector evaluation must report INSUFFICIENT_TELEMETRY (no protocol sequence)
        replay_res = collector.attack_detector.replay_detector.evaluate([obs1])
        assert replay_res.status == DetectionStatus.INSUFFICIENT_TELEMETRY
        assert "protocol_seq_num" in replay_res.missing_fields

        # 2. ESP32 payload with explicitly captured 802.11 MAC sequence control number (wlan_seq)
        payload_with_wlan_seq = dict(payload_internal_seq)
        payload_with_wlan_seq["wlan_seq"] = 2048
        obs2 = collector._map_wifi_mgmt_to_observation(payload_with_wlan_seq)
        assert obs2 is not None
        assert obs2.protocol_seq_num == 2048

        # 3. ESP32 payload with mac_seq alternative
        payload_with_mac_seq = dict(payload_internal_seq)
        payload_with_mac_seq["mac_seq"] = 4095
        obs3 = collector._map_wifi_mgmt_to_observation(payload_with_mac_seq)
        assert obs3 is not None
        assert obs3.protocol_seq_num == 4095

    def test_packet_size_semantics_protected_unprotected_missing(self, temp_db):
        """
        Correction 2: Captured frame length semantics:
        - Do not represent nominal 26-byte or 42-byte estimates as measured lengths.
        - Missing length uses sentinel 0 (PACKET_SIZE_UNKNOWN) supported by PacketObservation.packet_size: int.
        - Explicitly captured frame lengths are preserved without alteration.
        """
        collector = LiveCollector(
            interface_index=1,
            db_path=temp_db,
            no_sensors=True,
        )

        base_payload = {
            "type": "wifi_mgmt",
            "boot_id": 1,
            "seq": 1,
            "uptime_ms": 1000,
            "subtype": 12,
            "reason": 2,
            "ta": "00:11:22:33:44:55",
            "da": "66:77:88:99:aa:bb",
            "bssid": "00:11:22:33:44:55",
            "rssi": -60,
        }

        # Case A: Unprotected frame with missing length -> sentinel 0 (never nominal 26)
        p_missing_unprot = dict(base_payload)
        obs_a = collector._map_wifi_mgmt_to_observation(p_missing_unprot)
        assert obs_a is not None
        assert obs_a.packet_size == 0

        # Case B: Protected frame with missing length -> sentinel 0 (never nominal 42)
        p_missing_prot = dict(base_payload)
        p_missing_prot["is_protected"] = 1
        obs_b = collector._map_wifi_mgmt_to_observation(p_missing_prot)
        assert obs_b is not None
        assert obs_b.packet_size == 0

        # Case C: Unprotected frame with explicitly captured frame length (e.g. 28 bytes)
        p_len_unprot = dict(base_payload)
        p_len_unprot["len"] = 28
        obs_c = collector._map_wifi_mgmt_to_observation(p_len_unprot)
        assert obs_c is not None
        assert obs_c.packet_size == 28

        # Case D: Protected frame with explicitly captured frame length (e.g. 44 bytes)
        p_len_prot = dict(base_payload)
        p_len_prot["is_protected"] = 1
        p_len_prot["frame_len"] = 44
        obs_d = collector._map_wifi_mgmt_to_observation(p_len_prot)
        assert obs_d is not None
        assert obs_d.packet_size == 44


class TestReplayPersistenceAttributionStage62:
    """
    Stage 6.2 Regression Tests:
    Verifies that _persist_attack_results() properly preserves source MAC and IP attribution
    for Replay events without confusing IP addresses with MAC addresses.
    """

    def test_replay_event_with_source_mac_and_ips_persists_correctly(self, temp_db):
        """
        Replay event with source MAC and source/destination IP persists all available addresses:
        - source_mac is populated with the valid hardware MAC (lowercase normalized).
        - target_ip is populated with the destination IP.
        - source_ip is preserved in evidence_json.
        """
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(interface_index=1, db_path=temp_db, no_sensors=True)
            collector._run_id = run_id
            collector._attack_table_present = True

            replay_res = AttackDetectionResult(
                category=AttackCategory.REPLAY,
                status=DetectionStatus.SUSPICIOUS,
                severity=Severity.HIGH,
                evidence={
                    "verdict": "Potential replay attack detected",
                    "violations": [
                        {
                            "anomaly_type": "Cryptographic Nonce Reuse",
                            "nonce": "test_nonce_abc_123",
                            "source_mac": "CA:34:EA:92:D3:9E",
                            "src": "192.168.137.201",
                            "dst": "192.168.137.1",
                            "time_delta_seconds": 15.0,
                        }
                    ],
                },
                missing_fields=[],
                confidence=0.85,
                timestamp=1700000000.0,
                recommended_action="Inspect token.",
            )

            scored = {"client_mac": "00:00:00:00:00:00"}
            inserted = collector._persist_attack_results(
                db=conn,
                window_id=None,
                dos_results=[],
                stream_results=[replay_res],
                client_mac="00:00:00:00:00:00",
                scored=scored,
            )
            assert inserted == 1

            cur = conn.execute(
                "SELECT category, status, severity, confidence, source_mac, target_ip, evidence_json "
                "FROM live_attack_events WHERE run_id = ?",
                (run_id,),
            )
            row = cur.fetchone()
            assert row is not None
            assert row[0] == AttackCategory.REPLAY.value
            assert row[1] == DetectionStatus.SUSPICIOUS.value
            assert row[2] == Severity.HIGH.value
            assert abs(row[3] - 0.85) < 0.001
            # Exact address mapping verification:
            assert row[4] == "ca:34:ea:92:d3:9e"  # Source MAC preserved and normalized
            assert row[5] == "192.168.137.1"       # Destination IP mapped to target_ip
            # Source IP preserved in evidence JSON:
            ev = json.loads(row[6])
            assert ev["source_ip"] == "192.168.137.201"
            assert ev["violations"][0]["src"] == "192.168.137.201"
        finally:
            conn.close()

    def test_replay_event_with_missing_source_mac_stores_null_not_ip(self, temp_db):
        """
        When source MAC is unavailable (e.g. only IP endpoints in evidence),
        source_mac MUST be stored as NULL, never populated with an IP address.
        """
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(interface_index=1, db_path=temp_db, no_sensors=True)
            collector._run_id = run_id
            collector._attack_table_present = True

            replay_res = AttackDetectionResult(
                category=AttackCategory.REPLAY,
                status=DetectionStatus.SUSPICIOUS,
                severity=Severity.HIGH,
                evidence={
                    "verdict": "Potential replay attack detected",
                    "violations": [
                        {
                            "anomaly_type": "Stale Payload Re-injection",
                            "payload_hash": "sha256_mock_hash",
                            "src": "192.168.137.150",
                            "dst": "192.168.137.1",
                            "time_delta_seconds": 12.5,
                        }
                    ],
                },
                missing_fields=[],
                confidence=0.70,
                timestamp=1700000000.0,
                recommended_action="Verify tokens.",
            )

            inserted = collector._persist_attack_results(
                db=conn,
                window_id=None,
                dos_results=[],
                stream_results=[replay_res],
                client_mac="00:00:00:00:00:00",
                scored={},
            )
            assert inserted == 1

            cur = conn.execute(
                "SELECT source_mac, target_ip, evidence_json FROM live_attack_events WHERE run_id = ?",
                (run_id,),
            )
            row = cur.fetchone()
            assert row is not None
            assert row[0] is None                 # Genuinely unavailable -> stored as NULL
            assert row[1] == "192.168.137.1"       # Destination IP mapped to target_ip
            ev = json.loads(row[2])
            assert ev["source_ip"] == "192.168.137.150"  # Source IP preserved in evidence
        finally:
            conn.close()

    def test_replay_event_with_missing_optional_ip_fields_handled_safely(self, temp_db):
        """
        When optional IP fields are missing (e.g. L2-only replay detection),
        source MAC is preserved, target_ip remains NULL, and no exceptions are raised.
        """
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(interface_index=1, db_path=temp_db, no_sensors=True)
            collector._run_id = run_id
            collector._attack_table_present = True

            replay_res = AttackDetectionResult(
                category=AttackCategory.REPLAY,
                status=DetectionStatus.SUSPICIOUS,
                severity=Severity.HIGH,
                evidence={
                    "verdict": "Potential replay attack detected",
                    "violations": [
                        {
                            "anomaly_type": "Cryptographic Nonce Reuse",
                            "nonce": "nonce_l2_only_test",
                            "source_mac": "aa:bb:cc:dd:ee:ff",
                            # IP fields explicitly absent / None
                            "src": None,
                            "dst": None,
                            "time_delta_seconds": 8.0,
                        }
                    ],
                },
                missing_fields=[],
                confidence=0.85,
                timestamp=1700000000.0,
                recommended_action="Inspect token.",
            )

            inserted = collector._persist_attack_results(
                db=conn,
                window_id=None,
                dos_results=[],
                stream_results=[replay_res],
                client_mac="00:00:00:00:00:00",
                scored={},
            )
            assert inserted == 1

            cur = conn.execute(
                "SELECT source_mac, target_ip FROM live_attack_events WHERE run_id = ?",
                (run_id,),
            )
            row = cur.fetchone()
            assert row is not None
            assert row[0] == "aa:bb:cc:dd:ee:ff"
            assert row[1] is None  # Missing destination IP remains NULL
        finally:
            conn.close()

    def test_replay_event_with_l2_src_mac_in_src_field_persists_correctly(self, temp_db):
        """
        When ReplayDetector outputs MAC addresses directly into 'src' and 'dst' (L2 fallback),
        the collector properly identifies 'src' as a MAC address and avoids misclassifying it as an IP.
        """
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(interface_index=1, db_path=temp_db, no_sensors=True)
            collector._run_id = run_id
            collector._attack_table_present = True

            replay_res = AttackDetectionResult(
                category=AttackCategory.REPLAY,
                status=DetectionStatus.SUSPICIOUS,
                severity=Severity.HIGH,
                evidence={
                    "verdict": "Potential replay attack detected",
                    "violations": [
                        {
                            "anomaly_type": "Cryptographic Nonce Reuse",
                            "nonce": "nonce_l2_macs",
                            "src": "00:11:22:33:44:55",
                            "dst": "66:77:88:99:aa:bb",
                            "time_delta_seconds": 5.0,
                        }
                    ],
                },
                missing_fields=[],
                confidence=0.85,
                timestamp=1700000000.0,
                recommended_action="Inspect token.",
            )

            inserted = collector._persist_attack_results(
                db=conn,
                window_id=None,
                dos_results=[],
                stream_results=[replay_res],
                client_mac="00:00:00:00:00:00",
                scored={},
            )
            assert inserted == 1

            cur = conn.execute(
                "SELECT source_mac, target_ip FROM live_attack_events WHERE run_id = ?",
                (run_id,),
            )
            row = cur.fetchone()
            assert row is not None
            assert row[0] == "00:11:22:33:44:55"  # Identified as MAC address
            assert row[1] is None                 # Destination MAC is NOT put into target_ip
        finally:
            conn.close()

    def test_existing_non_replay_attack_persistence_unaffected(self, temp_db):
        """
        Confirms that persistence for non-Replay categories (DoS, Port Scan, Spoofing, Deauth)
        operates identically without any regression.
        """
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(interface_index=1, db_path=temp_db, no_sensors=True)
            collector._run_id = run_id
            collector._attack_table_present = True

            # 1. DoS result
            dos_res = AttackDetectionResult(
                category=AttackCategory.DOS,
                status=DetectionStatus.CONFIRMED_THREAT,
                severity=Severity.CRITICAL,
                evidence={"verdict": "Sustained high-rate flood", "rate_pps": 120.0},
                missing_fields=[],
                confidence=0.95,
                timestamp=1700000000.0,
                recommended_action="Inspect flood.",
            )

            # 2. Spoofing result
            spoof_res = AttackDetectionResult(
                category=AttackCategory.SPOOFING,
                status=DetectionStatus.CONFIRMED_THREAT,
                severity=Severity.CRITICAL,
                evidence={"verdict": "Rogue Gateway Claim", "offending_mac": "de:ad:be:ef:00:01", "claimed_ip": "192.168.137.1"},
                missing_fields=[],
                confidence=0.99,
                timestamp=1700000000.0,
                recommended_action="Isolate rogue gateway.",
            )

            scored = {"ip_dst": "192.168.137.1"}
            ins = collector._persist_attack_results(
                db=conn,
                window_id=None,
                dos_results=[dos_res],
                stream_results=[spoof_res],
                client_mac="ca:34:ea:92:d3:9e",
                scored=scored,
            )
            assert ins == 2

            cur = conn.execute(
                "SELECT category, source_mac, target_ip FROM live_attack_events WHERE run_id = ? ORDER BY event_id ASC",
                (run_id,),
            )
            rows = cur.fetchall()
            assert len(rows) == 2
            # DoS mapping:
            assert rows[0][0] == AttackCategory.DOS.value
            assert rows[0][1] == "ca:34:ea:92:d3:9e"
            assert rows[0][2] == "192.168.137.1"
            # Spoofing mapping:
            assert rows[1][0] == AttackCategory.SPOOFING.value
            assert rows[1][1] == "de:ad:be:ef:00:01"
            assert rows[1][2] == "192.168.137.1"
        finally:
            conn.close()

    def test_replay_cooldown_behavior_preserved(self, temp_db):
        """
        Confirms that Replay attack alert persistence continues emitting each detected
        replay finding without spurious cooldown side effects.
        """
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(interface_index=1, db_path=temp_db, no_sensors=True)
            collector._run_id = run_id
            collector._attack_table_present = True

            res = AttackDetectionResult(
                category=AttackCategory.REPLAY,
                status=DetectionStatus.SUSPICIOUS,
                severity=Severity.HIGH,
                evidence={
                    "verdict": "Potential replay attack detected",
                    "violations": [
                        {
                            "anomaly_type": "Cryptographic Nonce Reuse",
                            "nonce": "cooldown_test_nonce",
                            "source_mac": "00:11:22:33:44:55",
                            "src": "192.168.137.201",
                            "dst": "192.168.137.1",
                            "time_delta_seconds": 10.0,
                        }
                    ],
                },
                missing_fields=[],
                confidence=0.85,
                timestamp=1700000000.0,
                recommended_action="Inspect.",
            )

            ins1 = collector._persist_attack_results(conn, None, [], [res], "00:11:22:33:44:55", {})
            assert ins1 == 1

            ins2 = collector._persist_attack_results(conn, None, [], [res], "00:11:22:33:44:55", {})
            assert ins2 == 1

            cur = conn.execute("SELECT COUNT(*) FROM live_attack_events WHERE run_id = ?", (run_id,))
            assert cur.fetchone()[0] == 2
        finally:
            conn.close()


class TestOptionalBSSIDValidationStage63:
    """Stage 6.3 validation: Optional BSSID in Wi-Fi management telemetry."""

    @pytest.fixture
    def base_event(self) -> Dict[str, Any]:
        return {
            "type": "wifi_mgmt",
            "boot_id": 100,
            "seq": 1,
            "uptime_ms": 1000,
            "subtype": 12,
            "reason": 2,
            "ta": "aa:bb:cc:dd:ee:ff",
            "da": "11:22:33:44:55:66",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "rssi": -60,
        }

    def test_valid_event_with_bssid_succeeds(self, base_event):
        """Standard event with valid BSSID string succeeds validation."""
        is_valid, msg = validate_wifi_mgmt_event(base_event)
        assert is_valid is True
        assert msg == "OK"

    def test_missing_bssid_key_succeeds(self, base_event):
        """Event with missing 'bssid' key completely succeeds validation."""
        event = dict(base_event)
        del event["bssid"]
        is_valid, msg = validate_wifi_mgmt_event(event)
        assert is_valid is True
        assert msg == "OK"

    def test_explicit_none_bssid_succeeds(self, base_event):
        """Event with 'bssid': None succeeds validation."""
        event = dict(base_event)
        event["bssid"] = None
        is_valid, msg = validate_wifi_mgmt_event(event)
        assert is_valid is True
        assert msg == "OK"

    def test_empty_string_bssid_succeeds(self, base_event):
        """Event with 'bssid': '' succeeds validation."""
        event = dict(base_event)
        event["bssid"] = ""
        is_valid, msg = validate_wifi_mgmt_event(event)
        assert is_valid is True
        assert msg == "OK"

    def test_invalid_bssid_string_rejected(self, base_event):
        """Event with non-empty invalid MAC string for BSSID is rejected."""
        event = dict(base_event)
        event["bssid"] = "not-a-valid-mac"
        is_valid, msg = validate_wifi_mgmt_event(event)
        assert is_valid is False
        assert "Invalid BSSID MAC" in msg

        event["bssid"] = 12345
        is_valid, msg = validate_wifi_mgmt_event(event)
        assert is_valid is False
        assert "Invalid BSSID MAC" in msg

    def test_missing_mandatory_fields_rejected(self, base_event):
        """Removing any mandatory field (type, boot_id, seq, uptime_ms, subtype, reason, ta, da, rssi) fails."""
        mandatory_keys = ["type", "boot_id", "seq", "uptime_ms", "subtype", "reason", "ta", "da", "rssi"]
        for key in mandatory_keys:
            bad_event = dict(base_event)
            del bad_event[key]
            is_valid, msg = validate_wifi_mgmt_event(bad_event)
            assert is_valid is False, f"Expected key '{key}' to be required"
            assert "Missing required key" in msg or "Expected type" in msg

    def test_serial_ingestion_and_enqueue_missing_bssid(self, temp_db):
        """JSON serial line with missing 'bssid' key successfully parses and enqueues."""
        collector = LiveCollector(interface_index=1, db_path=temp_db, no_sensors=True)
        collector.active_boot_id = 100
        raw_line = json.dumps({
            "type": "wifi_mgmt",
            "boot_id": 100,
            "seq": 10,
            "uptime_ms": 2000,
            "subtype": 12,
            "reason": 3,
            "ta": "00:aa:bb:cc:dd:ee",
            "da": "ff:ff:ff:ff:ff:ff",
            "rssi": -55,
        })
        res = collector.process_serial_line(raw_line)
        assert res == "WIFI_MGMT_ENQUEUED"
        assert collector.stats["wifi_mgmt_events_pushed"] == 1
        assert collector._wifi_mgmt_queue.qsize() == 1

        enqueued = collector._wifi_mgmt_queue.get_nowait()
        assert "bssid" not in enqueued
        assert enqueued["ta"] == "00:aa:bb:cc:dd:ee"

    def test_map_wifi_mgmt_to_observation_missing_bssid(self, temp_db):
        """Observation mapper produces wlan_bssid=None when bssid key is missing or empty."""
        collector = LiveCollector(interface_index=1, db_path=temp_db, no_sensors=True)
        # 1. Missing key
        p1 = {
            "type": "wifi_mgmt", "boot_id": 1, "seq": 1, "uptime_ms": 100,
            "subtype": 12, "reason": 1, "ta": "00:11:22:33:44:55", "da": "ff:ff:ff:ff:ff:ff", "rssi": -50,
        }
        obs1 = collector._map_wifi_mgmt_to_observation(p1)
        assert obs1 is not None
        assert obs1.wlan_bssid is None
        assert obs1.eth_src == "00:11:22:33:44:55"
        assert obs1.eth_dst == "ff:ff:ff:ff:ff:ff"

        # 2. bssid is None
        p2 = dict(p1, bssid=None, seq=2)
        obs2 = collector._map_wifi_mgmt_to_observation(p2)
        assert obs2 is not None
        assert obs2.wlan_bssid is None

        # 3. bssid is ""
        p3 = dict(p1, bssid="", seq=3)
        obs3 = collector._map_wifi_mgmt_to_observation(p3)
        assert obs3 is not None
        assert obs3.wlan_bssid is None

        # 4. Valid BSSID preserved
        p4 = dict(p1, bssid="66:77:88:99:aa:bb", seq=4)
        obs4 = collector._map_wifi_mgmt_to_observation(p4)
        assert obs4 is not None
        assert obs4.wlan_bssid == "66:77:88:99:aa:bb"

    def test_end_to_end_pipeline_missing_bssid_deauth_flood_fallback_attribution(self, temp_db):
        """
        Full end-to-end integration:
          Serial JSON (missing bssid) -> process_serial_line -> _wifi_mgmt_queue
          -> _drain_wifi_mgmt_queue -> evaluate_packet_stream -> DeauthDetector fallback attribution
          -> _persist_attack_results -> live_attack_events DB verification.
        """
        conn = get_live_db_connection(temp_db)
        try:
            run_id = _seed_run(conn)
            collector = LiveCollector(
                interface_index=1,
                db_path=temp_db,
                no_sensors=True,
                deauth_cooldown_seconds=60.0,
            )
            collector._run_id = run_id
            collector._attack_table_present = True
            collector.active_boot_id = 200

            attacker_mac = "aa:11:22:33:44:bb"
            target_mac = "ff:ff:ff:ff:ff:ff"

            # Ingest 6 deauth frames missing 'bssid' key via serial JSON line processing
            for i in range(6):
                line = json.dumps({
                    "type": "wifi_mgmt",
                    "boot_id": 200,
                    "seq": i + 1,
                    "uptime_ms": 1000 + i * 50,
                    "subtype": 12,
                    "reason": 7,
                    "ta": attacker_mac,
                    "da": target_mac,
                    "rssi": -65,
                    "timestamp": 1000.0 + i * 0.05,
                })
                res = collector.process_serial_line(line)
                assert res == "WIFI_MGMT_ENQUEUED"

            assert collector._wifi_mgmt_queue.qsize() == 6

            # Drain queue into observations
            obs_list = collector._drain_wifi_mgmt_queue(window_epoch=1000.0)
            assert len(obs_list) == 6
            for obs in obs_list:
                assert obs.wlan_bssid is None
                assert obs.eth_src == attacker_mac

            # Evaluate through unified attack detector
            stream_results = collector.attack_detector.evaluate_packet_stream(obs_list)
            deauth_results = [r for r in stream_results if r.category == AttackCategory.DEAUTH_FLOOD]
            assert len(deauth_results) == 1
            res = deauth_results[0]
            assert res.status in (DetectionStatus.SUSPICIOUS, DetectionStatus.CONFIRMED_THREAT)
            # Confirms fallback attribution to source MAC (ta)
            assert res.evidence["details"][0]["bssid"] == attacker_mac
            assert res.evidence["details"][0]["frame_count_in_window"] == 6

            # Persist attack results to DB
            inserted = collector._persist_attack_results(
                db=conn,
                window_id=None,
                dos_results=[],
                stream_results=deauth_results,
                client_mac="00:00:00:00:00:00",
                scored={},
            )
            assert inserted == 1

            # Verify persisted row in SQLite
            cur = conn.execute(
                "SELECT category, source_mac, target_ip FROM live_attack_events WHERE run_id = ?",
                (run_id,),
            )
            rows = cur.fetchall()
            assert len(rows) == 1
            category, source_mac, target_ip = rows[0]
            assert category == AttackCategory.DEAUTH_FLOOD.value
            assert source_mac == attacker_mac
            assert target_ip is None
        finally:
            conn.close()

