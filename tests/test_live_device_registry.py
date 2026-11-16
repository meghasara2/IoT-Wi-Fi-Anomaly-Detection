"""
Unit Tests: Live Device Registry and Unknown Device Detection
File: tests/test_live_device_registry.py

Covers Requirements for Phase 2 Live IoT Network Security:
  1. Safe registration of known client MAC addresses into device_registry.
  2. Packet attribution for registered MAC addresses (Node_3, Node_4) without generating unknown device alerts.
  3. Detection and persistence of unknown/unregistered MAC observations in unknown_device_obs.
  4. Repeated observations of the same unknown MAC incrementing observation_count and updating last_seen_utc.
  5. Reserved status for Node 5 (Phone 3): present in registry as reserved, produces 0 traffic windows until packets are seen.
  6. Production database safety: ensures registration routines reject data/iot_anomaly.db.

All tests operate exclusively against an isolated, temporary SQLite database.
"""

import io
import sqlite3
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, List
from unittest.mock import MagicMock, patch

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))
_SRC_DIR = _PROJECT_ROOT / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from src.init_live_database import (
    DEFAULT_KNOWN_DEVICES,
    PRODUCTION_DB_PATH,
    get_live_db_connection,
    init_live_database,
    register_device,
    seed_default_devices,
)
from src.live_collector import (
    LiveCollector,
    _insert_traffic_window,
    _upsert_unknown_device,
)
from src.live_stream_extractor import (
    LiveStreamExtractor,
    _RawPacket,
    _attribute_packet,
)

# Test Constants
PHONE1_MAC = "ca:34:ea:92:d3:9e"
PHONE2_MAC = "e6:2e:db:73:1c:25"
RESERVED_PHONE3_MAC = "00:00:00:00:00:05"
UNKNOWN_MAC_1 = "de:ad:be:ef:01:23"
UNKNOWN_MAC_2 = "aa:bb:cc:dd:ee:ff"


@pytest.fixture
def temp_db(tmp_path):
    """Creates a temporary, isolated SQLite live monitoring database."""
    db_path = tmp_path / "test_monitoring.db"
    init_live_database(db_path, overwrite=True, seed_defaults=False)
    conn = get_live_db_connection(db_path)
    # Insert dummy collector run
    cur = conn.execute(
        "INSERT INTO collector_status (interface_index, status) VALUES (1, 'RUNNING')"
    )
    conn.commit()
    run_id = cur.lastrowid
    yield conn, run_id, db_path
    conn.close()


class TestLiveDeviceRegistry:
    """Verifies persisted device registry operations and safety."""

    def test_seed_default_devices(self, temp_db):
        conn, _, _ = temp_db
        count = seed_default_devices(conn)
        assert count == 3

        # Verify rows exist
        rows = conn.execute("SELECT mac_address, node_id, label FROM device_registry ORDER BY node_id").fetchall()
        assert len(rows) == 3
        assert rows[0]["node_id"] == "Node_3"
        assert rows[0]["mac_address"] == PHONE1_MAC
        assert rows[1]["node_id"] == "Node_4"
        assert rows[1]["mac_address"] == PHONE2_MAC
        assert rows[2]["node_id"] == "Node_5"
        assert rows[2]["mac_address"] == RESERVED_PHONE3_MAC
        assert rows[2]["label"] == "reserved_demo"

    def test_seed_default_devices_idempotent(self, temp_db):
        conn, _, _ = temp_db
        first_count = seed_default_devices(conn)
        assert first_count == 3
        # Second call should insert 0 duplicates
        second_count = seed_default_devices(conn)
        assert second_count == 0

    def test_register_device_custom_upsert(self, temp_db):
        conn, _, _ = temp_db
        custom_mac = "12:34:56:78:9a:bc"
        register_device(
            conn=conn,
            mac_address=custom_mac,
            node_id="Node_6",
            device_type="Test_Device",
            label="experimental_client",
            notes="Added by automated test",
        )
        row = conn.execute("SELECT * FROM device_registry WHERE mac_address=?", (custom_mac,)).fetchone()
        assert row is not None
        assert row["node_id"] == "Node_6"
        assert row["notes"] == "Added by automated test"

        # Update existing
        register_device(
            conn=conn,
            mac_address=custom_mac,
            node_id="Node_6_Updated",
            notes="Updated notes",
        )
        row2 = conn.execute("SELECT * FROM device_registry WHERE mac_address=?", (custom_mac,)).fetchone()
        assert row2["node_id"] == "Node_6_Updated"
        assert row2["notes"] == "Updated notes"

    def test_production_safety_guard(self):
        with pytest.raises(RuntimeError, match="SAFETY GUARD"):
            init_live_database(PRODUCTION_DB_PATH)


class TestRegisteredAndUnknownDeviceDetection:
    """Verifies stream attribution, unknown device logging, and repeated observation increments."""

    def _make_tshark_line(self, frame=1, epoch=1000.0, length=120, src=PHONE1_MAC,
                          dst="00:15:5d:01:02:03", ip_src="192.168.137.201", ip_dst="8.8.8.8", proto="TCP"):
        return f"{frame}\t{epoch}\t{length}\t{src}\t{dst}\t{ip_src}\t{ip_dst}\t{proto}\n"

    def test_registered_mac_produces_traffic_without_unknown_alert(self, temp_db):
        conn, run_id, _ = temp_db
        seed_default_devices(conn)

        # Build in-memory registry dict from SQLite
        rows = conn.execute("SELECT mac_address, node_id, device_type, label FROM device_registry").fetchall()
        registry = {r["mac_address"]: dict(r) for r in rows}

        extractor = LiveStreamExtractor(interface_index=1, device_registry=registry)
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.stdout = io.StringIO(
            self._make_tshark_line(frame=1, epoch=1000.2, src=PHONE1_MAC)
            + self._make_tshark_line(frame=2, epoch=1000.6, src=PHONE1_MAC)
        )
        extractor._proc = mock_proc

        windows = list(extractor.iter_windows())
        assert len(windows) == 1
        assert windows[0]["node_id"] == "Node_3"
        assert windows[0]["client_mac"] == PHONE1_MAC

        # Unknown devices should be completely empty
        unknown = extractor.drain_unregistered_macs()
        assert len(unknown) == 0

        # No rows in unknown_device_obs
        unk_rows = conn.execute("SELECT COUNT(*) FROM unknown_device_obs").fetchone()[0]
        assert unk_rows == 0

    def test_unknown_mac_detection_and_persisted_observation(self, temp_db):
        conn, run_id, _ = temp_db
        seed_default_devices(conn)

        rows = conn.execute("SELECT mac_address, node_id, device_type, label FROM device_registry").fetchall()
        registry = {r["mac_address"]: dict(r) for r in rows}

        extractor = LiveStreamExtractor(interface_index=1, device_registry=registry)
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        # Send packet from UNKNOWN_MAC_1
        mock_proc.stdout = io.StringIO(
            self._make_tshark_line(frame=1, epoch=1000.2, src=UNKNOWN_MAC_1, ip_src="192.168.137.99")
        )
        extractor._proc = mock_proc

        # Process stream: packet is unregistered, so 0 feature windows emitted
        windows = list(extractor.iter_windows())
        assert len(windows) == 0

        # Unregistered MAC should be collected
        unknown = extractor.drain_unregistered_macs()
        assert UNKNOWN_MAC_1 in unknown

        # Persist observation to unknown_device_obs table
        for mac in unknown:
            _upsert_unknown_device(conn, run_id, mac)

        row = conn.execute("SELECT observed_mac, observation_count FROM unknown_device_obs WHERE observed_mac=?", (UNKNOWN_MAC_1,)).fetchone()
        assert row is not None
        assert row["observed_mac"] == UNKNOWN_MAC_1
        assert row["observation_count"] == 1

    def test_repeated_unknown_mac_observations_increment_counter(self, temp_db):
        conn, run_id, _ = temp_db
        mac = UNKNOWN_MAC_2

        # First observation
        _upsert_unknown_device(conn, run_id, mac)
        r1 = conn.execute("SELECT observation_count, first_seen_utc, last_seen_utc FROM unknown_device_obs WHERE observed_mac=?", (mac,)).fetchone()
        assert r1["observation_count"] == 1

        # Second observation
        _upsert_unknown_device(conn, run_id, mac)
        r2 = conn.execute("SELECT observation_count FROM unknown_device_obs WHERE observed_mac=?", (mac,)).fetchone()
        assert r2["observation_count"] == 2

        # Third observation
        _upsert_unknown_device(conn, run_id, mac)
        r3 = conn.execute("SELECT observation_count FROM unknown_device_obs WHERE observed_mac=?", (mac,)).fetchone()
        assert r3["observation_count"] == 3

        # Exactly one unique row for this MAC
        total_rows = conn.execute("SELECT COUNT(*) FROM unknown_device_obs WHERE observed_mac=?", (mac,)).fetchone()[0]
        assert total_rows == 1

    def test_reserved_node5_unobserved_until_traffic_arrives(self, temp_db):
        conn, run_id, _ = temp_db
        seed_default_devices(conn)

        # 1. Node 5 exists in registry as reserved
        row = conn.execute("SELECT node_id, label, notes FROM device_registry WHERE mac_address=?", (RESERVED_PHONE3_MAC,)).fetchone()
        assert row is not None
        assert row["node_id"] == "Node_5"
        assert row["label"] == "reserved_demo"

        # 2. Check live_traffic_windows has 0 rows for Node 5
        node5_traffic_count = conn.execute(
            "SELECT COUNT(*) FROM live_traffic_windows WHERE node_id='Node_5'"
        ).fetchone()[0]
        assert node5_traffic_count == 0

        # 3. Simulate traffic arriving from Node 5 in a live test
        rows = conn.execute("SELECT mac_address, node_id, device_type, label FROM device_registry").fetchall()
        registry = {r["mac_address"]: dict(r) for r in rows}

        extractor = LiveStreamExtractor(interface_index=1, device_registry=registry)
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.stdout = io.StringIO(
            self._make_tshark_line(frame=1, epoch=1005.1, src=RESERVED_PHONE3_MAC, ip_src="192.168.137.150")
            + self._make_tshark_line(frame=2, epoch=1005.8, src=RESERVED_PHONE3_MAC, ip_src="192.168.137.150")
        )
        extractor._proc = mock_proc

        windows = list(extractor.iter_windows())
        assert len(windows) == 1
        assert windows[0]["node_id"] == "Node_5"
        assert windows[0]["client_mac"] == RESERVED_PHONE3_MAC
        assert windows[0]["packet_count"] == 2

        # Save window to DB
        _insert_traffic_window(conn, run_id, windows[0])
        n5_count_after = conn.execute(
            "SELECT COUNT(*) FROM live_traffic_windows WHERE node_id='Node_5'"
        ).fetchone()[0]
        assert n5_count_after == 1


class TestDynamicDeviceRegistryRefreshStage652:
    """
    Covers Stage 6.5.2 Dynamic Device Registry Refresh requirements:
      1. A newly registered device becomes recognized without restarting the collector.
      2. A removed device disappears after refresh, according to existing semantics.
      3. MAC address normalization remains correct (hyphens, case, whitespace).
      4. Duplicate entries are handled safely.
      5. Failed database refresh preserves the previous registry.
      6. Extractor and detector receive consistent registry updates.
      7. Refresh does not reset detector history or cooldowns.
      8. Packet processing can continue during refresh (concurrency / thread safety).
      9. Refresh interval prevents per-packet database queries.
      10. Existing device-registry tests remain passing.
    """

    @pytest.fixture
    def collector_env(self, tmp_path):
        db_path = tmp_path / "dynamic_reg_test.db"
        init_live_database(db_path, overwrite=True, seed_defaults=True)
        collector = LiveCollector(interface_index=1, db_path=db_path, no_sensors=True)
        collector._run_id = 1
        extractor = LiveStreamExtractor(interface_index=1, device_registry=collector.device_registry)
        collector._extractor = extractor
        yield collector, extractor, db_path
        if db_path.exists():
            try:
                db_path.unlink()
            except Exception:
                pass

    def test_newly_registered_device_recognized_at_runtime(self, collector_env):
        """1: Newly registered device becomes recognized without collector restart."""
        collector, extractor, db_path = collector_env
        new_mac = "aa:bb:cc:dd:ee:99"

        # Initially unrecognized
        pkt = _RawPacket(
            timestamp=1000.0,
            packet_size=100,
            eth_src=new_mac,
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.99",
            ip_dst="8.8.8.8",
            protocol="TCP",
        )
        node_id, info, direction = _attribute_packet(pkt, extractor.registry)
        assert node_id is None
        assert direction == "unregistered"

        # Register device into SQLite
        conn = get_live_db_connection(db_path)
        register_device(conn, mac_address=new_mac, node_id="Node_99", device_type="IoT_Sensor", label="test_node")
        conn.close()

        # Trigger refresh
        refreshed = collector.refresh_device_registry(force=True)
        assert refreshed is True
        assert new_mac in collector.device_registry
        assert new_mac in extractor.registry
        assert new_mac in collector.attack_detector.spoofing_detector._registered_macs

        # Now recognized
        node_id2, info2, direction2 = _attribute_packet(pkt, extractor.registry)
        assert node_id2 == "Node_99"
        assert direction2 == "uplink"

    def test_removed_device_disappears_after_refresh(self, collector_env):
        """2: Removed device disappears after refresh according to existing semantics."""
        collector, extractor, db_path = collector_env
        target_mac = PHONE1_MAC  # ca:34:ea:92:d3:9e (Node_3)

        # Initially present
        assert target_mac in collector.device_registry
        assert target_mac in extractor.registry

        # Delete from SQLite
        conn = get_live_db_connection(db_path)
        conn.execute("DELETE FROM device_registry WHERE mac_address=?", (target_mac,))
        conn.commit()
        conn.close()

        # Refresh
        refreshed = collector.refresh_device_registry(force=True)
        assert refreshed is True
        assert target_mac not in collector.device_registry
        assert target_mac not in extractor.registry
        assert target_mac not in collector.attack_detector.spoofing_detector._registered_macs

        # Packet from removed device is now unregistered
        pkt = _RawPacket(
            timestamp=1000.0,
            packet_size=100,
            eth_src=target_mac,
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.201",
            ip_dst="8.8.8.8",
            protocol="TCP",
        )
        node_id, _, direction = _attribute_packet(pkt, extractor.registry)
        assert node_id is None
        assert direction == "unregistered"

    def test_mac_address_normalization(self, collector_env):
        """3: MAC address normalization handles whitespace, hyphens, and uppercase."""
        collector, extractor, db_path = collector_env
        raw_mac = "  AA-BB-CC-11-22-33  "
        expected_mac = "aa:bb:cc:11:22:33"

        conn = get_live_db_connection(db_path)
        register_device(conn, mac_address=raw_mac, node_id="Node_Norm")
        conn.close()

        collector.refresh_device_registry(force=True)
        assert expected_mac in collector.device_registry
        assert expected_mac in extractor.registry
        assert expected_mac in collector.attack_detector.spoofing_detector._registered_macs

    def test_duplicate_entries_handled_safely(self):
        """4: Duplicate entries and varied formatting handled safely without error."""
        extractor = LiveStreamExtractor(interface_index=1, device_registry={})
        raw_input = {
            "AA:BB:CC:DD:EE:01": {"node_id": "Node_A"},
            "aa-bb-cc-dd-ee-01": {"node_id": "Node_A_Updated"},
            "  aa:bb:cc:dd:ee:01  ": {"node_id": "Node_A_Final"},
        }
        extractor.update_device_registry(raw_input)
        reg = extractor.get_device_registry()
        assert len(reg) == 1
        assert "aa:bb:cc:dd:ee:01" in reg
        assert reg["aa:bb:cc:dd:ee:01"]["node_id"] == "Node_A_Final"

    def test_failed_database_refresh_preserves_previous_registry(self, collector_env):
        """5: Failed database refresh preserves the previous registry."""
        collector, extractor, db_path = collector_env
        prev_registry = dict(collector.device_registry)

        with patch("src.live_collector.get_live_db_connection", side_effect=sqlite3.OperationalError("Database locked")):
            result = collector.refresh_device_registry(force=True)
            assert result is False

        assert collector.device_registry == prev_registry
        assert extractor.registry == prev_registry

    def test_extractor_and_detector_consistent_synchronization(self, collector_env):
        """6: Extractor and detector receive consistent registry updates."""
        collector, extractor, db_path = collector_env
        conn = get_live_db_connection(db_path)
        register_device(conn, mac_address="11:22:33:44:55:66", node_id="Node_Consistent")
        conn.close()

        collector.refresh_device_registry(force=True)
        collector_macs = set(collector.device_registry.keys())
        extractor_macs = set(extractor.registry.keys())
        detector_macs = set(collector.attack_detector.spoofing_detector._registered_macs)

        assert collector_macs == extractor_macs
        assert collector_macs == detector_macs

    def test_refresh_does_not_reset_detector_history_or_cooldowns(self, collector_env):
        """7: Refresh does not reset detector history, alert cooldowns, or baseline bindings."""
        collector, extractor, db_path = collector_env
        spoof_det = collector.attack_detector.spoofing_detector

        # Seed an active IP-MAC binding in spoofing detector
        spoof_det._ip_to_mac_binding["192.168.137.50"] = "ca:34:ea:92:d3:9e"
        spoof_det._conflict_candidates["192.168.137.50"] = {"fake_candidate": 1000.0}

        # Seed history in port scan detector
        collector.attack_detector.port_scan_detector._history["192.168.137.200"] = [MagicMock()]

        # Seed dedup cache in collector
        collector._port_scan_dedup_cache[("192.168.137.200", 80)] = 12345.0

        # Perform refresh
        collector.refresh_device_registry(force=True)

        # Verify state was not wiped
        assert spoof_det._ip_to_mac_binding.get("192.168.137.50") == "ca:34:ea:92:d3:9e"
        assert "192.168.137.50" in spoof_det._conflict_candidates
        assert "192.168.137.200" in collector.attack_detector.port_scan_detector._history
        assert collector._port_scan_dedup_cache.get(("192.168.137.200", 80)) == 12345.0

    def test_packet_processing_continues_during_concurrent_refresh(self):
        """8: Packet processing can continue during concurrent registry refresh."""
        extractor = LiveStreamExtractor(interface_index=1, device_registry={})
        stop_event = threading.Event()
        errors = []

        def worker_reader():
            pkt = _RawPacket(
                timestamp=1000.0,
                packet_size=100,
                eth_src="ca:34:ea:92:d3:9e",
                eth_dst="00:15:5d:01:02:03",
                ip_src="192.168.137.201",
                ip_dst="8.8.8.8",
                protocol="TCP",
            )
            while not stop_event.is_set():
                try:
                    with extractor._registry_lock:
                        cur_reg = extractor.registry
                    _attribute_packet(pkt, cur_reg)
                except Exception as e:
                    errors.append(e)

        def worker_updater():
            for i in range(200):
                mac = f"00:11:22:33:44:{i:02x}"
                extractor.update_device_registry({
                    mac: {"node_id": f"Node_{i}", "device_type": "Phone_Client", "label": "test"}
                })
                time.sleep(0.001)

        t_read = threading.Thread(target=worker_reader)
        t_up = threading.Thread(target=worker_updater)
        t_read.start()
        t_up.start()

        t_up.join(timeout=5)
        stop_event.set()
        t_read.join(timeout=5)

        assert len(errors) == 0, f"Concurrent read/write caused errors: {errors}"

    def test_refresh_interval_prevents_per_packet_queries(self, collector_env):
        """9: Refresh interval prevents per-packet database queries."""
        collector, _, db_path = collector_env
        query_count = 0

        real_get_db = get_live_db_connection

        def counting_get_db(path):
            nonlocal query_count
            query_count += 1
            return real_get_db(path)

        with patch("src.live_collector.get_live_db_connection", side_effect=counting_get_db):
            # First call with force=False after long duration triggers 1 query
            collector._last_registry_refresh_mono = 0.0
            res1 = collector.refresh_device_registry(force=False)
            assert query_count == 1

            # Subsequent 100 calls in rapid succession must NOT query DB
            for _ in range(100):
                res = collector.refresh_device_registry(force=False)
                assert res is False

            assert query_count == 1, f"Expected exactly 1 DB connection due to 30s rate limit, got {query_count}"

