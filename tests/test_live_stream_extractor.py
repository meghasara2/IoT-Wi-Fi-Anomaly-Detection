"""
Unit Tests: Live Stream Extractor
File: tests/test_live_stream_extractor.py

Covers:
  - _parse_tshark_line: valid and malformed lines
  - _is_broadcast_or_multicast: boundary cases
  - _attribute_packet: MAC match, IP fallback, broadcast, unregistered
  - _compute_1s_window_features: N=0/1/2/3+ arithmetic matching offline extractor
  - LiveStreamExtractor.iter_windows: integration with mock packet stream
  - Unregistered MAC tracking (drain_unregistered_macs)
  - build_tshark_command: correct argument construction

All tests use mock data — no real TShark process is launched.
"""

import math
import sys
import threading
import time
from pathlib import Path
from typing import Dict, Any, List
from unittest.mock import MagicMock, patch, PropertyMock
import io

import numpy as np
import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.live_stream_extractor import (
    LiveStreamExtractor,
    _RawPacket,
    _attribute_packet,
    _compute_1s_window_features,
    _is_broadcast_or_multicast,
    _parse_tshark_line,
    build_tshark_command,
    DEFAULT_DEVICE_REGISTRY,
    MIN_PACKETS_FOR_TIMING,
    FEATURE_COLS_PRIMARY,
    FEATURE_COLS_TIMING,
)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────
REGISTERED_MAC = "ca:34:ea:92:d3:9e"  # Node_3 in DEFAULT_DEVICE_REGISTRY
REGISTERED_MAC_2 = "e6:2e:db:73:1c:25"  # Node_4
UNKNOWN_MAC = "de:ad:be:ef:00:01"

TEST_REGISTRY: Dict[str, Dict[str, str]] = {
    REGISTERED_MAC: {
        "node_id": "Node_3",
        "device_type": "Phone_Client",
        "label": "real_observed_traffic",
        "ip": "192.168.137.201",
    },
    REGISTERED_MAC_2: {
        "node_id": "Node_4",
        "device_type": "Phone_Client",
        "label": "real_observed_traffic",
        "ip": "192.168.137.6",
    },
}


def _make_raw_packet(
    timestamp: float = 1000.0,
    packet_size: int = 100,
    eth_src: str = REGISTERED_MAC,
    eth_dst: str = "00:11:22:33:44:55",
    ip_src: str = "192.168.137.201",
    ip_dst: str = "8.8.8.8",
    protocol: str = "TCP",
) -> _RawPacket:
    return _RawPacket(
        timestamp=timestamp,
        packet_size=packet_size,
        eth_src=eth_src,
        eth_dst=eth_dst,
        ip_src=ip_src,
        ip_dst=ip_dst,
        protocol=protocol,
    )


# ─────────────────────────────────────────────────────────────────────────────
# _parse_tshark_line
# ─────────────────────────────────────────────────────────────────────────────
class TestParseTsharkLine:
    """Valid tshark field output line format:
    frame_num\ttime_epoch\tframe_len\teth_src\teth_dst\tip_src\tip_dst\tprotocol
    """

    def _make_line(self, frame=1, epoch=1000.5, length=200,
                   src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66",
                   ip_src="10.0.0.1", ip_dst="10.0.0.2", proto="TCP"):
        return f"{frame}\t{epoch}\t{length}\t{src}\t{dst}\t{ip_src}\t{ip_dst}\t{proto}"

    def test_valid_line_returns_packet(self):
        line = self._make_line()
        pkt = _parse_tshark_line(line)
        assert pkt is not None
        assert pkt.timestamp == pytest.approx(1000.5)
        assert pkt.packet_size == 200

    def test_mac_is_lowercased(self):
        line = self._make_line(src="AA:BB:CC:DD:EE:FF")
        pkt = _parse_tshark_line(line)
        assert pkt is not None
        assert pkt.eth_src == "aa:bb:cc:dd:ee:ff"

    def test_too_few_fields_returns_none(self):
        assert _parse_tshark_line("1\t1000.0\t100\tabc") is None

    def test_empty_line_returns_none(self):
        assert _parse_tshark_line("") is None

    def test_non_numeric_epoch_returns_none(self):
        assert _parse_tshark_line("1\tNOT_A_NUMBER\t100\ta\tb\tc\td\tTCP") is None

    def test_zero_packet_size_returns_none(self):
        line = self._make_line(length=0)
        assert _parse_tshark_line(line) is None

    def test_negative_packet_size_returns_none(self):
        line = self._make_line(length=-1)
        assert _parse_tshark_line(line) is None

    def test_crlf_line_endings_handled(self):
        line = self._make_line() + "\r\n"
        pkt = _parse_tshark_line(line)
        assert pkt is not None


# ─────────────────────────────────────────────────────────────────────────────
# _is_broadcast_or_multicast
# ─────────────────────────────────────────────────────────────────────────────
class TestIsBroadcastOrMulticast:

    def test_broadcast_ff(self):
        assert _is_broadcast_or_multicast("ff:ff:ff:ff:ff:ff") is True

    def test_ipv4_multicast(self):
        assert _is_broadcast_or_multicast("01:00:5e:00:00:01") is True

    def test_ipv6_multicast(self):
        assert _is_broadcast_or_multicast("33:33:00:00:00:01") is True

    def test_spanning_tree(self):
        assert _is_broadcast_or_multicast("01:80:c2:00:00:00") is True

    def test_unicast_not_broadcast(self):
        assert _is_broadcast_or_multicast("ca:34:ea:92:d3:9e") is False

    def test_case_insensitive(self):
        assert _is_broadcast_or_multicast("FF:FF:FF:FF:FF:FF") is True


# ─────────────────────────────────────────────────────────────────────────────
# _attribute_packet
# ─────────────────────────────────────────────────────────────────────────────
class TestAttributePacket:

    def test_registered_src_mac_uplink(self):
        pkt = _make_raw_packet(eth_src=REGISTERED_MAC)
        node_id, info, direction = _attribute_packet(pkt, TEST_REGISTRY)
        assert node_id == "Node_3"
        assert direction == "uplink"

    def test_registered_dst_mac_downlink(self):
        pkt = _make_raw_packet(eth_src="00:11:22:33:44:55", eth_dst=REGISTERED_MAC)
        node_id, info, direction = _attribute_packet(pkt, TEST_REGISTRY)
        assert node_id == "Node_3"
        assert direction == "downlink"

    def test_ip_src_fallback(self):
        # src MAC not in registry, but ip_src matches
        pkt = _make_raw_packet(
            eth_src="de:ad:be:ef:00:01",
            eth_dst="00:11:22:33:44:55",
            ip_src="192.168.137.201",
        )
        node_id, info, direction = _attribute_packet(pkt, TEST_REGISTRY)
        assert node_id == "Node_3"
        assert direction == "uplink"

    def test_broadcast_returns_infrastructure(self):
        pkt = _make_raw_packet(eth_dst="ff:ff:ff:ff:ff:ff")
        node_id, info, direction = _attribute_packet(pkt, TEST_REGISTRY)
        assert node_id is None
        assert direction == "infrastructure"

    def test_unknown_mac_returns_none_unregistered(self):
        pkt = _make_raw_packet(
            eth_src=UNKNOWN_MAC, eth_dst="00:11:22:33:44:55",
            ip_src="10.99.0.1", ip_dst="8.8.8.8"
        )
        node_id, info, direction = _attribute_packet(pkt, TEST_REGISTRY)
        assert node_id is None
        assert direction == "unregistered"

    def test_empty_registry_all_unregistered(self):
        pkt = _make_raw_packet(eth_src=REGISTERED_MAC)
        node_id, info, direction = _attribute_packet(pkt, {})
        assert node_id is None


# ─────────────────────────────────────────────────────────────────────────────
# _compute_1s_window_features
# ─────────────────────────────────────────────────────────────────────────────
class TestCompute1sWindowFeatures:
    """
    Verifies that the live feature computation exactly matches the offline
    extractor (compute_1s_features_for_client in extract_pcap_time_windows.py).
    """

    NODE_INFO = {"device_type": "Phone_Client", "label": "real_observed_traffic"}

    def _compute(self, timestamps, sizes, bin_start=1000.0):
        pkts = [
            _make_raw_packet(timestamp=t, packet_size=s)
            for t, s in zip(timestamps, sizes)
        ]
        pkts.sort(key=lambda p: p.timestamp)
        return _compute_1s_window_features(
            node_id="Node_3",
            node_info=self.NODE_INFO,
            client_mac=REGISTERED_MAC,
            bin_start=bin_start,
            packets=pkts,
        )

    def test_empty_window_packet_rate_zero(self):
        feat = self._compute([], [])
        assert feat["packet_rate"] == 0.0
        assert feat["packet_count"] == 0
        assert math.isnan(feat["mean_IAT"])
        assert math.isnan(feat["IAT_std"])
        assert math.isnan(feat["mean_packet_size"])
        assert math.isnan(feat["packet_size_std"])

    def test_single_packet_window(self):
        feat = self._compute([1000.5], [200])
        assert feat["packet_rate"] == 1.0
        assert feat["packet_count"] == 1
        assert math.isnan(feat["mean_IAT"])
        assert math.isnan(feat["IAT_std"])
        assert feat["mean_packet_size"] == pytest.approx(200.0)
        assert feat["packet_size_std"] == pytest.approx(0.0)

    def test_two_packet_window(self):
        """N=2: IAT_std must be 0.0 (single interval, no dispersion)."""
        feat = self._compute([1000.1, 1000.6], [100, 300])
        assert feat["packet_count"] == 2
        assert feat["packet_rate"] == 2.0
        assert feat["mean_IAT"] == pytest.approx(0.5, abs=1e-6)
        assert feat["IAT_std"] == pytest.approx(0.0)
        expected_mean_size = (100 + 300) / 2
        assert feat["mean_packet_size"] == pytest.approx(expected_mean_size)
        # sample std with ddof=1 for two values
        expected_std = np.std([100, 300], ddof=1)
        assert feat["packet_size_std"] == pytest.approx(expected_std)

    def test_three_packet_window(self):
        """N=3: both mean_IAT and IAT_std must be sample statistics."""
        timestamps = [1000.0, 1000.2, 1000.5]
        sizes = [100, 150, 200]
        feat = self._compute(timestamps, sizes)
        assert feat["packet_count"] == 3
        iats = np.diff(timestamps)
        assert feat["mean_IAT"] == pytest.approx(np.mean(iats), rel=1e-9)
        assert feat["IAT_std"] == pytest.approx(np.std(iats, ddof=1), rel=1e-9)
        assert feat["mean_packet_size"] == pytest.approx(np.mean(sizes))
        assert feat["packet_size_std"] == pytest.approx(np.std(sizes, ddof=1))

    def test_packet_rate_equals_count_over_one_second(self):
        """packet_rate must equal packet_count / 1.0."""
        for n in [5, 10, 50]:
            timestamps = [1000.0 + i * 0.1 for i in range(n)]
            sizes = [200] * n
            feat = self._compute(timestamps, sizes)
            assert feat["packet_rate"] == pytest.approx(float(n))

    def test_min_packets_for_timing_boundary(self):
        """MIN_PACKETS_FOR_TIMING == 3: N=2 must give IAT_std == 0.0."""
        assert MIN_PACKETS_FOR_TIMING == 3
        feat_2 = self._compute([1000.1, 1000.5], [100, 200])
        assert feat_2["IAT_std"] == pytest.approx(0.0)

        feat_3 = self._compute([1000.1, 1000.3, 1000.7], [100, 150, 200])
        assert not math.isnan(feat_3["IAT_std"])

    def test_metadata_fields_populated(self):
        feat = self._compute([1000.5], [100])
        assert feat["node_id"] == "Node_3"
        assert feat["client_mac"] == REGISTERED_MAC
        assert feat["bin_start_timestamp"] == pytest.approx(1000.0)
        assert feat["bin_end_timestamp"] == pytest.approx(1001.0)
        assert feat["window_center_epoch"] == pytest.approx(1000.5)


# ─────────────────────────────────────────────────────────────────────────────
# build_tshark_command
# ─────────────────────────────────────────────────────────────────────────────
class TestBuildTsharkCommand:

    def test_interface_index_present(self):
        cmd = build_tshark_command(interface_index=3)
        assert "-i" in cmd
        idx = cmd.index("-i")
        assert cmd[idx + 1] == "3"

    def test_line_buffered_flag_present(self):
        cmd = build_tshark_command(interface_index=1)
        assert "-l" in cmd

    def test_fields_mode_present(self):
        cmd = build_tshark_command(interface_index=1)
        assert "-T" in cmd
        assert "fields" in cmd

    def test_frame_epoch_field_included(self):
        cmd = build_tshark_command(interface_index=1)
        assert "frame.time_epoch" in cmd

    def test_eth_src_field_included(self):
        cmd = build_tshark_command(interface_index=1)
        assert "eth.src" in cmd

    def test_extra_args_inserted(self):
        cmd = build_tshark_command(interface_index=1, extra_args=["-a", "duration:60"])
        assert "-a" in cmd
        assert "duration:60" in cmd

    def test_returns_list_of_strings(self):
        cmd = build_tshark_command(interface_index=1)
        assert all(isinstance(s, str) for s in cmd)


# ─────────────────────────────────────────────────────────────────────────────
# LiveStreamExtractor integration (mocked TShark output)
# ─────────────────────────────────────────────────────────────────────────────
class TestLiveStreamExtractorIntegration:
    """
    Uses a mock subprocess to inject pre-built tshark field lines and verifies
    that iter_windows() yields correct feature windows.
    """

    def _make_tshark_line(self, frame=1, epoch=1000.0, length=200,
                          src=REGISTERED_MAC, dst="00:11:22:33:44:55",
                          ip_src="192.168.137.201", ip_dst="8.8.8.8",
                          proto="TCP"):
        return f"{frame}\t{epoch}\t{length}\t{src}\t{dst}\t{ip_src}\t{ip_dst}\t{proto}\n"

    def _make_extractor_with_lines(self, lines: List[str]) -> LiveStreamExtractor:
        """Patches subprocess.Popen to return lines from a StringIO."""
        extractor = LiveStreamExtractor(
            interface_index=1,
            device_registry=dict(TEST_REGISTRY),
        )
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None  # process appears alive
        mock_proc.stdout = io.StringIO("".join(lines))
        mock_proc.returncode = 0

        with patch("src.live_stream_extractor.subprocess.Popen", return_value=mock_proc):
            extractor.start()

        # Replace proc stdout with StringIO that iter_windows can read
        extractor._proc = mock_proc
        return extractor

    def test_single_packet_single_window(self):
        lines = [
            self._make_tshark_line(frame=1, epoch=1000.5, length=200),
        ]
        extractor = self._make_extractor_with_lines(lines)
        windows = list(extractor.iter_windows())
        # The packet is in bin 1000.0; it is flushed at stream end
        assert len(windows) == 1
        assert windows[0]["packet_count"] == 1
        assert windows[0]["packet_rate"] == 1.0
        assert windows[0]["node_id"] == "Node_3"

    def test_packets_in_different_bins(self):
        """Two packets in different 1-second bins → two windows."""
        lines = [
            self._make_tshark_line(frame=1, epoch=1000.5, length=100),
            self._make_tshark_line(frame=2, epoch=1001.5, length=200),
        ]
        extractor = self._make_extractor_with_lines(lines)
        windows = list(extractor.iter_windows())
        assert len(windows) == 2

    def test_packets_in_same_bin_merged(self):
        """Three packets within the same 1-second bin → one window, count=3."""
        lines = [
            self._make_tshark_line(frame=1, epoch=1000.1, length=100),
            self._make_tshark_line(frame=2, epoch=1000.5, length=150),
            self._make_tshark_line(frame=3, epoch=1000.9, length=200),
        ]
        extractor = self._make_extractor_with_lines(lines)
        windows = list(extractor.iter_windows())
        assert len(windows) == 1
        assert windows[0]["packet_count"] == 3

    def test_unregistered_mac_tracked(self):
        lines = [
            self._make_tshark_line(frame=1, epoch=1000.5, src=UNKNOWN_MAC,
                                   ip_src="10.99.0.1"),
        ]
        extractor = self._make_extractor_with_lines(lines)
        _ = list(extractor.iter_windows())
        unknown = extractor.drain_unregistered_macs()
        assert UNKNOWN_MAC in unknown

    def test_broadcast_packets_not_counted(self):
        """Broadcast packets should not generate a window."""
        lines = [
            self._make_tshark_line(frame=1, epoch=1000.5, dst="ff:ff:ff:ff:ff:ff"),
        ]
        extractor = self._make_extractor_with_lines(lines)
        windows = list(extractor.iter_windows())
        assert len(windows) == 0

    def test_two_nodes_tracked_independently(self):
        """Packets from two registered MACs should produce separate windows."""
        lines = [
            self._make_tshark_line(frame=1, epoch=1000.5, src=REGISTERED_MAC,
                                   ip_src="192.168.137.201"),
            self._make_tshark_line(frame=2, epoch=1000.7, src=REGISTERED_MAC_2,
                                   ip_src="192.168.137.6"),
        ]
        extractor = self._make_extractor_with_lines(lines)
        windows = list(extractor.iter_windows())
        node_ids = {w["node_id"] for w in windows}
        assert "Node_3" in node_ids
        assert "Node_4" in node_ids

    def test_downlink_packets_excluded_in_uplink_mode(self):
        """In 'uplink' mode, packets where src is not registered should not produce windows."""
        # AP → phone (downlink): eth_src is NOT a registered client MAC
        lines = [
            self._make_tshark_line(
                frame=1, epoch=1000.5,
                src="aa:bb:cc:dd:ee:ff",  # AP MAC, not in registry
                dst=REGISTERED_MAC,
                ip_src="8.8.8.8",
                ip_dst="192.168.137.201",
            ),
        ]
        extractor = self._make_extractor_with_lines(lines)
        windows = list(extractor.iter_windows())
        # Downlink packets should not generate uplink windows
        assert len(windows) == 0

    def test_drain_unregistered_clears_set(self):
        lines = [
            self._make_tshark_line(frame=1, epoch=1000.5, src=UNKNOWN_MAC,
                                   ip_src="10.99.0.1"),
        ]
        extractor = self._make_extractor_with_lines(lines)
        _ = list(extractor.iter_windows())
        first_drain = extractor.drain_unregistered_macs()
        second_drain = extractor.drain_unregistered_macs()
        assert UNKNOWN_MAC in first_drain
        assert UNKNOWN_MAC not in second_drain  # cleared


# ─────────────────────────────────────────────────────────────────────────────
# Device registry default validation
# ─────────────────────────────────────────────────────────────────────────────
class TestDefaultDeviceRegistry:

    def test_default_registry_has_node3_and_node4(self):
        node_ids = {v["node_id"] for v in DEFAULT_DEVICE_REGISTRY.values()}
        assert "Node_3" in node_ids
        assert "Node_4" in node_ids

    def test_default_registry_no_node5(self):
        """Node_5 is intentionally absent until connected in the demo."""
        node_ids = {v["node_id"] for v in DEFAULT_DEVICE_REGISTRY.values()}
        assert "Node_5" not in node_ids

    def test_default_registry_no_sensor_nodes(self):
        """Node_1 and Node_2 are logical sensor nodes, not Wi-Fi clients."""
        node_ids = {v["node_id"] for v in DEFAULT_DEVICE_REGISTRY.values()}
        assert "Node_1" not in node_ids
        assert "Node_2" not in node_ids

    def test_feature_cols_primary_match_known_columns(self):
        assert FEATURE_COLS_PRIMARY == ["packet_rate", "mean_packet_size", "packet_size_std"]

    def test_feature_cols_timing_match_known_columns(self):
        assert FEATURE_COLS_TIMING == ["mean_IAT", "IAT_std"]

    def test_min_packets_for_timing_is_three(self):
        assert MIN_PACKETS_FOR_TIMING == 3
