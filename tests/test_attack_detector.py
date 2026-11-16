"""
Unit Test Suite for Network Attack Detection Engine
File: tests/test_attack_detector.py

Validates explainable detection logic across five attack categories and RSSI handling:
  1. Denial-of-Service (DoS) vs legitimate fleet-wide classroom surge
  2. Sustained DoS vs transient 1-second burst
  3. Reconnaissance / Port Scanning across ports and hosts
  4. Unknown device without spoofing evidence (no false spoofing alert)
  5. Conflicting IP/MAC observations triggering investigation
  6. Missing 802.11 management frames -> INSUFFICIENT_TELEMETRY
  7. Missing protocol sequence/nonce -> INSUFFICIENT_TELEMETRY
  8. RSSI handling (None, non-zero, rejection of 0.0 dBm)
  9. Malformed and incomplete packet observations
  10. Normal baseline traffic -> NO_EVIDENCE
  11. Deauthentication flood detection when 802.11 frames are provided
  12. Replay attack detection with nonce reuse and stale payload re-injection
"""

import sys
from pathlib import Path

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
        RSSIMeasurement,
        DoSDetector,
        PortScanDetector,
        SpoofingDetector,
        DeauthDetector,
        resolve_gateway_mac,
        ReplayDetector,
        NetworkAttackDetector,
    )
except ModuleNotFoundError:
    from attack_detector import (
        AttackCategory,
        DetectionStatus,
        Severity,
        PacketObservation,
        WindowTrafficObservation,
        RSSIMeasurement,
        DoSDetector,
        PortScanDetector,
        SpoofingDetector,
        DeauthDetector,
        resolve_gateway_mac,
        ReplayDetector,
        NetworkAttackDetector,
    )
import math
import time
import pytest


# =============================================================================
# 1. Denial-of-Service (DoS) Tests
# =============================================================================

class TestDoSDetector:

    def test_classroom_fleet_surge_not_flagged_as_dos(self):
        """
        Classroom / exam scenario: 10 devices all surge simultaneously (e.g. starting
        an online quiz or downloading a lecture PDF).
        The detector MUST recognize this as a legitimate fleet-wide surge and NOT flag DoS.
        """
        detector = DoSDetector(rate_threshold_pps=50.0, fleet_surge_threshold=0.50)
        now = 1000.0

        # Create fleet of 10 surging devices
        fleet = [
            WindowTrafficObservation(
                bin_start_epoch=now,
                node_id=f"Node_{i}",
                mac_address=f"02:00:00:00:00:{i:02x}",
                packet_count=80,
                packet_rate=80.0,
                total_bytes=60000,
                ip_dst="192.168.137.1",
            )
            for i in range(1, 11)
        ]

        target_student = fleet[0]
        result = detector.evaluate(target_student, fleet_windows=fleet)

        assert result.category == AttackCategory.DOS
        assert result.status == DetectionStatus.NO_EVIDENCE
        assert "classroom" in result.evidence["explanation"].lower() or "fleet" in result.evidence["verdict"].lower()
        assert result.confidence < 0.3

    def test_two_devices_one_surging_not_suppressed_by_fleet_logic(self):
        """
        Stage 2.1 Test: Exactly two active devices, one surging (1 attacker + 1 idle peer).
        Even though 1/2 = 50% hits the ratio threshold, surging_devices == 1 (< 2),
        so fleet surge suppression must NOT activate, allowing the genuine attack to be flagged.
        """
        detector = DoSDetector(rate_threshold_pps=60.0, min_consecutive_windows=3, fleet_surge_threshold=0.50)
        attacker_mac = "ca:34:ea:92:d3:01"
        idle_mac = "ca:34:ea:92:d3:02"
        target_ip = "192.168.137.1"

        # Windows 1 and 2: Attacker ramping up
        for i in range(2):
            w = WindowTrafficObservation(1000.0 + i, "Node_1", attacker_mac, 80, 80.0, 50000, ip_dst=target_ip)
            detector.evaluate(w)

        # Window 3: Sustained attack (consecutive_high = 3) with fleet of 2 devices (1 surging, 1 idle)
        w3_attacker = WindowTrafficObservation(1002.0, "Node_1", attacker_mac, 85, 85.0, 52000, ip_dst=target_ip)
        w3_idle = WindowTrafficObservation(1002.0, "Node_2", idle_mac, 5, 5.0, 1000, ip_dst=target_ip)
        fleet = [w3_attacker, w3_idle]

        result = detector.evaluate(w3_attacker, fleet_windows=fleet)
        assert result.status == DetectionStatus.SUSPICIOUS
        assert result.evidence["verdict"] == "Sustained local infrastructure flood"
        assert result.evidence["target_ip"] == target_ip

    def test_two_devices_both_surging_suppressed_by_fleet_logic(self):
        """
        Stage 2.1 Test: Exactly two active devices, both surging simultaneously (surging_devices = 2 >= 2, ratio = 1.0).
        Fleet surge suppression must activate.
        """
        detector = DoSDetector(rate_threshold_pps=60.0, min_consecutive_windows=3, fleet_surge_threshold=0.50)
        w1 = WindowTrafficObservation(1000.0, "Node_1", "ca:34:ea:92:d3:01", 80, 80.0, 50000, ip_dst="192.168.137.1")
        w2 = WindowTrafficObservation(1000.0, "Node_2", "ca:34:ea:92:d3:02", 75, 75.0, 48000, ip_dst="192.168.137.1")
        fleet = [w1, w2]

        result = detector.evaluate(w1, fleet_windows=fleet)
        assert result.status == DetectionStatus.NO_EVIDENCE
        assert result.evidence["verdict"] == "Legitimate network-wide surge"
        assert result.evidence["surging_devices"] == 2
        assert result.evidence["fleet_ratio"] == 1.0

    def test_three_devices_one_surging_not_suppressed(self):
        """
        Stage 2.1 Test: Three active devices, one surging (1 attacker + 2 idle peers).
        surging_devices = 1 (< 2) and ratio = 1/3 (< 0.50). Attack must not be suppressed.
        """
        detector = DoSDetector(rate_threshold_pps=60.0, min_consecutive_windows=3, fleet_surge_threshold=0.50)
        attacker_mac = "ca:34:ea:92:d3:01"
        target_ip = "192.168.137.1"

        for i in range(2):
            w = WindowTrafficObservation(1000.0 + i, "Node_1", attacker_mac, 80, 80.0, 50000, ip_dst=target_ip)
            detector.evaluate(w)

        w3_att = WindowTrafficObservation(1002.0, "Node_1", attacker_mac, 90, 90.0, 55000, ip_dst=target_ip)
        w3_idle1 = WindowTrafficObservation(1002.0, "Node_2", "ca:34:ea:92:d3:02", 5, 5.0, 1000, ip_dst=target_ip)
        w3_idle2 = WindowTrafficObservation(1002.0, "Node_3", "ca:34:ea:92:d3:03", 2, 2.0, 500, ip_dst=target_ip)
        fleet = [w3_att, w3_idle1, w3_idle2]

        result = detector.evaluate(w3_att, fleet_windows=fleet)
        assert result.status == DetectionStatus.SUSPICIOUS
        assert result.evidence["verdict"] == "Sustained local infrastructure flood"

    def test_three_devices_two_surging_suppressed_by_fleet_logic(self):
        """
        Stage 2.1 Test: Three active devices, two surging (surging_devices = 2 >= 2, ratio = 2/3 = 0.67 >= 0.50).
        Fleet surge suppression must activate.
        """
        detector = DoSDetector(rate_threshold_pps=60.0, min_consecutive_windows=3, fleet_surge_threshold=0.50)
        w1 = WindowTrafficObservation(1000.0, "Node_1", "ca:34:ea:92:d3:01", 85, 85.0, 55000, ip_dst="192.168.137.1")
        w2 = WindowTrafficObservation(1000.0, "Node_2", "ca:34:ea:92:d3:02", 80, 80.0, 50000, ip_dst="192.168.137.1")
        w3 = WindowTrafficObservation(1000.0, "Node_3", "ca:34:ea:92:d3:03", 5, 5.0, 1000, ip_dst="192.168.137.1")
        fleet = [w1, w2, w3]

        result = detector.evaluate(w1, fleet_windows=fleet)
        assert result.status == DetectionStatus.NO_EVIDENCE
        assert result.evidence["verdict"] == "Legitimate network-wide surge"
        assert result.evidence["surging_devices"] == 2
        assert result.evidence["fleet_ratio"] == round(2 / 3, 3)

    def test_transient_single_window_burst_not_flagged_as_dos(self):
        """
        An isolated 1-second burst (e.g., launching an app or speed test)
        must NOT be classified as a DoS attack.
        """
        detector = DoSDetector(rate_threshold_pps=60.0, min_consecutive_windows=3)
        window = WindowTrafficObservation(
            bin_start_epoch=1000.0,
            node_id="Node_3",
            mac_address="ca:34:ea:92:d3:9e",
            packet_count=150,
            packet_rate=150.0,
            total_bytes=100000,
            ip_dst="192.168.137.1",
        )

        result = detector.evaluate(window)
        assert result.category == AttackCategory.DOS
        assert result.status == DetectionStatus.NO_EVIDENCE
        assert result.evidence["verdict"] == "Transient packet burst"
        assert result.evidence["consecutive_windows"] == 1

    def test_sustained_targeted_traffic_triggers_dos_suspicion(self):
        """
        Sustained excessive traffic from one source directed at a single target
        over multiple consecutive windows (>= 3s) must produce a SUSPICIOUS alert.
        """
        detector = DoSDetector(rate_threshold_pps=60.0, min_consecutive_windows=3)
        mac = "ca:34:ea:92:d3:9e"
        target_ip = "192.168.137.1"

        # Window 1: High
        w1 = WindowTrafficObservation(1000.0, "Node_3", mac, 80, 80.0, 50000, ip_dst=target_ip)
        res1 = detector.evaluate(w1)
        assert res1.status == DetectionStatus.NO_EVIDENCE

        # Window 2: High
        w2 = WindowTrafficObservation(1001.0, "Node_3", mac, 85, 85.0, 52000, ip_dst=target_ip)
        res2 = detector.evaluate(w2)
        assert res2.status == DetectionStatus.NO_EVIDENCE

        # Window 3: High (reaches 3 consecutive windows)
        w3 = WindowTrafficObservation(1002.0, "Node_3", mac, 90, 90.0, 55000, ip_dst=target_ip)
        res3 = detector.evaluate(w3)
        assert res3.status == DetectionStatus.SUSPICIOUS
        assert res3.severity in (Severity.MEDIUM, Severity.HIGH)
        assert res3.evidence["consecutive_windows"] == 3
        assert res3.evidence["target_ip"] == target_ip
        assert res3.confidence >= 0.60
        # Must recommend investigation, never auto-blocking
        assert "not automatically disconnect" in res3.recommended_action.lower()

    def test_event_744_wan_cdn_traffic_not_flagged_as_dos(self):
        """
        Regression Test for Event #744: Outbound streaming to Meta CDN (57.144.212.199)
        at 171 PPS across 10 consecutive seconds must NOT be flagged as DoS,
        reporting NO_EVIDENCE with verdict 'Outbound application transfer (WAN)'.
        """
        detector = DoSDetector(rate_threshold_pps=60.0, min_consecutive_windows=3)
        mac = "ca:34:ea:92:d3:9e"
        meta_cdn_ip = "57.144.212.199"

        results = []
        for i in range(10):
            w = WindowTrafficObservation(
                bin_start_epoch=1000.0 + i,
                node_id="Node_3",
                mac_address=mac,
                packet_count=171,
                packet_rate=171.0,
                total_bytes=145000,
                ip_src="192.168.137.101",
                ip_dst=meta_cdn_ip,
            )
            results.append(detector.evaluate(w))

        # Windows 1 and 2: Transient burst / normal
        # Windows 3-10: Evaluated as Outbound application transfer (WAN), NO_EVIDENCE
        last_res = results[-1]
        assert last_res.status == DetectionStatus.NO_EVIDENCE
        assert last_res.evidence["verdict"] == "Outbound application transfer (WAN)"
        assert last_res.evidence["destination_scope"] == "WAN / Internet"
        assert last_res.evidence["target_ip"] == meta_cdn_ip
        assert last_res.confidence == 0.0

    def test_wan_streaming_destinations_produce_no_evidence(self):
        """
        Public WAN traffic (Google, Cloudflare, Fastly) at high rates sustained over
        multiple windows must produce NO_EVIDENCE rather than DoS alerts.
        """
        wan_ips = ["142.250.190.46", "104.17.110.183", "151.101.67.52"]
        for wan_ip in wan_ips:
            detector = DoSDetector(rate_threshold_pps=60.0, min_consecutive_windows=3)
            mac = "ca:34:ea:92:d3:9e"
            for i in range(4):
                w = WindowTrafficObservation(
                    bin_start_epoch=1000.0 + i,
                    node_id="Node_3",
                    mac_address=mac,
                    packet_count=120,
                    packet_rate=120.0,
                    total_bytes=100000,
                    ip_src="192.168.137.101",
                    ip_dst=wan_ip,
                )
                res = detector.evaluate(w)
            assert res.status == DetectionStatus.NO_EVIDENCE
            assert res.evidence["verdict"] == "Outbound application transfer (WAN)"

    def test_sustained_local_gateway_flood_flagged_as_dos(self):
        """
        High-rate sustained traffic targeting the local gateway (192.168.137.1)
        must trigger a SUSPICIOUS DoS finding.
        """
        detector = DoSDetector(rate_threshold_pps=60.0, min_consecutive_windows=3)
        mac = "ca:34:ea:92:d3:9e"
        gateway_ip = "192.168.137.1"

        for i in range(3):
            w = WindowTrafficObservation(
                bin_start_epoch=1000.0 + i,
                node_id="Node_3",
                mac_address=mac,
                packet_count=80,
                packet_rate=80.0,
                total_bytes=50000,
                ip_src="192.168.137.101",
                ip_dst=gateway_ip,
            )
            res = detector.evaluate(w)

        assert res.status == DetectionStatus.SUSPICIOUS
        assert res.evidence["verdict"] == "Sustained local infrastructure flood"
        assert res.evidence["target_ip"] == gateway_ip
        assert res.confidence >= 0.60
        assert "not automatically disconnect" in res.recommended_action.lower()

    def test_sustained_local_iot_node_flood_flagged_as_dos(self):
        """
        High-rate sustained traffic targeting a local IoT node (192.168.137.201)
        must trigger a SUSPICIOUS DoS finding.
        """
        detector = DoSDetector(rate_threshold_pps=60.0, min_consecutive_windows=3)
        mac = "ca:34:ea:92:d3:9e"
        iot_ip = "192.168.137.201"

        for i in range(3):
            w = WindowTrafficObservation(
                bin_start_epoch=1000.0 + i,
                node_id="Node_3",
                mac_address=mac,
                packet_count=85,
                packet_rate=85.0,
                total_bytes=52000,
                ip_src="192.168.137.101",
                ip_dst=iot_ip,
            )
            res = detector.evaluate(w)

        assert res.status == DetectionStatus.SUSPICIOUS
        assert res.evidence["verdict"] == "Sustained local infrastructure flood"
        assert res.evidence["target_ip"] == iot_ip

    def test_distributed_local_traffic_below_concentration_threshold_not_flagged(self):
        """
        High-rate traffic distributed across multiple local hosts (below concentration 0.75)
        must produce NO_EVIDENCE with verdict 'Distributed local traffic volume'.
        """
        detector = DoSDetector(
            rate_threshold_pps=60.0,
            min_consecutive_windows=3,
            target_concentration_ratio=0.75,
        )
        mac = "ca:34:ea:92:d3:9e"
        local_hosts = [
            "192.168.137.10",
            "192.168.137.11",
            "192.168.137.12",
            "192.168.137.13",
        ]

        # 4 consecutive high rate windows, each with a different local destination (concentration 0.25)
        for i, host in enumerate(local_hosts):
            w = WindowTrafficObservation(
                bin_start_epoch=1000.0 + i,
                node_id="Node_3",
                mac_address=mac,
                packet_count=80,
                packet_rate=80.0,
                total_bytes=50000,
                ip_src="192.168.137.101",
                ip_dst=host,
            )
            res = detector.evaluate(w)

        assert res.status == DetectionStatus.NO_EVIDENCE
        assert res.evidence["verdict"] == "Distributed local traffic volume"
        assert res.evidence["target_concentration"] <= 0.25

    def test_missing_destination_ip_reports_insufficient_telemetry(self):
        """
        Sustained high rate traffic where destination IP is absent must report
        INSUFFICIENT_TELEMETRY with missing_fields=['ip_dst'].
        """
        detector = DoSDetector(rate_threshold_pps=60.0, min_consecutive_windows=3)
        mac = "ca:34:ea:92:d3:9e"

        for i in range(3):
            w = WindowTrafficObservation(
                bin_start_epoch=1000.0 + i,
                node_id="Node_3",
                mac_address=mac,
                packet_count=80,
                packet_rate=80.0,
                total_bytes=50000,
                ip_src="192.168.137.101",
                ip_dst=None,
            )
            res = detector.evaluate(w)

        assert res.status == DetectionStatus.INSUFFICIENT_TELEMETRY
        assert "ip_dst" in res.missing_fields
        assert res.confidence == 0.0

    def test_dos_packet_rate_exact_boundary_59_9_vs_60_0_pps(self):
        """
        GAP-82-01: Verifies the exact DoS packet rate boundary (>= 60.0 PPS):
        - 59.9 PPS sustained across >= 3 windows MUST NOT trigger (rate < 60.0 PPS).
        - 60.0 PPS sustained across >= 3 windows with target concentration >= 0.75 MUST trigger SUSPICIOUS.
        - 60.1 PPS (just above) also triggers SUSPICIOUS.
        """
        mac = "ca:34:ea:92:d3:9e"
        target_ip = "192.168.137.1"

        # Case A: Sub-threshold rate (59.9 PPS) across 3 consecutive windows
        detector_sub = DoSDetector(rate_threshold_pps=60.0, min_consecutive_windows=3)
        res_sub = None
        for i in range(3):
            w = WindowTrafficObservation(
                bin_start_epoch=1000.0 + i,
                node_id="Node_3",
                mac_address=mac,
                packet_count=60,
                packet_rate=59.9,
                total_bytes=30000,
                ip_dst=target_ip,
            )
            res_sub = detector_sub.evaluate(w)

        assert res_sub is not None
        assert res_sub.category == AttackCategory.DOS
        assert res_sub.status == DetectionStatus.NO_EVIDENCE
        assert res_sub.severity == Severity.NONE
        assert res_sub.evidence["verdict"] == "Normal traffic volume"
        assert res_sub.evidence["current_rate"] == 59.9

        # Case B: Exact threshold rate (60.0 PPS) across 3 consecutive windows
        detector_exact = DoSDetector(rate_threshold_pps=60.0, min_consecutive_windows=3)
        res_exact = None
        for i in range(3):
            w = WindowTrafficObservation(
                bin_start_epoch=1000.0 + i,
                node_id="Node_3",
                mac_address=mac,
                packet_count=60,
                packet_rate=60.0,
                total_bytes=30000,
                ip_dst=target_ip,
            )
            res_exact = detector_exact.evaluate(w)

        assert res_exact is not None
        assert res_exact.category == AttackCategory.DOS
        assert res_exact.status == DetectionStatus.SUSPICIOUS
        assert res_exact.severity in (Severity.MEDIUM, Severity.HIGH)
        assert res_exact.evidence["consecutive_windows"] == 3
        assert res_exact.evidence["current_rate_pps"] == 60.0
        assert res_exact.evidence["target_ip"] == target_ip
        assert res_exact.confidence >= 0.60

        # Case C: Just above threshold rate (60.1 PPS) across 3 consecutive windows
        detector_above = DoSDetector(rate_threshold_pps=60.0, min_consecutive_windows=3)
        res_above = None
        for i in range(3):
            w = WindowTrafficObservation(
                bin_start_epoch=1000.0 + i,
                node_id="Node_3",
                mac_address=mac,
                packet_count=61,
                packet_rate=60.1,
                total_bytes=30500,
                ip_dst=target_ip,
            )
            res_above = detector_above.evaluate(w)

        assert res_above is not None
        assert res_above.status == DetectionStatus.SUSPICIOUS
        assert res_above.evidence["current_rate_pps"] == 60.1


# =============================================================================
# 2. Reconnaissance / Port Scanning Tests
# =============================================================================

class TestPortScanDetector:

    def test_missing_transport_ports_reports_insufficient_telemetry(self):
        """
        When packets only have IP metadata without transport ports (as currently
        delivered by the NDIS capture), the detector MUST report INSUFFICIENT_TELEMETRY.
        """
        detector = PortScanDetector()
        packets = [
            PacketObservation(
                timestamp=1000.0 + i * 0.05,
                packet_size=64,
                eth_src="ca:34:ea:92:d3:9e",
                eth_dst="00:15:5d:01:02:03",
                ip_src="192.168.137.201",
                ip_dst="192.168.137.1",
                protocol="TCP",
                dst_port=None,  # Missing!
            )
            for i in range(10)
        ]

        result = detector.evaluate(packets)
        assert result.category == AttackCategory.PORT_SCAN
        assert result.status == DetectionStatus.INSUFFICIENT_TELEMETRY
        assert "dst_port" in result.missing_fields
        assert result.confidence == 0.0

    def test_vertical_port_scan_detected_when_ports_present(self):
        """
        When transport ports are present, probing multiple destination ports
        on a single target host triggers a SUSPICIOUS vertical scan alert.
        """
        detector = PortScanDetector(vertical_port_threshold=5, window_duration_seconds=5.0)
        probed_ports = [21, 22, 23, 25, 80, 443, 3389, 8080]

        packets = [
            PacketObservation(
                timestamp=1000.0 + i * 0.1,
                packet_size=60,
                eth_src="ca:34:ea:92:d3:9e",
                eth_dst="00:15:5d:01:02:03",
                ip_src="192.168.137.201",
                ip_dst="192.168.137.1",
                protocol="TCP",
                src_port=49152 + i,
                dst_port=port,
                tcp_flags="SYN",
            )
            for i, port in enumerate(probed_ports)
        ]

        result = detector.evaluate(packets)
        assert result.category == AttackCategory.PORT_SCAN
        assert result.status == DetectionStatus.SUSPICIOUS
        assert result.evidence["details"][0]["is_vertical_scan"] is True
        assert result.evidence["details"][0]["distinct_ports_count"] == len(probed_ports)
        assert result.confidence >= 0.70

    def test_horizontal_sweep_detected(self):
        """
        Probing the same port (e.g. 80) across multiple hosts triggers a horizontal sweep alert.
        """
        detector = PortScanDetector(horizontal_host_threshold=5, window_duration_seconds=5.0)
        packets = [
            PacketObservation(
                timestamp=1000.0 + i * 0.1,
                packet_size=60,
                eth_src="ca:34:ea:92:d3:9e",
                eth_dst="00:15:5d:01:02:03",
                ip_src="192.168.137.201",
                ip_dst=f"192.168.137.{10 + i}",
                protocol="TCP",
                src_port=50000,
                dst_port=80,
                tcp_flags="SYN",
            )
            for i in range(6)
        ]

        result = detector.evaluate(packets)
        assert result.category == AttackCategory.PORT_SCAN
        assert result.status == DetectionStatus.SUSPICIOUS
        assert result.evidence["details"][0]["is_horizontal_sweep"] is True

    def test_mobile_browsing_multiple_wan_hosts_produces_no_evidence(self):
        """
        Regression Test 1 (Event #745): Normal mobile browsing contacting 12 public internet
        hosts across multiple service ports (53, 443, 3478, 4500, 40003) with zero SYN flags
        must produce NO_EVIDENCE and never trigger a horizontal or vertical scan alert.
        """
        detector = PortScanDetector()
        wan_destinations = [
            ("57.144.212.199", 443, "TCP", "0x0010"),   # Meta CDN (ACK)
            ("142.250.190.46", 443, "TCP", "0x0018"),   # Google (PSH, ACK)
            ("8.8.8.8", 53, "UDP", None),                # Google DNS
            ("1.1.1.1", 53, "UDP", None),                # Cloudflare DNS
            ("17.253.144.10", 443, "TCP", "0x0010"),    # Apple (ACK)
            ("31.13.79.16", 3478, "UDP", None),          # WhatsApp STUN
            ("157.240.22.35", 4500, "UDP", None),        # IPsec
            ("157.240.22.35", 40003, "UDP", None),       # WhatsApp Call
            ("104.244.42.1", 443, "TCP", "0x0010"),     # Twitter/X (ACK)
            ("151.101.1.140", 443, "TCP", "0x0018"),    # Reddit CDN (PSH, ACK)
            ("20.190.159.0", 443, "TCP", "0x0010"),     # Microsoft (ACK)
            ("52.96.166.130", 443, "TCP", "0x0018"),    # Outlook (PSH, ACK)
        ]

        packets = [
            PacketObservation(
                timestamp=1000.0 + i * 0.1,
                packet_size=120,
                eth_src="ca:34:ea:92:d3:9e",
                eth_dst="36:6f:24:d2:34:3d",
                ip_src="192.168.137.101",
                ip_dst=dst_ip,
                protocol=proto,
                src_port=50000 + i,
                dst_port=dst_port,
                tcp_flags=flags,
            )
            for i, (dst_ip, dst_port, proto, flags) in enumerate(wan_destinations)
        ]

        result = detector.evaluate(packets)
        assert result.category == AttackCategory.PORT_SCAN
        assert result.status == DetectionStatus.NO_EVIDENCE
        assert result.severity == Severity.NONE
        assert result.confidence == 0.0
        assert "Normal transport diversity" in result.evidence["verdict"]

    def test_established_tcp_traffic_with_ack_psh_produces_no_evidence(self):
        """
        Regression Test 2: High-throughput established TCP traffic with ACK/PSH flags
        (even across multiple ports on the same host) must NOT be interpreted as scan probes.
        """
        detector = PortScanDetector(vertical_port_threshold=5)
        packets = [
            PacketObservation(
                timestamp=1000.0 + i * 0.05,
                packet_size=1400,
                eth_src="ca:34:ea:92:d3:9e",
                eth_dst="36:6f:24:d2:34:3d",
                ip_src="192.168.137.101",
                ip_dst="192.168.137.1",
                protocol="TCP",
                src_port=52000 + i,
                dst_port=80 if i % 2 == 0 else 443,
                tcp_flags="0x0018" if i % 3 == 0 else "0x0010",  # PSH, ACK or ACK
            )
            for i in range(20)
        ]

        result = detector.evaluate(packets)
        assert result.category == AttackCategory.PORT_SCAN
        assert result.status == DetectionStatus.NO_EVIDENCE
        assert result.severity == Severity.NONE

    def test_dns_traffic_to_multiple_hosts_produces_no_evidence(self):
        """
        Regression Test 3: DNS queries (port 53) directed at multiple DNS resolvers or local gateway
        must be excluded as normal infrastructure traffic and NOT flag a sweep.
        """
        detector = PortScanDetector(horizontal_host_threshold=5)
        dns_resolvers = [
            "192.168.137.1", "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222"
        ]
        packets = [
            PacketObservation(
                timestamp=1000.0 + i * 0.1,
                packet_size=75,
                eth_src="ca:34:ea:92:d3:9e",
                eth_dst="36:6f:24:d2:34:3d",
                ip_src="192.168.137.101",
                ip_dst=dst,
                protocol="UDP",
                src_port=53000 + i,
                dst_port=53,
            )
            for i, dst in enumerate(dns_resolvers)
        ]

        result = detector.evaluate(packets)
        assert result.category == AttackCategory.PORT_SCAN
        assert result.status == DetectionStatus.NO_EVIDENCE

    def test_genuine_tcp_horizontal_scan_detected(self):
        """
        Regression Test 4: Genuine TCP horizontal scan: probing the same port (e.g. 80) across 6 local LAN hosts
        using TCP SYN-without-ACK probes must trigger SUSPICIOUS with full evidence.
        """
        detector = PortScanDetector(horizontal_host_threshold=5, window_duration_seconds=5.0)
        targets = [f"192.168.137.{10 + i}" for i in range(6)]
        packets = [
            PacketObservation(
                timestamp=1000.0 + i * 0.1,
                packet_size=60,
                eth_src="00:0c:29:ab:cd:ef",
                eth_dst="ff:ff:ff:ff:ff:ff",
                ip_src="192.168.137.150",
                ip_dst=tgt,
                protocol="TCP",
                src_port=40000 + i,
                dst_port=80,
                tcp_flags="0x0002",  # SYN
            )
            for i, tgt in enumerate(targets)
        ]

        result = detector.evaluate(packets)
        assert result.category == AttackCategory.PORT_SCAN
        assert result.status == DetectionStatus.SUSPICIOUS
        assert result.severity in (Severity.MEDIUM, Severity.HIGH)
        primary = result.evidence["details"][0]
        assert primary["src_ip"] == "192.168.137.150"
        assert primary["source_mac"] == "00:0c:29:ab:cd:ef"
        assert primary["is_horizontal_sweep"] is True
        assert primary["distinct_hosts_count"] == 6
        assert primary["distinct_ports_count"] == 1
        assert primary["tcp_syn_count"] == 6
        assert primary["udp_probe_count"] == 0
        assert primary["probe_counts"] == 6
        assert "LAN" in primary["destination_scope"]
        assert "Horizontal sweep" in primary["detection_reason"]

    def test_genuine_udp_horizontal_scan_detected(self):
        """
        Regression Test 5: Genuine UDP horizontal scan: probing a non-infrastructure port (e.g. SNMP 161)
        across multiple local LAN hosts must trigger SUSPICIOUS without requiring TCP SYN flags.
        """
        detector = PortScanDetector(horizontal_host_threshold=5, window_duration_seconds=5.0)
        targets = [f"192.168.137.{20 + i}" for i in range(6)]
        packets = [
            PacketObservation(
                timestamp=1000.0 + i * 0.1,
                packet_size=80,
                eth_src="00:0c:29:ab:cd:ef",
                eth_dst="ff:ff:ff:ff:ff:ff",
                ip_src="192.168.137.150",
                ip_dst=tgt,
                protocol="UDP",
                src_port=45000 + i,
                dst_port=161,  # SNMP
            )
            for i, tgt in enumerate(targets)
        ]

        result = detector.evaluate(packets)
        assert result.category == AttackCategory.PORT_SCAN
        assert result.status == DetectionStatus.SUSPICIOUS
        primary = result.evidence["details"][0]
        assert primary["is_horizontal_sweep"] is True
        assert primary["udp_probe_count"] == 6
        assert primary["tcp_syn_count"] == 0
        assert "Horizontal sweep" in primary["detection_reason"]

    def test_genuine_vertical_tcp_scan_detected_with_evidence(self):
        """
        Regression Test 6: Genuine vertical TCP scan: probing 8 distinct non-infrastructure ports
        on a single local host with TCP SYN packets must trigger SUSPICIOUS with full evidence.
        """
        detector = PortScanDetector(vertical_port_threshold=6, window_duration_seconds=5.0)
        probed_ports = [21, 22, 23, 25, 80, 443, 3389, 8080]
        packets = [
            PacketObservation(
                timestamp=1000.0 + i * 0.1,
                packet_size=60,
                eth_src="00:0c:29:ab:cd:ef",
                eth_dst="36:6f:24:d2:34:3d",
                ip_src="192.168.137.150",
                ip_dst="192.168.137.1",
                protocol="TCP",
                src_port=50000 + i,
                dst_port=port,
                tcp_flags="SYN",
            )
            for i, port in enumerate(probed_ports)
        ]

        result = detector.evaluate(packets)
        assert result.category == AttackCategory.PORT_SCAN
        assert result.status == DetectionStatus.SUSPICIOUS
        primary = result.evidence["details"][0]
        assert primary["src_ip"] == "192.168.137.150"
        assert primary["source_mac"] == "00:0c:29:ab:cd:ef"
        assert primary["is_vertical_scan"] is True
        assert primary["distinct_ports_count"] == len(probed_ports)
        assert primary["distinct_hosts_count"] == 1
        assert primary["tcp_syn_count"] == len(probed_ports)
        assert primary["probe_counts"] == len(probed_ports)
        assert "Vertical scan" in primary["detection_reason"]

    def test_multiple_public_internet_hosts_different_ports_produces_no_evidence(self):
        """
        Regression Test 7: Contacting diverse public internet IPs on various ports (e.g. cloud services, CDNs)
        must NOT trigger local LAN port scanning alerts.
        """
        detector = PortScanDetector()
        public_traffic = [
            ("93.184.216.34", 80),      # example.com
            ("151.101.65.140", 443),    # fastly
            ("198.41.0.4", 53),         # root DNS
            ("13.107.4.52", 443),       # Azure
            ("34.200.10.1", 8080),      # AWS EC2
            ("52.84.120.30", 443),      # CloudFront
        ]
        packets = [
            PacketObservation(
                timestamp=1000.0 + i * 0.1,
                packet_size=100,
                eth_src="ca:34:ea:92:d3:9e",
                eth_dst="36:6f:24:d2:34:3d",
                ip_src="192.168.137.101",
                ip_dst=dst_ip,
                protocol="TCP",
                src_port=55000 + i,
                dst_port=dst_port,
                tcp_flags="0x0018",
            )
            for i, (dst_ip, dst_port) in enumerate(public_traffic)
        ]

        result = detector.evaluate(packets)
        assert result.status == DetectionStatus.NO_EVIDENCE

    def test_missing_tcp_flags_handled_safely_without_crashing_or_false_alert(self):
        """
        Regression Test 8: When TCP flags are None or unextracted, the detector must handle safely
        without crashing and must NOT invent SYN flags or produce false alerts.
        """
        detector = PortScanDetector()
        packets = [
            PacketObservation(
                timestamp=1000.0 + i * 0.1,
                packet_size=60,
                eth_src="ca:34:ea:92:d3:9e",
                eth_dst="36:6f:24:d2:34:3d",
                ip_src="192.168.137.101",
                ip_dst="192.168.137.1",
                protocol="TCP",
                src_port=50000 + i,
                dst_port=80 + i,
                tcp_flags=None,  # Missing flags!
            )
            for i in range(10)
        ]

        result = detector.evaluate(packets)
        assert result.category == AttackCategory.PORT_SCAN
        assert result.status == DetectionStatus.NO_EVIDENCE

    def test_randomized_client_mac_ordinary_browsing_produces_no_scan_alert(self):
        """
        Regression Test 9: A device with a locally administered / randomized MAC address
        (e.g. modern iOS/Android) performing normal browsing must NOT be flagged as a port scanner
        solely because of its MAC address.
        """
        detector = PortScanDetector()
        random_mac = "da:11:22:33:44:55"  # Locally administered bit set
        packets = [
            PacketObservation(
                timestamp=1000.0 + i * 0.1,
                packet_size=150,
                eth_src=random_mac,
                eth_dst="36:6f:24:d2:34:3d",
                ip_src="192.168.137.120",
                ip_dst="142.250.190.46",
                protocol="TCP",
                src_port=51000 + i,
                dst_port=443,
                tcp_flags="0x0018",
            )
            for i in range(8)
        ]

        result = detector.evaluate(packets)
        assert result.category == AttackCategory.PORT_SCAN
        assert result.status == DetectionStatus.NO_EVIDENCE

    def test_vertical_port_scan_exact_boundary_7_vs_8_ports(self):
        """
        GAP-82-02: Verifies the exact vertical port-scan boundary (>= 8 distinct ports):
        - 7 distinct ports: below threshold, MUST NOT trigger (NO_EVIDENCE).
        - 8 distinct ports: at threshold, MUST trigger SUSPICIOUS vertical port scan.
        - Verifies scanner MAC and target host attribution.
        """
        scanner_mac = "ca:34:ea:92:d3:9e"
        target_ip = "192.168.137.1"
        target_mac = "00:15:5d:01:02:03"
        ports_7 = [21, 22, 23, 25, 80, 110, 143]
        ports_8 = [21, 22, 23, 25, 80, 110, 143, 443]

        # Case A: 7 distinct ports (sub-threshold)
        detector_7 = PortScanDetector(vertical_port_threshold=8, window_duration_seconds=60.0)
        packets_7 = [
            PacketObservation(
                timestamp=1000.0 + i * 0.1,
                packet_size=60,
                eth_src=scanner_mac,
                eth_dst=target_mac,
                ip_src="192.168.137.201",
                ip_dst=target_ip,
                protocol="TCP",
                src_port=49152 + i,
                dst_port=port,
                tcp_flags="SYN",
            )
            for i, port in enumerate(ports_7)
        ]
        result_7 = detector_7.evaluate(packets_7)
        assert result_7.category == AttackCategory.PORT_SCAN
        assert result_7.status == DetectionStatus.NO_EVIDENCE
        assert result_7.severity == Severity.NONE
        assert result_7.evidence["verdict"] == "Normal transport diversity"

        # Case B: 8 distinct ports (exact threshold)
        detector_8 = PortScanDetector(vertical_port_threshold=8, window_duration_seconds=60.0)
        packets_8 = [
            PacketObservation(
                timestamp=1000.0 + i * 0.1,
                packet_size=60,
                eth_src=scanner_mac,
                eth_dst=target_mac,
                ip_src="192.168.137.201",
                ip_dst=target_ip,
                protocol="TCP",
                src_port=49152 + i,
                dst_port=port,
                tcp_flags="SYN",
            )
            for i, port in enumerate(ports_8)
        ]
        result_8 = detector_8.evaluate(packets_8)
        assert result_8.category == AttackCategory.PORT_SCAN
        assert result_8.status == DetectionStatus.SUSPICIOUS
        assert result_8.severity in (Severity.MEDIUM, Severity.HIGH)
        assert len(result_8.evidence["details"]) >= 1
        detail = result_8.evidence["details"][0]
        assert detail["is_vertical_scan"] is True
        assert target_ip in detail["sample_hosts"]
        assert detail["distinct_ports_count"] == 8
        assert detail["source_mac"] == scanner_mac
        assert result_8.confidence >= 0.70

    def test_horizontal_port_scan_exact_boundary_4_vs_5_hosts(self):
        """
        GAP-82-03: Verifies the exact horizontal port-scan sweep boundary (>= 5 destination hosts):
        - 4 distinct destination hosts: below threshold, MUST NOT trigger (NO_EVIDENCE).
        - 5 distinct destination hosts: at threshold, MUST trigger SUSPICIOUS horizontal sweep.
        - Verifies scanner source attribution.
        """
        scanner_mac = "ca:34:ea:92:d3:9e"
        target_hosts_4 = ["192.168.137.10", "192.168.137.11", "192.168.137.12", "192.168.137.13"]
        target_hosts_5 = ["192.168.137.10", "192.168.137.11", "192.168.137.12", "192.168.137.13", "192.168.137.14"]
        probed_port = 80

        # Case A: 4 distinct hosts (sub-threshold)
        detector_4 = PortScanDetector(horizontal_host_threshold=5, window_duration_seconds=60.0)
        packets_4 = [
            PacketObservation(
                timestamp=1000.0 + i * 0.1,
                packet_size=60,
                eth_src=scanner_mac,
                eth_dst="00:15:5d:01:02:03",
                ip_src="192.168.137.201",
                ip_dst=host,
                protocol="TCP",
                src_port=50000 + i,
                dst_port=probed_port,
                tcp_flags="SYN",
            )
            for i, host in enumerate(target_hosts_4)
        ]
        result_4 = detector_4.evaluate(packets_4)
        assert result_4.category == AttackCategory.PORT_SCAN
        assert result_4.status == DetectionStatus.NO_EVIDENCE
        assert result_4.severity == Severity.NONE
        assert result_4.evidence["verdict"] == "Normal transport diversity"

        # Case B: 5 distinct hosts (exact threshold)
        detector_5 = PortScanDetector(horizontal_host_threshold=5, window_duration_seconds=60.0)
        packets_5 = [
            PacketObservation(
                timestamp=1000.0 + i * 0.1,
                packet_size=60,
                eth_src=scanner_mac,
                eth_dst="00:15:5d:01:02:03",
                ip_src="192.168.137.201",
                ip_dst=host,
                protocol="TCP",
                src_port=50000 + i,
                dst_port=probed_port,
                tcp_flags="SYN",
            )
            for i, host in enumerate(target_hosts_5)
        ]
        result_5 = detector_5.evaluate(packets_5)
        assert result_5.category == AttackCategory.PORT_SCAN
        assert result_5.status == DetectionStatus.SUSPICIOUS
        assert result_5.severity in (Severity.MEDIUM, Severity.HIGH)
        assert len(result_5.evidence["details"]) >= 1
        detail = result_5.evidence["details"][0]
        assert detail["is_horizontal_sweep"] is True
        assert probed_port in detail["sample_ports"]
        assert detail["distinct_hosts_count"] == 5
        assert detail["source_mac"] == scanner_mac
        assert result_5.confidence >= 0.70


# =============================================================================
# 3. Spoofing / Impersonation Tests
# =============================================================================

class TestSpoofingDetector:

    def test_unknown_mac_without_ip_conflict_produces_no_spoofing_alert(self):
        """
        An un-enrolled or randomized MAC address appearing on the network
        MUST NOT be labelled as spoofing.
        """
        detector = SpoofingDetector()
        detector.set_registered_devices({"ca:34:ea:92:d3:9e"})

        # New un-registered phone connects
        unknown_mac = "ae:22:33:44:55:66"  # Locally administered randomized MAC
        p = PacketObservation(
            timestamp=1000.0,
            packet_size=120,
            eth_src=unknown_mac,
            eth_dst="ff:ff:ff:ff:ff:ff",
            ip_src="192.168.137.205",
            ip_dst="192.168.137.1",
        )

        result = detector.evaluate(p)
        assert result.category == AttackCategory.SPOOFING
        assert result.status == DetectionStatus.NO_EVIDENCE
        assert result.severity in (Severity.NONE, Severity.INFO)
        assert result.evidence["is_randomized_mac"] is True

    def test_conflicting_ip_to_mac_binding_triggers_investigation(self):
        """
        When two different MACs claim the same IP in a short time window (< 60s),
        it triggers a SUSPICIOUS investigation alert, NOT an automatic blockage.
        """
        detector = SpoofingDetector(ip_conflict_window_seconds=60.0)

        # Legitimate client
        p1 = PacketObservation(
            timestamp=1000.0,
            packet_size=100,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.201",
            ip_dst="192.168.137.1",
        )
        res1 = detector.evaluate(p1)
        assert res1.status == DetectionStatus.NO_EVIDENCE

        # Second MAC claiming same IP 5 seconds later
        p2 = PacketObservation(
            timestamp=1005.0,
            packet_size=100,
            eth_src="11:22:33:44:55:66",
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.201",
            ip_dst="192.168.137.1",
        )
        res2 = detector.evaluate(p2)
        assert res2.status == DetectionStatus.SUSPICIOUS
        assert res2.evidence["verdict"] == "Conflicting IP-to-MAC binding detected"
        assert res2.evidence["current_mac"] == "11:22:33:44:55:66"
        assert res2.evidence["previous_mac"] == "ca:34:ea:92:d3:9e"
        assert "dhcp" in res2.recommended_action.lower()

    def test_unknown_gateway_identity_reports_insufficient_telemetry(self):
        """
        Safety requirement: When the Gateway MAC address cannot be verified/configured,
        traffic claiming the gateway IP MUST report INSUFFICIENT_TELEMETRY instead of
        raising a false spoofing alert.
        """
        detector = SpoofingDetector(gateway_ip="192.168.137.1", gateway_mac=None)
        detector.set_registered_devices({"ca:34:ea:92:d3:9e"})

        pkt = PacketObservation(
            timestamp=1000.0,
            packet_size=80,
            eth_src="36:6f:24:d2:34:3d",
            eth_dst="ca:34:ea:92:d3:9e",
            ip_src="192.168.137.1",
            ip_dst="192.168.137.201",
        )

        res = detector.evaluate(pkt)
        assert res.category == AttackCategory.SPOOFING
        assert res.status == DetectionStatus.INSUFFICIENT_TELEMETRY
        assert "gateway_mac" in res.missing_fields
        assert res.confidence == 0.0
        assert "is_randomized_mac" in res.evidence

    def test_legitimate_gateway_traffic_produces_no_alert(self):
        """
        When gateway MAC is explicitly configured and observed traffic originates from
        the legitimate gateway MAC, it must be verified as NO_EVIDENCE.
        """
        gateway_mac = "36:6f:24:d2:34:3d"
        detector = SpoofingDetector(gateway_ip="192.168.137.1", gateway_mac=gateway_mac)

        legit_pkt = PacketObservation(
            timestamp=1000.0,
            packet_size=90,
            eth_src=gateway_mac,
            eth_dst="ca:34:ea:92:d3:9e",
            ip_src="192.168.137.1",
            ip_dst="192.168.137.201",
        )

        res = detector.evaluate(legit_pkt)
        assert res.status == DetectionStatus.NO_EVIDENCE
        assert res.severity == Severity.NONE
        assert res.evidence["is_gateway"] is True
        assert res.evidence["verdict"] == "Legitimate gateway traffic"
        assert res.evidence["is_randomized_mac"] is True  # 0x36 has locally administered bit set

    def test_conflicting_gateway_identity_triggers_suspicious_alert(self):
        """
        When gateway MAC is configured and an unauthorized rogue client emits traffic
        claiming the gateway IP, a high-severity SUSPICIOUS alert must be triggered.
        """
        gateway_mac = "36:6f:24:d2:34:3d"
        detector = SpoofingDetector(gateway_ip="192.168.137.1", gateway_mac=gateway_mac)
        detector.set_registered_devices({"ca:34:ea:92:d3:9e"})

        rogue_pkt = PacketObservation(
            timestamp=1000.0,
            packet_size=80,
            eth_src="00:aa:bb:cc:dd:ee",
            eth_dst="ff:ff:ff:ff:ff:ff",
            ip_src="192.168.137.1",  # Rogue host claiming Gateway IP!
            ip_dst="192.168.137.201",
        )

        res = detector.evaluate(rogue_pkt)
        assert res.status == DetectionStatus.SUSPICIOUS
        assert res.severity == Severity.HIGH
        assert "gateway ip impersonation" in res.evidence["verdict"].lower()
        assert res.evidence["authorized_gateway_mac"] == gateway_mac
        assert res.evidence["offending_mac"] == "00:aa:bb:cc:dd:ee"
        assert res.evidence["is_randomized_mac"] is False

    def test_dhcp_discover_from_0_0_0_0_does_not_generate_spoofing_alert(self):
        """
        DHCP Discover traffic originating from 0.0.0.0 must evaluate to NO_EVIDENCE
        and must not populate IP-to-MAC bindings, preventing spurious spoofing alerts
        when multiple devices negotiate DHCP within the conflict window.
        """
        detector = SpoofingDetector(local_subnet="192.168.137.0/24")
        p1 = PacketObservation(
            timestamp=1000.0,
            packet_size=300,
            eth_src="02:aa:bb:cc:dd:ee",
            eth_dst="ff:ff:ff:ff:ff:ff",
            ip_src="0.0.0.0",
            ip_dst="255.255.255.255",
            protocol="UDP",
            src_port=68,
            dst_port=67,
        )
        res1 = detector.evaluate(p1)
        assert res1.category == AttackCategory.SPOOFING
        assert res1.status == DetectionStatus.NO_EVIDENCE
        assert res1.severity == Severity.NONE
        assert "unassigned" in res1.evidence["verdict"].lower()

        # Second device sends DHCP Discover from 0.0.0.0 two seconds later
        p2 = PacketObservation(
            timestamp=1002.0,
            packet_size=300,
            eth_src="02:11:22:33:44:55",
            eth_dst="ff:ff:ff:ff:ff:ff",
            ip_src="0.0.0.0",
            ip_dst="255.255.255.255",
            protocol="UDP",
            src_port=68,
            dst_port=67,
        )
        res2 = detector.evaluate(p2)
        assert res2.category == AttackCategory.SPOOFING
        assert res2.status == DetectionStatus.NO_EVIDENCE
        assert res2.severity == Severity.NONE
        assert "0.0.0.0" not in detector._ip_to_mac_binding

    def test_broadcast_and_multicast_source_addresses_do_not_create_bindings(self):
        """
        Packets with non-unicast source IPs (limited broadcast 255.255.255.255,
        multicast 224.0.0.251, subnet network address, subnet broadcast address)
        must return NO_EVIDENCE and must not enter the IP-to-MAC binding table.
        """
        detector = SpoofingDetector(local_subnet="192.168.137.0/24")
        test_ips = [
            "255.255.255.255",
            "224.0.0.251",
            "192.168.137.0",
            "192.168.137.255",
        ]
        for idx, tip in enumerate(test_ips):
            pkt = PacketObservation(
                timestamp=1000.0 + idx,
                packet_size=100,
                eth_src=f"02:00:00:00:00:0{idx}",
                eth_dst="ff:ff:ff:ff:ff:ff",
                ip_src=tip,
                ip_dst="192.168.137.1",
            )
            res = detector.evaluate(pkt)
            assert res.status == DetectionStatus.NO_EVIDENCE
            assert res.severity == Severity.NONE
            assert tip not in detector._ip_to_mac_binding

    def test_valid_private_lan_ip_to_mac_conflict_still_detected(self):
        """
        Legitimate private LAN addresses (e.g. 192.168.137.101) claimed by two different
        MAC addresses within the conflict window must still be detected as SUSPICIOUS.
        """
        detector = SpoofingDetector(local_subnet="192.168.137.0/24", ip_conflict_window_seconds=60.0)
        p1 = PacketObservation(
            timestamp=1000.0,
            packet_size=120,
            eth_src="00:11:22:33:44:55",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.101",
            ip_dst="192.168.137.1",
        )
        res1 = detector.evaluate(p1)
        assert res1.status == DetectionStatus.NO_EVIDENCE

        # Second MAC claiming same IP 5s later
        p2 = PacketObservation(
            timestamp=1005.0,
            packet_size=120,
            eth_src="00:aa:bb:cc:dd:ee",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.101",
            ip_dst="192.168.137.1",
        )
        res2 = detector.evaluate(p2)
        assert res2.status == DetectionStatus.SUSPICIOUS
        assert res2.evidence["verdict"] == "Conflicting IP-to-MAC binding detected"
        assert res2.evidence["current_mac"] == "00:aa:bb:cc:dd:ee"
        assert res2.evidence["previous_mac"] == "00:11:22:33:44:55"

    def test_randomized_mac_alone_does_not_trigger_spoofing(self):
        """
        A device using a locally administered / randomized MAC address on a valid
        unconflicted IP must evaluate to NO_EVIDENCE, with is_randomized_mac=True.
        """
        detector = SpoofingDetector(local_subnet="192.168.137.0/24")
        random_mac = "da:11:22:33:44:55"  # Locally administered bit set (0xda & 0x02 != 0)
        pkt = PacketObservation(
            timestamp=1000.0,
            packet_size=150,
            eth_src=random_mac,
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.105",
            ip_dst="1.1.1.1",
        )
        res = detector.evaluate(pkt)
        assert res.status == DetectionStatus.NO_EVIDENCE
        assert res.severity == Severity.NONE
        assert res.evidence["is_randomized_mac"] is True

    def test_first_mac_establishes_binding(self):
        """
        Stage 3.2: The first observed MAC address communicating on a valid IP establishes
        the authoritative baseline binding.
        """
        detector = SpoofingDetector(local_subnet="192.168.137.0/24")
        mac_a = "00:11:22:33:44:55"
        ip = "192.168.137.101"

        pkt = PacketObservation(
            timestamp=1000.0,
            packet_size=100,
            eth_src=mac_a,
            eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip,
            ip_dst="192.168.137.1",
        )
        res = detector.evaluate(pkt)
        assert res.status == DetectionStatus.NO_EVIDENCE
        assert res.evidence["verdict"] == "Consistent identity binding"
        assert ip in detector._ip_to_mac_binding
        assert detector._ip_to_mac_binding[ip][0] == mac_a

    def test_one_conflicting_packet_does_not_replace_baseline(self):
        """
        Stage 3.2: A single conflicting packet from an alternate MAC must NOT overwrite
        or replace the baseline binding, even if it triggers a conflict alert.
        """
        detector = SpoofingDetector(local_subnet="192.168.137.0/24", ip_conflict_window_seconds=60.0)
        mac_a = "00:11:22:33:44:55"
        mac_b = "00:aa:bb:cc:dd:ee"
        ip = "192.168.137.101"

        # Baseline established by MAC A
        p1 = PacketObservation(
            timestamp=1000.0,
            packet_size=100,
            eth_src=mac_a,
            eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip,
            ip_dst="192.168.137.1",
        )
        detector.evaluate(p1)

        # Single conflicting packet from MAC B 5s later
        p2 = PacketObservation(
            timestamp=1005.0,
            packet_size=100,
            eth_src=mac_b,
            eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip,
            ip_dst="192.168.137.1",
        )
        res2 = detector.evaluate(p2)
        assert res2.status == DetectionStatus.SUSPICIOUS
        assert res2.evidence["verdict"] == "Conflicting IP-to-MAC binding detected"
        assert res2.evidence["current_mac"] == mac_b
        assert res2.evidence["previous_mac"] == mac_a

        # Baseline MUST remain MAC A
        assert detector._ip_to_mac_binding[ip][0] == mac_a

    def test_repeated_conflicting_packets_are_tracked(self):
        """
        Stage 3.2: Repeated conflicting packets from the same alternate MAC are tracked
        in candidate state with packet count incrementing.
        """
        detector = SpoofingDetector(local_subnet="192.168.137.0/24")
        mac_a = "00:11:22:33:44:55"
        mac_b = "00:aa:bb:cc:dd:ee"
        ip = "192.168.137.101"

        # Baseline
        detector.evaluate(PacketObservation(
            timestamp=1000.0, packet_size=100, eth_src=mac_a, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))

        # Repeated packets from MAC B
        for i in range(4):
            detector.evaluate(PacketObservation(
                timestamp=1002.0 + i, packet_size=100, eth_src=mac_b, eth_dst="36:6f:24:d2:34:3d",
                ip_src=ip, ip_dst="192.168.137.1"
            ))

        candidate = detector._conflict_candidates[ip][mac_b]
        assert candidate.packet_count == 4
        assert candidate.first_seen == 1002.0
        assert candidate.last_seen == 1005.0
        # Baseline remains untouched
        assert detector._ip_to_mac_binding[ip][0] == mac_a

    def test_repeated_packets_do_not_produce_unlimited_alert_stream(self):
        """
        Stage 3.2: Ongoing conflicting packets from the same alternate MAC within
        cooldown suppress duplicate SUSPICIOUS alerts.
        """
        detector = SpoofingDetector(
            local_subnet="192.168.137.0/24",
            conflict_alert_cooldown_seconds=60.0,
        )
        mac_a = "00:11:22:33:44:55"
        mac_b = "00:aa:bb:cc:dd:ee"
        ip = "192.168.137.101"

        # Baseline
        detector.evaluate(PacketObservation(
            timestamp=1000.0, packet_size=100, eth_src=mac_a, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))

        # First conflicting packet: triggers SUSPICIOUS
        r1 = detector.evaluate(PacketObservation(
            timestamp=1002.0, packet_size=100, eth_src=mac_b, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))
        assert r1.status == DetectionStatus.SUSPICIOUS

        # Subsequent packets within 60s cooldown: suppressed to NO_EVIDENCE (tracked)
        r2 = detector.evaluate(PacketObservation(
            timestamp=1005.0, packet_size=100, eth_src=mac_b, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))
        assert r2.status == DetectionStatus.NO_EVIDENCE
        assert "Ongoing conflicting" in r2.evidence["verdict"]

        r3 = detector.evaluate(PacketObservation(
            timestamp=1020.0, packet_size=100, eth_src=mac_b, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))
        assert r3.status == DetectionStatus.NO_EVIDENCE
        assert r3.evidence["conflict_packet_count"] == 3

    def test_legitimate_binding_can_change_after_safe_expiry(self):
        """
        Stage 3.2: When the baseline device has been silent past binding_expiry_seconds,
        a new MAC demonstrating confirmed sustained communication (>= confirmation_min_packets)
        is safely promoted to the new baseline.
        """
        detector = SpoofingDetector(
            local_subnet="192.168.137.0/24",
            binding_expiry_seconds=60.0,
            confirmation_min_packets=2,
        )
        mac_a = "00:11:22:33:44:55"
        mac_b = "00:aa:bb:cc:dd:ee"
        ip = "192.168.137.101"

        # Baseline MAC A communicated at t=1000.0, then disconnected/ceased transmitting
        detector.evaluate(PacketObservation(
            timestamp=1000.0, packet_size=100, eth_src=mac_a, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))

        # Time advances to t=1070.0 (> 60s silence from MAC A)
        # Packet 1 from MAC B: candidate recorded, single packet does NOT replace baseline
        res_cand1 = detector.evaluate(PacketObservation(
            timestamp=1070.0, packet_size=100, eth_src=mac_b, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))
        assert res_cand1.status == DetectionStatus.NO_EVIDENCE
        assert "Pending" in res_cand1.evidence["verdict"]
        assert detector._ip_to_mac_binding[ip][0] == mac_a

        # Packet 2 from MAC B: confirmation threshold met (2 packets) -> Safe Promotion!
        res_cand2 = detector.evaluate(PacketObservation(
            timestamp=1071.0, packet_size=100, eth_src=mac_b, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))
        assert res_cand2.status == DetectionStatus.NO_EVIDENCE
        assert "handover confirmed" in res_cand2.evidence["verdict"].lower()

        # Authoritative baseline is now MAC B
        assert detector._ip_to_mac_binding[ip][0] == mac_b

        # Subsequent packet from MAC B is standard consistent traffic
        res_norm = detector.evaluate(PacketObservation(
            timestamp=1075.0, packet_size=100, eth_src=mac_b, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))
        assert res_norm.status == DetectionStatus.NO_EVIDENCE
        assert res_norm.evidence["verdict"] == "Consistent identity binding"

    def test_third_mac_does_not_corrupt_baseline(self):
        """
        Stage 3.2: Observations from a third MAC are tracked independently and do NOT
        corrupt or overwrite the established baseline or other candidate state.
        """
        detector = SpoofingDetector(local_subnet="192.168.137.0/24")
        mac_a = "00:11:22:33:44:55"
        mac_b = "00:aa:bb:cc:dd:02"
        mac_c = "00:aa:bb:cc:dd:03"
        ip = "192.168.137.101"

        # Baseline MAC A
        detector.evaluate(PacketObservation(
            timestamp=1000.0, packet_size=100, eth_src=mac_a, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))

        # Conflict from MAC B
        res_b = detector.evaluate(PacketObservation(
            timestamp=1005.0, packet_size=100, eth_src=mac_b, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))
        assert res_b.status == DetectionStatus.SUSPICIOUS
        assert res_b.evidence["current_mac"] == mac_b
        assert res_b.evidence["previous_mac"] == mac_a

        # Conflict from MAC C
        res_c = detector.evaluate(PacketObservation(
            timestamp=1008.0, packet_size=100, eth_src=mac_c, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))
        assert res_c.status == DetectionStatus.SUSPICIOUS
        assert res_c.evidence["current_mac"] == mac_c
        assert res_c.evidence["previous_mac"] == mac_a

        # Baseline remains firmly MAC A
        assert detector._ip_to_mac_binding[ip][0] == mac_a
        assert mac_b in detector._conflict_candidates[ip]
        assert mac_c in detector._conflict_candidates[ip]

    def test_separate_ip_addresses_maintain_independent_state(self):
        """
        Stage 3.2: Separate IP addresses maintain independent baseline bindings
        and candidate trackers without cross-contamination.
        """
        detector = SpoofingDetector(local_subnet="192.168.137.0/24")
        mac_1 = "00:11:22:33:44:01"
        mac_2 = "00:11:22:33:44:02"
        ip_1 = "192.168.137.101"
        ip_2 = "192.168.137.102"

        detector.evaluate(PacketObservation(
            timestamp=1000.0, packet_size=100, eth_src=mac_1, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip_1, ip_dst="192.168.137.1"
        ))
        detector.evaluate(PacketObservation(
            timestamp=1000.0, packet_size=100, eth_src=mac_2, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip_2, ip_dst="192.168.137.1"
        ))

        assert detector._ip_to_mac_binding[ip_1][0] == mac_1
        assert detector._ip_to_mac_binding[ip_2][0] == mac_2

        # Conflict on IP 1 does not affect IP 2
        mac_rogue = "00:ff:ff:ff:ff:ff"
        detector.evaluate(PacketObservation(
            timestamp=1005.0, packet_size=100, eth_src=mac_rogue, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip_1, ip_dst="192.168.137.1"
        ))

        assert detector._ip_to_mac_binding[ip_1][0] == mac_1
        assert detector._ip_to_mac_binding[ip_2][0] == mac_2
        assert mac_rogue in detector._conflict_candidates[ip_1]
        assert ip_2 not in detector._conflict_candidates

    def test_bounded_memory_pruning_removes_stale_bindings(self):
        """
        Stage 3.2: When max_tracked_ips limit is reached, stale bindings older than
        the cutoff are automatically pruned to keep memory bounded.
        """
        detector = SpoofingDetector(
            local_subnet="192.168.137.0/24",
            binding_expiry_seconds=10.0,
            max_tracked_ips=3,
        )

        for i in range(3):
            detector.evaluate(PacketObservation(
                timestamp=1000.0 + i, packet_size=100, eth_src=f"00:11:22:33:44:0{i}",
                eth_dst="36:6f:24:d2:34:3d", ip_src=f"192.168.137.10{i}", ip_dst="192.168.137.1"
            ))

        assert len(detector._ip_to_mac_binding) == 3

        # Force simulate stale entries for cleanup
        detector._cleanup_stale_bindings(now_mono=time.monotonic() + 1000.0)
        assert len(detector._ip_to_mac_binding) == 0

    def test_stale_candidate_confirmation_resets_after_expiry(self):
        """
        Stage 3.2.1: If more than binding_expiry_seconds (default 300s) elapses between observations
        from a candidate MAC, its confirmation state resets as a fresh candidate (packet_count=1)
        so an old observation cannot combine with a new observation to satisfy the handover threshold.
        """
        detector = SpoofingDetector(
            local_subnet="192.168.137.0/24",
            binding_expiry_seconds=300.0,
            confirmation_min_packets=2,
        )
        mac_a = "00:11:22:33:44:55"
        mac_b = "00:aa:bb:cc:dd:ee"
        ip = "192.168.137.101"

        # Baseline MAC A communicated at t=1000.0, then went silent
        detector.evaluate(PacketObservation(
            timestamp=1000.0, packet_size=100, eth_src=mac_a, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))

        # Candidate MAC B sends 1 packet at t=1005.0 (packet_count = 1)
        detector.evaluate(PacketObservation(
            timestamp=1005.0, packet_size=100, eth_src=mac_b, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))
        assert detector._conflict_candidates[ip][mac_b].packet_count == 1

        # Gap of 350 seconds (> 300s binding_expiry_seconds). Baseline MAC A is now expired (> 300s).
        # MAC B sends a packet at t=1355.0.
        # Candidate state MUST reset to packet_count=1, preventing old observation from completing handover.
        res = detector.evaluate(PacketObservation(
            timestamp=1355.0, packet_size=100, eth_src=mac_b, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))
        assert detector._conflict_candidates[ip][mac_b].packet_count == 1
        assert detector._conflict_candidates[ip][mac_b].first_seen == 1355.0
        assert detector._conflict_candidates[ip][mac_b].last_seen == 1355.0
        assert res.status == DetectionStatus.NO_EVIDENCE
        assert "Pending" in res.evidence["verdict"]
        # Baseline must still be MAC A!
        assert detector._ip_to_mac_binding[ip][0] == mac_a

        # Second packet within active window (t=1357.0) confirms presence -> Handover succeeds!
        res2 = detector.evaluate(PacketObservation(
            timestamp=1357.0, packet_size=100, eth_src=mac_b, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))
        assert res2.status == DetectionStatus.NO_EVIDENCE
        assert "handover confirmed" in res2.evidence["verdict"].lower()
        assert detector._ip_to_mac_binding[ip][0] == mac_b

    def test_candidate_observations_within_window_still_accumulate(self):
        """
        Stage 3.2.1: Candidate observations arriving within binding_expiry_seconds (<= 300s)
        continue to accumulate packet counts normally.
        """
        detector = SpoofingDetector(
            local_subnet="192.168.137.0/24",
            binding_expiry_seconds=300.0,
        )
        mac_a = "00:11:22:33:44:55"
        mac_b = "00:aa:bb:cc:dd:ee"
        ip = "192.168.137.101"

        # Baseline
        detector.evaluate(PacketObservation(
            timestamp=1000.0, packet_size=100, eth_src=mac_a, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))

        # Packet 1 at t=1005.0
        detector.evaluate(PacketObservation(
            timestamp=1005.0, packet_size=100, eth_src=mac_b, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))
        # Packet 2 at t=1200.0 (gap of 195s <= 300s)
        detector.evaluate(PacketObservation(
            timestamp=1200.0, packet_size=100, eth_src=mac_b, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))
        # Packet 3 at t=1250.0 (gap of 50s <= 300s)
        detector.evaluate(PacketObservation(
            timestamp=1250.0, packet_size=100, eth_src=mac_b, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))

        assert detector._conflict_candidates[ip][mac_b].packet_count == 3
        assert detector._conflict_candidates[ip][mac_b].first_seen == 1005.0
        assert detector._conflict_candidates[ip][mac_b].last_seen == 1250.0

    def test_one_candidate_expiry_does_not_affect_another_candidate(self):
        """
        Stage 3.2.1: Expiration of one candidate's confirmation state does not affect
        another candidate's independently tracked state on the same IP.
        """
        detector = SpoofingDetector(
            local_subnet="192.168.137.0/24",
            binding_expiry_seconds=300.0,
        )
        mac_a = "00:11:22:33:44:55"
        mac_b = "00:aa:bb:cc:dd:02"
        mac_c = "00:aa:bb:cc:dd:03"
        ip = "192.168.137.101"

        # Baseline MAC A at t=1000
        detector.evaluate(PacketObservation(
            timestamp=1000.0, packet_size=100, eth_src=mac_a, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))

        # Candidate MAC B at t=1005.0
        detector.evaluate(PacketObservation(
            timestamp=1005.0, packet_size=100, eth_src=mac_b, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))

        # Baseline MAC A refreshes at t=1250.0 (baseline remains active)
        detector.evaluate(PacketObservation(
            timestamp=1250.0, packet_size=100, eth_src=mac_a, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))

        # Candidate MAC C at t=1300.0
        detector.evaluate(PacketObservation(
            timestamp=1300.0, packet_size=100, eth_src=mac_c, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))

        # At t=1350.0:
        # MAC C sends second packet (gap 50s <= 300s): accumulates to packet_count=2
        detector.evaluate(PacketObservation(
            timestamp=1350.0, packet_size=100, eth_src=mac_c, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))
        assert detector._conflict_candidates[ip][mac_c].packet_count == 2

        # MAC B sends packet at t=1355.0 (gap 350s > 300s): resets to packet_count=1
        detector.evaluate(PacketObservation(
            timestamp=1355.0, packet_size=100, eth_src=mac_b, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))
        assert detector._conflict_candidates[ip][mac_b].packet_count == 1
        # MAC C's count remains 2
        assert detector._conflict_candidates[ip][mac_c].packet_count == 2

    def test_active_baseline_traffic_does_not_prevent_stale_candidate_expiration(self):
        """
        Stage 3.2.1: Continuous baseline traffic refreshing the IP's last-seen time
        does not prevent an inactive candidate record from expiring after 300 seconds.
        """
        detector = SpoofingDetector(
            local_subnet="192.168.137.0/24",
            binding_expiry_seconds=300.0,
            conflict_alert_cooldown_seconds=60.0,
        )
        mac_a = "00:11:22:33:44:55"
        mac_b = "00:aa:bb:cc:dd:ee"
        ip = "192.168.137.101"

        # Baseline MAC A starts at t=1000
        detector.evaluate(PacketObservation(
            timestamp=1000.0, packet_size=100, eth_src=mac_a, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))

        # Candidate MAC B sends 1 packet at t=1005 (alert emitted)
        r1 = detector.evaluate(PacketObservation(
            timestamp=1005.0, packet_size=100, eth_src=mac_b, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))
        assert r1.status == DetectionStatus.SUSPICIOUS

        # Baseline MAC A transmits continuously every 50 seconds up to t=1400
        for t in range(1050, 1450, 50):
            detector.evaluate(PacketObservation(
                timestamp=float(t), packet_size=100, eth_src=mac_a, eth_dst="36:6f:24:d2:34:3d",
                ip_src=ip, ip_dst="192.168.137.1"
            ))

        assert detector._ip_to_mac_binding[ip][0] == mac_a
        assert detector._ip_to_mac_binding[ip][1] == 1400.0

        # Now at t=1405 (gap of 400s > 300s since MAC B's last packet at t=1005):
        # MAC B sends another packet. Even though baseline was active, MAC B's candidate state
        # is stale and MUST reset to packet_count=1 and re-alert as a fresh conflict episode.
        r2 = detector.evaluate(PacketObservation(
            timestamp=1405.0, packet_size=100, eth_src=mac_b, eth_dst="36:6f:24:d2:34:3d",
            ip_src=ip, ip_dst="192.168.137.1"
        ))
        assert r2.status == DetectionStatus.SUSPICIOUS
        assert detector._conflict_candidates[ip][mac_b].packet_count == 1
        assert detector._conflict_candidates[ip][mac_b].first_seen == 1405.0
        assert detector._ip_to_mac_binding[ip][0] == mac_a


# =============================================================================
# 4. Wi-Fi Deauthentication / Disassociation Abuse Tests
# =============================================================================

class TestDeauthDetector:

    def test_missing_80211_management_frames_reports_insufficient_telemetry(self):
        """
        Standard Windows Hotspot Ethernet-emulation capture strips 802.11 management frames.
        The detector MUST report INSUFFICIENT_TELEMETRY.
        """
        detector = DeauthDetector()
        packets = [
            PacketObservation(
                timestamp=1000.0,
                packet_size=100,
                eth_src="ca:34:ea:92:d3:9e",
                eth_dst="00:15:5d:01:02:03",
                ip_src="192.168.137.201",
                ip_dst="192.168.137.1",
                wlan_fc_type_subtype=None,  # Missing!
            )
        ]

        result = detector.evaluate(packets)
        assert result.category == AttackCategory.DEAUTH_FLOOD
        assert result.status == DetectionStatus.INSUFFICIENT_TELEMETRY
        assert "wlan_fc_type_subtype" in result.missing_fields

    def test_deauth_flood_detected_when_80211_telemetry_provided(self):
        """
        When 802.11 management frames are provided (e.g. from monitor mode or test frame),
        a burst of Deauth frames (subtype 12) triggers SUSPICIOUS.
        """
        detector = DeauthDetector(flood_rate_threshold=5, window_seconds=1.0)
        packets = [
            PacketObservation(
                timestamp=1000.0 + i * 0.05,
                packet_size=26,
                eth_src="00:11:22:33:44:55",
                eth_dst="ff:ff:ff:ff:ff:ff",
                wlan_fc_type_subtype=12,  # Deauthentication
                wlan_reason_code=7,       # Class 3 frame received from nonauthenticated STA
                wlan_bssid="00:11:22:33:44:55",
            )
            for i in range(8)
        ]

        result = detector.evaluate(packets)
        assert result.category == AttackCategory.DEAUTH_FLOOD
        assert result.status == DetectionStatus.SUSPICIOUS
        assert result.evidence["details"][0]["frame_count_in_window"] == 8

    def test_deauth_frame_rate_exact_boundary_4_vs_5_frames(self):
        """
        GAP-82-04: Verifies the exact Deauthentication flood rate boundary (>= 5 frames in 1.0s):
        - 4 frames in 1.0s window: rate = 4.0 fps (< 5.0 fps), MUST NOT trigger (NO_EVIDENCE).
        - 5 frames in 1.0s window: rate = 5.0 fps (>= 5.0 fps), MUST trigger SUSPICIOUS flood alert.
        - Spanning window test: 5 frames arriving over 1.02s (> 1.0s window duration) prunes the
          oldest frame, leaving only 4 frames in window, confirming sub-5.0 fps is rejected.
        """
        bssid = "00:11:22:33:44:55"

        # Case A: 4 frames within 1.0s (4.0 fps - sub-threshold)
        detector_4 = DeauthDetector(flood_rate_threshold=5, window_seconds=1.0)
        packets_4 = [
            PacketObservation(
                timestamp=1000.0 + i * 0.2,  # 0.0, 0.2, 0.4, 0.6 s
                packet_size=26,
                eth_src=bssid,
                eth_dst="ff:ff:ff:ff:ff:ff",
                wlan_fc_type_subtype=12,
                wlan_reason_code=7,
                wlan_bssid=bssid,
            )
            for i in range(4)
        ]
        result_4 = detector_4.evaluate(packets_4)
        assert result_4.category == AttackCategory.DEAUTH_FLOOD
        assert result_4.status == DetectionStatus.NO_EVIDENCE
        assert result_4.severity == Severity.NONE
        assert result_4.evidence["verdict"] == "Deauth frame rate below threshold"
        assert result_4.evidence["deauth_count"] == 4

        # Case B: 5 frames within 1.0s (5.0 fps - exact threshold)
        detector_5 = DeauthDetector(flood_rate_threshold=5, window_seconds=1.0)
        packets_5 = [
            PacketObservation(
                timestamp=1000.0 + i * 0.2,  # 0.0, 0.2, 0.4, 0.6, 0.8 s (all within 1.0s)
                packet_size=26,
                eth_src=bssid,
                eth_dst="ff:ff:ff:ff:ff:ff",
                wlan_fc_type_subtype=12,
                wlan_reason_code=7,
                wlan_bssid=bssid,
            )
            for i in range(5)
        ]
        result_5 = detector_5.evaluate(packets_5)
        assert result_5.category == AttackCategory.DEAUTH_FLOOD
        assert result_5.status == DetectionStatus.SUSPICIOUS
        assert result_5.severity == Severity.HIGH
        assert len(result_5.evidence["details"]) >= 1
        detail = result_5.evidence["details"][0]
        assert detail["bssid"] == bssid
        assert detail["frame_count_in_window"] == 5
        assert result_5.confidence >= 0.70

        # Case C: 5 frames spanning 1.02s (first frame at 1000.0s, last at 1001.02s)
        # Evaluated at now = 1001.02s: frame at 1000.0 is 1.02s old (> window_seconds 1.0s)
        # Resulting in exactly 4 frames inside the sliding window -> MUST NOT trigger.
        detector_span = DeauthDetector(flood_rate_threshold=5, window_seconds=1.0)
        packets_span = [
            PacketObservation(
                timestamp=1000.0 + i * 0.255,  # 1000.0, 1000.255, 1000.51, 1000.765, 1001.02
                packet_size=26,
                eth_src=bssid,
                eth_dst="ff:ff:ff:ff:ff:ff",
                wlan_fc_type_subtype=12,
                wlan_reason_code=7,
                wlan_bssid=bssid,
            )
            for i in range(5)
        ]
        result_span = detector_span.evaluate(packets_span)
        assert result_span.status == DetectionStatus.NO_EVIDENCE
        assert result_span.evidence["verdict"] == "Deauth frame rate below threshold"


# =============================================================================
# 5. Replay Attack Tests
# =============================================================================

class TestReplayDetector:

    def test_missing_sequence_and_payload_hash_reports_insufficient_telemetry(self):
        """
        Without cryptographic nonces or payload hashes, the detector MUST report
        INSUFFICIENT_TELEMETRY. Identical packet size is NOT sufficient.
        """
        detector = ReplayDetector()
        packets = [
            PacketObservation(
                timestamp=1000.0,
                packet_size=64,
                eth_src="ca:34:ea:92:d3:9e",
                eth_dst="00:15:5d:01:02:03",
                ip_src="192.168.137.201",
                ip_dst="192.168.137.1",
                payload_hash=None,
                nonce=None,
                protocol_seq_num=None,
            )
        ]

        result = detector.evaluate(packets)
        assert result.category == AttackCategory.REPLAY
        assert result.status == DetectionStatus.INSUFFICIENT_TELEMETRY
        assert "payload_hash" in result.missing_fields

    def test_tcp_retransmission_within_rto_window_not_flagged(self):
        """
        Legitimate TCP retransmission (same sequence number within 3 seconds)
        must NOT be flagged as a replay attack.
        """
        detector = ReplayDetector(tcp_retransmit_window_seconds=3.0)

        p1 = PacketObservation(
            timestamp=1000.0,
            packet_size=1500,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="00:15:5d:01:02:03",
            protocol_seq_num=1024,
            payload_hash="sha256_mock_hash_abc",
        )
        detector.evaluate([p1])

        # Retransmitted 0.5s later due to simulated packet loss
        p2 = PacketObservation(
            timestamp=1000.5,
            packet_size=1500,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="00:15:5d:01:02:03",
            protocol_seq_num=1024,
            payload_hash="sha256_mock_hash_abc",
        )
        res = detector.evaluate([p2])
        assert res.status == DetectionStatus.NO_EVIDENCE

    def test_nonce_reuse_detected_as_replay(self):
        """
        Cryptographic nonce reuse across separate messages must be flagged as a replay threat.
        """
        detector = ReplayDetector()
        p1 = PacketObservation(
            timestamp=1000.0,
            packet_size=256,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="00:15:5d:01:02:03",
            nonce="auth_nonce_xyz_9988",
        )
        detector.evaluate([p1])

        # Attacker re-injects message with same nonce 15 seconds later
        p2 = PacketObservation(
            timestamp=1015.0,
            packet_size=256,
            eth_src="00:11:22:33:44:55",
            eth_dst="00:15:5d:01:02:03",
            nonce="auth_nonce_xyz_9988",
        )
        res = detector.evaluate([p2])
        assert res.status == DetectionStatus.SUSPICIOUS
        assert "Nonce Reuse" in res.evidence["violations"][0]["anomaly_type"]

    def test_same_flow_same_sequence_number_suppressed_as_retransmission(self):
        """
        Repeated sequence numbers within the same flow and within the 3.0s RTO window
        must be suppressed as legitimate TCP retransmissions.
        """
        detector = ReplayDetector(tcp_retransmit_window_seconds=3.0)

        p1 = PacketObservation(
            timestamp=1000.0,
            packet_size=1460,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.201",
            ip_dst="192.168.137.1",
            src_port=50001,
            dst_port=80,
            protocol="TCP",
            protocol_seq_num=100,
            payload_hash=None,
        )
        detector.evaluate([p1])

        # Retransmitted on the same flow 0.6s later (within 3.0s window)
        p2 = PacketObservation(
            timestamp=1000.6,
            packet_size=1460,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.201",
            ip_dst="192.168.137.1",
            src_port=50001,
            dst_port=80,
            protocol="TCP",
            protocol_seq_num=100,
            payload_hash=None,
        )
        res = detector.evaluate([p2])
        assert res.status == DetectionStatus.NO_EVIDENCE

    def test_different_flows_same_sequence_number_evaluated_independently(self):
        """
        Unrelated network flows sharing the same TCP sequence number within the
        retransmission window must NOT collide or suppress each other.
        """
        detector = ReplayDetector(tcp_retransmit_window_seconds=3.0)

        # Flow A (Client 1 to Web Server)
        p_flow_a = PacketObservation(
            timestamp=1000.0,
            packet_size=100,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.201",
            ip_dst="192.168.137.1",
            src_port=50001,
            dst_port=80,
            protocol="TCP",
            protocol_seq_num=500,
            payload_hash=None,
        )
        detector.evaluate([p_flow_a])

        # Flow B (Different Client / Unrelated Flow) with IDENTICAL sequence number 500 at 0.5s later
        p_flow_b1 = PacketObservation(
            timestamp=1000.5,
            packet_size=100,
            eth_src="aa:bb:cc:dd:ee:ff",
            eth_dst="00:15:5d:01:02:03",
            ip_src="10.0.0.5",
            ip_dst="10.0.0.1",
            src_port=44332,
            dst_port=443,
            protocol="TCP",
            protocol_seq_num=500,
            payload_hash=None,
        )
        res_b1 = detector.evaluate([p_flow_b1])
        assert res_b1.status == DetectionStatus.NO_EVIDENCE

        # Verify flow keys are strictly distinct in detector's internal state
        flow_a_key = ReplayDetector._extract_flow_key(p_flow_a)
        flow_b_key = ReplayDetector._extract_flow_key(p_flow_b1)
        assert flow_a_key != flow_b_key
        assert f"seq_{flow_a_key}_500" in detector._seen_payloads
        assert f"seq_{flow_b_key}_500" in detector._seen_payloads
        assert len(detector._seen_payloads[f"seq_{flow_a_key}_500"]) == 1
        assert len(detector._seen_payloads[f"seq_{flow_b_key}_500"]) == 1

        # Now Flow B retransmits sequence 500 at 1001.0 (delta 0.5s from p_flow_b1)
        p_flow_b2 = PacketObservation(
            timestamp=1001.0,
            packet_size=100,
            eth_src="aa:bb:cc:dd:ee:ff",
            eth_dst="00:15:5d:01:02:03",
            ip_src="10.0.0.5",
            ip_dst="10.0.0.1",
            src_port=44332,
            dst_port=443,
            protocol="TCP",
            protocol_seq_num=500,
            payload_hash=None,
        )
        res_b2 = detector.evaluate([p_flow_b2])
        assert res_b2.status == DetectionStatus.NO_EVIDENCE
        # Flow B retransmission properly recorded under Flow B's key, not Flow A's
        assert len(detector._seen_payloads[f"seq_{flow_b_key}_500"]) == 2
        assert len(detector._seen_payloads[f"seq_{flow_a_key}_500"]) == 1

    def test_different_source_ports_treated_as_different_flows(self):
        """
        Two flows between the same IPs and destination port, but differing source ports,
        must be treated as distinct flows with independent sequence keys.
        """
        detector = ReplayDetector(tcp_retransmit_window_seconds=3.0)

        p1 = PacketObservation(
            timestamp=1000.0,
            packet_size=200,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.201",
            ip_dst="192.168.137.1",
            src_port=50001,
            dst_port=80,
            protocol="TCP",
            protocol_seq_num=1000,
        )
        p2 = PacketObservation(
            timestamp=1000.4,
            packet_size=200,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.201",
            ip_dst="192.168.137.1",
            src_port=50002,  # Different source port!
            dst_port=80,
            protocol="TCP",
            protocol_seq_num=1000,
        )

        flow_key_1 = ReplayDetector._extract_flow_key(p1)
        flow_key_2 = ReplayDetector._extract_flow_key(p2)
        assert flow_key_1 != flow_key_2
        assert flow_key_1[2] == 50001
        assert flow_key_2[2] == 50002

        detector.evaluate([p1])
        detector.evaluate([p2])
        assert f"seq_{flow_key_1}_1000" in detector._seen_payloads
        assert f"seq_{flow_key_2}_1000" in detector._seen_payloads
        assert len(detector._seen_payloads[f"seq_{flow_key_1}_1000"]) == 1
        assert len(detector._seen_payloads[f"seq_{flow_key_2}_1000"]) == 1

    def test_different_destination_ports_treated_as_different_flows(self):
        """
        Two flows from the same source IP/port to different destination ports
        must be treated as distinct flows with independent sequence keys.
        """
        detector = ReplayDetector(tcp_retransmit_window_seconds=3.0)

        p1 = PacketObservation(
            timestamp=1000.0,
            packet_size=200,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.201",
            ip_dst="192.168.137.1",
            src_port=50001,
            dst_port=80,
            protocol="TCP",
            protocol_seq_num=2000,
        )
        p2 = PacketObservation(
            timestamp=1000.4,
            packet_size=200,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.201",
            ip_dst="192.168.137.1",
            src_port=50001,
            dst_port=8080,  # Different destination port!
            protocol="TCP",
            protocol_seq_num=2000,
        )

        flow_key_1 = ReplayDetector._extract_flow_key(p1)
        flow_key_2 = ReplayDetector._extract_flow_key(p2)
        assert flow_key_1 != flow_key_2
        assert flow_key_1[3] == 80
        assert flow_key_2[3] == 8080

        detector.evaluate([p1])
        detector.evaluate([p2])
        assert f"seq_{flow_key_1}_2000" in detector._seen_payloads
        assert f"seq_{flow_key_2}_2000" in detector._seen_payloads

    def test_different_transport_protocols_treated_as_different_flows(self):
        """
        Packets sharing sequence numbers but using different transport protocols (e.g. TCP vs UDP)
        must be treated as distinct flows with independent sequence keys.
        """
        detector = ReplayDetector(tcp_retransmit_window_seconds=3.0)

        p_tcp = PacketObservation(
            timestamp=1000.0,
            packet_size=200,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.201",
            ip_dst="192.168.137.1",
            src_port=50001,
            dst_port=80,
            protocol="TCP",
            protocol_seq_num=3000,
        )
        p_udp = PacketObservation(
            timestamp=1000.4,
            packet_size=200,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.201",
            ip_dst="192.168.137.1",
            src_port=50001,
            dst_port=80,
            protocol="UDP",
            protocol_seq_num=3000,
        )

        flow_key_tcp = ReplayDetector._extract_flow_key(p_tcp)
        flow_key_udp = ReplayDetector._extract_flow_key(p_udp)
        assert flow_key_tcp != flow_key_udp
        assert flow_key_tcp[4] == "TCP"
        assert flow_key_udp[4] == "UDP"

        detector.evaluate([p_tcp])
        detector.evaluate([p_udp])
        assert f"seq_{flow_key_tcp}_3000" in detector._seen_payloads
        assert f"seq_{flow_key_udp}_3000" in detector._seen_payloads

    def test_missing_endpoint_fields_handled_safely_without_incorrect_merging(self):
        """
        Missing endpoint fields (e.g. missing ports, missing IPs) must remain None
        without inventing synthetic values, and must NOT cause unrelated flows to merge.
        """
        detector = ReplayDetector()

        # Packet with specified source port vs packet with missing source port
        p_with_port = PacketObservation(
            timestamp=1000.0,
            packet_size=60,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.201",
            ip_dst="192.168.137.1",
            src_port=50001,
            dst_port=80,
            protocol="TCP",
            protocol_seq_num=100,
        )
        p_missing_port = PacketObservation(
            timestamp=1000.2,
            packet_size=60,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.201",
            ip_dst="192.168.137.1",
            src_port=None,  # Missing port
            dst_port=80,
            protocol="TCP",
            protocol_seq_num=100,
        )
        k_port = ReplayDetector._extract_flow_key(p_with_port)
        k_no_port = ReplayDetector._extract_flow_key(p_missing_port)
        assert k_port != k_no_port
        assert k_no_port[2] is None  # Never invented as 0 or synthetic int

        # Packets with missing IP addresses must differentiate on L2 MAC addresses
        p_l2_node_a = PacketObservation(
            timestamp=1000.0,
            packet_size=60,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="00:15:5d:01:02:03",
            ip_src=None,
            ip_dst=None,
            src_port=None,
            dst_port=None,
            protocol=None,
            protocol_seq_num=777,
        )
        p_l2_node_b = PacketObservation(
            timestamp=1000.3,
            packet_size=60,
            eth_src="aa:bb:cc:dd:ee:ff",  # Different physical source
            eth_dst="00:15:5d:01:02:03",
            ip_src=None,
            ip_dst=None,
            src_port=None,
            dst_port=None,
            protocol=None,
            protocol_seq_num=777,
        )
        k_l2_a = ReplayDetector._extract_flow_key(p_l2_node_a)
        k_l2_b = ReplayDetector._extract_flow_key(p_l2_node_b)
        assert k_l2_a != k_l2_b
        assert k_l2_a[0] == "ca:34:ea:92:d3:9e"
        assert k_l2_b[0] == "aa:bb:cc:dd:ee:ff"

        detector.evaluate([p_l2_node_a])
        detector.evaluate([p_l2_node_b])
        assert f"seq_{k_l2_a}_777" in detector._seen_payloads
        assert f"seq_{k_l2_b}_777" in detector._seen_payloads

    def test_existing_stale_payload_reinjection_detected_after_rto_window(self):
        """
        Duplicate payload observation outside the 3.0s retransmission window
        must be flagged as a Stale Payload Re-injection threat.
        """
        detector = ReplayDetector(tcp_retransmit_window_seconds=3.0)

        p1 = PacketObservation(
            timestamp=1000.0,
            packet_size=128,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.201",
            ip_dst="192.168.137.1",
            payload_hash="sha256_command_valve_open",
        )
        detector.evaluate([p1])

        # Replayed 10.0s later (outside 3.0s RTO window)
        p2 = PacketObservation(
            timestamp=1010.0,
            packet_size=128,
            eth_src="00:11:22:33:44:55",
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.150",
            ip_dst="192.168.137.1",
            payload_hash="sha256_command_valve_open",
        )
        res = detector.evaluate([p2])
        assert res.status == DetectionStatus.SUSPICIOUS
        assert res.severity == Severity.HIGH
        assert res.confidence == 0.70
        assert "Stale Payload Re-injection" in res.evidence["violations"][0]["anomaly_type"]

    def test_replay_out_of_order_packets_timestamp_regression(self):
        """
        GAP-82-05: Tests replay detection when packets arrive out of chronological order (t2 < t1):
        1. Jitter / out-of-order on same flow: packet with seq 100 arrives at 1000.5, then duplicate
           packet with seq 100 arrives with timestamp 1000.2 (time regression: delta = -0.3s <= 3.0s).
           Must be suppressed as legitimate TCP retransmission/jitter, NOT flagged as replay.
        2. Nonce reuse with timestamp regression: packet with nonce 'auth_token_nonce_998877' at 1000.8,
           then another packet with identical nonce at 1000.3 (time regression: delta = -0.5s).
           Must still be correctly detected as 'Cryptographic Nonce Reuse' threat.
        3. Evaluates that timestamps are handled safely without crash, now = max(timestamps),
           and evidence attribution remains accurate.
        """
        detector = ReplayDetector(tcp_retransmit_window_seconds=3.0)

        # 1. Out-of-order TCP retransmission / jitter on same flow
        p_seq_1 = PacketObservation(
            timestamp=1000.5,
            packet_size=120,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.201",
            ip_dst="192.168.137.1",
            src_port=50001,
            dst_port=80,
            protocol="TCP",
            protocol_seq_num=100,
        )
        res1 = detector.evaluate([p_seq_1])
        assert res1.status == DetectionStatus.NO_EVIDENCE

        # Packet arriving later with an EARLIER timestamp (timestamp regression t2 < t1)
        p_seq_2 = PacketObservation(
            timestamp=1000.2,  # Earlier than p_seq_1 (1000.5)
            packet_size=120,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.201",
            ip_dst="192.168.137.1",
            src_port=50001,
            dst_port=80,
            protocol="TCP",
            protocol_seq_num=100,
        )
        res2 = detector.evaluate([p_seq_2])
        # Delta = 1000.2 - 1000.5 = -0.3s <= 3.0s RTO window -> legitimate retransmission
        assert res2.status == DetectionStatus.NO_EVIDENCE
        assert res2.severity == Severity.NONE
        assert res2.evidence["verdict"] == "No replay violations observed"

        # 2. Cryptographic Nonce Reuse with out-of-order arrival
        p_nonce_1 = PacketObservation(
            timestamp=1000.8,
            packet_size=90,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.201",
            ip_dst="192.168.137.1",
            nonce="auth_token_nonce_998877",
        )
        detector.evaluate([p_nonce_1])

        # Second packet with duplicate nonce arrives with EARLIER timestamp (1000.3 < 1000.8)
        p_nonce_2 = PacketObservation(
            timestamp=1000.3,
            packet_size=90,
            eth_src="00:11:22:33:44:55",  # Potentially spoofed or replayed
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.150",
            ip_dst="192.168.137.1",
            nonce="auth_token_nonce_998877",
        )
        res_nonce = detector.evaluate([p_nonce_2])
        assert res_nonce.status == DetectionStatus.SUSPICIOUS
        assert res_nonce.severity == Severity.HIGH
        assert res_nonce.confidence >= 0.80
        assert len(res_nonce.evidence["violations"]) >= 1
        violation = res_nonce.evidence["violations"][0]
        assert violation["anomaly_type"] == "Cryptographic Nonce Reuse"
        assert violation["nonce"] == "auth_token_nonce_998877"
        assert violation["src"] == "192.168.137.150"
        assert violation["dst"] == "192.168.137.1"


# =============================================================================
# 6. RSSI Validation Tests
# =============================================================================

class TestRSSIHandling:

    def test_missing_rssi_is_none_never_zero(self):
        """
        Missing RSSI must be None. 0.0 dBm must be rejected as an invalid/bogus value.
        """
        assert RSSIMeasurement.validate(None) is None
        assert RSSIMeasurement.validate(0.0) is None
        assert RSSIMeasurement.validate(5.0) is None  # Positive dBm is impossible
        assert RSSIMeasurement.validate(-150.0) is None  # Below thermal noise floor

    def test_valid_physical_rssi_accepted(self):
        """
        Realistic ambient Wi-Fi signal in [-100, -10] dBm range is valid.
        """
        assert RSSIMeasurement.validate(-65.0) == -65.0
        assert RSSIMeasurement.validate(-42.5) == -42.5


# =============================================================================
# 7. Robustness & Incomplete Packet Tests
# =============================================================================

class TestRobustnessAndMalformedPackets:

    def test_empty_or_malformed_packets_handled_gracefully(self):
        """
        Empty packet lists, missing IP addresses, and malformed records
        must not throw unhandled exceptions.
        """
        detector = NetworkAttackDetector()

        # Empty packet list
        results = detector.evaluate_packet_stream([])
        assert len(results) == 4
        for r in results:
            assert r.status in (DetectionStatus.NO_EVIDENCE, DetectionStatus.INSUFFICIENT_TELEMETRY)

        # Incomplete packet with missing IP/MAC
        bad_packet = PacketObservation(
            timestamp=1000.0,
            packet_size=0,
            eth_src="",
            eth_dst="",
            ip_src=None,
            ip_dst=None,
        )
        results = detector.evaluate_packet_stream([bad_packet])
        assert len(results) == 4
        # None should crash
        for r in results:
            assert isinstance(r.status, DetectionStatus)

    def test_normal_baseline_traffic_produces_no_evidence(self):
        """
        Normal steady-state traffic produces NO_EVIDENCE across all evaluable detectors.
        """
        detector = NetworkAttackDetector(dos_rate_threshold=60.0)
        detector.set_known_devices({"ca:34:ea:92:d3:9e"})

        normal_window = WindowTrafficObservation(
            bin_start_epoch=1000.0,
            node_id="Node_3",
            mac_address="ca:34:ea:92:d3:9e",
            packet_count=5,
            packet_rate=5.0,
            total_bytes=1200,
            ip_src="192.168.137.201",
            ip_dst="192.168.137.1",
        )

        window_results = detector.evaluate_traffic_window(normal_window)
        assert window_results[0].category == AttackCategory.DOS
        assert window_results[0].status == DetectionStatus.NO_EVIDENCE

    def test_capabilities_matrix_exposes_academic_truth(self):
        """
        Verifies that get_capabilities() truthfully exposes what is operational vs
        what requires enhanced capture.
        """
        caps = NetworkAttackDetector.get_capabilities()
        assert caps["DOS"]["status_on_current_stream"] == "OPERATIONAL"
        assert caps["SPOOFING"]["status_on_current_stream"] == "OPERATIONAL"
        assert caps["PORT_SCAN"]["status_on_current_stream"] == "INSUFFICIENT_TELEMETRY"
        assert caps["DEAUTH_FLOOD"]["status_on_current_stream"] == "INSUFFICIENT_TELEMETRY"
        assert caps["REPLAY"]["status_on_current_stream"] == "INSUFFICIENT_TELEMETRY"
        assert caps["RSSI_MONITORING"]["status_on_current_stream"] == "UNAVAILABLE"
