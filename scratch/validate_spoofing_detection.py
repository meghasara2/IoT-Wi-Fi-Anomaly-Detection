import sys
import math
import time
import json
import sqlite3
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

# Add project root to path
PROJECT_ROOT = Path(r"C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection")
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.attack_detector import (
    SpoofingDetector,
    PacketObservation,
    AttackDetectionResult,
    AttackCategory,
    DetectionStatus,
    Severity,
)
from src.init_live_database import init_live_database, get_live_db_connection
from src.live_collector import LiveCollector

def run_sequence(
    name: str,
    detector: SpoofingDetector,
    packets: List[PacketObservation],
    expected_status: Optional[DetectionStatus] = None,
    expected_severity: Optional[Severity] = None,
    expected_verdict_substring: Optional[str] = None,
    expected_missing_fields: Optional[List[str]] = None,
    expected_evidence_keys: Optional[Dict[str, Any]] = None,
    step_check: Optional[Dict[int, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Feeds a sequential list of packets to SpoofingDetector.
    Resets the detector at start.
    Optionally validates intermediate steps via step_check: {step_idx: {expected_attr: val}}.
    """
    detector.reset()
    results: List[AttackDetectionResult] = []

    step_checks_passed = True
    step_errors = []

    for idx, pkt in enumerate(packets):
        res = detector.evaluate(pkt)
        results.append(res)

        if step_check and idx in step_check:
            expected_step = step_check[idx]
            for key, val in expected_step.items():
                if key == "status" and res.status != val:
                    step_checks_passed = False
                    step_errors.append(f"Step {idx}: status {res.status.value} != {val.value}")
                elif key == "severity" and res.severity != val:
                    step_checks_passed = False
                    step_errors.append(f"Step {idx}: severity {res.severity.value} != {val.value}")
                elif key == "verdict" and val not in res.evidence.get("verdict", ""):
                    step_checks_passed = False
                    step_errors.append(f"Step {idx}: verdict '{res.evidence.get('verdict')}' does not contain '{val}'")

    final_res = results[-1]

    status_ok = (expected_status is None) or (final_res.status == expected_status)
    severity_ok = (expected_severity is None) or (final_res.severity == expected_severity)
    
    verdict_str = final_res.evidence.get("verdict", "")
    if not verdict_str and "reason" in final_res.evidence:
        verdict_str = final_res.evidence["reason"]
    verdict_ok = (expected_verdict_substring is None) or (expected_verdict_substring in verdict_str)

    missing_ok = True
    if expected_missing_fields is not None:
        missing_ok = set(final_res.missing_fields) == set(expected_missing_fields)

    evidence_ok = True
    if expected_evidence_keys is not None:
        for k, v in expected_evidence_keys.items():
            if final_res.evidence.get(k) != v:
                evidence_ok = False
                step_errors.append(f"Evidence {k}: {final_res.evidence.get(k)} != {v}")

    passed = status_ok and severity_ok and verdict_ok and missing_ok and evidence_ok and step_checks_passed

    return {
        "scenario": name,
        "packet_count": len(packets),
        "final_status": final_res.status.value,
        "final_severity": final_res.severity.value,
        "final_confidence": round(final_res.confidence, 4),
        "verdict": verdict_str,
        "evidence": final_res.evidence,
        "missing_fields": final_res.missing_fields,
        "expected_status": expected_status.value if expected_status else None,
        "expected_severity": expected_severity.value if expected_severity else None,
        "expected_verdict": expected_verdict_substring,
        "step_errors": step_errors,
        "passed": passed,
    }

def evaluate_real_pcap_spoofing(pcap_path: Path, gateway_mac: str) -> Dict[str, Any]:
    """
    Replays real-world PCAP offline against SpoofingDetector.
    Verifies that no false positive spoofing alerts are produced.
    """
    detector = SpoofingDetector(
        gateway_ip="192.168.137.1",
        gateway_mac=gateway_mac,
        local_subnet="192.168.137.0/24",
    )
    detector.reset()

    tshark_bin = Path(r"C:\Program Files\Wireshark\tshark.exe")
    if not tshark_bin.exists():
        return {"scenario": "L1_Real_PCAP_Replay_Spoofing", "passed": False, "error": "TShark not found"}

    cmd = [
        str(tshark_bin),
        "-r", str(pcap_path),
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "eth.src",
        "-e", "eth.dst",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "_ws.col.Protocol",
    ]

    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    lines = proc.stdout.strip().splitlines()

    total_packets = 0
    false_positives = 0
    fp_details = []

    for line in lines:
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        try:
            ts = float(parts[0]) if parts[0] else 0.0
            flen = int(parts[1]) if parts[1] else 0
            eth_src = parts[2] if parts[2] else ""
            eth_dst = parts[3] if parts[3] else ""
            ip_src = parts[4] if parts[4] else None
            ip_dst = parts[5] if parts[5] else None
            proto = parts[6] if len(parts) > 6 and parts[6] else "UNKNOWN"

            obs = PacketObservation(
                timestamp=ts,
                packet_size=flen,
                eth_src=eth_src,
                eth_dst=eth_dst,
                ip_src=ip_src,
                ip_dst=ip_dst,
                protocol=proto,
            )
            total_packets += 1
            res = detector.evaluate(obs)
            if res.status == DetectionStatus.SUSPICIOUS:
                false_positives += 1
                if len(fp_details) < 5:
                    fp_details.append({
                        "timestamp": ts,
                        "eth_src": eth_src,
                        "ip_src": ip_src,
                        "evidence": res.evidence,
                    })
        except (ValueError, IndexError):
            continue

    passed = (false_positives == 0)
    return {
        "scenario": "L1_Real_PCAP_Replay_Spoofing",
        "pcap_file": pcap_path.name,
        "total_packets": total_packets,
        "false_positive_count": false_positives,
        "fp_details": fp_details,
        "passed": passed,
    }

def main():
    gateway_mac = "36:6f:24:d2:34:3d"
    detector = SpoofingDetector(
        gateway_ip="192.168.137.1",
        gateway_mac=gateway_mac,
        ip_conflict_window_seconds=60.0,
        binding_expiry_seconds=300.0,
        conflict_alert_cooldown_seconds=60.0,
        confirmation_min_packets=2,
        local_subnet="192.168.137.0/24",
    )

    scenarios = []

    # =========================================================================
    # Group A: Rogue Gateway Impersonation
    # =========================================================================
    # A1: Rogue Gateway Impersonation (rogue MAC claims 192.168.137.1)
    pkts_a1 = [
        PacketObservation(
            timestamp=100.0,
            packet_size=60,
            eth_src="00:11:22:33:44:55",
            eth_dst="ca:34:ea:92:d3:9e",
            ip_src="192.168.137.1",
            ip_dst="192.168.137.201",
        )
    ]
    scenarios.append(run_sequence(
        "A1_Rogue_Gateway_Impersonation_Detected",
        detector,
        pkts_a1,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.HIGH,
        expected_verdict_substring="Gateway IP impersonation attempt",
        expected_evidence_keys={
            "claimed_ip": "192.168.137.1",
            "offending_mac": "00:11:22:33:44:55",
            "authorized_gateway_mac": gateway_mac,
        },
    ))

    # A2: Legitimate Gateway Traffic
    pkts_a2 = [
        PacketObservation(
            timestamp=200.0,
            packet_size=60,
            eth_src=gateway_mac,
            eth_dst="ca:34:ea:92:d3:9e",
            ip_src="192.168.137.1",
            ip_dst="192.168.137.201",
        )
    ]
    scenarios.append(run_sequence(
        "A2_Legitimate_Gateway_Traffic_Accepted",
        detector,
        pkts_a2,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Legitimate gateway traffic",
        expected_evidence_keys={"is_gateway": True, "claimed_ip": "192.168.137.1"},
    ))

    # A3: Gateway MAC Unconfigured / Unverified -> INSUFFICIENT_TELEMETRY
    det_unconf = SpoofingDetector(gateway_ip="192.168.137.1", gateway_mac=None)
    pkts_a3 = [
        PacketObservation(
            timestamp=300.0,
            packet_size=60,
            eth_src="00:11:22:33:44:55",
            eth_dst="ca:34:ea:92:d3:9e",
            ip_src="192.168.137.1",
            ip_dst="192.168.137.201",
        )
    ]
    scenarios.append(run_sequence(
        "A3_Unconfigured_Gateway_MAC_Insufficient_Telemetry",
        det_unconf,
        pkts_a3,
        expected_status=DetectionStatus.INSUFFICIENT_TELEMETRY,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Hotspot Gateway MAC address is unverified/unconfigured",
        expected_missing_fields=["gateway_mac"],
    ))

    # A4: Gateway MAC Normalization (uppercase hyphen format 36-6F-24-D2-34-3D)
    det_norm = SpoofingDetector(gateway_ip="192.168.137.1", gateway_mac="36-6F-24-D2-34-3D")
    pkts_a4 = [
        PacketObservation(
            timestamp=400.0,
            packet_size=60,
            eth_src="36:6f:24:d2:34:3d",
            eth_dst="ca:34:ea:92:d3:9e",
            ip_src="192.168.137.1",
            ip_dst="192.168.137.201",
        )
    ]
    scenarios.append(run_sequence(
        "A4_Gateway_MAC_Normalization_Hyphen_Uppercase",
        det_norm,
        pkts_a4,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Legitimate gateway traffic",
    ))

    # =========================================================================
    # Group B: Active Host IP Conflict
    # =========================================================================
    # B1: Active host IP conflict within 60s (elapsed = 10s <= 60s -> Severity HIGH, conf=0.85)
    pkts_b1 = [
        # Packet 1: Baseline established by MAC A
        PacketObservation(timestamp=500.0, packet_size=100, eth_src="ca:34:ea:92:d3:9e", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"),
        # Packet 2: Conflicting claim by MAC B at t=510.0 (elapsed = 10.0s <= 60.0s)
        PacketObservation(timestamp=510.0, packet_size=100, eth_src="00:0c:29:ab:cd:ef", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"),
    ]
    scenarios.append(run_sequence(
        "B1_Active_Host_IP_Conflict_Within_60s_HighSeverity",
        detector,
        pkts_b1,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.HIGH,
        expected_verdict_substring="Conflicting IP-to-MAC binding detected",
        expected_evidence_keys={
            "ip_address": "192.168.137.50",
            "current_mac": "00:0c:29:ab:cd:ef",
            "previous_mac": "ca:34:ea:92:d3:9e",
            "conflict_packet_count": 1,
        },
        step_check={
            0: {"status": DetectionStatus.NO_EVIDENCE, "verdict": "Consistent identity binding"},
            1: {"status": DetectionStatus.SUSPICIOUS, "severity": Severity.HIGH},
        },
    ))

    # B2: Conflict between 60s and 300s (elapsed = 120s -> Severity MEDIUM, conf=0.70)
    pkts_b2 = [
        # Packet 1: Baseline established by MAC A at t=600.0
        PacketObservation(timestamp=600.0, packet_size=100, eth_src="ca:34:ea:92:d3:9e", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"),
        # Packet 2: Conflicting claim by MAC B at t=720.0 (elapsed = 120.0s > 60s and <= 300s)
        PacketObservation(timestamp=720.0, packet_size=100, eth_src="00:0c:29:ab:cd:ef", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"),
    ]
    scenarios.append(run_sequence(
        "B2_Active_Host_IP_Conflict_120s_MediumSeverity",
        detector,
        pkts_b2,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.MEDIUM,
        expected_verdict_substring="Conflicting IP-to-MAC binding detected",
        expected_evidence_keys={
            "ip_address": "192.168.137.50",
            "current_mac": "00:0c:29:ab:cd:ef",
            "previous_mac": "ca:34:ea:92:d3:9e",
        },
    ))

    # =========================================================================
    # Group C: DHCP Lease Transition & Reassignment
    # =========================================================================
    # C1: Pending Lease Handover (baseline silent for 305s > 300s; candidate sends 1 packet -> Pending, NO_EVIDENCE)
    pkts_c1 = [
        PacketObservation(timestamp=800.0, packet_size=100, eth_src="ca:34:ea:92:d3:9e", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"),
        PacketObservation(timestamp=1105.0, packet_size=100, eth_src="e6:2e:db:73:1c:25", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"),
    ]
    scenarios.append(run_sequence(
        "C1_DHCP_Lease_Transition_Pending_1_Packet",
        detector,
        pkts_c1,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Pending IP-to-MAC lease transition",
        expected_evidence_keys={
            "ip_address": "192.168.137.50",
            "current_mac": "e6:2e:db:73:1c:25",
            "previous_mac": "ca:34:ea:92:d3:9e",
            "candidate_packet_count": 1,
            "required_packets": 2,
        },
    ))

    # C2: Confirmed Lease Handover (candidate sends 2nd packet -> Handover Confirmed, NO_EVIDENCE, promoted to baseline)
    pkts_c2 = [
        PacketObservation(timestamp=800.0, packet_size=100, eth_src="ca:34:ea:92:d3:9e", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"),
        PacketObservation(timestamp=1105.0, packet_size=100, eth_src="e6:2e:db:73:1c:25", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"),
        PacketObservation(timestamp=1106.0, packet_size=100, eth_src="e6:2e:db:73:1c:25", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"),
    ]
    scenarios.append(run_sequence(
        "C2_DHCP_Lease_Transition_Confirmed_Handover",
        detector,
        pkts_c2,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Legitimate IP-to-MAC binding handover confirmed",
        expected_evidence_keys={
            "ip_address": "192.168.137.50",
            "current_mac": "e6:2e:db:73:1c:25",
            "previous_mac": "ca:34:ea:92:d3:9e",
            "confirmed_packet_count": 2,
        },
    ))

    # C3: Consistent Identity Post-Handover (promoted MAC continues communicating)
    pkts_c3 = pkts_c2 + [
        PacketObservation(timestamp=1107.0, packet_size=100, eth_src="e6:2e:db:73:1c:25", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"),
    ]
    scenarios.append(run_sequence(
        "C3_Consistent_Identity_Post_Handover",
        detector,
        pkts_c3,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Consistent identity binding",
        expected_evidence_keys={"ip": "192.168.137.50", "mac": "e6:2e:db:73:1c:25"},
    ))

    # =========================================================================
    # Group D: Randomized MAC Handling
    # =========================================================================
    # D1: Locally Administered Randomized MAC claims fresh IP (da:34:ea:92:d3:9f -> bit 1 of 0xda is 1)
    pkts_d1 = [
        PacketObservation(timestamp=1200.0, packet_size=60, eth_src="da:34:ea:92:d3:9f", eth_dst=gateway_mac, ip_src="192.168.137.77", ip_dst="192.168.137.1"),
    ]
    scenarios.append(run_sequence(
        "D1_Randomized_MAC_Private_Addressing_NoAlert",
        detector,
        pkts_d1,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Consistent identity binding",
        expected_evidence_keys={"is_randomized_mac": True, "ip": "192.168.137.77"},
    ))

    # D2: Multiple Randomized MACs on Distinct IPs (all distinct, zero conflict -> all NO_EVIDENCE)
    random_macs = ["da:11:22:33:44:01", "e6:11:22:33:44:02", "fa:11:22:33:44:03", "ee:11:22:33:44:04"]
    pkts_d2 = [
        PacketObservation(timestamp=1300.0 + i, packet_size=60, eth_src=m, eth_dst=gateway_mac, ip_src=f"192.168.137.{100 + i}", ip_dst="192.168.137.1")
        for i, m in enumerate(random_macs)
    ]
    scenarios.append(run_sequence(
        "D2_Multiple_Randomized_MACs_Distinct_IPs",
        detector,
        pkts_d2,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Consistent identity binding",
    ))

    # D3: Device Registry with Unregistered MAC (severity INFO, not attack)
    det_reg = SpoofingDetector(gateway_ip="192.168.137.1", gateway_mac=gateway_mac)
    det_reg.set_registered_devices({"00:11:22:33:44:01", "00:11:22:33:44:02"})
    pkts_d3 = [
        PacketObservation(timestamp=1400.0, packet_size=60, eth_src="ca:34:ea:92:d3:9e", eth_dst=gateway_mac, ip_src="192.168.137.88", ip_dst="192.168.137.1"),
    ]
    scenarios.append(run_sequence(
        "D3_Unregistered_MAC_Produces_Info_NoAttack",
        det_reg,
        pkts_d3,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.INFO,
        expected_verdict_substring="Consistent identity binding",
        expected_evidence_keys={"is_registered": False},
    ))

    # =========================================================================
    # Group E: Unassigned DHCP Source IP (0.0.0.0)
    # =========================================================================
    # E1: DHCP Discover with ip_src = "0.0.0.0" -> NO_EVIDENCE, excluded from binding
    pkts_e1 = [
        PacketObservation(timestamp=1500.0, packet_size=300, eth_src="ca:34:ea:92:d3:9e", eth_dst="ff:ff:ff:ff:ff:ff", ip_src="0.0.0.0", ip_dst="255.255.255.255"),
    ]
    scenarios.append(run_sequence(
        "E1_DHCP_Discover_0_0_0_0_Excluded",
        detector,
        pkts_e1,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Unassigned or non-unicast source address",
        expected_evidence_keys={"ip": "0.0.0.0"},
    ))

    # E2: Verify 0.0.0.0 establishes no binding
    detector.reset()
    detector.evaluate(pkts_e1[0])
    pass_e2 = ("0.0.0.0" not in detector._ip_to_mac_binding)
    scenarios.append({
        "scenario": "E2_Verify_No_Binding_For_0_0_0_0",
        "packet_count": 1,
        "final_status": "NO_EVIDENCE",
        "final_severity": "NONE",
        "final_confidence": 0.0,
        "verdict": "Verified 0.0.0.0 absent from binding table",
        "evidence": {"binding_table_keys": list(detector._ip_to_mac_binding.keys())},
        "missing_fields": [],
        "expected_status": "NO_EVIDENCE",
        "expected_severity": "NONE",
        "expected_verdict": "Verified 0.0.0.0 absent from binding table",
        "step_errors": [],
        "passed": pass_e2,
    })

    # =========================================================================
    # Group F: Broadcast and Multicast Source IPs
    # =========================================================================
    # F1: Limited Broadcast 255.255.255.255
    pkts_f1 = [PacketObservation(timestamp=1600.0, packet_size=60, eth_src="ca:34:ea:92:d3:9e", eth_dst="ff:ff:ff:ff:ff:ff", ip_src="255.255.255.255", ip_dst="255.255.255.255")]
    scenarios.append(run_sequence("F1_Broadcast_255_255_255_255_Excluded", detector, pkts_f1, expected_status=DetectionStatus.NO_EVIDENCE, expected_verdict_substring="Unassigned or non-unicast source address"))

    # F2: Multicast 224.0.0.251
    pkts_f2 = [PacketObservation(timestamp=1601.0, packet_size=60, eth_src="ca:34:ea:92:d3:9e", eth_dst="01:00:5e:00:00:fb", ip_src="224.0.0.251", ip_dst="224.0.0.251")]
    scenarios.append(run_sequence("F2_Multicast_224_0_0_251_Excluded", detector, pkts_f2, expected_status=DetectionStatus.NO_EVIDENCE, expected_verdict_substring="Unassigned or non-unicast source address"))

    # F3: Network Address 192.168.137.0
    pkts_f3 = [PacketObservation(timestamp=1602.0, packet_size=60, eth_src="ca:34:ea:92:d3:9e", eth_dst="ff:ff:ff:ff:ff:ff", ip_src="192.168.137.0", ip_dst="192.168.137.1")]
    scenarios.append(run_sequence("F3_Network_Address_192_168_137_0_Excluded", detector, pkts_f3, expected_status=DetectionStatus.NO_EVIDENCE, expected_verdict_substring="Unassigned or non-unicast source address"))

    # F4: Subnet Broadcast 192.168.137.255
    pkts_f4 = [PacketObservation(timestamp=1603.0, packet_size=60, eth_src="ca:34:ea:92:d3:9e", eth_dst="ff:ff:ff:ff:ff:ff", ip_src="192.168.137.255", ip_dst="192.168.137.1")]
    scenarios.append(run_sequence("F4_Subnet_Broadcast_192_168_137_255_Excluded", detector, pkts_f4, expected_status=DetectionStatus.NO_EVIDENCE, expected_verdict_substring="Unassigned or non-unicast source address"))

    # =========================================================================
    # Group G: Transient Conflict Protection & Alert Cooldown
    # =========================================================================
    # G1-G4: Transient protection, baseline retention, cooldown suppression, cooldown expiration
    pkts_g = [
        # 0: Baseline established at t=1700.0 by MAC A
        PacketObservation(timestamp=1700.0, packet_size=100, eth_src="ca:34:ea:92:d3:9e", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"),
        # 1: Single conflicting packet from candidate MAC B at t=1701.0 -> Triggers alert (SUSPICIOUS)
        PacketObservation(timestamp=1701.0, packet_size=100, eth_src="00:0c:29:ab:cd:ef", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"),
        # 2: Baseline MAC A communicates again at t=1702.0 -> Baseline was NOT overwritten! (NO_EVIDENCE)
        PacketObservation(timestamp=1702.0, packet_size=100, eth_src="ca:34:ea:92:d3:9e", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"),
        # 3: Candidate MAC B sends 2nd packet at t=1710.0 (elapsed since last alert = 9s < 60s cooldown) -> Suppressed (NO_EVIDENCE)
        PacketObservation(timestamp=1710.0, packet_size=100, eth_src="00:0c:29:ab:cd:ef", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"),
        # 4: Candidate MAC B sends 3rd packet at t=1765.0 (elapsed since last alert = 64s >= 60s cooldown) -> New alert emitted (SUSPICIOUS)
        PacketObservation(timestamp=1765.0, packet_size=100, eth_src="00:0c:29:ab:cd:ef", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"),
    ]
    scenarios.append(run_sequence(
        "G1_Transient_Conflict_Protection_And_Cooldown_Lifecycle",
        detector,
        pkts_g,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.MEDIUM,
        expected_verdict_substring="Conflicting IP-to-MAC binding detected",
        step_check={
            0: {"status": DetectionStatus.NO_EVIDENCE, "verdict": "Consistent identity binding"},
            1: {"status": DetectionStatus.SUSPICIOUS, "severity": Severity.HIGH, "verdict": "Conflicting IP-to-MAC binding detected"},
            2: {"status": DetectionStatus.NO_EVIDENCE, "verdict": "Consistent identity binding"},
            3: {"status": DetectionStatus.NO_EVIDENCE, "verdict": "Ongoing conflicting IP-to-MAC observation (tracked)"},
            4: {"status": DetectionStatus.SUSPICIOUS, "severity": Severity.MEDIUM, "verdict": "Conflicting IP-to-MAC binding detected"},
        },
    ))

    # =========================================================================
    # Group H: Threshold & Timing Boundaries
    # =========================================================================
    # H1: Conflict Window Boundary: exactly 60.0s elapsed -> Severity HIGH
    pkts_h1 = [
        PacketObservation(timestamp=1800.0, packet_size=100, eth_src="ca:34:ea:92:d3:9e", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"),
        PacketObservation(timestamp=1860.0, packet_size=100, eth_src="00:0c:29:ab:cd:ef", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"),
    ]
    scenarios.append(run_sequence(
        "H1_Boundary_ConflictWindow_Exact_60_0s_HighSeverity",
        detector,
        pkts_h1,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.HIGH,
        expected_verdict_substring="Conflicting IP-to-MAC binding detected",
    ))

    # H2: Conflict Window Boundary: 60.1s elapsed (> 60.0s) -> Severity MEDIUM
    pkts_h2 = [
        PacketObservation(timestamp=1900.0, packet_size=100, eth_src="ca:34:ea:92:d3:9e", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"),
        PacketObservation(timestamp=1960.1, packet_size=100, eth_src="00:0c:29:ab:cd:ef", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"),
    ]
    scenarios.append(run_sequence(
        "H2_Boundary_ConflictWindow_60_1s_MediumSeverity",
        detector,
        pkts_h2,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.MEDIUM,
        expected_verdict_substring="Conflicting IP-to-MAC binding detected",
    ))

    # H3: Binding Expiry Boundary: exactly 300.0s elapsed (<= 300.0s -> Still protected baseline, SUSPICIOUS)
    pkts_h3 = [
        PacketObservation(timestamp=2000.0, packet_size=100, eth_src="ca:34:ea:92:d3:9e", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"),
        PacketObservation(timestamp=2300.0, packet_size=100, eth_src="00:0c:29:ab:cd:ef", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"),
    ]
    scenarios.append(run_sequence(
        "H3_Boundary_BindingExpiry_Exact_300_0s_Suspicious",
        detector,
        pkts_h3,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.MEDIUM,
        expected_verdict_substring="Conflicting IP-to-MAC binding detected",
    ))

    # H4: Binding Expiry Boundary: 300.1s elapsed (> 300.0s -> Baseline aged out, NO_EVIDENCE pending transition)
    pkts_h4 = [
        PacketObservation(timestamp=2400.0, packet_size=100, eth_src="ca:34:ea:92:d3:9e", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"),
        PacketObservation(timestamp=2700.1, packet_size=100, eth_src="00:0c:29:ab:cd:ef", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"),
    ]
    scenarios.append(run_sequence(
        "H4_Boundary_BindingExpiry_300_1s_TransitionPending",
        detector,
        pkts_h4,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Pending IP-to-MAC lease transition",
    ))

    # H5: Candidate Stale Reset: Candidate observed at t=2800.0, then silent for 305s (> 300s). Reappears at t=3105.0.
    # Candidate packet count resets to 1, does NOT combine with previous stale packet.
    pkts_h5 = [
        PacketObservation(timestamp=2800.0, packet_size=100, eth_src="ca:34:ea:92:d3:9e", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"),
        # Candidate MAC B observed once at t=2801.0
        PacketObservation(timestamp=2801.0, packet_size=100, eth_src="00:0c:29:ab:cd:ef", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"),
        # Silence of 305s from both baseline and candidate
        # Candidate MAC B sends another packet at t=3106.0 (> 300s since last seen). Candidate count resets to 1 (not 2).
        PacketObservation(timestamp=3106.0, packet_size=100, eth_src="00:0c:29:ab:cd:ef", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"),
    ]
    scenarios.append(run_sequence(
        "H5_Candidate_Stale_Tracker_Reset_After_300s_Silence",
        detector,
        pkts_h5,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Pending IP-to-MAC lease transition",
        expected_evidence_keys={"candidate_packet_count": 1},
    ))

    # =========================================================================
    # Group I: Multi-Identity Isolation
    # =========================================================================
    # I1: Two independent IP conflicts on 192.168.137.50 and 192.168.137.60
    detector.reset()
    # Baseline for IP1 and IP2
    detector.evaluate(PacketObservation(timestamp=3200.0, packet_size=100, eth_src="11:11:11:11:11:11", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"))
    detector.evaluate(PacketObservation(timestamp=3200.1, packet_size=100, eth_src="22:22:22:22:22:22", eth_dst=gateway_mac, ip_src="192.168.137.60", ip_dst="192.168.137.1"))
    # Rogue claim on IP1
    res_i1_a = detector.evaluate(PacketObservation(timestamp=3201.0, packet_size=100, eth_src="aa:aa:aa:aa:aa:aa", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"))
    # Rogue claim on IP2
    res_i1_b = detector.evaluate(PacketObservation(timestamp=3201.1, packet_size=100, eth_src="bb:bb:bb:bb:bb:bb", eth_dst=gateway_mac, ip_src="192.168.137.60", ip_dst="192.168.137.1"))

    pass_i1 = (
        res_i1_a.status == DetectionStatus.SUSPICIOUS
        and res_i1_a.evidence["ip_address"] == "192.168.137.50"
        and res_i1_a.evidence["current_mac"] == "aa:aa:aa:aa:aa:aa"
        and res_i1_a.evidence["previous_mac"] == "11:11:11:11:11:11"
        and res_i1_b.status == DetectionStatus.SUSPICIOUS
        and res_i1_b.evidence["ip_address"] == "192.168.137.60"
        and res_i1_b.evidence["current_mac"] == "bb:bb:bb:bb:bb:bb"
        and res_i1_b.evidence["previous_mac"] == "22:22:22:22:22:22"
    )
    scenarios.append({
        "scenario": "I1_Two_Independent_IP_Conflicts_Isolated",
        "packet_count": 4,
        "final_status": res_i1_b.status.value,
        "final_severity": res_i1_b.severity.value,
        "final_confidence": round(res_i1_b.confidence, 4),
        "verdict": res_i1_b.evidence.get("verdict", ""),
        "evidence": {"ip1_conflict": res_i1_a.evidence, "ip2_conflict": res_i1_b.evidence},
        "missing_fields": [],
        "expected_status": "SUSPICIOUS",
        "expected_severity": "HIGH",
        "expected_verdict": "Conflicting IP-to-MAC binding detected",
        "step_errors": [],
        "passed": pass_i1,
    })

    # I2: Third rogue MAC attempting to claim already conflicted IP
    res_i2 = detector.evaluate(PacketObservation(timestamp=3202.0, packet_size=100, eth_src="cc:cc:cc:cc:cc:cc", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1"))
    pass_i2 = (
        res_i2.status == DetectionStatus.SUSPICIOUS
        and res_i2.evidence["ip_address"] == "192.168.137.50"
        and res_i2.evidence["current_mac"] == "cc:cc:cc:cc:cc:cc"
        and res_i2.evidence["previous_mac"] == "11:11:11:11:11:11"
        and "aa:aa:aa:aa:aa:aa" in detector._conflict_candidates["192.168.137.50"]
        and "cc:cc:cc:cc:cc:cc" in detector._conflict_candidates["192.168.137.50"]
    )
    scenarios.append({
        "scenario": "I2_Third_Rogue_MAC_Independent_Candidate_Tracking",
        "packet_count": 5,
        "final_status": res_i2.status.value,
        "final_severity": res_i2.severity.value,
        "final_confidence": round(res_i2.confidence, 4),
        "verdict": res_i2.evidence.get("verdict", ""),
        "evidence": res_i2.evidence,
        "missing_fields": [],
        "expected_status": "SUSPICIOUS",
        "expected_severity": "HIGH",
        "expected_verdict": "Conflicting IP-to-MAC binding detected",
        "step_errors": [],
        "passed": pass_i2,
    })

    # =========================================================================
    # Group J: Missing Telemetry & Robustness
    # =========================================================================
    # J1: Missing ip_src
    pkts_j1 = [PacketObservation(timestamp=3300.0, packet_size=60, eth_src="ca:34:ea:92:d3:9e", eth_dst=gateway_mac, ip_src=None, ip_dst="192.168.137.1")]
    scenarios.append(run_sequence("J1_Missing_Source_IP_Insufficient_Telemetry", detector, pkts_j1, expected_status=DetectionStatus.INSUFFICIENT_TELEMETRY, expected_missing_fields=["ip_src"]))

    # J2: Missing eth_src
    pkts_j2 = [PacketObservation(timestamp=3301.0, packet_size=60, eth_src="", eth_dst=gateway_mac, ip_src="192.168.137.50", ip_dst="192.168.137.1")]
    scenarios.append(run_sequence("J2_Missing_Ethernet_Source_MAC_Insufficient_Telemetry", detector, pkts_j2, expected_status=DetectionStatus.INSUFFICIENT_TELEMETRY, expected_missing_fields=["eth_src"]))

    # J3: Missing both eth_src and ip_src
    pkts_j3 = [PacketObservation(timestamp=3302.0, packet_size=60, eth_src="", eth_dst=gateway_mac, ip_src=None, ip_dst="192.168.137.1")]
    scenarios.append(run_sequence("J3_Missing_Both_IP_And_MAC_Insufficient_Telemetry", detector, pkts_j3, expected_status=DetectionStatus.INSUFFICIENT_TELEMETRY, expected_missing_fields=["eth_src", "ip_src"]))

    # =========================================================================
    # Group K: Cooldown Deduplication & DB Persistence
    # =========================================================================
    scratch_db = PROJECT_ROOT / "scratch" / "test_stage54_cooldown.db"
    scratch_db.parent.mkdir(parents=True, exist_ok=True)
    if scratch_db.exists():
        scratch_db.unlink()
    init_live_database(scratch_db)

    conn = get_live_db_connection(scratch_db)
    cur_run = conn.execute("INSERT INTO collector_status (interface_index, status) VALUES (1, 'RUNNING')")
    run_id = cur_run.lastrowid
    conn.commit()

    collector = LiveCollector(
        interface_index=1,
        db_path=scratch_db,
        no_sensors=True,
        gateway_mac=gateway_mac,
        spoofing_cooldown_seconds=0.05,
    )
    collector._run_id = run_id
    collector._attack_table_present = True

    cur_w = conn.execute(
        "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
        "VALUES (?, 'ca:34:ea:92:d3:9e', 'Node_3', 3400.0, 3401.0, 5, 5.0)",
        (run_id,),
    )
    win_id = cur_w.lastrowid
    conn.commit()

    spoof_res = AttackDetectionResult(
        category=AttackCategory.SPOOFING,
        status=DetectionStatus.SUSPICIOUS,
        severity=Severity.HIGH,
        evidence={
            "verdict": "Conflicting IP-to-MAC binding detected",
            "ip_address": "192.168.137.50",
            "current_mac": "00:0c:29:ab:cd:ef",
            "previous_mac": "ca:34:ea:92:d3:9e",
        },
        missing_fields=[],
        confidence=0.85,
        timestamp=3400.0,
        recommended_action="Check DHCP lease table.",
    )
    scored_dummy = {"client_mac": "ca:34:ea:92:d3:9e", "ip_dst": "142.250.190.46"}

    # Emission 1 -> Persisted
    ins_k1 = collector._persist_attack_results(conn, win_id, [], [spoof_res], "ca:34:ea:92:d3:9e", scored_dummy)

    # Emission 2 immediately (< 0.05s cooldown) -> Suppressed
    ins_k2 = collector._persist_attack_results(conn, win_id, [], [spoof_res], "ca:34:ea:92:d3:9e", scored_dummy)

    # Sleep past 0.05s cooldown
    time.sleep(0.08)

    # Emission 3 (> 0.05s cooldown) -> Persisted as new row
    ins_k3 = collector._persist_attack_results(conn, win_id, [], [spoof_res], "ca:34:ea:92:d3:9e", scored_dummy)

    # Different source MAC on same IP -> Independent cooldown, persisted immediately
    spoof_res_diff_mac = AttackDetectionResult(
        category=AttackCategory.SPOOFING,
        status=DetectionStatus.SUSPICIOUS,
        severity=Severity.HIGH,
        evidence={
            "verdict": "Conflicting IP-to-MAC binding detected",
            "ip_address": "192.168.137.50",
            "current_mac": "00:0c:29:99:88:77",  # Different MAC!
            "previous_mac": "ca:34:ea:92:d3:9e",
        },
        missing_fields=[],
        confidence=0.85,
        timestamp=3400.1,
        recommended_action="Check DHCP lease table.",
    )
    ins_k4 = collector._persist_attack_results(conn, win_id, [], [spoof_res_diff_mac], "ca:34:ea:92:d3:9e", scored_dummy)

    total_k_rows = conn.execute("SELECT count(*) FROM live_attack_events WHERE run_id = ?", (run_id,)).fetchone()[0]
    conn.close()
    if scratch_db.exists():
        scratch_db.unlink()

    pass_k = (ins_k1 == 1 and ins_k2 == 0 and ins_k3 == 1 and ins_k4 == 1 and total_k_rows == 3)
    scenarios.append({
        "scenario": "K1_LiveCollector_Spoofing_Cooldown_And_Attribution",
        "packet_count": 4,
        "final_status": "SUSPICIOUS",
        "final_severity": "HIGH",
        "final_confidence": 0.85,
        "verdict": "Verified persistence, cooldown suppression, cooldown expiry, and MAC independence",
        "evidence": {"ins_k1": ins_k1, "ins_k2": ins_k2, "ins_k3": ins_k3, "ins_k4": ins_k4, "total_rows": total_k_rows},
        "missing_fields": [],
        "expected_status": "SUSPICIOUS",
        "expected_severity": "HIGH",
        "expected_verdict": "Verified persistence",
        "step_errors": [],
        "passed": pass_k,
    })

    # =========================================================================
    # Group L: Offline Real PCAP Evaluation
    # =========================================================================
    pcap_file = PROJECT_ROOT / "data" / "hotspot_two_phone_test.pcapng"
    res_l1 = evaluate_real_pcap_spoofing(pcap_file, gateway_mac)
    scenarios.append(res_l1)

    # Summary
    total_scenarios = len(scenarios)
    passed_scenarios = sum(1 for s in scenarios if s.get("passed", False))
    failed_scenarios = total_scenarios - passed_scenarios

    output_data = {
        "metadata": {
            "test_stage": "Stage 5.4",
            "component": "SpoofingDetector",
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_scenarios": total_scenarios,
            "passed_scenarios": passed_scenarios,
            "failed_scenarios": failed_scenarios,
            "pass_rate_pct": round(passed_scenarios / total_scenarios * 100, 2),
        },
        "scenarios": scenarios,
    }

    out_json = PROJECT_ROOT / "scratch" / "stage54_spoofing_validation_results.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)

    print(f"Validation finished: {passed_scenarios}/{total_scenarios} scenarios PASSED ({output_data['metadata']['pass_rate_pct']}%)")
    for s in scenarios:
        status_flag = "PASS" if s.get("passed") else "FAIL"
        print(f"[{status_flag}] {s['scenario']}")

if __name__ == "__main__":
    main()
