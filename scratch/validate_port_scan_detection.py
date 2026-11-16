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
    PortScanDetector,
    PacketObservation,
    AttackDetectionResult,
    AttackCategory,
    DetectionStatus,
    Severity,
    _is_tcp_syn_no_ack,
    _is_tcp_established_or_ack,
)
from src.init_live_database import init_live_database, get_live_db_connection
from src.live_collector import LiveCollector

def run_scenario(
    name: str,
    detector: PortScanDetector,
    packet_batches: List[List[PacketObservation]],
    expected_status: Optional[DetectionStatus] = None,
    expected_severity: Optional[Severity] = None,
    expected_verdict_substring: Optional[str] = None,
    expected_is_vertical: Optional[bool] = None,
    expected_is_horizontal: Optional[bool] = None,
    expected_missing_fields: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Feeds a sequence of packet batches to the PortScanDetector.
    Detector is reset at the start of each scenario.
    """
    detector.reset()
    results = []

    for batch in packet_batches:
        res = detector.evaluate(batch)
        results.append(res)

    final_res = results[-1]

    status_ok = (expected_status is None) or (final_res.status == expected_status)
    severity_ok = (expected_severity is None) or (final_res.severity == expected_severity)
    
    verdict_str = final_res.evidence.get("verdict", "")
    if not verdict_str and "reason" in final_res.evidence:
        verdict_str = final_res.evidence["reason"]
    verdict_ok = (expected_verdict_substring is None) or (expected_verdict_substring in verdict_str)

    details = final_res.evidence.get("details", [])
    primary = details[0] if details else {}

    vertical_ok = (expected_is_vertical is None) or (primary.get("is_vertical_scan") == expected_is_vertical)
    horizontal_ok = (expected_is_horizontal is None) or (primary.get("is_horizontal_sweep") == expected_is_horizontal)

    missing_ok = True
    if expected_missing_fields is not None:
        missing_ok = set(final_res.missing_fields) == set(expected_missing_fields)

    passed = status_ok and severity_ok and verdict_ok and vertical_ok and horizontal_ok and missing_ok

    # Calculate total packets across all batches
    total_pkts = sum(len(b) for b in packet_batches)

    return {
        "scenario": name,
        "batch_count": len(packet_batches),
        "total_packets": total_pkts,
        "final_status": final_res.status.value,
        "final_severity": final_res.severity.value,
        "final_confidence": round(final_res.confidence, 4),
        "verdict": verdict_str,
        "details_count": len(details),
        "is_vertical_scan": primary.get("is_vertical_scan"),
        "is_horizontal_sweep": primary.get("is_horizontal_sweep"),
        "distinct_ports_count": primary.get("distinct_ports_count"),
        "distinct_hosts_count": primary.get("distinct_hosts_count"),
        "missing_fields": final_res.missing_fields,
        "expected_status": expected_status.value if expected_status else None,
        "expected_severity": expected_severity.value if expected_severity else None,
        "expected_verdict": expected_verdict_substring,
        "expected_is_vertical": expected_is_vertical,
        "expected_is_horizontal": expected_is_horizontal,
        "passed": passed,
    }

def evaluate_real_pcap(detector: PortScanDetector, pcap_path: Path) -> Dict[str, Any]:
    """
    Parses a real PCAP file using TShark fields and evaluates it in 1-second chunks with PortScanDetector.
    """
    detector.reset()
    tshark_bin = Path(r"C:\Program Files\Wireshark\tshark.exe")
    if not tshark_bin.exists():
        return {"scenario": "J1_Real_PCAP_Replay", "passed": False, "error": "TShark not found"}

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
        "-e", "tcp.srcport",
        "-e", "udp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-e", "tcp.flags",
    ]

    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    lines = proc.stdout.strip().splitlines()

    observations: List[PacketObservation] = []
    for line in lines:
        parts = line.split("\t")
        if len(parts) < 12:
            continue
        try:
            ts = float(parts[0]) if parts[0] else 0.0
            flen = int(parts[1]) if parts[1] else 0
            eth_src = parts[2] if parts[2] else ""
            eth_dst = parts[3] if parts[3] else ""
            ip_src = parts[4] if parts[4] else None
            ip_dst = parts[5] if parts[5] else None
            proto = parts[6] if parts[6] else "UNKNOWN"
            
            src_port = None
            if parts[7]:
                src_port = int(parts[7].split(",")[0])
            elif parts[8]:
                src_port = int(parts[8].split(",")[0])

            dst_port = None
            if parts[9]:
                dst_port = int(parts[9].split(",")[0])
            elif parts[10]:
                dst_port = int(parts[10].split(",")[0])

            tcp_flags = parts[11] if parts[11] else None

            observations.append(PacketObservation(
                timestamp=ts,
                packet_size=flen,
                eth_src=eth_src,
                eth_dst=eth_dst,
                ip_src=ip_src,
                ip_dst=ip_dst,
                protocol=proto,
                src_port=src_port,
                dst_port=dst_port,
                tcp_flags=tcp_flags,
            ))
        except (ValueError, IndexError):
            continue

    if not observations:
        return {"scenario": "J1_Real_PCAP_Replay", "passed": False, "error": "No observations parsed"}

    # Group into 1-second time windows
    t_min = min(o.timestamp for o in observations)
    t_max = max(o.timestamp for o in observations)

    windows: Dict[int, List[PacketObservation]] = {}
    for o in observations:
        w_idx = int(math.floor(o.timestamp - t_min))
        if w_idx not in windows:
            windows[w_idx] = []
        windows[w_idx].append(o)

    window_results = []
    false_positives = 0
    for w_idx in sorted(windows.keys()):
        batch = windows[w_idx]
        res = detector.evaluate(batch)
        is_alert = (res.status == DetectionStatus.SUSPICIOUS)
        if is_alert:
            false_positives += 1
        window_results.append({
            "window_index": w_idx,
            "packets": len(batch),
            "status": res.status.value,
            "severity": res.severity.value,
            "verdict": res.evidence.get("verdict", ""),
        })

    passed = (false_positives == 0)
    return {
        "scenario": "J1_Real_PCAP_Replay_Hotspot",
        "pcap_file": pcap_path.name,
        "total_packets": len(observations),
        "duration_seconds": round(t_max - t_min, 2),
        "total_windows": len(windows),
        "false_positive_windows": false_positives,
        "passed": passed,
        "final_status": window_results[-1]["status"] if window_results else "NONE",
        "final_verdict": window_results[-1]["verdict"] if window_results else "",
    }

def main():
    detector = PortScanDetector(
        vertical_port_threshold=8,
        horizontal_host_threshold=5,
        window_duration_seconds=5.0,
        local_subnet="192.168.137.0/24",
    )

    scenarios = []

    # =========================================================================
    # Group A: Vertical TCP SYN Scan
    # =========================================================================
    # A1: Exactly 8 distinct non-infrastructure ports on 1 local target
    ports_a1 = [80, 81, 82, 83, 84, 85, 86, 87]
    b_a1 = [[
        PacketObservation(
            timestamp=100.0 + i * 0.1,
            packet_size=60,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst="192.168.137.1",
            protocol="TCP",
            src_port=50000 + i,
            dst_port=port,
            tcp_flags="0x0002",
        )
        for i, port in enumerate(ports_a1)
    ]]
    scenarios.append(run_scenario(
        "A1_Vertical_TCP_SYN_Scan_8_Ports",
        detector,
        b_a1,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.MEDIUM,
        expected_verdict_substring="Reconnaissance / scanning pattern observed",
        expected_is_vertical=True,
        expected_is_horizontal=False,
    ))

    # A2: 15 distinct non-infrastructure ports on 1 local host (high confidence)
    ports_a2 = [21, 22, 23, 25, 80, 81, 88, 110, 143, 443, 445, 8080, 8443, 9000, 9090]
    b_a2 = [[
        PacketObservation(
            timestamp=200.0 + i * 0.05,
            packet_size=60,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst="192.168.137.50",
            protocol="TCP",
            src_port=40000 + i,
            dst_port=port,
            tcp_flags="SYN",
        )
        for i, port in enumerate(ports_a2)
    ]]
    scenarios.append(run_scenario(
        "A2_Vertical_TCP_SYN_Scan_15_Ports_HighConfidence",
        detector,
        b_a2,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.MEDIUM,
        expected_verdict_substring="Reconnaissance / scanning pattern observed",
        expected_is_vertical=True,
        expected_is_horizontal=False,
    ))

    # A3: 10 distinct ports probed on public WAN host (Scope isolation -> NO_EVIDENCE)
    ports_a3 = [80, 81, 82, 83, 84, 85, 86, 87, 88, 89]
    b_a3 = [[
        PacketObservation(
            timestamp=300.0 + i * 0.1,
            packet_size=60,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst="93.184.216.34",  # WAN IP
            protocol="TCP",
            src_port=50000 + i,
            dst_port=port,
            tcp_flags="0x0002",
        )
        for i, port in enumerate(ports_a3)
    ]]
    scenarios.append(run_scenario(
        "A3_Vertical_WAN_Scan_Scope_Isolation",
        detector,
        b_a3,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Normal transport diversity",
    ))

    # =========================================================================
    # Group B: Horizontal TCP SYN Sweep
    # =========================================================================
    # B1: Exactly 5 distinct local hosts on port 80
    hosts_b1 = ["192.168.137.2", "192.168.137.3", "192.168.137.4", "192.168.137.5", "192.168.137.6"]
    b_b1 = [[
        PacketObservation(
            timestamp=400.0 + i * 0.1,
            packet_size=60,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst=host,
            protocol="TCP",
            src_port=51000 + i,
            dst_port=80,
            tcp_flags="0x0002",
        )
        for i, host in enumerate(hosts_b1)
    ]]
    scenarios.append(run_scenario(
        "B1_Horizontal_TCP_SYN_Sweep_5_Hosts",
        detector,
        b_b1,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.MEDIUM,
        expected_verdict_substring="Reconnaissance / scanning pattern observed",
        expected_is_vertical=False,
        expected_is_horizontal=True,
    ))

    # B2: 10 distinct local hosts on port 22 (SSH sweep)
    hosts_b2 = [f"192.168.137.{10 + i}" for i in range(10)]
    b_b2 = [[
        PacketObservation(
            timestamp=500.0 + i * 0.1,
            packet_size=60,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst=host,
            protocol="TCP",
            src_port=52000 + i,
            dst_port=22,
            tcp_flags="0x0002",
        )
        for i, host in enumerate(hosts_b2)
    ]]
    scenarios.append(run_scenario(
        "B2_Horizontal_TCP_SYN_Sweep_10_Hosts_SSH",
        detector,
        b_b2,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.MEDIUM,
        expected_verdict_substring="Reconnaissance / scanning pattern observed",
        expected_is_vertical=False,
        expected_is_horizontal=True,
    ))

    # B3: 8 distinct WAN hosts on port 443 (Outbound browsing across WAN -> NO_EVIDENCE)
    hosts_b3 = [
        "8.8.8.8", "1.1.1.1", "142.250.190.46", "104.20.23.154",
        "150.241.246.62", "204.79.197.200", "13.107.42.14", "172.217.16.206"
    ]
    b_b3 = [[
        PacketObservation(
            timestamp=600.0 + i * 0.1,
            packet_size=60,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst=host,
            protocol="TCP",
            src_port=53000 + i,
            dst_port=443,
            tcp_flags="0x0002",
        )
        for i, host in enumerate(hosts_b3)
    ]]
    scenarios.append(run_scenario(
        "B3_Horizontal_WAN_Sweep_Scope_Isolation",
        detector,
        b_b3,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Normal transport diversity",
    ))

    # =========================================================================
    # Group C: UDP Scanning
    # =========================================================================
    # C1: Vertical UDP scan (8 distinct non-infrastructure UDP ports)
    ports_c1 = [500, 5060, 69, 161, 162, 1194, 4500, 5000]
    b_c1 = [[
        PacketObservation(
            timestamp=700.0 + i * 0.1,
            packet_size=80,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst="192.168.137.1",
            protocol="UDP",
            src_port=40000 + i,
            dst_port=port,
            tcp_flags=None,
        )
        for i, port in enumerate(ports_c1)
    ]]
    scenarios.append(run_scenario(
        "C1_Vertical_UDP_Scan_8_Ports",
        detector,
        b_c1,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.MEDIUM,
        expected_verdict_substring="Reconnaissance / scanning pattern observed",
        expected_is_vertical=True,
        expected_is_horizontal=False,
    ))

    # C2: Horizontal UDP sweep (SNMP port 161 across 5 hosts)
    hosts_c2 = ["192.168.137.2", "192.168.137.3", "192.168.137.4", "192.168.137.5", "192.168.137.6"]
    b_c2 = [[
        PacketObservation(
            timestamp=800.0 + i * 0.1,
            packet_size=80,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst=host,
            protocol="UDP",
            src_port=45000,
            dst_port=161,
            tcp_flags=None,
        )
        for i, host in enumerate(hosts_c2)
    ]]
    scenarios.append(run_scenario(
        "C2_Horizontal_UDP_Sweep_5_Hosts_SNMP",
        detector,
        b_c2,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.MEDIUM,
        expected_verdict_substring="Reconnaissance / scanning pattern observed",
        expected_is_vertical=False,
        expected_is_horizontal=True,
    ))

    # C3: Mixed vertical scan (4 TCP SYN ports + 4 UDP ports = 8 distinct ports)
    tcp_ports_c3 = [80, 81, 82, 83]
    udp_ports_c3 = [161, 162, 500, 5060]
    pkts_c3 = []
    for i, p in enumerate(tcp_ports_c3):
        pkts_c3.append(PacketObservation(
            timestamp=900.0 + i * 0.1,
            packet_size=60,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst="192.168.137.1",
            protocol="TCP",
            src_port=50000 + i,
            dst_port=p,
            tcp_flags="0x0002",
        ))
    for i, p in enumerate(udp_ports_c3):
        pkts_c3.append(PacketObservation(
            timestamp=900.5 + i * 0.1,
            packet_size=80,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst="192.168.137.1",
            protocol="UDP",
            src_port=40000 + i,
            dst_port=p,
            tcp_flags=None,
        ))
    scenarios.append(run_scenario(
        "C3_Mixed_Vertical_Scan_TCP_UDP_8_Ports",
        detector,
        [pkts_c3],
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.MEDIUM,
        expected_verdict_substring="Reconnaissance / scanning pattern observed",
        expected_is_vertical=True,
        expected_is_horizontal=False,
    ))

    # =========================================================================
    # Group D: Established TCP Traffic
    # =========================================================================
    # D1: 15 distinct ports with ACK flag (0x0010)
    b_d1 = [[
        PacketObservation(
            timestamp=1000.0 + i * 0.1,
            packet_size=1200,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst="192.168.137.1",
            protocol="TCP",
            src_port=50000 + i,
            dst_port=8000 + i,
            tcp_flags="0x0010",
        )
        for i in range(15)
    ]]
    scenarios.append(run_scenario(
        "D1_Established_TCP_ACK_0x0010_15_Ports",
        detector,
        b_d1,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Normal transport diversity",
    ))

    # D2: 15 distinct ports with PSH+ACK flag (0x0018)
    b_d2 = [[
        PacketObservation(
            timestamp=1100.0 + i * 0.1,
            packet_size=1200,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst="192.168.137.1",
            protocol="TCP",
            src_port=50000 + i,
            dst_port=8000 + i,
            tcp_flags="0x0018",
        )
        for i in range(15)
    ]]
    scenarios.append(run_scenario(
        "D2_Established_TCP_PSH_ACK_0x0018_15_Ports",
        detector,
        b_d2,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Normal transport diversity",
    ))

    # D3: 15 distinct ports with SYN+ACK string flag (handshake response)
    b_d3 = [[
        PacketObservation(
            timestamp=1200.0 + i * 0.1,
            packet_size=60,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst="192.168.137.1",
            protocol="TCP",
            src_port=50000 + i,
            dst_port=8000 + i,
            tcp_flags="SYN, ACK",
        )
        for i in range(15)
    ]]
    scenarios.append(run_scenario(
        "D3_Established_TCP_SYN_ACK_String_15_Ports",
        detector,
        b_d3,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Normal transport diversity",
    ))

    # D4: High-volume normal session (100 packets across 20 ports with ACK flag)
    b_d4 = [[
        PacketObservation(
            timestamp=1300.0 + i * 0.02,
            packet_size=1400,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst="192.168.137.1",
            protocol="TCP",
            src_port=50000 + (i % 20),
            dst_port=8000 + (i % 20),
            tcp_flags="0x0010",
        )
        for i in range(100)
    ]]
    scenarios.append(run_scenario(
        "D4_HighVolume_Established_Session_100_Packets",
        detector,
        b_d4,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Normal transport diversity",
    ))

    # =========================================================================
    # Group E: Infrastructure Exclusions
    # =========================================================================
    # E1: All 11 infrastructure ports probed on 1 local host (53, 67, 68, 123, 137, 138, 139, 1900, 3702, 5353, 5355)
    infra_ports = [53, 67, 68, 123, 137, 138, 139, 1900, 3702, 5353, 5355]
    b_e1 = [[
        PacketObservation(
            timestamp=1400.0 + i * 0.1,
            packet_size=80,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst="192.168.137.1",
            protocol="UDP",
            src_port=54000 + i,
            dst_port=port,
            tcp_flags=None,
        )
        for i, port in enumerate(infra_ports)
    ]]
    scenarios.append(run_scenario(
        "E1_All_11_Infrastructure_Ports_Excluded",
        detector,
        b_e1,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Normal transport diversity",
    ))

    # E2: Horizontal sweep of DNS port 53 across 10 local hosts
    b_e2 = [[
        PacketObservation(
            timestamp=1500.0 + i * 0.1,
            packet_size=80,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst=f"192.168.137.{10 + i}",
            protocol="UDP",
            src_port=55000,
            dst_port=53,
            tcp_flags=None,
        )
        for i in range(10)
    ]]
    scenarios.append(run_scenario(
        "E2_Horizontal_DNS_Port_53_Sweep_Excluded",
        detector,
        b_e2,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Normal transport diversity",
    ))

    # E3: Horizontal sweep of mDNS port 5353 across 10 local hosts
    b_e3 = [[
        PacketObservation(
            timestamp=1600.0 + i * 0.1,
            packet_size=80,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst=f"192.168.137.{10 + i}",
            protocol="UDP",
            src_port=5353,
            dst_port=5353,
            tcp_flags=None,
        )
        for i in range(10)
    ]]
    scenarios.append(run_scenario(
        "E3_Horizontal_mDNS_Port_5353_Sweep_Excluded",
        detector,
        b_e3,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Normal transport diversity",
    ))

    # E4: Combined 7 infra ports + 2 non-infra ports (total 9 ports contacted, only 2 non-infra < 8)
    mixed_ports_e4 = [53, 67, 123, 137, 1900, 5353, 5355, 80, 443]
    b_e4 = [[
        PacketObservation(
            timestamp=1700.0 + i * 0.1,
            packet_size=80,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst="192.168.137.1",
            protocol="TCP" if port in (80, 443) else "UDP",
            src_port=56000 + i,
            dst_port=port,
            tcp_flags="0x0002" if port in (80, 443) else None,
        )
        for i, port in enumerate(mixed_ports_e4)
    ]]
    scenarios.append(run_scenario(
        "E4_Mixed_7_Infra_Plus_2_NonInfra_Excluded",
        detector,
        b_e4,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Normal transport diversity",
    ))

    # =========================================================================
    # Group F: Boundary Testing
    # =========================================================================
    # F1: Vertical scan - 7 ports (below threshold 8)
    b_f1 = [[
        PacketObservation(
            timestamp=1800.0 + i * 0.1,
            packet_size=60,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst="192.168.137.1",
            protocol="TCP",
            src_port=50000 + i,
            dst_port=80 + i,
            tcp_flags="0x0002",
        )
        for i in range(7)
    ]]
    scenarios.append(run_scenario(
        "F1_Boundary_Vertical_7_Ports_BelowThreshold",
        detector,
        b_f1,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Normal transport diversity",
    ))

    # F2: Vertical scan - 8 ports (exact threshold 8)
    b_f2 = [[
        PacketObservation(
            timestamp=1900.0 + i * 0.1,
            packet_size=60,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst="192.168.137.1",
            protocol="TCP",
            src_port=50000 + i,
            dst_port=80 + i,
            tcp_flags="0x0002",
        )
        for i in range(8)
    ]]
    scenarios.append(run_scenario(
        "F2_Boundary_Vertical_8_Ports_ExactThreshold",
        detector,
        b_f2,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.MEDIUM,
        expected_verdict_substring="Reconnaissance / scanning pattern observed",
        expected_is_vertical=True,
    ))

    # F3: Vertical scan - 9 ports (above threshold 8)
    b_f3 = [[
        PacketObservation(
            timestamp=2000.0 + i * 0.1,
            packet_size=60,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst="192.168.137.1",
            protocol="TCP",
            src_port=50000 + i,
            dst_port=80 + i,
            tcp_flags="0x0002",
        )
        for i in range(9)
    ]]
    scenarios.append(run_scenario(
        "F3_Boundary_Vertical_9_Ports_AboveThreshold",
        detector,
        b_f3,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.MEDIUM,
        expected_verdict_substring="Reconnaissance / scanning pattern observed",
        expected_is_vertical=True,
    ))

    # F4: Horizontal sweep - 4 hosts (below threshold 5)
    b_f4 = [[
        PacketObservation(
            timestamp=2100.0 + i * 0.1,
            packet_size=60,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst=f"192.168.137.{2 + i}",
            protocol="TCP",
            src_port=50000 + i,
            dst_port=80,
            tcp_flags="0x0002",
        )
        for i in range(4)
    ]]
    scenarios.append(run_scenario(
        "F4_Boundary_Horizontal_4_Hosts_BelowThreshold",
        detector,
        b_f4,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Normal transport diversity",
    ))

    # F5: Horizontal sweep - 5 hosts (exact threshold 5)
    b_f5 = [[
        PacketObservation(
            timestamp=2200.0 + i * 0.1,
            packet_size=60,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst=f"192.168.137.{2 + i}",
            protocol="TCP",
            src_port=50000 + i,
            dst_port=80,
            tcp_flags="0x0002",
        )
        for i in range(5)
    ]]
    scenarios.append(run_scenario(
        "F5_Boundary_Horizontal_5_Hosts_ExactThreshold",
        detector,
        b_f5,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.MEDIUM,
        expected_verdict_substring="Reconnaissance / scanning pattern observed",
        expected_is_horizontal=True,
    ))

    # F6: Horizontal sweep - 6 hosts (above threshold 5)
    b_f6 = [[
        PacketObservation(
            timestamp=2300.0 + i * 0.1,
            packet_size=60,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst=f"192.168.137.{2 + i}",
            protocol="TCP",
            src_port=50000 + i,
            dst_port=80,
            tcp_flags="0x0002",
        )
        for i in range(6)
    ]]
    scenarios.append(run_scenario(
        "F6_Boundary_Horizontal_6_Hosts_AboveThreshold",
        detector,
        b_f6,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.MEDIUM,
        expected_verdict_substring="Reconnaissance / scanning pattern observed",
        expected_is_horizontal=True,
    ))

    # F7: Time window boundary - 8 probes spaced within 4.9s (all within 5.0s window)
    b_f7 = [[
        PacketObservation(
            timestamp=2400.0 + i * 0.7,  # i=0 to 7: 0.0 to 4.9s
            packet_size=60,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst="192.168.137.1",
            protocol="TCP",
            src_port=50000 + i,
            dst_port=80 + i,
            tcp_flags="0x0002",
        )
        for i in range(8)
    ]]
    scenarios.append(run_scenario(
        "F7_Boundary_TimeWindow_Within_4_9s",
        detector,
        b_f7,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.MEDIUM,
        expected_verdict_substring="Reconnaissance / scanning pattern observed",
        expected_is_vertical=True,
    ))

    # F8: Time window boundary - 8 probes spaced over 6.0s (first probe at 0.0, 7 probes at 6.0)
    # First batch at t=2500.0 (1 probe)
    # Second batch at t=2506.0 (7 probes)
    # When evaluated at t=2506.0, the probe at t=2500.0 has age 6.0 > 5.0 and is pruned. Active = 7 < 8.
    b_f8 = [
        [PacketObservation(
            timestamp=2500.0,
            packet_size=60,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst="192.168.137.1",
            protocol="TCP",
            src_port=50000,
            dst_port=80,
            tcp_flags="0x0002",
        )],
        [PacketObservation(
            timestamp=2506.0 + i * 0.01,
            packet_size=60,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst="192.168.137.1",
            protocol="TCP",
            src_port=50001 + i,
            dst_port=81 + i,
            tcp_flags="0x0002",
        ) for i in range(7)],
    ]
    scenarios.append(run_scenario(
        "F8_Boundary_TimeWindow_Expired_6_0s_Pruned",
        detector,
        b_f8,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Normal transport diversity",
    ))

    # F9: Combined vertical + horizontal scan (Strobe scan: >=8 ports on >=5 hosts simultaneously) -> Severity HIGH
    pkts_f9 = []
    hosts_f9 = [f"192.168.137.{10 + h}" for h in range(5)]
    ports_f9 = [80 + p for p in range(8)]
    for h_idx, h in enumerate(hosts_f9):
        for p_idx, p in enumerate(ports_f9):
            pkts_f9.append(PacketObservation(
                timestamp=2600.0 + (h_idx * 8 + p_idx) * 0.05,
                packet_size=60,
                eth_src="ca:34:ea:92:d3:9e",
                eth_dst="36:6f:24:d2:34:3d",
                ip_src="192.168.137.100",
                ip_dst=h,
                protocol="TCP",
                src_port=50000 + (h_idx * 8 + p_idx),
                dst_port=p,
                tcp_flags="0x0002",
            ))
    scenarios.append(run_scenario(
        "F9_Strobe_Scan_Vertical_And_Horizontal_HighSeverity",
        detector,
        [pkts_f9],
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.HIGH,
        expected_verdict_substring="Reconnaissance / scanning pattern observed",
        expected_is_vertical=True,
        expected_is_horizontal=True,
    ))

    # =========================================================================
    # Group G: Benign Service Discovery
    # =========================================================================
    # G1: Realistic local discovery pattern (mDNS 5353, SSDP 1900, LLMNR 5355, NetBIOS 137, plus HTTP 80 & HTTPS 443 on 2 local hosts)
    pkts_g1 = [
        # Infra ports
        PacketObservation(timestamp=2700.0, packet_size=100, eth_src="ca:34:ea:92:d3:9e", eth_dst="36:6f:24:d2:34:3d", ip_src="192.168.137.100", ip_dst="192.168.137.1", protocol="UDP", src_port=5353, dst_port=5353),
        PacketObservation(timestamp=2700.1, packet_size=100, eth_src="ca:34:ea:92:d3:9e", eth_dst="36:6f:24:d2:34:3d", ip_src="192.168.137.100", ip_dst="192.168.137.1", protocol="UDP", src_port=1900, dst_port=1900),
        PacketObservation(timestamp=2700.2, packet_size=100, eth_src="ca:34:ea:92:d3:9e", eth_dst="36:6f:24:d2:34:3d", ip_src="192.168.137.100", ip_dst="192.168.137.1", protocol="UDP", src_port=5355, dst_port=5355),
        PacketObservation(timestamp=2700.3, packet_size=100, eth_src="ca:34:ea:92:d3:9e", eth_dst="36:6f:24:d2:34:3d", ip_src="192.168.137.100", ip_dst="192.168.137.1", protocol="UDP", src_port=137, dst_port=137),
        # Non-infra ports on 2 hosts (80 and 443)
        PacketObservation(timestamp=2700.4, packet_size=60, eth_src="ca:34:ea:92:d3:9e", eth_dst="36:6f:24:d2:34:3d", ip_src="192.168.137.100", ip_dst="192.168.137.1", protocol="TCP", src_port=50001, dst_port=80, tcp_flags="0x0002"),
        PacketObservation(timestamp=2700.5, packet_size=60, eth_src="ca:34:ea:92:d3:9e", eth_dst="36:6f:24:d2:34:3d", ip_src="192.168.137.100", ip_dst="192.168.137.1", protocol="TCP", src_port=50002, dst_port=443, tcp_flags="0x0002"),
        PacketObservation(timestamp=2700.6, packet_size=60, eth_src="ca:34:ea:92:d3:9e", eth_dst="36:6f:24:d2:34:3d", ip_src="192.168.137.100", ip_dst="192.168.137.2", protocol="TCP", src_port=50003, dst_port=80, tcp_flags="0x0002"),
        PacketObservation(timestamp=2700.7, packet_size=60, eth_src="ca:34:ea:92:d3:9e", eth_dst="36:6f:24:d2:34:3d", ip_src="192.168.137.100", ip_dst="192.168.137.2", protocol="TCP", src_port=50004, dst_port=443, tcp_flags="0x0002"),
    ]
    scenarios.append(run_scenario(
        "G1_Benign_Local_Service_Discovery_Profile",
        detector,
        [pkts_g1],
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Normal transport diversity",
    ))

    # G2: Dual-port service check (SSH 22, HTTP 80) across 3 local hosts
    pkts_g2 = [
        PacketObservation(
            timestamp=2800.0 + h_idx * 0.2 + p_idx * 0.1,
            packet_size=60,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst=f"192.168.137.{10 + h_idx}",
            protocol="TCP",
            src_port=51000 + h_idx * 2 + p_idx,
            dst_port=p,
            tcp_flags="0x0002",
        )
        for h_idx in range(3)
        for p_idx, p in enumerate([22, 80])
    ]
    scenarios.append(run_scenario(
        "G2_Benign_DualPort_Check_3_Hosts",
        detector,
        [pkts_g2],
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Normal transport diversity",
    ))

    # G3: Subnet broadcast and multicast discovery packets
    broadcast_ips = ["192.168.137.255", "224.0.0.251", "239.255.255.250", "255.255.255.255", "192.168.137.0"]
    pkts_g3 = [
        PacketObservation(
            timestamp=2900.0 + i * 0.1,
            packet_size=80,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="ff:ff:ff:ff:ff:ff",
            ip_src="192.168.137.100",
            ip_dst=dst,
            protocol="UDP",
            src_port=50000 + i,
            dst_port=8000 + i,
            tcp_flags=None,
        )
        for i, dst in enumerate(broadcast_ips * 2)  # 10 packets to broadcast/multicast
    ]
    scenarios.append(run_scenario(
        "G3_Broadcast_Multicast_Traffic_Excluded",
        detector,
        [pkts_g3],
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Normal transport diversity",
    ))

    # =========================================================================
    # Group H: Missing Telemetry & Robustness
    # =========================================================================
    # H1: Completely empty packet list []
    scenarios.append(run_scenario(
        "H1_Empty_Packet_List",
        detector,
        [[]],
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="No packets provided in observation window",
    ))

    # H2: Missing transport layer metadata (dst_port=None, ip_src=None)
    pkts_h2 = [
        PacketObservation(
            timestamp=3000.0 + i * 0.1,
            packet_size=100,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src=None,
            ip_dst=None,
            protocol="IPv4",
            src_port=None,
            dst_port=None,
            tcp_flags=None,
        )
        for i in range(10)
    ]
    scenarios.append(run_scenario(
        "H2_Missing_Transport_Ports_InsufficientTelemetry",
        detector,
        [pkts_h2],
        expected_status=DetectionStatus.INSUFFICIENT_TELEMETRY,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Capture stream lacks transport layer port metadata",
        expected_missing_fields=["dst_port", "src_port", "tcp_flags"],
    ))

    # H3: Missing TCP flags on TCP packets (tcp_flags=None, handled safely without crash or false alert)
    pkts_h3 = [
        PacketObservation(
            timestamp=3100.0 + i * 0.1,
            packet_size=100,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.100",
            ip_dst="192.168.137.1",
            protocol="TCP",
            src_port=50000 + i,
            dst_port=80 + i,
            tcp_flags=None,
        )
        for i in range(10)
    ]
    scenarios.append(run_scenario(
        "H3_Missing_TCP_Flags_Handled_Safely",
        detector,
        [pkts_h3],
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Normal transport diversity",
    ))

    # H4: Non-IP / ARP frames (ip_src=None, protocol='ARP')
    pkts_h4 = [
        PacketObservation(
            timestamp=3200.0 + i * 0.1,
            packet_size=42,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="ff:ff:ff:ff:ff:ff",
            ip_src=None,
            ip_dst=None,
            protocol="ARP",
            src_port=None,
            dst_port=None,
            tcp_flags=None,
        )
        for i in range(5)
    ]
    scenarios.append(run_scenario(
        "H4_Non_IP_ARP_Frames_InsufficientTelemetry",
        detector,
        [pkts_h4],
        expected_status=DetectionStatus.INSUFFICIENT_TELEMETRY,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Capture stream lacks transport layer port metadata",
    ))

    # =========================================================================
    # Group I: Scanner Attribution & Cooldown
    # =========================================================================
    # I1: Single scanner attribution integrity
    detector.reset()
    pkts_i1 = [
        PacketObservation(
            timestamp=3300.0 + i * 0.1,
            packet_size=60,
            eth_src="00:0c:29:ab:cd:ef",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.150",
            ip_dst="192.168.137.1",
            protocol="TCP",
            src_port=50000 + i,
            dst_port=80 + i,
            tcp_flags="0x0002",
        )
        for i in range(8)
    ]
    res_i1 = detector.evaluate(pkts_i1)
    d1 = res_i1.evidence["details"][0]
    pass_i1 = (
        res_i1.status == DetectionStatus.SUSPICIOUS
        and d1["src_ip"] == "192.168.137.150"
        and d1["source_mac"] == "00:0c:29:ab:cd:ef"
        and d1["distinct_ports_count"] == 8
    )
    scenarios.append({
        "scenario": "I1_Single_Scanner_Attribution_Integrity",
        "batch_count": 1,
        "total_packets": 8,
        "final_status": res_i1.status.value,
        "final_severity": res_i1.severity.value,
        "final_confidence": round(res_i1.confidence, 4),
        "verdict": res_i1.evidence.get("verdict", ""),
        "details_count": len(res_i1.evidence.get("details", [])),
        "is_vertical_scan": d1.get("is_vertical_scan"),
        "is_horizontal_sweep": d1.get("is_horizontal_sweep"),
        "distinct_ports_count": d1.get("distinct_ports_count"),
        "distinct_hosts_count": d1.get("distinct_hosts_count"),
        "missing_fields": res_i1.missing_fields,
        "expected_status": "SUSPICIOUS",
        "expected_severity": "MEDIUM",
        "expected_verdict": "Reconnaissance / scanning pattern observed",
        "expected_is_vertical": True,
        "expected_is_horizontal": False,
        "passed": pass_i1,
    })

    # I2: Two concurrent scanners identified independently
    detector.reset()
    pkts_i2_a = [
        PacketObservation(
            timestamp=3400.0 + i * 0.1,
            packet_size=60,
            eth_src="00:0c:29:ab:cd:ef",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.150",
            ip_dst="192.168.137.1",
            protocol="TCP",
            src_port=50000 + i,
            dst_port=80 + i,
            tcp_flags="0x0002",
        )
        for i in range(8)
    ]
    pkts_i2_b = [
        PacketObservation(
            timestamp=3400.05 + i * 0.1,
            packet_size=60,
            eth_src="00:0c:29:11:22:33",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.160",
            ip_dst=f"192.168.137.{10 + i}",
            protocol="TCP",
            src_port=51000 + i,
            dst_port=22,
            tcp_flags="0x0002",
        )
        for i in range(5)
    ]
    res_i2 = detector.evaluate(pkts_i2_a + pkts_i2_b)
    details_i2 = res_i2.evidence["details"]
    src_ips_found = {d["src_ip"] for d in details_i2}
    src_macs_found = {d["source_mac"] for d in details_i2}
    pass_i2 = (
        res_i2.status == DetectionStatus.SUSPICIOUS
        and len(details_i2) == 2
        and src_ips_found == {"192.168.137.150", "192.168.137.160"}
        and src_macs_found == {"00:0c:29:ab:cd:ef", "00:0c:29:11:22:33"}
    )
    scenarios.append({
        "scenario": "I2_Two_Simultaneous_Scanners_Independent",
        "batch_count": 1,
        "total_packets": 13,
        "final_status": res_i2.status.value,
        "final_severity": res_i2.severity.value,
        "final_confidence": round(res_i2.confidence, 4),
        "verdict": res_i2.evidence.get("verdict", ""),
        "details_count": len(details_i2),
        "is_vertical_scan": any(d.get("is_vertical_scan") for d in details_i2),
        "is_horizontal_sweep": any(d.get("is_horizontal_sweep") for d in details_i2),
        "distinct_ports_count": sum(d.get("distinct_ports_count", 0) for d in details_i2),
        "distinct_hosts_count": sum(d.get("distinct_hosts_count", 0) for d in details_i2),
        "missing_fields": res_i2.missing_fields,
        "expected_status": "SUSPICIOUS",
        "expected_severity": "MEDIUM",
        "expected_verdict": "Reconnaissance / scanning pattern observed",
        "expected_is_vertical": True,
        "expected_is_horizontal": True,
        "passed": pass_i2,
    })

    # I3: Scanner MAC updating (captures latest active MAC)
    detector.reset()
    pkts_i3 = [
        PacketObservation(
            timestamp=3500.0 + i * 0.1,
            packet_size=60,
            eth_src="00:0c:29:aa:bb:cc" if i < 3 else "00:0c:29:dd:ee:ff",
            eth_dst="36:6f:24:d2:34:3d",
            ip_src="192.168.137.150",
            ip_dst="192.168.137.1",
            protocol="TCP",
            src_port=50000 + i,
            dst_port=80 + i,
            tcp_flags="0x0002",
        )
        for i in range(8)
    ]
    res_i3 = detector.evaluate(pkts_i3)
    d3 = res_i3.evidence["details"][0]
    pass_i3 = (
        res_i3.status == DetectionStatus.SUSPICIOUS
        and d3["source_mac"] == "00:0c:29:dd:ee:ff"  # Latest MAC!
    )
    scenarios.append({
        "scenario": "I3_Scanner_MAC_Rotation_Captures_Latest",
        "batch_count": 1,
        "total_packets": 8,
        "final_status": res_i3.status.value,
        "final_severity": res_i3.severity.value,
        "final_confidence": round(res_i3.confidence, 4),
        "verdict": res_i3.evidence.get("verdict", ""),
        "details_count": len(res_i3.evidence.get("details", [])),
        "is_vertical_scan": d3.get("is_vertical_scan"),
        "is_horizontal_sweep": d3.get("is_horizontal_sweep"),
        "distinct_ports_count": d3.get("distinct_ports_count"),
        "distinct_hosts_count": d3.get("distinct_hosts_count"),
        "missing_fields": res_i3.missing_fields,
        "expected_status": "SUSPICIOUS",
        "expected_severity": "MEDIUM",
        "expected_verdict": "Reconnaissance / scanning pattern observed",
        "expected_is_vertical": True,
        "expected_is_horizontal": False,
        "passed": pass_i3,
    })

    # I4: LiveCollector Fingerprint Cooldown Deduplication
    scratch_db = PROJECT_ROOT / "scratch" / "test_stage53_cooldown.db"
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
        port_scan_cooldown_seconds=0.05,
    )
    collector._run_id = run_id
    collector._attack_table_present = True

    cur_w = conn.execute(
        "INSERT INTO live_traffic_windows (run_id, client_mac, node_id, bin_start_epoch, bin_end_epoch, packet_count, packet_rate) "
        "VALUES (?, 'ca:34:ea:92:d3:9e', 'Node_3', 3600.0, 3601.0, 5, 5.0)",
        (run_id,),
    )
    win_id = cur_w.lastrowid
    conn.commit()

    scan_res_cooldown = AttackDetectionResult(
        category=AttackCategory.PORT_SCAN,
        status=DetectionStatus.SUSPICIOUS,
        severity=Severity.MEDIUM,
        evidence={
            "verdict": "Reconnaissance / scanning pattern observed",
            "details": [{
                "src_ip": "192.168.137.150",
                "source_mac": "00:0c:29:ab:cd:ef",
                "sample_ports": [80, 81, 82, 83, 84, 85, 86, 87],
                "sample_hosts": ["192.168.137.1"],
                "distinct_ports_count": 8,
                "distinct_hosts_count": 1,
                "is_vertical_scan": True,
                "is_horizontal_sweep": False,
                "destination_scope": "LAN (192.168.137.0/24)",
            }],
        },
        missing_fields=[],
        confidence=0.85,
        timestamp=3600.0,
        recommended_action="Investigate host 192.168.137.150.",
    )
    scored_dummy = {"client_mac": "ca:34:ea:92:d3:9e", "ip_dst": "142.250.190.46"}

    # First emission at t0 -> persisted
    ins_1 = collector._persist_attack_results(conn, win_id, [], [scan_res_cooldown], "ca:34:ea:92:d3:9e", scored_dummy)

    # Second emission immediately (< 0.05s cooldown) -> suppressed
    ins_2 = collector._persist_attack_results(conn, win_id, [], [scan_res_cooldown], "ca:34:ea:92:d3:9e", scored_dummy)

    # Sleep 0.08s past cooldown
    time.sleep(0.08)

    # Third emission (> 0.05s cooldown) -> persisted as new row
    ins_3 = collector._persist_attack_results(conn, win_id, [], [scan_res_cooldown], "ca:34:ea:92:d3:9e", scored_dummy)

    total_rows = conn.execute("SELECT count(*) FROM live_attack_events WHERE run_id = ?", (run_id,)).fetchone()[0]
    conn.close()
    if scratch_db.exists():
        scratch_db.unlink()

    pass_i4 = (ins_1 == 1 and ins_2 == 0 and ins_3 == 1 and total_rows == 2)
    scenarios.append({
        "scenario": "I4_LiveCollector_Cooldown_Deduplication",
        "batch_count": 3,
        "total_packets": 24,
        "final_status": "SUSPICIOUS",
        "final_severity": "MEDIUM",
        "final_confidence": 0.85,
        "verdict": "Cooldown deduplication suppresses identical findings within 10s window",
        "details_count": 1,
        "is_vertical_scan": True,
        "is_horizontal_sweep": False,
        "distinct_ports_count": 8,
        "distinct_hosts_count": 1,
        "missing_fields": [],
        "expected_status": "SUSPICIOUS",
        "expected_severity": "MEDIUM",
        "expected_verdict": "Cooldown deduplication",
        "expected_is_vertical": True,
        "expected_is_horizontal": False,
        "passed": pass_i4,
    })

    # =========================================================================
    # Group J: Real PCAP Offline Evaluation
    # =========================================================================
    pcap_file = PROJECT_ROOT / "data" / "hotspot_two_phone_test.pcapng"
    res_j1 = evaluate_real_pcap(detector, pcap_file)
    scenarios.append(res_j1)

    # Summary
    total_scenarios = len(scenarios)
    passed_scenarios = sum(1 for s in scenarios if s.get("passed", False))
    failed_scenarios = total_scenarios - passed_scenarios

    output_data = {
        "metadata": {
            "test_stage": "Stage 5.3",
            "component": "PortScanDetector",
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_scenarios": total_scenarios,
            "passed_scenarios": passed_scenarios,
            "failed_scenarios": failed_scenarios,
            "pass_rate_pct": round(passed_scenarios / total_scenarios * 100, 2),
        },
        "scenarios": scenarios,
    }

    out_json = PROJECT_ROOT / "scratch" / "stage53_port_scan_validation_results.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)

    print(f"Validation finished: {passed_scenarios}/{total_scenarios} scenarios PASSED ({output_data['metadata']['pass_rate_pct']}%)")
    for s in scenarios:
        status_flag = "PASS" if s.get("passed") else "FAIL"
        print(f"[{status_flag}] {s['scenario']}")

if __name__ == "__main__":
    main()
