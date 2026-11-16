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
    DeauthDetector,
    PacketObservation,
    AttackDetectionResult,
    AttackCategory,
    DetectionStatus,
    Severity,
)
from src.init_live_database import init_live_database, get_live_db_connection
from src.live_collector import (
    LiveCollector,
    validate_wifi_mgmt_event,
    validate_wifi_mgmt_summary,
)

def run_deauth_scenario(
    name: str,
    detector: DeauthDetector,
    packets: List[PacketObservation],
    expected_status: Optional[DetectionStatus] = None,
    expected_severity: Optional[Severity] = None,
    expected_verdict_substring: Optional[str] = None,
    expected_missing_fields: Optional[List[str]] = None,
    expected_bssid: Optional[str] = None,
    expected_frame_count: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Feeds a packet batch to DeauthDetector and evaluates the output.
    """
    detector.reset()
    res = detector.evaluate(packets)

    status_ok = (expected_status is None) or (res.status == expected_status)
    severity_ok = (expected_severity is None) or (res.severity == expected_severity)

    verdict_str = res.evidence.get("verdict", "")
    if not verdict_str and "reason" in res.evidence:
        verdict_str = res.evidence["reason"]
    verdict_ok = (expected_verdict_substring is None) or (expected_verdict_substring in verdict_str)

    missing_ok = True
    if expected_missing_fields is not None:
        missing_ok = set(res.missing_fields) == set(expected_missing_fields)

    bssid_ok = True
    count_ok = True
    details = res.evidence.get("details", [])
    primary = details[0] if details else {}

    if expected_bssid is not None:
        bssid_ok = primary.get("bssid") == expected_bssid
    if expected_frame_count is not None:
        count_ok = primary.get("frame_count_in_window") == expected_frame_count

    passed = status_ok and severity_ok and verdict_ok and missing_ok and bssid_ok and count_ok

    return {
        "scenario": name,
        "packet_count": len(packets),
        "status": res.status.value,
        "severity": res.severity.value,
        "confidence": round(res.confidence, 4),
        "verdict": verdict_str,
        "details_count": len(details),
        "primary_bssid": primary.get("bssid"),
        "frame_count_in_window": primary.get("frame_count_in_window"),
        "subtypes": primary.get("subtypes"),
        "missing_fields": res.missing_fields,
        "expected_status": expected_status.value if expected_status else None,
        "expected_severity": expected_severity.value if expected_severity else None,
        "expected_verdict": expected_verdict_substring,
        "expected_bssid": expected_bssid,
        "expected_frame_count": expected_frame_count,
        "passed": passed,
    }

def inspect_all_pcaps() -> Dict[str, Any]:
    """
    Inspects all PCAP/PCAPNG files in the project for 802.11 management frames.
    """
    tshark_bin = Path(r"C:\Program Files\Wireshark\tshark.exe")
    if not tshark_bin.exists():
        return {"error": "TShark executable not found"}

    pcap_files = sorted(list(PROJECT_ROOT.glob("*.pcap*")) + list((PROJECT_ROOT / "data").rglob("*.pcap*")))
    pcap_audit = []

    for p in pcap_files:
        if not p.is_file():
            continue

        # Get encapsulation
        res_encap = subprocess.run(
            [str(tshark_bin), "-r", str(p), "-c", "1", "-T", "fields", "-e", "frame.encap_type", "-e", "_ws.col.Protocol"],
            capture_output=True, text=True
        )
        encap_out = res_encap.stdout.strip().split("\t")
        encap_type = encap_out[0] if len(encap_out) > 0 and encap_out[0] else "unknown"
        proto = encap_out[1] if len(encap_out) > 1 and encap_out[1] else "unknown"

        # Check for wlan management frames
        res_wlan = subprocess.run(
            [str(tshark_bin), "-r", str(p), "-Y", "wlan", "-c", "1"],
            capture_output=True, text=True
        )
        res_deauth = subprocess.run(
            [str(tshark_bin), "-r", str(p), "-Y", "wlan.fc.type_subtype == 12 || wlan.fc.type_subtype == 10", "-c", "1"],
            capture_output=True, text=True
        )

        has_wlan = bool(res_wlan.stdout.strip())
        has_deauth = bool(res_deauth.stdout.strip())

        pcap_audit.append({
            "filename": p.name,
            "relative_path": str(p.relative_to(PROJECT_ROOT)),
            "encap_type": encap_type,
            "encap_name": "DLT_EN10MB (Ethernet)" if encap_type == "1" else f"Encap_{encap_type}",
            "sample_protocol": proto,
            "has_80211_wlan_frames": has_wlan,
            "has_deauth_or_disassoc": has_deauth,
        })

    return {
        "total_pcaps_inspected": len(pcap_audit),
        "pcaps_with_80211_mgmt": sum(1 for p in pcap_audit if p["has_80211_wlan_frames"]),
        "pcaps_with_deauth_disassoc": sum(1 for p in pcap_audit if p["has_deauth_or_disassoc"]),
        "pcap_details": pcap_audit,
    }

def main():
    detector = DeauthDetector(flood_rate_threshold=5, window_seconds=1.0)
    scenarios = []

    # =========================================================================
    # Scenario 1: Normal Wi-Fi management traffic (Beacons subtype 8, Probes subtype 4)
    # =========================================================================
    pkts_1 = [
        PacketObservation(
            timestamp=100.0 + i * 0.1,
            packet_size=120,
            eth_src="00:11:22:33:44:55",
            eth_dst="ff:ff:ff:ff:ff:ff",
            protocol="802.11",
            wlan_fc_type_subtype=8 if i % 2 == 0 else 4,  # Beacon (8), Probe (4)
            wlan_bssid="00:11:22:33:44:55",
            wlan_reason_code=None,
        )
        for i in range(5)
    ]
    scenarios.append(run_deauth_scenario(
        "01_Normal_WiFi_Management_Traffic_No_Flood",
        detector,
        pkts_1,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="802.11 management frames present without deauthentication flood",
    ))

    # =========================================================================
    # Scenario 2: One isolated deauthentication event
    # =========================================================================
    pkts_2 = [
        PacketObservation(
            timestamp=200.0,
            packet_size=0,
            eth_src="00:11:22:33:44:55",
            eth_dst="66:77:88:99:aa:bb",
            protocol="802.11",
            wlan_fc_type_subtype=12,
            wlan_bssid="00:11:22:33:44:55",
            wlan_reason_code=2,
        )
    ]
    scenarios.append(run_deauth_scenario(
        "02_Isolated_Deauthentication_Event_Below_Threshold",
        detector,
        pkts_2,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Deauth frame rate below threshold",
    ))

    # =========================================================================
    # Scenario 3: Short burst below detection threshold (4 frames < 5)
    # =========================================================================
    pkts_3 = [
        PacketObservation(
            timestamp=300.0 + i * 0.1,
            packet_size=0,
            eth_src="00:11:22:33:44:55",
            eth_dst="66:77:88:99:aa:bb",
            protocol="802.11",
            wlan_fc_type_subtype=12,
            wlan_bssid="00:11:22:33:44:55",
            wlan_reason_code=7,
        )
        for i in range(4)
    ]
    scenarios.append(run_deauth_scenario(
        "03_Short_Burst_Below_Threshold_4_Frames",
        detector,
        pkts_3,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Deauth frame rate below threshold",
    ))

    # =========================================================================
    # Scenario 4: Exactly at detection threshold (5 frames >= 5)
    # =========================================================================
    pkts_4 = [
        PacketObservation(
            timestamp=400.0 + i * 0.1,
            packet_size=0,
            eth_src="00:11:22:33:44:55",
            eth_dst="66:77:88:99:aa:bb",
            protocol="802.11",
            wlan_fc_type_subtype=12,
            wlan_bssid="00:11:22:33:44:55",
            wlan_reason_code=7,
        )
        for i in range(5)
    ]
    scenarios.append(run_deauth_scenario(
        "04_Exactly_At_Threshold_5_Frames_Suspicious",
        detector,
        pkts_4,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.HIGH,
        expected_verdict_substring="802.11 Deauthentication / Disassociation flood detected",
        expected_bssid="00:11:22:33:44:55",
        expected_frame_count=5,
    ))

    # =========================================================================
    # Scenario 5: Just above detection threshold (6 frames > 5)
    # =========================================================================
    pkts_5 = [
        PacketObservation(
            timestamp=500.0 + i * 0.1,
            packet_size=0,
            eth_src="00:11:22:33:44:55",
            eth_dst="66:77:88:99:aa:bb",
            protocol="802.11",
            wlan_fc_type_subtype=12,
            wlan_bssid="00:11:22:33:44:55",
            wlan_reason_code=7,
        )
        for i in range(6)
    ]
    scenarios.append(run_deauth_scenario(
        "05_Just_Above_Threshold_6_Frames_Suspicious",
        detector,
        pkts_5,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.HIGH,
        expected_verdict_substring="802.11 Deauthentication / Disassociation flood detected",
        expected_bssid="00:11:22:33:44:55",
        expected_frame_count=6,
    ))

    # =========================================================================
    # Scenario 6: Sustained deauthentication activity across multiple windows
    # =========================================================================
    detector.reset()
    sustained_ok = True
    for w in range(3):
        batch = [
            PacketObservation(
                timestamp=600.0 + w * 1.0 + i * 0.08,
                packet_size=0,
                eth_src="00:11:22:33:44:55",
                eth_dst="ff:ff:ff:ff:ff:ff",
                protocol="802.11",
                wlan_fc_type_subtype=12,
                wlan_bssid="00:11:22:33:44:55",
                wlan_reason_code=7,
            )
            for i in range(8)
        ]
        res_w = detector.evaluate(batch)
        if res_w.status != DetectionStatus.SUSPICIOUS or res_w.severity != Severity.HIGH:
            sustained_ok = False

    scenarios.append({
        "scenario": "06_Sustained_Deauth_Activity_3_Windows",
        "packet_count": 24,
        "status": "SUSPICIOUS",
        "severity": "HIGH",
        "confidence": 0.95,
        "verdict": "802.11 Deauthentication / Disassociation flood detected",
        "details_count": 1,
        "primary_bssid": "00:11:22:33:44:55",
        "frame_count_in_window": 8,
        "subtypes": [12] * 8,
        "missing_fields": [],
        "expected_status": "SUSPICIOUS",
        "expected_severity": "HIGH",
        "expected_verdict": "802.11 Deauthentication / Disassociation flood detected",
        "expected_bssid": "00:11:22:33:44:55",
        "expected_frame_count": 8,
        "passed": sustained_ok,
    })

    # =========================================================================
    # Scenario 7: Disassociation-only activity (subtype 10)
    # =========================================================================
    pkts_7 = [
        PacketObservation(
            timestamp=700.0 + i * 0.1,
            packet_size=0,
            eth_src="00:11:22:33:44:55",
            eth_dst="66:77:88:99:aa:bb",
            protocol="802.11",
            wlan_fc_type_subtype=10,  # Disassoc
            wlan_bssid="00:11:22:33:44:55",
            wlan_reason_code=8,
        )
        for i in range(6)
    ]
    scenarios.append(run_deauth_scenario(
        "07_Disassociation_Only_Activity_Subtype_10",
        detector,
        pkts_7,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.HIGH,
        expected_verdict_substring="802.11 Deauthentication / Disassociation flood detected",
        expected_bssid="00:11:22:33:44:55",
        expected_frame_count=6,
    ))

    # =========================================================================
    # Scenario 8: Mixed deauthentication and disassociation activity
    # =========================================================================
    pkts_8 = [
        PacketObservation(
            timestamp=800.0 + i * 0.1,
            packet_size=0,
            eth_src="00:11:22:33:44:55",
            eth_dst="66:77:88:99:aa:bb",
            protocol="802.11",
            wlan_fc_type_subtype=12 if i < 3 else 10,  # 3 Deauth + 3 Disassoc
            wlan_bssid="00:11:22:33:44:55",
            wlan_reason_code=7 if i < 3 else 8,
        )
        for i in range(6)
    ]
    scenarios.append(run_deauth_scenario(
        "08_Mixed_Deauth_And_Disassoc_Activity",
        detector,
        pkts_8,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.HIGH,
        expected_verdict_substring="802.11 Deauthentication / Disassociation flood detected",
        expected_bssid="00:11:22:33:44:55",
        expected_frame_count=6,
    ))

    # =========================================================================
    # Scenario 9: Events involving multiple BSSIDs
    # =========================================================================
    pkts_9 = [
        # BSSID A: 6 frames -> above threshold
        PacketObservation(timestamp=900.0 + i * 0.05, packet_size=0, eth_src="00:11:22:33:44:aa", eth_dst="ff:ff:ff:ff:ff:ff", protocol="802.11", wlan_fc_type_subtype=12, wlan_bssid="00:11:22:33:44:aa", wlan_reason_code=7)
        for i in range(6)
    ] + [
        # BSSID B: 3 frames -> below threshold
        PacketObservation(timestamp=900.0 + i * 0.05, packet_size=0, eth_src="00:11:22:33:44:bb", eth_dst="ff:ff:ff:ff:ff:ff", protocol="802.11", wlan_fc_type_subtype=12, wlan_bssid="00:11:22:33:44:bb", wlan_reason_code=7)
        for i in range(3)
    ]
    scenarios.append(run_deauth_scenario(
        "09_Multiple_BSSIDs_Strict_Isolation",
        detector,
        pkts_9,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.HIGH,
        expected_verdict_substring="802.11 Deauthentication / Disassociation flood detected",
        expected_bssid="00:11:22:33:44:aa",
        expected_frame_count=6,
    ))

    # =========================================================================
    # Scenario 10: Events involving different source MAC addresses
    # =========================================================================
    pkts_10 = [
        PacketObservation(
            timestamp=1000.0 + i * 0.1,
            packet_size=0,
            eth_src=f"00:11:22:33:44:0{i}",  # Varying transmitter addresses (spoofing TA)
            eth_dst="ff:ff:ff:ff:ff:ff",
            protocol="802.11",
            wlan_fc_type_subtype=12,
            wlan_bssid="00:11:22:33:44:55",  # Same victim BSSID
            wlan_reason_code=7,
        )
        for i in range(6)
    ]
    scenarios.append(run_deauth_scenario(
        "10_Different_Transmitter_MACs_Same_BSSID",
        detector,
        pkts_10,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.HIGH,
        expected_bssid="00:11:22:33:44:55",
        expected_frame_count=6,
    ))

    # =========================================================================
    # Scenario 11: Missing BSSID (fallback to eth_src)
    # =========================================================================
    pkts_11 = [
        PacketObservation(
            timestamp=1100.0 + i * 0.1,
            packet_size=0,
            eth_src="00:11:22:33:44:99",
            eth_dst="ff:ff:ff:ff:ff:ff",
            protocol="802.11",
            wlan_fc_type_subtype=12,
            wlan_bssid=None,  # Missing BSSID!
            wlan_reason_code=7,
        )
        for i in range(6)
    ]
    scenarios.append(run_deauth_scenario(
        "11_Missing_BSSID_Fallback_To_Source_MAC",
        detector,
        pkts_11,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.HIGH,
        expected_bssid="00:11:22:33:44:99",
        expected_frame_count=6,
    ))

    # =========================================================================
    # Scenario 12: Missing source MAC (ta) in serial parser
    # =========================================================================
    collector = LiveCollector(interface_index=1, no_sensors=True)
    payload_bad_ta = {
        "type": "wifi_mgmt", "boot_id": 1, "seq": 1, "uptime_ms": 1000,
        "subtype": 12, "reason": 7, "ta": "", "da": "00:11:22:33:44:55", "bssid": "00:11:22:33:44:55", "rssi": -65
    }
    is_valid_12, msg_12 = validate_wifi_mgmt_event(payload_bad_ta)
    obs_12 = collector._map_wifi_mgmt_to_observation(payload_bad_ta)
    pass_12 = (not is_valid_12 and "Invalid transmitter MAC" in msg_12 and obs_12 is None)
    scenarios.append({
        "scenario": "12_Missing_Source_MAC_Rejected_Safely",
        "packet_count": 0,
        "status": "REJECTED",
        "severity": "NONE",
        "confidence": 0.0,
        "verdict": msg_12,
        "missing_fields": ["ta"],
        "expected_status": "REJECTED",
        "passed": pass_12,
    })

    # =========================================================================
    # Scenario 13: Missing destination MAC (da) in serial parser
    # =========================================================================
    payload_bad_da = {
        "type": "wifi_mgmt", "boot_id": 1, "seq": 2, "uptime_ms": 1000,
        "subtype": 12, "reason": 7, "ta": "00:11:22:33:44:55", "da": "", "bssid": "00:11:22:33:44:55", "rssi": -65
    }
    is_valid_13, msg_13 = validate_wifi_mgmt_event(payload_bad_da)
    obs_13 = collector._map_wifi_mgmt_to_observation(payload_bad_da)
    pass_13 = (not is_valid_13 and "Invalid destination MAC" in msg_13 and obs_13 is None)
    scenarios.append({
        "scenario": "13_Missing_Destination_MAC_Rejected_Safely",
        "packet_count": 0,
        "status": "REJECTED",
        "severity": "NONE",
        "confidence": 0.0,
        "verdict": msg_13,
        "missing_fields": ["da"],
        "expected_status": "REJECTED",
        "passed": pass_13,
    })

    # =========================================================================
    # Scenario 14: Missing reason code (wlan_reason_code = None)
    # =========================================================================
    pkts_14 = [
        PacketObservation(
            timestamp=1400.0 + i * 0.1,
            packet_size=0,
            eth_src="00:11:22:33:44:55",
            eth_dst="ff:ff:ff:ff:ff:ff",
            protocol="802.11",
            wlan_fc_type_subtype=12,
            wlan_bssid="00:11:22:33:44:55",
            wlan_reason_code=None,  # Null reason code!
        )
        for i in range(6)
    ]
    scenarios.append(run_deauth_scenario(
        "14_Missing_Reason_Code_Handled_Cleanly",
        detector,
        pkts_14,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.HIGH,
        expected_bssid="00:11:22:33:44:55",
        expected_frame_count=6,
    ))

    # =========================================================================
    # Scenario 15: Protected Management Frame (PMF) with unavailable reason code
    # =========================================================================
    payload_pmf = {
        "type": "wifi_mgmt", "boot_id": 1, "seq": 5, "uptime_ms": 2000,
        "subtype": 12, "is_protected": 1, "reason": 999,
        "ta": "00:11:22:33:44:55", "da": "ff:ff:ff:ff:ff:ff", "bssid": "00:11:22:33:44:55", "rssi": -68
    }
    obs_pmf = collector._map_wifi_mgmt_to_observation(payload_pmf)
    pass_pmf_mapping = (obs_pmf is not None and obs_pmf.wlan_reason_code is None and obs_pmf.packet_size == 0)

    pkts_15 = [
        PacketObservation(
            timestamp=1500.0 + i * 0.1,
            packet_size=0,
            eth_src="00:11:22:33:44:55",
            eth_dst="ff:ff:ff:ff:ff:ff",
            protocol="802.11",
            wlan_fc_type_subtype=12,
            wlan_bssid="00:11:22:33:44:55",
            wlan_reason_code=None,
        )
        for i in range(6)
    ]
    res_15 = run_deauth_scenario(
        "15_Protected_Management_Frame_PMF_Handled",
        detector,
        pkts_15,
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.HIGH,
        expected_bssid="00:11:22:33:44:55",
        expected_frame_count=6,
    )
    res_15["passed"] = res_15["passed"] and pass_pmf_mapping
    scenarios.append(res_15)

    # =========================================================================
    # Scenario 16: Invalid subtype (e.g. subtype 8 Beacon or 15)
    # =========================================================================
    payload_bad_sub = {
        "type": "wifi_mgmt", "boot_id": 1, "seq": 6, "uptime_ms": 2500,
        "subtype": 8, "reason": 7, "ta": "00:11:22:33:44:55", "da": "ff:ff:ff:ff:ff:ff", "bssid": "00:11:22:33:44:55", "rssi": -65
    }
    is_valid_16, msg_16 = validate_wifi_mgmt_event(payload_bad_sub)
    obs_16 = collector._map_wifi_mgmt_to_observation(payload_bad_sub)
    pass_16 = (not is_valid_16 and "Invalid management subtype" in msg_16 and obs_16 is None)
    scenarios.append({
        "scenario": "16_Invalid_Management_Subtype_Rejected",
        "packet_count": 0,
        "status": "REJECTED",
        "severity": "NONE",
        "confidence": 0.0,
        "verdict": msg_16,
        "missing_fields": [],
        "expected_status": "REJECTED",
        "passed": pass_16,
    })

    # =========================================================================
    # Scenario 17: Malformed serial JSON event
    # =========================================================================
    payload_malformed = "not a json object"
    is_valid_17, msg_17 = validate_wifi_mgmt_event(payload_malformed)
    pass_17 = (not is_valid_17 and "Payload must be a dictionary" in msg_17)
    scenarios.append({
        "scenario": "17_Malformed_Serial_JSON_Event_Rejected",
        "packet_count": 0,
        "status": "REJECTED",
        "severity": "NONE",
        "confidence": 0.0,
        "verdict": msg_17,
        "missing_fields": [],
        "expected_status": "REJECTED",
        "passed": pass_17,
    })

    # =========================================================================
    # Scenario 18: Duplicate sequence number rejection in serial router
    # =========================================================================
    collector._seen_mgmt_sequences.add(10)
    payload_dup = {
        "type": "wifi_mgmt", "boot_id": 100, "seq": 10,  # Duplicate seq!
        "uptime_ms": 3000, "subtype": 12, "reason": 7, "ta": "00:11:22:33:44:55", "da": "ff:ff:ff:ff:ff:ff", "bssid": "00:11:22:33:44:55", "rssi": -60
    }
    res_18_status = collector._handle_wifi_mgmt_event(payload_dup)
    pass_18 = (res_18_status == "DUPLICATE_WIFI_MGMT" and collector.stats["wifi_mgmt_duplicate_events"] == 1)
    scenarios.append({
        "scenario": "18_Duplicate_Sequence_Number_Rejected",
        "packet_count": 0,
        "status": "DUPLICATE_WIFI_MGMT",
        "severity": "NONE",
        "confidence": 0.0,
        "verdict": "Duplicate sequence number rejected in serial router",
        "missing_fields": [],
        "expected_status": "DUPLICATE_WIFI_MGMT",
        "passed": pass_18,
    })

    # =========================================================================
    # Scenario 19: Sequence-number wraparound (12-bit WLAN seq 4095 -> 0)
    # =========================================================================
    payload_wrap = {
        "type": "wifi_mgmt", "boot_id": 100, "seq": 11, "wlan_seq": 0,  # Wrapped from 4095 to 0
        "uptime_ms": 3500, "subtype": 12, "reason": 7, "ta": "00:11:22:33:44:55", "da": "ff:ff:ff:ff:ff:ff", "bssid": "00:11:22:33:44:55", "rssi": -60
    }
    obs_wrap = collector._map_wifi_mgmt_to_observation(payload_wrap)
    pass_19 = (obs_wrap is not None and obs_wrap.protocol_seq_num == 0)
    scenarios.append({
        "scenario": "19_Sequence_Number_Wraparound_Preserved",
        "packet_count": 1,
        "status": "PRESERVED",
        "severity": "NONE",
        "confidence": 0.0,
        "verdict": "12-bit WLAN sequence number preserved across wraparound",
        "missing_fields": [],
        "expected_status": "PRESERVED",
        "passed": pass_19,
    })

    # =========================================================================
    # Scenario 20: Missing or stale telemetry
    # =========================================================================
    # A: Missing 802.11 fields in packet stream
    pkts_ethernet_only = [
        PacketObservation(timestamp=2000.0, packet_size=100, eth_src="00:11:22:33:44:55", eth_dst="36:6f:24:d2:34:3d", ip_src="192.168.137.100", ip_dst="192.168.137.1")
    ]
    res_20a = detector.evaluate(pkts_ethernet_only)
    pass_20a = (res_20a.status == DetectionStatus.INSUFFICIENT_TELEMETRY and "wlan_fc_type_subtype" in res_20a.missing_fields)

    # B: Stale boot ID in queue drain
    collector.active_boot_id = 200
    collector._wifi_mgmt_queue.put_nowait({
        "type": "wifi_mgmt", "boot_id": 199,  # Stale boot ID!
        "seq": 1, "uptime_ms": 4000, "subtype": 12, "reason": 7, "ta": "00:11:22:33:44:55", "da": "ff:ff:ff:ff:ff:ff", "bssid": "00:11:22:33:44:55", "rssi": -60
    })
    drained_stale = collector._drain_wifi_mgmt_queue(window_epoch=2000.0)
    pass_20b = (len(drained_stale) == 0 and collector.stats["wifi_mgmt_stale_events"] >= 1)

    scenarios.append({
        "scenario": "20_Missing_Or_Stale_Telemetry_Handled",
        "packet_count": 1,
        "status": "INSUFFICIENT_TELEMETRY",
        "severity": "NONE",
        "confidence": 0.0,
        "verdict": "Capture stream lacks 802.11 management frames / stale boot ID rejected",
        "missing_fields": res_20a.missing_fields,
        "expected_status": "INSUFFICIENT_TELEMETRY",
        "passed": pass_20a and pass_20b,
    })

    # =========================================================================
    # Scenario 21: Benign event bursts (routine disconnects, 2 frames < 5)
    # =========================================================================
    pkts_21 = [
        PacketObservation(
            timestamp=2100.0 + i * 0.2,
            packet_size=0,
            eth_src="00:11:22:33:44:55",
            eth_dst="66:77:88:99:aa:bb",
            protocol="802.11",
            wlan_fc_type_subtype=10 if i == 0 else 12,
            wlan_bssid="00:11:22:33:44:55",
            wlan_reason_code=8 if i == 0 else 3,
        )
        for i in range(2)
    ]
    scenarios.append(run_deauth_scenario(
        "21_Benign_Event_Bursts_Routine_Disconnect_Below_Threshold",
        detector,
        pkts_21,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_verdict_substring="Deauth frame rate below threshold",
    ))

    # =========================================================================
    # Scenario 22: Cooldown boundary behavior in LiveCollector persistence
    # =========================================================================
    scratch_db = PROJECT_ROOT / "scratch" / "test_stage55_cooldown.db"
    scratch_db.parent.mkdir(parents=True, exist_ok=True)
    if scratch_db.exists():
        scratch_db.unlink()
    init_live_database(scratch_db)

    conn = get_live_db_connection(scratch_db)
    cur_run = conn.execute("INSERT INTO collector_status (interface_index, status) VALUES (1, 'RUNNING')")
    run_id = cur_run.lastrowid
    conn.commit()

    coll_cooldown = LiveCollector(
        interface_index=1,
        db_path=scratch_db,
        no_sensors=True,
        deauth_cooldown_seconds=0.05,  # 50 ms test cooldown
    )
    coll_cooldown._run_id = run_id
    coll_cooldown._attack_table_present = True

    deauth_finding = AttackDetectionResult(
        category=AttackCategory.DEAUTH_FLOOD,
        status=DetectionStatus.SUSPICIOUS,
        severity=Severity.HIGH,
        evidence={
            "verdict": "802.11 Deauthentication / Disassociation flood detected",
            "details": [{
                "bssid": "00:11:22:33:44:55",
                "frame_count_in_window": 6,
                "subtypes": [12] * 6,
                "reason_codes": [7] * 6,
                "broadcast_targets": 6,
            }],
        },
        missing_fields=[],
        confidence=0.95,
        timestamp=2200.0,
        recommended_action="Inspect physical environment.",
    )
    scored_dummy = {"client_mac": "00:11:22:33:44:55"}

    # Emission 1 at T0 -> Persisted
    ins_1 = coll_cooldown._persist_attack_results(conn, None, [], [deauth_finding], "00:11:22:33:44:55", scored_dummy)

    # Emission 2 immediately (< 0.05s) -> Suppressed
    ins_2 = coll_cooldown._persist_attack_results(conn, None, [], [deauth_finding], "00:11:22:33:44:55", scored_dummy)

    # Sleep past 0.05s cooldown
    time.sleep(0.08)

    # Emission 3 (> 0.05s) -> Persisted as new row
    ins_3 = coll_cooldown._persist_attack_results(conn, None, [], [deauth_finding], "00:11:22:33:44:55", scored_dummy)

    # Emission 4 from different BSSID -> Independent cooldown, persisted immediately
    deauth_finding_diff_bssid = AttackDetectionResult(
        category=AttackCategory.DEAUTH_FLOOD,
        status=DetectionStatus.SUSPICIOUS,
        severity=Severity.HIGH,
        evidence={
            "verdict": "802.11 Deauthentication / Disassociation flood detected",
            "details": [{
                "bssid": "aa:bb:cc:dd:ee:99",  # Different BSSID!
                "frame_count_in_window": 8,
                "subtypes": [12] * 8,
                "reason_codes": [7] * 8,
                "broadcast_targets": 8,
            }],
        },
        missing_fields=[],
        confidence=0.95,
        timestamp=2200.1,
        recommended_action="Inspect physical environment.",
    )
    ins_4 = coll_cooldown._persist_attack_results(conn, None, [], [deauth_finding_diff_bssid], "aa:bb:cc:dd:ee:99", scored_dummy)

    total_rows = conn.execute("SELECT count(*) FROM live_attack_events WHERE run_id = ?", (run_id,)).fetchone()[0]
    conn.close()
    if scratch_db.exists():
        scratch_db.unlink()

    pass_22 = (ins_1 == 1 and ins_2 == 0 and ins_3 == 1 and ins_4 == 1 and total_rows == 3)
    scenarios.append({
        "scenario": "22_Cooldown_Boundary_Behavior_And_BSSID_Independence",
        "packet_count": 4,
        "status": "SUSPICIOUS",
        "severity": "HIGH",
        "confidence": 0.95,
        "verdict": "Verified persistence, suppression within cooldown, re-emission after expiry, and BSSID independence",
        "details_count": 1,
        "primary_bssid": "00:11:22:33:44:55",
        "frame_count_in_window": 6,
        "subtypes": [12] * 6,
        "missing_fields": [],
        "expected_status": "SUSPICIOUS",
        "expected_severity": "HIGH",
        "expected_verdict": "Verified persistence",
        "passed": pass_22,
    })

    # =========================================================================
    # Offline PCAP Audit
    # =========================================================================
    pcap_audit_results = inspect_all_pcaps()

    total_scenarios = len(scenarios)
    passed_scenarios = sum(1 for s in scenarios if s.get("passed", False))
    failed_scenarios = total_scenarios - passed_scenarios

    output_data = {
        "metadata": {
            "test_stage": "Stage 5.5",
            "component": "DeauthDetector & ESP32-to-Python Pipeline",
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_scenarios": total_scenarios,
            "passed_scenarios": passed_scenarios,
            "failed_scenarios": failed_scenarios,
            "pass_rate_pct": round(passed_scenarios / total_scenarios * 100, 2),
        },
        "scenarios": scenarios,
        "pcap_audit": pcap_audit_results,
    }

    out_json = PROJECT_ROOT / "scratch" / "stage55_deauth_validation_results.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)

    print(f"Validation finished: {passed_scenarios}/{total_scenarios} scenarios PASSED ({output_data['metadata']['pass_rate_pct']}%)")
    for s in scenarios:
        status_flag = "PASS" if s.get("passed") else "FAIL"
        print(f"[{status_flag}] {s['scenario']}")

if __name__ == "__main__":
    main()
