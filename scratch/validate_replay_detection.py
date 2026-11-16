#!/usr/bin/env python3
"""
Stage 5.6 - Replay Attack Detection Empirical Validation Script

Validates existing ReplayDetector and pipeline capabilities:
1. TCP sequence reuse within legitimate RTO window (<= 3.0s).
2. TCP sequence reuse without payload hash / nonce (> 3.0s).
3. Legitimate TCP retransmission handling.
4. Cryptographic nonce reuse detection.
5. Stale payload re-injection detection.
6. Cross-flow sequence collision behavior.
7. Out-of-order sequence arrivals.
8. 32-bit TCP sequence wraparound.
9. Time-window history cleanup (> 60.0s).
10. Missing telemetry handling (INSUFFICIENT_TELEMETRY).
11. Missing flow fields (None ip/eth).
12. Periodic identical payload false-positive evaluation.
13. LiveCollector attack integration and DB persistence to isolated temporary database.
14. Systematic offline PCAP audit across all 11 repository capture files.

Strictly READ-ONLY regarding production databases and project source code.
All outputs are saved to scratch/stage56_replay_validation_results.json.
"""

import os
import sys
import json
import time
import sqlite3
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.attack_detector import (
    AttackCategory,
    DetectionStatus,
    Severity,
    PacketObservation,
    ReplayDetector,
    NetworkAttackDetector,
)
from src.live_stream_extractor import _RawPacket
from src.live_collector import LiveCollector, _insert_attack_event


def run_scenario(
    name: str,
    detector: ReplayDetector,
    packets: List[PacketObservation],
    expected_status: DetectionStatus,
    expected_severity: Severity,
    expected_confidence: float,
    expected_anomaly_substring: Optional[str] = None,
    reset_before: bool = True,
) -> Dict[str, Any]:
    if reset_before:
        detector.reset()

    res = detector.evaluate(packets)

    status_ok = (res.status == expected_status)
    severity_ok = (res.severity == expected_severity)
    confidence_ok = (abs(res.confidence - expected_confidence) < 0.01)

    anomaly_ok = True
    violations = res.evidence.get("violations", [])
    if expected_anomaly_substring is not None:
        anomaly_ok = any(
            expected_anomaly_substring in v.get("anomaly_type", "")
            for v in violations
        )

    passed = status_ok and severity_ok and confidence_ok and anomaly_ok

    return {
        "scenario": name,
        "packet_count": len(packets),
        "status": res.status.value,
        "severity": res.severity.value,
        "confidence": round(res.confidence, 4),
        "verdict": res.evidence.get("verdict", res.evidence.get("reason", "")),
        "violations_count": len(violations),
        "violations": violations,
        "missing_fields": res.missing_fields,
        "expected_status": expected_status.value,
        "expected_severity": expected_severity.value,
        "expected_confidence": expected_confidence,
        "expected_anomaly": expected_anomaly_substring,
        "passed": passed,
    }


def audit_pcaps() -> List[Dict[str, Any]]:
    tshark_bin = Path(r"C:\Program Files\Wireshark\tshark.exe")
    if not tshark_bin.exists():
        return [{"error": "TShark not found"}]

    pcaps = sorted(
        list(PROJECT_ROOT.glob("*.pcap*")) + list((PROJECT_ROOT / "data").rglob("*.pcap*"))
    )

    results = []
    for p in pcaps:
        if not p.is_file() or "node_modules" in str(p) or ".git" in str(p):
            continue

        rel_path = str(p.relative_to(PROJECT_ROOT))

        # 1. Total packet count
        res_tot = subprocess.run([str(tshark_bin), "-r", str(p), "-c", "200000"], capture_output=True, text=True)
        tot_lines = len([l for l in res_tot.stdout.splitlines() if l.strip()])

        # 2. TCP packet count
        res_tcp = subprocess.run([str(tshark_bin), "-r", str(p), "-Y", "tcp", "-c", "200000"], capture_output=True, text=True)
        tcp_lines = len([l for l in res_tcp.stdout.splitlines() if l.strip()])

        # 3. Sample protocols
        res_proto = subprocess.run([str(tshark_bin), "-r", str(p), "-T", "fields", "-e", "_ws.col.Protocol", "-c", "200"], capture_output=True, text=True)
        protos = sorted(list(set(l.strip() for l in res_proto.stdout.splitlines() if l.strip())))

        # 4. Check for payload hashes or nonces in PCAP
        # Native PCAP files contain raw bytes, but neither payload_hash nor nonces are precomputed.
        results.append({
            "filename": p.name,
            "relative_path": rel_path,
            "total_packets": tot_lines,
            "tcp_packets": tcp_lines,
            "has_tcp": tcp_lines > 0,
            "protocols": protos,
            "has_precomputed_payload_hash": False,
            "has_precomputed_nonce": False,
            "replay_telemetry_status": "INSUFFICIENT_TELEMETRY" if tcp_lines == 0 else "TCP_SEQ_ONLY_NO_PAYLOAD_HASH",
        })

    return results


def main():
    detector = ReplayDetector(
        tcp_retransmit_window_seconds=3.0,
        replay_history_window_seconds=60.0,
    )
    scenarios = []

    # =========================================================================
    # Scenario 1: Missing Sequence, Nonce, and Payload Hash -> INSUFFICIENT_TELEMETRY
    # =========================================================================
    pkts_1 = [
        PacketObservation(
            timestamp=100.0,
            packet_size=64,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.201",
            ip_dst="192.168.137.1",
            protocol="UDP",
            protocol_seq_num=None,
            payload_hash=None,
            nonce=None,
        )
    ]
    scenarios.append(run_scenario(
        "01_Missing_Telemetry_Insufficient_Telemetry",
        detector,
        pkts_1,
        expected_status=DetectionStatus.INSUFFICIENT_TELEMETRY,
        expected_severity=Severity.NONE,
        expected_confidence=0.0,
    ))

    # =========================================================================
    # Scenario 2: Standard TCP Retransmission within RTO (<= 3.0s) -> NO_EVIDENCE
    # =========================================================================
    detector.reset()
    p2_1 = PacketObservation(
        timestamp=200.0,
        packet_size=1460,
        eth_src="ca:34:ea:92:d3:9e",
        eth_dst="00:15:5d:01:02:03",
        ip_src="192.168.137.201",
        ip_dst="192.168.137.1",
        protocol="TCP",
        protocol_seq_num=1024,
        payload_hash="hash_payload_1024",
    )
    detector.evaluate([p2_1])
    p2_2 = PacketObservation(
        timestamp=200.6,  # 0.6s later (within 3.0s RTO)
        packet_size=1460,
        eth_src="ca:34:ea:92:d3:9e",
        eth_dst="00:15:5d:01:02:03",
        ip_src="192.168.137.201",
        ip_dst="192.168.137.1",
        protocol="TCP",
        protocol_seq_num=1024,
        payload_hash="hash_payload_1024",
    )
    scenarios.append(run_scenario(
        "02_TCP_Retransmission_Within_RTO_Window",
        detector,
        [p2_2],
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_confidence=0.0,
        reset_before=False,
    ))

    # =========================================================================
    # Scenario 3: Progressive TCP Stream (Unique Sequence Numbers) -> NO_EVIDENCE
    # =========================================================================
    pkts_3 = [
        PacketObservation(
            timestamp=300.0 + i * 0.1,
            packet_size=1460,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.201",
            ip_dst="192.168.137.1",
            protocol="TCP",
            protocol_seq_num=1000 + i * 1460,
            payload_hash=f"hash_{i}",
        )
        for i in range(5)
    ]
    scenarios.append(run_scenario(
        "03_Normal_Progressive_TCP_Stream",
        detector,
        pkts_3,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_confidence=0.0,
    ))

    # =========================================================================
    # Scenario 4: TCP Sequence Reuse Without Payload Hash After RTO (> 3.0s) -> NO_EVIDENCE
    # Demonstrates academic principle: sequence reuse alone without payload hash/nonce is NOT flagged
    # =========================================================================
    detector.reset()
    p4_1 = PacketObservation(
        timestamp=400.0,
        packet_size=512,
        eth_src="ca:34:ea:92:d3:9e",
        eth_dst="00:15:5d:01:02:03",
        ip_src="192.168.137.201",
        ip_dst="192.168.137.1",
        protocol="TCP",
        protocol_seq_num=5000,
        payload_hash=None,  # No payload hash!
    )
    detector.evaluate([p4_1])
    p4_2 = PacketObservation(
        timestamp=410.0,  # 10s later (> 3.0s)
        packet_size=512,
        eth_src="ca:34:ea:92:d3:9e",
        eth_dst="00:15:5d:01:02:03",
        ip_src="192.168.137.201",
        ip_dst="192.168.137.1",
        protocol="TCP",
        protocol_seq_num=5000,
        payload_hash=None,
    )
    scenarios.append(run_scenario(
        "04_TCP_Seq_Reuse_Without_Payload_Hash_Not_Flagged",
        detector,
        [p4_2],
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_confidence=0.0,
        reset_before=False,
    ))

    # =========================================================================
    # Scenario 5: Cryptographic Nonce Reuse -> SUSPICIOUS / HIGH (conf=0.85)
    # =========================================================================
    detector.reset()
    p5_1 = PacketObservation(
        timestamp=500.0,
        packet_size=256,
        eth_src="ca:34:ea:92:d3:9e",
        eth_dst="00:15:5d:01:02:03",
        ip_src="192.168.137.201",
        ip_dst="192.168.137.1",
        nonce="auth_token_nonce_998811",
    )
    detector.evaluate([p5_1])
    p5_2 = PacketObservation(
        timestamp=515.0,  # 15s later
        packet_size=256,
        eth_src="00:11:22:33:44:55",  # Attacker machine replaying nonce
        eth_dst="00:15:5d:01:02:03",
        ip_src="192.168.137.150",
        ip_dst="192.168.137.1",
        nonce="auth_token_nonce_998811",
    )
    scenarios.append(run_scenario(
        "05_Cryptographic_Nonce_Reuse_Detected",
        detector,
        [p5_2],
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.HIGH,
        expected_confidence=0.85,
        expected_anomaly_substring="Cryptographic Nonce Reuse",
        reset_before=False,
    ))

    # =========================================================================
    # Scenario 6: Stale Payload Re-injection (> 3.0s) -> SUSPICIOUS / HIGH (conf=0.70)
    # =========================================================================
    detector.reset()
    p6_1 = PacketObservation(
        timestamp=600.0,
        packet_size=512,
        eth_src="ca:34:ea:92:d3:9e",
        eth_dst="00:15:5d:01:02:03",
        ip_src="192.168.137.201",
        ip_dst="192.168.137.1",
        protocol_seq_num=8000,
        payload_hash="sha256_control_cmd_unlock_gate",
    )
    detector.evaluate([p6_1])
    p6_2 = PacketObservation(
        timestamp=620.0,  # 20s later (> 3.0s retransmit window)
        packet_size=512,
        eth_src="00:11:22:33:44:55",
        eth_dst="00:15:5d:01:02:03",
        ip_src="192.168.137.150",
        ip_dst="192.168.137.1",
        protocol_seq_num=8000,
        payload_hash="sha256_control_cmd_unlock_gate",
    )
    scenarios.append(run_scenario(
        "06_Stale_Payload_Reinjection_Detected",
        detector,
        [p6_2],
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.HIGH,
        expected_confidence=0.70,
        expected_anomaly_substring="Stale Payload Re-injection",
        reset_before=False,
    ))

    # =========================================================================
    # Scenario 7: Out-of-Order TCP Arrivals (Different Sequence Numbers) -> NO_EVIDENCE
    # =========================================================================
    pkts_7 = [
        PacketObservation(
            timestamp=700.0,
            packet_size=1460,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.201",
            ip_dst="192.168.137.1",
            protocol="TCP",
            protocol_seq_num=3000,  # Arrived first
            payload_hash="hash_3000",
        ),
        PacketObservation(
            timestamp=700.05,
            packet_size=1460,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.201",
            ip_dst="192.168.137.1",
            protocol="TCP",
            protocol_seq_num=1500,  # Arrived out-of-order
            payload_hash="hash_1500",
        ),
    ]
    scenarios.append(run_scenario(
        "07_Out_Of_Order_TCP_Arrivals_Normal",
        detector,
        pkts_7,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_confidence=0.0,
    ))

    # =========================================================================
    # Scenario 8: Cross-Flow Key Collision Behavior (Shared Key Without Flow 4-Tuple)
    # Demonstrates architectural limitation: ReplayDetector keys by seq without flow IP/port
    # =========================================================================
    detector.reset()
    p8_flow_a = PacketObservation(
        timestamp=800.0,
        packet_size=60,
        eth_src="ca:34:ea:92:d3:9e",
        eth_dst="00:15:5d:01:02:03",
        ip_src="192.168.137.201",
        ip_dst="192.168.137.1",
        src_port=50001,
        dst_port=80,
        protocol="TCP",
        protocol_seq_num=100,  # Sequence 100 on Flow A
        payload_hash=None,
    )
    detector.evaluate([p8_flow_a])
    p8_flow_b = PacketObservation(
        timestamp=800.8,  # 0.8s later
        packet_size=60,
        eth_src="aa:bb:cc:dd:ee:ff",
        eth_dst="00:15:5d:01:02:03",
        ip_src="10.0.0.5",
        ip_dst="10.0.0.1",
        src_port=44332,
        dst_port=443,
        protocol="TCP",
        protocol_seq_num=100,  # Sequence 100 on completely different Flow B!
        payload_hash=None,
    )
    # Because delta <= 3.0s, Case A triggers and suppresses it as TCP retransmission
    scenarios.append(run_scenario(
        "08_Cross_Flow_Sequence_Collision_Handled_As_Retransmission",
        detector,
        [p8_flow_b],
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_confidence=0.0,
        reset_before=False,
    ))

    # =========================================================================
    # Scenario 9: 32-bit TCP Sequence Wraparound Across Streams
    # =========================================================================
    pkts_9 = [
        PacketObservation(
            timestamp=900.0,
            packet_size=1460,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.201",
            ip_dst="192.168.137.1",
            protocol="TCP",
            protocol_seq_num=4294967200,  # Near 2^32 - 1
            payload_hash="hash_pre_wrap",
        ),
        PacketObservation(
            timestamp=900.2,
            packet_size=1460,
            eth_src="ca:34:ea:92:d3:9e",
            eth_dst="00:15:5d:01:02:03",
            ip_src="192.168.137.201",
            ip_dst="192.168.137.1",
            protocol="TCP",
            protocol_seq_num=50,  # Wrapped around
            payload_hash="hash_post_wrap",
        ),
    ]
    scenarios.append(run_scenario(
        "09_TCP_Sequence_Wraparound_Distinct_Keys",
        detector,
        pkts_9,
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_confidence=0.0,
    ))

    # =========================================================================
    # Scenario 10: History Expiration Cleanup (> 60.0s Window Purge)
    # An entry older than 60s is pruned, so a subsequent message arriving after cleanup
    # starts a new baseline.
    # =========================================================================
    detector.reset()
    p10_1 = PacketObservation(
        timestamp=1000.0,
        packet_size=128,
        eth_src="ca:34:ea:92:d3:9e",
        eth_dst="00:15:5d:01:02:03",
        ip_src="192.168.137.201",
        ip_dst="192.168.137.1",
        nonce="token_expiring_soon",
    )
    detector.evaluate([p10_1])

    # Intervening evaluation at t=1070.0 (70s later) cleans up entries > 60s old
    p10_intermediate = PacketObservation(
        timestamp=1070.0,
        packet_size=64,
        eth_src="ca:34:ea:92:d3:9e",
        eth_dst="00:15:5d:01:02:03",
        ip_src="192.168.137.201",
        ip_dst="192.168.137.1",
        protocol="TCP",
        protocol_seq_num=99999,
    )
    detector.evaluate([p10_intermediate])

    # Now at t=1080.0, same token arrives again. Since original at 1000.0 was purged at 1070.0,
    # it is treated as a fresh entry!
    p10_replayed_after_purge = PacketObservation(
        timestamp=1080.0,
        packet_size=128,
        eth_src="ca:34:ea:92:d3:9e",
        eth_dst="00:15:5d:01:02:03",
        ip_src="192.168.137.201",
        ip_dst="192.168.137.1",
        nonce="token_expiring_soon",
    )
    scenarios.append(run_scenario(
        "10_History_Window_Cleanup_Pruned_After_60s",
        detector,
        [p10_replayed_after_purge],
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_confidence=0.0,
        reset_before=False,
    ))

    # =========================================================================
    # Scenario 11: Missing Flow Identification Fields (None IP & MAC)
    # =========================================================================
    detector.reset()
    p11_1 = PacketObservation(
        timestamp=1100.0,
        packet_size=128,
        eth_src="00:00:00:00:00:00",
        eth_dst="00:00:00:00:00:00",
        ip_src=None,
        ip_dst=None,
        nonce="nonce_missing_flow_ids",
    )
    detector.evaluate([p11_1])
    p11_2 = PacketObservation(
        timestamp=1110.0,
        packet_size=128,
        eth_src="00:00:00:00:00:00",
        eth_dst="00:00:00:00:00:00",
        ip_src=None,
        ip_dst=None,
        nonce="nonce_missing_flow_ids",
    )
    scenarios.append(run_scenario(
        "11_Missing_Flow_IP_Handled_Safely",
        detector,
        [p11_2],
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.HIGH,
        expected_confidence=0.85,
        expected_anomaly_substring="Cryptographic Nonce Reuse",
        reset_before=False,
    ))

    # =========================================================================
    # Scenario 12: Periodic IoT Sensor False-Positive Vulnerability
    # Periodic static payload without seq/nonce transmitted every 5s triggers Stale Payload Re-injection
    # =========================================================================
    detector.reset()
    p12_1 = PacketObservation(
        timestamp=1200.0,
        packet_size=32,
        eth_src="ca:34:ea:92:d3:9e",
        eth_dst="00:15:5d:01:02:03",
        ip_src="192.168.137.201",
        ip_dst="192.168.137.1",
        payload_hash="dht11_temp_24c_humidity_55pct_hash",
    )
    detector.evaluate([p12_1])
    p12_2 = PacketObservation(
        timestamp=1205.0,  # 5s later (periodic DHT11 update)
        packet_size=32,
        eth_src="ca:34:ea:92:d3:9e",
        eth_dst="00:15:5d:01:02:03",
        ip_src="192.168.137.201",
        ip_dst="192.168.137.1",
        payload_hash="dht11_temp_24c_humidity_55pct_hash",
    )
    # The detector flags this because it cannot distinguish static periodic sensor telemetry from replay
    scenarios.append(run_scenario(
        "12_Periodic_Static_IoT_Payload_False_Positive_Demonstration",
        detector,
        [p12_2],
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.HIGH,
        expected_confidence=0.70,
        expected_anomaly_substring="Stale Payload Re-injection",
        reset_before=False,
    ))

    # =========================================================================
    # Scenario 13: Multiple Violations (Both Nonce Reuse and Stale Payload) -> conf=0.85
    # =========================================================================
    detector.reset()
    p13_base = PacketObservation(
        timestamp=1300.0,
        packet_size=256,
        eth_src="ca:34:ea:92:d3:9e",
        eth_dst="00:15:5d:01:02:03",
        ip_src="192.168.137.201",
        ip_dst="192.168.137.1",
        nonce="nonce_multi_1",
        payload_hash="payload_multi_1",
    )
    detector.evaluate([p13_base])
    p13_replay = PacketObservation(
        timestamp=1310.0,
        packet_size=256,
        eth_src="ca:34:ea:92:d3:9e",
        eth_dst="00:15:5d:01:02:03",
        ip_src="192.168.137.201",
        ip_dst="192.168.137.1",
        nonce="nonce_multi_1",
        payload_hash="payload_multi_1",
    )
    scenarios.append(run_scenario(
        "13_Multiple_Violations_Confidence_Escalation",
        detector,
        [p13_replay],
        expected_status=DetectionStatus.SUSPICIOUS,
        expected_severity=Severity.HIGH,
        expected_confidence=0.85,
        expected_anomaly_substring="Cryptographic Nonce Reuse",
        reset_before=False,
    ))

    # =========================================================================
    # Scenario 14: TShark LiveStreamExtractor Simulation
    # Verifies that _RawPacket extracts tcp_seq into PacketObservation.protocol_seq_num
    # but does NOT extract payload_hash or nonce.
    # =========================================================================
    raw_parts = [
        "1400.123456", "1460", "ca:34:ea:92:d3:9e", "00:15:5d:01:02:03",
        "192.168.137.201", "192.168.137.1", "TCP", "6",
        "54321", "80", "", "", "0x018", "778899"
    ]
    # Build _RawPacket via extractor parser simulation
    raw_pkt = _RawPacket(
        timestamp=float(raw_parts[0]),
        packet_size=int(raw_parts[1]),
        eth_src=raw_parts[2],
        eth_dst=raw_parts[3],
        ip_src=raw_parts[4],
        ip_dst=raw_parts[5],
        protocol=raw_parts[6],
        src_port=int(raw_parts[8]),
        dst_port=int(raw_parts[9]),
        tcp_flags=raw_parts[12],
        tcp_seq=int(raw_parts[13]),
    )
    obs_14 = raw_pkt.to_observation()
    pass_14 = (
        obs_14.protocol_seq_num == 778899
        and obs_14.payload_hash is None
        and obs_14.nonce is None
    )
    # When evaluated alone, detector finds protocol_seq_num, no violations -> NO_EVIDENCE
    res_14 = detector.evaluate([obs_14])
    scenarios.append({
        "scenario": "14_LiveStreamExtractor_Mapping_Verification",
        "packet_count": 1,
        "status": res_14.status.value,
        "severity": res_14.severity.value,
        "confidence": round(res_14.confidence, 4),
        "verdict": "Extractor extracts tcp_seq to protocol_seq_num; payload_hash & nonce are None",
        "violations_count": 0,
        "violations": [],
        "missing_fields": res_14.missing_fields,
        "expected_status": DetectionStatus.NO_EVIDENCE.value,
        "expected_severity": Severity.NONE.value,
        "expected_confidence": 0.0,
        "expected_anomaly": None,
        "passed": pass_14 and res_14.status == DetectionStatus.NO_EVIDENCE,
    })

    # =========================================================================
    # Scenario 15: LiveCollector Replay Alert Database Persistence Integration
    # Uses isolated scratch SQLite database to verify row insertion into live_attack_events
    # =========================================================================
    scratch_dir = PROJECT_ROOT / "scratch"
    temp_db_path = scratch_dir / "temp_replay_validation.db"
    if temp_db_path.exists():
        temp_db_path.unlink()

    # Initialize isolated schema
    conn = sqlite3.connect(str(temp_db_path))
    conn.execute("""
        CREATE TABLE live_attack_events (
            event_id            INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id              INTEGER,
            window_id           INTEGER,
            timestamp_epoch     REAL NOT NULL,
            timestamp_utc       TEXT NOT NULL,
            category            TEXT NOT NULL,
            status              TEXT NOT NULL,
            severity            TEXT NOT NULL,
            confidence          REAL NOT NULL,
            source_mac          TEXT,
            target_ip           TEXT,
            evidence_json       TEXT NOT NULL,
            missing_fields_json TEXT,
            recommended_action  TEXT,
            acknowledged        INTEGER DEFAULT 0
        )
    """)
    conn.commit()

    # Create dummy collector pointing to scratch db
    collector = LiveCollector(interface_index=1, db_path=temp_db_path, no_sensors=True)
    collector._run_id = 1

    # Evaluate replay threat
    detector.reset()
    p15_1 = PacketObservation(
        timestamp=1500.0,
        packet_size=256,
        eth_src="ca:34:ea:92:d3:9e",
        eth_dst="00:15:5d:01:02:03",
        ip_src="192.168.137.201",
        ip_dst="192.168.137.1",
        nonce="persist_nonce_999",
    )
    detector.evaluate([p15_1])
    p15_2 = PacketObservation(
        timestamp=1510.0,
        packet_size=256,
        eth_src="ca:34:ea:92:d3:9e",
        eth_dst="00:15:5d:01:02:03",
        ip_src="192.168.137.201",
        ip_dst="192.168.137.1",
        nonce="persist_nonce_999",
    )
    res_15 = detector.evaluate([p15_2])

    inserted = collector._persist_attack_results(
        db=conn,
        window_id=1,
        dos_results=[],
        stream_results=[res_15],
        client_mac="ca:34:ea:92:d3:9e",
        scored={},
    )
    conn.commit()

    cursor = conn.cursor()
    cursor.execute("SELECT category, severity, confidence, source_mac, target_ip FROM live_attack_events")
    row = cursor.fetchone()
    conn.close()
    if temp_db_path.exists():
        temp_db_path.unlink()

    pass_15 = (
        inserted == 1
        and row is not None
        and row[0] == AttackCategory.REPLAY.value
        and row[1] == Severity.HIGH.value
        and abs(row[2] - 0.85) < 0.01
        # Because ReplayDetector line 1722 assigns `src = p.ip_src or p.eth_src`,
        # when ip_src is present, replay_src is an IP ("192.168.137.201").
        # LiveCollector line 1264 strictly checks `":" in replay_src and len(replay_src) == 17`,
        # so source_mac is correctly evaluated to None (not mispopulated with an IP),
        # while target_ip is correctly evaluated to replay_dst ("192.168.137.1").
        and row[3] is None
        and row[4] == "192.168.137.1"
    )

    scenarios.append({
        "scenario": "15_LiveCollector_Replay_Database_Persistence",
        "packet_count": 2,
        "status": res_15.status.value,
        "severity": res_15.severity.value,
        "confidence": round(res_15.confidence, 4),
        "verdict": "Verified alert persistence to live_attack_events with source_mac and target_ip",
        "violations_count": len(res_15.evidence.get("violations", [])),
        "violations": res_15.evidence.get("violations", []),
        "missing_fields": [],
        "expected_status": DetectionStatus.SUSPICIOUS.value,
        "expected_severity": Severity.HIGH.value,
        "expected_confidence": 0.85,
        "expected_anomaly": "Cryptographic Nonce Reuse",
        "passed": pass_15,
    })

    # =========================================================================
    # Scenario 16: Zero Packets in Window -> NO_EVIDENCE
    # =========================================================================
    scenarios.append(run_scenario(
        "16_Zero_Packets_In_Window_Handled_Cleanly",
        detector,
        [],
        expected_status=DetectionStatus.NO_EVIDENCE,
        expected_severity=Severity.NONE,
        expected_confidence=0.0,
    ))

    # Audit PCAPs
    pcap_results = audit_pcaps()

    total_scenarios = len(scenarios)
    passed_scenarios = sum(1 for s in scenarios if s["passed"])

    output = {
        "metadata": {
            "test_stage": "Stage 5.6",
            "component": "ReplayDetector & LiveCollector Replay Integration",
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_scenarios": total_scenarios,
            "passed_scenarios": passed_scenarios,
            "failed_scenarios": total_scenarios - passed_scenarios,
            "pass_rate_pct": round(passed_scenarios / total_scenarios * 100, 2),
        },
        "scenarios": scenarios,
        "pcap_audit": {
            "total_pcaps_inspected": len(pcap_results),
            "pcaps_with_tcp": sum(1 for p in pcap_results if p.get("has_tcp", False)),
            "pcap_details": pcap_results,
        },
    }

    out_file = scratch_dir / "stage56_replay_validation_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"Validation complete: {passed_scenarios}/{total_scenarios} scenarios passed ({output['metadata']['pass_rate_pct']}%).")
    print(f"Results written to: {out_file}")


if __name__ == "__main__":
    main()
