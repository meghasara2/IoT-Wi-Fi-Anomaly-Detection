# STAGE 5.6 — REPLAY ATTACK DETECTION VALIDATION REPORT

**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Workspace:** `C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection`  
**Execution Mode:** Strictly Read-Only  
**Status:** Complete  
**Final Assessment:** **PASS WITH LIMITATIONS**

---

## 1. Executive Summary

Stage 5.6 conducted an empirical, read-only validation of the project's replay attack detection capabilities. The audit investigated the full pipeline across [`src/attack_detector.py`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/attack_detector.py), [`src/live_stream_extractor.py`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/live_stream_extractor.py), and [`src/live_collector.py`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/live_collector.py), evaluated 16 synthetic scenarios, and audited all 11 offline PCAP capture files.

### Key Validation Outcomes:
1. **Synthetic Validation Suite:** **16 / 16 scenarios PASSED (100.0%)** ([`scratch/stage56_replay_validation_results.json`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/scratch/stage56_replay_validation_results.json)).
2. **Regression Test Suite:** **125 / 125 tests PASSED (100.0%)** (56/56 in [`tests/test_attack_detector.py`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/tests/test_attack_detector.py) and 69/69 in [`tests/test_live_collector_attack_integration.py`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/tests/test_live_collector_attack_integration.py)).
3. **Offline PCAP Audit:** **11 / 11 PCAPs audited**. All files contain standard TCP/UDP traffic. However, none of the PCAP files or live extraction pipelines compute payload hashes or extract cryptographic nonces. In offline replay evaluations without synthetic enrichment, the detector honestly reports `INSUFFICIENT_TELEMETRY` or `NO_EVIDENCE`.
4. **Database Integrity:** Production databases (`data/live_monitoring.db` and `data/iot_anomaly.db`) remained completely untouched; post-run SHA-256 hashes match baseline values bit-for-bit.

---

## 2. Complete Source-Code Audit & Pipeline Trace

```
TShark Process (Live / PCAP)
  - Options: -e tcp.seq -e ip.src -e ip.dst
  - Does NOT extract payload bytes (-e data) or compute hashes
                     │
                     ▼
LiveStreamExtractor / _RawPacket (src/live_stream_extractor.py: L131-L145)
  - Maps tcp_seq -> PacketObservation.protocol_seq_num
  - Leaves payload_hash = None, nonce = None
                     │
                     ▼
Observation Stream Merge (src/live_collector.py: L1583-L1595)
  - Combines TShark IP traffic + ESP32 Wi-Fi management frames
                     │
                     ▼
ReplayDetector.evaluate() (src/attack_detector.py: L1647-L1806)
  - Evaluates: payload_hash, nonce, protocol_seq_num
  - If all None: returns INSUFFICIENT_TELEMETRY
  - Suppresses retransmissions within RTO (<= 3.0s)
  - Flags Nonce Reuse (conf=0.85) or Stale Payload Re-injection (conf=0.70)
                     │
                     ▼
LiveCollector._persist_attack_results() (src/live_collector.py: L1252-L1269)
  - Routes AttackCategory.REPLAY alerts to live_attack_events table
```

### Detailed Component Analysis:

1. **Replay Detection Engine ([`src/attack_detector.py`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/attack_detector.py#L1647-L1806)):**
   - **Lines 1694–1716:** Filter `evaluable_packets`. If `p.payload_hash`, `p.nonce`, and `p.protocol_seq_num` are all `None`, the detector emits `status = INSUFFICIENT_TELEMETRY`, with `missing_fields = ["payload_hash", "protocol_seq_num", "nonce"]`.
   - **Lines 1721–1723:** `key = p.payload_hash or p.nonce or f"seq_{p.protocol_seq_num}"`.
   - **Lines 1736–1743 (Legitimate Retransmission):** If `p.protocol_seq_num == prev_seq` and `time_delta <= 3.0s` (`tcp_retransmit_window_seconds`), the packet is skipped (`continue`) as a routine network retransmission.
   - **Lines 1745–1753 (Nonce Reuse):** If `p.nonce == prev_nonce`, flags `"Cryptographic Nonce Reuse"`.
   - **Lines 1755–1764 (Stale Payload):** If `p.payload_hash` is present and `time_delta > 3.0s`, flags `"Stale Payload Re-injection"`.
   - **Lines 1768–1775 (History Pruning):** Purges entries older than `60.0s` (`replay_history_window_seconds`).
   - **Lines 1791–1805:** Emits `status = SUSPICIOUS`, `severity = Severity.HIGH`, with `confidence = 0.85` (if nonce reuse) or `0.70` (if payload re-injection).

2. **Telemetry Extraction Boundary ([`src/live_stream_extractor.py`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/live_stream_extractor.py#L340-L416)):**
   - TShark is invoked with `-e tcp.seq` (line 341).
   - In `_RawPacket.to_observation()` (lines 131–145):
     `protocol_seq_num` is mapped from `self.tcp_seq`.
   - Crucially, **neither payload data nor cryptographic nonces are extracted**. `payload_hash` and `nonce` remain `None`.

3. **Collector Ingress & Database Persistence ([`src/live_collector.py`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/live_collector.py#L1252-L1269)):**
   - `_persist_attack_results()` intercepts `AttackCategory.REPLAY`.
   - Extracts `replay_src` and `replay_dst` from `att_res.evidence["violations"][0]`.
   - Lines 1264–1265:
     ```python
     source_mac=replay_src if (replay_src and ":" in replay_src and len(replay_src) == 17) else None,
     target_ip=replay_dst if (replay_dst and "." in replay_dst) else None,
     ```
     Because `ReplayDetector` line 1722 assigns `src = p.ip_src or p.eth_src`, for IP packets `replay_src` holds an IP address. The validator ensures `source_mac` is not polluted with an IP address (storing `None`), while `target_ip` correctly records `replay_dst`.
   - Inserts row into `live_attack_events` in `data/live_monitoring.db`.

---

## 3. Existing Replay Detection Logic & Academic Principles

The implementation in [`ReplayDetector`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/attack_detector.py#L1647-L1662) strictly implements the following scientific principles:

1. **Packet Size and Timing Invariance:**
   - Repetitive transmission timings and identical packet sizes **do not** prove a replay attack. Periodic IoT sensors (e.g., DHT11 temperature telemetry) routinely transmit packets of identical size at periodic intervals.
2. **TCP Sequence Reuse vs. Application Replay:**
   - Under standard TCP operation, duplicate sequence numbers within the retransmission timeout ($RTO \le 3.0\text{ s}$) represent legitimate network packet loss recovery.
   - Reused TCP sequence numbers occurring $> 3.0\text{ s}$ later **without** payload hash or nonce are **NOT** flagged as replay attacks. ReplayDetector requires cryptographic nonce duplication or identical payload content to establish a replay threat.
3. **Telemetry Honesty:**
   - If sequence numbers, nonces, and payload hashes are absent (e.g., UDP/ICMP traffic), the detector emits `INSUFFICIENT_TELEMETRY` rather than hallucinating alerts.

---

## 4. Synthetic Scenario Validation Results

All 16 scenarios were executed via [`scratch/validate_replay_detection.py`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/scratch/validate_replay_detection.py) with structured results written to [`scratch/stage56_replay_validation_results.json`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/scratch/stage56_replay_validation_results.json):

| ID | Scenario Name | Test Inputs & Conditions | Expected Status / Severity | Actual Status / Severity | Confidence | Key Evidence & Verdict | Verdict |
|---|---|---|---|---|---|---|---|
| **01** | Missing Telemetry | Pure UDP packet (no seq, nonce, or hash) | `INSUFFICIENT_TELEMETRY` / `NONE` | `INSUFFICIENT_TELEMETRY` / `NONE` | 0.00 | Missing `["payload_hash", "protocol_seq_num", "nonce"]` | **PASS** |
| **02** | Retransmission within RTO | TCP seq 1024 repeated at $\Delta t = 0.6\text{ s} \le 3.0\text{ s}$ | `NO_EVIDENCE` / `NONE` | `NO_EVIDENCE` / `NONE` | 0.00 | Retransmission within RTO safely ignored | **PASS** |
| **03** | Progressive TCP Stream | Consecutive packets with incrementing seq numbers | `NO_EVIDENCE` / `NONE` | `NO_EVIDENCE` / `NONE` | 0.00 | Normal progressive stream produces unique keys | **PASS** |
| **04** | Seq Reuse Without Hash | TCP seq 5000 repeated at $\Delta t = 10\text{ s}$ without hash | `NO_EVIDENCE` / `NONE` | `NO_EVIDENCE` / `NONE` | 0.00 | Sequence reuse alone without hash/nonce not flagged | **PASS** |
| **05** | Cryptographic Nonce Reuse | Nonce `auth_token_9988` repeated at $\Delta t = 15\text{ s}$ | `SUSPICIOUS` / `HIGH` | `SUSPICIOUS` / `HIGH` | 0.85 | `Cryptographic Nonce Reuse` flagged | **PASS** |
| **06** | Stale Payload Re-injection | Payload hash repeated at $\Delta t = 20\text{ s} > 3.0\text{ s}$ | `SUSPICIOUS` / `HIGH` | `SUSPICIOUS` / `HIGH` | 0.70 | `Stale Payload Re-injection` flagged | **PASS** |
| **07** | Out-of-Order TCP Arrivals | TCP seq 3000 followed by seq 1500 at $\Delta t = 0.05\text{ s}$ | `NO_EVIDENCE` / `NONE` | `NO_EVIDENCE` / `NONE` | 0.00 | Reordered sequence numbers handled safely | **PASS** |
| **08** | Cross-Flow Key Collision | Same seq 100 on Flow A and Flow B within 0.8s | `NO_EVIDENCE` / `NONE` | `NO_EVIDENCE` / `NONE` | 0.00 | Shared key collision suppressed by RTO rule | **PASS** |
| **09** | 32-bit TCP Wraparound | TCP seq 4294967200 followed by seq 50 | `NO_EVIDENCE` / `NONE` | `NO_EVIDENCE` / `NONE` | 0.00 | Wraparound maps to distinct keys (`seq_50`) | **PASS** |
| **10** | History Window Cleanup | Nonce replayed after intermediate window at $t+70\text{ s}$ | `NO_EVIDENCE` / `NONE` | `NO_EVIDENCE` / `NONE` | 0.00 | Expired entry pruned after 60s; fresh baseline started | **PASS** |
| **11** | Missing Flow IP/MAC | Replay observation with `ip_src=None`, `ip_dst=None` | `SUSPICIOUS` / `HIGH` | `SUSPICIOUS` / `HIGH` | 0.85 | Safe execution; attributes to fallback MAC | **PASS** |
| **12** | Periodic IoT False Positive | Static DHT11 sensor payload retransmitted at $\Delta t = 5\text{ s}$ | `SUSPICIOUS` / `HIGH` | `SUSPICIOUS` / `HIGH` | 0.70 | Flags stale payload (known limitation of static telemetry) | **PASS** |
| **13** | Multiple Violations | Both nonce reuse and stale payload in same packet | `SUSPICIOUS` / `HIGH` | `SUSPICIOUS` / `HIGH` | 0.85 | Confidence escalates to 0.85 on nonce violation | **PASS** |
| **14** | LiveStreamExtractor Mapping | Simulation of `_RawPacket` with `tcp_seq` | `NO_EVIDENCE` / `NONE` | `NO_EVIDENCE` / `NONE` | 0.00 | Maps `tcp_seq` to `protocol_seq_num`; hash/nonce None | **PASS** |
| **15** | LiveCollector DB Persistence | Ingestion into `live_attack_events` in scratch DB | `SUSPICIOUS` / `HIGH` | `SUSPICIOUS` / `HIGH` | 0.85 | Persists `category=Replay_Attack`, `target_ip=192.168.137.1` | **PASS** |
| **16** | Zero Packets in Window | Empty packet list passed to evaluator | `NO_EVIDENCE` / `NONE` | `NO_EVIDENCE` / `NONE` | 0.00 | Cleanly emits `NO_EVIDENCE` without error | **PASS** |

**Summary: 16 / 16 Passed (100.0%)**

---

## 5. Offline PCAP Findings

All 11 PCAP files in the repository were systematically audited for TCP sequence numbers, payload hashing, and cryptographic nonces:

| File Name | Relative Path | Total Packets | TCP Packets | Dominant Protocols | Payload Hash / Nonce Present | Replay Detector Telemetry Status |
|---|---|---|---|---|---|---|
| `hotspot_two_phone_test.pcapng` | `data/hotspot_two_phone_test.pcapng` | 2,329 | 1,051 | TLSv1.2, TLSv1.3, SSL, TCP, UDP | None | `TCP_SEQ_ONLY_NO_PAYLOAD_HASH` |
| `session3_hotspot_capture.pcapng` | `data/telemetry_test/session3_...` | 80,180 | 30,210 | TLSv1.2, TLSv1.3, TCP, SSL, DNS | None | `TCP_SEQ_ONLY_NO_PAYLOAD_HASH` |
| `session4_hotspot_capture.pcapng` | `data/telemetry_test/session4_...` | 75,892 | 33,134 | TCP, TLSv1.2, TLSv1.3, QUIC, UDP | None | `TCP_SEQ_ONLY_NO_PAYLOAD_HASH` |
| `session5_hotspot_capture.pcapng` | `data/telemetry_test/session5_...` | 59,853 | 8,390 | TCP, TLSv1.2, MDNS, SSDP, UDP | None | `TCP_SEQ_ONLY_NO_PAYLOAD_HASH` |
| `session6_hotspot_capture.pcapng` | `data/telemetry_test/session6_...` | 48,270 | 9,331 | TLSv1.2, TLSv1.3, TCP, QUIC, HTTP | None | `TCP_SEQ_ONLY_NO_PAYLOAD_HASH` |
| `synchronized2_hotspot_capture.pcapng`| `data/telemetry_test/synchronized2...`| 5,472 | 2,679 | TLSv1.2, TLSv1.3, TCP, QUIC, UDP | None | `TCP_SEQ_ONLY_NO_PAYLOAD_HASH` |
| `synchronized_hotspot_capture.pcapng` | `data/telemetry_test/synchronized...` | 7,412 | 1,159 | TLSv1.2, TLSv1.3, TCP, QUIC, UDP | None | `TCP_SEQ_ONLY_NO_PAYLOAD_HASH` |
| `wifi_capture_01.pcapng` | `wifi_capture_01.pcapng` | 4,602 | 4,315 | TLSv1.2, TLSv1.3, SSL, TCP, UDP | None | `TCP_SEQ_ONLY_NO_PAYLOAD_HASH` |
| `wifi_capture_devices.pcapng` | `wifi_capture_devices.pcapng` | 6,639 | 2,904 | TCP, TLSv1.2, QUIC, SSL, UDP | None | `TCP_SEQ_ONLY_NO_PAYLOAD_HASH` |
| `wifi_hotspot_clients.pcapng` | `wifi_hotspot_clients.pcapng` | 19,203 | 1,298 | UDP, DNS, STUN, TCP | None | `TCP_SEQ_ONLY_NO_PAYLOAD_HASH` |
| `wifi_hotspot_clients_fresh.pcapng` | `wifi_hotspot_clients_fresh.pcapng` | 38,467 | 1,508 | TCP, TLSv1.2, UDP | None | `TCP_SEQ_ONLY_NO_PAYLOAD_HASH` |

### PCAP Replay Telemetry Reality:
- TCP sequence numbers are extracted from PCAP files via TShark (`-e tcp.seq`).
- However, standard PCAP packets do **not** contain precomputed payload hashes or parsed cryptographic nonces.
- Consequently, when raw PCAPs are evaluated by `ReplayDetector`:
  - Packets with TCP sequence numbers evaluate to `NO_EVIDENCE` (because sequence reuse alone without payload hash is not treated as replay).
  - Packets without TCP sequence numbers evaluate to `INSUFFICIENT_TELEMETRY`.
  - Zero false-positive replay alerts are generated across all 348,319 packets inspected.

---

## 6. Regression Testing Results

Both test suites were executed without modifications or regressions:

| Test Suite | Tests Run | Passed | Failed | Duration | Scope |
|---|---|---|---|---|---|
| [`tests/test_attack_detector.py`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/tests/test_attack_detector.py) | 56 | 56 | 0 | 0.09 s | Detection engine (DoS, PortScan, Spoofing, Deauth, Replay, RSSI) |
| [`tests/test_live_collector_attack_integration.py`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/tests/test_live_collector_attack_integration.py) | 69 | 69 | 0 | 10.12 s | Collector routing, observation mapping, and database persistence |
| **Total** | **125** | **125** | **0** | **10.21 s** | **100.0% Pass Rate** |

---

## 7. Capability Classification Matrix

| Capability | Implemented? | Validated? | Evidence | Known Limitation |
|---|---|---|---|---|
| **TCP Sequence Reuse Detection** | Implemented but not validated as standalone threat (by design) | Validated | [`ReplayDetector`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/attack_detector.py#L1736-L1743): suppresses reuse $\le 3\text{ s}$ as retransmission; ignores reuse $> 3\text{ s}$ if payload hash is absent | Does not classify TCP seq reuse alone as replay; requires payload hash or nonce |
| **Legitimate Retransmission Discrimination** | Implemented and validated | Validated | [`ReplayDetector`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/attack_detector.py#L1736-L1743): `time_delta <= tcp_retransmit_window_seconds (3.0s)` skips violation | Fixed 3.0s window; does not track dynamic TCP smoothed RTT or RTO calculations |
| **Out-of-Order Packet Handling** | Implemented and validated | Validated | Scenario 07: Distinct sequence numbers create unique keys without false alarms | Does not maintain full TCP state reassembly buffer |
| **Sequence-Number Wraparound** | Partially implemented | Validated | Scenario 09: Wraparound ($2^{32}-1 \to 0$) maps to distinct string keys (`seq_50`); pruned after 60s | No modular arithmetic ($\Delta \pmod{2^{32}}$); relies on time-based pruning |
| **Application Payload Replay Detection** | Implemented and validated | Validated | [`ReplayDetector`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/attack_detector.py#L1755-L1764): duplicate `payload_hash` at $\Delta t > 3.0\text{ s}$ triggers alert (conf=0.70) | Live TShark capture pipeline does not extract payload bytes (`-e data`) or compute hashes |
| **Cryptographic Nonce Reuse Detection** | Implemented and validated | Validated | [`ReplayDetector`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/attack_detector.py#L1745-L1753): duplicate `nonce` triggers alert (conf=0.85) | Live TShark capture pipeline does not parse application-layer nonces |
| **Live Collector Integration** | Implemented and validated | Validated | [`LiveCollector`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/live_collector.py#L1252-L1269): routes `AttackCategory.REPLAY` to `live_attack_events` in DB | Alerts require upstream payload hashing or nonce extraction to be emitted |

---

## 8. Known Limitations and False-Positive Risks

1. **Absence of Payload Hashing in Capture Stream:**
   - In production live monitoring and standard PCAP captures, `src/live_stream_extractor.py` runs TShark without `-e data`. Therefore, `payload_hash` and `nonce` are never populated from live network traffic.
   - Replay detection functions in synthetic testing and integration tests where `PacketObservation` is provided with hashes/nonces, but operates as `INSUFFICIENT_TELEMETRY` or `NO_EVIDENCE` on raw captured traffic.
2. **False-Positive Risk on Periodic Static IoT Telemetry:**
   - Scenario 12 proved that if an IoT sensor transmits an identical reading (e.g., constant 24°C temperature) without an incrementing counter, timestamp, or nonce, and an application payload hash is supplied, the detector will flag subsequent transmissions occurring $> 3.0\text{ s}$ later as `Stale Payload Re-injection`.
3. **Cross-Flow Key Collisions:**
   - In `ReplayDetector` line 1721, `key = f"seq_{p.protocol_seq_num}"` when hashes and nonces are absent. The key does **not** incorporate the flow 4-tuple `(src_ip, dst_ip, src_port, dst_port)`. If two unrelated TCP connections coincidentally share the same sequence number within 3.0 seconds, they share the same key in `_seen_payloads`.
4. **No Dynamic RTO Tracking:**
   - The detector uses a static 3.0-second retransmission threshold rather than tracking TCP connection RTT / RTO dynamics. High-latency satellite or mobile connections with $RTO > 3.0\text{ s}$ could theoretically exceed this threshold if payload hashes were enabled.

---

## 9. Production Database Integrity Verification

Before and after running the validation suite, SHA-256 hashes and file metadata were recorded for both production databases:

```powershell
Get-FileHash data/live_monitoring.db, data/iot_anomaly.db | Format-List
```

| Database File | Baseline SHA-256 Hash | Post-Validation SHA-256 Hash | File Size (Bytes) | Last Modified | Status |
|---|---|---|---|---|---|
| `data/live_monitoring.db` | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | 3,809,280 | 07-11-2026 21:04:17 | **MATCH (UNTOUCHED)** |
| `data/iot_anomaly.db` | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | 495,616 | 07-10-2026 19:57:43 | **MATCH (UNTOUCHED)** |

---

## 10. Files Inspected, Created, or Modified

### Files Inspected (Read-Only):
- [`src/attack_detector.py`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/attack_detector.py) (Lines 1647–1806, 1845, 1924–1925, 1960–1965)
- [`src/live_stream_extractor.py`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/live_stream_extractor.py) (Lines 131–145, 340–342, 388–416)
- [`src/live_collector.py`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/live_collector.py) (Lines 530–570, 1052–1064, 1252–1269, 1583–1595)
- [`src/init_live_database.py`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/init_live_database.py) (Lines 203–228)
- [`tests/test_attack_detector.py`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/tests/test_attack_detector.py) (Lines 1590–1672)
- [`tests/test_live_collector_attack_integration.py`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/tests/test_live_collector_attack_integration.py) (Lines 2994–3040)
- 11 PCAP files in `data/` and project root.

### Files Created:
- [`scratch/validate_replay_detection.py`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/scratch/validate_replay_detection.py) — 16-scenario offline synthetic test and PCAP audit runner.
- [`scratch/stage56_replay_validation_results.json`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/scratch/stage56_replay_validation_results.json) — Full structured execution log.
- [`scratch/stage56_replay_validation_report.md`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/scratch/stage56_replay_validation_report.md) — Comprehensive validation report.

### Production Files Modified:
- **NONE** (Zero source, firmware, model, dashboard, or production database files were modified).

---

## 11. Final Assessment & Verdict

### Final Verdict: **PASS WITH LIMITATIONS**

### Justification:
1. **PASS:** The detector and collector logic function strictly according to specification. The system correctly identifies cryptographic nonce reuse (confidence 0.85), identifies stale payload re-injection (confidence 0.70), distinguishes legitimate TCP retransmissions within the 3.0s RTO window, prunes history after 60s, and integrates with `live_attack_events` in the database.
2. **LIMITATIONS:** In standard live network operation and PCAP captures, the packet extraction layer does not dissect application payloads or compute SHA-256 hashes. Consequently, live replay detection is constrained by available telemetry. The detector appropriately reports `INSUFFICIENT_TELEMETRY` rather than making unsubstantiated claims.

> [!IMPORTANT]
> **STOP CONDITION REACHED:** Stage 5.6 is complete. In strict compliance with instructions, no production code has been modified, no live processes have been started, and no live RF/network injections were executed. Awaiting your explicit approval before proceeding to any subsequent stage.
