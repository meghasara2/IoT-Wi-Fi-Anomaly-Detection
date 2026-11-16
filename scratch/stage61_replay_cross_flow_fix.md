# Stage 6.1 — Replay Detector Cross-Flow Correction Report
**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Workspace:** `C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection`  
**Execution Date:** 2026-11-10  
**Scope:** Narrowly Scoped Replay Detector Cross-Flow Sequence Collision Correction  
**Target Files:** `src/attack_detector.py`, `tests/test_attack_detector.py`

---

## 1. Root Cause Analysis

In the frozen implementation of `ReplayDetector.evaluate()` in `src/attack_detector.py` (prior to this correction), the history lookup key for packet observations was constructed at line 1721 as:

```python
key = p.payload_hash or p.nonce or f"seq_{p.protocol_seq_num}"
```

### The Mechanism of the Defect
1. **Fallback to Sequence Number Without Flow Context:** When `payload_hash` and `nonce` are absent (the standard condition in live captures where Layer 7 payload extraction is disabled), the detector keyed packet history purely by:
   $$\text{key} = \text{"seq\_"} + \text{str}(p.\text{protocol\_seq\_num})$$
2. **Cross-Flow State Contamination:** This key completely omitted the network and transport flow 5-tuple (`ip_src`, `ip_dst`, `src_port`, `dst_port`, `protocol`). As a consequence, two completely unrelated TCP connections—such as Flow A (`192.168.137.201:50001 -> 192.168.137.1:80`) and Flow B (`10.0.0.5:44332 -> 10.0.0.1:443`)—that coincidentally used the same TCP sequence number (e.g., sequence `100` or `1024`) hashed to the identical dictionary key: `"seq_100"`.
3. **Improper Retransmission Suppression:** When the packet from Flow B arrived within 3.0 seconds of Flow A's packet:
   $$\Delta t = t_B - t_A \le 3.0\text{ seconds}$$
   Case A in the evaluation loop checked:
   ```python
   if (p.protocol_seq_num is not None and prev_seq is not None
       and p.protocol_seq_num == prev_seq and time_delta <= self.tcp_retransmit_window_seconds):
       continue  # Legitimate network retransmission
   ```
   Because Case A never verified that `p` and `prev` belonged to the same flow, Flow B's packet was misclassified as a "TCP retransmission" of Flow A's packet and suppressed from security evaluation.
4. **History Pollution:** The history list `self._seen_payloads["seq_100"]` intermingled packets from separate TCP sessions, corrupting sequence progression analysis.

---

## 2. Exact Implementation Change

The correction was applied strictly within `ReplayDetector` in `src/attack_detector.py` without modifying any other detector or subsystem.

### 2.1 Flow Identity Tuple Extraction
A static helper method `_extract_flow_key()` was added to `ReplayDetector` to extract a robust 5-tuple representing flow identity from available fields:

```python
@staticmethod
def _extract_flow_key(p: PacketObservation) -> Tuple[Any, ...]:
    """
    Extracts a flow identity 5-tuple from available network and transport fields.

    Flow fields:
      - Source IP (falls back to eth_src if IP is absent, to distinguish L2 frames)
      - Destination IP (falls back to eth_dst if IP is absent)
      - Source port (int or None; missing fields remain None without inventing synthetic values)
      - Destination port (int or None; missing fields remain None)
      - Transport protocol (uppercase string or None)
    """
    src = p.ip_src if (p.ip_src is not None and p.ip_src != "") else p.eth_src
    dst = p.ip_dst if (p.ip_dst is not None and p.ip_dst != "") else p.eth_dst
    proto = p.protocol.upper() if isinstance(p.protocol, str) else None
    return (src, dst, p.src_port, p.dst_port, proto)
```

**Key Safety Guarantees:**
- **No Synthetic Values:** Missing transport ports or protocols remain `None`; no artificial defaults (such as port `0` or `"TCP"`) are invented.
- **L2 Fallback Guard:** If `p.ip_src` or `p.ip_dst` is absent (such as in non-IP frames or layer-2 test observations), the L2 hardware MAC addresses (`eth_src`, `eth_dst`) are utilized. This ensures two different physical devices with missing IP headers do not collapse into the same collision key.

### 2.2 Sequence Key Scoping
In `ReplayDetector.evaluate()`, the key construction was updated so that sequence-number-based history is scoped to the flow identity:

```python
flow_key = self._extract_flow_key(p)
src = p.ip_src or p.eth_src
dst = p.ip_dst or p.eth_dst

if p.payload_hash is not None:
    key = p.payload_hash
elif p.nonce is not None:
    key = p.nonce
elif p.protocol_seq_num is not None:
    key = f"seq_{flow_key}_{p.protocol_seq_num}"
else:
    continue
```

### 2.3 Flow-Aware Retransmission Suppression
The internal history record was expanded to preserve `flow_key`:
$$\text{entry\_record} = (p.\text{timestamp}, p.\text{protocol\_seq\_num}, p.\text{nonce}, \text{src}, \text{dst}, \text{flow\_key})$$

Case A was updated to require that retransmission suppression applies **only within the same flow**:

```python
# Case A: Standard TCP retransmission (same sequence number within RTO window on same flow)
if (
    p.protocol_seq_num is not None
    and prev_seq is not None
    and p.protocol_seq_num == prev_seq
    and time_delta <= self.tcp_retransmit_window_seconds
    and flow_key == prev_flow
):
    # Legitimate network retransmission
    continue
```

### 2.4 Preservation of Nonce and Payload Hash Semantics
- Cryptographic nonces (`p.nonce`) continue to key by `p.nonce`. If a nonce is observed again across any session or client, Case B triggers `Cryptographic Nonce Reuse` (`SUSPICIOUS` / `HIGH`, confidence 0.85).
- Content-based payload hashes (`p.payload_hash`) continue to key by `p.payload_hash`. If an identical payload is observed outside the 3.0-second RTO window, Case C triggers `Stale Payload Re-injection` (`SUSPICIOUS` / `HIGH`, confidence 0.70).

---

## 3. Files Modified

| File | Nature of Modification | Lines Changed |
|---|---|---:|
| [`src/attack_detector.py`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/attack_detector.py) | Added `_extract_flow_key()`, scoped sequence key to flow, added `flow_key == prev_flow` check in Case A | +36 / -7 |
| [`tests/test_attack_detector.py`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/tests/test_attack_detector.py) | Added 7 comprehensive regression tests to `TestReplayDetector` | +346 / -0 |

---

## 4. New Regression Tests & Results

Seven new automated regression tests were authored in `tests/test_attack_detector.py` under the `TestReplayDetector` suite:

| Test Name | Validation Scenario | Outcome |
|---|---|---|
| `test_same_flow_same_sequence_number_suppressed_as_retransmission` | Identical sequence number on same 5-tuple flow within 0.6s ($\le 3.0\text{s}$) is properly suppressed as a legitimate TCP retransmission | **PASSED** |
| `test_different_flows_same_sequence_number_evaluated_independently` | Flow A and Flow B share sequence 500 at $\Delta t = 0.5\text{s}$. Both are evaluated independently without cross-flow collision. Subsequent retransmission on Flow B is suppressed only against Flow B | **PASSED** |
| `test_different_source_ports_treated_as_different_flows` | Same IPs, same destination port, same sequence 1000, but source port 50001 vs 50002. Verified distinct flow keys (`flow_key_1 != flow_key_2`) and independent state entries | **PASSED** |
| `test_different_destination_ports_treated_as_different_flows` | Same source IP/port, same destination IP, but destination port 80 vs 8080 with sequence 2000. Verified distinct flow keys and independent state entries | **PASSED** |
| `test_different_transport_protocols_treated_as_different_flows` | Same endpoints and sequence 3000, but TCP vs UDP. Verified distinct protocol tags (`"TCP"` vs `"UDP"`) and independent state entries | **PASSED** |
| `test_missing_endpoint_fields_handled_safely_without_incorrect_merging` | Missing port (`src_port=None`) does not collide with specified port (`src_port=50001`); missing IPs differentiate on physical MACs (`eth_src`); missing fields never invent synthetic values | **PASSED** |
| `test_existing_stale_payload_reinjection_detected_after_rto_window` | Identical payload re-injected after 10.0s ($\Delta t > 3.0\text{s}$) triggers `Stale Payload Re-injection` with confidence 0.70 and `HIGH` severity | **PASSED** |

---

## 5. Existing Test-Suite Verification Results

The entire project test suite was executed against the corrected implementation:

### 5.1 Unit Tests (`tests/test_attack_detector.py`)
```
platform win32 -- Python 3.11.9, pytest-9.0.2, pluggy-1.6.0
collected 63 items

tests\test_attack_detector.py .......................................... [ 66%]
.....................                                                    [100%]
============================= 63 passed in 0.19s ==============================
```
*Result: 63 passed (56 pre-existing + 7 new tests).*

### 5.2 Collector Integration Tests (`tests/test_live_collector_attack_integration.py`)
```
platform win32 -- Python 3.11.9, pytest-9.0.2, pluggy-1.6.0
collected 69 items

tests\test_live_collector_attack_integration.py ........................ [ 34%]
.............................................                            [100%]
============================= 69 passed in 6.06s ==============================
```
*Result: 69 passed (100% pass rate).*

### 5.3 Complete Repository Regression Suite (`python -m pytest tests/`)
```
platform win32 -- Python 3.11.9, pytest-9.0.2, pluggy-1.6.0
collected 315 items

tests\test_align_time_windows_with_sensors.py ......                     [  1%]
tests\test_attack_detector.py .......................................... [ 15%]
.....................                                                    [ 21%]
tests\test_benchmark_1s_anomaly_detector.py ........                     [ 24%]
tests\test_correlate_traffic_and_sensors.py ....                         [ 25%]
tests\test_cross_session_1s_detector.py .....                            [ 27%]
tests\test_dual_detector_1s.py ......                                    [ 29%]
tests\test_evaluate_synthetic_1s_anomalies.py ......                     [ 31%]
tests\test_extract_pcap_time_windows.py ..........                       [ 34%]
tests\test_live_collector.py .....................................       [ 46%]
tests\test_live_collector_attack_integration.py ........................ [ 53%]
.............................................                            [ 67%]
tests\test_live_device_registry.py ........                              [ 70%]
tests\test_live_interface_resolver.py .........................          [ 78%]
tests\test_live_stream_extractor.py .................................... [ 89%]
............                                                             [ 93%]
tests\test_record_sensor_telemetry.py .......                            [ 95%]
tests\test_serial_protocol.py .......                                    [ 98%]
tests\test_validate_long_baseline_workflow.py ......                     [100%]

============================ 315 passed in 15.17s =============================
```
*Result: Zero failures, zero regressions across all 315 tests.*

---

## 6. Preservation of System Boundaries & Detector Logic

- **DoS Detector (`DoSDetector`):** Completely untouched. 60 PPS threshold, 3-window persistence, 75% target concentration, subnet restrictions, and fleet surge logic intact.
- **Port Scan Detector (`PortScanDetector`):** Completely untouched. Vertical threshold ($\ge 8$), horizontal sweep threshold ($\ge 5$), infrastructure port exclusions, and TCP SYN / UDP probe rules intact.
- **Spoofing Detector (`SpoofingDetector`):** Completely untouched. Rogue gateway claim (`CRITICAL`), active IP conflict, 300s silence handover threshold, and randomized MAC awareness intact.
- **Deauthentication Detector (`DeauthDetector`):** Completely untouched. 5 frames/sec threshold, Subtypes 10/12, PMF encryption masking, and 60s cooldown intact.
- **Replay Thresholds & Window Parameters:**
  - `tcp_retransmit_window_seconds = 3.0` (Unchanged).
  - `replay_history_window_seconds = 60.0` (Unchanged).
  - Confidence: Nonce reuse = 0.85, Stale payload = 0.70 (Unchanged).
  - Severity: `HIGH` (Unchanged).

---

## 7. Production Database Integrity Verification

As mandated by safety constraints, cryptographic checksums for both SQLite databases were verified post-execution:

| Database File | File Size (Bytes) | SHA-256 Checksum Baseline | Current State |
|---|---:|---|---|
| `data/live_monitoring.db` | 3,809,280 | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | **BIT-FOR-BIT IDENTICAL** |
| `data/iot_anomaly.db` | 495,616 | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | **BIT-FOR-BIT IDENTICAL** |

Zero writes or DDL executions occurred against production databases.

---

## 8. Remaining Limitations

1. **Live Payload Hash Extraction:** In the live TShark streaming extractor (`src/live_stream_extractor.py`), the command line arguments currently extract transport sequence numbers (`-e tcp.seq`) but omit payload bytes (`-e data`). Consequently, live streaming traffic relies on sequence numbers and nonces, while payload hash remains `None` unless Layer 7 extraction is added.
2. **Collector Persistence Attribution:** In `LiveCollector._persist_attack_results()`, when an IP address is present on a replay event, the collector records `source_mac = NULL` and assigns the IP to `target_ip`. This collector-level attribution mapping will be addressed in a subsequent stage.

---
*End of Stage 6.1 Replay Detector Cross-Flow Correction Report.*

