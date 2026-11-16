# STAGE 5.6 — TARGETED REPLAY DETECTOR INVESTIGATION: CROSS-FLOW KEY COLLISION & ARCHITECTURAL CLARIFICATION

**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Workspace:** `C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection`  
**Investigation Mode:** Strictly Read-Only  
**Status:** Complete  

---

## 1. Executive Findings

This report delivers a rigorous, evidence-based investigation into the keying mechanics of [`ReplayDetector`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/attack_detector.py#L1647-L1806) in [`src/attack_detector.py`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/attack_detector.py) and Scenario 08 of [`scratch/validate_replay_detection.py`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/scratch/validate_replay_detection.py).

### Summary of Core Findings:
1. **Flow-Blind Keying:** The history lookup key in `ReplayDetector` is defined as `key = p.payload_hash or p.nonce or f"seq_{p.protocol_seq_num}"` ([line 1721](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/attack_detector.py#L1721)).
2. **Zero Flow Isolation:** The key **does not include** source IP, destination IP, source port, destination port, or protocol.
3. **Cross-Flow History Sharing:** Any two completely unrelated TCP flows that happen to use the same sequence number (e.g. `seq = 100`) share the exact same dictionary bucket in `_seen_payloads["seq_100"]`.
4. **Incorrect Suppression Across Flows:** If Packet B from Flow 2 arrives within 3.0 seconds of Packet A from Flow 1 with the same sequence number, the retransmission logic ([lines 1736–1743](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/attack_detector.py#L1736-L1743)) unconditionally treats Packet B as a retransmission of Packet A and skips it (`continue`).
5. **Scenario 08 Reality:** Scenario 08 **does not** validate cross-flow isolation. Instead, it empirically demonstrates that `ReplayDetector` lacks flow scoping and collapses unrelated flows into a single sequence collision bucket.

---

## 2. Answers to Targeted Investigation Questions

### Question 1: What exact key is used to store replay history?
In [`src/attack_detector.py`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/attack_detector.py#L1721), line 1721 defines the exact key used:

```python
# src/attack_detector.py: Line 1721
key = p.payload_hash or p.nonce or f"seq_{p.protocol_seq_num}"
```

The history dictionary is typed at line 1673 as:
```python
# src/attack_detector.py: Line 1673
self._seen_payloads: Dict[str, List[Tuple[float, Optional[int], Optional[str], str, str]]] = {}
```
Where each list entry stores `(timestamp, protocol_seq_num, nonce, src, dst)`.

---

### Question 2: Does the key include source IP, destination IP, source port, destination port, protocol, or flow identity?
**NO.** None of these fields are included in the key:
- `ip_src` is NOT in the key.
- `ip_dst` is NOT in the key.
- `src_port` is NOT in the key.
- `dst_port` is NOT in the key.
- `protocol` is NOT in the key.
- `eth_src` / `eth_dst` are NOT in the key.

Although lines 1722–1723 extract:
```python
src = p.ip_src or p.eth_src
dst = p.ip_dst or p.eth_dst
```
these variables are stored solely as metadata inside the list tuple `(p.timestamp, p.protocol_seq_num, p.nonce, src, dst)` appended at line 1727 and line 1765. They are **never used to partition, hash, or look up history keys**.

---

### Question 3: Can two unrelated TCP flows with the same sequence number share replay history?
**YES.**
If Flow 1 (`192.168.137.201:50001 -> 192.168.137.1:80`) and Flow 2 (`10.0.0.5:44332 -> 10.0.0.1:443`) both transmit packets with `protocol_seq_num = 100` (and `payload_hash` is `None`), both packets map to the identical string key:

$$\text{key} = \text{"seq\_100"}$$

Both packets are appended to `self._seen_payloads["seq_100"]`. When Flow 2's packet is evaluated, it iterates over Flow 1's entry in `previous_entries = self._seen_payloads["seq_100"]`.

---

### Question 4: Does the 3-second retransmission suppression incorrectly suppress evidence across unrelated flows?
**YES.**
Lines 1735–1743 of [`src/attack_detector.py`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/attack_detector.py#L1735-L1743) state:

```python
# Case A: Standard TCP retransmission (same sequence number within RTO window)
if (
    p.protocol_seq_num is not None
    and prev_seq is not None
    and p.protocol_seq_num == prev_seq
    and time_delta <= self.tcp_retransmit_window_seconds
):
    # Legitimate network retransmission
    continue
```

Because `ReplayDetector` does not verify `src == prev_src` or `dst == prev_dst` inside Case A:
- If Packet A arrives from Host A on Flow 1 with `seq = 100` at $t_0$,
- And Packet B arrives from Host B on Flow 2 with `seq = 100` at $t_0 + 0.8\text{ s}$,
- The detector calculates $\Delta t = 0.8\text{ s} \le 3.0\text{ s}$.
- Case A evaluates to `True` and executes `continue`.
- Packet B from Host B is **suppressed as a "legitimate network retransmission" of Packet A from Host A**, despite originating from a totally different network, interface, port, and flow!

---

## 3. Concrete In-Memory Demonstrations

To verify this behavior without modifying any project code, two isolated in-memory test cases were constructed using the frozen `ReplayDetector` class:

### Demonstration Code:
```python
from src.attack_detector import ReplayDetector, PacketObservation

detector = ReplayDetector(tcp_retransmit_window_seconds=3.0)

# -------------------------------------------------------------
# Case 1: Same flow, repeated sequence number within 3 seconds
# -------------------------------------------------------------
p1 = PacketObservation(
    timestamp=100.0, packet_size=100, eth_src="aa:aa:aa:aa:aa:aa", eth_dst="bb:bb:bb:bb:bb:bb",
    ip_src="192.168.1.10", ip_dst="192.168.1.1", src_port=5000, dst_port=80,
    protocol="TCP", protocol_seq_num=1000
)
p2 = PacketObservation(
    timestamp=100.5, packet_size=100, eth_src="aa:aa:aa:aa:aa:aa", eth_dst="bb:bb:bb:bb:bb:bb",
    ip_src="192.168.1.10", ip_dst="192.168.1.1", src_port=5000, dst_port=80,
    protocol="TCP", protocol_seq_num=1000
)

detector.reset()
detector.evaluate([p1])
res1 = detector.evaluate([p2])

# -------------------------------------------------------------
# Case 2: Different flows, repeated sequence number within 3 seconds
# -------------------------------------------------------------
p3 = PacketObservation(
    timestamp=200.0, packet_size=100, eth_src="aa:aa:aa:aa:aa:aa", eth_dst="bb:bb:bb:bb:bb:bb",
    ip_src="192.168.1.10", ip_dst="192.168.1.1", src_port=5000, dst_port=80,
    protocol="TCP", protocol_seq_num=2000
)
p4 = PacketObservation(
    timestamp=200.5, packet_size=100, eth_src="cc:cc:cc:cc:cc:cc", eth_dst="dd:dd:dd:dd:dd:dd",
    ip_src="10.0.0.5", ip_dst="10.0.0.1", src_port=9000, dst_port=443,
    protocol="TCP", protocol_seq_num=2000
)

detector.reset()
detector.evaluate([p3])
res2 = detector.evaluate([p4])
```

### Exact Detector Output Recorded:

```
Case 1 (Same Flow):
  Status: NO_EVIDENCE
  Severity: NONE
  Confidence: 0.0
  Evidence: {'verdict': 'No replay violations observed', 'evaluable_packets': 1}
  History Keys: ['seq_1000']
  History Entries: [(100.0, 1000, None, '192.168.1.10', '192.168.1.1'),
                    (100.5, 1000, None, '192.168.1.10', '192.168.1.1')]

Case 2 (Different Flows):
  Status: NO_EVIDENCE
  Severity: NONE
  Confidence: 0.0
  Evidence: {'verdict': 'No replay violations observed', 'evaluable_packets': 1}
  History Keys: ['seq_2000']
  History Entries: [(200.0, 2000, None, '192.168.1.10', '192.168.1.1'),
                    (200.5, 2000, None, '10.0.0.5', '10.0.0.1')]
```

### Analysis of Output:
- In Case 2, the detector internal history shows both entries stored under the identical key `['seq_2000']`.
- Entry 1: `(200.0, 2000, None, '192.168.1.10', '192.168.1.1')`
- Entry 2: `(200.5, 2000, None, '10.0.0.5', '10.0.0.1')`
- The detector produced `NO_EVIDENCE` for Flow 2 because Case A's retransmission logic matched:
  `2000 == 2000 and (200.5 - 200.0) <= 3.0` $\to$ `continue`.
- Flow 2 was incorrectly treated as a TCP retransmission of Flow 1.

---

## 4. Evaluation of Scenario 08: Genuine Isolation vs. Sequence Suppression

In [`scratch/validate_replay_detection.py`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/scratch/validate_replay_detection.py#L383-L423), Scenario 08 is implemented as:

```python
# Lines 386-423 in scratch/validate_replay_detection.py
detector.reset()
p8_flow_a = PacketObservation(
    timestamp=800.0, packet_size=60, eth_src="ca:34:ea:92:d3:9e", eth_dst="00:15:5d:01:02:03",
    ip_src="192.168.137.201", ip_dst="192.168.137.1", src_port=50001, dst_port=80,
    protocol="TCP", protocol_seq_num=100, payload_hash=None
)
detector.evaluate([p8_flow_a])

p8_flow_b = PacketObservation(
    timestamp=800.8, packet_size=60, eth_src="aa:bb:cc:dd:ee:ff", eth_dst="00:15:5d:01:02:03",
    ip_src="10.0.0.5", ip_dst="10.0.0.1", src_port=44332, dst_port=443,
    protocol="TCP", protocol_seq_num=100, payload_hash=None
)
scenarios.append(run_scenario(
    "08_Cross_Flow_Sequence_Collision_Handled_As_Retransmission",
    detector,
    [p8_flow_b],
    expected_status=DetectionStatus.NO_EVIDENCE,
    expected_severity=Severity.NONE,
    expected_confidence=0.0,
    reset_before=False,
))
```

### Critical Assessment:
- **Does Scenario 08 validate cross-flow isolation?**
  **NO.** It validates the exact opposite: **cross-flow sequence leakage**.
- **Why does the test pass?**
  The test passes because its expectation was set to `DetectionStatus.NO_EVIDENCE`.
  However, `NO_EVIDENCE` was produced **not** because the detector isolated Flow B from Flow A, but because Case A's retransmission check (`time_delta <= 3.0`) triggered on the colliding key `"seq_100"`.
- **Architectural Meaning:**
  If true cross-flow isolation existed, Flow B would be hashed into an independent flow bucket (e.g., `key = (10.0.0.5, 10.0.0.1, 44332, 443, 100)`). Packet B would then establish a **fresh baseline** for Flow B rather than matching against Flow A's entry.

---

## 5. Three Critical Distinctions: Synthetic, Live Telemetry, and Real-World Replay

To prevent any misunderstanding of the project's security posture, three distinct operational domains must be explicitly decoupled:

```
┌────────────────────────────────────────────────────────────────────────┐
│ 1. Synthetic Unit Validation (What tests run)                         │
│    - Directly injects synthetic nonces ("auth_token_9988")             │
│    - Directly injects synthetic payload hashes ("sha256_deadbeef")     │
│    - Proves: State machine flags duplicate nonces / hashes in memory   │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │  GAP: No payload hashing in TShark
┌──────────────────────────────────▼─────────────────────────────────────┐
│ 2. Actual Live Telemetry Pipeline (What the system captures)           │
│    - TShark captures tcp.seq, tcp.flags, ip.src, ip.dst, ports         │
│    - Does NOT extract payload bytes (-e data)                          │
│    - Does NOT compute payload hashes                                   │
│    - Does NOT extract application-layer nonces                         │
│    - Result: payload_hash=None, nonce=None on 100% of live packets     │
│    - Real live stream ALWAYS reports NO_EVIDENCE or INSUFFICIENT       │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │  GAP: Replay is an application threat
┌──────────────────────────────────▼─────────────────────────────────────┐
│ 3. Real-World Replay Attack Defense (What protects the network)        │
│    - Replay attacks replay application payloads (MQTT/HTTP commands)   │
│    - Transport layer: Attacker opens a NEW TCP handshake with NEW seq  │
│    - TCP sequence tracking CANNOT detect application-level replay      │
│    - Defense requires TLS 1.3 / session tokens / app nonces            │
└────────────────────────────────────────────────────────────────────────┘
```

### 1. Synthetic Payload-Hash and Nonce Detection:
- **Mechanism:** Synthetic unit tests instantiate `PacketObservation` objects in memory with pre-populated `nonce` or `payload_hash` strings.
- **What it Proves:** It proves that `ReplayDetector`'s internal evaluation rules (Case B and Case C) execute correctly, compute confidence scores (0.85 for nonces, 0.70 for payload hashes), and generate structured evidence dictionaries when such telemetry is supplied.
- **Limitation:** It is strictly an algorithmic unit test of a state machine in memory.

### 2. Actual Live Telemetry Capabilities:
- **Mechanism:** In live network capture ([`src/live_stream_extractor.py`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/live_stream_extractor.py#L340-L416)) and all 11 repository PCAPs, TShark extracts only Layer 3 and Layer 4 header fields (`tcp.seq`, `tcp.flags`, `ip.src`, `ip.dst`, `tcp.srcport`, `tcp.dstport`).
- **Telemetry Reality:**
  - `payload_hash` is **always `None`**.
  - `nonce` is **always `None`**.
- **Operational Consequence:**
  - When raw captured traffic is evaluated, `ReplayDetector` **never emits an alert**.
  - If TCP sequence numbers are present, it emits `NO_EVIDENCE` (because sequence reuse alone without payload hash is intentionally ignored).
  - If sequence numbers are absent (UDP, ICMP, ARP), it emits `INSUFFICIENT_TELEMETRY`.
  - In actual deployment, the system has **zero live replay alert emission capability** unless an application-layer dissector or payload hasher is added to TShark.

### 3. Real-World Replay Attack Validation:
- **Mechanism:** A real-world adversary capturing IoT traffic (e.g. an unencrypted HTTP or MQTT control command such as `POST /api/lock/open`) replays that command by establishing a **new TCP connection** to the server.
- **Why TCP Sequence Tracking Fails:** In a new TCP connection, the OS assigns a **new random initial sequence number (ISN)**. The TCP sequence numbers will be completely different from the original transaction. A detector inspecting only `tcp.seq` will perceive a completely normal, legitimate TCP flow with unique sequence numbers.
- **Defense Requirement:** Application-level replay defense requires cryptographic nonces, ephemeral session tokens, TLS anti-replay mechanisms, or monotonic command counters validated inside the application protocol.
- **Project Boundary:** The project has **not** executed, simulated, or validated real-world replay attacks against live IoT devices. The existing pipeline does not inspect Layer 7 payloads or TLS records.

---

## 6. Recommendations & Code Impact

1. **Maintain Implementation Immutability:**
   - In accordance with the Stage 5 validation guidelines, [`src/attack_detector.py`](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/attack_detector.py) must remain **frozen**.
   - Do not alter the keying logic or thresholds in production code.
2. **Clarify Scientific Documentation:**
   - In the final project report, explicitly state that `ReplayDetector` is a protocol-aware prototype demonstrating the mathematical concepts of nonce reuse and payload re-injection.
   - Acknowledge that the detector is flow-blind (keys solely by sequence number when hashes/nonces are absent) and relies on upstream telemetry that is not currently extracted by the live TShark pipeline.
   - Maintain the final assessment: **PASS WITH LIMITATIONS**.

---

## 7. Verification of Production Database Integrity

Before and after this investigation, SHA-256 hashes of both production databases were verified bit-for-bit:

```powershell
Get-FileHash data/live_monitoring.db, data/iot_anomaly.db | Format-List
```

| Database File | SHA-256 Hash | File Size | Status |
|---|---|---|---|
| `data/live_monitoring.db` | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | 3,809,280 bytes | **MATCH (UNTOUCHED)** |
| `data/iot_anomaly.db` | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | 495,616 bytes | **MATCH (UNTOUCHED)** |

No production source code, firmware, models, dashboards, or databases were modified.

> [!IMPORTANT]
> **STOP CONDITION REACHED:** Investigation complete. Awaiting user approval.
