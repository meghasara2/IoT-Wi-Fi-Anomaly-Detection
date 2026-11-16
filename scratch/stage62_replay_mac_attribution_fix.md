# Stage 6.2 — Replay Alert MAC Attribution Correction Report
**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Workspace:** `C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection`  
**Execution Date:** 2026-11-10  
**Scope:** Replay Alert Address Attribution & Database Persistence Correction  
**Target Files:** `src/live_collector.py`, `tests/test_live_collector_attack_integration.py`

---

## 1. Root Cause Analysis

Inside `LiveCollector._persist_attack_results()` in `src/live_collector.py` (prior to this correction), the logic for persisting Replay attack alerts (`AttackCategory.REPLAY`) into SQLite table `live_attack_events` was implemented as:

```python
elif att_res.category == AttackCategory.REPLAY:
    replay_src = None
    replay_dst = None
    if att_res.evidence.get("violations"):
        v0 = att_res.evidence["violations"][0]
        replay_src = v0.get("src")
        replay_dst = v0.get("dst")
    _insert_attack_event(
        conn=db,
        run_id=self._run_id,
        window_id=window_id,
        result=att_res,
        source_mac=replay_src if (replay_src and ":" in replay_src and len(replay_src) == 17) else None,
        target_ip=replay_dst if (replay_dst and "." in replay_dst) else None,
    )
    self.stats["attack_events_flagged"] += 1
    inserted_count += 1
```

### The Mechanism of the Defect
1. **Overloaded `src` Representation in Detection Findings:**
   In `ReplayDetector` (`src/attack_detector.py`), when a replay violation is identified, the evidence record populates:
   ```python
   src = p.ip_src or p.eth_src
   dst = p.ip_dst or p.eth_dst
   ```
   For standard IP packet streams, `p.ip_src` is prioritized. Consequently, `v0.get("src")` contains an IPv4 address string (e.g. `"192.168.137.201"`).
2. **String-Format Check Dropped Valid MACs:**
   In `_persist_attack_results()`, the collector assigned `replay_src = v0.get("src")`. It then applied the guard:
   $$\text{replay\_src and } \text{":" in replay\_src and } \text{len(replay\_src) == 17}$$
   Because an IPv4 address contains dots and has a length between 7 and 15 characters, this check evaluated to `False`. The collector assigned `source_mac = None`, writing `NULL` into SQLite table `live_attack_events`.
3. **Failure to Inspect Explicit MAC Fields:**
   Even when the offending packet observation or finding evidence explicitly provided the source hardware MAC (via `v0["source_mac"]`, `v0["eth_src"]`, `v0["src_mac"]`, or `evidence["source_mac"]`), the collector completely ignored these fields and relied solely on `v0["src"]`.
4. **Source IP Lost from Persistent Record:**
   Because `live_attack_events` has address columns `source_mac` and `target_ip` (no dedicated `source_ip` column), assigning `source_mac = None` while mapping destination IP to `target_ip` meant the source IP address was not explicitly highlighted in structured evidence.

---

## 2. Exact Implementation Change

The correction was implemented in [`src/live_collector.py`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/live_collector.py).

### 2.1 IPv4/IPv6 Address Validation Helper
A robust IP address validation helper `_is_valid_ip()` using Python's standard `ipaddress` library was added alongside `_is_valid_mac()`:

```python
def _is_valid_ip(ip: Any) -> bool:
    """Validates whether ip is a valid IPv4 or IPv6 address string."""
    if not isinstance(ip, str) or not ip.strip():
        return False
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except (ValueError, AttributeError):
        return False
```

### 2.2 Replay Alert Address Attribution Logic
The `elif att_res.category == AttackCategory.REPLAY:` block inside `_persist_attack_results()` was updated to decouple source MAC, source IP, and target (destination) IP extraction:

```python
elif att_res.category == AttackCategory.REPLAY:
    # Stage 6.2: Replay alert address attribution correction
    # Explicitly extract source MAC, source IP, and target (destination) IP
    # without confusing IP addresses with MAC addresses.
    replay_source_mac: Optional[str] = None
    replay_source_ip: Optional[str] = None
    replay_target_ip: Optional[str] = None

    v0: Dict[str, Any] = {}
    if att_res.evidence.get("violations") and isinstance(att_res.evidence["violations"], list):
        raw_v0 = att_res.evidence["violations"][0]
        if isinstance(raw_v0, dict):
            v0 = raw_v0

    # 1. Source MAC: Check explicit MAC fields, then fallback to v0['src'] if it is a valid MAC
    mac_candidate = (
        v0.get("source_mac")
        or v0.get("eth_src")
        or v0.get("src_mac")
        or att_res.evidence.get("source_mac")
        or att_res.evidence.get("eth_src")
        or att_res.evidence.get("src_mac")
        or v0.get("src")
    )
    if mac_candidate and _is_valid_mac(str(mac_candidate)):
        replay_source_mac = str(mac_candidate).strip().lower().replace("-", ":")

    # 2. Source IP: Check explicit IP fields, fallback to v0['src'] if it is a valid IP
    src_ip_candidate = (
        v0.get("source_ip")
        or v0.get("src_ip")
        or v0.get("ip_src")
        or att_res.evidence.get("source_ip")
        or att_res.evidence.get("src_ip")
        or v0.get("src")
    )
    if src_ip_candidate and _is_valid_ip(str(src_ip_candidate)):
        replay_source_ip = str(src_ip_candidate).strip()
        if "source_ip" not in att_res.evidence:
            att_res.evidence["source_ip"] = replay_source_ip

    # 3. Target / Destination IP: Check destination IP fields, fallback to v0['dst'] if it is a valid IP
    dst_ip_candidate = (
        v0.get("target_ip")
        or v0.get("dst_ip")
        or v0.get("destination_ip")
        or v0.get("ip_dst")
        or att_res.evidence.get("target_ip")
        or att_res.evidence.get("dst_ip")
        or att_res.evidence.get("destination_ip")
        or v0.get("dst")
    )
    if dst_ip_candidate and _is_valid_ip(str(dst_ip_candidate)):
        replay_target_ip = str(dst_ip_candidate).strip()

    _insert_attack_event(
        conn=db,
        run_id=self._run_id,
        window_id=window_id,
        result=att_res,
        source_mac=replay_source_mac,
        target_ip=replay_target_ip,
    )
    self.stats["attack_events_flagged"] += 1
    inserted_count += 1
```

---

## 3. Files Modified

| File | Nature of Modification | Lines Changed |
|---|---|---:|
| [`src/live_collector.py`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/live_collector.py) | Added `import ipaddress`, `_is_valid_ip()` helper, and updated Replay address extraction in `_persist_attack_results()` | +73 / -13 |
| [`tests/test_live_collector_attack_integration.py`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/tests/test_live_collector_attack_integration.py) | Added 6 focused regression tests under `TestReplayPersistenceAttributionStage62` | +356 / -0 |

---

## 4. Before / After Example of Persisted Address Mapping

### Example Scenario: Replay Attack Injected by Node_3
A packet stream generates a replay violation with:
- Source Hardware MAC: `ca:34:ea:92:d3:9e`
- Source IPv4 Address: `192.168.137.201`
- Destination IPv4 Address: `192.168.137.1`

```python
replay_res = AttackDetectionResult(
    category=AttackCategory.REPLAY,
    status=DetectionStatus.SUSPICIOUS,
    severity=Severity.HIGH,
    evidence={
        "verdict": "Potential replay attack detected",
        "violations": [{
            "anomaly_type": "Cryptographic Nonce Reuse",
            "nonce": "auth_token_999",
            "source_mac": "CA:34:EA:92:D3:9E",
            "src": "192.168.137.201",
            "dst": "192.168.137.1",
        }],
    },
)
```

### Persisted Database Row Comparison in `live_attack_events`:

| Database Column | Before Stage 6.2 | After Stage 6.2 (Corrected) | Explanation |
|---|---|---|---|
| `category` | `Replay_Attack` | `Replay_Attack` | Unchanged |
| `status` | `SUSPICIOUS` | `SUSPICIOUS` | Unchanged |
| `severity` | `HIGH` | `HIGH` | Unchanged |
| `source_mac` | **`NULL`** *(Defect: MAC dropped)* | **`ca:34:ea:92:d3:9e`** *(Fixed)* | Hardware MAC preserved and normalized |
| `target_ip` | `192.168.137.1` | `192.168.137.1` | Destination IP preserved in target IP column |
| `evidence_json` | Missing explicit `source_ip` | **Contains `"source_ip": "192.168.137.201"`** | Source IP safely preserved in JSON payload |

### Additional Address Handling Guarantees:
1. **Missing Source MAC:** If `source_mac` is genuinely absent (e.g. only IP addresses provided), `source_mac` is stored as `NULL`—never populated with an IP string.
2. **Missing Destination IP:** If destination IP is absent, `target_ip` is stored as `NULL`—source IP is never incorrectly assigned to `target_ip`.
3. **L2-Only Frame:** If `src` and `dst` are MAC addresses, `source_mac` receives `src`, and `target_ip` remains `NULL` (MAC is never written into `target_ip`).

---

## 5. Regression Test Results

Six new automated regression tests were added in `tests/test_live_collector_attack_integration.py` under the `TestReplayPersistenceAttributionStage62` class:

| Test Name | Test Condition | Outcome |
|---|---|---|
| `test_replay_event_with_source_mac_and_ips_persists_correctly` | Replay event with source MAC, source IP, and destination IP persists `source_mac` and `target_ip` correctly, preserving `source_ip` in `evidence_json` | **PASSED** |
| `test_replay_event_with_missing_source_mac_stores_null_not_ip` | Replay event with only IP addresses stores `source_mac = NULL` (never puts an IP in `source_mac`), mapping destination IP to `target_ip` | **PASSED** |
| `test_replay_event_with_missing_optional_ip_fields_handled_safely` | Replay event with source MAC but missing IP endpoints preserves `source_mac` while storing `target_ip = NULL` without exception | **PASSED** |
| `test_replay_event_with_l2_src_mac_in_src_field_persists_correctly` | L2-only replay event with MAC in `src` preserves `source_mac` and sets `target_ip = NULL` (destination MAC never put into `target_ip`) | **PASSED** |
| `test_existing_non_replay_attack_persistence_unaffected` | Verified that DoS, Port Scan, and Spoofing events persist their respective address fields without alteration | **PASSED** |
| `test_replay_cooldown_behavior_preserved` | Verified that replay alert persistence continues emitting detected replay findings without unintended suppression side effects | **PASSED** |

---

## 6. Complete Test Suite Execution Results

The test suites were executed sequentially:

1. **Attack Integration Tests:**
   ```
   pytest tests/test_live_collector_attack_integration.py
   ============================= 75 passed in 9.45s ==============================
   ```
   *Result: 75 passed (69 pre-existing + 6 new tests).*

2. **Attack Detector Tests:**
   ```
   pytest tests/test_attack_detector.py
   ============================= 63 passed in 0.12s ==============================
   ```
   *Result: 63 passed (100% pass rate).*

3. **Complete Repository Suite (`python -m pytest tests/`):**
   ```
   collected 321 items
   tests\test_align_time_windows_with_sensors.py ......                     [  1%]
   tests\test_attack_detector.py .......................................... [ 14%]
   .....................                                                    [ 21%]
   tests\test_benchmark_1s_anomaly_detector.py ........                     [ 23%]
   tests\test_correlate_traffic_and_sensors.py ....                         [ 25%]
   tests\test_cross_session_1s_detector.py .....                            [ 26%]
   tests\test_dual_detector_1s.py ......                                    [ 28%]
   tests\test_evaluate_synthetic_1s_anomalies.py ......                     [ 30%]
   tests\test_extract_pcap_time_windows.py ..........                       [ 33%]
   tests\test_live_collector.py .....................................       [ 45%]
   tests\test_live_collector_attack_integration.py ........................ [ 52%]
   ...................................................                      [ 68%]
   tests\test_live_device_registry.py ........                              [ 71%]
   tests\test_live_interface_resolver.py .........................          [ 78%]
   tests\test_live_stream_extractor.py .................................... [ 90%]
   ............                                                             [ 93%]
   tests\test_record_sensor_telemetry.py .......                            [ 95%]
   tests\test_serial_protocol.py .......                                    [ 98%]
   tests\test_validate_long_baseline_workflow.py ......                     [100%]
   ============================ 321 passed in 26.17s =============================
   ```
   *Result: 321 passed, zero failures, zero warnings.*

---

## 7. Production Database Integrity Verification

Both production database files were verified bit-for-bit to guarantee zero writes or mutations:

| Database File | File Size (Bytes) | SHA-256 Checksum Baseline | Current State |
|---|---:|---|---|
| `data/live_monitoring.db` | 3,809,280 | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | **BIT-FOR-BIT IDENTICAL** |
| `data/iot_anomaly.db` | 495,616 | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | **BIT-FOR-BIT IDENTICAL** |

Zero test records were written to production files; all tests executed strictly within isolated `tmp_path` fixtures.

---

## 8. Remaining Limitations

1. **Replay Violation Evidence Schema in `attack_detector.py`:**
   In `ReplayDetector`, individual violation entries (`replay_anomalies`) currently prioritize `src = p.ip_src or p.eth_src`. When `p.ip_src` is present, `ReplayDetector` does not redundantly store `p.eth_src` in `v0` unless provided in extended evidence. While `LiveCollector` now properly captures `source_mac` whenever present in evidence or when `src` is an L2 MAC, future enhancements to `ReplayDetector` could explicitly output `"source_mac": p.eth_src` in all violation records.
2. **Absence of Payload Hashing in Live TShark:**
   TShark command arguments in `src/live_stream_extractor.py` omit `-e data`, meaning live traffic replay detection currently relies on sequence numbers and cryptographic nonces.

---
*End of Stage 6.2 Replay Alert MAC Attribution Correction Report.*

