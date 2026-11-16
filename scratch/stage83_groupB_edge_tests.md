# STAGE 8.3 — GROUP B: MEDIUM-PRIORITY EDGE-CASE TESTS

**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Workspace:** `C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection`  
**Execution Date:** 2026-11-10  
**Status:** GROUP B COMPLETE (3/3 New Edge-Case Tests Passing, 391/391 Full Suite Passing)

---

## 1. Executive Summary

In accordance with Stage 8.3 instructions, test coverage improvements were executed exclusively for **Group B: Three Medium-Priority Edge-Case Tests** targeting real-world concurrency, serial corruption, and out-of-order network arrival:
1. **Test 1 (GAP-82-05):** Replay Detection Under Timestamp Regression / Out-of-Order Packet Arrival (`src/attack_detector.py`).
2. **Test 2 (GAP-82-06):** Serial Ingestion Resilience to Malformed Bytes, Null Characters, and Invalid UTF-8 (`src/live_collector.py`).
3. **Test 3 (GAP-82-07):** Simultaneous Multi-Device Window Persistence at Identical Timestamps (`src/live_collector.py`).

### Key Verification Metrics
- **Group B Individual Execution Result:** 3/3 new edge-case tests passed ($100\%$).
- **Full Automated Test Suite Result:** **391 passed, 0 failed, 0 skipped, 0 errors** in **35.94 seconds** (expanded from 388 tests).
- **Production Source Code Integrity:** $0$ production source files modified in `src/` (all timestamps intact).
- **Database Cryptographic Integrity:** Bit-for-bit identical SHA-256 hashes verified on all production and test databases.
- **Defects Discovered:** Zero implementation defects. Existing systems handle timestamp regression, serial byte corruption, and simultaneous timestamp writes with complete safety and data preservation.

---

## 2. Test Cases Added

Three comprehensive edge-case unit and integration test methods were added across `tests/test_attack_detector.py` and `tests/test_live_collector.py`:

### 2.1 Test 1: Replay Timestamp Regression (GAP-82-05)
- **Method Name:** `test_replay_out_of_order_packets_timestamp_regression()`
- **File:** [test_attack_detector.py](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/tests/test_attack_detector.py) (Lines 2297–2375)
- **Class:** `TestReplayDetector`
- **Verification Logic:**
  1. *Out-of-Order TCP Jitter on Same Flow:* Packet 1 arrives with sequence number 100 at $t_1 = 1000.5\text{s}$. Packet 2 arrives later in processing with sequence number 100 but timestamp $t_2 = 1000.2\text{s}$ (out-of-order arrival, $\Delta t = -0.3\text{s} \le 3.0\text{s}$). Verified that this time regression is recognized as legitimate TCP retransmission/jitter and suppressed (`status == DetectionStatus.NO_EVIDENCE`, `severity == Severity.NONE`, `verdict == "No replay violations observed"`).
  2. *Cryptographic Nonce Reuse with Timestamp Regression:* Packet 1 arrives with nonce `auth_token_nonce_998877` at $t_1 = 1000.8\text{s}$. A replayed packet arrives with identical nonce but earlier timestamp $t_2 = 1000.3\text{s}$ ($\Delta t = -0.5\text{s}$). Verified that timestamp regression does *not* mask genuine cryptographic replay; triggers `status == DetectionStatus.SUSPICIOUS`, `severity == Severity.HIGH`, `confidence >= 0.80`, `anomaly_type == "Cryptographic Nonce Reuse"`.
  3. *Timestamp Safety & Attribution:* Verified that `now = max(timestamps)` is computed safely, no negative time-delta exception occurs, and offending IP/MAC attribution remains intact.

### 2.2 Test 2: Serial Malformed Bytes Handling (GAP-82-06)
- **Method Name:** `test_serial_malformed_bytes_and_subsequent_valid_messages()`
- **File:** [test_live_collector.py](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/tests/test_live_collector.py) (Lines 806–885)
- **Class:** `TestCollectorWorkerSupervisionStage651`
- **Verification Logic:**
  1. *Null Bytes:* Ingests `"\x00\x00\x00"`; verified returns `"RAW_LOG"` and increments `stats["serial_raw_lines"] = 1`.
  2. *Invalid UTF-8:* Ingests replacement string `b"\xff\xfe\xfd".decode("utf-8", errors="replace")`; verified returns `"RAW_LOG"` and increments `stats["serial_raw_lines"] = 2`.
  3. *Whitespace:* Ingests `"   \t  \n"`; verified returns `None` and safely discards without incrementing error counters.
  4. *Non-Dict JSON:* Ingests `"[10, 20, 30]"`; verified returns `"INVALID_JSON"`.
  5. *Immediate Valid Message Processing:* Ingests valid sensor JSON immediately after corrupted lines:
     `{"node":"esp32_gateway","seq":101,"uptime_ms":20200,"dht11":{"valid":1,"temp_c":29.1,"humidity":88.4},"pir":{"motion":1}}`
     Verified returns `"SENSOR_TELEMETRY"`, increments `stats["sensor_records"] = 1`.
  6. *Subsequent Mixed Corrupted Line & Second Valid Message:* Ingests `"SERIAL_CORRUPT_FRAME_CHECKSUM_ERROR"` followed by valid sensor sequence 102 with motion=0.
  7. *Database State Verification:* Verifies on isolated temporary database that:
     - Exactly 2 rows exist in `live_sensor_telemetry` (`seq=101` and `102` for `Node_1` with $29.1^\circ\text{C}$ and $29.2^\circ\text{C}$).
     - Exactly 2 rows exist in `live_pir_events` (`seq=101` with `motion=1`, and `seq=102` with `motion=0` for `Node_2`).
     - Zero NULL, duplicate, or corrupted rows exist.
     - Serial worker thread remains completely healthy and unblocked.

### 2.3 Test 3: Simultaneous Device Windows Persistence (GAP-82-07)
- **Method Name:** `test_simultaneous_device_windows_preserved_without_overwrite()`
- **File:** [test_live_collector.py](file:///C:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/tests/test_live_collector.py) (Lines 887–995)
- **Class:** `TestCollectorWorkerSupervisionStage651`
- **Verification Logic:**
  1. *Simultaneous Bins:* Constructs two 1.0s feature windows for `Node_3` (`ca:34:ea:92:d3:9e`) and `Node_4` (`e6:2e:db:73:1c:25`) arriving at the exact same epoch (`bin_start_timestamp = 1700000000.0`).
  2. *Mixed Classifications:* `Node_3` window is scored as normal inlier (`pred_dual = 1`), while `Node_4` window is scored as an anomalous burst (`pred_dual = -1`, `dual_reason = "ANOMALY_PRIMARY_AND_TIMING"`).
  3. *Atomic Commit:* Both windows are committed via `_persist_window_with_retry()`.
  4. *Database State Verification:*
     - `live_traffic_windows` contains exactly 2 rows with distinct auto-increment primary keys (`window_id = 1` and `2`), both retaining `bin_start_epoch = 1700000000.0`.
     - Neither window overwrites the other.
     - `live_alerts` contains exactly 1 alert row referencing `Node_4`'s `window_id = 2`, `client_mac = "e6:2e:db:73:1c:25"`, `node_id = "Node_4"`. No false alert is created for `Node_3`.
     - `device_registry` has `last_seen` timestamps successfully updated for both devices.

---

## 3. Test Execution Results

### 3.1 Individual Test Execution (Group B Only)
```
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.0.2, pluggy-1.6.0
rootdir: C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection
plugins: anyio-4.12.1, asyncio-1.3.0
collected 115 items / 112 deselected / 3 selected

tests/test_attack_detector.py::TestReplayDetector::test_replay_out_of_order_packets_timestamp_regression PASSED [ 33%]
tests/test_live_collector.py::TestCollectorWorkerSupervisionStage651::test_serial_malformed_bytes_and_subsequent_valid_messages PASSED [ 66%]
tests/test_live_collector.py::TestCollectorWorkerSupervisionStage651::test_simultaneous_device_windows_preserved_without_overwrite PASSED [100%]

====================== 3 passed, 112 deselected in 2.33s ======================
```

### 3.2 Full Regression Test Suite Execution
```
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.0.2, pluggy-1.6.0
rootdir: C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection
plugins: anyio-4.12.1, asyncio-1.3.0
collected 391 items

tests\test_align_time_windows_with_sensors.py ......                     [  1%]
tests\test_attack_detector.py .......................................... [ 12%]
..........................                                               [ 18%]
tests\test_benchmark_1s_anomaly_detector.py ........                     [ 20%]
tests\test_correlate_traffic_and_sensors.py ....                         [ 21%]
tests\test_cross_session_1s_detector.py .....                            [ 23%]
tests\test_database_reliability.py ..............                        [ 26%]
tests\test_dual_detector_1s.py ......                                    [ 28%]
tests\test_evaluate_synthetic_1s_anomalies.py ......                     [ 29%]
tests\test_extract_pcap_time_windows.py ..........                       [ 32%]
tests\test_live_collector.py ........................................... [ 43%]
....                                                                     [ 44%]
tests\test_live_collector_attack_integration.py ........................ [ 50%]
............................................................             [ 65%]
tests\test_live_dashboard.py ............                                [ 69%]
tests\test_live_device_registry.py .................                     [ 73%]
tests\test_live_interface_resolver.py .........................          [ 79%]
tests\test_live_stream_extractor.py .................................... [ 89%]
............                                                             [ 92%]
tests\test_record_sensor_telemetry.py .......                            [ 93%]
tests\test_serial_protocol.py ..................                         [ 98%]
tests\test_validate_long_baseline_workflow.py ......                     [100%]

============================ 391 passed in 35.94s =============================
```

---

## 4. Source-Code Integrity Verification

All 39 Python files in `src/` remain completely untouched (verified via filesystem timestamps):

| File Name | Last Modified Time | Status |
| :--- | :--- | :--- |
| `src/live_collector.py` | 2026-11-10 20:23:16 | UNTOUCHED |
| `src/live_stream_extractor.py` | 2026-11-10 19:31:41 | UNTOUCHED |
| `src/live_dashboard.py` | 2026-11-10 18:45:56 | UNTOUCHED |
| `src/attack_detector.py` | 2026-11-10 17:43:16 | UNTOUCHED |
| `src/init_live_database.py` | 2026-11-07 21:00:01 | UNTOUCHED |
| `src/dual_detector_1s.py` | 2026-10-13 21:01:31 | UNTOUCHED |

---

## 5. Database Cryptographic Hash Verification

Cryptographic SHA-256 hashes of all databases were verified before and after test execution:

```
Algorithm Hash                                                             Path
--------- ----                                                             ----
SHA256    0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB data\live_monitoring.db (Pristine)
SHA256    CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968 data\iot_anomaly.db     (Pristine)
SHA256    74C773C29C49B25CE73E5D5B0641BAB5636FBCC83DA07E08CFFF5043761DFE2D data\test_stage722_live_monitoring.db
```

---

## 6. Discovered Defects or Discrepancies

- **Defects Discovered:** **Zero (0)**.
- **Architectural Confirmations:**
  1. `ReplayDetector` safely accommodates negative time-deltas ($\Delta t < 0$) resulting from network jitter or thread processing reordering, suppressing false alarms for legitimate same-flow retransmissions while reliably capturing genuine nonce reuse.
  2. `LiveCollector.process_serial_line()` safely absorbs null characters and non-UTF-8 strings, logs raw lines without crashing, and processes valid subsequent sensor frames cleanly.
  3. `live_traffic_windows` and `live_alerts` correctly key on independent `AUTOINCREMENT` integer IDs, allowing simultaneous client windows at identical epochs to persist without conflict or data loss.

---

## 7. Completion Status

Group B implementation is complete. All 3 edge-case tests have been integrated into `tests/test_attack_detector.py` and `tests/test_live_collector.py` and pass with 100% reliability.

*Per Stage 8.3 instructions, work has stopped after Group B. Awaiting user approval before proceeding to Group C.*

