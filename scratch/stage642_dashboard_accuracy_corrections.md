# STAGE 6.4.2 — DASHBOARD STATUS ACCURACY CORRECTIONS REPORT

**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Workspace:** `C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection`  
**Date:** November 10, 2026  
**Status:** Completed & Fully Validated  

---

## 1. Executive Summary

During Stage 6.4.1, a read-only audit of the newly implemented dashboard attack-category status indicators and ESP32 diagnostics (`src/live_dashboard.py`) revealed five critical accuracy defects:
1. **Latest Session Run-ID Scoping:** When `run_id=None` ("Latest Session"), queries omitted a `WHERE run_id = ?` clause, aggregating all historical attack events into the latest session status cards.
2. **Deauthentication Telemetry Accuracy:** Environmental DHT11 sensor telemetry was incorrectly accepted as proof that the 802.11 management frame sniffer was operational.
3. **Replay Telemetry Accuracy:** Generic packet counts (`total_packets > 0`) were accepted as proof of replay detection capability, even when cryptographic nonces or TCP sequence payload hashes were unavailable.
4. **Spoofing Telemetry Accuracy:** Generic packet counts alone were accepted as proof of spoofing telemetry without verifying IP-to-MAC registry baselines or IP traffic observations.
5. **Collector Heartbeat Staleness:** A collector record marked `RUNNING` would misleadingly report active monitoring indefinitely, even if the collector daemon crashed or was killed without updating `collector_status`.

In Stage 6.4.2, all five defects were systematically corrected in `src/live_dashboard.py`. In addition, orphaned duplicate code fragments in `src/live_dashboard.py` were eliminated, and a 12-scenario test suite was implemented in `tests/test_live_dashboard.py`.

### Validation Overview
- **Dashboard Status Test Suite (`tests/test_live_dashboard.py`):** **12 / 12 PASSED** (100%).
- **Full Project Regression Test Suite (`tests/`):** **342 / 342 PASSED** (100%).
- **Database Integrity:** Zero modifications to production databases (`data/live_monitoring.db` and `data/iot_anomaly.db`); SHA256 hashes verified pristine.

---

## 2. Root Cause Analysis & Corrections

### Defect 1: Latest Session Run-ID Scoping
- **Root Cause:** When `run_id=None`, `filter_clause` resolved to `""`. Consequently, `SELECT ... FROM live_attack_events` scanned all rows across every historical run in the database. Historical alerts from terminated runs (e.g., Run 1) contaminated the status of a subsequent clean run (e.g., Run 2).
- **Correction:** 
  1. Inspect `collector_status` to determine the latest valid session run ID:
     ```python
     effective_run_id = run_id if run_id is not None else (status_row[0] if status_row else None)
     filter_clause = f"WHERE run_id = {effective_run_id}" if effective_run_id is not None else ""
     ```
  2. Apply `effective_run_id` consistently across all queries (`live_traffic_windows`, `live_sensor_telemetry`, and `live_attack_events`).
  3. In `render_attack_intelligence()`, pass `run_id=effective_run_id` to `fetch_attack_events()`, ensuring the event table feed is also strictly scoped to the active session.

### Defect 2: Deauthentication Telemetry Accuracy
- **Root Cause:** `has_esp32_active` checked `(sensor_count > 0 or daemon_status == "RUNNING")`. Sensor count reflects ambient DHT11 readings (`live_sensor_telemetry`). An active DHT11 sensor node proves serial communication, but does *not* prove that 802.11 management frames are being sniffed or parsed.
- **Correction:** 
  Decoupled physical environmental sensor records from 802.11 sniffer validation. Deauthentication status requires verified 802.11 management frame evaluations in `live_attack_events` that are not `INSUFFICIENT_TELEMETRY`. If no verified deauth telemetry is present, the card strictly reports `INSUFFICIENT TELEMETRY` (`ESP32 802.11 sniffer telemetry unavailable • NDIS filters mgmt frames`).

### Defect 3: Replay Telemetry Accuracy
- **Root Cause:** When no explicit `INSUFFICIENT_TELEMETRY` record was present, `elif total_packets > 0:` caused the Replay card to display `NO ALERT OBSERVED`. However, general TShark packet captures on Windows Hotspot adapters do not contain cryptographic nonces or payload hashes.
- **Correction:** 
  Replay status strictly reports `INSUFFICIENT TELEMETRY` unless actual cryptographic nonces or payload hashes are verified in `evidence_json`:
  ```python
  has_crypto_telemetry = False
  for r in cat_events:
      ev_raw = r[6]
      if ev_raw:
          try:
              ev = json.loads(ev_raw) if isinstance(ev_raw, str) else ev_raw
              if isinstance(ev, dict) and (ev.get("payload_hash") or ev.get("nonce") or ev.get("crypto_telemetry")):
                  has_crypto_telemetry = True
                  break
          except Exception:
              pass
  ```
  If `has_crypto_telemetry` is false, Replay remains `INSUFFICIENT TELEMETRY`.

### Defect 4: Spoofing Telemetry Accuracy
- **Root Cause:** Spoofing required only `total_windows >= 1 and total_packets > 0`. General packet counts do not establish whether IP addresses (`ip_src`, `ip_dst`) and MAC addresses are available for identity binding.
- **Correction:** 
  Spoofing requires verified IP-to-MAC evidence—either from `device_registry` containing registered IP mappings, or from observed IP traffic in `live_attack_events` (`target_ip` populated or `ev.get("ip")`). Without IP-to-MAC baseline or observation data, the card reports `INSUFFICIENT TELEMETRY`.

### Defect 5: Collector Heartbeat Staleness & Abandoned Sessions
- **Root Cause:** If the collector crashed, `collector_status` retained `status = 'RUNNING'` indefinitely, falsely signaling to operators that live monitoring was healthy.
- **Correction:** 
  Implemented `_is_heartbeat_stale(last_heartbeat_raw, timeout_seconds=60.0)` helper function ($6\times$ the collector's 10-second heartbeat interval).
  - If `daemon_status == "RUNNING"` but the heartbeat is $>60\text{s}$ old, missing (`NULL`), or unparseable, the dashboard overrides all attack categories to:
    `MONITORING UNAVAILABLE (Collector heartbeat stale)`
  - Serial sniffer diagnostics reports: `connection_status = "Heartbeat Stale / Inactive"`.

### Defect 6: Contextual Live vs Archived Session Tagging
- **Correction:**
  The dashboard now transparently reports session context:
  - If the collector is running with a fresh heartbeat: `[Live Session]`.
  - If viewing an archived or historical run: `[Archived Session #<run_id>]`.
  - Sub-captions and headers clearly reflect whether alerts are active or historical.

---

## 3. Code Modifications Summary

### 1. `src/live_dashboard.py`
- **Cleaned Orphaned Code:** Removed 5 orphaned duplicated code snippets accidentally injected between `fetch_*` functions.
- **Added `_is_heartbeat_stale()`:**
  ```python
  def _is_heartbeat_stale(
      last_heartbeat_raw: Any,
      timeout_seconds: float = 60.0,
  ) -> Tuple[bool, Optional[float]]:
      if not last_heartbeat_raw:
          return True, None
      try:
          clean_str = str(last_heartbeat_raw).strip().replace("T", " ")[:19]
          hb_dt = datetime.datetime.strptime(clean_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=datetime.timezone.utc)
          now_utc = datetime.datetime.now(datetime.timezone.utc)
          age = (now_utc - hb_dt).total_seconds()
          if age < 0:
              return False, 0.0
          return age > timeout_seconds, age
      except Exception:
          return True, None
  ```
- **Refactored `compute_attack_category_status()`:**
  - Dynamic `effective_run_id` resolution.
  - Heartbeat staleness evaluation overriding stale `RUNNING` status.
  - Decoupled Deauth sniffer verification from DHT11 sensor records.
  - Enforced nonce/payload hash verification for Replay.
  - Enforced IP-to-MAC telemetry for Spoofing.
  - Added session context tagging (`[Live Session]` vs `[Archived Session #<id>]`).
- **Refactored `fetch_esp32_sniffer_diagnostics()`:**
  - Scoped to `effective_run_id`.
  - Evaluates heartbeat staleness against `last_heartbeat`.
- **Refactored `render_attack_intelligence()`:**
  - Scopes event feed table to `effective_run_id`.
  - Displays context badge `[Live Session]` or `[Archived Session #<id>]`.

### 2. `tests/test_live_dashboard.py`
- Upgraded test suite from 10 tests to 12 rigorous tests matching Stage 6.4.2 specifications.

---

## 4. Test Results

### 1. Stage 6.4.2 Test Suite Execution
Command: `python -m pytest tests/test_live_dashboard.py -v`

| Test Name | Target Behavior | Result |
| :--- | :--- | :--- |
| `test_01_latest_session_excludes_previous_run_events` | `run_id=None` resolves latest run and excludes historical run alerts | **PASSED** |
| `test_02_explicit_run_id_selection_works` | Explicit `run_id=1` targets historical run and reports its alerts | **PASSED** |
| `test_03_dht11_activity_does_not_establish_deauth_telemetry` | DHT11 telemetry alone does not validate Deauth sniffer | **PASSED** |
| `test_04_missing_wifi_mgmt_telemetry_produces_insufficient` | Missing 802.11 management frames reports `INSUFFICIENT TELEMETRY` | **PASSED** |
| `test_05_replay_insufficient_with_only_generic_packet_counts` | Generic packet counts without cryptographic nonces report `INSUFFICIENT` | **PASSED** |
| `test_06_replay_eligible_only_with_actual_hash_or_nonce_evidence` | Cryptographic hash/nonce evidence enables Replay operational status | **PASSED** |
| `test_07_spoofing_insufficient_without_ip_to_mac_registry` | Spoofing reports `INSUFFICIENT` without IP-to-MAC telemetry | **PASSED** |
| `test_08_valid_ip_to_mac_evidence_handled_correctly` | Registered IP mappings or observed IP traffic enable Spoofing evaluation | **PASSED** |
| `test_09_stale_heartbeat_overrides_running_status` | Heartbeat $>60\text{s}$ old overrides `RUNNING` to `MONITORING UNAVAILABLE` | **PASSED** |
| `test_10_missing_or_invalid_heartbeat_handled_conservatively` | `NULL` or unparseable heartbeats safely override `RUNNING` | **PASSED** |
| `test_11_archived_sessions_identified_correctly` | Archived sessions tagged `[Archived Session #<id>]` with `is_live=False` | **PASSED** |
| `test_12_empty_database_and_sql_error_handling` | Empty DB, `None` connection, closed DB, and partial payloads handled | **PASSED** |

**Summary: 12 passed in 3.13s**

### 2. Full Regression Suite Execution
Command: `python -m pytest tests/`

```text
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.0.2, pluggy-1.6.0
rootdir: C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection
collected 342 items

tests\test_align_time_windows_with_sensors.py ......                     [  1%]
tests\test_attack_detector.py .......................................... [ 14%]
.....................                                                    [ 20%]
tests\test_benchmark_1s_anomaly_detector.py ........                     [ 22%]
tests\test_correlate_traffic_and_sensors.py ....                         [ 23%]
tests\test_cross_session_1s_detector.py .....                            [ 25%]
tests\test_dual_detector_1s.py ......                                    [ 26%]
tests\test_evaluate_synthetic_1s_anomalies.py ......                     [ 28%]
tests\test_extract_pcap_time_windows.py ..........                       [ 31%]
tests\test_live_collector.py .....................................       [ 42%]
tests\test_live_collector_attack_integration.py ........................ [ 49%]
............................................................             [ 66%]
tests\test_live_dashboard.py ............                                [ 70%]
tests\test_live_device_registry.py ........                              [ 72%]
tests\test_live_interface_resolver.py .........................          [ 80%]
tests\test_live_stream_extractor.py .................................... [ 90%]
............                                                             [ 94%]
tests\test_record_sensor_telemetry.py .......                            [ 96%]
tests\test_serial_protocol.py .......                                    [ 98%]
tests\test_validate_long_baseline_workflow.py ......                     [100%]

============================ 342 passed in 25.35s =============================
```

---

## 5. Database Integrity Verification

Both production databases were strictly untouched during all inspection, modification, and test phases:

| Database File | Expected SHA256 Hash | Observed SHA256 Hash | Status |
| :--- | :--- | :--- | :--- |
| `data/live_monitoring.db` | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | **MATCH (UNTOUCHED)** |
| `data/iot_anomaly.db` | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | **MATCH (UNTOUCHED)** |

---

## 6. Remaining Telemetry & Architecture Realities

In alignment with academic honesty and research rigor:
1. **Windows NDIS 802.11 Frame Stripping:** Standard Windows Wi-Fi adapters in Mobile Hotspot mode provide emulated 802.3 Ethernet frames. Raw 802.11 management frames (Deauth/Disassoc) and physical radiotap headers (RSSI) are stripped by NDIS before reaching user-space TShark. The dedicated ESP32 hardware sniffer remains the sole authorized source for management frame telemetry.
2. **Periodic Sniffer Summary In-Memory Scope:** Firmware periodic summary counters (`rx_total`, `tb_suppressed`, `enqueued`) are received over serial and maintained in the daemon's in-memory state (`_last_summary_snapshot`). Because Streamlit operates in a separate process with a read-only database URI, these counters remain `Unavailable (in-memory only)` on the dashboard to prevent fabricating numbers. Individual detected deauth attack events are persisted to `live_attack_events` and correctly displayed.
3. **Replay Cryptographic Nonces:** Standard TCP streams lack application-layer nonces unless specialized protocols are inspected. Replay accurately remains `INSUFFICIENT TELEMETRY` during standard HTTP/TCP traffic monitoring.

---

## 7. Conclusion & Readiness

Stage 6.4.2 has fully resolved all identified status calculation, telemetry validation, heartbeat staleness, and session scoping defects. The live dashboard now operates with scientific honesty, never reports false operational readiness, and provides transparent visibility into both live and archived monitoring runs.

All work in Stage 6.4.2 is complete and verified. The agent awaits user approval before proceeding to any subsequent tasks.

