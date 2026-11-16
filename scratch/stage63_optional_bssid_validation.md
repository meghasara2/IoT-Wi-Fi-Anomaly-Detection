# STAGE 6.3 — OPTIONAL BSSID VALIDATION CORRECTION REPORT

**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Workspace:** `C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection`  
**Execution Date:** 2026-11-10  
**Status:** COMPLETE & VERIFIED

---

## 1. Executive Summary

During the Stage 5.5 and 5.7 audits, an architectural inconsistency was identified in the Wi-Fi management telemetry ingestion pipeline:
- `DeauthDetector.evaluate()` in `src/attack_detector.py` implemented a fallback attribution mechanism (`bssid = p.wlan_bssid or p.eth_src or "unknown_bssid"`), allowing deauthentication and disassociation flood detection to proceed even when the BSSID was absent, by attributing the attack to the transmitter MAC address (`p.eth_src` / `ta`).
- However, upstream in `src/live_collector.py`, `validate_wifi_mgmt_event()` included `"bssid"` in its `required_keys` list (`["type", "boot_id", "seq", "uptime_ms", "subtype", "reason", "ta", "da", "bssid", "rssi"]`).
- Consequently, any incoming serial telemetry payload omitting the `"bssid"` key was prematurely rejected as `MALFORMED_WIFI_MGMT` before it could be enqueued into `_wifi_mgmt_queue` or mapped to a `PacketObservation`. As a result, the downstream detector's fallback attribution was rendered unreachable for over-the-air frames captured without BSSID.

In **Stage 6.3**, `validate_wifi_mgmt_event()` was corrected to make the `"bssid"` field optional, while preserving strict format validation when supplied (`None`, empty string, or valid 6-octet colon/hyphen MAC). All mandatory frame parameters remain strictly enforced. Missing BSSID events now cleanly traverse serial ingestion, validation, host queuing, observation mapping, and detector fallback attribution to source MAC.

---

## 2. Root Cause Analysis

### 2.1 Upstream vs. Downstream Mismatch
In `src/live_collector.py` prior to correction:
```python
# Lines 215-218 (PRE-FIX)
required_keys = ["type", "boot_id", "seq", "uptime_ms", "subtype", "reason", "ta", "da", "bssid", "rssi"]
for k in required_keys:
    if k not in payload:
        return False, f"Missing required key: '{k}'"

# Lines 246-248 (PRE-FIX)
bssid = payload["bssid"]
if bssid is not None and bssid != "" and not _is_valid_mac(bssid):
    return False, f"Invalid BSSID MAC: '{bssid}'"
```

Because `"bssid"` was in `required_keys`, any JSON payload omitting `"bssid"` triggered line 218 (`Missing required key: 'bssid'`).
Furthermore, line 246 used direct dictionary subscripting `payload["bssid"]`, which would raise a `KeyError` if `"bssid"` was absent without the `required_keys` check.

### 2.2 Downstream Fallback Readiness
Downstream components were already fully designed to handle `bssid is None`:
1. `_map_wifi_mgmt_to_observation()`:
   ```python
   bssid_raw = payload.get("bssid")
   if bssid_raw and _is_valid_mac(str(bssid_raw)):
       wlan_bssid = str(bssid_raw).strip().lower()
   else:
       wlan_bssid = None
   ```
2. `DeauthDetector.evaluate()`:
   ```python
   for p in deauth_frames:
       bssid = p.wlan_bssid or p.eth_src or "unknown_bssid"
   ```
3. `_persist_attack_results()`:
   ```python
   primary = att_res.evidence["details"][0]
   bssid = primary.get("bssid")
   deauth_src_mac = bssid if bssid and bssid != "unknown_bssid" else None
   ...
   _insert_attack_event(..., source_mac=deauth_src_mac, target_ip=None)
   ```

Because upstream validation blocked missing BSSID events at the serial boundary, this fallback chain could never be exercised via live telemetry.

---

## 3. Implementation Details

### 3.1 Code Changes in `src/live_collector.py`
In `validate_wifi_mgmt_event()`:
1. Removed `"bssid"` from `required_keys`:
   ```python
   required_keys = ["type", "boot_id", "seq", "uptime_ms", "subtype", "reason", "ta", "da", "rssi"]
   ```
2. Changed `payload["bssid"]` to safe `.get()` extraction:
   ```python
   bssid = payload.get("bssid")
   if bssid is not None and bssid != "" and not _is_valid_mac(bssid):
       return False, f"Invalid BSSID MAC: '{bssid}'"
   ```

### 3.2 Behavior Matrix

| Input Scenario | Validation Result | Normalized `wlan_bssid` | Downstream Attribution |
| :--- | :--- | :--- | :--- |
| `"bssid": "00:11:22:33:44:55"` | `(True, "OK")` | `"00:11:22:33:44:55"` | BSSID (`00:11:22:33:44:55`) |
| `"bssid"` key absent | `(True, "OK")` | `None` | Source MAC fallback (`p.eth_src` / `ta`) |
| `"bssid": None` | `(True, "OK")` | `None` | Source MAC fallback (`p.eth_src` / `ta`) |
| `"bssid": ""` | `(True, "OK")` | `None` | Source MAC fallback (`p.eth_src` / `ta`) |
| `"bssid": "invalid-mac"` | `(False, "Invalid BSSID MAC...")` | N/A (rejected) | Rejected at ingestion |
| Missing mandatory key (`ta`, `da`, `subtype`, etc.) | `(False, "Missing required key...")` | N/A (rejected) | Rejected at ingestion |

---

## 4. Test Suite and Verification

### 4.1 Existing Integration Test Updated
In `tests/test_live_collector_attack_integration.py`, line 2209:
- Updated `test_missing_required_fields_handled_safely` to reflect that `"bssid"` is an optional field:
  ```python
  for k in base_valid.keys():
      incomplete = dict(base_valid)
      del incomplete[k]
      is_valid, err_msg = validate_wifi_mgmt_event(incomplete)
      if k == "bssid":
          assert is_valid
          assert err_msg == "OK"
      else:
          assert not is_valid
          assert "Missing required key" in err_msg or "Expected type" in err_msg
  ```

### 4.2 New Stage 6.3 Dedicated Test Class
Added `TestOptionalBSSIDValidationStage63` in `tests/test_live_collector_attack_integration.py` containing 9 comprehensive test cases:
1. `test_valid_event_with_bssid_succeeds`: Valid explicit BSSID string passes.
2. `test_missing_bssid_key_succeeds`: Missing `"bssid"` key passes with `(True, "OK")`.
3. `test_explicit_none_bssid_succeeds`: `"bssid": None` passes with `(True, "OK")`.
4. `test_empty_string_bssid_succeeds`: `"bssid": ""` passes with `(True, "OK")`.
5. `test_invalid_bssid_string_rejected`: Malformed MAC strings and non-string types fail validation.
6. `test_missing_mandatory_fields_rejected`: Mandatory keys (`type`, `boot_id`, `seq`, `uptime_ms`, `subtype`, `reason`, `ta`, `da`, `rssi`) are strictly required.
7. `test_serial_ingestion_and_enqueue_missing_bssid`: Serial JSON without `"bssid"` returns `"WIFI_MGMT_ENQUEUED"`, updates metrics, and pushes to queue.
8. `test_map_wifi_mgmt_to_observation_missing_bssid`: Verifies `wlan_bssid` is `None` for missing/None/empty BSSID, and preserves valid BSSID.
9. `test_end_to_end_pipeline_missing_bssid_deauth_flood_fallback_attribution`: Ingests 6 serial deauth frames without `"bssid"`, drains the queue, evaluates via `NetworkAttackDetector`, triggers `CONFIRMED_THREAT` / `SUSPICIOUS`, attributes alert to source MAC `aa:11:22:33:44:bb`, persists to SQLite `live_attack_events`, and verifies `source_mac == "aa:11:22:33:44:bb"` and `target_ip IS NULL`.

### 4.3 Test Execution Summary

| Test Command | Scope | Result | Execution Time |
| :--- | :--- | :--- | :--- |
| `python -m pytest tests/test_live_collector_attack_integration.py -k TestOptionalBSSIDValidationStage63` | Focused Stage 6.3 tests | **9 / 9 PASSED** | 6.14s |
| `python -m pytest tests/test_live_collector_attack_integration.py` | Live collector attack integration | **84 / 84 PASSED** | 9.81s |
| `python -m pytest tests/test_attack_detector.py` | Core attack detection suite | **63 / 63 PASSED** | 0.14s |
| `python -m pytest tests/` | Complete project test suite | **330 / 330 PASSED** | 24.98s |

Total passing tests across the entire codebase increased from 321 to **330** with 0 failures and 0 warnings.

---

## 5. Production Database Integrity

As required by strict safety rules, no modifications were made to production SQLite databases. Hashes were re-verified following all test runs:

| Database File | Expected Baseline SHA-256 | Observed SHA-256 | Verification Status |
| :--- | :--- | :--- | :--- |
| `data/live_monitoring.db` | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | **UNTOUCHED / MATCH** |
| `data/iot_anomaly.db` | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | **UNTOUCHED / MATCH** |

---

## 6. Files Modified

1. `src/live_collector.py`
   - Modified `validate_wifi_mgmt_event()` to remove `"bssid"` from `required_keys` and use `payload.get("bssid")`.
2. `tests/test_live_collector_attack_integration.py`
   - Updated `test_missing_required_fields_handled_safely()`.
   - Added `TestOptionalBSSIDValidationStage63` class (9 unit and integration tests).

No production databases, firmware, trained models, or other source files were modified.

---

## 7. Remaining Limitations

1. **Passive Sniffing Frame Completeness:**
   If an attacker transmits spoofed deauthentication frames using randomized or null transmitter addresses in addition to omitting BSSID, fallback attribution groups by transmitter address (`eth_src`). If `ta` is also completely randomized per frame, grouping falls back to `"unknown_bssid"` unless rate thresholds across all deauth frames trigger an aggregate alert.
2. **Firmware Emitted BSSID:**
   The current ESP32 sensor node firmware (`firmware/esp32_sensor_node/esp32_sensor_node.ino`) currently populates BSSID from frame header byte offsets 16–21. The correction in Stage 6.3 ensures resilience if firmware parses truncated frames, 3-address frames without BSSID, or if upstream serial forwarders drop the `bssid` key.

