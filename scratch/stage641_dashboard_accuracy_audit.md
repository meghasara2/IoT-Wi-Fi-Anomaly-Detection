# STAGE 6.4.1 — DASHBOARD STATUS ACCURACY AUDIT

**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Workspace:** `C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection`  
**Execution Date:** 2026-11-10  
**Audit Scope:** Read-Only Source Code & Test Verification (`src/live_dashboard.py`, `tests/test_live_dashboard.py`, `scratch/stage64_dashboard_correction.md`)  
**Status:** AUDIT COMPLETE (Read-Only)

---

## 1. Executive Summary

This audit rigorously evaluates the dashboard status logic implemented in Stage 6.4, specifically focusing on `compute_attack_category_status()` and its telemetry availability rules in `src/live_dashboard.py`.

The audit identified **4 critical architectural edge cases** where the current implementation risks conveying false confidence or inaccurate threat scoping:
1. **Unscoped Default View (`run_id=None`):** On the default `"Latest Session"` dropdown selection, the query omits `WHERE run_id = ...`, causing historical attacks from past runs to contaminate the current session view.
2. **Environmental Sensor Conflation with Wi-Fi Sniffing:** An active serial link with DHT11 temperature/humidity readings falsely marks Wi-Fi Deauthentication as green `NO ALERT OBSERVED`, even if the ESP32 is not running promiscuous 802.11 sniffer firmware.
3. **Replay Fallback on Generic Packet Traffic:** If the baseline `INSUFFICIENT_TELEMETRY` seed record is absent, Replay falsely marks green `NO ALERT OBSERVED` merely because generic TCP packets exist (`total_packets > 0`), despite cryptographic nonces and payload hashes being uncaptured.
4. **Crashed Daemon False-Active State:** The dashboard checks `status == 'RUNNING'` without evaluating `last_heartbeat` staleness. A collector daemon that crashed or froze hours ago continues to display active green `NO ALERT OBSERVED`.

All findings, relevant code references, risks, and smallest surgical corrections are detailed below.

---

## 2. Detailed Findings by Verification Item

---

### Item 1: Are attack counts scoped to the selected `run_id`?

- **Current Implementation Behavior:**
  - In `compute_attack_category_status(conn, run_id)`:
    - Line 972: `filter_clause = f"WHERE run_id = {run_id}" if run_id else ""`
    - Line 1018: `f"FROM live_attack_events {filter_clause} ORDER BY event_id DESC"`
  - When an explicit run is selected (e.g. `run_id=1`), the query is scoped: `WHERE run_id = 1`.
  - However, in `main()` (lines 2519–2523), the sidebar dropdown defaults to `"Latest Session"`, which sets `selected_run_id = None`.
  - When `run_id is None`: `filter_clause` becomes empty string `""`.
  - Consequently, `cur.execute("SELECT ... FROM live_attack_events ORDER BY event_id DESC")` retrieves and aggregates **all attack events across all runs in the database**.
- **Relevant Code Locations:**
  - `src/live_dashboard.py`: lines 972, 1018, 2519–2523.
- **Whether the Behavior is Correct:**
  **PARTIALLY INCORRECT.**
  Correct when a specific numerical run is chosen; incorrect when `"Latest Session"` is selected.
- **False-Positive or False-Confidence Risk:**
  **HIGH FALSE-POSITIVE RISK FOR NEW SESSIONS:**
  If Run 1 had 500 DoS attack events, and the operator launches a clean, attack-free Run 2, the dashboard on "Latest Session" will display `DETECTED: 🚨 500 Threat(s) Flagged` for DoS, misleading the operator into believing the current active network is under attack.
- **Smallest Recommended Correction:**
  In `compute_attack_category_status()`:
  ```python
  # Resolve effective run_id if run_id is None
  effective_run_id = run_id
  if effective_run_id is None and status_row:
      effective_run_id = status_row[0]  # Latest run_id from collector_status
  filter_clause = f"WHERE run_id = {effective_run_id}" if effective_run_id is not None else ""
  ```

---

### Item 2: Are old alerts from previous monitoring runs excluded from current-run counts?

- **Current Implementation Behavior:**
  - When an explicit run ID is selected: YES, old alerts from other runs are excluded by `WHERE run_id = {run_id}`.
  - When `"Latest Session"` (`run_id=None`) is selected: NO, old alerts from previous runs are NOT excluded. They are summed together.
- **Relevant Code Locations:**
  - `src/live_dashboard.py`: line 972 (`filter_clause`), line 1018 (`live_attack_events`).
- **Whether the Behavior is Correct:**
  **INCORRECT on "Latest Session".**
- **False-Positive or False-Confidence Risk:**
  Past attack drills or legacy test runs permanently contaminate the "Latest Session" status view.
- **Smallest Recommended Correction:**
  Always bind queries to the resolved `effective_run_id`.

---

### Item 3: Does the dashboard distinguish historical alerts from current alerts?

- **Current Implementation Behavior:**
  - The dashboard displays a timestamp string (e.g. `Latest: 2026-11-07 15:25:38`) in the card subtext (line 1052).
  - In `render_system_overview()`, an archived banner is shown if `status == 'STOPPED'`.
  - However, within the attack category cards in `render_attack_intelligence()`:
    - There is no indicator whether the displayed threat event occurred in an archived past run, 3 days ago, or 10 seconds ago.
    - If `run_id=None`, historical alerts appear side-by-side with current status.
- **Relevant Code Locations:**
  - `src/live_dashboard.py`: lines 1045–1055, lines 2243–2264.
- **Whether the Behavior is Correct:**
  **PARTIALLY INCORRECT.**
  Timestamps are shown, but temporal context (live vs. historical/archived) is absent from the cards.
- **False-Positive or False-Confidence Risk:**
  Operator confusion: seeing `DETECTED` without knowing if the attack is ongoing right now or occurred in an archived session.
- **Smallest Recommended Correction:**
  If `daemon_status == 'STOPPED'`, prefix the card subtext with `[Archived Session #X]`. If `daemon_status == 'RUNNING'` and the latest alert is older than 5 minutes, mark as `Prior Threat in Session (Dormant)`.

---

### Item 4: Can Deauthentication show `NO ALERT OBSERVED` when only sensor serial connectivity is known but no actual Wi-Fi management telemetry is available?

- **Current Implementation Behavior:**
  - Lines 1001–1008:
    ```python
    s_row = cur.execute(f"SELECT COUNT(*) FROM live_sensor_telemetry {filter_clause}").fetchone()
    sensor_count = s_row[0] if s_row else 0
    has_esp32_active = (serial_port is not None and str(serial_port).lower() not in ("none", "disabled", "")) and (sensor_count > 0 or daemon_status == "RUNNING")
    ```
  - Lines 1126–1135:
    ```python
    elif cat_k == "deauth":
        if has_esp32_active:
            results[cat_k] = {
                "title": cfg["title"],
                "status": "NO ALERT OBSERVED",
                "color": DARK_PALETTE["safe_emerald"],
                "border_cls": "success-border",
                "sub": "ESP32 serial sniffer active • No deauth flood flagged",
                ...
            }
    ```
- **Relevant Code Locations:**
  - `src/live_dashboard.py`: lines 1001–1008, lines 1126–1135.
- **Whether the Behavior is Correct:**
  **INCORRECT.**
  `sensor_count` queries `live_sensor_telemetry` (Node 1 DHT11 environmental readings).
  Receiving DHT11 temperature and humidity readings over serial does NOT mean the ESP32 is running promiscuous Wi-Fi management frame sniffing.
- **False-Positive or False-Confidence Risk:**
  **CRITICAL FALSE-CONFIDENCE RISK:**
  If an operator connects an ESP32 that only streams DHT11/PIR readings, the dashboard displays green `NO ALERT OBSERVED` with text `"ESP32 serial sniffer active • No deauth flood flagged"`. The operator is falsely led to believe the Wi-Fi management airwaves are being monitored, when zero 802.11 management frames can actually be captured.
- **Smallest Recommended Correction:**
  Do not infer Wi-Fi sniffer operation from DHT11 sensor records alone.
  Check for actual sniffer telemetry evidence:
  1. Has any deauth event been parsed?
  2. Or has the sniffer initialization handshake (`WIFI_SNIFFER_INITIALIZED`) or periodic summary been recorded?
  If only environmental sensors are streaming without confirmed Wi-Fi sniffer telemetry, display `INSUFFICIENT TELEMETRY` with subtext `"Sensors streaming • Wi-Fi sniffer telemetry unconfirmed"`.

---

### Item 5: Does Replay correctly show `INSUFFICIENT TELEMETRY` when payload hashes and nonces are unavailable?

- **Current Implementation Behavior:**
  - Lines 1148–1177:
    ```python
    elif cat_k == "replay":
        if insufficient_records:
            results[cat_k] = {
                "status": "INSUFFICIENT TELEMETRY", ...
            }
        elif total_packets > 0:
            results[cat_k] = {
                "status": "NO ALERT OBSERVED",
                "color": DARK_PALETTE["safe_emerald"],
                "border_cls": "success-border",
                "sub": "Flow sequence monitoring active • No replay flagged",
                ...
            }
    ```
- **Relevant Code Locations:**
  - `src/live_dashboard.py`: lines 1039–1042, lines 1148–1177.
- **Whether the Behavior is Correct:**
  **FRAGILE & CONDITIONALLY INCORRECT.**
  - If the collector seeded `('Replay_Attack', 'INSUFFICIENT_TELEMETRY', 'NONE')` at startup, it correctly reports `INSUFFICIENT TELEMETRY`.
  - However, if that baseline row is absent (e.g. clean test database, unseeded run, or cleared table), `insufficient_records` is empty. Because `total_packets > 0`, the logic falls into `elif total_packets > 0:`, displaying green `NO ALERT OBSERVED`.
- **False-Positive or False-Confidence Risk:**
  **FALSE-CONFIDENCE RISK:**
  As proven in Stages 5.6 and 5.7, TCP sequence tracking alone does not constitute application replay attack detection. TShark does not extract application nonces or payload hashes in default capture mode. Showing green `NO ALERT OBSERVED` on generic TCP packets provides false confidence.
- **Smallest Recommended Correction:**
  Invert the default: Replay should report `INSUFFICIENT TELEMETRY` unless explicit cryptographic nonce or application payload hash telemetry is confirmed present in the session evidence.

---

### Item 6: Does Spoofing require relevant IP-to-MAC telemetry rather than general network activity?

- **Current Implementation Behavior:**
  - Lines 1104–1123:
    ```python
    elif cat_k == "spoofing":
        if total_windows >= 1 and total_packets > 0:
            results[cat_k] = {
                "status": "NO ALERT OBSERVED",
                "sub": "IP-to-MAC mapping active • No spoofing alert",
                ...
            }
    ```
- **Relevant Code Locations:**
  - `src/live_dashboard.py`: lines 976–980, lines 1104–1123.
- **Whether the Behavior is Correct:**
  **IMPRECISE.**
  `total_windows >= 1 and total_packets > 0` verifies only that general Ethernet frames were captured. It does not verify that IP addresses (`ip_src`, `ip_dst`) were parsed from those frames or mapped to MACs in `device_registry`.
- **False-Positive or False-Confidence Risk:**
  **Minor False-Confidence Risk:**
  If the network has only Layer 2 non-IP traffic (e.g. pure ARP broadcasts, EAPOL, STP), Spoofing will still claim `"IP-to-MAC mapping active"`. On a Wi-Fi mobile hotspot, IP traffic is normally present, so the operational risk is low, but conceptually imprecise.
- **Smallest Recommended Correction:**
  Verify that at least one registered client or window contains a valid IP address:
  `SELECT COUNT(*) FROM device_registry WHERE ip_address IS NOT NULL`.

---

### Item 7: Can a stale collector or stale telemetry incorrectly appear active?

- **Current Implementation Behavior:**
  - Lines 988–998:
    `daemon_status = status_row[1] if status_row else "OFFLINE"`
  - If the collector daemon process crashes or terminates abnormally without running its shutdown hook, the SQLite row in `collector_status` remains `status = 'RUNNING'`.
  - `compute_attack_category_status()` never checks `last_heartbeat` or compares it to the current time.
  - Because `status == 'RUNNING'`, `is_monitoring_functional` evaluates to `True`, and `has_esp32_active` evaluates to `True`.
- **Relevant Code Locations:**
  - `src/live_dashboard.py`: lines 960–970 (query omits `last_heartbeat`), lines 988–998 (no staleness check).
- **Whether the Behavior is Correct:**
  **INCORRECT.**
  A crashed or hung collector daemon will be treated as actively running indefinitely.
- **False-Positive or False-Confidence Risk:**
  **CRITICAL FALSE-ACTIVE RISK:**
  An operator opening the dashboard hours after a collector crash will see green `NO ALERT OBSERVED` across categories and assume the system is actively monitoring the network.
- **Smallest Recommended Correction:**
  Fetch `last_heartbeat` from `collector_status`. If `daemon_status == 'RUNNING'` and `last_heartbeat` is older than 60 seconds (or `datetime.utcnow() - last_heartbeat > 60s`), override `daemon_status` to `'STALE'` and report `MONITORING UNAVAILABLE` with subtext `"Collector daemon heartbeat lost (>60s)"`.

---

### Item 8: Are all five categories handled conservatively when the database is empty or incomplete?

- **Current Implementation Behavior:**
  - `conn is None`: Returns `MONITORING UNAVAILABLE` for all 5 categories (lines 948–951).
  - Empty database (`not status_row and total_windows == 0`): Returns `MONITORING UNAVAILABLE` for all 5 categories (lines 983–986).
  - Query exceptions: Caught in `try...except`, returns `MONITORING UNAVAILABLE` with error description for all 5 categories (lines 1179–1188).
  - Closed connections: Caught and returns `MONITORING UNAVAILABLE`.
- **Relevant Code Locations:**
  - `src/live_dashboard.py`: lines 948–951, 983–986, 1179–1188.
- **Whether the Behavior is Correct:**
  **CORRECT.**
  The empty, null, and exception handling paths are completely conservative and resilient.

---

### Item 9: Do the existing dashboard tests actually cover these cases?

- **Current Implementation Behavior:**
  - `tests/test_live_dashboard.py` currently has 10 tests:
    - `test_01`: Explicitly sets `run_id=1`. Does not test `run_id=None` or multi-run contamination.
    - `test_02`: Seeds DHT11 sensor data and asserts `deauth == 'NO ALERT OBSERVED'`. It validates the code as written, but does not test whether DHT11 sensor data without Wi-Fi sniffer frames should be accepted.
    - `test_02`: Seeds generic traffic without nonces and asserts `replay == 'NO ALERT OBSERVED'`. Validates the code as written, but does not test nonce availability.
    - `test_04`: Tests `status = 'ERROR'`, but does not test heartbeat timeout when `status = 'RUNNING'`.
    - `test_05`–`test_10`: Accurately test baseline capability exclusion, statistical alert decoupling, empty DB, partial summary handling, unpersisted memory handling, and query failure.
- **Relevant Code Locations:**
  - `tests/test_live_dashboard.py`: lines 99–319.
- **Whether the Behavior is Correct:**
  **PARTIALLY INCOMPLETE.**
  The test suite ensures the existing code behaves as implemented, but does not test the 4 edge cases identified in this audit.
- **False-Positive or False-Confidence Risk:**
  Tests pass at 100% (10/10), which may give a false impression that multi-run scoping, sniffer separation, and heartbeat staleness are covered when they are not.
- **Smallest Recommended Correction:**
  Add 3 targeted test methods to `tests/test_live_dashboard.py`:
  1. `test_multirun_scoping_latest_session()`
  2. `test_collector_heartbeat_staleness()`
  3. `test_deauth_requires_mgmt_telemetry_not_just_dht11()`

---

## 3. Summary of Findings & Action Plan

| Item | Focus Area | Status | Severity | Recommended Fix Scope |
| :---: | :--- | :---: | :---: | :--- |
| **1** | Run ID Scoping | **Defect** | High | Resolve `effective_run_id = status_row[0]` when `run_id is None`. |
| **2** | Alert Isolation Across Runs | **Defect** | High | Bind all queries to `effective_run_id`. |
| **3** | Live vs. Historical Context | **Imprecise** | Medium | Add session context prefix to card subtext. |
| **4** | Deauth Telemetry Verification | **Defect** | High | Require actual Wi-Fi sniffer telemetry, not just DHT11 sensor records. |
| **5** | Replay Nonce Verification | **Fragile** | Medium | Default Replay to `INSUFFICIENT TELEMETRY` unless nonces confirmed. |
| **6** | Spoofing IP Verification | **Imprecise** | Low | Check for presence of IP addresses in traffic/registry. |
| **7** | Daemon Staleness Detection | **Defect** | High | Compare `last_heartbeat` to current time; flag stale if $>60\text{s}$. |
| **8** | Conservative Empty Handling | **Verified** | None | Already fully conservative and robust. |
| **9** | Test Coverage Completeness | **Incomplete** | Medium | Add tests for multi-run scoping, staleness, and sniffer decoupling. |

---

## 4. Verification Check

In accordance with strict safety rules:
- No source code files were modified.
- No tests were modified.
- No production database writes occurred.
- Production database hashes remain 100% identical to baseline:
  - `data/live_monitoring.db`: `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB`
  - `data/iot_anomaly.db`: `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968`

