# STAGE 6.4 — LIVE DASHBOARD STATUS CORRECTION AND ESP32 DIAGNOSTICS REPORT

**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Workspace:** `C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection`  
**Execution Date:** 2026-11-10  
**Status:** COMPLETE & VERIFIED

---

## 1. Executive Summary

In **Stage 6.4**, the Streamlit live threat console in `src/live_dashboard.py` was corrected from hardcoded placeholder cards to a fully dynamic, evidence-backed evaluation engine. A dedicated **ESP32 Wi-Fi Sniffer Health & Telemetry Diagnostics Panel** was implemented to provide real-time hardware visibility without fabricating unpersisted data.

Key achievements:
1. **Dynamic Database-Driven Statuses:** Replaced misleading static labels with rigorous real-time database queries across all five attack categories:
   - `DETECTED`: Confirmed or suspicious attack events present in `live_attack_events`.
   - `NO ALERT OBSERVED`: Relevant telemetry verified active in capture stream with no alert flagged.
   - `INSUFFICIENT TELEMETRY`: Necessary packet headers or hardware source unavailable.
   - `MONITORING UNAVAILABLE`: Collector offline, in error, or database uninitialized.
2. **Strict Metric Separation:** Preserved complete independence between Isolation Forest statistical anomalies (`live_alerts`) and deterministic attack events (`live_attack_events`). Statistical anomalies are never misclassified as cyberattacks.
3. **Startup Capability Record Filtering:** Excluded baseline capability records seeded at collector initialization from being counted as detected attacks.
4. **ESP32 Sniffer Diagnostics Panel:** Displayed actual persisted telemetry link health (`COM6`, `2,214` sensor records, device identity `esp32_gateway`, last-seen timestamps) and honestly reported in-memory periodic summary counters as `Unavailable (in-memory only)` to respect pipeline architecture constraints.
5. **Zero Production Impact:** Tested strictly via temporary isolated SQLite databases without starting live monitoring, TShark, COM6 serial, or modifying production databases. Both production SQLite database hashes were preserved with 100% bit-level integrity.

---

## 2. Initial Inspection Findings & Original Defects

### 2.1 The Hardcoded Operational Ribbon
In `src/live_dashboard.py` lines 1450–1508 (`render_attack_intelligence`), the five attack-category cards previously had hardcoded HTML strings:
- **Card 1 (Denial of Service):** Hardcoded green `<div class="metric-val" ...>OPERATIONAL</div>`.
- **Card 2 (Reconnaissance / Port Scan):** Hardcoded green `<div class="metric-val" ...>OPERATIONAL</div>`.
- **Card 3 (Spoofing / Impersonation):** Hardcoded green `<div class="metric-val" ...>OPERATIONAL</div>`.
- **Card 4 (Wi-Fi Deauth Flood):** Hardcoded gray `<div class="metric-val" ...>INSUFFICIENT</div>`.
- **Card 5 (Replay Attack):** Hardcoded gray `<div class="metric-val" ...>INSUFFICIENT</div>`.

### 2.2 Operational Contradictions Resolved
- **False Safety:** When inspecting `data/live_monitoring.db`, DoS had **516** flagged threat events and Port Scan had **951** flagged threat events, yet both cards displayed green `OPERATIONAL` as if no attack existed.
- **Permanent Invalidation:** Deauth and Replay cards were permanently locked to gray `INSUFFICIENT` regardless of actual detector findings or active ESP32 sniffer telemetry.
- **Disconnection from DB Evidence:** The cards never queried `live_attack_events`, `collector_status`, or `live_traffic_windows`.

---

## 3. Database-Driven Status Architecture

### 3.1 Four Strict Operational Distinctions

| Status | Visual Styling | Border CSS | Definition & Trigger Condition |
| :--- | :--- | :--- | :--- |
| **`DETECTED`** | Coral Red (`#F43F5E`) | `alert-border` | Persisted attack event in `live_attack_events` with `status IN ('CONFIRMED_THREAT', 'SUSPICIOUS')` and `severity != 'NONE'` and `confidence > 0.0`. Displays threat count and latest timestamp. |
| **`NO ALERT OBSERVED`** | Emerald Green (`#10B981`) | `success-border` | Relevant telemetry verified active in the stream/hardware link, but zero attack alerts are flagged. Never claims the network is "safe" or "attack-free". |
| **`INSUFFICIENT TELEMETRY`** | Amber / Gray (`#F59E0B` / `#9CA3AF`) | `warning-border` / `neutral-border` | The required headers, packet accumulation, or hardware link are missing from the stream. Displays explicit explanation of missing requirements. |
| **`MONITORING UNAVAILABLE`** | Dim Gray (`#6B7280`) | `neutral-border` | Collector daemon is in `ERROR`, `OFFLINE`, uninitialized, or database is inaccessible. |

### 3.2 Exact Event-Category Mapping
Implemented via `CATEGORY_CONFIG` in `src/live_dashboard.py`:

```python
CATEGORY_CONFIG = {
    "dos": {
        "title": "1. Denial of Service",
        "aliases": ["Denial_of_Service", "DOS", "dos", "denial_of_service"],
        "default_sub": "Multi-window (≥3s) • Target conc. ≥75%",
    },
    "port_scan": {
        "title": "2. Reconnaissance",
        "aliases": ["Reconnaissance_Port_Scan", "PORT_SCAN", "port_scan", "reconnaissance_port_scan"],
        "default_sub": "Transport ports & SYN flags • Horizontal/vertical sweeps",
    },
    "spoofing": {
        "title": "3. Spoofing / Impersonation",
        "aliases": ["Spoofing_Impersonation", "SPOOFING", "spoofing", "spoofing_impersonation"],
        "default_sub": "Conflicting IP-to-MAC • Gateway IP theft",
    },
    "deauth": {
        "title": "4. Wi-Fi Deauth Flood",
        "aliases": ["Deauthentication_Disassociation_Abuse", "DEAUTH_FLOOD", "deauth_flood", "deauth", "deauthentication_disassociation_abuse"],
        "default_sub": "ESP32 802.11 mgmt sniffer • ≥5 frames/s",
    },
    "replay": {
        "title": "5. Replay Attack",
        "aliases": ["Replay_Attack", "REPLAY", "replay", "replay_attack"],
        "default_sub": "Cryptographic nonces & TCP flow sequence tracking",
    },
}
```

### 3.3 Telemetry Availability Criteria

| Attack Category | Telemetry Source | Verification Logic for `NO ALERT OBSERVED` | Fallback to `INSUFFICIENT TELEMETRY` |
| :--- | :--- | :--- | :--- |
| **Denial of Service** | `live_traffic_windows` | Multi-window sliding state requires $\ge 3$ accumulated 1s feature windows (`total_windows >= 3`). | `total_windows < 3` (burst accumulation incomplete). |
| **Reconnaissance (Port Scan)** | TShark live stream / `live_traffic_windows` | Active packet traffic parsed (`total_packets > 0`) with transport layer TCP/UDP destination ports and TCP SYN flags. | No packets parsed or uncorrected `INSUFFICIENT_TELEMETRY` header finding. |
| **Spoofing / Impersonation** | TShark live stream / `live_traffic_windows` | Active IP-to-MAC traffic observations (`total_windows >= 1` and `total_packets > 0`). | Zero IP/MAC traffic observed in session. |
| **Wi-Fi Deauth Flood** | ESP32 serial sniffer / `live_sensor_telemetry` | ESP32 serial link active (`serial_port` active, sensor records streaming or daemon running). | Windows NDIS adapter strips 802.11 mgmt frames; no active ESP32 sniffer attached. |
| **Replay Attack** | TShark stream / `live_attack_events` | Active transport flow sequence tracking without unaddressed missing field findings. | Default capture stream omits cryptographic nonces/payload hashes (`INSUFFICIENT_TELEMETRY`). |

---

## 4. ESP32 Wi-Fi Sniffer Diagnostics Panel

### 4.1 Persisted Telemetry Fields Displayed
From `collector_status` and `live_sensor_telemetry`:
- **Serial Sniffer Link:** Port `COM6` (`Active` when running, `Archived / Inactive` when stopped, `Disabled` if `--no-sensors`).
- **Device Identity & Last Seen:** Device name `esp32_gateway`, logical node `Node_1`, UTC timestamp, and staleness indicator (`STALE` if $>30\text{s}$ during active collection).
- **Sensor Telemetry Ingestion:** Total records ingested (`2,214` in current database).
- **Deauth Threat Events Persisted:** Total deauthentication alert events recorded in `live_attack_events`.

### 4.2 Unpersisted Telemetry Fields Honestly Documented
The initial inspection revealed that periodic accounting summaries (`wifi_mgmt_summary`) are maintained in the live collector daemon's in-memory variable `self._last_summary_snapshot` and are not written to SQLite.

In strict adherence to telemetry honesty rules, the dashboard **does not fabricate zeroes** for these metrics. The expandable Sniffer Accounting table reports:
- Wi-Fi Operating Channel: `Not reported in DB`
- Firmware Session Boot ID: `Not reported in DB`
- Raw 802.11 Management Callbacks: `Unavailable (in-memory only)`
- Valid Deauth/Disassoc Frames Parsed: `Unavailable (in-memory only)`
- Unsupported Management Frames: `Unavailable (in-memory only)`
- Malformed Management Frames: `Unavailable (in-memory only)`
- Token-Bucket Rate Suppressed: `Unavailable (in-memory only)`
- Host Queue Dropped: `Unavailable (in-memory only)`
- Host Enqueued Events: `Unavailable (in-memory only)`
- Last 1.0s Summary Timestamp: `Unavailable (in-memory only)`

A permanent informational banner informs the operator of this architectural boundary.

---

## 5. Live Evaluation Evidence on Production Database

Execution of the corrected status logic on `data/live_monitoring.db` (read-only mode) yielded the following actual production statuses:

```text
=== LIVE MONITORING DB (Latest Run #1) ===
dos          -> DETECTED               | 🚨 516 Threat(s) Flagged • Latest: 2026-11-07 15:25:38
port_scan    -> DETECTED               | 🚨 951 Threat(s) Flagged • Latest: 2026-11-07 15:33:43
spoofing     -> NO ALERT OBSERVED      | IP-to-MAC mapping active • No spoofing alert
deauth       -> NO ALERT OBSERVED      | ESP32 serial sniffer active • No deauth flood flagged
replay       -> INSUFFICIENT TELEMETRY | Cryptographic nonces/payload hashes required • Not in default stream

=== ESP32 DIAGNOSTICS ===
serial_port               : COM6
connection_status         : Archived / Inactive
last_seen_utc             : 2026-11-07 15:34:17
node_id                   : Node_1
physical_device           : esp32_gateway
total_sensor_records      : 2214
is_stale                  : False
deauth_events_persisted   : 1
wifi_channel              : Not reported in DB
boot_id                   : Not reported in DB
raw_callbacks             : Unavailable (in-memory only)
valid_frames              : Unavailable (in-memory only)
unsupported_mgmt          : Unavailable (in-memory only)
malformed_frames          : Unavailable (in-memory only)
tb_suppressed             : Unavailable (in-memory only)
queue_dropped             : Unavailable (in-memory only)
enqueued_events           : Unavailable (in-memory only)
last_summary_utc          : Unavailable (in-memory only)
```

---

## 6. Automated Testing & Verification

### 6.1 Dedicated Test Suite (`tests/test_live_dashboard.py`)
Authored 10 comprehensive test cases verifying all required Phase 5 scenarios:

| Test ID | Scenario Description | Expected Outcome | Result |
| :---: | :--- | :--- | :---: |
| **01** | One detected event for each of the five categories | All 5 report `DETECTED` with threat counts & timestamps | **PASSED** |
| **02** | No events with relevant telemetry verified available | All report `NO ALERT OBSERVED` with green styling | **PASSED** |
| **03** | Missing telemetry (single window, no serial, explicit record) | Target categories report `INSUFFICIENT TELEMETRY` | **PASSED** |
| **04** | Collector status in `ERROR` or inactive without data | All 5 report `MONITORING UNAVAILABLE` | **PASSED** |
| **05** | Startup capability records present in `live_attack_events` | Never counted as attacks (`detected_count == 0`) | **PASSED** |
| **06** | 10 statistical anomaly alerts in `live_alerts` | Decoupled; zero attack cards report `DETECTED` | **PASSED** |
| **07** | Empty database (zero rows across all tables) | All 5 report `MONITORING UNAVAILABLE` | **PASSED** |
| **08** | In-memory summary missing optional fields (`tb_suppressed`, etc.) | Safely reports `Not reported` without KeyError | **PASSED** |
| **09** | Periodic summary absent (`in_memory_summary=None`) | Honest `Unavailable (in-memory only)` labels & stale detection | **PASSED** |
| **10** | Database query failure or `conn=None` / closed connection | Handled gracefully without throwing exceptions | **PASSED** |

### 6.2 Test Execution Results

| Test Target | Command | Result | Duration |
| :--- | :--- | :--- | :--- |
| **Dashboard Status Suite** | `python -m pytest tests/test_live_dashboard.py` | **10 / 10 PASSED** | 3.30s |
| **Live Collector Attack Integration** | `python -m pytest tests/test_live_collector_attack_integration.py` | **84 / 84 PASSED** | 12.34s |
| **Attack Detector Suite** | `python -m pytest tests/test_attack_detector.py` | **63 / 63 PASSED** | 0.25s |
| **Full Repository Test Suite** | `python -m pytest tests/` | **340 / 340 PASSED** | 24.11s |

Total passing tests across the entire repository increased from 330 to **340** with 0 failures and 0 warnings.

---

## 7. Production Database Integrity Verification

In strict compliance with safety rules, no writes were directed to production databases:

| Database File | Baseline SHA-256 Hash | Post-Stage 6.4 SHA-256 Hash | Status |
| :--- | :--- | :--- | :--- |
| `data/live_monitoring.db` | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | **UNTOUCHED / MATCH** |
| `data/iot_anomaly.db` | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | **UNTOUCHED / MATCH** |

---

## 8. Files Modified

1. `src/live_dashboard.py`
   - Added `CATEGORY_CONFIG` dictionary.
   - Added `compute_attack_category_status(conn, run_id)` helper function.
   - Added `fetch_esp32_sniffer_diagnostics(conn, run_id, in_memory_summary)` helper function.
   - Updated `render_attack_intelligence()` to render dynamic status cards, last evaluated timestamp, and the ESP32 Wi-Fi Sniffer Diagnostics Panel.
2. `tests/test_live_dashboard.py`
   - Created dedicated test suite covering scenarios 1–10.

No other source files, firmware files, models, thresholds, or databases were modified.

---

## 9. Remaining Architectural Limitations & Future Recommendations

1. **Persistence of Sniffer Periodic Accounting Summaries:**
   Currently, `wifi_mgmt_summary` periodic accounting records are processed in `LiveCollector._handle_wifi_mgmt_summary()` and saved in `self._last_summary_snapshot` in daemon memory. Because the dashboard runs as a separate process connecting to SQLite in read-only mode, it cannot read in-memory variables. If persistent historical sniffer diagnostics are desired in future stages, an approved migration adding a `live_wifi_mgmt_summaries` table to `data/live_monitoring.db` would enable full historical graphing of dropped/suppressed frames.
2. **Offline Hardware Detection:**
   When an archived session is viewed, `connection_status` accurately displays `Archived / Inactive`. During live execution, staleness is detected if no new sensor telemetry has arrived for $>30\text{s}$.

