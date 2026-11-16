# STAGE 10.1 — FROZEN PROJECT DASHBOARD VERIFICATION REPORT

**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Workspace:** `C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection`  
**Execution Timestamp:** 2026-11-15 13:15:00 UTC / 18:45:00 IST  
**Status:** **PASSED — VERIFIED & LIVE**  
**Dashboard URL:** [http://localhost:8502](http://localhost:8502)  
**Target Evidence Database:** [`data/stage9_demo_live_monitoring.db`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/data/stage9_demo_live_monitoring.db)  
**Channel Diagnostic Sidecar:** [`data/stage9_demo_live_monitoring_diagnostic.json`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/data/stage9_demo_live_monitoring_diagnostic.json)  

---

## 1. Executive Summary

Under **Stage 10.1**, the frozen Streamlit monitoring dashboard (`src/live_dashboard.py`) was launched in strict read-only mode on local port **8502** and exhaustively inspected across all 7 functional tabs using the headless Chrome DevTools browser agent against the ground-truth evidence database from the Stage 9.2 physical demonstration (`data/stage9_demo_live_monitoring.db`).

### Key Verification Verdicts:
1. **Zero Errors or Glitches:** 100% clean UI rendering with 0 broken widgets, 0 red error boxes, 0 exception tracebacks, and 0 missing charts.
2. **Strict Read-Only Enforcement:** Dashboard connects exclusively via SQLite `file:<path>?mode=ro`. No write locks or schema mutations occurred.
3. **100% Ground-Truth Metric Correspondence:** Every visual KPI card, time-series chart, and tabular log exactly matches the verified SQLite database records from the 180.59s live run.
4. **Channel Alignment Sidecar Freshness:** The neutral `CHANNEL_UNAVAILABLE` advisory badge is correctly rendered, confirming the fix applied in Stage 8.4 against stale sidecars.
5. **Dashboard Retained Active:** The Streamlit server remains alive and active on port **8502** for direct user exploration in any browser.

---

## 2. Server Runtime & Process Details

- **Process Command:** `python -m streamlit run src/live_dashboard.py --server.port 8502 --server.headless true`
- **Streamlit Version:** `1.52.1`
- **Binding Ports:**
  - Streamlit Web UI: `http://localhost:8502`
  - Chrome Remote Debugging: `http://localhost:9222`
- **Database Connection URI:** `file:c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/data/stage9_demo_live_monitoring.db?mode=ro`
- **Active Task ID:** `02da79cc-f88e-4621-8b82-bdeed5d867b1/task-6358` (Daemon background process)

---

## 3. Tab-by-Tab Visual Inspection & Metric Audit

| Tab / View | Ground Truth Evidence (`stage9_demo_live_monitoring.db`) | Rendered Dashboard Metric (`http://localhost:8502`) | Alignment Status |
| :--- | :--- | :--- | :--- |
| **Header Status Banner** | Run #1 graceful termination at 12:20:07 UTC | `⏸️ Collector Daemon Inactive (Archived Session)` | **MATCH** |
| **Top KPI 1: Daemon State** | Run #1 stopped | `STOPPED (Run #1 • Persisted Archive)` | **MATCH** |
| **Top KPI 2: Traffic Windows** | 159 rows in `live_traffic_windows`, 2,466 attributed pkts | `159 Windows (2,466 Total Pkts • 1 Active Clients)` | **MATCH** |
| **Top KPI 3: Anomaly Alerts** | 33 rows in `live_alerts` (20.75% of 159 windows) | `33 Alerts (20.75% Anomaly Ratio (Dual IF))` | **MATCH** |
| **Top KPI 4: Sensors** | Latest: 28.5 °C, 93% RH, Motion: True | `28.5°C 93% (Node 1 (DHT) • Node 2 PIR: MOTION)` | **MATCH** |
| **Top KPI 5: Unknown Devices** | 2 entries in `unknown_device_obs` | `2 Unregistered Devices (Active Investigation Needed)` | **MATCH** |
| **Physical Sensors (Node 1)** | 93 valid DHT11 reads (28.5 °C, 92–93% RH) | Dual-axis line plot, 100.0% read reliability (93/93) | **MATCH** |
| **Physical Sensors (Node 2)** | 93 intervals, 11 motion transitions (11.8% active) | Binary square-wave chart, 11 events (11.8% active) | **MATCH** |
| **Live Network Traffic** | Attributed to `ca:34:ea:92:d3:9e` (Phone 1) | Interactive rate & jitter plots attributed to `Node_3` | **MATCH** |
| **Alerts Decision Space** | 20 Primary, 12 Timing, 1 Both (Sum = 33) | 20 Primary, 12 Timing, 1 Both (2D Decision scatter plot) | **MATCH** |
| **Attack Intelligence** | 0 flagged cyberattacks across all 5 families | 0 Cyberattacks Flagged; all 5 categories evaluated SAFE | **MATCH** |
| **Device Topology** | 5 logical nodes defined | 5-Node inventory table displayed with Phone 1 active | **MATCH** |
| **Unregistered Surveillance** | MACs `26:f0:ec:aa:b7:78` (108), `36:6f:24:d2:34:3d` (92) | 2 MAC entries displayed with explicit non-blocking disclaimer | **MATCH** |
| **Daemon Diagnostics** | Interface 5 (`Local Area Connection* 2`), 28,254 pkts | 28,254 parsed packets, WAL metrics, Run #1 metadata | **MATCH** |
| **Channel Alignment Badge** | Unverified operating channel in sidecar JSON | `CHANNEL_UNAVAILABLE (Neutral Status)` | **MATCH** |

---

## 4. Verification Checkpoint Confirmations

- [x] **Read-Only SQLite Connection:** Verified `uri=True` with `?mode=ro`.
- [x] **No Live Ingestion or Hardware Contention:** Live collector, TShark, dumpcap, and COM6 remained completely idle and closed.
- [x] **Database Isolation:** All 3 protected databases (`data/live_monitoring.db`, `data/iot_anomaly.db`, `data/test_stage722_live_monitoring.db`) remain untouched and bit-identical.
- [x] **Zero Cyberattack False Alarms:** Verified that statistical deviations detected by the baseline Isolation Forest model (33 alerts) are rigorously differentiated from deliberate cyberattacks (0 cyberattacks flagged).
- [x] **Operator Safety Banner:** Verified defensive posture ("Under no circumstances should any device be automatically blocked, dropped, or deauthenticated").
- [x] **Server Retained Alive:** Streamlit daemon process remains active and accessible on `http://localhost:8502`.

