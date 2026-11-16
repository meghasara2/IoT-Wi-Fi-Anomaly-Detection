# MASTER DASHBOARD REDESIGN COMPLETION REPORT
## IoT Network Guard — Dual-Detector SOC Console

**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Workspace:** `C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection`  
**Completion Date:** 2026-11-15 19:40 UTC  
**Target URL:** [http://localhost:8502](http://localhost:8502)  
**Evidence Database:** [`data/stage9_demo_live_monitoring.db`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/data/stage9_demo_live_monitoring.db)  
**Pre-Redesign Backup:** [`src/live_dashboard_backup_pre_redesign.py`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/live_dashboard_backup_pre_redesign.py)  

---

## 1. Executive Summary

The existing Streamlit live monitoring dashboard (`src/live_dashboard.py`) has been completely transformed from a generic UI into a **commercial-grade Cybersecurity Security Operations Center (SOC) Console**. 

All **seven functional sections** were redesigned with an 85% enterprise cybersecurity SOC + 15% subtle futuristic aesthetic. Zero business logic, detection rules, firmware, models, or database schemas were modified.

The visual, structural, and numerical integrity of the redesigned console was audited and confirmed 100% operational via headless Chrome DevTools automated browser inspection against the Stage 9.2 physical demonstration database.

---

## 2. Files Modified

| File Path | Action | Description |
| :--- | :--- | :--- |
| `src/live_dashboard.py` | **Redesigned** | Complete SOC aesthetic redesign across all 7 views, custom CSS, enhanced KPI ribbon, Plotly dark theme. |
| `src/live_dashboard_backup_pre_redesign.py` | **Preserved Backup** | Exact bit-for-bit backup of the pre-redesign working baseline. |
| `scratch/build_redesigned_dashboard.py` | **Created** | Deterministic UTF-8 builder script used to construct the redesigned dashboard. |
| `scratch/final_dashboard_redesign_report.md` | **Created** | Comprehensive completion and verification report. |

---

## 3. Seven-Section Implementation Summary

### Section 1: Overview & Live Feed
- **SOC Header & Branding:** Displays `IoT NETWORK GUARD — DUAL-DETECTOR SOC CONSOLE`, dynamic session badge (`◼ RUN #1 • ARCHIVED`), and live UTC console clock.
- **Top 6 KPI Ribbon:**
  1. `⚡ Collector State`: `STOPPED (Run #1 • Persisted Archive)`
  2. `📦 Total Packets`: `2,466` (attributed client packets; 28,254 total frames parsed)
  3. `📊 1s Traffic Windows`: `159`
  4. `⚠️ Statistical Alerts`: `33` (`20.75% Anomaly Ratio`)
  5. `📱 Registered Devices`: `3` (`1 Active in Traffic`)
  6. `🌡️ Logical Sensors`: `28.5°C 93%` (`PIR: MOTION`)
- **Main Stage Visuals:**
  - **Left (1.75x):** 1-Second Packet Rate stream with Node_3 uplink and distinct markers for Burst/Size anomalies (Crimson `#F43F5E`), Timing Jitter (Amber `#F59E0B`), and Dual anomalies (Ruby `#E11D48`).
  - **Right (1.25x):** Dual-detector decision partition donut chart (60.4% Normal Inlier, 18.9% Quiet Timing Unavailable, 12.6% Primary Burst/Size, 7.55% Timing Jitter, 0.63% Dual).
- **Lower Stage:** Latest Statistical Anomaly Alerts table side-by-side with the Attack Intelligence Operational Summary (highlighting zero cyberattack false alarms).

### Section 2: Live Network Traffic
- **Metric Cards:** Total Packets (`2,466`), Traffic Windows (`159`), Active Clients (`1`), Avg Packet Rate (`15.5/s`), Peak Packet Rate (`62/s`).
- **Interactive Controls:** Client node filter (`All Nodes`, `Node_3`, `Node_4`, `Node_5`), history depth slider (50–1000 windows).
- **Sub-Tabs:**
  - Tab 1: Packet Rate and Mean Packet Size ± Std Dev subplots.
  - Tab 2: Inter-Arrival Timing (IAT) and Timing Jitter (IAT Std) subplots.
- **Raw Windows Explorer:** Interactive expander showing full 1-second feature windows, decision function scores, and classification reasons.

### Section 3: Anomaly Alerts Console
- **Methodological Disclaimer Banner:** Clearly explains that Isolation Forest alerts are statistical deviations from baseline, NOT confirmed cyberattacks. Explains `-1 = Anomaly` and `+1 = Normal` conventions.
- **Reconciled Partition Cards (5 Cards):**
  - Total Dual Alerts: `33`
  - 1. Primary Anomaly Only: `20`
  - 2. Timing Anomaly Only: `12`
  - 3. Simultaneous Both: `1`
  - Normal Inliers: `126`
- **Reconciliation Equation:** $\text{Total Alerts (33)} = \text{Primary (20)} + \text{Timing (12)} + \text{Both (1)}$.
- **2D Decision Space Scatter Plot:** Visualizes Primary vs Timing decision scores with threshold crosshairs at $0.0$.
- **Alerts Table:** Filterable by dual reason and client node with formatted scores.

### Section 4: Attack Intelligence
- **Guiding Principles Banner:** Details decoupled detection pipelines, telemetry honesty, and non-disruptive operator assistance.
- **Five Attack Category Cards:**
  1. Denial of Service: `NO ALERT OBSERVED` (0 cyberattacks flagged)
  2. Reconnaissance (Port Scan): `INSUFFICIENT TELEMETRY` (0 cyberattacks flagged)
  3. Spoofing / Impersonation: `INSUFFICIENT TELEMETRY` (0 cyberattacks flagged)
  4. Wi-Fi Deauth Flood: `INSUFFICIENT TELEMETRY` (0 cyberattacks flagged)
  5. Replay Attack: `INSUFFICIENT TELEMETRY` (0 cyberattacks flagged)
  - **Result:** Exactly `0` false alarms across all 795 evaluations.
- **ESP32 Wi-Fi Sniffer Diagnostics:** Link status, device identity, sensor records logged, and deauth events persisted.
- **Detection Event Log:** Full `live_attack_events` table with structured JSON evidence inspector.

### Section 5: Physical Sensors (ESP32)
- **Causal Decoupling Disclaimer:** Explicitly notes that physical sensor telemetry is partitioned logically from Wi-Fi traffic and physical events do not cause network anomalies.
- **Node 1 (DHT11):** Latest Temperature (`28.5 °C`), Relative Humidity (`93.0%`), Read Reliability (`100.0%` valid reads), and dual-axis Plotly time-series chart.
- **Node 2 (AM312 PIR):** Latest State (`MOTION DETECTED`), Motion Detections (`11 Events` / 11.8%), Idle Intervals (`82 Intervals`), and activity bar chart.
- **Hardware Status Table:** ESP32 gateway hardware identity and sensor pinout mappings.

### Section 6: Device Registry
- **Operator Mandate Banner:** Warns that unregistered MAC addresses require manual review and must never be automatically blocked due to modern OS MAC randomization.
- **5-Node Logical Topology Matrix:** Node_1 (DHT11), Node_2 (PIR), Node_3 (Phone 1, active), Node_4 (Phone 2, configured), Node_5 (Phone 3, reserved demo).
- **Unknown Device Surveillance Table:** Unregistered MAC surveillance tracking `26:f0:ec:aa:b7:78` (108 frames) and `36:6f:24:d2:34:3d` (92 frames).

### Section 7: Daemon Diagnostics
- **Execution Record:** Run ID `#1`, Status `STOPPED`, Started `12:17:00 UTC`, Last Heartbeat `12:20:07 UTC`, Termination Reason `Stage 9.2 180s live demonstration completed successfully`.
- **Hardware Configuration:** TShark interface index `5` (`Local Area Connection* 2`), serial port `COM6`, packets parsed `28,254`, windows emitted `159`, sensor records `93`.
- **Wi-Fi Channel Alignment Diagnostic:** Preserved Stage 8.4 freshness logic; displays neutral `CHANNEL_UNAVAILABLE` advisory badge without hardcoded channel assumptions.
- **SQLite Database Health Table:** Accurate row counts across all 8 database tables.
- **Reliability Notice:** Explains that in-memory counters (ring buffer drops, retry counts) are not persisted to SQLite and RSSI is unavailable under NDIS capture.

---

## 4. Visual Improvements Delivered

1. **Cybersecurity Dark Palette:** Deep midnight navy background (`#080D18`), darker sidebar (`#070B14`), elevated card surfaces (`#111827`, `#172235`), and subtle slate borders (`#1E293B`).
2. **Glowing Cyan & Electric Blue Accents:** Refined accent palette using `#22D3EE` (Electric Cyan) and `#3B82F6` (Electric Blue).
3. **Typography & Hierarchy:** Integration of Google's `Inter` font for UI elements and `JetBrains Mono` for tabular metrics and MAC addresses.
4. **Structured SOC Cards:** Rounded corners (10–12px), soft shadow depth, left accent indicator stripes color-coded to status (green, amber, red, blue, neutral).
5. **High-Contrast Dark Charts:** Custom `plotly_cyber_layout` with zero-line and grid styling, unified dark tooltips with cyan border accents.
6. **Responsive Spacing:** Compact KPI cards and balanced two-column sections designed to prevent unnecessary vertical scrolling on standard desktop displays.

---

## 5. Protected Artifact Hash Comparison

| Protected File | Expected Baseline SHA-256 | Current Workspace SHA-256 | Status |
| :--- | :--- | :--- | :--- |
| `src/live_collector.py` | `8B11E16AA89C321D18BA24C7F660B67E8CD502DC251E2E01BFAAA1E4F2CBDC06` | `8B11E16AA89C321D18BA24C7F660B67E8CD502DC251E2E01BFAAA1E4F2CBDC06` | **UNTOUCHED** |
| `src/attack_detector.py` | `0A7B7A5630FE8691BF3B59F6122F6F330AEB274A0C672B2E90CD158D40755D65` | `0A7B7A5630FE8691BF3B59F6122F6F330AEB274A0C672B2E90CD158D40755D65` | **UNTOUCHED** |
| `src/live_stream_extractor.py` | `5FB9081DE741952A229F877957802E0C139D36D0CDB6EF94F7685FE70F5EEB40` | `5FB9081DE741952A229F877957802E0C139D36D0CDB6EF94F7685FE70F5EEB40` | **UNTOUCHED** |
| `src/init_live_database.py` | `D2A65B31D6CF7D63D62224DD3B17892A9265D9751EAF6FC6E8C505E93C35EF46` | `D2A65B31D6CF7D63D62224DD3B17892A9265D9751EAF6FC6E8C505E93C35EF46` | **UNTOUCHED** |
| `data/stage9_demo_live_monitoring.db` | `01B2053CD928E8EC4965EE63638F36CBA1B60A46309DFE20D742B12D7CBB87C6` | `01B2053CD928E8EC4965EE63638F36CBA1B60A46309DFE20D742B12D7CBB87C6` | **UNTOUCHED** |
| `data/live_monitoring.db` | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | **UNTOUCHED** |
| `data/iot_anomaly.db` | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | **UNTOUCHED** |

---

## 6. Known System Limitations

1. **RSSI Telemetry Unavailable:** The Windows Mobile Hotspot adapter provides 802.3 Ethernet-emulated frames without 802.11 radiotap signal headers. No synthetic RSSI values are fabricated.
2. **In-Memory Collector Counters:** Periodic accounting summaries (such as token-bucket drops and UART queue drops) are maintained in the live collector daemon's runtime memory and are not persisted to SQLite.
3. **Channel Verification:** When the collector daemon is stopped, channel alignment cannot be actively probed live, correctly yielding a neutral `CHANNEL_UNAVAILABLE` advisory badge.

---

## 7. Launch Command

```bash
streamlit run src/live_dashboard.py --server.port 8502
```
URL: `http://localhost:8502`

