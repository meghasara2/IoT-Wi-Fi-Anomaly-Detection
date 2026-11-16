# Stage 7.3.2: Final Demonstration Readiness Review

**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Workspace:** `C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection`  
**Review Type:** Strictly Read-Only Architecture, Safety, and Operational Assessment  
**Reviewed Artifacts:**
1. [`scratch/stage73_demo_plan.md`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/scratch/stage73_demo_plan.md) (Demonstration sequence and safe scenarios)
2. [`scratch/stage73_demo_checklist.md`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/scratch/stage73_demo_checklist.md) (Pre-flight, launch, presentation, and shutdown checklists)
3. [`scratch/stage731_fallback_verification.md`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/scratch/stage731_fallback_verification.md) (Source-code trace and database integrity verification)
4. [`scratch/stage722_live_test.log`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/scratch/stage722_live_test.log) (Execution log from verified physical test)
5. [`data/test_stage722_live_monitoring.db`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/data/test_stage722_live_monitoring.db) (Verified physical test evidence database)

---

## 1. Safety & Scientific Guardrail Audits

| Guardrail Requirement | Audit Status | Evidence & Source-Code Verification |
| :--- | :---: | :--- |
| **1. Accidental Production DB Writes** | **PASSED WITH DIRECTIVE** | Source inspection of [`src/live_collector.py`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/live_collector.py#L2571) confirms omitting `--db-path` defaults to `data/live_monitoring.db`. The demonstration checklist has been explicitly directed to pass `--db-path data/demo_live_monitoring.db` (or `test_stage722`) to guarantee production databases remain 100% untouched. |
| **2. Statistical Anomalies vs. Cyberattacks** | **PASSED** | Both [`scratch/stage73_demo_plan.md`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/scratch/stage73_demo_plan.md) and [`src/live_dashboard.py`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/live_dashboard.py#L2005) explicitly document that Isolation Forest anomalies represent volumetric/statistical deviations from idle Session 1 baseline, NOT confirmed cyberattacks. |
| **3. Physical RF Attack Claims** | **PASSED** | No claims of live over-the-air deauthentication jamming or RF manipulation are made. The demonstration explicitly notes that deauth flood logic is validated via synthetic unit tests (63 tests) and offline frames, respecting RF legal and ethical regulations. |
| **4. Live Replay Telemetry Honesty** | **PASSED** | Source code in [`src/attack_detector.py`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/attack_detector.py#L1719) and live logs confirm Replay reports `INSUFFICIENT_TELEMETRY` on standard live streams because TShark does not compute real-time cryptographic payload hashes. The demo presentation highlights this as scientific honesty. |
| **5. Archival vs. Live Presentation** | **PASSED** | Inspection of [`src/live_dashboard.py`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/live_dashboard.py#L1160-L1172) confirms that when viewing historical runs or the fallback database, an amber `archived-banner` renders prominently, preventing historical evidence from being misrepresented as live activity. |

---

## 2. Live Demonstration Readiness Verification

### A. Startup Prerequisites & Environment
* **Hardware Attached:** Silicon Labs CP210x USB-to-UART bridge detected on `COM6` (`USB VID:PID=10C4:EA60`).
* **Sensor Nodes:** Node 1 (DHT11 on GPIO 4) and Node 2 (AM312 PIR on GPIO 27) powered via 3.3V/GND.
* **Network Adapter:** `Local Area Connection* 2` active with gateway IP `192.168.137.1` and subnet `255.255.255.0` (`192.168.137.0/24`).
* **Active Hotspot Clients:** `Node_3` (`ca:34:ea:92:d3:9e`) and `Node_4` (`e6:2e:db:73:1c:25`) active in the ARP table.
* **Packet Capture Binary:** TShark 4.6.9 confirmed at `C:\Program Files\Wireshark\tshark.exe` with capture Interface Index `5`.

### B. Launch Commands
* **Terminal 1 (Dashboard):**
  ```powershell
  streamlit run src/live_dashboard.py
  ```
* **Terminal 2 (Collector):**
  ```powershell
  python src/live_collector.py --interface 5 --port COM6 --db-path data/demo_live_monitoring.db
  ```
  *(Using a dedicated demonstration database preserves `data/live_monitoring.db` with zero added rows).*

### C. Attack Detection Explanation Strategy
The demonstration presents the five threat categories with rigorous distinction between capability and telemetry constraints:
1. **Denial of Service (DoS):** Checks sustained rate ($\ge 60\text{ pps}$, $\ge 3\text{s}$), target concentration ($\ge 75\%$), and fleet surge suppression. Outbound WAN streaming is safely filtered.
2. **Port Scanning:** Checks vertical port probes ($\ge 8$ ports) and horizontal sweeps ($\ge 5$ hosts) requiring connection attempts (SYN w/o ACK, UDP probes). Filters normal browsing and 11 discovery ports.
3. **Identity Spoofing:** Checks conflicting IP-to-MAC bindings over 60s windows with $\ge 2$ packet confirmation. Ignores randomized MACs; guards gateway MAC impersonation.
4. **Deauthentication Flood:** Checks 802.11 management frames (subtypes 10/12) and flood rate ($\ge 5\text{ frames/s}$). Notes Windows NDIS Ethernet stripping and shows ESP32 promiscuous sniffer on Channel 6.
5. **Replay Attack:** Checks flow-key 5-tuples and sequence regression. Honestly reports `INSUFFICIENT_TELEMETRY` when raw payload hashes are unextracted.

### D. Verified Fallback Demonstration
If live hardware fails during the presentation, the presenter executes an instant 10-second switch:
1. In the Streamlit sidebar under **System Controls**, set `Live DB Path` to:
   ```text
   data/test_stage722_live_monitoring.db
   ```
2. Select **`Run #1 (STOPPED)`** and click **`🔄 Refresh Data Now`**.
3. Renders the complete, verified Stage 7.2.2 physical evaluation: 239 feature windows, 71,967 packets, 90 valid DHT11 readings ($29.3\text{ }^\circ\text{C}$, $92.3\%$), 90 PIR readings (motion trigger at sequence 19), and sniffer session `boot_id=4199123527`.

### E. Safe Shutdown Sequence
1. Send `Ctrl+C` once to Terminal 2; collector waits for worker threads to terminate cleanly, closes TShark subprocess, releases `COM6`, and updates status to `STOPPED`.
2. Stop Streamlit in Terminal 1 via `Ctrl+C`.
3. Confirm zero lingering `tshark` or `dumpcap` processes via `Get-Process`.

---

## 3. Final GO / NO-GO Assessment

| Evaluation Dimension | Assessment | Operational Justification |
| :--- | :---: | :--- |
| **1. Hardware Demonstration Readiness** | **GO (CONDITIONAL)** | Verified physical hardware presence on `COM6`, active hotspot on `192.168.137.1`, and associated clients `Node_3` & `Node_4`. Condition: Requires maintaining physical USB and hotspot power during presentation; if interrupted, switch to Fallback. |
| **2. Dashboard Demonstration Readiness** | **GO** | Streamlit console verified 100% read-only (`mode=ro`), zero write statements, clean multi-tab layout, and live/archived session banners. |
| **3. Archived-Evidence Fallback Readiness** | **GO** | `data/test_stage722_live_monitoring.db` passes SQLite integrity check (`ok`) and retains all 239 windows, 190 alerts, 90 sensor records, and 90 PIR events with instant sidebar activation. |
| **4. Technical Explanation Readiness** | **GO** | 8-step ordered presentation sequence clearly distinguishes ML anomaly scoring from deterministic cyberattack evaluation, ensuring complete academic honesty. |
| **OVERALL PROJECT DEMONSTRATION** | **GO** | **The project is fully prepared, hardened, and verified for live capstone evaluation.** |

---

## 4. Remaining Risks and Pre-Presentation Action Items

### Risks & Mitigations
1. **Risk:** Phone clients go into deep Wi-Fi power-save sleep or drop hotspot connection during presentation.  
   *Action:* Set Phone 1 and Phone 2 screen timeout to "Never" or 10 minutes, and disable "Wi-Fi Power Saving" in developer options prior to starting.
2. **Risk:** Windows Mobile Hotspot auto-disables due to brief inactivity before the presentation begins.  
   *Action:* Verify the hotspot toggle is ON immediately before launching the collector; generate a ping or open a web page from Phone 1 to keep the adapter awake.
3. **Risk:** Accidentally writing demonstration runs into production database.  
   *Action:* Launch Terminal 2 with an explicit `--db-path data/demo_live_monitoring.db` or `--db-path data/test_stage722_live_monitoring.db`.
4. **Risk:** External lock on SQLite from a third-party tool.  
   *Action:* Do not open SQLite GUI tools (such as DB Browser for SQLite) in write mode during the live run; the dashboard uses `mode=ro` and 250 ms busy timeouts.

---

## 5. Production Database Hash Baseline (Confirmed Untouched)

* [`data/live_monitoring.db`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/data/live_monitoring.db): `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB`
* [`data/iot_anomaly.db`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/data/iot_anomaly.db): `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968`

*(Readiness review completed. Awaiting user approval to commence final demonstration.)*

