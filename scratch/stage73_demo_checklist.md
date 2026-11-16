# Stage 7.3: Demonstration & Operational Checklist

**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Workspace Root:** `C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection`  
**Purpose:** Quick-reference operational checklist for setting up, executing, and shutting down the live project demonstration.

---

## 1. Pre-Demonstration Hardware & Network Checklist

Execute these checks **10 minutes prior** to presenting:

- [ ] **Physical ESP32 Board:**
  - [ ] ESP32 Dev Board connected via micro-USB to PC.
  - [ ] DHT11 Data Pin connected to **GPIO 4**.
  - [ ] AM312 PIR Output Pin connected to **GPIO 27**.
  - [ ] VCC connected to 3.3V; GND connected to common GND.
- [ ] **Serial Port Verification:**
  - [ ] Device Manager confirms `Silicon Labs CP210x USB to UART Bridge` on **`COM6`**.
- [ ] **Windows Mobile Hotspot:**
  - [ ] Open Windows Settings $\to$ Network & Internet $\to$ Mobile Hotspot.
  - [ ] Toggle **Mobile Hotspot ON**.
  - [ ] Verify adapter `Local Area Connection* 2` is active via `ipconfig` (IP: `192.168.137.1`, Subnet: `255.255.255.0`).
- [ ] **Client Device Association:**
  - [ ] Connect Phone 1 (`Node_3`: `ca:34:ea:92:d3:9e`) to the hotspot Wi-Fi SSID.
  - [ ] Connect Phone 2 (`Node_4`: `e6:2e:db:73:1c:25`) to the hotspot Wi-Fi SSID.
  - [ ] Confirm both devices show connected in Windows Mobile Hotspot settings.
- [ ] **TShark Executable Check:**
  - [ ] Verify `C:\Program Files\Wireshark\tshark.exe` exists.
  - [ ] Run `tshark -D` in PowerShell to confirm Interface Index `5` maps to `(Local Area Connection* 2)`.

---

## 2. Launch Commands & Terminal Setup

> [!IMPORTANT]
> Always execute commands from the project root:  
> `cd C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection`

### Terminal 1: Streamlit Cyber Dashboard
Launch the dashboard first so it is ready in your browser:
```powershell
# Open Terminal 1
cd C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection
streamlit run src/live_dashboard.py
```
* **Browser Address:** Open `http://localhost:8501` (set browser window to full screen, dark mode).

### Terminal 2: Live Ingestion Collector
Launch the live collector daemon when ready to begin live ingestion:
```powershell
# Open Terminal 2
cd C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection
python src/live_collector.py --interface 5 --port COM6 --db-path data/live_monitoring.db
```

* **Verify Startup Messages in Terminal 2:**
  - `[DETECTOR] Frozen dual detector loaded from: time_1s_session1_pcap_features_uplink.csv`
  - `[COLLECTOR] Starting run_id=X | Interface=5 | Serial=COM6`
  - `[COLLECTOR] Hotspot Gateway MAC verified: 36:6f:24:d2:34:3d`
  - `[NET] TShark packet stream started.`
  - `[SERIAL] Connected to COM6.`
  - `[SERIAL][INFO] Sniffer session active: boot_id=..., nonce=...`

---

## 3. Live Presentation Execution Checklist

Follow this tab-by-tab progression during the demonstration:

- [ ] **Tab 1: Overview & Live Feed**
  - [ ] Show **Daemon State** badge (`STREAMING` / green).
  - [ ] Show **1s Traffic Windows** counter updating dynamically.
  - [ ] Show **Active Clients** (`Node_3` and `Node_4`).
  - [ ] Explain the Executive KPI metric ribbon.
- [ ] **Tab 2: Physical Sensors (ESP32)**
  - [ ] Show the dual-axis line chart for **Node 1 (DHT11)**: temperature (~29 °C) and humidity (~92%).
  - [ ] Wave hand near PIR sensor; show **Node 2 (PIR)** motion detection count increment.
  - [ ] *State verbal disclaimer:* Sensor telemetry monitors physical room conditions concurrently; physical events do not cause network anomalies.
- [ ] **Tab 3: Live Network Traffic**
  - [ ] Show the uplink packet rate and mean packet size time-series plots.
  - [ ] Browse a web page on Phone 1 (`Node_3`) to generate an observable traffic surge on the chart.
- [ ] **Tab 4: Anomaly Alerts Console**
  - [ ] Show the **Dual-Detector Anomaly Breakdown** bar chart.
  - [ ] Explain `ANOMALY_PRIMARY_BURST_OR_SIZE`: high packet rate bursts diverge from the quiet Session 1 baseline.
  - [ ] Explain `NORMAL_QUIET_TIMING_UNAVAILABLE`: low packet windows ($N < 3$) prevent false timing alarms.
  - [ ] *State verbal disclaimer:* Statistical anomalies are quantitative deviations from the training distribution, not confirmed attacks.
- [ ] **Tab 5: Attack Intelligence**
  - [ ] Show the **Five Attack Categories Operational Status** ribbon:
    - `Denial of Service`: `NO_EVIDENCE` (Normal CDN streaming filtered).
    - `Port Scanning`: `NO_EVIDENCE` / `INSUFFICIENT_TELEMETRY`.
    - `Spoofing`: `NO_EVIDENCE` (Valid IP-MAC bindings maintained).
    - `Deauth Flood`: `NO_EVIDENCE` (Sniffer active on Channel 6).
    - `Replay Attack`: `INSUFFICIENT_TELEMETRY` (Telemetry honesty).
  - [ ] Point out the **ESP32 Wi-Fi Sniffer Diagnostics** panel showing active sniffer boot ID.
- [ ] **Tab 6: Device Registry**
  - [ ] Show `Node_3` and `Node_4` MAC address attribution and recent `last_seen` timestamps.
- [ ] **Tab 7: Daemon Diagnostics**
  - [ ] Show SQLite WAL storage mode, zero write failures, and heartbeat health.

---

## 4. Fallback Demonstration Checklist (If Hardware Fails)

If the ESP32 disconnects, TShark blocks, or the hotspot fails during the live review, switch to the verified **Stage 7.2.2 physical evidence**:

- [ ] **Step 1:** In the Streamlit dashboard sidebar, scroll down to **System Controls**.
- [ ] **Step 2:** In the **Live DB Path** text box, enter:
  ```text
  data/test_stage722_live_monitoring.db
  ```
- [ ] **Step 3:** Under **Collector Run Filter**, select:
  ```text
  Run #1 (STOPPED)
  ```
- [ ] **Step 4:** Click **🔄 Refresh Data Now**.
- [ ] **Step 5:** Present the complete, verified 180-second physical test:
  - 239 feature windows, 71,967 packets, 90 valid DHT11 readings ($29.3\text{ }^\circ\text{C}$, $92.3\%$), 90 PIR readings (motion trigger at sequence 19), and sniffer session `boot_id=4199123527`.
- [ ] **Alternative Fallback:** If desired, set path to `data/live_monitoring.db` and select `Run #6 (STOPPED)` to demonstrate the historical 1,512-window physical evaluation.

---

## 5. Post-Demonstration Graceful Shutdown Checklist

Follow these steps immediately after the demonstration concludes:

- [ ] **1. Stop the Live Collector:**
  - In Terminal 2, press **`Ctrl + C`** once.
  - Wait for shutdown messages:
    - `[COLLECTOR] Stopping: Keyboard interrupt (Ctrl+C)`
    - `[NET] TShark stream stopped.`
    - `[SERIAL] Serial thread stopped.`
    - `[COLLECTOR] Final statistics:`
- [ ] **2. Confirm Process Termination:**
  - Verify in PowerShell that no lingering capture processes remain:
    ```powershell
    Get-Process -Name tshark, dumpcap, python -ErrorAction SilentlyContinue
    ```
- [ ] **3. Release Serial Handle:**
  - Confirm `COM6` is released and available.
- [ ] **4. Stop the Streamlit Dashboard:**
  - In Terminal 1, press **`Ctrl + C`** to stop the web server.
- [ ] **5. Production Database Verification:**
  - Verify that both production databases remain untouched by running:
    ```powershell
    Get-FileHash data\live_monitoring.db, data\iot_anomaly.db | Format-List
    ```
  - Expected Hashes:
    - `data\live_monitoring.db`: `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB`
    - `data\iot_anomaly.db`: `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968`

