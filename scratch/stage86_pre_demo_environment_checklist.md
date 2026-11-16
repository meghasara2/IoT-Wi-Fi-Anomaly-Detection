# STAGE 8.6 — PRE-DEMONSTRATION ENVIRONMENT & OPERATIONAL CHECKLIST

**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Workspace:** `C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection`  
**Purpose:** Comprehensive operational guide and step-by-step verification checklist for preparing, executing, and safely concluding the live hardware and dashboard demonstration.

---

## 1. Classification of Checklist Tasks

To ensure rigorous execution and prevent operational confusion, every check is explicitly labeled:
- **[PHYSICAL]**: Requires physical hardware interaction (cables, buttons, phones, RF proximity).
- **[SOFTWARE/OFFLINE]**: Can be verified in software, via terminal command, or inspected offline.
- **[RUNTIME VERIFICATION]**: Real-time validation observed in live logs or dashboard widgets.

---

## 2. Pre-Demonstration Setup & Verification Checklist

### 1. Windows Mobile Hotspot Startup
- [ ] **[PHYSICAL / OS]** Open Windows Settings $\to$ Network & Internet $\to$ Mobile Hotspot.
- [ ] **[PHYSICAL / OS]** Configure Network Band to **2.4 GHz only** (prevents dynamic 5 GHz band steering).
- [ ] **[PHYSICAL / OS]** Toggle **Mobile Hotspot ON**.
- [ ] **[SOFTWARE/OFFLINE]** Open PowerShell and run `ipconfig`.
  - Verify that the Mobile Hotspot adapter reports IPv4 address `192.168.137.1` and Subnet Mask `255.255.255.0`.

### 2. Correct Hotspot Virtual Interface Identification
- [ ] **[SOFTWARE/OFFLINE]** Run `netsh wlan show interfaces` in PowerShell.
  - Locate the virtual adapter section (e.g., `Name : Local Area Connection* 2`, `Description : Microsoft Wi-Fi Direct Virtual Adapter`).
  - Confirm the adapter `State` is `connected` or `operational`.
  - Confirm the `Channel` field is populated (expected: Channel 6).
- [ ] **[SOFTWARE/OFFLINE]** Verify TShark interface enumeration:
  ```powershell
  & "C:\Program Files\Wireshark\tshark.exe" -D
  ```
  - Confirm which index corresponds to `(Local Area Connection* 2)`. (Typically Index `1` or Index `5` depending on network adapter configuration).
  - Note: `LiveCollector` automatically resolves this via `resolve_hotspot_interface()`, or it can be passed explicitly via `--interface <index>`.

### 3. ESP32 Hardware & COM6 Port Availability
- [ ] **[PHYSICAL]** Connect the ESP32 Dev Board via Micro-USB to the host PC.
- [ ] **[PHYSICAL]** Verify wiring connections:
  - DHT11 Data Pin $\to$ **GPIO 4** (with pull-up).
  - AM312 PIR Output Pin $\to$ **GPIO 27**.
  - Sensor VCC $\to$ **3.3V**; Sensor GND $\to$ **GND**.
- [ ] **[SOFTWARE/OFFLINE]** Open Windows Device Manager $\to$ Ports (COM & LPT).
  - Verify `Silicon Labs CP210x USB to UART Bridge` is assigned to **`COM6`**.
- [ ] **[SOFTWARE/OFFLINE]** **COM Port Contention Check:**
  - Verify that **NO other application** holds an open handle to `COM6`.
  - Close Arduino IDE Serial Monitor, PuTTY, TeraTerm, or standalone Python listeners (`src/ingest_serial_sensors.py`).
  - *Rule:* Only one process can bind to a Windows COM port at any given instant.

### 4. ESP32 Firmware Handshake Verification
- [ ] **[SOFTWARE/OFFLINE]** Firmware pre-flash verification:
  - Confirm `firmware/esp32_sensor_node/esp32_sensor_node.ino` is compiled and flashed to the board.
- [ ] **[RUNTIME VERIFICATION]** Upon collector startup, monitor terminal output for the handshake:
  - Collector sends probe: `{"cmd":"probe","nonce":<nonce>}`.
  - ESP32 responds: `{"status":"WIFI_SNIFFER_INITIALIZED","boot_id":<id>,"nonce":<nonce>,"channel":6}`.
  - Log verification: `[SERIAL][INFO] Sniffer session active: boot_id=..., nonce=...`.

### 5. Runtime Channel Alignment Verification
- [ ] **[RUNTIME VERIFICATION]** Observe the Stage 8.4 startup channel diagnostic output in the collector terminal:
  - Expected: `[COLLECTOR][INFO] Hotspot channel diagnostic: CHANNEL_ALIGNED` (or `CHANNEL_UNAVAILABLE` until handshake arrives).
- [ ] **[RUNTIME VERIFICATION]** Verify that when the handshake arrives with Channel 6, collector updates diagnostic:
  - Expected: `[SERIAL][INFO] Channel alignment verified by hardware handshake: Hotspot and ESP32 both on Channel 6`.
- [ ] **[RUNTIME VERIFICATION]** In the Streamlit Dashboard (Tab: Diagnostics):
  - Verify that the **Wi-Fi Channel Alignment Status** renders the emerald green badge:
    `ALIGNED (Channel 6)`.
  - Verify that both ESP32 and Hotspot report Channel 6.
  - *Invariant:* If channels differ (e.g. Hotspot is on Channel 1 and ESP32 on 6), dashboard will display red `MISMATCH` and 802.11 management packet capture will be degraded.

### 6. Phone Client Connectivity & Traffic Association
- [ ] **[PHYSICAL]** Connect Phone 1 (`Node_3`: MAC `ca:34:ea:92:d3:9e`) to the Mobile Hotspot SSID.
  - Confirm phone obtains IP in the `192.168.137.x` range (typically `192.168.137.201` or similar).
- [ ] **[PHYSICAL]** Connect Phone 2 (`Node_4`: MAC `e6:2e:db:73:1c:25`) to the Mobile Hotspot SSID.
  - Confirm phone obtains IP in the `192.168.137.x` range (typically `192.168.137.6` or similar).
- [ ] **[SOFTWARE/OFFLINE]** Verify in Windows Mobile Hotspot settings that 2 connected devices are listed.

### 7. TShark Availability & Capture Permissions
- [ ] **[SOFTWARE/OFFLINE]** Verify executable exists:
  ```powershell
  Test-Path "C:\Program Files\Wireshark\tshark.exe"
  ```
- [ ] **[SOFTWARE/OFFLINE]** Verify Npcap service is running:
  ```powershell
  Get-Service -Name npcap -ErrorAction SilentlyContinue
  ```

### 8. Database Path Selection & Isolation Safety
- [ ] **[SOFTWARE/OFFLINE]** Confirm target live database path:
  - Live Demo: `data/live_monitoring.db`
  - Fallback Replay: `data/test_stage722_live_monitoring.db`
- [ ] **[SAFETY GUARD]** Verify that `data/iot_anomaly.db` is NEVER passed as `--db-path`.
  - The collector contains a built-in safety block (`_safety_check`) that refuses to run against `iot_anomaly.db`.

### 9. Collector Startup Order & Execution
- [ ] **[SOFTWARE/OFFLINE]** Open **Terminal 1 (Collector Terminal)**.
- [ ] **[SOFTWARE/OFFLINE]** Navigate to workspace:
  ```powershell
  cd C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection
  ```
- [ ] **[RUNTIME EXECUTION]** Launch the live collector daemon:
  ```powershell
  python src/live_collector.py --port COM6 --db-path data/live_monitoring.db
  ```
- [ ] **[RUNTIME VERIFICATION]** Confirm startup banners in Terminal 1:
  - `[DETECTOR] Frozen dual detector loaded from: time_1s_session1_pcap_features_uplink.csv`
  - `[COLLECTOR] Starting run_id=X | Interface=... | Serial=COM6`
  - `[NET] TShark packet stream started.`
  - `[SERIAL] Connected to COM6.`
  - `[SERIAL][INFO] Sniffer session active: boot_id=..., nonce=...`
  - `[COLLECTOR] Both threads started. Press Ctrl+C to stop.`

### 10. Dashboard Startup & Browser Verification
- [ ] **[SOFTWARE/OFFLINE]** Open **Terminal 2 (Dashboard Terminal)**.
- [ ] **[SOFTWARE/OFFLINE]** Navigate to workspace:
  ```powershell
  cd C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection
  ```
- [ ] **[RUNTIME EXECUTION]** Launch the Streamlit monitoring console on dedicated port 8502:
  ```powershell
  streamlit run src/live_dashboard.py --server.port 8502
  ```
- [ ] **[RUNTIME VERIFICATION]** Browser opens at `http://localhost:8502`.
  - Verify dark cybersecurity theme renders.
  - Verify **Persisted Daemon Execution Record** shows active Run #X with status `RUNNING`.
  - Verify zero console errors or missing table warnings.

### 11. Sensor Telemetry Verification (Live Physical Ingestion)
- [ ] **[RUNTIME VERIFICATION]** Navigate to **Physical Sensors (ESP32)** section:
  - Check **Node 1 (DHT11)**: Temperature (~27–31 °C) and Humidity (~85–95%) update every 2.0s.
  - Status indicator displays green `VALID SENSING`.
- [ ] **[PHYSICAL]** Wave hand over the AM312 PIR sensor:
  - Check **Node 2 (PIR)**: Motion event triggers, incrementing the motion count and displaying active status.
- [ ] **[PRESENTATION POINT]** Emphasize verbal disclaimer: Environmental sensors monitor physical ambient conditions independently; physical PIR events do not cause network traffic anomalies.

### 12. Graceful Shutdown Sequence
Follow this exact shutdown sequence to prevent lingering processes or locked ports:
- [ ] **[1. Stop Collector Daemon]**: In Terminal 1, press **`Ctrl + C`** once.
  - Wait for clean shutdown confirmation:
    ```text
    [COLLECTOR] Stopping: Keyboard interrupt (Ctrl+C)
    [SERIAL] Serial thread stopped.
    [COLLECTOR] Final statistics:
    ```
- [ ] **[2. Verify Process Termination]**: In PowerShell, confirm no orphaned subprocesses remain:
  ```powershell
  Get-Process -Name tshark, dumpcap, python -ErrorAction SilentlyContinue
  ```
- [ ] **[3. Stop Dashboard]**: In Terminal 2, press **`Ctrl + C`** to stop Streamlit.
- [ ] **[4. Release Serial Port]**: Confirm COM6 handle is completely released.

### 13. Evidence Preservation & Database Cryptographic Verification
- [ ] **[SOFTWARE/OFFLINE]** Verify cryptographic hashes of all databases immediately after demonstration:
  ```powershell
  Get-FileHash data\live_monitoring.db, data\iot_anomaly.db, data\test_stage722_live_monitoring.db | Format-Table -AutoSize
  ```
- [ ] **[SOFTWARE/OFFLINE]** Confirm `iot_anomaly.db` and `test_stage722_live_monitoring.db` hashes are bit-for-bit identical to baseline.
- [ ] **[SOFTWARE/OFFLINE]** If a demonstration session was recorded in `live_monitoring.db`, note the final `run_id` for reporting.

---

## 3. COM Port Contention Architecture & Avoidance Rules

### 3.1 Root Cause of Contention
On Windows, hardware communication ports (such as COM6 created by the CP210x USB-to-UART driver) enforce an **exclusive OS-level lock** via the Win32 `CreateFile` API.
When process A holds the COM6 handle, any attempt by process B to open COM6 fails immediately with:
```text
serial.serialutil.SerialException: could not open port 'COM6': PermissionError(13, 'Access is denied.', None, 5)
```

### 3.2 Process Ownership Hierarchy
In this project architecture, **`LiveCollector` (running via `python src/live_collector.py`) is the sole authorized owner of COM6 during live operation.**
- `LiveCollector` runs a dedicated serial thread (`LiveCollector-Serial`) that reads sensor telemetry, parses sniffer management frames, sends probe handshakes, and handles automatic exponential reconnection if the cable is disconnected.
- The Streamlit dashboard (`src/live_dashboard.py`) **NEVER opens COM6 directly**. It reads sensor telemetry exclusively from SQLite (`live_sensor_telemetry` and `live_pir_events`), maintaining complete thread and process isolation.

### 3.3 Strict Contention Avoidance Rules:
1. **Never run standalone listeners concurrently:** Do not run `python src/ingest_serial_sensors.py` while `LiveCollector` is running.
2. **Close external serial monitors:** Close Arduino IDE Serial Monitor, PuTTY, or VS Code serial consoles before starting `LiveCollector`.
3. **Verify port ownership before launch:** Run `Get-Process | Where-Object { $_.ProcessName -match "python" }` to ensure no orphaned collector daemon is holding the port in the background.
4. **Order of Operations:**
   - Plug in ESP32 $\to$ Verify COM6 in Device Manager $\to$ Start `LiveCollector` $\to$ Start `LiveDashboard`.
   - On shutdown: Stop `LiveCollector` (`Ctrl+C`) $\to$ Verify port released $\to$ Stop `LiveDashboard`.

