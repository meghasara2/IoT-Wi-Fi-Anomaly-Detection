# Long-Baseline Physical Capture & Processing Execution Guide
**Target File**: `data/processed/experimental_time_windows/long_baseline_validation/workflow_execution_guide.md`  
**Purpose**: Step-by-step, beginner-friendly instructions and exact PowerShell commands to capture 10-minute sessions and process them with the frozen Dual Detector.

---

## 1. Pre-Capture Setup (5 Minutes)

### Step 1.1: Enable Windows Mobile Hotspot
1. Open Windows **Settings** -> **Network & Internet** -> **Mobile Hotspot**.
2. Turn Mobile Hotspot **ON**. Set Network Band to **2.4 GHz**.
3. Note the Hotspot SSID and Password.

### Step 1.2: Connect the Two Mobile Test Devices
1. On **Phone 1 (Node_Client_1)**:
   - Connect to the Hotspot.
   - Verify MAC address matches registered MAC: `ca:34:ea:92:d3:9e` (or record the actual MAC if randomized MAC is active).
   - Expected IP: `192.168.137.201` (or verify via `arp -a`).
2. On **Phone 2 (Node_Client_2)**:
   - Connect to the Hotspot.
   - Verify MAC address matches registered MAC: `e6:2e:db:73:1c:25`.
   - Expected IP: `192.168.137.6` (or verify via `arp -a`).

### Step 1.3: Connect ESP32 Sensor Node
1. Connect ESP32 Dev Module via USB cable to PC.
2. In Device Manager or PowerShell, confirm serial port is `COM6` (or note current COM port).
3. Allow hardware to sit undisturbed for **30 seconds** so the AM312 PIR sensor stabilizes.

---

## 2. Identify the Hotspot Capture Interface

Open PowerShell and query available Wireshark interfaces:

```powershell
& "C:\Program Files\Wireshark\tshark.exe" -D
```

Example Output:
```
1. \Device\NPF_{3D966D1A...} (Local Area Connection* 10)
2. \Device\NPF_{E3465DF4...} (Local Area Connection* 9)
5. \Device\NPF_{5635802C...} (Wi-Fi)
```
Look for the interface corresponding to the Microsoft Wi-Fi Direct Virtual Adapter (usually named `Local Area Connection* 10` or `Local Area Connection* 9`). Note the interface number (e.g., `1` or `2`).

---

## 3. Synchronized 10-Minute Capture Execution

To capture **Session 3 (10 Minutes)**, open **two separate PowerShell terminal windows**.

### Terminal 1: Start ESP32 Physical Sensor Telemetry Storage
In the first PowerShell window, initialize the database and start the listener:

```powershell
cd C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection
python src/record_sensor_telemetry.py --init-db --db data/telemetry_test/session3_sensor_telemetry.db --port COM6
```
*(Leave this running. You will see validated readings printed every 2 seconds).*

### Terminal 2: Start Network PCAP Capture (Automatic 600-Second Duration)
In the second PowerShell window, launch TShark to capture on your hotspot interface (replace `-i 1` with your interface number from Step 2):

```powershell
cd C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection
& "C:\Program Files\Wireshark\tshark.exe" -i 1 -a duration:600 -w data/telemetry_test/session3_hotspot_capture.pcapng
```
*(This command will automatically capture traffic for exactly 600 seconds (10 minutes) and then cleanly terminate).*

### Execute the Activity Schedule During the 10 Minutes:
- **00:00 to 03:00 (3 min)**: Phones idle on desk. Background apps only.
- **03:00 to 07:00 (4 min)**: Normal web browsing and apps on Phone 1.
- **07:00 to 08:30 (1.5 min)**: Documented non-disruptive burst: stream a 720p/1080p web clip on Phone 1.
- **08:30 to 10:00 (1.5 min)**: Idle recovery. Phones resting on desk.

### Stop Terminal 1:
When the network capture in Terminal 2 completes after 600 seconds, switch to Terminal 1 and press **Ctrl+C** to stop the sensor listener.

*(Repeat the above procedure for Session 4, replacing `session3` with `session4` in filenames).*

---

## 4. Automated Workflow Execution Command

Once `data/telemetry_test/session3_hotspot_capture.pcapng` and `data/telemetry_test/session3_sensor_telemetry.db` are recorded, execute the complete validation pipeline with a single command:

```powershell
python src/validate_long_baseline_workflow.py `
  --session-name session3_10min `
  --pcap data/telemetry_test/session3_hotspot_capture.pcapng `
  --sensor-db data/telemetry_test/session3_sensor_telemetry.db `
  --output-dir data/processed/experimental_time_windows/long_baseline_validation
```

### What the Pipeline Performs Automatically:
1. Extracts uniform 1-second uplink feature windows using `src/extract_pcap_time_windows.py`.
2. Aligns physical sensor telemetry records within $\pm 2.0$s tolerance using `src/align_time_windows_with_sensors.py`.
3. Scores every window using the **frozen Dual Detector** trained on Session 1 (no refitting).
4. Applies $N \ge 3$ timing gating ($N < 3$ windows are not penalized for missing IAT).
5. Compiles window counts, packet-rate distributions, outlier percentages, and alert attributions.
6. Saves all outputs under `data/processed/experimental_time_windows/long_baseline_validation/`:
   - `session3_10min_1s_features.csv`
   - `session3_10min_1s_traffic_sensor_aligned.csv`
   - `session3_10min_dual_detector_predictions.csv`
   - `session3_10min_validation_summary.csv`
   - `session3_10min_session_report.md`
