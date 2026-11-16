# Controlled 10-Minute Capture Protocol & Operator Run Sheet
**Directory**: `data/processed/experimental_time_windows/controlled_baseline_planning/`  
**File**: `controlled_capture_protocol_and_run_sheet.md`  
**Purpose**: Standardized, repeatable protocol for executing controlled baseline captures with timestamped operator activity logging.

---

## 1. Operational Scope & Core Philosophy

Previous captures (Sessions 3 and 4) demonstrated that the automated extraction and scoring pipeline works reliably across 10-minute durations (598 seconds). However, because operator action timestamps were not recorded during capture, user activity phases (browsing vs. streaming) could not be verified against the timeline.

This protocol introduces a **timestamped operator run sheet**.

> [!IMPORTANT]
> **METHODOLOGICAL RULE**: Planned activities are **planned procedures**, NOT proof of what the network capture actually contains. All activity timestamps must be physically recorded by the operator during execution and compared against observed packet rates during offline analysis. Anomaly alerts indicate statistical deviation from the Session 1 baseline, **NOT confirmed cyberattacks**.

---

## 2. Pre-Capture Equipment & Environment Checklist

Complete every check prior to starting capture:

### A. Wi-Fi Hotspot & Gateway Setup
- [ ] **Windows Mobile Hotspot Enabled**: On the capture laptop, navigate to **Settings** $\rightarrow$ **Network & Internet** $\rightarrow$ **Mobile Hotspot** and turn ON.
- [ ] **Frequency Band**: Configured strictly to **2.4 GHz** (to ensure compatibility with IoT devices).
- [ ] **Subnet Confirmed**: Gateway IP is `192.168.137.1` (subnet `192.168.137.0/24`).
- [ ] **Internet Uplink Active**: Ensure host laptop has active Internet connectivity (via Ethernet or secondary Wi-Fi) to allow normal DNS and cloud traffic.
- [ ] **Interface Identification**: Run `& "C:\Program Files\Wireshark\tshark.exe" -D` in PowerShell to identify the exact interface number for the Microsoft Wi-Fi Direct Virtual Adapter (e.g., `Local Area Connection* 10`).

### B. Mobile Client Node Configuration
- [ ] **Device 1 (Node_Client_1)**:
  - Connected to the Hotspot.
  - MAC Address verified: `ca:34:ea:92:d3:9e`. (*Ensure "Randomized MAC" is set to "Use Device MAC"*).
  - Assigned IP verified: `192.168.137.201` (or checked via `arp -a`).
  - Mobile Data (Cellular) turned **OFF** (forces all uplink/downlink traffic through Wi-Fi).
- [ ] **Device 2 (Node_Client_2)**:
  - Connected to the Hotspot.
  - MAC Address verified: `e6:2e:db:73:1c:25`. (*Ensure "Randomized MAC" is set to "Use Device MAC"*).
  - Assigned IP verified: `192.168.137.6` (or checked via `arp -a`).
  - Mobile Data (Cellular) turned **OFF**.
- [ ] **Physical Placement**: Both phones placed on a non-conductive surface (desk) approximately **1.0 meter** apart and ~1.5 meters from the laptop hotspot antenna.

### C. Physical Sensor Node Configuration
- [ ] **Hardware Role**: Single ESP32 Dev Module attached via USB cable to PC. (*Note: No second ESP32 or external Wi-Fi monitor hardware is assumed*).
- [ ] **Serial Port Confirmed**: COM port verified as `COM6` at 115200 baud.
- [ ] **Pre-Warm Stabilization**: Plug in ESP32 and wait **at least 30 seconds** prior to starting capture to allow AM312 pyroelectric IR background and DHT11 single-wire bus to stabilize.
- [ ] **Placement**: Sensor node positioned adjacent to client devices with clear line-of-sight to the desk environment.

---

## 3. Four-Phase Activity Timeline (Exactly 10 Minutes / 600 Seconds)

```
[00:00] ─── Phase 1: Quiescent Background Standby (2.5 min) ─── [02:30]
[02:30] ─── Phase 2: Light / Ordinary Browsing & Apps (3.0 min) ─ [05:30]
[05:30] ─── Phase 3: Sustained Video / High-Rate Burst (2.5 min) ─ [08:00]
[08:00] ─── Phase 4: Return to Quiescent Baseline (2.0 min) ───── [10:00]
```

### Phase 1: Quiescent Background Standby (Planned: 00:00 to 02:30, 150s)
- **Goal**: Evaluate baseline low-rate polling and timing gating ($N < 3$).
- **Operator Action**: Both phones remain on the table, screens ON, no user touches or app launches. Allow background operating system sync (NTP, DNS, push tokens) to proceed naturally.
- **Expected Traffic**: 1 to 5 pkts/s per device with intermittent quiet seconds ($N \in [0, 2]$).

### Phase 2: Light / Ordinary Browsing & Apps (Planned: 02:30 to 05:30, 180s)
- **Goal**: Establish nominal interactive multi-flow baseline.
- **Operator Action**: On `Node_Client_1`, open a mobile web browser and browse university or news pages (e.g., wikipedia.org, srmist.edu.in). On `Node_Client_2`, open a standard weather or calendar application and refresh.
- **Expected Traffic**: 10 to 35 pkts/s per device, payload sizes 150 to 500 bytes.

### Phase 3: Sustained Video / High-Rate Traffic Burst (Planned: 05:30 to 08:00, 150s)
- **Goal**: Test primary detector response to sustained high throughput without malicious flood generation.
- **Operator Action**: On `Node_Client_1`, launch YouTube or web browser and stream a 720p or 1080p video clip continuously. On `Node_Client_2`, scroll an image-heavy social media feed or load multiple web pages.
- **Expected Traffic**: 150 to 600+ pkts/s with MTU-sized packets (1200–1514 bytes).

### Phase 4: Return to Quiescent Baseline (Planned: 08:00 to 10:00, 120s)
- **Goal**: Verify rapid return to baseline and test for lingering state-leakage false alarms.
- **Operator Action**: Close video player and browser. Place both phones on desk. No user interaction for the remaining 2 minutes.
- **Expected Traffic**: Return to 1 to 5 pkts/s.

---

## 4. Printable / Digital Operator Run Sheet

The operator must keep a clock or smartphone timer visible and record the **actual clock time** when each action occurs:

```markdown
# Operator Run Sheet: Controlled Baseline Capture
- **Session Identifier**: session5_controlled_10min
- **Date**: YYYY-MM-DD
- **Operator Name**: __________________________
- **Laptop Host Clock Synchronized**: [ YES / NO ]
- **Hotspot Virtual Interface**: Local Area Connection* [ ____ ] (TShark index: [ ___ ])
- **ESP32 COM Port**: COM6 (Baud: 115200)

### Execution Timestamps:
| Capture Step | Target Action | Planned Offset | Actual Local Time (HH:MM:SS) | Actual UTC Time (HH:MM:SS) |
| :--- | :--- | :---: | :---: | :---: |
| **Pre-Capture** | ESP32 Plugged in (Pre-warm 30s) | -00:30 | __:__:__ | __:__:__ |
| **Capture Start** | Sensor Listener Started (Term 1)| 00:00 | __:__:__ | __:__:__ |
| **Capture Start** | TShark Capture Started (Term 2) | 00:00 | __:__:__ | __:__:__ |
| **Phase 1 Start** | Phones on table, idle standby | 00:00 | __:__:__ | __:__:__ |
| **Phase 1 End** | End of idle standby | 02:30 | __:__:__ | __:__:__ |
| **Phase 2 Start** | Browsing started on Phone 1 | 02:30 | __:__:__ | __:__:__ |
| **Phase 2 End** | Browsing stopped | 05:30 | __:__:__ | __:__:__ |
| **Phase 3 Start** | 720p/1080p Video Stream Started | 05:30 | __:__:__ | __:__:__ |
| **Phase 3 End** | Video Stream Closed | 08:00 | __:__:__ | __:__:__ |
| **Phase 4 Start** | Phones resting on desk, idle | 08:00 | __:__:__ | __:__:__ |
| **Phase 4 End** | TShark Auto-Stops (600s reached)| 10:00 | __:__:__ | __:__:__ |
| **Post-Capture** | Sensor Listener Stopped (Ctrl+C)| 10:05 | __:__:__ | __:__:__ |

### Detailed Activity & Environment Notes:
- Phone 1 (ca:34:ea:92:d3:9e) Browsing Domains: ___________________________________
- Phone 1 Video Title / Platform: _________________________________________________
- Phone 2 (e6:2e:db:73:1c:25) Apps Used: __________________________________________
- Operator Physical Movement in Room (PIR context): [ Seated Still / Moving around ]
- Any Unexpected Device Behavior (e.g. phone screen sleep, OS notification): _________
```

---

## 5. Offline Evaluation Plan (Frozen Dual-Detector)

Once capture files are saved (`data/telemetry_test/session5_hotspot_capture.pcapng` and `data/telemetry_test/session5_sensor_telemetry.db`), evaluate them using the existing automated workflow script:

```powershell
python src/validate_long_baseline_workflow.py `
  --session-name session5_controlled_10min `
  --pcap data/telemetry_test/session5_hotspot_capture.pcapng `
  --sensor-db data/telemetry_test/session5_sensor_telemetry.db `
  --output-dir data/processed/experimental_time_windows/controlled_baseline_planning
```

### Analysis Methodology:
1. **Zero Retraining**: The detector bundle remains strictly frozen (Primary offset: -0.581180; Timing offset: -0.617487).
2. **Phase Correlation**: Map the 1-second prediction windows to the **actual recorded timestamps** from the operator run sheet:
   - Compute the alert rate during Phase 1 (Idle). Verify whether timing gating ($N < 3$) prevented false alarms.
   - Compute the alert rate during Phase 2 (Browsing). Check whether standard multi-flow traffic fits within the primary envelope.
   - Compute the alert rate during Phase 3 (Video Burst). Identify whether primary burst alerts correlate directly with the video playback duration.
   - Compute the alert rate during Phase 4 (Recovery). Verify rapid return to inlier status.
3. **Sensor Cross-Verification**: Check DHT11 validity and inspect whether AM312 PIR motion transitions correlate with physical room movement noted in the run sheet.
