# Stage 7.3: Final Demonstration Plan

**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Target Audience:** Capstone Evaluation Panel, Technical Reviewers, and Academic Examiners  
**Execution Context:** Windows 11 Host, Python 3.11, Streamlit Live Console, ESP32 Dev Board on COM6, Windows Mobile Hotspot

---

## 1. Executive Demonstration Overview

This demonstration showcases an end-to-end, multi-tier security and monitoring system designed for IoT Wi-Fi environments. The demonstration highlights:
1. **Physical & Environmental Telemetry:** Ingestion of DHT11 temperature/humidity and AM312 PIR motion sensing from a hardware ESP32 node via serial UART.
2. **Real-Time Network Ingestion:** TShark live packet capture from the Windows Mobile Hotspot interface with client MAC attribution.
3. **Fixed 1-Second Sliding Window Feature Extraction:** Mathematical aggregation of volumetric, payload size, and inter-arrival time (IAT) features.
4. **Machine Learning Anomaly Detection:** An unsupervised Dual-Detector Isolation Forest (trained on Session 1 baseline) with mathematical gating ($N \ge 3$) preventing false alarms on quiet intervals.
5. **Deterministic Cyberattack Detection:** Five parallel protocol-aware threat engines (DoS, Port Scan, Identity Spoofing, Deauthentication Flood, and Replay Attack) providing explainable JSON evidence and telemetry honesty.
6. **Live Cyber Console:** A dark-themed Streamlit dashboard delivering real-time telemetry charts, anomaly score distributions, and threat intelligence.

---

## 2. System Architecture & Data Flow

```
                                      ┌─────────────────────────────────────────────────────────┐
                                      │                    PHYSICAL TESTBED                     │
                                      └─────────────────────────────────────────────────────────┘
                                                │                                       │
                                                ▼                                       ▼
                                     ┌─────────────────────┐                 ┌─────────────────────┐
                                     │   ESP32 Dev Module  │                 │    Hotspot Clients  │
                                     │  • DHT11 (GPIO 4)   │                 │  • Node_3 (Phone 1) │
                                     │  • AM312 PIR (GP27) │                 │  • Node_4 (Phone 2) │
                                     │  • Promiscuous Ch 6 │                 │  • Hotspot: 192.168.│
                                     └─────────────────────┘                 └─────────────────────┘
                                                │ (UART 115200)                         │ (802.11 Wi-Fi)
                                                ▼                                       ▼
                                     ┌─────────────────────┐                 ┌─────────────────────┐
                                     │   Serial Worker     │                 │   TShark Subprocess │
                                     │   (COM6 Ingestion)  │                 │ (Local Area Conn* 2)│
                                     └─────────────────────┘                 └─────────────────────┘
                                                │                                       │
                                                └───────────────────┬───────────────────┘
                                                                    │
                                                                    ▼
                                                 ┌─────────────────────────────────────┐
                                                 │       LiveCollector Pipeline        │
                                                 │   • 1.0s Fixed Window Aggregation   │
                                                 │   • MAC Registry Attribution        │
                                                 │   • Supervisor Heartbeat Protection │
                                                 └─────────────────────────────────────┘
                                                                    │
                                       ┌────────────────────────────┴───────────────────────────┐
                                       ▼                                                        ▼
                        ┌─────────────────────────────┐                          ┌─────────────────────────────┐
                        │   Dual Isolation Forest     │                          │   Deterministic Detectors   │
                        │   • Primary: Rate & Size    │                          │   • DoS (Burst vs Sustained)│
                        │   • Timing: IAT (N >= 3)    │                          │   • Port Scan (SYN Probes)  │
                        │   • Statistical Anomaly -1  │                          │   • Spoofing (IP Conflicts) │
                        └─────────────────────────────┘                          │   • Deauth (802.11 Frames)  │
                                       │                                         │   • Replay (Flow Nonces)    │
                                       │                                         └─────────────────────────────┘
                                       │                                                        │
                                       └────────────────────────────┬───────────────────────────┘
                                                                    ▼
                                                 ┌─────────────────────────────────────┐
                                                 │     SQLite WAL Storage Engine       │
                                                 │   • Atomic Multi-Table Windows      │
                                                 │   • 250ms PRAGMA busy_timeout       │
                                                 │   • Deferred Dedup Cache Updates    │
                                                 └─────────────────────────────────────┘
                                                                    │
                                                                    ▼
                                                 ┌─────────────────────────────────────┐
                                                 │       Streamlit Live Console        │
                                                 │        (src/live_dashboard.py)      │
                                                 │   • Overview KPI Ribbon             │
                                                 │   • Network Traffic Analytics       │
                                                 │   • Statistical Anomaly Console     │
                                                 │   • Attack Threat Intelligence      │
                                                 │   • ESP32 Environmental Graphs      │
                                                 └─────────────────────────────────────┘
```

---

## 3. Step-by-Step Demonstration Sequence

### Step 1: Physical Setup & Architecture Overview (Duration: ~2 min)
* **What to Show:**
  - Show the physical hardware setup: the ESP32 Dev Module plugged into USB (`COM6`), the DHT11 sensor (GPIO 4), and the AM312 PIR sensor (GPIO 27).
  - Show the Windows Mobile Hotspot settings screen with connected client phones (`Node_3` and `Node_4`).
* **Audience Takeaway:**
  - Understand the multi-tiered architecture: hardware IoT sensors combined with edge traffic monitoring on a Windows-hosted hotspot.

### Step 2: Collector Launch & Firmware Handshake (Duration: ~2 min)
* **What to Show:**
  - Launch the collector terminal:
    ```bash
    python src/live_collector.py --interface 5 --port COM6 --db-path data/live_monitoring.db
    ```
  - Highlight the initial log output:
    1. Frozen Dual-Detector offset loading (`Primary offset: -0.581180`, `Timing offset: -0.617487`).
    2. Hotspot Gateway MAC auto-verification (`36:6f:24:d2:34:3d`).
    3. TShark packet stream startup on Interface Index 5.
    4. ESP32 serial connection and cryptographic probe handshake (`Sniffer session active: boot_id=..., nonce=...`).
* **Audience Takeaway:**
  - The collector is fully autonomous, resilient against stale UART buffers, and initializes all ML and security components deterministically.

### Step 3: Streamlit Live Dashboard Tour (Duration: ~3 min)
* **What to Show:**
  - Launch and open the dashboard in a web browser (`http://localhost:8501`):
    ```bash
    streamlit run src/live_dashboard.py
    ```
  - Direct the panel to the **Overview & Live Feed** tab:
    - Point out the **Daemon State** badge (`STREAMING` / green border).
    - Show the **1s Traffic Windows** counter and **Active Clients** (`Node_3`, `Node_4`).
    - Explain the top KPI cards: Anomaly Rate, Gateway Ingestion PPS, and Environmental Telemetry.
* **Audience Takeaway:**
  - The dashboard delivers live, unified visibility into both the physical room environment and virtual network state.

### Step 4: Environmental & Physical Sensor Monitoring (Duration: ~2 min)
* **What to Show:**
  - Navigate to the **Physical Sensors (ESP32)** tab.
  - Show the dual-axis line chart for Node 1: real-time room temperature in °C and relative humidity in %.
  - Trigger the PIR motion sensor by waving a hand over the AM312 sensor; show the motion detection count update and active interval gauge increment.
* **Audience Takeaway:**
  - Physical telemetry is reliably ingested every 2.0 seconds with zero invalid readings.
  - *Verbal Clarification:* Physical room temperature and motion are monitored concurrently but are mathematically decoupled from network anomaly scoring (no causal conflation).

### Step 5: Network Traffic Dynamics & Feature Extraction (Duration: ~2 min)
* **What to Show:**
  - Navigate to the **Live Network Traffic** tab.
  - Generate benign traffic by browsing a web page or playing a short video on one of the connected phones.
  - Show the instantaneous packet rate surge (e.g. 70–180 pps) and mean packet size trends for `Node_3` and `Node_4`.
* **Audience Takeaway:**
  - TShark packet streams are binned into non-overlapping 1.0-second intervals per client MAC address.

### Step 6: Isolation Forest Anomaly Detection in Action (Duration: ~3 min)
* **What to Show:**
  - Navigate to the **Anomaly Alerts Console** tab.
  - Show the **Dual-Detector Anomaly Breakdown**:
    - `ANOMALY_PRIMARY_BURST_OR_SIZE`: Highlight how mobile traffic bursts diverge from the quiet Session 1 IoT baseline.
    - `NORMAL_QUIET_TIMING_UNAVAILABLE`: Explain the mathematical gating ($N < 3$) that prevents spurious timing jitter alarms when devices are quiet.
  - Show the Anomaly Score distribution and explain that negative scores ($< 0$) indicate outliers per standard scikit-learn convention.
* **Audience Takeaway:**
  - The Isolation Forest is frozen (re-fitted strictly on Session 1 without runtime drift).
  - *Verbal Clarification:* Statistical anomalies reflect mathematical deviations from the idle training distribution—they are *not* cyberattacks.

### Step 7: Deterministic Attack Intelligence & Threat Console (Duration: ~3 min)
* **What to Show:**
  - Navigate to the **Attack Intelligence** tab.
  - Review the Five Category Capability Ribbon:
    1. *Denial of Service (DoS):* Shows `NO_EVIDENCE` / `OPERATIONAL`. Explain the fleet surge filter ($\ge 50\%$ active devices surging) and outbound WAN CDN streaming exclusions.
    2. *Reconnaissance / Port Scan:* Shows `NO_EVIDENCE` / `INSUFFICIENT_TELEMETRY`. Explain local LAN horizontal sweep isolation and infrastructure port exclusions.
    3. *Identity Spoofing:* Shows `NO_EVIDENCE` / `OPERATIONAL`. Explain that randomized MACs are tolerated and genuine spoofing requires confirmed IP-to-MAC binding conflicts ($\ge 2$ packets).
    4. *Deauthentication Flood:* Shows `NO_EVIDENCE` / `INSUFFICIENT_TELEMETRY`. Explain that Windows NDIS strips raw 802.11 management frames, and show the ESP32 promiscuous sniffer status on Channel 6.
    5. *Replay Attack:* Shows `INSUFFICIENT_TELEMETRY`. Explain telemetry honesty: without cryptographic nonces or payload hashes on raw frames, the system refuses to guess.
* **Audience Takeaway:**
  - High academic credibility: the engine strictly separates statistical outliers from deterministic attacks and explicitly reports missing telemetry rather than producing false alarms.

### Step 8: Controlled Shutdown & Database Verification (Duration: ~2 min)
* **What to Show:**
  - Switch to the collector terminal and issue a graceful stop (`Ctrl+C`).
  - Show the terminal output: worker threads terminate cleanly, TShark subprocess closes, and COM6 is released.
  - Refresh the dashboard: show that the Daemon State immediately updates to `STOPPED` and displays an **Archived Session Banner** without crashing.
* **Audience Takeaway:**
  - The system is robust, safe, and production-engineered with complete lifecycle supervision.

---

## 4. Safe Demonstration Scenario (Zero Live Attack Traffic)

The demonstration is conducted entirely using **ordinary, safe network activity**:
1. **Idle IoT Baseline:** Connected phones remain locked and idle, producing periodic low-rate keepalive packets (1–10 pps) classified as `NORMAL_INLIER` or `NORMAL_QUIET_TIMING_UNAVAILABLE`.
2. **Benign Mobile Browsing / Streaming:** Opening a news website or loading a video generates an uplink burst (60–180 pps). This demonstrates:
   - Live traffic window extraction.
   - Dual-detector statistical alert generation (`ANOMALY_PRIMARY_BURST_OR_SIZE`).
   - Attack detector restraint: the DoS detector inspects the destination IP (`most_targeted_ip`), recognizes external CDN streaming, and logs `NO_EVIDENCE` (no false cyberattack alarm).
3. **PIR Physical Motion Trigger:** Waving near the sensor triggers `motion_detected = 1` in `live_pir_events`.
4. **Device Registry Identification:** Show both phones identified as `Node_3` and `Node_4` with `last_seen` timestamps updating in real time.

---

## 5. Honest Explanation of Attack Detector Capabilities

| Threat Category | What the Detector Checks | What Existing Tests Demonstrate | What Has NOT Been Live-Tested (Limitations) |
| :--- | :--- | :--- | :--- |
| **Denial of Service (DoS)** | Sustained packet rate ($\ge 60\text{ pps}$) over $\ge 3$ consecutive 1s windows; target concentration ($\ge 75\%$); local gateway/node destination. | 13 automated tests verify fleet surge suppression, transient burst exclusion, WAN CDN exclusion, and local flood detection. | Physical, destructive DDoS was never launched against the hotspot router to prevent network disruption. |
| **Port Scanning** | Vertical scans ($\ge 8$ ports/host) and horizontal sweeps ($\ge 5$ local LAN hosts); connection attempts (SYN w/o ACK, UDP probes); excludes 11 discovery ports. | 12 automated tests verify TCP SYN sweeps, UDP horizontal scans, mobile web browsing exclusion, and established TCP exclusion. | Active Nmap or masscan probes were not launched against live phones during evaluations. |
| **Identity Spoofing** | Conflicting IP-to-MAC bindings over a 60s conflict window; $\ge 2$ packet confirmation; ignores randomized MACs; gateway impersonation guard. | 17 automated tests verify conflicting bindings, DHCP discovery handling, safe binding expiry (300s), and baseline integrity. | Physical ARP cache poisoning or rogue DHCP servers were not deployed on the live hotspot network. |
| **Deauth / Disassoc Flood** | 802.11 management frames (subtypes 10/12); flood threshold ($\ge 5\text{ frames/s}$ per BSSID); reason codes; broadcast targets. | 2 automated tests verify frame ingestion and flood thresholds; ESP32 sniffer protocol tests pass 18/18. | Active RF deauthentication jamming (`aireplay-ng`) was not broadcast over the airwaves (adhering to RF legal regulations). |
| **Message / Packet Replay** | Flow-key 5-tuple matching; sequence number regression; nonce reuse; suppresses TCP retransmissions within RTO (3.0s window). | 7 automated tests verify TCP retransmission suppression and synthetic nonce replay detection. | Real-time payload hashing is not computed in live TShark arguments (`INSUFFICIENT_TELEMETRY` honestly reported). |

---

## 6. Fallback Demonstration Plan (Zero Live Hardware Required)

If hardware failure occurs during the presentation (e.g. USB port disconnect, ESP32 brownout, or Windows hotspot failure), the presenter can immediately activate the **Stage 7.2.2 Archival Fallback**:

1. **Keep Dashboard Running:** Do not close the Streamlit dashboard.
2. **Switch Database Path in Sidebar:**
   - In the Streamlit sidebar under **System Controls**, replace `Live DB Path` with:
     ```text
     data/test_stage722_live_monitoring.db
     ```
   - Click **🔄 Refresh Data Now**.
3. **Select Run #1:** Under **Collector Run Filter**, select `Latest Session` or `Run #1 (STOPPED)`.
4. **What the Dashboard Immediately Displays:**
   - All **239 feature windows** and **71,967 packets** from the physical Stage 7.2.2 run.
   - All **90 physical DHT11 environmental readings** ($29.3\text{ }^\circ\text{C}$, $92.3\%$ humidity).
   - All **90 physical PIR motion readings** (including the motion trigger at sequence 19).
   - The complete Dual-Detector anomaly distribution (185 primary burst, 5 timing jitter, 27 inlier, 22 quiet).
   - The Five Category Attack Status ribbon reflecting verified live sniffer session data.
5. **Alternative Historical Fallback:** The presenter can alternatively point the path to `data/live_monitoring.db` and select `Run #6` or `Run #5` to demonstrate historical physical runs.

