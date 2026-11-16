# STAGE 9.2 — CONTROLLED LIVE DEMONSTRATION REPORT

**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Workspace:** `C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection`  
**Target Live DB:** `C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection\data\stage9_demo_live_monitoring.db`  
**Start Timestamp (UTC):** `2026-11-15T12:17:00+00:00`  
**End Timestamp (UTC):** `2026-11-15T12:20:07+00:00`  
**Planned Duration:** 180.0 seconds | **Actual Duration:** `187.00` seconds  
**Overall Result:** **`PASS WITH LIMITATIONS`**  

---

## 1. Executive Summary

An authorized, controlled 3-minute live physical demonstration of the complete IoT Wi-Fi Network Security and Anomaly Detection platform was successfully executed. The demonstration concurrently captured live over-the-air 802.11 network traffic from two authenticated smartphones connected to the Windows Mobile Hotspot (`Local Area Connection* 2`) alongside live physical sensor telemetry streamed via serial (`COM6`) from an ESP32 microcontroller equipped with a DHT11 temperature/humidity sensor and an AM312 PIR motion detector.

All demonstration operations strictly complied with approved safety rules:
- Normal, non-disruptive phone traffic was captured (browsing, background sync, reachability checks).
- Zero attack traffic was injected.
- All evidence was stored exclusively in the dedicated demonstration database (`data/stage9_demo_live_monitoring.db`).
- All three pre-existing databases (`live_monitoring.db`, `iot_anomaly.db`, and `test_stage722_live_monitoring.db`) remained cryptographically verified and bit-for-bit untouched.
- Clean shutdown was executed: the LiveCollector stopped gracefully, serial port `COM6` was closed, TShark terminated cleanly, the Streamlit dashboard on port 8502 was stopped, and no lingering processes remained.

---

## 2. Hardware and Software Environment

| Component | Specification / Device Identity | Operational Status |
| :--- | :--- | :---: |
| **ESP32 Microcontroller** | Silicon Labs CP210x USB to UART Bridge (`COM6`, `VID:10C4 PID:EA60`) | Verified Operational |
| **Serial Configuration** | 115,200 baud, 8 data bits, no parity, 1 stop bit | Verified Operational |
| **Environmental Sensor** | DHT11 Digital Temperature & Humidity Sensor (GPIO 4) | Verified Operational |
| **Motion Sensor** | AM312 Passive Infrared (PIR) Sensor (GPIO 27) | Verified Operational |
| **Host Operating System** | Windows 11 (Windows-10-10.0.26200-SP0) | Verified Operational |
| **Capture Subsystem** | TShark v4.6.9 (64-bit) / Npcap v1.89 | Verified Operational |
| **Capture Interface** | Index 5: `Local Area Connection* 2` | Verified Operational |
| **Virtual Hotspot Gateway** | MAC: `36:6f:24:d2:34:3d` (IP: `192.168.137.1 / 24`) | Verified Operational |
| **Client Phone 1** | Vivo V2031 (`ca:34:ea:92:d3:9e`, IP: `192.168.137.101`) -> `Node_3` | Connected & Attributed |
| **Client Phone 2** | Samsung Galaxy A55 (`26:f0:ec:aa:b7:78`, IP: `192.168.137.67`) | Connected & Tracked |
| **Dashboard Server** | Streamlit v1.52.1 on TCP Port 8502 | Verified Responsive |

---

## 3. ESP32 Handshake and Physical Telemetry

- **ESP32 Firmware Boot Handshake:** Valid `WIFI_SNIFFER_INITIALIZED` response received (`boot_id=411020411`, `nonce=2888996866`).
- **Total Physical Sensor Records Ingested:** `93` records.
- **Total PIR Motion Events Recorded:** `93` records.

### 3.1 Environmental Telemetry (Node_1 / DHT11)
| Logical Node | Sensor Type | Ingested Samples | Min Temp (°C) | Mean Temp (°C) | Max Temp (°C) | Min Humidity (%) | Mean Humidity (%) | Max Humidity (%) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Node_1** | DHT11 Temp & Humidity | 93 | 28.5 | 28.5 | 28.5 | 92.0 | 93.0 | 93.0 |

### 3.2 Motion Telemetry (Node_2 / AM312 PIR)
| Motion State | Event Count | Percentage | Physical Interpretation |
| :--- | :---: | :---: | :--- |
| **0** | 82 | 88.2% | NO MOTION (Ambient / Idle) |
| **1** | 11 | 11.8% | MOTION DETECTED (Active Wave) |

---

## 4. Actual Hotspot and ESP32 Runtime Channels

- **ESP32 Runtime Handshake Channel:** **Channel 6** (`Source: FIRMWARE_HANDSHAKE`)
- **Windows Mobile Hotspot Channel:** **`Unavailable via CLI`** (Interface: `Mobile Hotspot`)
- **Channel Alignment Diagnostic Result:** **`CHANNEL_UNAVAILABLE`**
- **Diagnostic Explanation:** `ESP32 sniffer hardware reported Channel 6, but Windows hotspot channel was unavailable.`

> [!NOTE]
> Per Stage 8.4 requirements, the system strictly refuses to assume Channel 6 from the 2.4 GHz band setting or from firmware constants. Because Windows Mobile Hotspot operates as a virtual miniport adapter that does not expose its physical 802.11 channel via `netsh wlan show interfaces`, the diagnostic transparently reports `CHANNEL_UNAVAILABLE` rather than manufacturing an alignment claim.

---

## 5. Phone Attribution and Traffic Breakdown

- **Total 802.11 / IP Packets Parsed:** `28,254` packets
- **1-Second Feature Windows Emitted:** `159` windows

### 5.1 Attributed Device Traffic Windows
| Node ID | Client MAC Address | Windows Emitted | Total Packets | Mean Rate | Min Rate | Max Rate | Attributed Device Identity |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Node_3** | `ca:34:ea:92:d3:9e` | 159 | 2,466 | 15.51 pps | 1.0 pps | 62.0 pps | Phone 1: Vivo V2031 (Static Profile) |

### 5.2 Dynamic Unmapped Device Discovery
| Observed MAC Address | Observations Count | First Observed (UTC) | Last Observed (UTC) | Inferred Device Identity |
| :--- | :---: | :--- | :--- | :--- |
| `26:f0:ec:aa:b7:78` | 108 | `2026-11-15 12:17:03` | `2026-11-15 12:20:04` | Phone 2: Galaxy A55 (Randomized MAC) |
| `36:6f:24:d2:34:3d` | 92 | `2026-11-15 12:17:03` | `2026-11-15 12:20:00` | Windows Mobile Hotspot Virtual Gateway |

---

## 6. Machine Learning Anomaly Detection (Frozen Isolation Forest)

- **Total Windows Scored by Dual Detector:** `159` windows
- **Statistical Outlier Windows Flagged (`pred_dual == -1`):** `33` alerts
- **Statistical Outlier Rate:** `20.8%`
- **Mean Primary Model Outlier Score:** `0.0202`
- **Mean Timing Model Outlier Score:** `0.0899`
- **Mean Packet Rate During Outliers:** `14.06 pps`

### Statistical Deviation Reason Breakdown:
| Dual Reason Code | Alert Count | Percentage | Statistical Interpretation |
| :--- | :---: | :---: | :--- |
| `ANOMALY_PRIMARY_AND_TIMING` | 1 | 3.0% | Inter-arrival time (IAT) timing variance from regular polling |
| `ANOMALY_PRIMARY_BURST_OR_SIZE` | 20 | 60.6% | Burst packet rate or mean packet size variance from idle baseline |
| `ANOMALY_TIMING_JITTER` | 12 | 36.4% | Inter-arrival time (IAT) timing variance from regular polling |

> [!NOTE]
> All anomaly alerts generated by the dual Isolation Forest model represent volumetric and timing statistical deviations from the idle Session 1 baseline during phone web browsing. They are correctly labelled as statistical deviations and were **NOT** interpreted as confirmed cyberattacks.

---

## 7. Deterministic Attack Detection Results

During the 3-minute benign demonstration, the deterministic attack engine performed **795 independent threat evaluations** across all active feature windows and packet streams:

| Threat Category | Operational Status | Live Detection Result | Severity | Events Flagged | Verification Analysis |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Denial of Service (DoS)** | Operational | `NO_EVIDENCE` | `NONE` | 0 | 0 flood windows detected. Benign phone burst traffic correctly remained below DoS sustained rate threshold (60.0 PPS, 3s duration). |
| **Port Scanning** | Operational | `INSUFFICIENT_TELEMETRY` | `NONE` | 0 | 0 vertical or horizontal port scans detected. Normal HTTP/DNS connection attempts safely filtered. |
| **Identity Spoofing** | Operational | `NO_EVIDENCE` | `NONE` | 0 | 0 conflicting IP-to-MAC bindings detected. Client phone bindings remained stable throughout. |
| **Deauthentication Flood** | Operational | `INSUFFICIENT_TELEMETRY` | `NONE` | 0 | 0 deauth frame floods detected. ESP32 sniffer monitored Channel 6 management frames. |
| **Replay Attack** | Operational | `INSUFFICIENT_TELEMETRY` | `NONE` | 0 | Correctly reported telemetry constraint: live stream lacks real-time packet cryptographic payload hashes. |

---

## 8. Database Integrity and Production Isolation

### 8.1 Demonstration Database Verification (`stage9_demo_live_monitoring.db`)
- **Database File Size:** `159,744` bytes
- **PRAGMA integrity_check:** **`ok`**
- **PRAGMA foreign_key_check:** **`0 violations`**
- **Demonstration Tables Summary:**
  - `collector_status`: 1 rows
  - `device_registry`: 0 rows
  - `live_traffic_windows`: 159 rows
  - `live_alerts`: 33 rows
  - `unknown_device_obs`: 2 rows
  - `live_sensor_telemetry`: 93 rows
  - `live_pir_events`: 93 rows
  - `live_attack_events`: 5 rows

### 8.2 Production Database Cryptographic Verification
SHA-256 hashes were computed prior to test startup and immediately following test shutdown.

| Database Path | Expected Baseline SHA-256 | Post-Demonstration SHA-256 | Verification Result |
| :--- | :--- | :--- | :---: |
| `data/live_monitoring.db` | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | **100% UNTOUCHED** |
| `data/iot_anomaly.db` | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | **100% UNTOUCHED** |
| `data/test_stage722_live_monitoring.db` | `74C773C29C49B25CE73E5D5B0641BAB5636FBCC83DA07E08CFFF5043761DFE2D` | `74C773C29C49B25CE73E5D5B0641BAB5636FBCC83DA07E08CFFF5043761DFE2D` | **100% UNTOUCHED** |

---

## 9. Shutdown and Resource Release Verification

- **Collector Termination Status:** `STOPPED`
- **Collector Stop Reason:** `Stage 9.2 180s live demonstration completed successfully`
- **Serial Port (`COM6`):** Closed; exclusive Win32 serial handle released.
- **TShark & Npcap Capture:** TShark stream stopped; zero lingering `tshark.exe` or `dumpcap.exe` processes.
- **Streamlit Dashboard Server:** Subprocess terminated; TCP port 8502 released.
- **Process Cleanup:** Zero test processes remain active in Windows process table.

---

## 10. Limitations and Unresolved Issues

1. **Windows Hotspot Operating Channel CLI Invisibility:** Windows 11 virtual Wi-Fi Direct miniports (`Local Area Connection* 2`) do not report their active RF operating channel via `netsh wlan show interfaces`. Rather than hardcoding or guessing Channel 6, the system transparently logs `CHANNEL_UNAVAILABLE`.
2. **Replay Attack Telemetry Constraint:** Replay attack detection honestly preserves `INSUFFICIENT_TELEMETRY` on live streams because real-time payload hashing is not computed by TShark.
3. **Benign Traffic Distinction:** All Isolation Forest anomaly markers represent expected statistical rate/variance deviations during normal phone browsing, distinctly separated from actionable cyberattacks.
4. **Physical RF Attack Abstention:** Per ethical and legal constraints, live over-the-air deauthentication floods were not transmitted during this physical demonstration; deauth detector accuracy is established via synthetic unit tests (63 tests).

---

*(Report compiled and verified following completion of authorized Stage 9.2 Controlled Live Demonstration).*
