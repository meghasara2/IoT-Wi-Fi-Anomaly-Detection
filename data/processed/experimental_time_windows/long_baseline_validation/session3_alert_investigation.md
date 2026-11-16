# Detailed Investigation Report: Session 3 (10-Minute Baseline Validation)
**File**: `data/processed/experimental_time_windows/long_baseline_validation/session3_alert_investigation.md`  
**Evaluation Scope**: Physical 10-Minute Capture (Session 3) vs. Frozen Session 1 Dual-Detector  
**Capture Input**: `data/telemetry_test/session3_hotspot_capture.pcapng` (PCAPNG, 598s duration)  
**Sensor Database**: `data/telemetry_test/session3_sensor_telemetry.db` (SQLite, 510 records)  
**Frozen Model Baseline**: Trained strictly on Session 1 (`time_1s_session1_pcap_features_uplink.csv`)  

---

## 1. Executive Summary & Key Findings

1. **Successful Execution of 10-Minute Protocol**:
   - Session 3 captured **598.0 continuous seconds (9 minutes 58 seconds)** of multi-client Wi-Fi uplink traffic.
   - A total of **678 one-second feature windows** were extracted across the two registered mobile clients (`Node_Client_1`: 445 windows; `Node_Client_2`: 233 windows).
2. **Dual-Detector Anomaly Flagging**:
   - Total dual alerts: **123 out of 678 windows (18.14%)**.
   - Primary Volumetric/Payload alerts: **92 windows (13.57%)**, driven by active web browsing, background mobile OS synchronization, and video streaming bursts (packet rates up to 509 pkts/s).
   - Secondary Timing Jitter alerts: **31 windows (4.57%)**, driven by extreme bimodal inter-arrival time dispersion ($\sigma_{\text{IAT}}$ up to 0.59s) during low-packet bursts ($N \in [3, 6]$).
   - **Zero Overlap**: There was exactly **0 overlap** between primary-only and timing-only alerts. The two detectors operated in completely orthogonal parameter regimes.
3. **Timing Gating Verification ($N < 3$)**:
   - Out of 678 windows, **168 windows (24.78%)** had fewer than 3 packets ($N=1$ or $N=2$).
   - For all 168 windows, the timing detector was correctly gated to `UNAVAILABLE_N_LT_3` and generated **zero false timing alarms**.
   - **165 of these 168 windows** were classified as `NORMAL_QUIET_TIMING_UNAVAILABLE`.
   - **3 windows** were flagged by the Primary Detector due to unusually large payload sizes (893 to 1158 bytes), correctly demonstrating that volumetric/size protection remains active even when timing is unavailable.
4. **Physical Sensor Performance**:
   - The ESP32 sensor listener logged **510 records** over 1018 seconds, completely enveloping the 598-second network capture.
   - **DHT11**: 100% valid reads (510/510, 0% checksum timeout), though reporting an unvarying 30.2°C / 92.0% humidity throughout the trace.
   - **AM312 PIR**: **Dynamic operation restored**. Unlike Session 2 where PIR was stuck HIGH at 100%, Session 3 recorded 363 motion=0 (71.18%) and 147 motion=1 (28.82%).
   - All 678 network windows successfully aligned with a sensor record within a maximum time delta of 0.5 seconds (100.0% match rate).
5. **Session 4 Operational Recommendation**:
   - **Session 4 should proceed**. The network capture, sensor logging, and feature extraction pipelines worked stably.
   - **Crucial Refinement**: The operator must log the exact clock timestamps (HH:MM:SS) of physical user actions (when browsing began, when video streaming was started and stopped) on a physical run sheet, as activity transitions cannot be reliably inferred from network traffic volume alone.

---

## 2. Actual CSV Schemas & Data Inspection

The evaluated Session 3 datasets adhere strictly to the experimental schema:

### 1. `session3_10min_1s_features.csv` (678 rows, 16 columns)
- **Identifiers & Metadata**: `client_mac`, `node_id`, `Node_Type`, `Data_Label`, `Window_ID`, `Bin_Index`
- **Window Timestamps**: `bin_start_timestamp`, `bin_end_timestamp`, `Window_Start_UTC`, `Window_End_UTC`
- **Network Feature Matrix**: `packet_count`, `mean_IAT`, `IAT_std`, `packet_rate`, `mean_packet_size`, `packet_size_std`

### 2. `session3_10min_1s_traffic_sensor_aligned.csv` (678 rows, 29 columns)
- Adds `window_center_epoch` and sensor contextual fields:
  `telemetry_id`, `sensor_node_id`, `sensor_sequence_num`, `sensor_uptime_ms`, `temperature_c`, `humidity_pct`, `dht_valid`, `motion_detected`, `sensor_captured_at`, `sensor_epoch`, `time_delta_sec`, `alignment_status`

### 3. `session3_10min_dual_detector_predictions.csv` (678 rows, 36 columns)
- Adds dual detector scores and classifications:
  `score_primary`, `pred_primary`, `score_timing`, `pred_timing`, `timing_status`, `pred_dual`, `dual_reason`

### 4. `session3_10min_validation_summary.csv` (1 row, 14 summary metrics)

---

## 3. Capture Duration, Timestamps, and Activity Schedule Analysis

### Actual Capture Boundaries:
- **Global Start Timestamp**: `2026-10-14 09:28:45.000 UTC` (Epoch: 1791970125.0)
- **Global End Timestamp**:   `2026-10-14 09:38:43.000 UTC` (Epoch: 1791970723.0)
- **Actual Measured Duration**: **598.0 seconds** (9 minutes 58 seconds)
- **Active Client Devices Verified**:
  - `Node_Client_1` (`ca:34:ea:92:d3:9e`): 445 active windows, spanning 598.0 seconds (`09:28:45` to `09:38:43 UTC`).
  - `Node_Client_2` (`e6:2e:db:73:1c:25`): 233 active windows, spanning 565.0 seconds (`09:28:45` to `09:38:10 UTC`).
  - *Note*: Window counts are less than 598 because feature extraction operates in sparse mode (`include_empty=False`); seconds with zero captured packets for a client are not emitted.

### Can the Planned Schedule Be Identified from Traffic Alone?
**No. Activity boundaries cannot be definitively confirmed from traffic alone without operator run-sheet logs.**

Analyzing minute-by-minute traffic rates reveals significant divergence from the nominal schedule:

| Minute | Time Offset | Total Windows | C1 Windows (Rate Mean / Max) | C2 Windows (Rate Mean / Max) | Observed Traffic Nature |
| :---: | :---: | :---: | :---: | :---: | :--- |
| **0** | 00:00 - 01:00 | 88 | 54 win (30.9 / 71 pkts/s) | 34 win (28.0 / 86 pkts/s) | Initial interactive / setup activity |
| **1** | 01:00 - 02:00 | 40 | 24 win ( 8.8 / 45 pkts/s) | 16 win ( 5.0 / 21 pkts/s) | Temporary drop in traffic |
| **2** | 02:00 - 03:00 | 70 | 34 win (65.4 / 376 pkts/s) | 36 win (67.2 / 509 pkts/s) | **Major burst** (both clients $\ge 376$ pkts/s) |
| **3** | 03:00 - 04:00 | 80 | 45 win (38.9 / 373 pkts/s) | 35 win (27.6 / 261 pkts/s) | Sustained high throughput |
| **4** | 04:00 - 05:00 | 97 | 54 win (71.6 / 493 pkts/s) | 43 win (60.2 / 458 pkts/s) | **Peak volumetric burst** ($\approx 500$ pkts/s) |
| **5** | 05:00 - 06:00 | 82 | 45 win (20.2 / 133 pkts/s) | 37 win (11.4 / 44 pkts/s) | Quieting / moderate app traffic |
| **6** | 06:00 - 07:00 | 81 | 58 win (44.9 / 340 pkts/s) | 23 win ( 6.4 / 41 pkts/s) | Secondary burst on Client 1 |
| **7** | 07:00 - 08:00 | 53 | 49 win (27.2 / 112 pkts/s) | 4 win ( 2.2 / 4 pkts/s) | Client 2 goes idle; Client 1 active |
| **8** | 08:00 - 09:00 | 51 | 48 win (10.2 / 93 pkts/s) | 3 win ( 1.7 / 2 pkts/s) | Quiescent transition; Client 2 near silent |
| **9** | 09:00 - 09:58 | 36 | 34 win ( 5.2 / 26 pkts/s) | 2 win ( 1.0 / 1 pkts/s) | Low-rate idle baseline |

**Key Discrepancy**: The protocol intended quiescent idle in Minutes 0–3, browsing in Minutes 3–7, and a burst in Minutes 7:00–8:30. In reality, the largest volumetric bursts (376 to 509 pkts/s) occurred during **Minutes 2 and 4**, while Minutes 7 to 9 exhibited declining, relatively quiet traffic. Whether this was caused by early video playback or background cloud syncing cannot be verified without physical run logs.

---

## 4. Anomaly Attribution & Alert Analysis (123 Flagged Windows)

### Overall Attribution Breakdown:
- **Total Windows Evaluated**: 678
- **Total Dual Anomalies**: **123 (18.14%)**
- **Primary-Only Alerts (`ANOMALY_PRIMARY_BURST_OR_SIZE`)**: **92 windows (13.57%)**
- **Timing-Only Alerts (`ANOMALY_TIMING_JITTER`)**: **31 windows (4.57%)**
- **Dual Overlap (`ANOMALY_PRIMARY_AND_TIMING`)**: **0 windows (0.00%)**
- **Normal Inliers (`NORMAL_INLIER`)**: 390 windows (57.52%)
- **Normal Quiet Gated (`NORMAL_QUIET_TIMING_UNAVAILABLE`)**: 165 windows (24.34%)

### Per-Client Alert Distribution:
| Client Identifier | Total Windows | Dual Alerts | Primary Only | Timing Only | Both | Inlier Count |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Node_Client_1** | 445 | 90 (20.22%) | 67 (15.06%) | 23 (5.17%) | 0 (0.00%) | 355 (79.78%) |
| **Node_Client_2** | 233 | 33 (14.16%) | 25 (10.73%) | 8 (3.43%) | 0 (0.00%) | 200 (85.84%) |

### Alerts by Capture Time (Minute-by-Minute):
```
Minute 0 (00:00-01:00):  17 alerts (15 Primary,  2 Timing)  [C1: 15, C2:  2]
Minute 1 (01:00-02:00):   4 alerts ( 1 Primary,  3 Timing)  [C1:  2, C2:  2]
Minute 2 (02:00-03:00):  18 alerts (15 Primary,  3 Timing)  [C1: 11, C2:  7]
Minute 3 (03:00-04:00):  14 alerts (11 Primary,  3 Timing)  [C1:  9, C2:  5]
Minute 4 (04:00-05:00):  23 alerts (22 Primary,  1 Timing)  [C1: 12, C2: 11]  <-- Peak Primary Flags
Minute 5 (05:00-06:00):   7 alerts ( 3 Primary,  4 Timing)  [C1:  4, C2:  3]
Minute 6 (06:00-07:00):  14 alerts ( 9 Primary,  5 Timing)  [C1: 12, C2:  2]
Minute 7 (07:00-08:00):  20 alerts (13 Primary,  7 Timing)  [C1: 19, C2:  1]  <-- Peak Timing Flags
Minute 8 (08:00-09:00):   4 alerts ( 3 Primary,  1 Timing)  [C1:  4, C2:  0]
Minute 9 (09:00-09:58):   2 alerts ( 0 Primary,  2 Timing)  [C1:  2, C2:  0]
```
- **Primary Alerts** correlated directly with volumetric surges (peaking at 22 flags during Minute 4, and 0 flags during the quiet Minute 9).
- **Timing Alerts** remained distributed across the session (1 to 7 flags per minute), occurring when low-packet bursts experienced high jitter.

---

## 5. Statistical Comparison: Flagged vs. Unflagged Windows

| Metric | Unflagged Windows ($N=555$) | Primary-Only Alerts ($N=92$) | Timing-Only Alerts ($N=31$) | All Flagged Combined ($N=123$) |
| :--- | :---: | :---: | :---: | :---: |
| **Packet Rate (Mean $\pm$ Std)** | $17.81 \pm 23.77$ | $\mathbf{139.37 \pm 129.88}$ | $\mathbf{3.71 \pm 0.97}$ | $105.18 \pm 126.81$ |
| **Packet Rate Median (Min / Max)** | 8.0 (1.0 / 134.0) | **91.0 (1.0 / 509.0)** | **3.0 (3.0 / 6.0)** | 56.0 (1.0 / 509.0) |
| **Mean Packet Size (Mean $\pm$ Std)** | $240.26 \pm 194.49$ | $\mathbf{310.75 \pm 296.72}$ | $144.50 \pm 154.99$ | $268.85 \pm 277.19$ |
| **Packet Size Std (Mean $\pm$ Std)** | $228.65 \pm 220.31$ | $\mathbf{257.66 \pm 173.56}$ | $88.60 \pm 166.12$ | $215.05 \pm 186.25$ |
| **Mean IAT (Mean $\pm$ Std)** | $0.05 \pm 0.08$ | $0.01 \pm 0.01$ | $\mathbf{0.25 \pm 0.08}$ | $0.07 \pm 0.11$ |
| **IAT Std Dev (Mean $\pm$ Std)** | $0.05 \pm 0.05$ | $0.02 \pm 0.02$ | $\mathbf{0.27 \pm 0.14}$ | $0.09 \pm 0.13$ |
| **Primary Score (Mean $\pm$ Std)** | $+0.09 \pm 0.04$ | $\mathbf{-0.05 \pm 0.04}$ | $+0.10 \pm 0.03$ | $-0.01 \pm 0.08$ |
| **Timing Score (Mean $\pm$ Std)** | $+0.17 \pm 0.06$ | $+0.17 \pm 0.05$ | $\mathbf{-0.07 \pm 0.05}$ | $+0.11 \pm 0.11$ |

### Physical Interpretation:
1. **Primary Outliers ($N=92$)**: Characterized by massive volumetric rates (median 91.0 pkts/s, up to 509.0 pkts/s) and large frames (up to 1157.5 B). Their timing scores were strongly inlier (+0.17), because high-rate floods have naturally uniform, tight IATs.
2. **Timing Outliers ($N=31$)**: Characterized by low packet counts (mean 3.71 pkts/s) with extreme intra-window jitter (mean $\sigma_{\text{IAT}} = 0.27$s, max 0.59s). Their primary scores were strongly inlier (+0.10), proving that volumetric detectors alone are completely blind to timing jitter.

### Representative Examples of Strongest Alerts:

#### Top 3 Primary Volumetric Alerts:
1. **Window 172 (`Node_Client_1`, `09:33:01 UTC`)**:
   - `packet_rate`: 487.0 pkts/s | `mean_packet_size`: 67.9 B | `score_primary`: **-0.125691** (Strong Volumetric ACK/Push Flood)
2. **Window 170 (`Node_Client_1`, `09:32:59 UTC`)**:
   - `packet_rate`: 493.0 pkts/s | `mean_packet_size`: 95.0 B | `score_primary`: **-0.123265**
3. **Window 176 (`Node_Client_1`, `09:33:05 UTC`)**:
   - `packet_rate`: 272.0 pkts/s | `mean_packet_size`: 105.5 B | `score_primary`: **-0.123265**

#### Top 3 Timing Jitter Alerts:
1. **Window 335 (`Node_Client_1`, `09:36:11 UTC`)**:
   - `packet_count`: 3 | `mean_IAT`: 0.449755 s | `IAT_std`: **0.592197 s** | `score_timing`: **-0.144239**
   - *Physical Mechanism*: Packets 1 and 2 arrived within 1 ms, while packet 3 arrived 899 ms later, creating extreme dispersion.
2. **Window 356 (`Node_Client_1`, `09:36:36 UTC`)**:
   - `packet_count`: 3 | `mean_IAT`: 0.369205 s | `IAT_std`: **0.522133 s** | `score_timing`: **-0.144239**
3. **Window 207 (`Node_Client_2`, `09:35:05 UTC`)**:
   - `packet_count`: 3 | `mean_IAT`: 0.316392 s | `IAT_std`: **0.447444 s** | `score_timing`: **-0.144239**

---

## 6. Physical Sensor Telemetry Audit

### Sensor Stream Coverage:
- **Sensor Database**: `data/telemetry_test/session3_sensor_telemetry.db` (510 records).
- **Sensor Logging Window**: `2026-10-14 09:22:57` to `2026-10-14 09:39:55 UTC` (Uptime span: 1018.0 seconds).
- **Coverage**: The sensor listener was started 5.8 minutes prior to PCAP capture and stopped 1.2 minutes after, completely enveloping the 598-second network session.

### Sensor Data Quality:
1. **AM312 PIR Motion Sensor (Dynamic Restored)**:
   - `motion_detected = 0`: **363 records (71.18%)**
   - `motion_detected = 1`: **147 records (28.82%)**
   - *Audit*: Demonstrates successful alternating periods of physical movement and rest. The 100% stuck-high failure observed in Session 2 did not recur.
2. **DHT11 Temperature & Relative Humidity**:
   - Valid readings: **510 out of 510 (100.0%)** (zero failed reads or checksum errors).
   - Temperature: Fixed at **30.2°C** across all records.
   - Relative Humidity: Fixed at **92.0%** across all records.
   - *Audit*: While null-safety was 100% successful, the static values indicate high sensor quantization and lack of thermal gradient in the test environment.

### Alignment Rate & Match Plausibility:
- **Alignment Tolerance**: $\pm 2.0$ seconds.
- **Matched Windows**: **678 out of 678 (100.0%)**.
- **Time Delta**: Exactly **0.500 seconds** across all 678 windows.
  - *Mathematical Explanation*: Network window centers are defined as $T + 0.5$ (e.g., `09:28:45.500`), while SQLite sensor timestamps are integer seconds $S$ (e.g., `09:28:45.000` or `09:28:46.000`). With sensor sampling every ~2.0 seconds, every half-second network center is equidistant ($|T + 0.5 - S| = 0.5$ s) from an integer sensor second.
- **Reading Re-use / Duplication**:
  - 279 unique sensor readings were matched to the 678 network windows.
  - 223 sensor records matched to multiple windows (maximum 4 windows per sensor record: 2 concurrent clients across 2 consecutive seconds). This is physically valid given the 2.0s sensor sampling interval vs. 1.0s network windowing.

---

## 7. Report Attribution Reconciliation & Apparent Inconsistency Audit

In [`session3_10min_session_report.md`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/data/processed/experimental_time_windows/long_baseline_validation/session3_10min_session_report.md), an apparent numerical contradiction exists between Section 1 and Section 2:
- Section 1 reports: `Unavailable Timing Windows (N < 3): 168 (24.78%)`
- Section 2 reports: `NORMAL_QUIET_TIMING_UNAVAILABLE: 165 windows (24.34%)`

### Reconciliation & Root Cause:
This is **not a calculation error**, but an **attribution taxonomy distinction**:
- In the Dual Detector decision logic, a window with $N < 3$ is only labeled `NORMAL_QUIET_TIMING_UNAVAILABLE` if it is an **inlier for the Primary Detector** (`pred_primary == 1`).
- If a low-packet window is flagged as an anomaly by the Primary Detector (`pred_primary == -1`), it is categorized under `ANOMALY_PRIMARY_BURST_OR_SIZE`.
- Querying the 168 windows where $N < 3$ in `session3_10min_dual_detector_predictions.csv` reveals the exact 3 windows accounting for the difference:
  1. **Window 147 (`Node_Client_1`, `09:32:31 UTC`)**: $N=2$, packet rate = 2.0, mean packet size = **1157.5 B** (`score_primary = -0.105989`, flagged).
  2. **Window 144 (`Node_Client_2`, `09:33:13 UTC`)**: $N=2$, packet rate = 2.0, mean packet size = **893.0 B**, packet size std = **793.4 B** (`score_primary = -0.064323`, flagged).
  3. **Window 174 (`Node_Client_2`, `09:33:54 UTC`)**: $N=1$, packet rate = 1.0, mean packet size = **1115.0 B** (`score_primary = -0.084384`, flagged).

Because these 3 windows contained abnormally large frames (893 to 1158 bytes) compared to Session 1 normal traffic (~150-350 bytes), the Primary Detector correctly flagged them as payload size outliers. This confirms that the Dual Detector's volumetric/size protection remains active even when timing statistics are mathematically unavailable.

---

## 8. Limitations & Methodological Boundaries

1. **Statistical Outliers $\neq$ Cyberattacks**:
   - The 123 flagged windows represent deviations from the Session 1 baseline density envelope.
   - Because Session 3 consisted of ordinary mobile browsing, background traffic, and video streaming without attacks, these alerts reflect benign operational drift and normal multi-flow bursts, **not confirmed security incidents**.
2. **Session 1 Density Ceiling**:
   - Session 1 training data was short (~70s) and lacked high-speed 1080p video streaming. Applying its frozen threshold to 10 minutes of active multi-app mobile usage yielded an 18.14% outlier rate.
3. **No Retraining Conducted**:
   - In accordance with safety rules, the Dual Detector was evaluated in frozen mode without refitting or adjusting contamination thresholds.

---

## 9. Recommendation for Session 4

### Can Session 4 Proceed?
**YES. Session 4 can proceed.** There are no blocking hardware or capture pipeline failures:
- Wireshark cleanly captured the full 600-second session.
- Both mobile devices maintained fixed MAC addresses without MAC randomization.
- The ESP32 sensor node maintained continuous serial telemetry with 0% dropped packets and dynamic PIR states.

### Operational Improvement Required for Session 4:
To enable rigorous correlation between physical user activities and detector flags, the operator **must use a physical run sheet with a synchronized stopwatch**:
1. Note the exact clock time (HH:MM:SS) when the video streaming burst begins.
2. Note the exact clock time when video streaming stops.
3. Record whether any background app installations or file downloads occurred.
4. Keep the activity schedule synchronized with the 10-minute protocol timeline (idle $\rightarrow$ browsing $\rightarrow$ burst $\rightarrow$ idle).

---

## 10. System Preservation Audit

- **Production Database**: [`data/iot_anomaly.db`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/data/iot_anomaly.db) was **not accessed or modified**.
- **Production Dashboard**: [`src/dashboard.py`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/dashboard.py) was **not modified**.
- **Production Models, Firmware, and Capture Datasets**: Completely preserved.
- **Previous Experimental Outputs**: Unaltered under `data/processed/experimental_time_windows/`.
- **New Analysis File**: Saved to [`data/processed/experimental_time_windows/long_baseline_validation/session3_alert_investigation.md`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/data/processed/experimental_time_windows/long_baseline_validation/session3_alert_investigation.md) without overwriting any existing artifacts.
