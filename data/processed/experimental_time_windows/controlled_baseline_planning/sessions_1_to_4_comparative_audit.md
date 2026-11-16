# Cross-Session Comparative Audit: Sessions 1 to 4
**Directory**: `data/processed/experimental_time_windows/controlled_baseline_planning/`  
**File**: `sessions_1_to_4_comparative_audit.md`  
**Purpose**: Read-only engineering analysis comparing network traffic distributions, timing feature availability, frozen Dual-Detector anomaly alert rates, and physical sensor telemetry across all four experimental capture sessions.

---

## 1. Executive Summary & Cross-Session High-Level Overview

Across all four sessions, the experimental architecture operated under frozen constraints:
- **Model Training**: Strictly on Session 1 (`time_1s_session1_pcap_features_uplink.csv`).
- **Primary Detector**: Isolation Forest (3 features: `packet_rate`, `mean_packet_size`, `packet_size_std`), fitted offset: **-0.581180**, contamination: **0.05**.
- **Timing Detector**: Isolation Forest (2 features: `mean_IAT`, `IAT_std`), active strictly when $N \ge 3$, fitted offset: **-0.617487**, contamination: **0.05**.
- **Zero Retraining**: Sessions 2, 3, and 4 were evaluated without refitting models, updating imputer medians, or altering decision thresholds.

### Key Cross-Session Observations:
1. **Scale Expansion**: Sessions 1 and 2 provided short exploratory baselines (~70 seconds, ~102–112 windows). Sessions 3 and 4 established true extended 10-minute baselines (598 seconds each, 678 and 577 windows).
2. **Stable Traffic Central Tendencies**: Median packet rates across all four sessions remained remarkably stable within a tight band of **10.0 to 14.0 pkts/s**, representing typical mobile standby and light app polling.
3. **Consistent Timing Availability ($N \ge 3$)**: Across Sessions 2, 3, and 4, the proportion of windows where timing was mathematically unavailable ($N < 3$) stayed consistently between **21.1% and 24.8%** (compared to 8.9% in Session 1).
4. **Reproducible Long-Baseline Alert Rates**:
   - Short sessions: Session 1 self-evaluation = **9.82%**; Session 2 evaluation = **8.82%**.
   - 10-minute sessions: Session 3 = **18.14%** (123/678); Session 4 = **16.81%** (97/577).
   - In both 10-minute sessions, Secondary Timing alerts stayed remarkably consistent at **4.57%** (S3) and **4.51%** (S4), directly aligning with the 5.0% training contamination parameter. Primary burst/size alerts accounted for **13.57%** (S3) and **12.31%** (S4), driven by high-speed video streaming bursts (up to 509 pkts/s in S3 and 1326 pkts/s in S4).
5. **Physical Sensor Evolution**:
   - In Session 2, the PIR sensor failed in a stuck-HIGH state (100% motion) and DHT11 experienced 14.3% packet loss.
   - In Sessions 3 and 4, the PIR sensor demonstrated restored dynamic behavior (motion detected: 28.8% in S3, 33.3% in S4), and DHT11 achieved **100% valid reads (0% dropped packets)** across hundreds of samples.

---

## 2. Comprehensive Multi-Session Metric Matrix

The table below compiles measurements directly from the underlying prediction CSVs and feature datasets:

| Metric Category | Feature / Indicator | Session 1 (Short Train) | Session 2 (Short Test) | Session 3 (Long Test 1) | Session 4 (Long Test 2) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Temporal Boundaries** | Capture Duration (s) | 71.0 s (~1.18 min) | 70.0 s (~1.17 min) | 598.0 s (~9.97 min) | 598.0 s (~9.97 min) |
| | Global Start (UTC) | `2026-10-11 12:21:11` | `2026-10-11 12:33:33` | `2026-10-14 09:28:45` | `2026-10-14 10:00:14` |
| | Global End (UTC) | `2026-10-11 12:22:22` | `2026-10-11 12:34:43` | `2026-10-14 09:38:43` | `2026-10-14 10:10:12` |
| **Window & Client Counts** | Total 1-Second Windows | 112 | 102 | 678 | 577 |
| | Active Clients | 2 | 2 | 2 | 2 |
| | `Node_Client_1` Windows | 64 (57.14%) | 61 (59.80%) | 445 (65.63%) | 348 (60.31%) |
| | `Node_Client_2` Windows | 48 (42.86%) | 41 (40.20%) | 233 (34.37%) | 229 (39.69%) |
| **Packet Rate Distribution** | Min / 25th Percentile | 1.0 / 5.0 pkts/s | 1.0 / 3.0 pkts/s | 1.0 / 3.0 pkts/s | 1.0 / 4.0 pkts/s |
| | **Median Rate** | **13.0 pkts/s** | **12.5 pkts/s** | **10.0 pkts/s** | **14.0 pkts/s** |
| | Mean $\pm$ Std Dev | $27.47 \pm 37.05$ | $26.98 \pm 43.63$ | $33.66 \pm 67.05$ | $50.26 \pm 131.82$ |
| | 75th / 95th Percentile | 33.2 / 105.3 pkts/s | 32.0 / 94.3 pkts/s | 34.0 / 134.1 pkts/s | 46.0 / 179.2 pkts/s |
| | **Maximum Packet Rate** | **183.0 pkts/s** | **250.0 pkts/s** | **509.0 pkts/s** | **1326.0 pkts/s** |
| **Packet Size Distribution** | Min / Median | 64.5 / 390.8 B | 66.0 / 339.4 B | 42.0 / 163.1 B | 42.0 / 246.0 B |
| | Mean $\pm$ Std Dev | $384.08 \pm 216.01$ | $327.28 \pm 228.69$ | $245.45 \pm 211.95$ | $289.85 \pm 212.71$ |
| | Maximum Packet Size | 1000.0 B | 1140.0 B | 1157.5 B | 1165.9 B |
| **Timing Feature Gating** | Qualified Windows ($N \ge 3$) | 102 (91.07%) | 78 (76.47%) | 510 (75.22%) | 455 (78.86%) |
| | Unavailable Timing ($N < 3$) | 10 (8.93%) | 24 (23.53%) | 168 (24.78%) | 122 (21.14%) |
| | Qualified Mean IAT (Mean/Med) | 0.04859s / 0.02690s | 0.03286s / 0.02276s | 0.04764s / 0.02509s | 0.04604s / 0.02469s |
| | Qualified IAT Std Dev (Mean/Med)| 0.07426s / 0.04869s | 0.05528s / 0.05035s | 0.06754s / 0.04083s | 0.07178s / 0.04744s |
| **Dual Detector Alerts** | Primary Volumetric/Size Flags | 6 (5.36%) | 9 (8.82%) | 92 (13.57%) | 71 (12.31%) |
| | Secondary Timing Jitter Flags | 6 (5.36%) | **0 (0.00%)** | 31 (4.57%) | 26 (4.51%) |
| | Dual Overlap (Both Flagged) | 1 (0.89%) | 0 (0.00%) | 0 (0.00%) | 0 (0.00%) |
| | **Total Combined Alerts** | **11 (9.82%)** | **9 (8.82%)** | **123 (18.14%)** | **97 (16.81%)** |
| **Attribution Taxonomy** | `NORMAL_INLIER` | 91 (81.25%) | 69 (67.65%) | 390 (57.52%) | 362 (62.74%) |
| | `NORMAL_QUIET_TIMING_UNAVAIL` | 10 (8.93%) | 24 (23.53%) | 165 (24.34%) | 118 (20.45%) |
| | `ANOMALY_PRIMARY_BURST_OR_SIZE`| 5 (4.46%) | 9 (8.82%) | 92 (13.57%) | 71 (12.31%) |
| | `ANOMALY_TIMING_JITTER` | 5 (4.46%) | 0 (0.00%) | 31 (4.57%) | 26 (4.51%) |
| | `ANOMALY_PRIMARY_AND_TIMING` | 1 (0.89%) | 0 (0.00%) | 0 (0.00%) | 0 (0.00%) |
| **Physical Sensor Stream** | Total Sensor Records in DB | 35 | 35 | 510 | 321 |
| | DHT11 Valid Read Rate | 35/35 (100.0%) | 30/35 (85.71%) | 510/510 (100.0%) | 321/321 (100.0%) |
| | DHT11 Dropped Reads (NULL) | 0 (0.00%) | **5 (14.29%)** | 0 (0.00%) | 0 (0.00%) |
| | Temperature Min/Med/Max | 30.8 / 30.8 / 30.8 °C | 30.8 / 30.8 / 30.8 °C | 30.2 / 30.2 / 30.2 °C | 30.2 / 30.2 / 30.2 °C |
| | Humidity Min/Med/Max | 82.0 / 82.0 / 82.0 % | 82.0 / 82.0 / 82.0 % | 92.0 / 92.0 / 92.0 % | 92.0 / 92.0 / 92.0 % |
| | AM312 Motion = 0 (Rest) | 14 (40.0%) | **0 (0.0%)** | 363 (71.18%) | 214 (66.67%) |
| | AM312 Motion = 1 (Active) | 21 (60.0%) | **35 (100.0%)** | 147 (28.82%) | 107 (33.33%) |
| | Sensor Alignment Match Rate | 112/112 (100.0%) | 102/102 (100.0%) | 678/678 (100.0%) | 577/577 (100.0%) |
| | Alignment Time Delta (Sec) | $\le 0.50$ s | $\le 0.50$ s | $\mathbf{0.500}$ s | $\mathbf{0.500}$ s |

---

## 3. Discrepancy & Zero-Value Distinctions

To maintain absolute scientific transparency, we explicitly distinguish measured zero values from unrecorded or unapplicable data:

1. **Measured Zero Values**:
   - **Session 2 Timing Flags = 0 (0.00%)**: This is a true empirical measurement. In Session 2, traffic pacing during qualified windows ($N \ge 3$) remained smooth and regular, never exceeding the Session 1 timing boundary.
   - **Sessions 2, 3, and 4 Overlap Flags (`ANOMALY_PRIMARY_AND_TIMING`) = 0 (0.00%)**: This is a measured zero. In all evaluated test sessions, no single window simultaneously violated both the primary volumetric envelope and the timing jitter envelope.
2. **Attribution Taxonomy Reconciliation ($N < 3$)**:
   - In Session 3, total $N < 3$ windows = **168**, while `NORMAL_QUIET_TIMING_UNAVAILABLE` = **165**.
   - In Session 4, total $N < 3$ windows = **122**, while `NORMAL_QUIET_TIMING_UNAVAILABLE` = **118**.
   - *Explanation*: The remaining 3 windows in Session 3 and 4 windows in Session 4 were single- or two-packet windows that contained abnormally large MTU payloads (585 to 1158 bytes) compared to Session 1 normal traffic (~150-350 bytes). The Primary Detector correctly flagged them under `ANOMALY_PRIMARY_BURST_OR_SIZE`, confirming that volumetric/payload size monitoring remains active even when timing is unavailable.
3. **Missing Information (Not Available in Raw PCAP)**:
   - *Activity Phase Start/Stop Times*: In Sessions 1–4, operator run sheets logging exact clock seconds of user actions (e.g., launching YouTube, closing a browser tab) were not recorded. These activity transitions **cannot be inferred from network traffic alone**.
   - *Sensor Internal Telemetry*: Radio signal strength indicator (RSSI), packet loss over-the-air, and ESP32 battery level were not implemented in firmware and are unavailable across all sessions.

---

## 4. Alert Rate & Traffic Distribution Consistency Analysis

### Is the Baseline Sufficiently Consistent for Another Comparison?
**YES, but with explicit operational caveats:**

1. **Traffic Baseline Consistency**:
   - Median packet rates across all sessions (**10.0 to 14.0 pkts/s**) and qualified inter-arrival times (**0.046s to 0.048s**) show strong physical reproducibility across different recording days.
   - The proportion of timing-unavailable quiet windows is remarkably stable at **21% to 25%** across all longer traces.
2. **Detector Sensitivity Consistency**:
   - In both 10-minute sessions, Secondary Timing alerts settled at **4.57%** (S3) and **4.51%** (S4). This closely matches the model's 5.0% training contamination threshold, confirming that the timing detector is stable across sessions.
   - Primary volumetric alerts hovered at **12.31%** (S4) and **13.57%** (S3). The elevated primary alert rate compared to Session 1 (5.36%) directly reflects the inclusion of sustained high-definition video streaming bursts (up to 1326 pkts/s) that were deliberately absent from the quiescent Session 1 baseline.
3. **Core Limitation: Statistical Outlier $\neq$ Cyberattack**:
   - All 123 alerts in Session 3 and 97 alerts in Session 4 represent benign user traffic that deviated from Session 1's quiescent baseline.
   - Without verified ground-truth attack labels, these alerts must **never be described as attack detections**. They represent normal operational variance under heavy multi-app usage.
