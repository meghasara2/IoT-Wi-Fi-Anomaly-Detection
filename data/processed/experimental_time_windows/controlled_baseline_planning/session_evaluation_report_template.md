# Controlled Baseline Evaluation Report Template
**Template File**: `data/processed/experimental_time_windows/controlled_baseline_planning/session_evaluation_report_template.md`  
**Purpose**: Standardized reporting template for evaluating the next controlled baseline capture session against the frozen Dual-Detector architecture.

---

# Baseline Evaluation Report: [Session Name, e.g., session5_controlled_10min]
**Evaluated Windows**: [Total Window Count, e.g., 600]  
**Capture Duration**: [Measured Duration, e.g., 598.0 seconds]  
**Global Capture Timestamps**: `YYYY-MM-DD HH:MM:SS UTC` to `YYYY-MM-DD HH:MM:SS UTC`  
**Frozen Model Baseline**: Trained on Session 1 (`time_1s_session1_pcap_features_uplink.csv`)  
- **Primary Detector Offset**: `-0.581180` (Contamination: 0.05)  
- **Timing Detector Offset**: `-0.617487` (Contamination: 0.05, Gated on $N \ge 3$)  

---

## 1. Operator Run Sheet & Activity Phase Alignment

| Planned Phase | Description | Planned Duration | Actual Start (UTC) | Actual End (UTC) | Measured Windows | Window % |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Phase 1** | Quiescent Background Standby | 00:00 - 02:30 (150s) | `HH:MM:SS` | `HH:MM:SS` | [ ___ ] | [ __% ] |
| **Phase 2** | Light / Ordinary Browsing & Apps | 02:30 - 05:30 (180s) | `HH:MM:SS` | `HH:MM:SS` | [ ___ ] | [ __% ] |
| **Phase 3** | Sustained Video / Traffic Burst | 05:30 - 08:00 (150s) | `HH:MM:SS` | `HH:MM:SS` | [ ___ ] | [ __% ] |
| **Phase 4** | Return to Quiescent Baseline | 08:00 - 10:00 (120s) | `HH:MM:SS` | `HH:MM:SS` | [ ___ ] | [ __% ] |

*Operator Notes on Run-Sheet Synchronization*: [Insert notes on whether mobile devices entered sleep mode, unexpected push notifications, or manual clock timing discrepancies].

---

## 2. Traffic Distribution & Timing Availability ($N \ge 3$ vs. $N < 3$)

| Metric Category | Measured Value | Historical S3 Reference | Historical S4 Reference |
| :--- | :---: | :---: | :---: |
| **Total 1-Second Windows** | [ ___ ] | 678 | 577 |
| **Node_Client_1 Active Windows** | [ ___ ] ([ __% ]) | 445 (65.63%) | 348 (60.31%) |
| **Node_Client_2 Active Windows** | [ ___ ] ([ __% ]) | 233 (34.37%) | 229 (39.69%) |
| **Packet Rate Median** | [ ___ ] pkts/s | 10.0 pkts/s | 14.0 pkts/s |
| **Packet Rate Mean $\pm$ Std Dev** | [ ___ $\pm$ ___ ] pkts/s | $33.66 \pm 67.05$ pkts/s | $50.26 \pm 131.82$ pkts/s |
| **Maximum Observed Packet Rate** | [ ___ ] pkts/s | 509.0 pkts/s | 1326.0 pkts/s |
| **Qualified Timing Windows ($N \ge 3$)** | [ ___ ] ([ __% ]) | 510 (75.22%) | 455 (78.86%) |
| **Unavailable Timing Windows ($N < 3$)** | [ ___ ] ([ __% ]) | 168 (24.78%) | 122 (21.14%) |
| **Qualified Mean IAT (Mean / Med)** | [ ___ / ___ ] s | 0.04764s / 0.02509s | 0.04604s / 0.02469s |

---

## 3. Phase-by-Phase Anomaly Alert Distribution

Comparing alert generation across the physically recorded activity phases:

| Phase | Phase Activity Description | Windows in Phase | Primary Flags | Timing Flags | Dual Flags Combined | Phase Alert Rate (%) |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| **Phase 1** | Quiescent Standby | [ ___ ] | [ ___ ] | [ ___ ] | [ ___ ] | [ __% ] |
| **Phase 2** | Light Browsing & Apps | [ ___ ] | [ ___ ] | [ ___ ] | [ ___ ] | [ __% ] |
| **Phase 3** | Sustained Video Burst | [ ___ ] | [ ___ ] | [ ___ ] | [ ___ ] | [ __% ] |
| **Phase 4** | Quiescent Recovery | [ ___ ] | [ ___ ] | [ ___ ] | [ ___ ] | [ __% ] |
| **Total** | Full 10-Minute Session | [ ___ ] | [ ___ ] | [ ___ ] | [ ___ ] | [ __% ] |

### Key Phase Correlation Questions:
1. Did Phase 1 (quiescent standby) achieve low alert rates without false alarms on $N < 3$ heartbeats?
2. Did Phase 2 (browsing) remain mostly within the nominal inlier envelope?
3. Did Phase 3 (video burst) account for the majority of Primary Volumetric alerts?
4. Did Phase 4 (recovery) rapidly drop back to baseline without lingering false alarms?

---

## 4. Anomaly Attribution Breakdown

| Attribution Category | Count | Percentage | Historical S3 Rate | Historical S4 Rate | Physical Meaning |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **`ANOMALY_PRIMARY_BURST_OR_SIZE`** | [ ___ ] | [ __% ] | 13.57% (92) | 12.31% (71) | High packet rate or large payload frame |
| **`ANOMALY_TIMING_JITTER`** | [ ___ ] | [ __% ] | 4.57% (31) | 4.51% (26) | Low-rate burst with high intra-window IAT std dev |
| **`ANOMALY_PRIMARY_AND_TIMING`** | [ ___ ] | [ __% ] | 0.00% (0) | 0.00% (0) | Simultaneous primary and timing outlier |
| **`NORMAL_INLIER`** | [ ___ ] | [ __% ] | 57.52% (390) | 62.74% (362) | Within nominal Session 1 baseline density |
| **`NORMAL_QUIET_TIMING_UNAVAIL`** | [ ___ ] | [ __% ] | 24.34% (165) | 20.45% (118) | Single/double packet heartbeat ($N < 3$, inlier) |

*Attribution Reconciliation Note*: Total windows with $N < 3$ should equal `NORMAL_QUIET_TIMING_UNAVAILABLE` plus any low-packet windows flagged by the Primary Detector under `ANOMALY_PRIMARY_BURST_OR_SIZE` due to large frame sizes.

---

## 5. Physical Sensor Telemetry Audit

- **Sensor Database**: `data/telemetry_test/[session_name]_sensor_telemetry.db`  
- **Sensor Records Logged**: [ ___ ] records spanning [ ___ ] seconds.  
- **Coverage Check**: Confirm whether sensor listener started before PCAP capture and ended after PCAP capture: [ YES / NO ].  
- **DHT11 Reliability**:
  - Valid Reads: [ ___ ] out of [ ___ ] ([ __% ] valid).
  - Dropped Reads (NULL): [ ___ ] reads.
  - Temperature Min / Med / Max: [ ___ / ___ / ___ ] °C.
  - Humidity Min / Med / Max: [ ___ / ___ / ___ ] %.
- **AM312 PIR Motion Sensor**:
  - Motion = 0 (Rest): [ ___ ] records ([ __% ]).
  - Motion = 1 (Motion Detected): [ ___ ] records ([ __% ]).
  - Dynamic Operation Confirmed: [ YES / NO ] (Verify not stuck on 100% or 0%).
- **Alignment Metrics**:
  - Windows Matched within $\pm 2.0$s tolerance: [ ___ ] out of [ ___ ] ([ 100.0% ]).
  - Time Delta: [ $\le 0.50$ s ].

---

## 6. Scientific Notice & Interpretation Boundaries

> [!CAUTION]
> **CRITICAL SCIENTIFIC DISCLAIMER**:
> 1. Anomaly alerts reported above are **statistical deviations from the Session 1 baseline density envelope**.
> 2. In the absence of confirmed attack vectors, these alerts represent benign operational shifts (e.g., streaming high-definition video or bursty mobile operating system updates), **NOT verified cyberattacks**.
> 3. The Dual Detector was evaluated in **frozen mode** without retraining, parameter refitting, or contamination threshold adjustments.
