# Experimental Dual-Detector Architecture Benchmark Report
**Generated**: Offline Experimental Pipeline
**Folder**: `data/processed/experimental_time_windows/dual_detector_experiment/`
**Target Scope**: 1-Second Time Window Network Traffic Anomaly Detection

---

## 1. Executive Summary & Core Findings

This experiment designed, trained, and evaluated an offline **dual-detector architecture** aimed at overcoming the key failure modes identified in previous single-model benchmarks:
1. **Primary Detector**: Isolation Forest (3 features: `packet_rate`, `mean_packet_size`, `packet_size_std`).
2. **Secondary Timing Jitter Detector**: Isolation Forest (2 features: `mean_IAT`, `IAT_std`), activated strictly when packet count N >= 3.
3. **Combined Decision Logic**: Flags an anomaly if Primary flags OR (Secondary is active AND Secondary flags). Windows with N < 3 are handled gracefully without false alarms.

### Key Benchmark Takeaways:
- **Synthetic Benchmark Metrics (Controlled Profiles Only)**:
  - **Primary (3-feature)**: F1 = 0.8000 (Precision: 1.0000, Recall: 0.6667). Missed erratic timing jitter (0% recall on timing).
  - **Timing-only (gated)**: F1 = 0.5000 (Precision: 1.0000, Recall: 0.3333). Missed volumetric bursts and jumbo frames.
  - **Existing 5-feature (median imputed + indicators)**: F1 = 0.4242 (Precision: 0.5385, Recall: 0.3500). Suffered massive sensitivity collapse (20% on bursts, 0% on jumbo frames) and 18 false positives on quiet single-packet windows.
  - **Dual Combined Detector**: **F1 = 1.0000 (Precision: 1.0000, Recall: 1.0000)**. Captured 100% of bursts, jumbo frames, and timing jitter while yielding **0 false positives** on normal and quiet single-packet windows.
- **Session 2 Generalization**:
  - The dual detector flagged **9 out of 102 windows (8.82%)** on Session 2, driven entirely by primary volumetric/size outliers (9 windows, 8.82%).
  - The timing detector was active for 78 windows (76.47%) and flagged 0 outliers (normal traffic maintained nominal pacing).
  - For the 24 windows (23.53%) where N < 3, timing was marked `UNAVAILABLE_N_LT_3` and **zero false positives** were generated.

> **CRITICAL SCIENTIFIC NOTICE**: Precision, Recall, and F1 values are strictly **synthetic benchmark metrics** evaluated against controlled synthetic scenarios. They quantify detector sensitivities to isolated feature anomalies and do NOT represent production cyberattack detection rates.

---

## 2. Gating Methodology & Mathematical Rationale

### Minimum Packet Count Threshold: N_min = 3
In a discrete 1-second time window:
- **N = 0**: Empty window.
- **N = 1**: Single packet. Inter-arrival time is nonexistent. `mean_IAT` is undefined (NaN) and `IAT_std` is mathematically undefined.
- **N = 2**: Exactly 1 interval (dt1 = t2 - t1). Sample standard deviation with Bessel's correction (ddof=1) has M - 1 = 2 - 1 - 1 = 0 degrees of freedom. Hence, sample variance is mathematically undefined or artificially zero, providing no measure of dispersion.
- **N >= 3**: At least 2 inter-arrival intervals (M >= 2). Degrees of freedom M - 1 >= 1. Both sample mean mu_IAT and sample standard deviation sigma_IAT (ddof=1) are mathematically sound and physically meaningful.

### Handling Unavailable Timing:
When N < 3:
- `timing_status` is explicitly set to `UNAVAILABLE_N_LT_3`.
- `score_timing` is assigned `NaN`.
- `pred_timing` defaults to `+1` (inlier / not flagged).
- Combined decision delegates exclusively to the Primary Detector.

---

## 3. Training & Preprocessing Baseline (Session 1 Only)

All estimators, thresholds, and imputers were fitted **solely on Session 1** (`time_1s_session1_pcap_features_uplink.csv`). No data from Session 2 or synthetic scenarios was used during training.

| Component | Training Scope | Feature Set | Samples Fitted | Fitted Offset | Contamination |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **Primary Detector** | Session 1 All | `packet_rate`, `mean_packet_size`, `packet_size_std` | 112 | -0.581180 | 0.05 |
| **Timing Detector** | Session 1 N >= 3 | `mean_IAT`, `IAT_std` | 102 | -0.617487 | 0.05 |
| **Timing Imputer** | Session 1 N >= 3 | `mean_IAT` (med=0.026903), `IAT_std` (med=0.048694) | 102 | N/A | N/A |

*Note: In Session 1 training, 10 windows had N < 3 (N=1: 7 windows, N=2: 3 windows) and were safely excluded from timing model training.*

---

## 4. Synthetic Scenario Architecture Comparison

Performance across all 130 synthetic test scenario windows:

### Aggregate Benchmark Metrics:
| Architecture | TP | FP | TN | FN | Synthetic Precision | Synthetic Recall | Synthetic F1 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Primary (3-feature)** | 40 | 0 | 70 | 20 | 1.0000 | 0.6667 | 0.8000 |
| **Timing (gated N>=3)** | 20 | 0 | 70 | 40 | 1.0000 | 0.3333 | 0.5000 |
| **Existing 5-feature** | 21 | 18 | 52 | 39 | 0.5385 | 0.3500 | 0.4242 |
| **Dual Combined** | **60** | **0** | **70** | **0** | **1.0000** | **1.0000** | **1.0000** |

### Per-Scenario Flagged Counts (Flagged / Total):

| Scenario | Ground Truth | Primary (3F) | Timing-only | 5-Feature | Dual Combined |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `erratic_iat_dispersion` | Anomaly (1) | 0/20 (0.0%) | 20/20 (100.0%) | 17/20 (85.0%) | **20/20 (100.0%)** |
| `high_rate_burst` | Anomaly (1) | 20/20 (100.0%) | 0/20 (0.0%) | 4/20 (20.0%) | **20/20 (100.0%)** |
| `jumbo_payload_extreme` | Anomaly (1) | 20/20 (100.0%) | 0/20 (0.0%) | 0/20 (0.0%) | **20/20 (100.0%)** |
| `normal_like` | Normal (0) | 0/50 (0.0%) | 0/50 (0.0%) | 0/50 (0.0%) | **0/50 (0.0%)** |
| `single_packet_quiescent` | Normal (0) | 0/20 (0.0%) | 0/20 (0.0%) | 18/20 (90.0%) | **0/20 (0.0%)** |

---

## 5. Evaluation on Session 2 Real Capture Data

Evaluating Session 2 (`time_1s_pcap_features_uplink.csv`, N = 102) using the unchanged Session 1-fitted dual detector:

- **Total Session 2 Windows**: 102
- **Timing Active (N >= 3)**: 78 windows (76.47%)
- **Timing Unavailable (N < 3)**: 24 windows (23.53%) (N=1: 16, N=2: 8)
- **Primary Outliers Flagged**: 9 windows (8.82%)
- **Timing Outliers Flagged**: 0 windows (0.00%)
- **Dual Combined Outliers Flagged**: 9 windows (8.82%)

All 9 outliers were flagged exclusively by the Primary Detector (unusual packet rates and sizes during transient multi-flow activity). Because normal Session 2 traffic maintained stable inter-arrival pacing, the Timing Detector raised zero alarms on qualified traffic. Crucially, the 24 quiet windows with N < 3 generated **zero false alarms**.

---

## 6. Architecture Trade-Offs & Production Recommendations

### Advantages of the Dual-Detector:
1. **Resolves the Missing-Data Trap**: By gating timing analysis to N >= 3, the model completely eliminates false alarms on single-packet quiet heartbeats without needing artificial imputation (1.0s) or indicator penalty features.
2. **Preserves Volumetric & Payload Sensitivity**: Primary 3-feature detector isolates severe volumetric floods (100%) and jumbo MTU frame anomalies (100%) without feature space dilution.
3. **Specialized Jitter Detection**: Secondary timing detector catches 100% of severe inter-arrival timing irregularities when packet counts support mathematical variance.
4. **Transparent Anomaly Attribution**: The architecture explicitly categorizes flagged windows into `ANOMALY_PRIMARY_BURST_OR_SIZE`, `ANOMALY_TIMING_JITTER`, or `ANOMALY_PRIMARY_AND_TIMING`.

### Empirical Trade-Offs & Risks:
1. **Dual Hyperparameter Maintenance**: Both detectors require contamination tuning. While contamination=0.05 worked stably across Session 1, different traffic environments may require asymmetric sensitivity settings.
2. **Timing Blind Spot for N < 3**: If an adversary crafts low-rate timing attacks with exactly 1 or 2 packets per second, the timing detector is inactive and will not flag them. Only packet rate and payload size protect against low-rate anomalies.
3. **Small Empirical Corpus**: Session 1 (N=112) and Session 2 (N=102) represent short observation windows across only 2 client nodes.

### Dashboard Integration Recommendation:
- **Status: NOT RECOMMENDED FOR DIRECT PRODUCTION MERGE YET.**
- **Rationale**: While the dual detector substantially outperforms the 5-feature model on synthetic benchmarks, integration into `src/dashboard.py` and `data/iot_anomaly.db` requires:
  1. Multi-hour live baseline captures under varying IoT traffic profiles (video streaming, idle IoT, bursty sensors).
  2. Calibration of dual decision thresholds on longer continuous traces.
  3. Safe database schema design to persist dual anomaly attributions and timing gating status without breaking existing dashboard queries.
