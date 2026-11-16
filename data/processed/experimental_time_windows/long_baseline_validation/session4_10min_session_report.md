# Baseline Validation Report: session4_10min
**Evaluated Windows**: 577
**Frozen Baseline Model**: Trained on Session 1 (`time_1s_session1_pcap_features_uplink.csv`)
**Primary Fitted Offset**: -0.581180
**Timing Fitted Offset**: -0.617487

---

## 1. Traffic Distribution & Timing Availability

| Metric | Measured Value |
| :--- | :---: |
| Total 1-Second Windows | 577 |
| Active Client Nodes | 2 (Node_Client_1, Node_Client_2) |
| Packet Rate Min / Median / Max | 1.0 / 14.0 / 1326.0 pkts/s |
| Packet Rate Mean +- Std | 50.26 +- 131.70 pkts/s |
| Qualified Timing Windows (N >= 3) | 455 (78.86%) |
| Unavailable Timing Windows (N < 3) | 122 (21.14%) |
| Qualified Mean IAT | 0.046043 s |

---

## 2. Frozen Dual-Detector Anomaly Scoring

| Anomaly Detection Metric | Count / Percentage |
| :--- | :---: |
| Primary Detector Flags | 71 |
| Secondary Timing Flags | 26 |
| **Dual Combined Flags** | **97 (16.81%)** |

### Attribution Breakdown:
- `NORMAL_INLIER`: 362 windows (62.74%)
- `NORMAL_QUIET_TIMING_UNAVAILABLE`: 118 windows (20.45%)
- `ANOMALY_PRIMARY_BURST_OR_SIZE`: 71 windows (12.31%)
- `ANOMALY_TIMING_JITTER`: 26 windows (4.51%)

---

## 3. Physical Sensor Telemetry Alignment

- **Sensor Alignment**: Active
- **Windows Matched with Sensor Telemetry**: 577 out of 577 (100.0%)
- **Scientific Notice**: Environmental sensor telemetry (DHT11/PIR) is stored strictly as contextual metadata and is NEVER used to label network attacks.

---

## 4. Scientific Notice
- All statistical outliers flagged are deviations from the Session 1 density envelope.
- In the absence of verified real attack ground truth, flagged windows are statistical anomalies, NOT confirmed cyberattacks.