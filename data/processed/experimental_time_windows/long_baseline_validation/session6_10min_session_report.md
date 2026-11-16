# Baseline Validation Report: session6_10min
**Evaluated Windows**: 570
**Frozen Baseline Model**: Trained on Session 1 (`time_1s_session1_pcap_features_uplink.csv`)
**Primary Fitted Offset**: -0.581180
**Timing Fitted Offset**: -0.617487

---

## 1. Traffic Distribution & Timing Availability

| Metric | Measured Value |
| :--- | :---: |
| Total 1-Second Windows | 570 |
| Active Client Nodes | 2 (Node_Client_1, Node_Client_2) |
| Packet Rate Min / Median / Max | 1.0 / 9.0 / 285.0 pkts/s |
| Packet Rate Mean +- Std | 25.53 +- 40.73 pkts/s |
| Qualified Timing Windows (N >= 3) | 427 (74.91%) |
| Unavailable Timing Windows (N < 3) | 143 (25.09%) |
| Qualified Mean IAT | 0.054755 s |

---

## 2. Frozen Dual-Detector Anomaly Scoring

| Anomaly Detection Metric | Count / Percentage |
| :--- | :---: |
| Primary Detector Flags | 62 |
| Secondary Timing Flags | 23 |
| **Dual Combined Flags** | **85 (14.91%)** |

### Attribution Breakdown:
- `NORMAL_INLIER`: 345 windows (60.53%)
- `NORMAL_QUIET_TIMING_UNAVAILABLE`: 140 windows (24.56%)
- `ANOMALY_PRIMARY_BURST_OR_SIZE`: 62 windows (10.88%)
- `ANOMALY_TIMING_JITTER`: 23 windows (4.04%)

---

## 3. Physical Sensor Telemetry Alignment

- **Sensor Alignment**: Active
- **Windows Matched with Sensor Telemetry**: 570 out of 570 (100.0%)
- **Scientific Notice**: Environmental sensor telemetry (DHT11/PIR) is stored strictly as contextual metadata and is NEVER used to label network attacks.

---

## 4. Scientific Notice
- All statistical outliers flagged are deviations from the Session 1 density envelope.
- In the absence of verified real attack ground truth, flagged windows are statistical anomalies, NOT confirmed cyberattacks.