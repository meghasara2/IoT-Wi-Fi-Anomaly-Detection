# Baseline Validation Report: session5_10min
**Evaluated Windows**: 541
**Frozen Baseline Model**: Trained on Session 1 (`time_1s_session1_pcap_features_uplink.csv`)
**Primary Fitted Offset**: -0.581180
**Timing Fitted Offset**: -0.617487

---

## 1. Traffic Distribution & Timing Availability

| Metric | Measured Value |
| :--- | :---: |
| Total 1-Second Windows | 541 |
| Active Client Nodes | 2 (Node_Client_1, Node_Client_2) |
| Packet Rate Min / Median / Max | 1.0 / 6.0 / 578.0 pkts/s |
| Packet Rate Mean +- Std | 23.80 +- 46.16 pkts/s |
| Qualified Timing Windows (N >= 3) | 353 (65.25%) |
| Unavailable Timing Windows (N < 3) | 188 (34.75%) |
| Qualified Mean IAT | 0.057168 s |

---

## 2. Frozen Dual-Detector Anomaly Scoring

| Anomaly Detection Metric | Count / Percentage |
| :--- | :---: |
| Primary Detector Flags | 57 |
| Secondary Timing Flags | 33 |
| **Dual Combined Flags** | **90 (16.64%)** |

### Attribution Breakdown:
- `NORMAL_INLIER`: 263 windows (48.61%)
- `NORMAL_QUIET_TIMING_UNAVAILABLE`: 188 windows (34.75%)
- `ANOMALY_PRIMARY_BURST_OR_SIZE`: 57 windows (10.54%)
- `ANOMALY_TIMING_JITTER`: 33 windows (6.1%)

---

## 3. Physical Sensor Telemetry Alignment

- **Sensor Alignment**: Not performed (No sensor database provided for this run).

---

## 4. Scientific Notice
- All statistical outliers flagged are deviations from the Session 1 density envelope.
- In the absence of verified real attack ground truth, flagged windows are statistical anomalies, NOT confirmed cyberattacks.