# Baseline Validation Report: session3_10min
**Evaluated Windows**: 678
**Frozen Baseline Model**: Trained on Session 1 (`time_1s_session1_pcap_features_uplink.csv`)
**Primary Fitted Offset**: -0.581180
**Timing Fitted Offset**: -0.617487

---

## 1. Traffic Distribution & Timing Availability

| Metric | Measured Value |
| :--- | :---: |
| Total 1-Second Windows | 678 |
| Active Client Nodes | 2 (Node_Client_1, Node_Client_2) |
| Packet Rate Min / Median / Max | 1.0 / 10.0 / 509.0 pkts/s |
| Packet Rate Mean +- Std | 33.66 +- 67.00 pkts/s |
| Qualified Timing Windows (N >= 3) | 510 (75.22%) |
| Unavailable Timing Windows (N < 3) | 168 (24.78%) |
| Qualified Mean IAT | 0.04764 s |

---

## 2. Frozen Dual-Detector Anomaly Scoring

| Anomaly Detection Metric | Count / Percentage |
| :--- | :---: |
| Primary Detector Flags | 92 |
| Secondary Timing Flags | 31 |
| **Dual Combined Flags** | **123 (18.14%)** |

### Attribution Breakdown:
- `NORMAL_INLIER`: 390 windows (57.52%)
- `NORMAL_QUIET_TIMING_UNAVAILABLE`: 165 windows (24.34%)
- `ANOMALY_PRIMARY_BURST_OR_SIZE`: 92 windows (13.57%)
- `ANOMALY_TIMING_JITTER`: 31 windows (4.57%)

---

## 3. Physical Sensor Telemetry Alignment

- **Sensor Alignment**: Active
- **Windows Matched with Sensor Telemetry**: 678 out of 678 (100.0%)
- **Scientific Notice**: Environmental sensor telemetry (DHT11/PIR) is stored strictly as contextual metadata and is NEVER used to label network attacks.

---

## 4. Scientific Notice
- All statistical outliers flagged are deviations from the Session 1 density envelope.
- In the absence of verified real attack ground truth, flagged windows are statistical anomalies, NOT confirmed cyberattacks.