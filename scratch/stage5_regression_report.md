# STAGE 5 — REGRESSION AUDIT REPORT
**Preservation of Local Monitoring, Frozen ML Detectors, and SQLite Databases**
**Project:** IoT Network Guard — Dual-Detector SOC Console  
**Date:** November 15, 2026  
**Baseline Test Count:** 419 Passed (Stage 0)  
**Current Test Count:** 439 Passed (Stage 5)  
**Net Regressions:** **ZERO (0)**

---

## 1. Executive Summary

This regression audit certifies that the integration of cloud synchronization, durable outbox buffering, and the public Streamlit dashboard has caused **zero regressions** to the existing local platform.

The core local architecture—including the frozen Isolation Forest models, the 5 deterministic attack detector algorithms, the serial UART protocol parser, the Windows hotspot interface resolver, and the local SQLite database files—remains completely intact, fully operational, and strictly preserved.

---

## 2. Baseline Comparison Matrix

| Evaluation Area | Stage 0 Baseline | Stage 5 Current | Status / Verdict |
|---|---|---|---|
| **Total Automated Tests** | 419 / 419 Passed | 439 / 439 Passed (+20 new tests) | **100% Pass Rate** |
| **Attack Detector Tests** | 66 / 66 Passed | 66 / 66 Passed | **Zero Drift** |
| **Collector Thread Tests** | 53 / 53 Passed | 53 / 53 Passed | **Zero Drift** |
| **Collector Attack Integration**| 84 / 84 Passed | 84 / 84 Passed | **Zero Drift** |
| **Local Dashboard UI Tests** | 23 / 23 Passed | 23 / 23 Passed | **Zero Drift** |
| **Serial Protocol Tests** | 18 / 18 Passed | 18 / 18 Passed | **Zero Drift** |
| **Interface Resolver Tests** | 36 / 36 Passed | 36 / 36 Passed | **Zero Drift** |
| **Frozen ML Weights & Model** | Bitwise Identical | Bitwise Identical | **Untouched** |
| **Anomaly Thresholds** | Untouched | Untouched | **Strictly Preserved** |
| **Local Database Files** | 3 DBs Intact (8/8/6 tables) | 3 DBs Intact + Outbox Table | **Sovereignty Preserved** |

---

## 3. Database Integrity Verification

The three SQLite databases were inspected and verified:
1. `data/live_monitoring.db`:
   - Size: 3,720 KB
   - Base Tables: 8 tables intact (5,914 feature windows, 1,898 alerts, 1,472 attack events, 1,411 sensor records, 1,411 PIR events).
   - New Table: `cloud_sync_outbox` initialized without table locks or schema drift.
2. `data/stage9_demo_live_monitoring.db`:
   - Size: 156 KB
   - Base Tables: 8 tables intact (159 windows, 5 attack events). Untouched.
3. `data/iot_anomaly.db`:
   - Size: 484 KB
   - Base Tables: 6 tables intact (9,073 traffic observations, ML training baseline). Untouched.

---

## 4. Local Dashboard Operational Certification

The local Streamlit SOC console [`src/live_dashboard.py`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/live_dashboard.py) was tested against `tests/test_live_dashboard.py`:
- All 23 UI tests passed in 2.45s.
- All 7 console sections render cleanly.
- The local console continues to connect to `data/live_monitoring.db` in read-only mode (`?mode=ro`), guaranteeing that local monitoring operates completely independently of internet connectivity or cloud availability.

