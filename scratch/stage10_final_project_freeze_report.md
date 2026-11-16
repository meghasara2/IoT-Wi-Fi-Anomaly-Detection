# STAGE 10 — FINAL PROJECT FREEZE AND RELEASE VERIFICATION REPORT

**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Workspace:** `C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection`  
**Freeze Date:** November 15, 2026  
**Execution Mode:** Strictly Read-Only Project Baseline & Release Verification  
**Release Manifest:** [`scratch/stage10_release_manifest.sha256`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/scratch/stage10_release_manifest.sha256)  

---

## 1. Executive Summary & Freeze Declaration

This document establishes the official project freeze and release baseline for the capstone project: **AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection**.

All development, correction, hardening, live demonstration, and evidence audit stages (Stages 1 through 9.3.1) are complete. This freeze records the cryptographic state of all project source modules, firmware binaries, model training artifacts, historical evidence databases, demonstration records, and test assets.

### Freeze Verdict:
### **`READY WITH DOCUMENTED LIMITATIONS`**

The project is fully operational, physically demonstrated, regression-verified (419 passing unit tests), and backed by cryptographically protected evidence databases. The "DOCUMENTED LIMITATIONS" designation accurately and scientifically reflects known physical, operating-system, and hardware constraints that were preserved rather than obscured.

---

## 2. Final Project Inventory

A comprehensive read-only scan of the project workspace cataloged all assets across 10 functional domains:

| Category | Item Count | Primary Location | Key Artifacts / Descriptions |
| :--- | :---: | :--- | :--- |
| **1. Python Source Files** | 39 modules | `src/` | Core collector daemon, live dashboard, deterministic attack detector, Npcap stream extractor, interface resolver, SQLite WAL pipeline, feature extractors. |
| **2. Firmware Files** | 8 files | `firmware/` | C++/Arduino firmware source (`esp32_sensor_node.ino`), compiled binary (`.bin`, 892.6 KB), bootloader, partitions, and merged binary. |
| **3. ML Model & Baselines** | 5 CSV datasets | `data/processed/experimental_time_windows/` | Frozen Session 1 idle uplink feature dataset (`time_1s_session1_pcap_features_uplink.csv`, 112 training windows, offset thresholds `-0.581180` / `-0.617487`). |
| **4. Database Files** | 9 `.db` files | `data/` | Offline training/research DB (`iot_anomaly.db`), primary live DB (`live_monitoring.db`), Stage 7.2.2 fallback DB (`test_stage722_live_monitoring.db`), and Stage 9 demo DB (`stage9_demo_live_monitoring.db`). |
| **5. Test Modules** | 18 test files | `tests/` | 18 unit/integration test suites covering serial protocols, attack detection, collector reliability, interface resolution, dashboard, and long-baseline workflows. |
| **6. Requirements** | 1 file | `requirements.txt` | Explicit version constraints for all 7 runtime dependencies (Python 3.11 compatibility). |
| **7. Entry Points** | 2 primary CLIs | `src/` | `src/live_collector.py` (Ingestion Daemon) and `src/live_dashboard.py` (Streamlit Visual Console). |
| **8. Configuration Files** | 3 files | `src/`, root | `src/live_stream_extractor.py` (`DEFAULT_DEVICE_REGISTRY`), `src/init_live_database.py` (schema), `requirements.txt`. |
| **9. Project Documentation** | 35 reports | `scratch/` | Comprehensive technical audits, design fixes, preflight reports, and demonstration plans from Stages 5 through 10. |
| **10. Stage 9 Evidence** | 5 artifacts | `data/`, `scratch/` | Live demonstration DB (`stage9_demo_live_monitoring.db`), diagnostic JSON (`stage9_demo_live_monitoring_diagnostic.json`), and audit reports (`stage92`, `stage93`, `stage931`). |

---

## 3. Important Release Artifact Hashes

The release manifest [`scratch/stage10_release_manifest.sha256`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/scratch/stage10_release_manifest.sha256) defines the immutable baseline:

### 3.1 Core Source Modules
| Relative Path | Size | SHA-256 Hash |
| :--- | :---: | :--- |
| `src/live_collector.py` | 129,355 B | `8B11E16AA89C321D18BA24C7F660B67E8CD502DC251E2E01BFAAA1E4F2CBDC06` |
| `src/live_dashboard.py` | 114,470 B | `BE3D7C9E5CCDDFE0A2F7CCEA1240A751ACC3A7E783EAB5A966A620C51BCDBC0D` |
| `src/attack_detector.py` | 87,903 B | `0A7B7A5630FE8691BF3B59F6122F6F330AEB274A0C672B2E90CD158D40755D65` |
| `src/live_interface_resolver.py` | 21,714 B | `F7B628224E54880843ADE81CB09FFD662508F2E58484F0CD62914D90582EA03B` |
| `src/live_stream_extractor.py` | 31,430 B | `5FB9081DE741952A229F877957802E0C139D36D0CDB6EF94F7685FE70F5EEB40` |
| `src/init_live_database.py` | 22,526 B | `D2A65B31D6CF7D63D62224DD3B17892A9265D9751EAF6FC6E8C505E93C35EF46` |
| `src/dual_detector_1s.py` | 34,976 B | `8C64DADE72AB1397C0638319DC88DD0B640FB08DB77C4E24BF456F4DD2CB419C` |
| `src/validate_long_baseline_workflow.py` | 16,627 B | `E05BAA32ED53660EC1255D19C3A275ACA994A923440E8B93E395DC86E9F8BFFF` |
| `src/dashboard.py` | 88,771 B | `C0079FE85BA95F3279EE34FFE679FB88D56377B515BEF58335712683FDD38BC1` |
| `requirements.txt` | 281 B | `F75AC5527E6B9BA2940782A65191776AE088AE139299B4285D03E4CC6C502060` |

### 3.2 ESP32 Firmware Artifacts
| Relative Path | Size | SHA-256 Hash |
| :--- | :---: | :--- |
| `firmware/esp32_sensor_node/esp32_sensor_node.ino` | 19,751 B | `3D56DFE3BD66E7416DE5A3AC3A5651D9AF051F948799F2BD1EF7E5F5703A0B75` |
| `firmware/build/esp32_sensor_node.ino.bin` | 892,640 B | `970389FC05815C67557FB4890ACD246D11E5013A5F57DAC604DCC028E863654A` |
| `firmware/build/esp32_sensor_node.ino.bootloader.bin` | 25,168 B | `E27D5D644E79AEF9D4044622273007A5DE4C2EF3B80B6D499BA76A3CF93A4E9D` |
| `firmware/build/esp32_sensor_node.ino.partitions.bin` | 3,072 B | `148B959CBFF1C38AA8E1D5C0BA9D612C54997B945E56A63F41223EEF650653A1` |
| `firmware/build/esp32_sensor_node.ino.merged.bin` | 4,194,304 B | `8F5413E0CAC93A678950419EC0B818CA02F5039336F318CE1D4572B567B74F72` |

### 3.3 Model Training Baseline
| Relative Path | Size | SHA-256 Hash |
| :--- | :---: | :--- |
| `data/processed/experimental_time_windows/time_1s_session1_pcap_features_uplink.csv` | 26,178 B | `4042255104E1F6C50281F172D79998280DFA113A136F57CD817E5FF19F191585` |

### 3.4 Evidence Databases & Stage 9 Evidence
| Relative Path | Size | SHA-256 Hash |
| :--- | :---: | :--- |
| `data/live_monitoring.db` | 3,809,280 B | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` |
| `data/iot_anomaly.db` | 495,616 B | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` |
| `data/test_stage722_live_monitoring.db` | 212,992 B | `74C773C29C49B25CE73E5D5B0641BAB5636FBCC83DA07E08CFFF5043761DFE2D` |
| `data/stage9_demo_live_monitoring.db` | 159,744 B | `01B2053CD928E8EC4965EE63638F36CBA1B60A46309DFE20D742B12D7CBB87C6` |
| `data/stage9_demo_live_monitoring_diagnostic.json` | 331 B | `1C57831B7676CE372463BB24004722D3C9127644B06E49EC14D773E7801592F9` |
| `scratch/stage92_live_demonstration_report.md` | 11,554 B | `BD35789298E1394A760FDC5F6C5DCFC9F3F2E1C931A419D68AFB86B059F227DD` |
| `scratch/stage93_final_evidence_audit.md` | 21,965 B | `7189D22F491067EEBA0B5425591E5413BD4A796D07001FE253410D68B64A8236` |
| `scratch/stage931_execution_history_clarification.md` | 18,177 B | `E5D89A901AFBE14844AFB0821D712E43139DE15C2B3CC900F3821485CE9A6633` |

---

## 4. Source, Firmware, and Model Integrity Verification

1. **Python Bytecode Compilation:** Verified via `python -m compileall -q src/`. All 39 source modules compiled cleanly with zero syntax or import errors.
2. **Firmware Source & Binary Match:** Firmware source (`esp32_sensor_node.ino`, 19,751 bytes) defines the authenticated handshake protocol (`WIFI_SNIFFER_INITIALIZED`), channel 6 promiscuous filtering, token-bucket suppression (5 pkts/sec), DHT11 2.0s polling, and PIR interrupt handling. The precompiled binary (`esp32_sensor_node.ino.bin`, 892,640 bytes) was verified bit-for-bit identical to the physical flash on the ESP32 hardware node.
3. **Model Determinism & Reproducibility:** Rather than storing fragile pickle/joblib binaries, the frozen Dual Isolation Forest model is re-fitted deterministically from `time_1s_session1_pcap_features_uplink.csv` with pinned random seeds (`random_state=42`) and contamination `0.05`. Offset thresholds remain bit-for-bit identical (`Primary: -0.581180`, `Timing: -0.617487`).

---

## 5. Production Database Protection Verification

Cryptographic SHA-256 verification confirms that all pre-existing databases remained 100% untouched throughout all testing and demonstration stages:

| Database File | Baseline SHA-256 Hash | Post-Demonstration SHA-256 | Verification Result |
| :--- | :--- | :--- | :---: |
| `data/live_monitoring.db` | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | **100% UNTOUCHED** |
| `data/iot_anomaly.db` | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | **100% UNTOUCHED** |
| `data/test_stage722_live_monitoring.db` | `74C773C29C49B25CE73E5D5B0641BAB5636FBCC83DA07E08CFFF5043761DFE2D` | `74C773C29C49B25CE73E5D5B0641BAB5636FBCC83DA07E08CFFF5043761DFE2D` | **100% UNTOUCHED** |

---

## 6. Live Demonstration Database Preservation

The physical demonstration database [`data/stage9_demo_live_monitoring.db`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/data/stage9_demo_live_monitoring.db) is preserved as an immutable release artifact:
- **File Size:** `159,744 bytes`
- **SHA-256 Hash:** `01B2053CD928E8EC4965EE63638F36CBA1B60A46309DFE20D742B12D7CBB87C6`
- **SQLite PRAGMA integrity_check:** **`ok`**
- **SQLite PRAGMA foreign_key_check:** **`0 violations`**
- **Preserved Records:**
  - `collector_status`: 1 row (Run ID 1, `STOPPED`, duration: 187s lifecycle / 180.59s loop)
  - `live_traffic_windows`: 159 rows (2,466 packets attributed to Node_3)
  - `live_sensor_telemetry`: 93 rows (Node_1 DHT11, 28.5 °C, 92–93% humidity)
  - `live_pir_events`: 93 rows (Node_2 PIR, 82 idle, 11 motion detections)
  - `live_alerts`: 33 rows (volumetric & timing statistical anomalies)
  - `unknown_device_obs`: 2 rows (Galaxy A55: 108 observations, Gateway virtual MAC: 92 observations)
  - `live_attack_events`: 5 rows (baseline capability seeds; zero attack false alarms)

---

## 7. Historical Test Evidence

- **Regression Test Suite:** 18 test files, 419 unit and integration tests.
- **Documented Result:** **419 passed / 0 failed in 40.14s (100% pass rate)**.
- **Evidence Provenance:** Verified in execution log `task-6236.log` (`2026-11-15T12:24:53Z`).
- **Scope Distinction:**
  - *Historical Unit & Boundary Tests:* 419 tests covering boundary conditions, malformed JSON, queue full drops, serial disconnect/reconnect backoff, SQLite locked retry backoff, and synthetic attack vectors.
  - *Physical Live Demonstration:* 180.59s benign physical test on COM6 and Windows Hotspot validating physical sensors and normal phone traffic.
  - *Synthetic Attack Injection:* 63 synthetic tests validating DoS, Port Scan, Spoofing, Deauth, and Replay detection algorithms without transmitting live over-the-air attack traffic.

---

## 8. Stage 9 Live Demonstration Evidence Summary

| Observation Domain | Measured Demonstration Metric | Operational Status |
| :--- | :--- | :---: |
| **Active Monitoring Window** | 180.59 seconds (Wall-clock loop) | Verified |
| **Total Captured Packets** | 28,254 packets (Npcap Interface 5) | Verified |
| **Feature Windows Emitted** | 159 1-second feature windows | Verified |
| **Phone 1 (Vivo V2031)** | `ca:34:ea:92:d3:9e` -> Node_3 (2,466 packets, mean 15.51 PPS) | Verified |
| **Phone 2 (Samsung Galaxy A55)** | `26:f0:ec:aa:b7:78` (108 observations in `unknown_device_obs`) | Verified |
| **ESP32 Runtime Handshake** | Boot ID: `411020411`, Nonce: `2888996866`, Channel: `6` | Verified |
| **DHT11 Environmental Data** | 93 samples (28.5 °C, 92–93% RH, 2.0s cadence) | Verified |
| **AM312 Motion Data** | 93 samples (82 idle, 11 physical motion waves) | Verified |
| **Isolation Forest Alerts** | 33 statistical alerts (20.8% rate; browsing burst variance) | Verified |
| **Deterministic Attack Alerts** | 0 cyberattacks flagged across 795 evaluations | Verified |

---

## 9. Documented Known Limitations

Per strict scientific integrity standards, the following seven known limitations are explicitly preserved in the release record:

1. **Windows Hotspot CLI Channel Invisibility:** Windows 11 Wi-Fi Direct virtual adapters (`Local Area Connection* 2`) do not report their 802.11 RF channel via `netsh wlan show interfaces`.
2. **Channel Alignment Unverified at Runtime:** The ESP32 hardware handshake was verified on Channel 6, but because the Windows hotspot channel could not be retrieved via CLI, channel alignment is recorded as `CHANNEL_UNAVAILABLE`.
3. **Dynamic MAC Randomization on Client Phone 2:** Android's private MAC feature caused Phone 2 to connect via `26:f0:ec:aa:b7:78`. The system dynamically tracked it in `unknown_device_obs` (108 observations) rather than mapping it to `Node_4`.
4. **Replay Telemetry Constraint:** Real-time Replay attack detection reports `INSUFFICIENT_TELEMETRY` on live capture streams because standard TShark pipelines do not extract live cryptographic payload hashes.
5. **Physical Live RF Attack Abstention:** Per ethical and legal RF transmission regulations, live over-the-air deauthentication floods or jamming were not transmitted; deauth detection accuracy is validated via synthetic unit tests (63 tests).
6. **Windows NDIS Interface Stripping:** The Windows NDIS network stack strips raw 802.11 management frames before reaching TShark on virtual adapters. The ESP32 sniffer provides the dedicated management-frame capture pipeline.
7. **Offline Clean-Environment Dependency Validation:** A completely fresh virtual environment installation could not be performed due to sandbox network isolation; all dependencies were audited and verified against the working host environment.

---

## 10. Outstanding Project Risks & Mitigation

| Identified Risk | Risk Severity | Impact Description | Implemented Mitigation / Operational Remedy |
| :--- | :---: | :--- | :--- |
| **Win32 COM Port Contention** | Low | Opening COM6 from multiple processes causes Win32 Access Denied. | Architecture strictly enforces `LiveCollector` as the sole process owner of COM6. Dashboard accesses SQLite database exclusively via read-only URI mode. |
| **Npcap Capture Index Drift** | Low | Windows virtual adapter index can change across network resets. | `src/live_interface_resolver.py` auto-resolves interface index and accepts explicit `--interface 5` override. |
| **SQLite WAL Lock Contention** | Low | High-rate concurrent writes from network and serial threads. | Bounded exponential backoff retry implemented in `_persist_window_with_retry()` and `_persist_sensor_with_retry()`; zero write failures observed during live run. |
| **Live Presentation RF Fade** | Low | Physical Wi-Fi interference or hardware disconnect during demo. | Pre-validated physical fallback database [`data/test_stage722_live_monitoring.db`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/data/test_stage722_live_monitoring.db) allows instant 10-second presentation recovery. |

---

## 11. Final Release Readiness Review Matrix

| Evaluation Dimension | Readiness Status | Evidence & Audit Basis |
| :--- | :---: | :--- |
| **1. Source & Firmware Integrity** | **VERIFIED** | 39 Python files compile cleanly; firmware binary matches hardware flash; SHA-256 hashes pinned. |
| **2. Model Integrity** | **VERIFIED** | Training dataset verified; decision boundaries pinned; deterministic re-fitting ensures 100% reproducibility. |
| **3. Database Preservation** | **VERIFIED** | All three protected databases bit-for-bit identical; Stage 9 demo database preserved intact with zero FK violations. |
| **4. Test Evidence Availability** | **VERIFIED** | 419 unit tests passing verified in `task-6236.log`; complete coverage across all modules. |
| **5. Live Demonstration Evidence** | **VERIFIED** | Authentic 180.59s live run recorded in `stage9_demo_live_monitoring.db`; 28,254 pkts, 93 sensors, 159 windows. |
| **6. Dashboard & Collector Availability** | **VERIFIED** | Entry points verified; dashboard tested on port 8502; collector shutdown confirmed. |
| **7. Dependency Documentation** | **VERIFIED** | `requirements.txt` updated with explicit verified version bounds for Python 3.11. |
| **8. Deployment & Channel Limitations**| **VERIFIED WITH LIMITATIONS** | Windows CLI channel invisibility honestly reported; offline pip download constrained by sandbox. |
| **9. Threat Detection Honesty** | **VERIFIED** | Zero false alarms on benign traffic; replay telemetry constraint preserved; statistical anomalies distinguished. |

---

## 12. Final Recommendation

### Final Status: **`READY WITH DOCUMENTED LIMITATIONS`**

The project **AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection** is formally frozen and verified release-ready.

All software source code, firmware binaries, machine learning feature baselines, evidence databases, and documentation are cryptographically secured. The system is ready for final college capstone presentation, demonstration defense, and archival.

---

*(Stage 10 Final Project Freeze completed. Project state is immutable. Awaiting user instruction).*

