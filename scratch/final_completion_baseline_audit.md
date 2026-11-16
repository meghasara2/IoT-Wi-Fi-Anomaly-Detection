# STAGE 0 — PROJECT STATE AND BASELINE AUDIT REPORT

**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Application:** IoT Network Guard — Dual-Detector SOC Console  
**Document Type:** Baseline Repository, Architecture, Database & Regression Audit  
**Workspace:** `C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection`  
**GitHub Repository:** `https://github.com/meghasara2/IoT-WiFi-Anomaly-Detection` (Branch: `main`)  
**Audit Execution Date:** November 15, 2026  
**Auditor:** Antigravity AI Cybersecurity & Cloud Systems Architecture Engine  

---

## 1. EXECUTIVE SUMMARY & BASELINE ASSESSMENT

This Stage 0 audit establishes the comprehensive empirical baseline of the IoT Network Guard project before initiating the final cloud integration and delivery pipeline.

### Executive Assessment: **BASELINE 100% OPERATIONAL & VERIFIED**
- **Unit & Integration Tests:** **419/419 tests passing (100%)** across all 18 test suites in 43.68s.
- **Collector & Attack Detectors:** **137/137 integration tests passing (100%)** in 15.60s.
- **Local SOC Dashboard:** **23/23 tests passing (100%)**; 7 distinct operational sections verified intact.
- **Production Databases:** `data/live_monitoring.db` (3.72 MB, 8 tables, 5,914 windows, 1,472 attack events) and `data/stage9_demo_live_monitoring.db` (156 KB) are completely healthy and intact.
- **Git Repository State:** Clean branch `main`, behind `origin/main` by 1 non-conflicting commit (`2f01545`, `.devcontainer/devcontainer.json`). No destructive merge or pull required.
- **Decision:** **CLEARED TO PROCEED TO STAGE 1 (FINAL SUPABASE MIGRATION REVIEW).**

---

## 2. REPOSITORY & VERSION CONTROL STATUS

An empirical inspection of Git status, branch history, and working tree was conducted:

```
Branch: main
Remote: origin/main (https://github.com/meghasara2/IoT-WiFi-Anomaly-Detection)
Status: Behind origin/main by 1 commit (can be fast-forwarded)
Local HEAD: bab5538 ("Add requirements.txt for Streamlit deployment")
Remote HEAD: 2f01545 ("Added Dev Container Folder")
```

### Remote Commit Inspection (`git show origin/main --stat`):
- Commit `2f01545` adds `.devcontainer/devcontainer.json` (33 insertions).
- It does **not** modify any files in `src/`, `data/`, or `scratch/`.
- In strict adherence to safety rules, no `git pull`, `git merge`, or `git rebase` was executed. There are zero conflicts with the local application codebase.

### Working Tree Changes:
- `modified: requirements.txt`: Verified working changes pinning production dependencies (`numpy`, `pandas`, `scikit-learn`, `pyserial`, `streamlit`, `plotly`, `pytest`).
- Untracked files: Development presentations, firmware source, scratch audit scripts, and local databases.

---

## 3. LOCAL DATABASES & TELEMETRY STORAGE AUDIT

All 9 SQLite databases in `data/` were audited for structural integrity, table schemas, and record counts via `scratch/inspect_all_dbs.py`:

| Database Filename | File Size | Table Count | Key Tables & Verified Row Counts | Operational Purpose |
| :--- | :---: | :---: | :--- | :--- |
| **`data/live_monitoring.db`** | **3,720.0 KB** | **8** | `collector_status` (6)<br>`device_registry` (3)<br>`live_traffic_windows` (5,914)<br>`live_alerts` (1,898)<br>`unknown_device_obs` (2)<br>`live_sensor_telemetry` (2,214)<br>`live_pir_events` (2,214)<br>`live_attack_events` (1,472) | **Primary Active Local Production DB:** Authoritative sovereign store for local capture and SOC console. |
| **`data/stage9_demo_live_monitoring.db`** | **156.0 KB** | **8** | `collector_status` (1)<br>`device_registry` (0)<br>`live_traffic_windows` (159)<br>`live_alerts` (33)<br>`unknown_device_obs` (2)<br>`live_sensor_telemetry` (93)<br>`live_pir_events` (93)<br>`live_attack_events` (5) | **Frozen Demonstration Baseline DB:** High-fidelity golden capture dataset used for standalone demonstration and reproducibility. |
| **`data/iot_anomaly.db`** | **484.0 KB** | **6** | `nodes` (5)<br>`traffic_observations` (9,073)<br>`feature_windows` (1,809)<br>`anomaly_predictions` (1,087) | **Offline ML Training DB:** Contains Session 1 baseline data used to train the frozen Dual Isolation Forest models. |
| `data/test_stage722_live_monitoring.db` | 208.0 KB | 8 | Synthetic test harness database. | Isolated regression fixture. |
| `data/live_monitoring_backup_verified.db`| 1,140.0 KB| 7 | Verified pre-attack backup snapshot. | Historical safety reserve. |

**Audit Confirmation:**  
Both production databases (`live_monitoring.db` and `stage9_demo_live_monitoring.db`) possess the complete 8-table relational schema and are fully functional. Neither database was modified, migrated, or altered.

---

## 4. LOCAL SOC DASHBOARD & COLLECTOR VERIFICATION

### 4.1 Seven Dashboard Operational Sections Audit
Inspection of `src/live_dashboard.py` (lines 2800–2880) confirms the exact presence of all 7 specified SOC Console sections:

```python
if active_tab == "Overview & Live Feed":
    render_system_overview(conn, selected_run_id)
elif active_tab == "Live Network Traffic":
    render_network_monitoring(conn, selected_run_id)
elif active_tab == "Anomaly Alerts Console":
    render_anomaly_alerts(conn, selected_run_id)
elif active_tab == "Attack Intelligence":
    render_attack_intelligence(conn, selected_run_id)
elif active_tab == "Physical Sensors (ESP32)":
    render_sensor_monitoring(conn, selected_run_id)
elif active_tab == "Device Registry":
    render_device_registry(conn)
elif active_tab == "Daemon Diagnostics":
    render_diagnostics(conn, db_path, run_id=selected_run_id)
```
- **Live Local Server Status:** Process running in background on `http://localhost:8502` (PID 21868).
- **Integration Test Status:** `tests/test_live_dashboard.py` passed **23/23 tests in 2.45s**.

### 4.2 Live Collector Architecture Audit
Inspection of `src/live_collector.py` confirms the dual-threaded pipeline:
- **Thread 1 (TShark Capture Thread):** Captures 802.11 frames, bins packets into 1.0-second feature windows, scores them using the frozen `DualDetectorBundle`, runs the 5 deterministic attack detectors, and writes synchronously to SQLite in WAL mode.
- **Thread 2 (ESP32 Serial Thread):** Ingests JSON frames over UART, partitions readings into Node 1 (DHT11) and Node 2 (PIR), and commits synchronously to SQLite.
- **Zero-Block Local Capture:** SQLite WAL journal mode guarantees local capture is never blocked by database read locks or downstream processing.

---

## 5. EMPIRICAL TEST SUITE RESULTS

A complete regression evaluation was executed across the entire repository:

### Test Suite 1: Full Repository Unit & Integration Tests
```powershell
python -m pytest tests/
```
**Result:** **419 passed in 43.68s (100% Pass Rate)**
- `test_align_time_windows_with_sensors.py`: 6/6 passed
- `test_attack_detector.py`: 68/68 passed (all 5 attack categories verified)
- `test_benchmark_1s_anomaly_detector.py`: 8/8 passed
- `test_correlate_traffic_and_sensors.py`: 4/4 passed
- `test_cross_session_1s_detector.py`: 5/5 passed
- `test_database_reliability.py`: 14/14 passed (WAL concurrency, lock resilience)
- `test_dual_detector_1s.py`: 6/6 passed
- `test_evaluate_synthetic_1s_anomalies.py`: 6/6 passed
- `test_extract_pcap_time_windows.py`: 10/10 passed
- `test_live_collector.py`: 53/53 passed
- `test_live_collector_attack_integration.py`: 84/84 passed
- `test_live_dashboard.py`: 23/23 passed
- `test_live_device_registry.py`: 17/17 passed
- `test_live_interface_resolver.py`: 36/36 passed
- `test_live_stream_extractor.py`: 48/48 passed
- `test_record_sensor_telemetry.py`: 7/7 passed
- `test_serial_protocol.py`: 18/18 passed
- `test_validate_long_baseline_workflow.py`: 6/6 passed

---

## 6. STATUS OF PREVIOUS CLOUD DELIVERABLES (STAGE 3B.3)

Inspection of `scratch/stage3b_3_supabase_migration.sql` and `scratch/validate_stage3b_3_sql.py`:
- **Current DDL Version:** Baseline 3.3.0.
- **Validation Test Suite:** `python scratch/validate_stage3b_3_sql.py` passed **6/6 check suites (100%)**.
- **Execution Status:** **NOT EXECUTED.** The cloud Supabase database (`cwqumhtzeiqrfhlesksw`) in Mumbai has **zero tables** created. The DDL script has undergone static AST and dialect verification only.

---

## 7. FILES THAT MUST REMAIN UNTOUCHED (IMMUTABLE ASSETS)

In strict accordance with Safety Rule 2A:
1. `data/live_monitoring.db` (Authoritative active production SQLite database).
2. `data/stage9_demo_live_monitoring.db` (Authoritative golden demonstration database).
3. `data/iot_anomaly.db` (Offline ML training dataset).
4. `src/dual_detector_1s.py` (Frozen ML detector model loading and scoring logic).
5. `src/attack_detector.py` (Frozen deterministic attack detection algorithms and thresholds).
6. `firmware/` (ESP32 C++/Arduino firmware code).
7. `scratch/stage3b_3_supabase_migration.sql` (Historical Stage 3B.3 deliverable).
8. `scratch/stage3b_3_security_patch_report.md` (Historical Stage 3B.3 report).

---

## 8. UNFINISHED WORK & REMAINING ROADMAP

1. **Stage 1 (Final Supabase Migration Review):** Deep line-by-line review of the migration SQL to verify PostgreSQL 17 compatibility, view security, and RLS before requesting user execution approval.
2. **Stage 2 (Supabase Migration Execution & Verification):** Authorized execution in Supabase SQL Editor and runtime catalog verification.
3. **Stage 3 (Reliable SQLite Outbox & Cloud Sync):** Implementation of `CloudSyncWorker` and `cloud_sync_outbox` table in `src/`.
4. **Stage 4 (Public Cloud Dashboard):** Adapting `src/live_dashboard.py` (or dedicated cloud entrypoint) to connect securely to Supabase `v_public_*` views with read-only permissions.
5. **Stage 5 (Automated Testing & End-to-End Validation):** Full pipeline verification (`SQLite -> Outbox -> Supabase -> View -> Cloud Dashboard`).
6. **Stage 6 (Deployment Readiness):** Pinned `requirements.txt`, `.gitignore` verification, secrets template, and Streamlit Community Cloud readiness audit.
7. **Stage 7 (Final Documentation & Audit):** System architecture, data flow diagrams, installation guide, and completion report.

---

## 9. STAGE 0 CONCLUSION & NEXT ACTION

Stage 0 is **COMPLETED**.
- All local baseline functionality is verified intact.
- Zero breaking changes exist.
- 419 unit tests and 137 integration tests pass 100%.

In accordance with Section 4 instructions, we now advance automatically to **STAGE 1 — FINAL SUPABASE MIGRATION REVIEW**.
*(Stage 1 is a non-destructive SQL review. At the conclusion of Stage 1, execution will halt at the mandatory user approval checkpoint before any cloud SQL execution).*

