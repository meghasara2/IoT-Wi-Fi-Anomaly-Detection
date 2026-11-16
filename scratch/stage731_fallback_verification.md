# Stage 7.3.1: Read-Only Fallback and Launch Command Verification Report

**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Workspace:** `C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection`  
**Execution Mode:** Strictly Read-Only (no processes launched, no capture started, COM6 unopened, zero writes to production or test databases)

---

## 1. Executive Verification Verdict

### **OVERALL VERDICT: VERIFIED WITH MINOR DOCUMENTATION CLARIFICATIONS**

All technical instructions, launch commands, fallback procedures, database queries, and presentation claims documented in Stage 7.3 have been audited against the actual source code and retained evidence:
- **Collector CLI:** Fully verified. Honors `--interface 5`, `--port COM6`, and `--db-path <path>`.
- **Dashboard CLI & Safety:** Fully verified. `src/live_dashboard.py` connects strictly in read-only mode (`mode=ro`) with zero `INSERT`, `UPDATE`, `DELETE`, or schema DDL statements.
- **Fallback Database:** Fully verified. `data/test_stage722_live_monitoring.db` passes SQLite integrity check and retains all exact record counts.
- **Presentation Claims:** All primary presentation values (71,967 packets, 239 windows, 190 alerts, 90 sensor records, 90 PIR records, PIR motion at sequence 19) are verified directly in SQLite tables.
- **Production Safety:** Production databases [`data/live_monitoring.db`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/data/live_monitoring.db) and [`data/iot_anomaly.db`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/data/iot_anomaly.db) remain completely untouched with identical pre-test hashes.

---

## 2. Detailed Task-by-Task Verification

### Task 1 — Collector Launch Command Verification
* **Source Code Inspected:** [`src/live_collector.py`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/live_collector.py#L2545-L2723) (`main()`, lines 2547–2720).
* **Launch Command:**
  ```powershell
  python src/live_collector.py --interface 5 --port COM6 --db-path data/live_monitoring.db
  ```
* **Verification Findings:**
  1. *Interface Argument (`--interface 5`):* **VERIFIED.** Defined as `type=int, default=None` (line 2556). Passing `5` overrides auto-detection and selects Interface Index 5 (`Local Area Connection* 2`).
  2. *Serial Port Argument (`--port COM6`):* **VERIFIED.** Defined as `type=str, default=DEFAULT_SERIAL_PORT` (`COM6`, line 2564). Passing `COM6` specifies COM6.
  3. *Database Path Argument (`--db-path`):* **VERIFIED.** Defined as `type=str, default=str(DEFAULT_LIVE_DB_PATH)` (line 2570). Lines 2642 and 2708 pass this path directly into `LiveCollector(db_path=db_path)`. All internal database write helpers (`_persist_window_transaction`, `_persist_sensor_with_retry`, `_persist_status_locked`) construct connections exclusively via `get_live_db_connection(self.db_path)`.
  4. *Accidental Production Database Selection Guard:* **VERIFIED WITH LIMITATIONS.**
     - `data/iot_anomaly.db` (historical batch database) is strictly protected by `_safety_check(db_path)` in [`src/init_live_database.py`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/init_live_database.py#L232-L235), which raises `RuntimeError` if targeted.
     - However, `data/live_monitoring.db` is the default live database. If `--db-path` is omitted, the collector writes new runs into `data/live_monitoring.db` (creating Run #7).
     - *Clarification:* To execute a live demonstration without adding new runs to `data/live_monitoring.db`, the operator **must** explicitly pass `--db-path data/test_stage722_live_monitoring.db` (or a dedicated demo database).
  5. *Documented Optional Arguments:* **VERIFIED.** `--no-sensors`, `--gateway-mac`, `--init-db`, `--overwrite-db`, and `--migrate-db` are all fully implemented and active in the parser.
* **Classification:** **VERIFIED WITH LIMITATIONS** (operational requirement to pass `--db-path` explicitly when production database isolation is desired).

---

### Task 2 — Dashboard Launch Command & Working Directory Verification
* **Source Code Inspected:** [`src/live_dashboard.py`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/live_dashboard.py#L1-L65,L275-L285,L2250-L2329).
* **Launch Command:**
  ```powershell
  streamlit run src/live_dashboard.py
  ```
* **Verification Findings:**
  1. *Streamlit Entry Point:* **VERIFIED.** Lines 2252–2329 define `main()`, executing UI components within `render_live_dashboard_fragment()`.
  2. *Project Working Directory:* **VERIFIED.** Line 59 anchors project root via `_PROJECT_ROOT = Path(__file__).resolve().parent.parent`. Executing from `C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection` ensures all relative paths entered by the user (such as `data/test_stage722_live_monitoring.db`) resolve correctly.
  3. *Actual Navigation Tab Names:* **VERIFIED.** Lines 2273–2281 define the exact 7 navigation options:
     - `"Overview & Live Feed"`
     - `"Live Network Traffic"`
     - `"Anomaly Alerts Console"`
     - `"Attack Intelligence"`
     - `"Physical Sensors (ESP32)"`
     - `"Device Registry"`
     - `"Daemon Diagnostics"`
  4. *Zero Database Writes / No DDL:* **VERIFIED.** An exhaustive regex search for `INSERT`, `UPDATE`, `DELETE`, and `.commit` across `src/live_dashboard.py` returns **0 occurrences**. Connection initialization (lines 282–285) explicitly sets SQLite read-only mode:
     ```python
     uri = f"file:{db_path.resolve().as_posix()}?mode=ro"
     conn = sqlite3.connect(uri, uri=True, check_same_thread=False, timeout=5.0)
     ```
* **Classification:** **VERIFIED**.

---

### Task 3 — Fallback Database Verification
* **Database Inspected:** [`data/test_stage722_live_monitoring.db`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/data/test_stage722_live_monitoring.db) (Opened with `mode=ro`).
* **Verification Findings:**
  1. *Database Existence & Readability:* **VERIFIED.** File size: 286,720 bytes.
  2. *SQLite Integrity Check:* **VERIFIED.** `PRAGMA integrity_check` returns `ok`.
  3. *Collector Status & Run ID:* **VERIFIED.** Contains `run_id = 1`, `status = STOPPED`, `stop_reason = Stage 7.2.2 controlled 180s test finished`, `started_at = 2026-11-10 15:47:49`, `last_heartbeat = 2026-11-10 15:50:51`.
  4. *Dashboard Run-Filter Generation:* **VERIFIED.** Dashboard query `SELECT run_id, status FROM collector_status ORDER BY run_id DESC` produces:
     `['Latest Session', 'Run #1 (STOPPED)']`.
     Selecting either option filters queries to Run 1.
  5. *Exact Record Counts:* **VERIFIED.**
     - `live_traffic_windows`: **239 rows** (Node_3: 180 windows, Node_4: 59 windows).
     - `live_alerts`: **190 rows** (185 primary burst/size, 5 timing jitter).
     - `live_sensor_telemetry`: **90 rows** (100% valid DHT11 readings).
     - `live_pir_events`: **90 rows** (1 motion event at sequence 19, 89 idle).
     - `live_attack_events`: **5 rows** (Startup capability status rows; zero attack findings).
     - `collector_status`: **1 row**.
     - `device_registry`: **3 rows** (`Node_3`, `Node_4`, `Node_5`).
     - `unknown_device_obs`: **0 rows**.
* **Classification:** **VERIFIED**.

---

### Task 4 — Tracing Dashboard Fallback Behavior
* **Code Paths Inspected:** [`src/live_dashboard.py`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/live_dashboard.py) lines 1155–1173, 2288–2325.
* **Verification Findings:**
  1. *Live DB Path Selection:* When the user updates the sidebar text input to `data/test_stage722_live_monitoring.db`, line 2290 instantiates `db_path = Path("data/test_stage722_live_monitoring.db")` and opens the connection with `mode=ro`.
  2. *Collector Run Filter Selection:* `run_options` populates with `['Latest Session', 'Run #1 (STOPPED)']`. Selecting either option assigns `selected_run_id = 1` or defaults to latest (Run 1), correctly isolating all metrics to Stage 7.2.2 evidence.
  3. *Archived Session Banner:* Lines 1162–1172 check `status["status"] == "STOPPED"`. When viewing Run 1, the dashboard displays:
     ```html
     <div class="archived-banner">
         <b>⏸️ Collector Daemon Inactive (Archived Session):</b>
         The collector daemon stopped gracefully via <code>Stage 7.2.2 controlled 180s test finished</code> at <b>2026-11-10 15:50:51 UTC</b>.
         All 239 traffic feature windows and 190 statistical alerts below represent completed, persisted data from Run #1 on adapter Local Area Connection* 2.
     </div>
     ```
     This prevents audience confusion by confirming the session is an archive.
  4. *Refresh Data Now Control:* Line 2309 calls `st.rerun()`, forcing Streamlit to re-execute without writing or locking SQLite.
  5. *Automatic DDL / Migration Absence:* No automatic schema creation or migration runs during dashboard startup. If a non-existent path is provided, the dashboard renders an error notification without crashing.
* **Classification:** **VERIFIED**.

---

### Task 5 — Fallback Presentation Claims Verification
Every numeric claim documented in Stage 7.3 was cross-referenced against [`data/test_stage722_live_monitoring.db`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/data/test_stage722_live_monitoring.db) and [`scratch/stage722_live_test.log`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/scratch/stage722_live_test.log):

| Claimed Presentation Metric | Stage 7.3 Claim | Source of Truth | Verification Result | Classification |
| :--- | :---: | :---: | :---: | :---: |
| **Captured Packet Total** | 71,967 packets | `collector_status.packets_parsed` & Log line 56 | **71,967** | **VERIFIED** (DB & Log) |
| **Traffic Windows Emitted** | 239 windows | `live_traffic_windows` row count & Log line 57 | **239** | **VERIFIED** (DB & Log) |
| **Uplink Packets Aggregated** | 35,834 packets | `SUM(packet_count)` in `live_traffic_windows` | **35,834** | **VERIFIED** (DB-backed) |
| **Non-Uplink Packets** | 36,133 packets | Extractor filtering ($71967 - 35834$) | **36,133** | **VERIFIED WITH LIMITATIONS** (Derived; raw frames not retained in PCAP) |
| **Valid DHT11 Records** | 90 records | `live_sensor_telemetry` where `dht_valid = 1` | **90 (100%)** | **VERIFIED** (DB-backed) |
| **Ambient Temperature** | 29.3 °C | Average in `live_sensor_telemetry` | **29.3 °C** | **VERIFIED** (DB-backed) |
| **Relative Humidity** | 92.3% (92–93%) | Average in `live_sensor_telemetry` | **92.3%** | **VERIFIED** (DB-backed) |
| **PIR Records Total** | 90 records | `live_pir_events` row count | **90** | **VERIFIED** (DB-backed) |
| **PIR Motion Event** | Sequence 19 | `live_pir_events` where `motion_detected = 1` | **Seq 19 (`uptime_ms`: 38000)** | **VERIFIED** (DB-backed) |
| **Statistical Alerts** | 190 alerts | `live_alerts` row count & Log line 58 | **190** | **VERIFIED** (DB & Log) |
| **Primary Burst Alerts** | 185 alerts | `live_alerts` where `dual_reason LIKE '%PRIMARY%'` | **185** | **VERIFIED** (DB-backed) |
| **Timing Jitter Alerts** | 5 alerts | `live_alerts` where `dual_reason LIKE '%TIMING%'` | **5** | **VERIFIED** (DB-backed) |
| **Normal Inlier Windows** | 27 windows | `live_traffic_windows` where `pred_dual = 1` | **27** | **VERIFIED** (DB-backed) |
| **Quiet Gated Windows** | 22 windows | `live_traffic_windows` where $N < 3$ | **22** | **VERIFIED** (DB-backed) |
| **Sniffer Session Boot ID** | 4199123527 | Runner Log line 30 | **4199123527** | **VERIFIED** (Log-only) |
| **Sniffer Handshake Nonce** | 3842178638 | Runner Log line 30 | **3842178638** | **VERIFIED** (Log-only) |

*All primary presentation numbers are 100% database-backed. Handshake nonces and sniffer boot IDs are verified via execution logs.*

---

## 3. Recommended Clarifications for Stage 7.3 Demonstration Documents

To ensure operational accuracy during presentation, the following clarifications should be incorporated into presenter notes:

1. **Explicit `--db-path` during Live Execution:**
   - In [`scratch/stage73_demo_checklist.md`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/scratch/stage73_demo_checklist.md), note that if the presenter desires an isolated live test without appending Run #7 to `data/live_monitoring.db`, they should pass `--db-path data/test_stage722_live_monitoring.db` (or a dedicated demo database). Running with default parameters appends to `data/live_monitoring.db`.
2. **Fallback Run Filter Selection:**
   - In [`scratch/stage73_demo_checklist.md`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/scratch/stage73_demo_checklist.md), note that selecting either `Latest Session` or `Run #1 (STOPPED)` in `data/test_stage722_live_monitoring.db` displays identical data because Run 1 is the sole run in that database.
3. **Log-Only Metrics:**
   - The exact sniffer boot ID (`4199123527`), request nonce (`3842178638`), and buffer overflow drops (`723`) originate from [`scratch/stage722_live_test.log`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/scratch/stage722_live_test.log), whereas all window, alert, and sensor metrics originate directly from SQLite tables.

---

## 4. Production Database Hash Integrity

Cryptographic verification confirms that **zero writes occurred during this audit**:

| Database File | Reference SHA-256 Hash | Current SHA-256 Hash | Status |
| :--- | :---: | :---: | :---: |
| [`data/live_monitoring.db`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/data/live_monitoring.db) | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | **MATCH (UNTOUCHED)** |
| [`data/iot_anomaly.db`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/data/iot_anomaly.db) | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | **MATCH (UNTOUCHED)** |

---

## 5. Summary Conclusion

The demonstration launch instructions and fallback procedures are **technically verified, safe, and ready for deployment**. The fallback procedure allows instant, 100% read-only presentation of physical experimental evidence without hardware dependency.

*(Auditing complete. Awaiting user instructions.)*

