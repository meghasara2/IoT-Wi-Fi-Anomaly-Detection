# Stage 6.5.4 & 6.5.4.1 — Bounded Database Write Reliability & SQLite Busy Timeout Correction Report

**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Stages:** Stage 6.5.4 (Bounded Database Write Reliability) & Stage 6.5.4.1 (SQLite Busy Timeout Correction)  
**Date:** 2026-11-10  
**Status:** COMPLETE & VERIFIED (384/384 tests passing)

---

## 1. Exact Files Modified

1. **`src/live_collector.py`**
   - Added `is_transient_db_lock_error()` predicate to selectively target transient SQLite lock/busy errors.
   - Updated database write helpers (`_insert_traffic_window`, `_insert_alert`, `_insert_attack_event`, `_upsert_unknown_device`, `_insert_sensor_telemetry`) with optional `commit: bool = True` parameter (preserving 100% backward compatibility for existing callers and tests).
   - Added bounded retry attributes to `LiveCollector.__init__`: `db_max_retries = 2`, `db_retry_initial_delay_sec = 0.05`, `db_retry_backoff_factor = 2.0`, and `db_busy_timeout_ms = 250`.
   - Added diagnostic observability counters to `self.stats`: `db_transient_write_retries`, `db_window_write_failures`, `db_sensor_write_failures`.
   - Updated `_persist_attack_results()` to accept `commit: bool = True` and `pending_dedup_actions: Optional[List[Any]] = None`, ensuring that in-memory attack cooldown caches are only updated **after** the database transaction successfully commits.
   - Implemented `_persist_window_transaction()` and `_persist_window_with_retry()` to atomically encapsulate `live_traffic_windows`, `device_registry.last_seen`, `live_alerts`, `unknown_device_obs`, and `live_attack_events` within a single SQLite transaction with clean rollback on error.
   - **Stage 6.5.4.1 Correction:** In `_persist_window_with_retry()` and `_persist_sensor_with_retry()`, immediately executed `db.execute(f"PRAGMA busy_timeout = {int(self.db_busy_timeout_ms)};")` on every newly opened connection inside the managed `try...finally` block, ensuring safe closure if the PRAGMA fails.
   - Implemented `_persist_sensor_with_retry()` to safely encapsulate DHT11 and PIR persistence with bounded transient retry and deduplication protection.
   - Updated `_network_loop()` and `process_serial_line()` to invoke the atomic retry mechanisms and increment `windows_emitted` and `sensor_records` strictly upon confirmed commit.

2. **`tests/test_database_reliability.py`**
   - Created a comprehensive 14-test suite exercising:
     - Transient SQLite lock followed by recovery.
     - Persistent lock exhausting retries.
     - Non-transient errors failing fast without retry.
     - Atomic rollback when alert insertion fails.
     - Zero duplicate rows after retry.
     - Accurate `windows_emitted` and `sensor_records` counters under failure and recovery.
     - Resilient sensor telemetry ingestion.
     - Attack cooldown consistency across failure/recovery.
     - Worker thread supervision intactness.
     - **Stage 6.5.4.1:** Verified `PRAGMA busy_timeout = 250` is configured on every connection for window persistence.
     - **Stage 6.5.4.1:** Verified `PRAGMA busy_timeout = 250` is configured on every connection for sensor persistence.
     - **Stage 6.5.4.1:** Verified failure while setting PRAGMA is handled safely and closes the connection.
     - **Stage 6.5.4.1:** Verified real SQLite database file lock timing (no mocks) is strictly bounded to $\approx 0.8\text{s} - 1.5\text{s}$ rather than 30+ seconds.

---

## 2. Transaction, Retry & Timeout Architecture

### A. Atomic Window Persistence Boundary
Previously, `_insert_traffic_window`, `_insert_alert`, and each `_insert_attack_event` called `conn.commit()` independently. If an error occurred between inserting the window and inserting the alert/attack event, the window row was committed while the anomaly alert was dropped, causing dashboard metric desynchronization.

Under Stage 6.5.4:
- All writes for a given 1-second window are executed within `_persist_window_transaction(conn, ..., commit=False)`.
- If all statements succeed, `conn.commit()` commits the entire batch atomically.
- If any statement or the commit fails, `conn.rollback()` rolls back the entire batch.
- In-memory cooldown actions (e.g. updating `_dos_dedup_cache`, `_spoofing_dedup_cache`) are deferred and applied **only after `conn.commit()` succeeds**.

### B. SQLite Busy Timeout Calibration (Stage 6.5.4.1)
Default connections created via `get_live_db_connection()` inherit SQLite's default busy timeout of 10.0 seconds (`timeout=10.0`). Under persistent external locks, retrying with new connections multiplied this timeout ($3 \times 10\text{s} = 30\text{s}$).

Stage 6.5.4.1 overrides the busy timeout on every newly created writer connection:
```python
db = get_live_db_connection(self.db_path)
try:
    db.execute(f"PRAGMA busy_timeout = {int(self.db_busy_timeout_ms)};")  # 250 ms
```
- Each attempt now waits at most **$250\text{ms}$** for a lock before raising `OperationalError: database is locked`.
- Handled safely inside the `try...finally` block so the connection is cleanly closed if the PRAGMA execution fails.

### C. Sensor Telemetry Persistence
- `_insert_sensor_telemetry()` writes logical Node_1 (DHT11) and Node_2 (PIR) rows within a single transaction.
- In `process_serial_line()`, `_persist_sensor_with_retry()` applies bounded retry ($50\text{ms} \to 100\text{ms}$) with the $250\text{ms}$ PRAGMA.
- Preserves existing `UNIQUE(run_id, physical_node_id, sequence_num)` with `INSERT OR IGNORE`, mathematically guaranteeing zero duplicate rows.
- Increments `sensor_records` strictly upon successful commit.

---

## 3. Expected Timing and Maximum Blocking Behavior

- **Configured SQLite Wait Budget:** $3 \text{ attempts} \times 250\text{ms} = \mathbf{750\text{ms}}$.
- **Application Backoff Budget:** $50\text{ms} + 100\text{ms} = \mathbf{150\text{ms}}$.
- **Total Configured Maximum:** $\mathbf{900\text{ms}}$ (excluding Python scheduling, OS process context switching, connection setup/teardown, and disk I/O latency).
- **Non-Real-Time Qualification:** Because Windows is a non-real-time operating system with periodic background indexing and filesystem latency, actual wall-clock elapsed time under continuous lock is observed between $\approx 0.8\text{s}$ and $1.5\text{s}$. It is strictly bounded well below the previous $30.15\text{s}$ duration.
- **Window & Serial Cadence Budget:** A total blocking duration of $\sim 900\text{ms}$ fits comfortably within the 1-second network window and serial baud budget, preventing UART or pipe buffer overruns.
- **Interruption Safety:** All backoff delays use `self._stop_event.wait(timeout=current_delay)`, guaranteeing immediate termination upon shutdown signal.

---

## 4. Test Verification Results

### Unit & Integration Test Suites
- `python -m pytest tests/test_database_reliability.py`: **14 passed in 4.47s**
- `python -m pytest tests/test_live_collector.py`: **45 passed in 4.33s**
- `python -m pytest tests/test_live_collector_attack_integration.py`: **84 passed in 16.18s**
- `python -m pytest tests/test_live_device_registry.py`: **17 passed**
- `python -m pytest tests/test_attack_detector.py`: **63 passed**
- `python -m pytest tests/test_serial_protocol.py`: **18 passed**

### Complete Test Suite
- `python -m pytest tests/`: **384 passed in 33.57s (100% passing across all 19 test modules)**.

---

## 5. Remaining Limitations

1. **Persistent External Lockout:**
   - If an external process (e.g. an un-sandboxed SQLite browser or external backup script) holds an exclusive table lock continuously for $>900\text{ms}$, all 3 attempts will exhaust. Under this condition, the collector drops the window and records `db_window_write_failures += 1`, preserving worker thread liveness rather than blocking the packet stream or serial reader indefinitely.
2. **Read-Only SQLite URI:**
   - If the database file is placed on a read-only filesystem, writes fail immediately (non-transient error) and are logged without retries.

---

## 6. Production Database Integrity Verification

SHA-256 hashes of the production databases were verified before and after implementation:

| Database File | Established Baseline Hash | Post-Implementation Hash | Status |
| :--- | :--- | :--- | :---: |
| `data/live_monitoring.db` | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | **MATCH (UNTOUCHED)** |
| `data/iot_anomaly.db` | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | **MATCH (UNTOUCHED)** |
