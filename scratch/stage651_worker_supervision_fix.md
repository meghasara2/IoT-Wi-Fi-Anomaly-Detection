# STAGE 6.5.1 — COLLECTOR WORKER SUPERVISION AND HEARTBEAT CORRECTION REPORT

**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**File Modified:** `src/live_collector.py`  
**Test Suite Modified:** `tests/test_live_collector.py`  
**Date:** 2026-11-10  
**Status:** COMPLETE & VERIFIED  

---

## 1. Executive Summary

During Stage 6.5 (*Collector Reliability and Device Registration Audit*), multiple critical worker lifecycle and status supervision defects were identified in `src/live_collector.py`:
1. **Silent Network Worker Termination (DEF-65-02):** If the network worker thread (`_network_loop`) encountered EOF from TShark or terminated normally while capture was meant to be active (`_stop_event.is_set() == False`), it exited without setting an error flag, allowing the collector process to falsely appear operational.
2. **Heartbeat Status Overwrite (DEF-65-03, DEF-65-04):** The periodic collector heartbeat (`_heartbeat()`) blindly executed `self._update_status("RUNNING")` every 10 seconds, immediately overwriting established `ERROR` states and failing to inspect whether `_net_thread` or `_serial_thread` were actually alive.
3. **Serial Worker Failure Misrepresentation (DEF-65-05):** When serial port errors exceeded `MAX_SERIAL_ERRORS`, `_serial_loop` called `_update_status("RUNNING", stop_reason=...)`, which permanently disabled the serial worker without health supervision and was vulnerable to being wiped out by subsequent blind heartbeats.

In Stage 6.5.1, thread-safe worker supervision, state transition protection, and worker liveness monitoring were implemented in `src/live_collector.py`. Nine dedicated unit and integration regression tests were added to `tests/test_live_collector.py`. All 45 tests in `test_live_collector.py` and all 350 tests across the full project test suite pass with 100% compliance. Both production databases (`data/live_monitoring.db` and `data/iot_anomaly.db`) remain untouched.

---

## 2. Root Cause Analysis

### 2.1 Silent Network Worker Termination (TShark EOF / Stream Exit)
- **Location:** `LiveCollector._network_loop()`
- **Mechanism:** `LiveStreamExtractor.iter_windows()` yields 1-second aggregated traffic windows. When the underlying `tshark` subprocess terminates, crashes, or closes stdout, `iter_windows()` reaches end-of-iteration (EOF) and cleanly exits the `for window in extractor.iter_windows():` loop.
- **Defect:** Prior to this fix, the loop termination did not check whether `self._stop_event.is_set()` was True. Because no Python exception was raised by an EOF generator exit, execution simply proceeded to the `finally:` block and returned. The thread died, no error was written, and the collector remained in `status = 'RUNNING'`.

### 2.2 Blind Heartbeat Status Overwrite
- **Location:** `LiveCollector._heartbeat()`
- **Mechanism:** The heartbeat thread runs every 10 seconds, invoking `self._heartbeat()`.
- **Defect:** `_heartbeat()` formerly consisted of a single call: `self._update_status("RUNNING")`. Even if `_network_loop()` or an unhandled exception had previously marked `collector_status` as `ERROR`, the very next 10-second heartbeat blindly updated SQLite with `status = 'RUNNING'` and `stop_reason = NULL`. Additionally, `_heartbeat()` never inspected `self._net_thread.is_alive()`, meaning a dead worker thread was never discovered.

### 2.3 Serial Worker Failure Misrepresentation
- **Location:** `LiveCollector._serial_loop()`
- **Mechanism:** When 3 consecutive serial errors occurred (`MAX_SERIAL_ERRORS`), the thread logged an error and executed `self._update_status("RUNNING", stop_reason=f"Serial disabled after {MAX_SERIAL_ERRORS} errors")` before breaking out of the loop.
- **Defect:** The status remained `RUNNING`, but `stop_reason` was ephemeral—it was erased by the next `_heartbeat()` call. If serial failed unexpectedly through any other path, no status or reason was recorded, and `_heartbeat()` had no awareness of serial worker health.

---

## 3. Exact Code Changes in `src/live_collector.py`

### 3.1 Worker State and Lock Initialization (`LiveCollector.__init__`)
Added internal tracking flags and a reentrant/thread lock to manage lifecycle state transitions safely:

```python
        # Worker supervision and status tracking (Stage 6.5.1)
        self._status: str = "STARTING"
        self._stop_reason: Optional[str] = None
        self._status_lock = threading.Lock()
        self._net_worker_failed: bool = False
        self._serial_worker_failed: bool = False
        self._net_failure_reason: Optional[str] = None
        self._serial_failure_reason: Optional[str] = None
```

### 3.2 Resetting Status Under Lock on Start (`LiveCollector.start`)
Guarantees clean status initialization when starting a capture run:

```python
            self._run_id = cur.lastrowid
            with self._status_lock:
                self._status = "STARTING"
                self._stop_reason = None
                self._net_worker_failed = False
                self._serial_worker_failed = False
                self._net_failure_reason = None
                self._serial_failure_reason = None
            with self._dedup_lock:
                self._dedup_cache.clear()
```

### 3.3 Explicit Shutdown Marking (`LiveCollector.stop`)
Signals shutdown and sets state to `STOPPED` under lock before joining threads:

```python
    def stop(self, reason: str = "User requested stop") -> None:
        """Signals both threads to stop and waits for clean shutdown."""
        print(f"\n[COLLECTOR] Stopping: {reason}")
        self._stop_event.set()
        with self._status_lock:
            self._status = "STOPPED"
            self._stop_reason = reason

        if self._net_thread and self._net_thread.is_alive():
            self._net_thread.join(timeout=10)

        if self._serial_thread and self._serial_thread.is_alive():
            self._serial_thread.join(timeout=5)

        self._update_status("STOPPED", stop_reason=reason)
        self._print_final_stats()
```

### 3.4 Protected Status Updates & Heartbeat Worker Supervision
Separated raw DB writes into `_persist_status_locked()` and guarded `_update_status()` and `_heartbeat()` with strict transition validation:

```python
    def _persist_status_locked(self, status: str, stop_reason: Optional[str] = None) -> None:
        """Writes current status and statistics to collector_status in SQLite. Must be called with _status_lock held."""
        if self._run_id is None:
            return
        try:
            db = get_live_db_connection(self.db_path)
            try:
                db.execute(
                    """
                    UPDATE collector_status
                    SET status=?, stop_reason=?,
                        packets_parsed=?, windows_emitted=?, sensor_records=?,
                        last_heartbeat=CURRENT_TIMESTAMP
                    WHERE run_id=?
                    """,
                    (
                        status,
                        stop_reason,
                        self.stats["packets_parsed"],
                        self.stats["windows_emitted"],
                        self.stats["sensor_records"],
                        self._run_id,
                    ),
                )
                db.commit()
            finally:
                db.close()
        except Exception:
            pass  # Never let DB errors crash the collector

    def _update_status(self, status: str, stop_reason: Optional[str] = None) -> None:
        """
        Thread-safely updates collector status, protecting against invalid transitions
        (e.g., overwriting established ERROR or STOPPED state with RUNNING).
        """
        with self._status_lock:
            if self._status == "ERROR" and status == "RUNNING":
                return
            if self._status == "STOPPED" and status == "RUNNING":
                return

            self._status = status
            self._stop_reason = stop_reason
            self._persist_status_locked(status, stop_reason)

    def _heartbeat(self) -> None:
        """
        Inspects worker health and updates collector_status.
        Enforces:
          - Never overwrites an established ERROR or STOPPED state with RUNNING.
          - Detects silent network worker failure (e.g. TShark EOF / crash) and transitions to ERROR.
          - Detects serial worker failure and accurately reflects it in stop_reason.
          - Only reports RUNNING when required worker health conditions are satisfied.
        """
        with self._status_lock:
            # 1. Protection: If shutdown was requested or already STOPPED, preserve STOPPED
            if self._stop_event.is_set() or self._status == "STOPPED":
                if self._status != "STOPPED":
                    self._status = "STOPPED"
                    self._persist_status_locked("STOPPED", self._stop_reason or "Shutdown requested")
                return

            # 2. Protection: If already in ERROR state, preserve ERROR and refresh timestamp/stats
            if self._status == "ERROR" or self._net_worker_failed:
                self._status = "ERROR"
                err_reason = self._net_failure_reason or self._stop_reason or "Critical worker failure"
                self._stop_reason = err_reason
                self._persist_status_locked("ERROR", err_reason)
                return

            # 3. Supervise Network Worker Liveness
            # Network worker is critical: if it was started and is now dead, transition to ERROR
            if self._net_thread is not None and not self._net_thread.is_alive():
                err_reason = self._net_failure_reason or "Network worker thread terminated unexpectedly"
                self._net_worker_failed = True
                self._net_failure_reason = err_reason
                self._status = "ERROR"
                self._stop_reason = err_reason
                self._persist_status_locked("ERROR", err_reason)
                return

            # 4. Supervise Serial Worker Liveness (when sensors are enabled)
            if not self.no_sensors:
                if self._serial_thread is not None and not self._serial_thread.is_alive():
                    self._serial_worker_failed = True
                    if not self._serial_failure_reason:
                        self._serial_failure_reason = "Serial worker thread terminated unexpectedly"

            # 5. Both required health checks passed -> Report RUNNING
            # Accurately reflect serial worker status in stop_reason if it failed
            effective_stop_reason = self._serial_failure_reason if self._serial_worker_failed else None
            self._status = "RUNNING"
            self._stop_reason = effective_stop_reason
            self._persist_status_locked("RUNNING", effective_stop_reason)

    def get_worker_health(self) -> Dict[str, Any]:
        """
        Returns a snapshot of worker thread health and collector status.
        Thread-safe.
        """
        with self._status_lock:
            net_alive = self._net_thread is not None and self._net_thread.is_alive()
            serial_alive = (
                self._serial_thread is not None and self._serial_thread.is_alive()
                if not self.no_sensors else True
            )
            return {
                "status": self._status,
                "stop_reason": self._stop_reason,
                "net_worker_alive": net_alive,
                "serial_worker_alive": serial_alive,
                "net_worker_failed": self._net_worker_failed,
                "serial_worker_failed": self._serial_worker_failed,
                "net_failure_reason": self._net_failure_reason,
                "serial_failure_reason": self._serial_failure_reason,
                "is_shutdown_requested": self._stop_event.is_set(),
            }
```

### 3.5 Detecting Unexpected Network Stream Exit in `_network_loop`
```python
            # Check if iter_windows exited unexpectedly while shutdown was NOT requested (e.g. TShark EOF)
            if not self._stop_event.is_set():
                err_msg = "Network worker terminated unexpectedly (TShark stream closed)"
                print(f"[NET][ERROR] {err_msg}")
                with self._status_lock:
                    self._net_worker_failed = True
                    self._net_failure_reason = err_msg
                    self._status = "ERROR"
                    self._stop_reason = err_msg
                    self._persist_status_locked("ERROR", err_msg)
```

### 3.6 Accurate Serial Worker Failure Retention in `_serial_loop`
```python
                if consecutive_errors >= MAX_SERIAL_ERRORS:
                    err_msg = f"Serial worker disabled after {MAX_SERIAL_ERRORS} consecutive errors: {e}"
                    print(f"[SERIAL] {err_msg}")
                    with self._status_lock:
                        self._serial_worker_failed = True
                        self._serial_failure_reason = err_msg
                        if self._status != "ERROR":
                            self._stop_reason = err_msg
                            self._persist_status_locked(self._status, err_msg)
                    break
```

---

## 4. Thread-Safe State Transition Table

The state machine enforced by `_status_lock` guarantees deterministic behavior:

| Current State | Event / Trigger | Next State | Next `stop_reason` | Allowed? | Rationale |
|:---|:---|:---|:---|:---|:---|
| `STARTING` | Worker threads spawned | `RUNNING` | `None` | Yes | Normal capture initiation |
| `RUNNING` | `_heartbeat()` (workers alive) | `RUNNING` | `None` (or serial err) | Yes | Worker health confirmed |
| `RUNNING` | TShark stream ends (`EOF`) | `ERROR` | `"Network worker terminated..."` | Yes | Critical worker loss detected |
| `RUNNING` | Network thread died | `ERROR` | `"Network worker thread..."` | Yes | Detected by `_heartbeat()` |
| `RUNNING` | Serial max errors reached | `RUNNING` | `"Serial worker disabled..."` | Yes | Network capture continues, degraded serial noted |
| `RUNNING` | User calls `stop()` | `STOPPED` | Reason given by caller | Yes | Intentional operator shutdown |
| `ERROR` | `_heartbeat()` | `ERROR` | Preserved error reason | Overwrite blocked | **Defect fix:** Heartbeat refreshes stats but NEVER overwrites ERROR with RUNNING |
| `ERROR` | User calls `stop()` | `STOPPED` | Reason given by caller | Yes | Operator teardown from error state |
| `STOPPED` | `_heartbeat()` | `STOPPED` | Preserved stop reason | Overwrite blocked | Heartbeat ignores stopped session |

---

## 5. Verification and Test Results

### 5.1 Stage 6.5.1 Regression Tests in `tests/test_live_collector.py`
The test class `TestCollectorWorkerSupervisionStage651` implements tests verifying all 9 required scenarios:

| Test Name | Verified Scenario | Result |
|:---|:---|:---:|
| `test_scenario1_and_2_network_worker_unexpected_exit_tshark_eof` | 1 & 2: Network worker unexpected exit (TShark EOF) transitions status to `ERROR` and persists reason to SQLite. | **PASSED** |
| `test_scenario3_heartbeat_does_not_overwrite_error` | 3: `_heartbeat()` preserves `ERROR` and never overwrites with `RUNNING`. | **PASSED** |
| `test_scenario4_intentional_shutdown_avoids_false_error` | 4: `stop()` cleanly marks `STOPPED` and subsequent heartbeats do not raise false `ERROR`. | **PASSED** |
| `test_scenario5_dead_network_thread_detected_by_heartbeat` | 5: Dead `_net_thread` (`is_alive() == False`) is detected by `_heartbeat()` and transitions status to `ERROR`. | **PASSED** |
| `test_scenario6_serial_worker_failure_represented_accurately` | 6: Serial failure is captured in `stop_reason` and `get_worker_health()` without being overwritten. | **PASSED** |
| `test_scenario7_healthy_workers_maintain_running` | 7: Healthy workers maintain `RUNNING` and write timely heartbeats. | **PASSED** |
| `test_scenario8_repeated_heartbeats_preserve_state` | 8: Repeated heartbeat invocations preserve `ERROR`, `STOPPED`, and `RUNNING` states consistently. | **PASSED** |
| `test_scenario9_update_status_lock_protection` | 9: `_update_status` lock guards against invalid out-of-order state overwrites. | **PASSED** |

### 5.2 Unit Test Execution
```
python -m pytest tests/test_live_collector.py -v
============================= 45 passed in 4.21s ==============================
```

### 5.3 Full Project Regression Suite
All 350 automated tests in the workspace pass without errors:
```
python -m pytest tests/
============================ 350 passed in 18.55s =============================
```

---

## 6. Database Integrity Verification

SHA-256 hashes of the production databases were verified before and after the implementation:

| Database File | Expected SHA-256 Hash | Post-Test SHA-256 Hash | Status |
|:---|:---|:---|:---:|
| `data/live_monitoring.db` | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | **MATCH (UNTOUCHED)** |
| `data/iot_anomaly.db` | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | **MATCH (UNTOUCHED)** |

---

## 7. Remaining Limitations and Scope Boundary

1. **Automatic Worker Restart:** Stage 6.5.1 adds worker supervision and accurate failure persistence; it does not automatically respawn `tshark` if it crashes. If TShark exits, the collector transitions to `ERROR`, allowing the operator or external supervisor (e.g. systemd/Windows service) to detect failure and initiate recovery.
2. **Dynamic Device Registration Reloading:** As analyzed in Stage 6.5 audit, reloading device registry changes without restarting the collector is a separate reliability item.
3. **Serial Reconnection Cap:** Once `MAX_SERIAL_ERRORS` is reached, serial polling ceases permanently for the session. Reconnecting the physical USB port requires restarting the collector session.

---

## 8. Conclusion

Stage 6.5.1 has successfully resolved silent worker failures and heartbeat status overwriting in `src/live_collector.py`. The collector now reliably detects and reports worker crashes, protects error states, and maintains full compatibility with downstream dashboard and attack detection systems.

