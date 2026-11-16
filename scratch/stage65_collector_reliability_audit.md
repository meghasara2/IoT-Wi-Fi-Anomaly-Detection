# STAGE 6.5 — COLLECTOR RELIABILITY AND DEVICE REGISTRATION AUDIT REPORT

**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Workspace:** `C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection`  
**Date:** November 10, 2026  
**Type:** Strictly Read-Only Architecture and Reliability Audit  
**Status:** Audit Completed  

---

## 1. Executive Summary & Overall Reliability Verdict

This audit performs a forensic, strictly read-only evaluation of the live telemetry ingestion daemon (`src/live_collector.py`), the streaming packet extractor (`src/live_stream_extractor.py`), the database synchronization layer (`src/init_live_database.py`), and their integration with the operational dashboard (`src/live_dashboard.py`).

### Overall Reliability Verdict: **CONDITIONALLY ROBUST / ARCHITECTURALLY VULNERABLE TO SILENT FAILURES**

- **Core Strengths:**
  - The feature engineering, Isolation Forest scoring, multi-window timing math, and deterministic attack heuristics are strictly decoupled, thread-safe, and empirically validated (342/342 passing tests).
  - SQLite WAL mode and the 10.0-second busy timeout prevent reader-writer lock starvation with the live Streamlit dashboard.
  - Wi-Fi management queue (`maxsize=256`) and packet observation buffers (`maxsize=5000`) are bounded and non-blocking, protecting against memory exhaustion during traffic spikes.
- **Critical Vulnerabilities & Reliability Deficits:**
  1. **Static Device Registry Loading:** The device registry is loaded exactly once at startup. Devices added or updated in `device_registry` during runtime are never recognized without restarting the daemon.
  2. **Silent Worker Thread Death & Ghost Running State:** If the TShark packet reader or serial ingestion thread crashes or terminates unexpectedly, the main collector loop continues running and updating its heartbeat as `RUNNING` every 10 seconds. The dashboard displays green health while telemetry ingestion has silently halted.
  3. **Permanent Serial Abandonment after 20 Errors:** If the ESP32 USB cable is unplugged for $>100$ seconds, the serial thread breaks out of its loop and permanently terminates. It never reconnects even if the hardware is restored.
  4. **Uncalled Sniffer Probe Handshake:** The `send_sniffer_probe()` handshake method is defined in `LiveCollector` but is never invoked upon serial port reconnection.
  5. **Heartbeat Overwrites Error Status:** If a worker thread catches an unhandled exception and marks `status="ERROR"`, the main loop's `_heartbeat()` blindly overwrites `status="RUNNING"` 10 seconds later.
  6. **Zero Test Coverage for Daemon Resilience:** No unit or integration tests exist for process recovery, serial reconnect backoff, thread liveness monitoring, or dynamic registry reloading.

---

## 2. Device Registration and Registry Refresh

### 2.1 How Registered Devices Are Loaded
In `src/live_collector.py` (`LiveCollector.start()`, lines 824–845):
```python
# Sync persisted device_registry from SQLite into collector registry
try:
    db_sync = get_live_db_connection(self.db_path)
    try:
        for row in db_sync.execute(
            "SELECT mac_address, node_id, device_type, label FROM device_registry"
        ).fetchall():
            mac = row["mac_address"].lower().strip()
            if mac not in self.device_registry:
                self.device_registry[mac] = {
                    "node_id": row["node_id"],
                    "device_type": row["device_type"] or "Phone_Client",
                    "label": row["label"] or "real_observed_traffic",
                }
    finally:
        db_sync.close()
except Exception as e:
    print(f"[COLLECTOR][WARN] Could not load device_registry from DB: {e}")

self.attack_detector.set_known_devices(set(self.device_registry.keys()))
```
The dictionary is then passed into `LiveStreamExtractor(device_registry=self.device_registry)` at line 1554. In `LiveStreamExtractor.__init__()` (line 462):
```python
self.registry: Dict[str, Dict[str, str]] = (
    device_registry if device_registry is not None
    else dict(DEFAULT_DEVICE_REGISTRY)
)
```

### 2.2 Runtime Visibility of Newly Registered Devices
- **Audit Finding:** **CONFIRMED DEFECT.**
- **Details:** The query against SQLite executes **once** during `collector.start()`. Neither `LiveCollector._network_loop()` nor `LiveStreamExtractor` polls or checks `device_registry` during runtime.
- **Operational Consequence:** If an operator or automated procedure inserts a new device (e.g. Node 5 / Phone 3) into `device_registry` via the database or dashboard while the collector is running, the collector **never sees it**. Its packets continue to be classified as `unregistered`, and observations are repeatedly upserted into `unknown_device_obs`. It will not generate 1-second feature windows in `live_traffic_windows` until the collector daemon is fully restarted.

### 2.3 Unknown-Device Recording
- **Audit Finding:** **IMPLEMENTED AND VERIFIED.**
- **Details:** In `src/live_stream_extractor.py` (lines 627–636), any packet whose MAC or IP is not found in `self.registry` is recorded via `_record_unknown_mac(pkt.eth_src)`.
- In `src/live_collector.py` (lines 1594–1598), `extractor.drain_unregistered_macs()` flushes the thread-safe set to `_upsert_unknown_device()`.
- The SQLite query executes:
  ```sql
  INSERT INTO unknown_device_obs (run_id, observed_mac)
  VALUES (?, ?)
  ON CONFLICT(run_id, observed_mac) DO UPDATE
      SET observation_count = observation_count + 1,
          last_seen_utc = CURRENT_TIMESTAMP
  ```
- This correctly tracks distinct unknown devices per monitoring session without redundant row inflation.

### 2.4 Duplicate MAC/IP Registrations
- **Audit Finding:** **IMPLEMENTED AND VERIFIED.**
- **Details:** In `src/init_live_database.py`, `device_registry` defines `mac_address TEXT PRIMARY KEY`.
- `register_device()` uses `INSERT INTO ... ON CONFLICT(mac_address) DO UPDATE`, updating `node_id`, `device_type`, `label`, and `notes`.
- Duplicate IP collisions across distinct MAC addresses are not rejected by the registry schema (as IPs change with DHCP), but are instead actively monitored by `SpoofingDetector` in `src/attack_detector.py`.

### 2.5 Device Removal or MAC Changes
- **Audit Finding:** **STALE IN-MEMORY STATE.**
- **Details:** If a device is deleted from `device_registry` in SQLite while the collector runs, the collector retains the MAC in `self.device_registry` and `extractor.registry`. It will continue attributing its traffic to the deleted node ID until daemon restart.

### 2.6 Smallest Safe Correction for Runtime Refresh
To enable zero-downtime device registration without race conditions:
1. In `src/live_stream_extractor.py`, add a thread-safe method `update_registry(new_registry: Dict[str, Dict[str, str]])` that swaps `self.registry` atomically under an existing or dedicated lock.
2. In `src/live_collector.py`, add `_refresh_device_registry(db: sqlite3.Connection)` invoked periodically (e.g., every 30 feature windows / ~30 seconds) in `_network_loop()`.
3. Synchronize `self.attack_detector.set_known_devices(set(self.device_registry.keys()))`.

---

## 3. Serial Reader Reliability

### 3.1 Behavior After a Single Read Error
- **Audit Finding:** **IMPLEMENTED AND VERIFIED.**
- **Details:** In `src/live_collector.py` (`_serial_loop()`, lines 1923–1966):
  A single `serial.SerialException` (e.g. transient USB voltage drop or bus read timeout) is caught by `except serial.SerialException as e:`.
  `ser.close()` is executed in `finally:`.
  The loop waits for `SERIAL_RECONNECT_DELAY = 5.0s` and re-attempts connection on the next iteration.

### 3.2 Behavior After Consecutive Errors & 20-Error Permanent Break
- **Audit Finding:** **CONFIRMED DEFECT (PREMATURE TERMINATION).**
- **Details:** Line 178 sets `MAX_SERIAL_ERRORS = 20`. Lines 1950–1960:
  ```python
  except serial.SerialException as e:
      consecutive_errors += 1
      print(f"[SERIAL][ERROR] Port error ({consecutive_errors}/{MAX_SERIAL_ERRORS}): {e}")
      if consecutive_errors >= MAX_SERIAL_ERRORS:
          print("[SERIAL] Max errors reached — disabling serial thread.")
          self._update_status(
              "RUNNING",
              stop_reason=f"Serial disabled after {MAX_SERIAL_ERRORS} errors",
          )
          break
      self._stop_event.wait(timeout=SERIAL_RECONNECT_DELAY)
  ```
- **Consequence:** Since `SERIAL_RECONNECT_DELAY = 5.0s`, $20 \times 5\text{s} = 100$ seconds. If the ESP32 is unplugged or undergoing firmware flashing for $>100$ seconds, the serial reader hits `break`, terminates `_serial_loop()`, and the thread permanently dies.
- Re-connecting the ESP32 after 2 minutes will **never** restore serial ingestion. The collector must be manually killed and restarted.

### 3.3 Reconnection After USB Disconnection
- **Audit Finding:** **IMPLEMENTED FOR SHORT OUTAGES (<100s) ONLY.**
- **Details:** Lines 1913–1920 verify port presence using `serial.tools.list_ports.comports()`. If the port is absent, it waits 5.0s and continues. However, each failed check increments `consecutive_errors` when `SerialException` occurs on open, burning down the 20-error budget.

### 3.4 Detection of Terminated Reader Thread
- **Audit Finding:** **CONFIRMED DEFECT (ZERO SUPERVISION).**
- **Details:** When `_serial_loop()` breaks and terminates, line 1956 calls:
  `self._update_status("RUNNING", stop_reason="Serial disabled after 20 errors")`.
  Notice that `status` remains `"RUNNING"`.
  More critically, the main thread's `run_until_stopped()` loop only checks `not self._stop_event.is_set()`. It **never** inspects `self._serial_thread.is_alive()`.
  Every 10 seconds, `_heartbeat()` updates `last_heartbeat = CURRENT_TIMESTAMP`.
  The process reports healthy `RUNNING` status indefinitely with a dead serial worker.

### 3.5 Boot ID and Sniffer Probe Reconnection Handshake
- **Audit Finding:** **CONFIRMED DEFECT (DEAD CODE / NEVER CALLED).**
- **Details:** Lines 1687–1704 implement `send_sniffer_probe(ser, nonce)`.
  However, `send_sniffer_probe()` is **never called anywhere** in `_serial_loop()` or `LiveCollector.start()`.
  Upon opening `serial.Serial()`, the loop only calls `ser.reset_input_buffer()` and waits for incoming lines.
  If the ESP32 was already running before the collector started (or reconnected without an ESP32 hardware reset), the ESP32 does not spontaneously re-send `WIFI_SNIFFER_INITIALIZED`.
  Consequently, `self.active_boot_id` remains `None`, bypassing boot ID session correlation.

### 3.6 Handling of Queued Wi-Fi Events During Disconnection
- **Audit Finding:** **IMPLEMENTED AND VERIFIED.**
- **Details:** Events already enqueued in `self._wifi_mgmt_queue` continue to be drained by the network thread. When a new session connects with a different `boot_id`, line 1533 rejects old-session events (`wifi_mgmt_stale_events`).

### 3.7 Resource Cleanup on Shutdown
- **Audit Finding:** **IMPLEMENTED AND VERIFIED.**
- **Details:** `ser.close()` is guaranteed in the `finally:` block (lines 1966–1971), and `self._serial_thread.join(timeout=5)` ensures thread reclamation on collector shutdown.

---

## 4. TShark and Network Reader Reliability

### 4.1 Unexpected TShark Subprocess Exit
- **Audit Finding:** **CONFIRMED DEFECT (SILENT UNHANDLED TERMINATION).**
- **Details:** In `src/live_stream_extractor.py` (line 598):
  `for raw_line in stdout:`
  If the `tshark` subprocess crashes, is killed by Windows task manager, or the Mobile Hotspot adapter disables itself, `stdout` encounters EOF.
  The `for` loop terminates normally.
  Lines 659–663 flush the remaining partial bins and `iter_windows()` raises `StopIteration`.
- In `src/live_collector.py` (`_network_loop()`, lines 1565–1684):
  `for window in extractor.iter_windows():` completes normally.
  No exception is thrown.
  The code skips the `except Exception as e:` crash handler and executes:
  ```python
  finally:
      extractor.stop()
      print("[NET] TShark stream stopped.")
  ```
  `_network_loop()` returns and `_net_thread` terminates cleanly from Python's perspective.

### 4.2 Failure Detection by Collector Daemon
- **Audit Finding:** **CONFIRMED DEFECT (UNSUPERVISED PROCESS FAILURE).**
- **Details:** `_stop_event` was not set, and `self._update_status("ERROR")` was never invoked.
- In `LiveCollector.run_until_stopped()` (lines 956–960):
  ```python
  while not self._stop_event.is_set():
      self._heartbeat()
      time.sleep(HEARTBEAT_INTERVAL_SEC)
  ```
  The main thread has no idea `_net_thread` has died. It continues sleeping, waking up every 10 seconds to update `collector_status` with `status='RUNNING'` and `last_heartbeat=CURRENT_TIMESTAMP`.
- The collector becomes a "zombie" daemon: packet ingestion has completely halted, no new traffic windows are generated, no alerts are produced, yet the database claims it is running live.

### 4.3 Automatic Restart
- **Audit Finding:** **MISSING CAPABILITY.**
- **Details:** No subprocess restart loop exists in `LiveStreamExtractor` or `LiveCollector`. Any transient TShark crash is fatal to network monitoring for the remainder of the session.

### 4.4 Subprocess Handle and Pipe Release
- **Audit Finding:** **IMPLEMENTED AND VERIFIED.**
- **Details:** `LiveStreamExtractor.stop()` (lines 520–533) explicitly calls `terminate()`, waits up to 5 seconds, and falls back to `kill()`, setting `self._proc = None`.

### 4.5 Risk of Duplicate TShark Processes
- **Audit Finding:** **IMPLEMENTED AND VERIFIED (NO DUPLICATION RISK).**
- **Details:** Because automatic restart is absent, duplicate TShark instances cannot be spawned. If restart logic is added in the future, it must strictly call `self.stop()` before re-initializing `self._proc`.

---

## 5. Queue and Memory Management

### 5.1 Queue Size Limits & Backpressure
- **Audit Finding:** **IMPLEMENTED AND BOUNDED.**
  - `_wifi_mgmt_queue = queue.Queue(maxsize=256)` (line 740).
  - `max_packet_buffer = 5000` (lines 447, 469).
  - `_seen_mgmt_sequences` bounded at 10,000 entries (line 1759).
  - Dedup caches (`_port_scan_dedup_cache`, `_dos_dedup_cache`, `_spoofing_dedup_cache`, `_deauth_dedup_cache`) bounded at 100 entries each, pruned when exceeded.

### 5.2 Behavior on Full Queues
- **Audit Finding:** **IMPLEMENTED AND VERIFIED (NON-BLOCKING DROP).**
  - For `_wifi_mgmt_queue` (lines 1762–1770):
    ```python
    try:
        payload["_recv_epoch"] = time.time()
        self._wifi_mgmt_queue.put_nowait(payload)
    except queue.Full:
        self.stats["wifi_mgmt_queue_dropped"] += 1
        print("[SERIAL][WARN] Wi-Fi mgmt queue full (256 items); event dropped.")
    ```
    The serial thread is never blocked by a slow network thread.
  - For `_recent_packet_observations` (lines 610–618):
    When size reaches 5,000, excess packets are sliced from the front (`del self._recent_packet_observations[:excess]`), `_dropped_packet_count` is incremented, and `_telemetry_degraded` is set to `True`.

### 5.3 Collection Expiration and Memory Leaks
- **Audit Findings:**
  1. `ReplayDetector._seen_payloads`: Cleaned every evaluation. Entries older than `replay_history_window_seconds` (60.0s) are deleted; empty keys are deleted via `del self._seen_payloads[k]`. **(Verified bounded)**
  2. `SpoofingDetector._ip_to_mac_binding`: Cleaned when count $\ge 1000$ via `_cleanup_stale_bindings()`. **(Verified bounded)**
  3. `DoSDetector._history`: Trimmed to `self._history[mac][-10:]`. **(Verified bounded)**
  4. `PortScanDetector._history` & `DeauthDetector._history`:
     - **Minor Defect:** In both detectors, records older than window duration are filtered out (`self._history[src] = active_records`), but when `active_records` is empty, the dictionary key is **not** deleted. In long-running production with thousands of transient IP scans, empty dictionary keys accumulate in memory.
  5. `LiveStreamExtractor._bins`:
     - **Minor Defect:** If a registered device transmits in second $T$ and disconnects, `self._bins[mac]` is never flushed until `extractor.stop()`. However, since registered devices are restricted to known nodes, maximum memory overhead is capped by the number of registered clients ($<10$).

---

## 6. Collector Lifecycle

### 6.1 Partial Startup Failures
- **Audit Finding:** **PARTIALLY HANDLED / INCONSISTENT ERROR STATE.**
- **Details:**
  - If `session1_csv` is missing, `load_frozen_dual_detector()` raises `FileNotFoundError` synchronously in `start()`, halting the daemon cleanly.
  - If `db_path` cannot be created, `init_live_database()` raises synchronously.
  - **However:** If `tshark` fails to start inside `_net_thread` (e.g. invalid interface index), `_network_loop()` catches `Exception`, prints a traceback, and calls `_update_status("ERROR", stop_reason=...)`. But `LiveCollector.start()` has already completed and returned control to `main()`.

### 6.2 Thread Monitoring & Heartbeat Health Representation
- **Audit Finding:** **CONFIRMED DEFECT (BLIND HEARTBEAT OVERWRITES ERROR).**
- **Details:** Look at line 994 in `src/live_collector.py`:
  ```python
  def _heartbeat(self) -> None:
      self._update_status("RUNNING")
  ```
  And `run_until_stopped()`:
  ```python
  while not self._stop_event.is_set():
      self._heartbeat()
      time.sleep(HEARTBEAT_INTERVAL_SEC)
  ```
  Every 10 seconds, `_heartbeat()` unconditionally executes `UPDATE collector_status SET status='RUNNING'`.
- Even if `_network_loop()` crashed on startup and marked `status='ERROR'`, 10 seconds later `_heartbeat()` overwrites `status='RUNNING'`.
- There is **no thread health verification** prior to emitting a heartbeat.

---

## 7. SQLite Reliability

### 7.1 SQLite Connection Lifecycle & Thread Isolation
- **Audit Finding:** **IMPLEMENTED AND VERIFIED.**
- **Details:** Connections are strictly thread-isolated. No connection object is shared between Thread 1 (`_network_loop`), Thread 2 (`_serial_loop`), or the Main Thread (`_heartbeat`).
- Each write opens a short-lived connection via `get_live_db_connection()`, executes its statement with a 10.0s busy timeout, commits, and closes immediately in a `finally:` block.

### 7.2 WAL Mode & Concurrent Dashboard Access
- **Audit Finding:** **IMPLEMENTED AND VERIFIED.**
- **Details:** `get_live_db_connection()` enforces `PRAGMA journal_mode = WAL;` and `PRAGMA synchronous = NORMAL;`.
- WAL mode allows concurrent readers (Streamlit dashboard via `?mode=ro`) to query tables without blocking daemon write transactions.

### 7.3 Failed Write Handling & Silent Dropping
- **Audit Finding:** **CONFIRMED DEFECT / RELIABILITY GAP.**
- **Details:** In `_network_loop()` (lines 1670–1672):
  ```python
  except Exception as e:
      print(f"[NET][ERROR] DB write failed: {e}")
  ```
  And in `_serial_loop()` (lines 1877–1878):
  ```python
  except Exception as e:
      print(f"[SERIAL][ERROR] DB write failed: {e}")
  ```
  If SQLite encounters a disk I/O error or lock timeout, the exception is caught and printed to stdout.
  The scored traffic window, its anomaly alert, and all evaluated attack events are **permanently dropped**. There is no disk spillover, write-ahead buffer, or retry queue.

---

## 8. Dashboard and Collector Failure Consistency

### 8.1 Dead Worker Reflection on Dashboard
- **Audit Finding:** **CONFIRMED DEFECT (FALSE OPERATIONAL VISIBILITY).**
- **Details:**
  - In Stage 6.4.2, the dashboard was updated to verify heartbeat freshness: if `last_heartbeat` is $>60\text{s}$ old, status overrides to `MONITORING UNAVAILABLE (Collector heartbeat stale)`.
  - However, because `run_until_stopped()` keeps emitting fresh heartbeats even when `_net_thread` is dead, `last_heartbeat` remains $<10\text{s}$ old.
  - The dashboard queries `collector_status`, observes `status='RUNNING'` with a fresh timestamp, and continues reporting `NO ALERT OBSERVED` for DoS, Port Scan, and Spoofing based on the stale windows in the database.
  - An operator monitoring the screen has zero indication that packet capture halted hours ago.

---

## 9. Existing Test Coverage and Gaps

| Component / Scenario | Audit Classification | Existing Test File | Gap Details |
| :--- | :--- | :--- | :--- |
| **Device Registry Seed & Idempotency** | Implemented & verified | `tests/test_live_device_registry.py` | Verified across 8 test functions. |
| **Unknown Device Logging** | Implemented & verified | `tests/test_live_collector.py` | Verified insert + increment on conflict. |
| **Runtime Registry Reload** | **Missing** | None | Zero tests verify dynamic registry updates while collector is running. |
| **Serial Payload Routing** | Implemented & verified | `tests/test_live_collector_attack_integration.py` | Verified boot, summary, mgmt, sensor routing. |
| **Serial Disconnect & Reconnect** | **Missing** | None | No tests simulate USB drop and recovery. |
| **Serial 20-Error Permanent Break** | **Confirmed defect / Untested** | None | Untested failure mode leading to thread termination. |
| **Sniffer Probe Handshake** | Implemented but insufficiently tested | `tests/test_live_collector_attack_integration.py` | Handshake tested in isolation; probe transmission in `_serial_loop` omitted. |
| **TShark Process Crash / Pipe EOF** | **Confirmed defect / Untested** | None | No tests simulate TShark subprocess exit. |
| **Thread Liveness in Heartbeat** | **Confirmed defect / Untested** | None | No tests verify heartbeat status when workers crash. |
| **SQLite WAL & Busy Timeout** | Implemented & verified | `tests/test_live_collector.py` | Pragma verified. |
| **Failed Write Retry / Buffer** | **Architectural limitation** | None | Dropped writes not buffered or retried. |
| **Dashboard Status Accuracy** | Implemented & verified | `tests/test_live_dashboard.py` | 12 tests verify Stage 6.4.2 status card rules. |

---

## 10. Confirmed Defects with Source Locations

| Defect ID | Defect Summary | Severity | Exact Source Location |
| :--- | :--- | :--- | :--- |
| **DEF-65-01** | **Static Registry:** Device registry never reloaded at runtime; new devices remain unknown until collector restart. | **HIGH** | `src/live_collector.py`: lines 826–845; `src/live_stream_extractor.py`: line 462, lines 620–636. |
| **DEF-65-02** | **Silent Network Thread Death:** TShark exit causes `_net_thread` to terminate cleanly on EOF without setting `_stop_event` or error status. | **CRITICAL** | `src/live_collector.py`: lines 1565–1568, 1673–1684; `src/live_stream_extractor.py`: line 598. |
| **DEF-65-03** | **Unsupervised Worker Threads in Heartbeat:** `_heartbeat()` blindly sends `RUNNING` every 10s without verifying worker thread liveness, masking dead workers from the dashboard. | **CRITICAL** | `src/live_collector.py`: lines 956–960, lines 994–996. |
| **DEF-65-04** | **Heartbeat Overwrites Error Status:** Blind heartbeat overwrites `status='ERROR'` set by crashed threads back to `status='RUNNING'`. | **HIGH** | `src/live_collector.py`: line 995, lines 1678–1681. |
| **DEF-65-05** | **Permanent Serial Disabling:** 20 consecutive serial errors ($100\text{s}$) breaks the loop and kills the serial thread permanently. | **HIGH** | `src/live_collector.py`: lines 178, lines 1954–1960. |
| **DEF-65-06** | **Uncalled Sniffer Probe Handshake:** `send_sniffer_probe()` is never called in `_serial_loop()` upon port connection, leaving `active_boot_id` uninitialized if ESP32 does not reboot. | **MEDIUM** | `src/live_collector.py`: lines 1687–1705, lines 1923–1933. |
| **DEF-65-07** | **Silent Discard of Failed DB Writes:** Transient database errors catch and print, dropping feature windows, alerts, and attack events without retry. | **MEDIUM** | `src/live_collector.py`: lines 1670–1672, lines 1877–1878. |
| **DEF-65-08** | **Empty History Keys in Detectors:** `PortScanDetector` and `DeauthDetector` retain empty list keys in `_history` dictionary indefinitely. | **LOW** | `src/attack_detector.py`: `PortScanDetector.evaluate`, `DeauthDetector.evaluate`. |

---

## 11. Prioritized Correction Roadmap

To resolve these defects in future implementation stages, the following prioritized roadmap is recommended:

### Priority 1: Worker Liveness Supervision and Honest Heartbeat (Resolves DEF-65-02, DEF-65-03, DEF-65-04)
- **Proposed Correction:**
  1. In `LiveCollector._heartbeat()`, inspect worker thread liveness:
     ```python
     net_alive = self._net_thread is not None and self._net_thread.is_alive()
     serial_alive = self._serial_thread is not None and self._serial_thread.is_alive() if not self.no_sensors else True

     if not net_alive:
         self._update_status("ERROR", stop_reason="Network reader thread terminated unexpectedly")
         return
     if not serial_alive:
         self._update_status("DEGRADED", stop_reason="Serial reader thread terminated")
         return
     self._update_status("RUNNING")
     ```
  2. In `LiveCollector._network_loop()`, check `if not self._stop_event.is_set():` after `iter_windows()` finishes. If stopped unexpectedly, record `self._update_status("ERROR", stop_reason="TShark stream closed unexpectedly")`.
- **Files to Modify:** `src/live_collector.py`.
- **Potential Regression Risks:** Very low. Directly enforces operational honesty.

### Priority 2: Dynamic Device Registry Refresh (Resolves DEF-65-01)
- **Proposed Correction:**
  1. Add `LiveStreamExtractor.update_registry(new_reg: Dict[str, Dict[str, str]])` with thread-safe pointer swap.
  2. In `LiveCollector._network_loop()`, call `_sync_device_registry()` every 30 feature windows (~30s). Re-query SQLite, update `self.device_registry`, `extractor.update_registry()`, and `attack_detector.set_known_devices()`.
- **Files to Modify:** `src/live_collector.py`, `src/live_stream_extractor.py`.
- **Potential Regression Risks:** Low. Must ensure atomic dictionary swap so packet attribution during iteration does not encounter runtime dictionary mutation errors.

### Priority 3: Persistent Serial Reconnection & Probe Handshake (Resolves DEF-65-05, DEF-65-06)
- **Proposed Correction:**
  1. Remove hard `break` on `consecutive_errors >= MAX_SERIAL_ERRORS`. Instead, cap retry delay with backoff (e.g. max 30s) and continue retrying indefinitely, marking serial status as degraded rather than killing the thread.
  2. Call `self.send_sniffer_probe(ser)` immediately after `ser.reset_input_buffer()` upon connection to establish `active_boot_id`.
- **Files to Modify:** `src/live_collector.py`.
- **Potential Regression Risks:** Low. Must ensure probe write does not block serial thread.

### Priority 4: Bounded DB Write Retry Buffer (Resolves DEF-65-07)
- **Proposed Correction:**
  Implement a small bounded buffer (e.g. `collections.deque(maxlen=50)`) for unwritten windows/alerts. If a write fails with `sqlite3.OperationalError: database is locked`, queue the item and retry on the next window before dropping.
- **Files to Modify:** `src/live_collector.py`.
- **Potential Regression Risks:** Moderate. Must ensure memory remains strictly bounded.

---

## 12. Production Database Hash Verification

Both production databases were cryptographically verified before and after the audit to ensure strictly read-only execution:

| Database File | Initial SHA256 Hash | Post-Audit SHA256 Hash | Integrity Status |
| :--- | :--- | :--- | :--- |
| `data/live_monitoring.db` | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | **MATCH (UNTOUCHED)** |
| `data/iot_anomaly.db` | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | **MATCH (UNTOUCHED)** |

---

## 13. Stop Condition & Approval Request

This concludes the Stage 6.5 audit. In strict accordance with user safety instructions:
- **No production code, tests, models, or database schemas were modified.**
- **No live collector, TShark, COM6 serial, or Streamlit processes were launched.**
- **No attack traffic was transmitted.**

Awaiting user review and authorization before proceeding with any implementation or subsequent stages.

