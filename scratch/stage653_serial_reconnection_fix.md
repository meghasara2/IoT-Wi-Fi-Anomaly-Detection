# STAGE 6.5.3 — ESP32 SERIAL RECONNECTION AND PROBE HANDSHAKE REPORT

**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Target Files Modified:**
- `src/live_collector.py`
- `tests/test_serial_protocol.py`  
**Date:** 2026-11-10  
**Status:** COMPLETE & FULLY VERIFIED  

---

## 1. Root Cause Analysis (DEF-65-05, DEF-65-06)

During Stage 6.5 (*Collector Reliability and Device Registration Audit*), two major serial ingestion and reconnection defects were identified:

1. **Premature Permanent Termination after 20 Errors (DEF-65-05):**
   - In `LiveCollector._serial_loop()`, any port read or open failure incremented `consecutive_errors`.
   - When `consecutive_errors >= MAX_SERIAL_ERRORS (20)`, the code printed an error and executed a hard `break`.
   - Since `SERIAL_RECONNECT_DELAY = 5.0s`, if the ESP32 was unplugged, reflashed, or rebooted for longer than $20 \times 5 = 100$ seconds, the thread permanently terminated. Re-inserting the ESP32 USB cable never resumed ingestion.
2. **Missing Probe Handshake after Serial Connection (DEF-65-06):**
   - While `send_sniffer_probe()` and `_handle_sniffer_status()` were previously implemented, `_serial_loop()` never called `send_sniffer_probe(ser)` upon opening the COM port.
   - Consequently, the host collector never sent the `{"cmd":"probe","nonce":N}` command upon connection, leaving `active_boot_id` unconfirmed and rendering session validation passive rather than active.

---

## 2. Reconnection State Machine Architecture

The serial ingestion lifecycle was overhauled into a continuous reconnection loop with controlled backoff:

```
               +-------------------------------------------------------------+
               |                  START / RECOVERY CYCLE                     |
               +-------------------------------------------------------------+
                                              |
                                              v
                              +-------------------------------+
+---------------------------> |   Is Port Enumerated in OS?   | <-------------------------+
|                             +-------------------------------+                           |
|                                             |                                           |
|                                No           | Yes                                       |
|                                             v                                           |
|       +---------------------------------------------+   Open Error                      |
|       | Set _serial_reconnecting = True             |   (e.g., SerialException)         |
|       | Wait min(backoff, max_sec) on _stop_event   | <-----------------------------+   |
|       | Exponential backoff: delay *= 2             |                               |   |
|       +---------------------------------------------+                               |   |
|                                                                                     |   |
|                                                                                     |   |
|                                 +---------------------------------------------+     |   |
|                                 | serial.Serial(port, baudrate, timeout=3.0)  | ----+   |
|                                 +---------------------------------------------+         |
|                                                        |                                |
|                                                        | Success                        |
|                                                        v                                |
|                                 +---------------------------------------------+         |
|                                 | 1. Reset backoff = 2.0s                     |         |
|                                 | 2. Reset consecutive_errors = 0             |         |
|                                 | 3. Set _serial_connected = True             |         |
|                                 | 4. Flush input buffer                       |         |
|                                 | 5. Transmit sniffer probe:                  |         |
|                                 |    send_sniffer_probe(ser)                  |         |
|                                 +---------------------------------------------+         |
|                                                        |                                |
|                                                        v                                |
|                                 +---------------------------------------------+         |
|                                 |         Continuous Readline Loop            |         |
|                                 | - raw = ser.readline()                      |         |
|                                 | - process_serial_line(line)                 |         |
|                                 | - on SerialException / disconnect:          |         |
|                                 |   Close handle -> Re-enter backoff cycle    | --------+
|                                 +---------------------------------------------+
|                                                        |
|                                                        v
+------------------------------------------ Close Handle Safely --------------------------+
```

---

## 3. Capped Exponential Backoff Behavior

To prevent USB bus contention and excessive CPU spinning during sustained ESP32 power outages, capped exponential backoff was implemented:

- **Initial Backoff:** `serial_backoff_initial_sec = 2.0s`
- **Backoff Multiplier:** `serial_backoff_factor = 2.0`
- **Maximum Cap:** `serial_backoff_max_sec = 30.0s`
- **Progression:** $2.0\text{s} \to 4.0\text{s} \to 8.0\text{s} \to 16.0\text{s} \to 30.0\text{s} \to 30.0\text{s} \dots$
- **Reset on Connection:** Once `serial.Serial` succeeds and input buffer is flushed, `current_backoff` immediately resets to `serial_backoff_initial_sec` ($2.0\text{s}$).
- **Prompt Shutdown Interruption:** All sleep waits use `self._stop_event.wait(timeout=current_backoff)`. When `collector.stop()` is signaled, the backoff wait unblocks in milliseconds without waiting for the 30-second timer to expire.

---

## 4. Probe Handshake Implementation

Immediately following a successful COM port connection:
1. `_serial_loop()` executes:
   ```python
   try:
       self.send_sniffer_probe(ser)
   except Exception as probe_err:
       print(f"[SERIAL][WARN] Initial sniffer probe transmission failed: {probe_err}")
   ```
2. `send_sniffer_probe()` generates a random 32-bit request nonce, records `self._expected_probe_nonce`, and transmits `{"cmd": "probe", "nonce": <nonce>}\n` over the raw serial interface.
3. The ESP32 firmware parses this command and immediately replies:
   `{"status": "WIFI_SNIFFER_INITIALIZED", "boot_id": <boot_id>, "nonce": <nonce>, "channel": 6}\n`
4. The collector's `_handle_sniffer_status()` verifies nonce matching, records `self.active_boot_id`, and sets `self._session_established = True`.
5. If the ESP32 firmware is an older build that does not respond to probes, the read loop continues normally, processing sensor lines without crashing.

---

## 5. Session and Queue Handling Across Reboots

When an ESP32 is unplugged and rebooted, it generates a fresh, randomized `boot_id`:
1. **Invalidation of Pre-Reboot Events:**
   In `_handle_sniffer_status()`:
   ```python
   new_boot_id = payload.get("boot_id")
   if self.active_boot_id is not None and new_boot_id != self.active_boot_id:
       purged_count = 0
       while not self._wifi_mgmt_queue.empty():
           try:
               self._wifi_mgmt_queue.get_nowait()
               purged_count += 1
               self.stats["wifi_mgmt_stale_events"] += 1
           except Exception:
               break
   ```
2. **Double-Layer Filtering:**
   Even if an old frame escapes queue purging, `_drain_wifi_mgmt_queue()` in `_network_loop()` checks `item.get("boot_id") != self.active_boot_id` and drops it with `stats["wifi_mgmt_stale_events"] += 1`.
3. **Sequence Reset:**
   `self._seen_mgmt_sequences.clear()` resets sequence deduplication history, preventing sequence collisions between different ESP32 boot lifecycles.

---

## 6. Worker Health Integration (Stage 6.5.1 Alignment)

Stage 6.5.1 supervision invariants were preserved and enriched:
- **Degraded vs Dead Distinction:** When the serial port is disconnected or reconnecting, the worker thread is **alive**. `_heartbeat()` reports `status = 'RUNNING'` with an informative `stop_reason` (e.g., `"Serial port COM6 disconnected; reconnecting in 8.0s"`).
- **Genuinely Dead Worker Detection:** If `_serial_thread.is_alive()` returns `False` while sensors are enabled, `_heartbeat()` detects the terminated worker and sets `self._serial_worker_failed = True`.
- **Diagnostics API:** `get_worker_health()` exposes:
  `serial_worker_alive: bool`, `serial_connected: bool`, `serial_reconnecting: bool`, `current_serial_backoff: float`, and `serial_failure_reason`.

---

## 7. Files Modified

| File | Nature of Changes |
|:---|:---|
| `src/live_collector.py` | Added serial backoff configuration fields, updated `_heartbeat()` and `get_worker_health()`, added queue purge on boot ID transition in `_handle_sniffer_status()`, and replaced permanent 20-error termination in `_serial_loop()` with capped exponential backoff and automatic probe transmission. |
| `tests/test_serial_protocol.py` | Added `FakeSerialHandle`, `FakePortInfo`, and unit test suite `TestSerialReconnectionAndHandshakeStage653` covering all 13 regression scenarios. |

---

## 8. Regression Test Results

All 13 required scenarios were verified in `tests/test_serial_protocol.py`:

| # | Verified Requirement | Test Method | Result |
|:---:|:---|:---|:---:|
| 1 | Serial connection succeeds normally | `test_serial_connection_succeeds_and_probe_sent` | **PASSED** |
| 2 | Transient read error triggers reconnection without killing thread | `test_transient_read_error_does_not_terminate_worker` | **PASSED** |
| 3 | 20+ consecutive errors trigger reconnection rather than permanent termination | `test_twenty_plus_errors_trigger_reconnection_not_permanent_break` | **PASSED** |
| 4 | Reconnection succeeds after simulated port unplug and re-plug | `test_reconnection_succeeds_after_simulated_disconnection` | **PASSED** |
| 5 | Exponential backoff increases and caps at 30 seconds | `test_exponential_backoff_increases_and_caps_at_30s` | **PASSED** |
| 6 | Backoff resets to initial delay after successful reconnection | `test_backoff_resets_after_successful_reconnection` | **PASSED** |
| 7 | Stop event interrupts backoff promptly (<1s) | `test_stop_event_interrupts_backoff_promptly` | **PASSED** |
| 8 | Probe handshake is transmitted upon connection | `test_serial_connection_succeeds_and_probe_sent` | **PASSED** |
| 9 | Failed probe transmission is handled safely without crashing | `test_failed_probe_handshake_handled_safely` | **PASSED** |
| 10 | New boot ID purges stale queued events from prior session | `test_new_boot_id_invalidates_stale_session_events` | **PASSED** |
| 11 | Exactly one serial reader thread and single active handle exist | `test_no_duplicate_serial_connection_or_thread_created` | **PASSED** |
| 12 | Sensor and Wi-Fi event processing remains intact | `test_transient_read_error_does_not_terminate_worker` | **PASSED** |
| 13 | Worker supervision reports RUNNING with reconnecting reason | `test_worker_health_reflects_reconnecting_state` | **PASSED** |

### Execution Output:
```
python -m pytest tests/test_serial_protocol.py -v
============================= 18 passed in 11.78s =============================
```

---

## 9. Full Suite Results

All unit and integration test suites were executed across the workspace:

- `python -m pytest tests/test_serial_protocol.py`: **18 passed**
- `python -m pytest tests/test_live_collector.py`: **45 passed**
- `python -m pytest tests/test_live_collector_attack_integration.py`: **84 passed**
- `python -m pytest tests/test_live_device_registry.py`: **17 passed**
- `python -m pytest tests/test_attack_detector.py`: **63 passed**
- **Full Suite (`python -m pytest tests/`):**
  ```
  ============================ 370 passed in 30.11s =============================
  ```
  **100% PASS RATE ACROSS ALL 370 TESTS.**

---

## 10. Production Database Hash Verification

Both production databases were verified against baseline hashes and confirmed completely untouched:

| Database File | Expected SHA-256 Hash | Post-Test SHA-256 Hash | Status |
|:---|:---|:---|:---:|
| `data/live_monitoring.db` | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | `0475D1D32DFC4B2FC5AD950A8575C7D3E81E1AE810AAC6746764DECDE7D03EAB` | **MATCH (UNTOUCHED)** |
| `data/iot_anomaly.db` | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | `CA61FD5B306BF4E51B5B27B6DA81F2BE3B31C6F2132E4A25718F686C23ECF968` | **MATCH (UNTOUCHED)** |

---

## 11. Remaining Limitations

1. **Static COM Port Target:** The configured COM port (e.g. `COM6`) is searched during port enumeration. If Windows assigns a different COM port number (e.g., `COM7`) after re-plugging into a different physical USB port, the collector will not automatically switch ports unless reconfigured or restarted.
2. **Transient Sniffer Gap During Reboot:** Packets transmitted in the RF domain during the 2–3 seconds while the ESP32 is physically rebooting cannot be captured by the firmware. When reconnected, the probe handshake establishes the new boot ID, and live sniffer monitoring resumes cleanly.

---

## 12. Conclusion

Stage 6.5.3 is complete and verified. The collector now reliably survives transient serial disconnections and USB power drops, applies capped exponential backoff, initiates handshake probe synchronization upon every connection, and safely purges stale queued frames across ESP32 boot sessions.

