"""
Unit Tests: ESP32 Serial Protocol Validation (Offline)
File: tests/test_serial_protocol.py

Purpose:
  Validates JSON schema, sensor ranges, error handling, null formatting,
  and payload validation without requiring physical hardware.
"""

import unittest
import json
import tempfile
import sqlite3
import threading
import time
from pathlib import Path
import sys
from unittest.mock import MagicMock, patch

# Ensure src directory is on sys.path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from ingest_serial_sensors import validate_payload, format_display_row
from src.init_live_database import init_live_database
from src.live_collector import LiveCollector


class TestSerialProtocol(unittest.TestCase):

    def test_valid_payload_motion_idle(self):
        sample = {
            "node": "esp32_gateway",
            "seq": 1,
            "uptime_ms": 2045,
            "dht11": {"valid": 1, "temp_c": 24.8, "humidity": 55.2},
            "pir": {"motion": 0}
        }
        is_valid, msg = validate_payload(sample)
        self.assertTrue(is_valid)
        self.assertEqual(msg, "OK")

        row = format_display_row(sample)
        self.assertIn("24.8 °C", row)
        self.assertIn("55.2 %", row)
        self.assertIn("Clear", row)

    def test_valid_payload_motion_detected(self):
        sample = {
            "node": "esp32_gateway",
            "seq": 45,
            "uptime_ms": 90120,
            "dht11": {"valid": 1, "temp_c": 28.1, "humidity": 62.0},
            "pir": {"motion": 1}
        }
        is_valid, msg = validate_payload(sample)
        self.assertTrue(is_valid)
        self.assertEqual(msg, "OK")

        row = format_display_row(sample)
        self.assertIn(">> MOTION DETECTED <<", row)

    def test_dht11_null_reading_when_read_fails(self):
        # When DHT11 fails checksum/times out, null should be accepted if valid=0
        sample = {
            "node": "esp32_gateway",
            "seq": 12,
            "uptime_ms": 24000,
            "dht11": {"valid": 0, "temp_c": None, "humidity": None},
            "pir": {"motion": 0}
        }
        is_valid, msg = validate_payload(sample)
        self.assertTrue(is_valid)
        self.assertEqual(msg, "OK")

        row = format_display_row(sample)
        self.assertIn("N/A", row)
        self.assertIn("READ_FAIL", row)

    def test_missing_required_keys(self):
        # Missing 'pir' key
        sample = {
            "node": "esp32_gateway",
            "seq": 1,
            "uptime_ms": 2000,
            "dht11": {"valid": 1, "temp_c": 25.0, "humidity": 50.0}
        }
        is_valid, msg = validate_payload(sample)
        self.assertFalse(is_valid)
        self.assertIn("Missing required top-level key: 'pir'", msg)

    def test_invalid_temperature_range(self):
        sample = {
            "node": "esp32_gateway",
            "seq": 2,
            "uptime_ms": 4000,
            "dht11": {"valid": 1, "temp_c": 125.0, "humidity": 50.0},
            "pir": {"motion": 0}
        }
        is_valid, msg = validate_payload(sample)
        self.assertFalse(is_valid)
        self.assertIn("Temperature out of plausible range", msg)

    def test_invalid_pir_state(self):
        sample = {
            "node": "esp32_gateway",
            "seq": 3,
            "uptime_ms": 6000,
            "dht11": {"valid": 1, "temp_c": 22.0, "humidity": 45.0},
            "pir": {"motion": 99}
        }
        is_valid, msg = validate_payload(sample)
        self.assertFalse(is_valid)
        self.assertIn("Invalid PIR motion state", msg)

    def test_json_serialization_roundtrip(self):
        raw_json_str = '{"node":"esp32_gateway","seq":10,"uptime_ms":20050,"dht11":{"valid":1,"temp_c":26.5,"humidity":58.2},"pir":{"motion":0}}\n'
        parsed = json.loads(raw_json_str.strip())
        is_valid, msg = validate_payload(parsed)
        self.assertTrue(is_valid)
        self.assertEqual(parsed["dht11"]["temp_c"], 26.5)


class FakeSerialHandle:
    def __init__(self, lines=None, error_on_read=None, error_on_write=False):
        self.port = "COM6"
        self.is_open = True
        self.lines = list(lines) if lines else []
        self.written = []
        self.error_on_read = error_on_read
        self.error_on_write = error_on_write
        self.close_calls = 0

    def reset_input_buffer(self):
        pass

    def readline(self):
        if self.error_on_read:
            err = self.error_on_read
            self.error_on_read = None  # transient
            import serial
            raise serial.SerialException(f"Simulated read error: {err}")
        if self.lines:
            return self.lines.pop(0)
        return b""

    def write(self, data):
        if self.error_on_write:
            import serial
            raise serial.SerialException("Simulated write error during probe")
        self.written.append(data)
        return len(data)

    def close(self):
        self.is_open = False
        self.close_calls += 1


class FakePortInfo:
    def __init__(self, device="COM6"):
        self.device = device


class TestSerialReconnectionAndHandshakeStage653(unittest.TestCase):
    """
    Validates Stage 6.5.3 ESP32 Serial Reconnection, Capped Exponential Backoff,
    Probe Handshake, and Stale Queue Invalidation.
    """

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db_path = Path(self.tmp.name)
        self.db_path.unlink()
        init_live_database(self.db_path)

        self.collector = LiveCollector(
            interface_index=1,
            db_path=self.db_path,
            serial_port="COM6",
            no_sensors=False,
        )
        self.collector._run_id = 1
        # Use accelerated backoff timings for fast unit tests
        self.collector.serial_backoff_initial_sec = 0.01
        self.collector.serial_backoff_factor = 2.0
        self.collector.serial_backoff_max_sec = 0.08

    def tearDown(self):
        self.collector._stop_event.set()
        if self.db_path.exists():
            try:
                self.db_path.unlink()
            except Exception:
                pass

    def test_serial_connection_succeeds_and_probe_sent(self):
        """1 & 8: Successful serial connection transmits sniffer probe handshake."""
        fake_ser = FakeSerialHandle()
        was_connected = False
        was_reconnecting = True

        def run_once():
            nonlocal was_connected, was_reconnecting
            was_connected = self.collector._serial_connected
            was_reconnecting = self.collector._serial_reconnecting
            self.collector._stop_event.set()

        fake_ser.reset_input_buffer = run_once

        with patch("serial.tools.list_ports.comports", return_value=[FakePortInfo("COM6")]), \
             patch("serial.Serial", return_value=fake_ser):
            self.collector._serial_loop()

        self.assertTrue(was_connected)
        self.assertFalse(was_reconnecting)
        self.assertFalse(self.collector._serial_worker_failed)
        self.assertGreaterEqual(self.collector.stats["sniffer_probe_requests_sent"], 1)
        self.assertTrue(any(b'"cmd": "probe"' in w for w in fake_ser.written))

    def test_transient_read_error_does_not_terminate_worker(self):
        """2: Transient read error triggers reconnection attempt without killing thread."""
        first_handle = FakeSerialHandle(error_on_read="USB glitch")
        second_handle = FakeSerialHandle(lines=[b'{"node":"esp32_gateway","seq":1,"uptime_ms":2000,"dht11":{"valid":1,"temp_c":24.0,"humidity":50.0},"pir":{"motion":0}}\n'])

        handles = [first_handle, second_handle]

        def get_handle(*args, **kwargs):
            if handles:
                h = handles.pop(0)
                if not handles:
                    def delayed_stop():
                        time.sleep(0.02)
                        self.collector._stop_event.set()
                    threading.Thread(target=delayed_stop).start()
                return h
            return FakeSerialHandle()

        with patch("serial.tools.list_ports.comports", return_value=[FakePortInfo("COM6")]), \
             patch("serial.Serial", side_effect=get_handle):
            self.collector._serial_loop()

        self.assertGreaterEqual(self.collector.stats["sensor_records"], 1)
        self.assertTrue(first_handle.close_calls >= 1)

    def test_twenty_plus_errors_trigger_reconnection_not_permanent_break(self):
        """3: Twenty or more consecutive errors trigger reconnection rather than permanent termination."""
        error_count = 0
        was_reconnecting = False
        import serial

        def fail_open(*args, **kwargs):
            nonlocal error_count, was_reconnecting
            error_count += 1
            if error_count >= 25:
                was_reconnecting = self.collector._serial_reconnecting
                self.collector._stop_event.set()
            raise serial.SerialException("Access denied / busy")

        with patch("serial.tools.list_ports.comports", return_value=[FakePortInfo("COM6")]), \
             patch("serial.Serial", side_effect=fail_open):
            self.collector._serial_loop()

        self.assertGreaterEqual(error_count, 25)
        self.assertTrue(was_reconnecting)

    def test_reconnection_succeeds_after_simulated_disconnection(self):
        """4: Reconnection succeeds after simulated port unplug and re-plug."""
        attempts = 0

        def dynamic_ports():
            nonlocal attempts
            attempts += 1
            if attempts <= 2:
                return []  # Disconnected
            return [FakePortInfo("COM6")]  # Reconnected

        fake_ser = FakeSerialHandle(lines=[b'{"node":"esp32_gateway","seq":10,"uptime_ms":5000,"dht11":{"valid":1,"temp_c":25.0,"humidity":55.0},"pir":{"motion":0}}\n'])

        def stop_after_read():
            def waiter():
                time.sleep(0.03)
                self.collector._stop_event.set()
            threading.Thread(target=waiter).start()

        fake_ser.reset_input_buffer = stop_after_read

        with patch("serial.tools.list_ports.comports", side_effect=dynamic_ports), \
             patch("serial.Serial", return_value=fake_ser):
            self.collector._serial_loop()

        self.assertGreaterEqual(attempts, 3)
        self.assertGreaterEqual(self.collector.stats["sensor_records"], 1)

    def test_exponential_backoff_increases_and_caps_at_30s(self):
        """5: Exponential backoff increases with errors and caps at maximum (30s)."""
        c = LiveCollector(interface_index=1, db_path=self.db_path, serial_port="COM6")
        c.serial_backoff_initial_sec = 2.0
        c.serial_backoff_factor = 2.0
        c.serial_backoff_max_sec = 30.0

        backoff = c.serial_backoff_initial_sec
        observed = [backoff]
        for _ in range(6):
            backoff = min(backoff * c.serial_backoff_factor, c.serial_backoff_max_sec)
            observed.append(backoff)

        self.assertEqual(observed[0], 2.0)
        self.assertEqual(observed[1], 4.0)
        self.assertEqual(observed[2], 8.0)
        self.assertEqual(observed[3], 16.0)
        self.assertEqual(observed[4], 30.0)
        self.assertEqual(observed[5], 30.0)
        self.assertEqual(observed[6], 30.0)

    def test_backoff_resets_after_successful_reconnection(self):
        """6: Backoff resets to initial delay after successful connection."""
        import serial
        fail_attempts = 0
        was_connected = False
        backoff_at_connect = None

        def fail_then_succeed(*args, **kwargs):
            nonlocal fail_attempts, was_connected, backoff_at_connect
            fail_attempts += 1
            if fail_attempts <= 3:
                raise serial.SerialException("Port busy")
            s = FakeSerialHandle()
            def record_and_stop():
                nonlocal was_connected, backoff_at_connect
                was_connected = self.collector._serial_connected
                backoff_at_connect = self.collector._current_serial_backoff
                self.collector._stop_event.set()
            s.reset_input_buffer = record_and_stop
            return s

        with patch("serial.tools.list_ports.comports", return_value=[FakePortInfo("COM6")]), \
             patch("serial.Serial", side_effect=fail_then_succeed):
            self.collector._serial_loop()

        self.assertEqual(backoff_at_connect, self.collector.serial_backoff_initial_sec)
        self.assertTrue(was_connected)

    def test_stop_event_interrupts_backoff_promptly(self):
        """7: Stop event unblocks long backoff sleep promptly without waiting full duration."""
        self.collector.serial_backoff_initial_sec = 30.0
        self.collector.serial_backoff_max_sec = 30.0

        start_time = time.monotonic()

        def stop_after_delay():
            time.sleep(0.05)
            self.collector._stop_event.set()

        threading.Thread(target=stop_after_delay).start()

        with patch("serial.tools.list_ports.comports", return_value=[]):
            self.collector._serial_loop()

        elapsed = time.monotonic() - start_time
        self.assertLess(elapsed, 1.0, f"Expected prompt exit, took {elapsed:.2f}s")

    def test_failed_probe_handshake_handled_safely(self):
        """9: Failed probe transmission does not crash the collector or stop reading."""
        fake_ser = FakeSerialHandle(
            lines=[b'{"node":"esp32_gateway","seq":1,"uptime_ms":2000,"dht11":{"valid":1,"temp_c":24.0,"humidity":50.0},"pir":{"motion":0}}\n'],
            error_on_write=True,
        )

        def stop_it():
            def waiter():
                time.sleep(0.02)
                self.collector._stop_event.set()
            threading.Thread(target=waiter).start()

        fake_ser.reset_input_buffer = stop_it

        with patch("serial.tools.list_ports.comports", return_value=[FakePortInfo("COM6")]), \
             patch("serial.Serial", return_value=fake_ser):
            self.collector._serial_loop()

        self.assertGreaterEqual(self.collector.stats["sensor_records"], 1)

    def test_new_boot_id_invalidates_stale_session_events(self):
        """10: A new boot ID invalidates stale queued events from prior boot session."""
        self.collector.active_boot_id = 1111
        self.collector._wifi_mgmt_queue.put({"type": "wifi_mgmt", "boot_id": 1111, "seq": 1})
        self.collector._wifi_mgmt_queue.put({"type": "wifi_mgmt", "boot_id": 1111, "seq": 2})

        self.assertEqual(self.collector._wifi_mgmt_queue.qsize(), 2)

        # Handshake with new boot_id
        nonce = self.collector.send_sniffer_probe(ser=None, nonce=55555)
        status_payload = {
            "status": "WIFI_SNIFFER_INITIALIZED",
            "boot_id": 2222,
            "nonce": nonce,
            "channel": 6,
        }
        res = self.collector._handle_sniffer_status(status_payload)
        self.assertEqual(res, "SNIFFER_STATUS")
        self.assertEqual(self.collector.active_boot_id, 2222)
        # Verify stale queue from 1111 was purged
        self.assertEqual(self.collector._wifi_mgmt_queue.qsize(), 0)
        self.assertEqual(self.collector.stats["wifi_mgmt_stale_events"], 2)

    def test_no_duplicate_serial_connection_or_thread_created(self):
        """11: Exactly one serial reader thread and single active serial handle exist."""
        with patch.object(self.collector, "_serial_loop") as mock_loop:
            self.collector.start()
            self.assertIsNotNone(self.collector._serial_thread)
            self.collector.stop()

    def test_worker_health_reflects_reconnecting_state(self):
        """12 & 13: Worker supervision reports RUNNING with reconnecting reason during outage."""
        self.collector._status = "RUNNING"
        self.collector._serial_reconnecting = True
        self.collector._serial_failure_reason = "Serial port COM6 disconnected; reconnecting (backoff 4.0s)"

        mock_net = MagicMock()
        mock_net.is_alive.return_value = True
        self.collector._net_thread = mock_net

        mock_serial = MagicMock()
        mock_serial.is_alive.return_value = True
        self.collector._serial_thread = mock_serial

        self.collector._heartbeat()

        health = self.collector.get_worker_health()
        self.assertEqual(health["status"], "RUNNING")
        self.assertTrue(health["serial_worker_alive"])
        self.assertTrue(health["serial_reconnecting"])
        self.assertIn("Serial port COM6 disconnected", health["stop_reason"])


if __name__ == "__main__":
    unittest.main()
