"""
Serial Sensor Listener
File: src/ingest_serial_sensors.py

Purpose:
  Connects to the ESP32 USB-to-UART bridge on COM6 at 115200 baud,
  receives newline-delimited JSON telemetry, validates sensor data,
  and renders a clean, real-time telemetry console in the terminal.

Scope & Safety:
  - Terminal-only display.
  - Does NOT write to SQLite or alter dashboard files.
  - Requires pyserial (installed separately).
"""

import sys
import json
import time
from typing import Optional, Dict, Any

DEFAULT_PORT = "COM6"
DEFAULT_BAUD = 115200


def validate_payload(data: Dict[str, Any]) -> tuple[bool, str]:
    """
    Validates the structure, required fields, and ranges of incoming JSON sensor data.
    """
    # Check top-level structure
    required_keys = ["node", "seq", "uptime_ms", "dht11", "pir"]
    for k in required_keys:
        if k not in data:
            return False, f"Missing required top-level key: '{k}'"

    # Validate DHT11 object
    dht = data["dht11"]
    if not isinstance(dht, dict) or "valid" not in dht or "temp_c" not in dht or "humidity" not in dht:
        return False, "Malformed 'dht11' block"

    if dht["valid"] == 1:
        temp = dht["temp_c"]
        hum = dht["humidity"]
        if temp is None or hum is None:
            return False, "DHT11 marked valid but values are null"
        if not (-10.0 <= temp <= 60.0):
            return False, f"Temperature out of plausible range: {temp} °C"
        if not (0.0 <= hum <= 100.0):
            return False, f"Humidity out of plausible range: {hum} %"

    # Validate PIR object
    pir = data["pir"]
    if not isinstance(pir, dict) or "motion" not in pir:
        return False, "Malformed 'pir' block"
    if pir["motion"] not in (0, 1):
        return False, f"Invalid PIR motion state (expected 0 or 1): {pir['motion']}"

    return True, "OK"


def format_display_row(data: Dict[str, Any]) -> str:
    """
    Formats parsed telemetry into a readable terminal row.
    """
    seq = data.get("seq", 0)
    uptime_sec = data.get("uptime_ms", 0) / 1000.0

    dht = data.get("dht11", {})
    if dht.get("valid") == 1:
        temp_str = f"{dht.get('temp_c'):>5.1f} °C"
        hum_str = f"{dht.get('humidity'):>5.1f} %"
        dht_status = "VALID"
    else:
        temp_str = "  N/A   "
        hum_str = "  N/A  "
        dht_status = "READ_FAIL"

    pir = data.get("pir", {})
    motion = pir.get("motion", 0)
    motion_str = ">> MOTION DETECTED <<" if motion == 1 else "   Clear (No Motion)"

    return (
        f"[{seq:>5}] Uptime: {uptime_sec:>6.1f}s | "
        f"DHT11: {temp_str} | Hum: {hum_str} [{dht_status}] | "
        f"PIR: {motion_str}"
    )


def run_serial_listener(port: str = DEFAULT_PORT, baud: int = DEFAULT_BAUD, max_records: Optional[int] = None):
    """
    Main loop to read from serial port and stream verified readings.
    """
    try:
        import serial
        import serial.tools.list_ports
    except ImportError:
        print("\n" + "!" * 75)
        print("ERROR: 'pyserial' package is not installed.")
        print("To install pyserial, run:")
        print("    pip install pyserial")
        print("!" * 75 + "\n")
        sys.exit(1)

    print("=" * 80)
    print("ESP32 HARDWARE SENSOR TELEMETRY LISTENER (PHASE A)")
    print(f"Target Port: {port} | Baud Rate: {baud}")
    print("=" * 80)
    print("\nCRITICAL PRE-CHECK:")
    print("  Make sure the Arduino IDE 'Serial Monitor' or 'Serial Plotter' is CLOSED.")
    print("  Only one program can access the COM port at a time.\n")

    # Check if target port exists
    available_ports = [p.device for p in serial.tools.list_ports.comports()]
    if port not in available_ports:
        print(f"WARNING: {port} was not found in active Windows COM ports.")
        print(f"Available ports: {available_ports}")
        print("Please verify the USB cable is firmly connected and check Device Manager.")
        print("Retrying connection...\n")

    ser = None
    try:
        ser = serial.Serial(port=port, baudrate=baud, timeout=2.5)
        # Flush initial boot garble / partial bytes
        ser.reset_input_buffer()
        print(f"Successfully connected to {port}. Listening for JSON telemetry stream...\n")
        print("-" * 80)
        print(f"{'Seq':<7} {'Uptime':<12} {'Temperature':<18} {'Humidity':<17} {'PIR Motion State'}")
        print("-" * 80)

        record_count = 0
        while True:
            raw_line = ser.readline()
            if not raw_line:
                # Timeout occurred with no data
                print("... waiting for sensor stream (no data received in 2.5s) ...")
                continue

            try:
                line_str = raw_line.decode("utf-8", errors="replace").strip()
            except Exception as e:
                print(f"[ERROR] Decoding raw bytes failed: {e}")
                continue

            # Ignore empty lines or startup comments
            if not line_str:
                continue
            if line_str.startswith("{") and not line_str.endswith("}"):
                print(f"[WARN] Incomplete packet line received: {line_str}")
                continue

            try:
                payload = json.loads(line_str)
            except json.JSONDecodeError:
                # Non-JSON status lines emitted by firmware setup or bootloader
                if "ESP32_TELEMETRY_INITIALIZED" in line_str:
                    print(f"[INFO] Hardware Boot Announcement: {line_str}")
                else:
                    print(f"[RAW UNPARSED]: {line_str}")
                continue

            # Validate the JSON telemetry payload
            is_valid, msg = validate_payload(payload)
            if not is_valid:
                print(f"[INVALID PAYLOAD]: {msg} -> {line_str}")
                continue

            # Display real readings
            print(format_display_row(payload))
            record_count += 1

            if max_records and record_count >= max_records:
                print(f"\nTarget sample count ({max_records}) reached. Stopping listener.")
                break

    except serial.SerialException as e:
        print("\n" + "!" * 75)
        print(f"COM PORT ACCESS ERROR: Could not open or read {port}.")
        print(f"Detail: {e}")
        print("Troubleshooting steps:")
        print("  1. Close Arduino IDE Serial Monitor / Serial Plotter if open.")
        print("  2. Disconnect and firmly reconnect the ESP32 USB cable.")
        print("  3. Verify port assignment in Device Manager -> Ports (COM & LPT).")
        print("!" * 75 + "\n")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nListener stopped by user (Ctrl+C).")
    finally:
        if ser and ser.is_open:
            ser.close()
            print("Serial port connection closed cleanly.")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Live terminal listener for ESP32 DHT11 & PIR telemetry.")
    parser.add_argument("--port", type=str, default=DEFAULT_PORT, help="COM port (default: COM6)")
    parser.add_argument("--baud", type=int, default=DEFAULT_BAUD, help="Baud rate (default: 115200)")
    parser.add_argument("--count", type=int, default=None, help="Stop after N verified readings (default: continuous)")
    args = parser.parse_args()

    run_serial_listener(port=args.port, baud=args.baud, max_records=args.count)


if __name__ == "__main__":
    main()
