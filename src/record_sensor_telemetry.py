"""
Isolated Sensor Telemetry Storage Component
File: src/record_sensor_telemetry.py

Purpose:
  Receives validated ESP32 JSON telemetry and persists readings to an isolated
  'sensor_telemetry' SQLite table using parameterized transactions.

Safety & Constraints:
  - Never automatically alters production tables.
  - Requires explicit '--init-db' flag to create table schema on a target database.
  - Supports dry-run mode (--dry-run) which validates payloads without writing to disk.
  - Stores invalid/timed-out DHT11 readings as SQL NULL.
  - Prevents duplicate insertions of (node_id, sequence_num) via UNIQUE constraint
    and INSERT OR IGNORE / ON CONFLICT DO NOTHING.
"""

import sys
import json
import sqlite3
import argparse
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

# Re-use existing validated parsing from ingest_serial_sensors
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from ingest_serial_sensors import validate_payload, format_display_row


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS sensor_telemetry (
    telemetry_id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT NOT NULL,
    sequence_num INTEGER NOT NULL,
    uptime_ms INTEGER NOT NULL,
    temperature_c REAL,
    humidity_pct REAL,
    dht_valid INTEGER NOT NULL,
    motion_detected INTEGER NOT NULL,
    captured_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(node_id, sequence_num)
);
"""


def init_database(db_path: Path) -> None:
    """
    Explicitly initializes the sensor_telemetry table in the target database.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    try:
        with conn:
            conn.execute(SCHEMA_SQL)
        print(f"[INIT] 'sensor_telemetry' table successfully initialized in: {db_path}")
    finally:
        conn.close()


def insert_sensor_telemetry(
    db_path: Path,
    payload: Dict[str, Any],
    dry_run: bool = False
) -> Tuple[bool, str]:
    """
    Validates and stores an ESP32 sensor telemetry payload.
    
    Returns:
        (success: bool, message: str)
    """
    # 1. Reject invalid payloads before database interaction
    is_valid, validation_msg = validate_payload(payload)
    if not is_valid:
        return False, f"Payload rejected: {validation_msg}"

    # Extract fields
    node_id = str(payload["node"])
    seq_num = int(payload["seq"])
    uptime_ms = int(payload["uptime_ms"])

    dht = payload.get("dht11", {})
    dht_valid = int(dht.get("valid", 0))

    # Failed readings stored as SQL NULL (None)
    if dht_valid == 1:
        temp_c = float(dht["temp_c"]) if dht["temp_c"] is not None else None
        hum_pct = float(dht["humidity"]) if dht["humidity"] is not None else None
    else:
        temp_c = None
        hum_pct = None

    pir = payload.get("pir", {})
    motion_detected = int(pir.get("motion", 0))

    # Dry-run handling
    if dry_run:
        return True, f"Dry-run passed (valid={dht_valid}, temp={temp_c}, hum={hum_pct}, motion={motion_detected})"

    # Verify table existence before write to prevent implicit table creation
    if not db_path.exists():
        return False, f"Database does not exist: {db_path}. Run with --init-db to initialize."

    conn = sqlite3.connect(str(db_path), timeout=5.0)
    try:
        # Check that the sensor_telemetry table exists
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sensor_telemetry';")
        if not cur.fetchone():
            return False, f"Table 'sensor_telemetry' not found in {db_path}. Run with --init-db first."

        # Parameterized INSERT OR IGNORE to prevent duplicate (node_id, sequence_num)
        insert_sql = """
        INSERT OR IGNORE INTO sensor_telemetry (
            node_id, sequence_num, uptime_ms, temperature_c, humidity_pct, dht_valid, motion_detected
        ) VALUES (?, ?, ?, ?, ?, ?, ?);
        """

        with conn:
            cur.execute(insert_sql, (
                node_id,
                seq_num,
                uptime_ms,
                temp_c,
                hum_pct,
                dht_valid,
                motion_detected
            ))

        if cur.rowcount == 0:
            return True, f"Duplicate record ignored (node='{node_id}', seq={seq_num})"
        else:
            return True, f"Record stored successfully (id={cur.lastrowid}, seq={seq_num})"

    except sqlite3.Error as e:
        return False, f"SQLite error: {e}"
    finally:
        conn.close()


def run_storage_listener(
    db_path: Path,
    port: str = "COM6",
    baud: int = 115200,
    dry_run: bool = False,
    max_records: Optional[int] = None
):
    """
    Connects to serial port, validates telemetry stream, and persists to SQLite.
    """
    try:
        import serial
        import serial.tools.list_ports
    except ImportError:
        print("\nERROR: 'pyserial' package is required for live hardware connection.")
        sys.exit(1)

    print("=" * 80)
    print("ESP32 SENSOR TELEMETRY STORAGE WRITER")
    print(f"Target DB:  {db_path}")
    print(f"Serial Port: {port} @ {baud} baud")
    print(f"Mode:        {'DRY-RUN (No disk writes)' if dry_run else 'LIVE PERSISTENCE'}")
    print("=" * 80)

    try:
        ser = serial.Serial(port=port, baudrate=baud, timeout=2.5)
        ser.reset_input_buffer()
        print(f"Connected to {port}. Awaiting telemetry packets...\n")

        records_processed = 0
        while True:
            raw_line = ser.readline()
            if not raw_line:
                continue

            line_str = raw_line.decode("utf-8", errors="replace").strip()
            if not line_str or not (line_str.startswith("{") and line_str.endswith("}")):
                continue

            try:
                payload = json.loads(line_str)
            except json.JSONDecodeError:
                continue

            success, msg = insert_sensor_telemetry(db_path, payload, dry_run=dry_run)
            status_tag = "[STORED]" if success else "[REJECTED]"
            print(f"{status_tag} {format_display_row(payload)} | {msg}")

            if success:
                records_processed += 1
            if max_records and records_processed >= max_records:
                break

    except serial.SerialException as e:
        print(f"\n[SERIAL ERROR]: Could not open {port}: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nListener stopped by user.")
    finally:
        if 'ser' in locals() and ser.is_open:
            ser.close()


def main():
    parser = argparse.ArgumentParser(description="Standalone SQLite Storage Writer for ESP32 Sensor Telemetry.")
    parser.add_argument("--db", type=str, default="data/scratch/sensor_telemetry.db", help="Path to target SQLite database")
    parser.add_argument("--port", type=str, default="COM6", help="Serial port (default: COM6)")
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate (default: 115200)")
    parser.add_argument("--init-db", action="store_true", help="Explicitly create the sensor_telemetry table schema in target database")
    parser.add_argument("--dry-run", action="store_true", help="Validate incoming telemetry without writing to database")
    parser.add_argument("--count", type=int, default=None, help="Stop after N stored records")
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.is_absolute():
        db_path = project_root / db_path

    if args.init_db:
        init_database(db_path)
        if not args.dry_run and not sys.stdin.isatty():
            return

    run_storage_listener(
        db_path=db_path,
        port=args.port,
        baud=args.baud,
        dry_run=args.dry_run,
        max_records=args.count
    )


if __name__ == "__main__":
    main()
