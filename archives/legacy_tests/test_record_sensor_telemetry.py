"""
Unit Tests: Isolated Sensor Telemetry Storage
File: tests/test_record_sensor_telemetry.py

Purpose:
  Tests schema creation, payload rejection, insertion, NULL handling for failed sensors,
  duplicate record prevention, and dry-run execution using a temporary scratch database.
  Does NOT open COM ports or access production database files.
"""

import unittest
import sqlite3
import tempfile
import shutil
from pathlib import Path
import sys

# Ensure src directory is available
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from record_sensor_telemetry import init_database, insert_sensor_telemetry


class TestRecordSensorTelemetry(unittest.TestCase):

    def setUp(self):
        # Create a fresh, temporary scratch directory for each test
        self.test_dir = tempfile.mkdtemp()
        self.scratch_db = Path(self.test_dir) / "scratch_sensors.db"

    def tearDown(self):
        # Clean up temporary scratch directory
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_init_database_creates_expected_schema(self):
        # Verify init_database creates the table and expected columns
        init_database(self.scratch_db)
        self.assertTrue(self.scratch_db.exists())

        conn = sqlite3.connect(str(self.scratch_db))
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(sensor_telemetry);")
        columns = {col[1]: col[2] for col in cur.fetchall()}
        conn.close()

        expected_columns = [
            "telemetry_id", "node_id", "sequence_num", "uptime_ms",
            "temperature_c", "humidity_pct", "dht_valid", "motion_detected", "captured_at"
        ]
        for col in expected_columns:
            self.assertIn(col, columns, f"Missing expected column: {col}")

    def test_insert_valid_payload_stores_record(self):
        init_database(self.scratch_db)
        payload = {
            "node": "esp32_gateway",
            "seq": 101,
            "uptime_ms": 20450,
            "dht11": {"valid": 1, "temp_c": 28.5, "humidity": 65.0},
            "pir": {"motion": 1}
        }
        success, msg = insert_sensor_telemetry(self.scratch_db, payload, dry_run=False)
        self.assertTrue(success)
        self.assertIn("Record stored successfully", msg)

        # Check database content
        conn = sqlite3.connect(str(self.scratch_db))
        cur = conn.cursor()
        cur.execute("SELECT node_id, sequence_num, temperature_c, humidity_pct, dht_valid, motion_detected FROM sensor_telemetry;")
        row = cur.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row[0], "esp32_gateway")
        self.assertEqual(row[1], 101)
        self.assertAlmostEqual(row[2], 28.5)
        self.assertAlmostEqual(row[3], 65.0)
        self.assertEqual(row[4], 1)
        self.assertEqual(row[5], 1)

    def test_failed_dht_stores_sql_null(self):
        init_database(self.scratch_db)
        # When valid=0, temperature and humidity must be stored as SQL NULL
        payload = {
            "node": "esp32_gateway",
            "seq": 102,
            "uptime_ms": 22450,
            "dht11": {"valid": 0, "temp_c": None, "humidity": None},
            "pir": {"motion": 0}
        }
        success, msg = insert_sensor_telemetry(self.scratch_db, payload, dry_run=False)
        self.assertTrue(success)

        conn = sqlite3.connect(str(self.scratch_db))
        cur = conn.cursor()
        cur.execute("SELECT temperature_c, humidity_pct, dht_valid, motion_detected FROM sensor_telemetry WHERE sequence_num=102;")
        row = cur.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertIsNone(row[0], "temperature_c should be SQL NULL (None)")
        self.assertIsNone(row[1], "humidity_pct should be SQL NULL (None)")
        self.assertEqual(row[2], 0)
        self.assertEqual(row[3], 0)

    def test_duplicate_record_prevention(self):
        init_database(self.scratch_db)
        payload = {
            "node": "esp32_gateway",
            "seq": 200,
            "uptime_ms": 50000,
            "dht11": {"valid": 1, "temp_c": 25.0, "humidity": 50.0},
            "pir": {"motion": 0}
        }
        # First insertion succeeds
        success1, msg1 = insert_sensor_telemetry(self.scratch_db, payload, dry_run=False)
        self.assertTrue(success1)
        self.assertIn("Record stored successfully", msg1)

        # Second insertion with same (node_id, sequence_num) is ignored
        success2, msg2 = insert_sensor_telemetry(self.scratch_db, payload, dry_run=False)
        self.assertTrue(success2)
        self.assertIn("Duplicate record ignored", msg2)

        conn = sqlite3.connect(str(self.scratch_db))
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM sensor_telemetry WHERE node_id='esp32_gateway' AND sequence_num=200;")
        count = cur.fetchone()[0]
        conn.close()

        self.assertEqual(count, 1, "Duplicate record should not be inserted")

    def test_invalid_payload_rejected_before_db(self):
        init_database(self.scratch_db)
        # Invalid temperature (out of plausible range: 150 °C)
        invalid_payload = {
            "node": "esp32_gateway",
            "seq": 300,
            "uptime_ms": 60000,
            "dht11": {"valid": 1, "temp_c": 150.0, "humidity": 50.0},
            "pir": {"motion": 0}
        }
        success, msg = insert_sensor_telemetry(self.scratch_db, invalid_payload, dry_run=False)
        self.assertFalse(success)
        self.assertIn("Payload rejected", msg)

        conn = sqlite3.connect(str(self.scratch_db))
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM sensor_telemetry;")
        count = cur.fetchone()[0]
        conn.close()

        self.assertEqual(count, 0, "Rejected payload must not write to table")

    def test_dry_run_does_not_modify_database(self):
        init_database(self.scratch_db)
        payload = {
            "node": "esp32_gateway",
            "seq": 401,
            "uptime_ms": 70000,
            "dht11": {"valid": 1, "temp_c": 26.0, "humidity": 55.0},
            "pir": {"motion": 0}
        }
        success, msg = insert_sensor_telemetry(self.scratch_db, payload, dry_run=True)
        self.assertTrue(success)
        self.assertIn("Dry-run passed", msg)

        conn = sqlite3.connect(str(self.scratch_db))
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM sensor_telemetry;")
        count = cur.fetchone()[0]
        conn.close()

        self.assertEqual(count, 0, "Dry run must not insert any rows")

    def test_uninitialized_database_rejected_without_init_db(self):
        # Database file does not exist, inserting without --init-db must fail gracefully
        non_existent_db = Path(self.test_dir) / "does_not_exist.db"
        payload = {
            "node": "esp32_gateway",
            "seq": 501,
            "uptime_ms": 80000,
            "dht11": {"valid": 1, "temp_c": 24.0, "humidity": 45.0},
            "pir": {"motion": 0}
        }
        success, msg = insert_sensor_telemetry(non_existent_db, payload, dry_run=False)
        self.assertFalse(success)
        self.assertIn("Database does not exist", msg)


if __name__ == "__main__":
    unittest.main()
