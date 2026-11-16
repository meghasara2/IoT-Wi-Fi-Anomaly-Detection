"""
Unit tests for the experimental 1-second network feature and sensor telemetry aligner.

Tests cover:
1. Successful matching within tolerance (<= 2.0s).
2. Unmatched windows outside tolerance (> 2.0s).
3. Empty sensor tables (preserves all network rows with UNMATCHED_NO_SENSOR_DATA).
4. Invalid DHT readings (dht_valid=0 or null retained with NaN temperature/humidity, NEVER 0.0).
5. Full preservation of all network rows and original row order.
6. Overwrite protection guards on the output file.
"""

import math
import os
import shutil
import sqlite3
import tempfile
import unittest
import pandas as pd
import numpy as np

from src.align_time_windows_with_sensors import (
    load_network_1s_windows,
    load_sensor_telemetry,
    align_1s_windows_with_sensors,
    run_alignment
)


class TestAlignTimeWindowsWithSensors(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.csv_path = os.path.join(self.test_dir, "test_features.csv")
        self.db_path = os.path.join(self.test_dir, "test_sensor.db")
        self.out_csv = os.path.join(self.test_dir, "test_aligned.csv")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_sample_network_csv(self, rows):
        df = pd.DataFrame(rows)
        df.to_csv(self.csv_path, index=False)
        return self.csv_path

    def _create_sample_sensor_db(self, rows):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE sensor_telemetry (
            telemetry_id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT NOT NULL,
            sequence_num INTEGER NOT NULL,
            uptime_ms INTEGER NOT NULL,
            temperature_c REAL,
            humidity_pct REAL,
            dht_valid INTEGER NOT NULL,
            motion_detected INTEGER NOT NULL,
            captured_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        """)
        for r in rows:
            cur.execute("""
            INSERT INTO sensor_telemetry (
                node_id, sequence_num, uptime_ms, temperature_c, humidity_pct, dht_valid, motion_detected, captured_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """, r)
        conn.commit()
        conn.close()
        return self.db_path

    def test_successful_matching_within_tolerance(self):
        """
        A network window centered at 1700000001.5 should match a sensor reading
        captured at 1700000002.0 (time delta = 0.5s <= 2.0s).
        """
        df_net = pd.DataFrame([{
            "client_mac": "00:11:22:33:44:55",
            "node_id": "Node_Client_1",
            "bin_start_timestamp": 1700000001.0,
            "bin_end_timestamp": 1700000002.0,
            "window_center_epoch": 1700000001.5,
            "packet_rate": 10.0,
            "mean_IAT": 0.1,
            "IAT_std": 0.05,
            "mean_packet_size": 100.0,
            "packet_size_std": 20.0
        }])

        df_sensor = pd.DataFrame([{
            "telemetry_id": 1,
            "sensor_node_id": "esp32_gateway",
            "sequence_num": 10,
            "sensor_uptime_ms": 20000,
            "temperature_c": 28.5,
            "humidity_pct": 65.0,
            "dht_valid": 1,
            "motion_detected": 1,
            "captured_at": "2023-11-14 22:13:22",
            "sensor_epoch": 1700000002.0
        }])

        aligned = align_1s_windows_with_sensors(df_net, df_sensor, tolerance_sec=2.0)

        self.assertEqual(len(aligned), 1)
        row = aligned.iloc[0]
        self.assertEqual(row["alignment_status"], "MATCHED_WITHIN_TOLERANCE")
        self.assertEqual(row["telemetry_id"], 1)
        self.assertAlmostEqual(row["time_delta_sec"], 0.5, places=5)
        self.assertEqual(row["temperature_c"], 28.5)
        self.assertEqual(row["humidity_pct"], 65.0)
        self.assertEqual(row["dht_valid"], 1)
        self.assertEqual(row["motion_detected"], 1)
        self.assertEqual(row["packet_rate"], 10.0)

    def test_unmatched_window_outside_tolerance(self):
        """
        A network window centered at 1700000010.5 with nearest sensor reading at 1700000002.0
        has time delta = 8.5s > 2.0s, so it must be marked UNMATCHED_OUTSIDE_TOLERANCE
        with sensor columns set to NaN.
        """
        df_net = pd.DataFrame([{
            "client_mac": "00:11:22:33:44:55",
            "node_id": "Node_Client_1",
            "bin_start_timestamp": 1700000010.0,
            "bin_end_timestamp": 1700000011.0,
            "window_center_epoch": 1700000010.5,
            "packet_rate": 5.0
        }])

        df_sensor = pd.DataFrame([{
            "telemetry_id": 1,
            "sensor_node_id": "esp32_gateway",
            "sequence_num": 1,
            "sensor_uptime_ms": 2000,
            "temperature_c": 25.0,
            "humidity_pct": 50.0,
            "dht_valid": 1,
            "motion_detected": 0,
            "captured_at": "2023-11-14 22:13:22",
            "sensor_epoch": 1700000002.0
        }])

        aligned = align_1s_windows_with_sensors(df_net, df_sensor, tolerance_sec=2.0)

        self.assertEqual(len(aligned), 1)
        row = aligned.iloc[0]
        self.assertEqual(row["alignment_status"], "UNMATCHED_OUTSIDE_TOLERANCE")
        self.assertTrue(math.isnan(row["telemetry_id"]))
        self.assertTrue(math.isnan(row["time_delta_sec"]))
        self.assertTrue(math.isnan(row["temperature_c"]))
        self.assertTrue(math.isnan(row["humidity_pct"]))
        self.assertTrue(math.isnan(row["motion_detected"]))
        # Network feature preserved
        self.assertEqual(row["packet_rate"], 5.0)

    def test_empty_sensor_table(self):
        """
        When the sensor table has 0 rows, all network windows must still be preserved
        and marked UNMATCHED_NO_SENSOR_DATA.
        """
        df_net = pd.DataFrame([
            {"node_id": "c1", "bin_start_timestamp": 100.0, "bin_end_timestamp": 101.0, "window_center_epoch": 100.5},
            {"node_id": "c2", "bin_start_timestamp": 102.0, "bin_end_timestamp": 103.0, "window_center_epoch": 102.5}
        ])
        df_sensor_empty = pd.DataFrame()

        aligned = align_1s_windows_with_sensors(df_net, df_sensor_empty, tolerance_sec=2.0)

        self.assertEqual(len(aligned), 2)
        for idx in range(2):
            self.assertEqual(aligned.iloc[idx]["alignment_status"], "UNMATCHED_NO_SENSOR_DATA")
            self.assertTrue(math.isnan(aligned.iloc[idx]["temperature_c"]))

    def test_invalid_dht_reading_never_zero(self):
        """
        When dht_valid == 0, temperature and humidity must be NaN (never 0.0),
        while motion_detected, dht_valid, and the network window are preserved.
        """
        df_net = pd.DataFrame([{
            "node_id": "Node_Client_1",
            "bin_start_timestamp": 1700000001.0,
            "bin_end_timestamp": 1700000002.0,
            "window_center_epoch": 1700000001.5,
            "packet_rate": 15.0
        }])

        df_sensor = pd.DataFrame([{
            "telemetry_id": 99,
            "sensor_node_id": "esp32_gateway",
            "sequence_num": 5,
            "sensor_uptime_ms": 10000,
            "temperature_c": np.nan,
            "humidity_pct": np.nan,
            "dht_valid": 0,
            "motion_detected": 1,
            "captured_at": "2023-11-14 22:13:22",
            "sensor_epoch": 1700000002.0
        }])

        aligned = align_1s_windows_with_sensors(df_net, df_sensor, tolerance_sec=2.0)

        self.assertEqual(len(aligned), 1)
        row = aligned.iloc[0]
        self.assertEqual(row["alignment_status"], "MATCHED_WITHIN_TOLERANCE")
        self.assertEqual(row["dht_valid"], 0)
        self.assertEqual(row["motion_detected"], 1)
        self.assertTrue(math.isnan(row["temperature_c"]))
        self.assertTrue(math.isnan(row["humidity_pct"]))
        # Never zero
        self.assertFalse(row["temperature_c"] == 0.0)
        self.assertFalse(row["humidity_pct"] == 0.0)

    def test_preservation_of_all_network_rows(self):
        """
        Verify that exact row count and relative order of network windows are preserved
        even when interspersed between matched and unmatched times.
        """
        net_rows = [
            {"node_id": "c1", "bin_start_timestamp": 10.0, "bin_end_timestamp": 11.0, "window_center_epoch": 10.5, "w_id": 1},
            {"node_id": "c1", "bin_start_timestamp": 20.0, "bin_end_timestamp": 21.0, "window_center_epoch": 20.5, "w_id": 2},
            {"node_id": "c2", "bin_start_timestamp": 30.0, "bin_end_timestamp": 31.0, "window_center_epoch": 30.5, "w_id": 3},
            {"node_id": "c2", "bin_start_timestamp": 40.0, "bin_end_timestamp": 41.0, "window_center_epoch": 40.5, "w_id": 4},
        ]
        df_net = pd.DataFrame(net_rows)

        # Only one sensor reading near window 2 (at 21.0s)
        sensor_rows = [{
            "telemetry_id": 1,
            "sensor_node_id": "esp32",
            "sequence_num": 1,
            "sensor_uptime_ms": 2000,
            "temperature_c": 30.0,
            "humidity_pct": 70.0,
            "dht_valid": 1,
            "motion_detected": 0,
            "captured_at": "2023-11-14 22:13:22",
            "sensor_epoch": 21.0
        }]
        df_sensor = pd.DataFrame(sensor_rows)

        aligned = align_1s_windows_with_sensors(df_net, df_sensor, tolerance_sec=2.0)

        # All 4 rows preserved in original order
        self.assertEqual(len(aligned), 4)
        self.assertEqual(list(aligned["w_id"]), [1, 2, 3, 4])
        self.assertEqual(aligned.iloc[0]["alignment_status"], "UNMATCHED_OUTSIDE_TOLERANCE")
        self.assertEqual(aligned.iloc[1]["alignment_status"], "MATCHED_WITHIN_TOLERANCE")
        self.assertEqual(aligned.iloc[2]["alignment_status"], "UNMATCHED_OUTSIDE_TOLERANCE")
        self.assertEqual(aligned.iloc[3]["alignment_status"], "UNMATCHED_OUTSIDE_TOLERANCE")

    def test_pipeline_refuses_overwrite(self):
        """
        Verify run_alignment refuses to overwrite an existing output file without overwrite=True.
        """
        # Create dummy existing file
        with open(self.out_csv, "w") as f:
            f.write("existing")

        self._create_sample_network_csv([{
            "node_id": "c1",
            "bin_start_timestamp": 1.0,
            "bin_end_timestamp": 2.0
        }])
        self._create_sample_sensor_db([])

        with self.assertRaises(FileExistsError):
            run_alignment(
                csv_path=self.csv_path,
                db_path=self.db_path,
                output_path=self.out_csv,
                overwrite=False
            )


if __name__ == "__main__":
    unittest.main()
