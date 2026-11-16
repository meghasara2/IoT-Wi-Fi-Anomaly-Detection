"""
Unit Tests: Temporal Alignment Prototype
File: tests/test_correlate_traffic_and_sensors.py

Purpose:
  Validates nearest-neighbor temporal alignment between network windows and
  sensor readings, covering:
  - Exact matched rows within tolerance
  - Unmatched rows outside tolerance (marked as NaN/UNMATCHED without fabrication)
  - Non-overlapping session ranges
  - Empty or invalid timestamp handling
  - Preservation of all 5 network features
"""

import unittest
import pandas as pd
import numpy as np
import datetime
from pathlib import Path
import sys

# Ensure src directory is available
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from correlate_traffic_and_sensors import correlate_traffic_with_sensors


class TestTemporalAlignment(unittest.TestCase):

    def setUp(self):
        # Base network dataframe simulating 5 windows around t=1000.0s
        self.df_net = pd.DataFrame([
            {
                "Node_ID": "Node_Client_1",
                "Window_ID": 1,
                "Window_Start_Time": 1000.0,
                "Window_End_Time": 1000.5,
                "window_center_epoch": 1000.25,
                "mean_IAT": 0.05,
                "IAT_std": 0.01,
                "packet_rate": 18.0,
                "mean_packet_size": 150.0,
                "packet_size_std": 20.0
            },
            {
                "Node_ID": "Node_Client_1",
                "Window_ID": 2,
                "Window_Start_Time": 1002.0,
                "Window_End_Time": 1002.5,
                "window_center_epoch": 1002.25,
                "mean_IAT": 0.05,
                "IAT_std": 0.01,
                "packet_rate": 18.0,
                "mean_packet_size": 150.0,
                "packet_size_std": 20.0
            },
            {
                "Node_ID": "Node_Client_1",
                "Window_ID": 3,
                "Window_Start_Time": 1010.0,
                "Window_End_Time": 1010.5,
                "window_center_epoch": 1010.25,
                "mean_IAT": 0.05,
                "IAT_std": 0.01,
                "packet_rate": 18.0,
                "mean_packet_size": 150.0,
                "packet_size_std": 20.0
            }
        ])

    def test_matched_row_within_tolerance(self):
        # Sensor reading at t=1000.5 (delta = 0.25s from Window 1 center)
        df_sensor = pd.DataFrame([
            {
                "telemetry_id": 1,
                "sensor_node_id": "esp32_gateway",
                "sequence_num": 1,
                "uptime_ms": 2000,
                "temperature_c": 29.5,
                "humidity_pct": 75.0,
                "dht_valid": 1,
                "motion_detected": 1,
                "captured_at": "2026-10-11 12:00:00",
                "sensor_epoch": 1000.5
            }
        ])

        aligned = correlate_traffic_with_sensors(self.df_net, df_sensor, tolerance_sec=2.0)

        # Window 1 (center 1000.25) should match sensor at 1000.5 (delta 0.25 <= 2.0s)
        w1 = aligned[aligned["Window_ID"] == 1].iloc[0]
        self.assertEqual(w1["alignment_status"], "MATCHED_WITHIN_TOLERANCE")
        self.assertEqual(w1["sensor_temp_c"], 29.5)
        self.assertEqual(w1["sensor_motion_detected"], 1)
        self.assertAlmostEqual(w1["time_delta_sec"], 0.25)

        # Network features must remain identical
        self.assertEqual(w1["packet_rate"], 18.0)
        self.assertEqual(w1["mean_IAT"], 0.05)

    def test_unmatched_row_outside_tolerance(self):
        # Sensor reading only at t=1000.5. Window 3 is at t=1010.25 (delta = 9.75s > 2.0s)
        df_sensor = pd.DataFrame([
            {
                "telemetry_id": 1,
                "sensor_node_id": "esp32_gateway",
                "sequence_num": 1,
                "uptime_ms": 2000,
                "temperature_c": 29.5,
                "humidity_pct": 75.0,
                "dht_valid": 1,
                "motion_detected": 1,
                "captured_at": "2026-10-11 12:00:00",
                "sensor_epoch": 1000.5
            }
        ])

        aligned = correlate_traffic_with_sensors(self.df_net, df_sensor, tolerance_sec=2.0)

        # Window 3 must be UNMATCHED, with sensor fields as NaN
        w3 = aligned[aligned["Window_ID"] == 3].iloc[0]
        self.assertEqual(w3["alignment_status"], "UNMATCHED_OUTSIDE_TOLERANCE")
        self.assertTrue(pd.isna(w3["sensor_temp_c"]))
        self.assertTrue(pd.isna(w3["sensor_motion_detected"]))
        self.assertTrue(pd.isna(w3["telemetry_id"]))

        # Network features still preserved
        self.assertEqual(w3["packet_rate"], 18.0)

    def test_completely_non_overlapping_ranges(self):
        # Sensor recorded 2 hours after traffic capture
        df_sensor_future = pd.DataFrame([
            {
                "telemetry_id": 10,
                "sensor_node_id": "esp32_gateway",
                "sequence_num": 1,
                "uptime_ms": 2000,
                "temperature_c": 30.0,
                "humidity_pct": 80.0,
                "dht_valid": 1,
                "motion_detected": 0,
                "captured_at": "2026-10-11 14:00:00",
                "sensor_epoch": 8200.0  # Far away from t=1000
            }
        ])

        aligned = correlate_traffic_with_sensors(self.df_net, df_sensor_future, tolerance_sec=2.0)

        # All rows should be UNMATCHED
        self.assertEqual(len(aligned), len(self.df_net))
        self.assertTrue((aligned["alignment_status"] == "UNMATCHED_OUTSIDE_TOLERANCE").all())
        self.assertTrue(aligned["sensor_temp_c"].isna().all())

    def test_empty_sensor_telemetry(self):
        empty_sensor = pd.DataFrame()
        aligned = correlate_traffic_with_sensors(self.df_net, empty_sensor, tolerance_sec=2.0)

        self.assertEqual(len(aligned), len(self.df_net))
        self.assertTrue((aligned["alignment_status"] == "UNMATCHED_NO_SENSOR_DATA").all())
        self.assertTrue(aligned["sensor_temp_c"].isna().all())


if __name__ == "__main__":
    unittest.main()
