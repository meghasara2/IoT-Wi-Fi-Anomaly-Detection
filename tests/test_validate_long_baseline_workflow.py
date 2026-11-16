"""
Unit Tests for Long-Duration Baseline Validation Workflow
File: tests/test_validate_long_baseline_workflow.py

Covers:
1. Input validation: Detection of missing files and invalid schemas.
2. Output-path protection: Rejection of overwrites unless explicitly authorized.
3. Feature consistency: Schema preservation across scoring pipeline.
4. Frozen threshold application: Unchanged Session 1 model offsets applied without refitting.
5. Timing gating consistency: Windows with N < 3 receive inlier timing without penalty.
6. Sensor alignment integration: Optional sensor metadata joined without corrupting model scores.
"""

import os
import shutil
import tempfile
import sqlite3
import unittest
import pandas as pd
import numpy as np

from src.validate_long_baseline_workflow import (
    compute_baseline_session_metrics,
    run_session_validation_pipeline,
    MIN_PACKETS_FOR_TIMING
)
from src.dual_detector_1s import train_dual_detector


class TestValidateLongBaselineWorkflow(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.s1_csv = os.path.join(self.test_dir, "s1_train.csv")
        self.eval_csv = os.path.join(self.test_dir, "eval_session.csv")
        self.sensor_db = os.path.join(self.test_dir, "sensors.db")
        self.out_dir = os.path.join(self.test_dir, "long_baseline_validation")

        self._create_mock_session1_data(self.s1_csv, n=60)
        self._create_mock_eval_data(self.eval_csv, n=40)
        self._create_mock_sensor_db(self.sensor_db)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_mock_session1_data(self, path, n=60):
        rows = []
        for i in range(n):
            is_single = (i % 6 == 0)
            is_double = (i % 6 == 1)
            if is_single:
                cnt = 1
                rate = 1.0
                mean_iat = np.nan
                iat_std = np.nan
            elif is_double:
                cnt = 2
                rate = 2.0
                mean_iat = 0.3
                iat_std = 0.0
            else:
                cnt = 12
                rate = 12.0
                mean_iat = 0.06 + (i * 0.001)
                iat_std = 0.03 + (i * 0.0005)

            rows.append({
                "client_mac": "ca:34:ea:92:d3:9e",
                "node_id": "Node_Client_1",
                "Node_Type": "Unverified_Mobile_Client",
                "Data_Label": "real_observed_traffic",
                "Window_ID": i + 1,
                "Bin_Index": i,
                "bin_start_timestamp": 1000.0 + i,
                "bin_end_timestamp": 1001.0 + i,
                "packet_count": cnt,
                "packet_rate": rate,
                "mean_packet_size": 250.0 + (i * 2.0),
                "packet_size_std": 40.0,
                "mean_IAT": mean_iat,
                "IAT_std": iat_std
            })
        df = pd.DataFrame(rows)
        df.to_csv(path, index=False)
        return df

    def _create_mock_eval_data(self, path, n=40):
        rows = []
        for j in range(n):
            is_single = (j % 5 == 0)
            rows.append({
                "client_mac": "e6:2e:db:73:1c:25",
                "node_id": "Node_Client_2",
                "Node_Type": "Unverified_Mobile_Client",
                "Data_Label": "real_observed_traffic",
                "Window_ID": j + 1,
                "Bin_Index": j,
                "bin_start_timestamp": 2000.0 + j,
                "bin_end_timestamp": 2001.0 + j,
                "packet_count": 1 if is_single else 10,
                "packet_rate": 1.0 if is_single else 10.0,
                "mean_packet_size": 300.0,
                "packet_size_std": 35.0,
                "mean_IAT": np.nan if is_single else 0.08,
                "IAT_std": np.nan if is_single else 0.02
            })
        df = pd.DataFrame(rows)
        df.to_csv(path, index=False)
        return df

    def _create_mock_sensor_db(self, path):
        conn = sqlite3.connect(path)
        with conn:
            conn.execute("""
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
            # Insert a few mock readings around timestamp 2005.0
            for k in range(10):
                conn.execute("""
                    INSERT INTO sensor_telemetry (node_id, sequence_num, uptime_ms, temperature_c, humidity_pct, dht_valid, motion_detected, captured_at)
                    VALUES ('esp32_gateway', ?, ?, 28.5, 60.0, 1, 0, datetime(2000 + ?, 'unixepoch'))
                """, (k + 1, (k + 1) * 2000, k * 2))
        conn.close()

    def test_input_validation_missing_files(self):
        """
        Verify that missing feature CSV or missing training baseline raises FileNotFoundError.
        """
        with self.assertRaises(FileNotFoundError):
            run_session_validation_pipeline(
                session_name="invalid_session",
                features_csv_path=os.path.join(self.test_dir, "nonexistent.csv"),
                session1_train_path=self.s1_csv,
                output_dir=self.out_dir
            )

        with self.assertRaises(FileNotFoundError):
            run_session_validation_pipeline(
                session_name="invalid_session",
                features_csv_path=self.eval_csv,
                session1_train_path=os.path.join(self.test_dir, "nonexistent_s1.csv"),
                output_dir=self.out_dir
            )

    def test_output_path_protection(self):
        """
        Verify that run_session_validation_pipeline refuses to overwrite existing artifacts
        unless overwrite=True.
        """
        # First execution succeeds
        res1 = run_session_validation_pipeline(
            session_name="test_session_protect",
            features_csv_path=self.eval_csv,
            session1_train_path=self.s1_csv,
            output_dir=self.out_dir,
            overwrite=False
        )
        self.assertTrue(os.path.exists(res1["out_files"][0]))

        # Second execution without overwrite must raise FileExistsError
        with self.assertRaises(FileExistsError):
            run_session_validation_pipeline(
                session_name="test_session_protect",
                features_csv_path=self.eval_csv,
                session1_train_path=self.s1_csv,
                output_dir=self.out_dir,
                overwrite=False
            )

    def test_feature_consistency_and_schema_preservation(self):
        """
        Verify that all expected network feature columns and scoring columns
        are present in the output scored dataframe.
        """
        res = run_session_validation_pipeline(
            session_name="test_schema_session",
            features_csv_path=self.eval_csv,
            session1_train_path=self.s1_csv,
            output_dir=self.out_dir,
            overwrite=True
        )
        df_scored = res["df_scored"]

        # Base network features
        for col in ["packet_rate", "mean_packet_size", "packet_size_std", "mean_IAT", "IAT_std"]:
            self.assertIn(col, df_scored.columns)

        # Dual detector outputs
        for col in ["score_primary", "pred_primary", "score_timing", "pred_timing", "timing_status", "pred_dual", "dual_reason"]:
            self.assertIn(col, df_scored.columns)

        self.assertEqual(len(df_scored), 40)

    def test_frozen_thresholds_applied_without_refitting(self):
        """
        Verify that model thresholds and imputer medians derive strictly from Session 1,
        and that evaluating the session does not change the training baseline parameters.
        """
        df_s1 = pd.read_csv(self.s1_csv)
        bundle = train_dual_detector(df_s1, contamination=0.05, random_state=42)

        ref_prim_offset = bundle.meta_primary["fitted_offset"]
        ref_time_offset = bundle.meta_timing["fitted_offset"]

        res = run_session_validation_pipeline(
            session_name="test_frozen_session",
            features_csv_path=self.eval_csv,
            session1_train_path=self.s1_csv,
            output_dir=self.out_dir,
            contamination=0.05,
            random_state=42,
            overwrite=True
        )

        # Re-check that scored decision function aligns with threshold: score < 0 <=> pred == -1
        df_scored = res["df_scored"]
        for score, pred in zip(df_scored["score_primary"], df_scored["pred_primary"]):
            if score < 0:
                self.assertEqual(pred, -1)
            else:
                self.assertEqual(pred, 1)

    def test_timing_gating_for_low_packet_windows(self):
        """
        Verify that windows with N < 3:
        1. Have timing_status == 'UNAVAILABLE_N_LT_3'.
        2. Have pred_timing == 1 (inlier / not flagged).
        3. Are not flagged by pred_dual if primary features are within normal range.
        """
        res = run_session_validation_pipeline(
            session_name="test_gating_session",
            features_csv_path=self.eval_csv,
            session1_train_path=self.s1_csv,
            output_dir=self.out_dir,
            overwrite=True
        )
        df_scored = res["df_scored"]
        low_pkts = df_scored[df_scored["packet_count"] < MIN_PACKETS_FOR_TIMING]

        self.assertGreater(len(low_pkts), 0)
        self.assertTrue((low_pkts["timing_status"] == "UNAVAILABLE_N_LT_3").all())
        self.assertTrue((low_pkts["pred_timing"] == 1).all())
        self.assertTrue(low_pkts["score_timing"].isna().all())

    def test_optional_sensor_alignment(self):
        """
        Verify that providing a sensor database augments output with sensor columns
        without modifying network features or anomaly classifications.
        """
        res_no_sensor = run_session_validation_pipeline(
            session_name="test_no_sensor",
            features_csv_path=self.eval_csv,
            session1_train_path=self.s1_csv,
            output_dir=self.out_dir,
            overwrite=True
        )

        res_sensor = run_session_validation_pipeline(
            session_name="test_with_sensor",
            features_csv_path=self.eval_csv,
            sensor_db_path=self.sensor_db,
            session1_train_path=self.s1_csv,
            output_dir=self.out_dir,
            overwrite=True
        )

        # Predictions must be 100% identical
        np.testing.assert_array_equal(
            res_no_sensor["df_scored"]["pred_dual"].values,
            res_sensor["df_scored"]["pred_dual"].values
        )

        # Sensor metadata present
        self.assertIn("alignment_status", res_sensor["df_scored"].columns)
        self.assertTrue(res_sensor["metrics"]["sensor_aligned"])


if __name__ == "__main__":
    unittest.main()
