"""
Unit Tests for Dual-Detector Architecture (Fixed 1-Second Time Windows)
File: tests/test_dual_detector_1s.py

Covers:
1. Deterministic output: Identical scores and predictions with fixed seed.
2. Training-only preprocessing: Imputer and detectors fitted solely on training data.
3. Fixed threshold application: Decision boundary (offset_) preserved across evaluation.
4. Unavailable IAT handling: Single-packet (N < 3) windows are not penalized or flagged solely for missing IAT.
5. Gating boundary verification: N < 3 inactive vs N >= 3 active.
6. Overwrite protection: Refusal to overwrite existing artifacts unless overwrite=True.
"""

import os
import shutil
import tempfile
import unittest
import pandas as pd
import numpy as np

from src.dual_detector_1s import (
    train_dual_detector,
    evaluate_dual_detector,
    compare_all_architectures_on_synthetic,
    run_dual_detector_experiment,
    DualDetectorBundle,
    MIN_PACKETS_FOR_TIMING,
    FEATURE_COLS_PRIMARY,
    FEATURE_COLS_TIMING
)


class TestDualDetector1s(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.s1_csv = os.path.join(self.test_dir, "s1_test.csv")
        self.s2_csv = os.path.join(self.test_dir, "s2_test.csv")
        self.synth_csv = os.path.join(self.test_dir, "synth_test.csv")
        self.out_dir = os.path.join(self.test_dir, "dual_detector_experiment")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_synthetic_training_data(self, n=50):
        rows = []
        for i in range(n):
            is_single = (i % 7 == 0)
            is_double = (i % 7 == 1)
            if is_single:
                cnt = 1
                rate = 1.0
                mean_iat = np.nan
                iat_std = np.nan
            elif is_double:
                cnt = 2
                rate = 2.0
                mean_iat = 0.25
                iat_std = 0.0
            else:
                cnt = 15
                rate = 15.0
                mean_iat = 0.05 + (i * 0.001)
                iat_std = 0.02 + (i * 0.0005)

            rows.append({
                "client_mac": "00:11:22:33:44:55",
                "node_id": "Node_Client_1",
                "Node_Type": "Unverified_Mobile_Client",
                "Data_Label": "real_observed_traffic",
                "Window_ID": i + 1,
                "Bin_Index": i,
                "bin_start_timestamp": 1000.0 + i,
                "bin_end_timestamp": 1001.0 + i,
                "packet_count": cnt,
                "packet_rate": rate,
                "mean_packet_size": 300.0 + (i * 2.0),
                "packet_size_std": 50.0,
                "mean_IAT": mean_iat,
                "IAT_std": iat_std
            })
        df = pd.DataFrame(rows)
        df.to_csv(self.s1_csv, index=False)
        return df

    def test_deterministic_output(self):
        """
        Verify that training and evaluation produce identical decision scores
        and predictions given the same random seed (random_state=42).
        """
        df_train = self._create_synthetic_training_data(n=60)
        df_eval = self._create_synthetic_training_data(n=30)

        bundle1 = train_dual_detector(df_train, contamination=0.05, random_state=42)
        res1 = evaluate_dual_detector(bundle1, df_eval)

        bundle2 = train_dual_detector(df_train, contamination=0.05, random_state=42)
        res2 = evaluate_dual_detector(bundle2, df_eval)

        np.testing.assert_array_almost_equal(res1["score_primary"].values, res2["score_primary"].values)
        np.testing.assert_array_equal(res1["pred_primary"].values, res2["pred_primary"].values)

        # Compare valid timing scores
        valid_timing = ~res1["score_timing"].isna()
        np.testing.assert_array_almost_equal(
            res1.loc[valid_timing, "score_timing"].values,
            res2.loc[valid_timing, "score_timing"].values
        )
        np.testing.assert_array_equal(res1["pred_timing"].values, res2["pred_timing"].values)
        np.testing.assert_array_equal(res1["pred_dual"].values, res2["pred_dual"].values)

    def test_training_only_preprocessing(self):
        """
        Verify that the imputer and models are fitted strictly on Session 1 training data.
        Evaluating an arbitrary evaluation set must not change the imputer statistics or offsets.
        """
        df_train = self._create_synthetic_training_data(n=50)
        bundle = train_dual_detector(df_train, contamination=0.05, random_state=42)

        initial_median_iat = bundle.meta_timing["fitted_median_mean_IAT"]
        initial_median_std = bundle.meta_timing["fitted_median_IAT_std"]
        initial_offset_prim = bundle.meta_primary["fitted_offset"]
        initial_offset_time = bundle.meta_timing["fitted_offset"]

        # Create evaluation data with extreme distribution shift
        eval_rows = [{
            "client_mac": "00:11:22:33:44:55",
            "node_id": "Node_Client_1",
            "Node_Type": "Unverified_Mobile_Client",
            "Data_Label": "real_observed_traffic",
            "Window_ID": 100,
            "Bin_Index": 99,
            "bin_start_timestamp": 2000.0,
            "bin_end_timestamp": 2001.0,
            "packet_count": 50,
            "packet_rate": 50.0,
            "mean_packet_size": 1400.0,
            "packet_size_std": 10.0,
            "mean_IAT": 0.9999,
            "IAT_std": 0.8888
        }]
        df_eval = pd.DataFrame(eval_rows)

        # Evaluate
        evaluate_dual_detector(bundle, df_eval)

        # Ensure parameters are strictly unchanged
        self.assertEqual(bundle.imputer_timing.statistics_[0], initial_median_iat)
        self.assertEqual(bundle.imputer_timing.statistics_[1], initial_median_std)
        self.assertEqual(bundle.clf_primary.offset_, initial_offset_prim)
        self.assertEqual(bundle.clf_timing.offset_, initial_offset_time)

    def test_fixed_thresholds_applied(self):
        """
        Verify that the decision_function scores strictly align with predict:
        score < 0 <==> predict == -1 for both Primary and Timing detectors.
        """
        df_train = self._create_synthetic_training_data(n=60)
        bundle = train_dual_detector(df_train, contamination=0.05, random_state=42)
        df_eval = self._create_synthetic_training_data(n=40)

        res = evaluate_dual_detector(bundle, df_eval)

        # Primary detector alignment
        for score, pred in zip(res["score_primary"], res["pred_primary"]):
            if score < 0:
                self.assertEqual(pred, -1)
            else:
                self.assertEqual(pred, 1)

        # Timing detector alignment for active windows
        active_timing = res[res["timing_status"] == "ACTIVE"]
        for score, pred in zip(active_timing["score_timing"], active_timing["pred_timing"]):
            if score < 0:
                self.assertEqual(pred, -1)
            else:
                self.assertEqual(pred, 1)

    def test_unavailable_iat_handling(self):
        """
        Verify that single-packet windows (packet_count = 1) with NaN IAT are:
        1. Marked as UNAVAILABLE_N_LT_3 in timing_status.
        2. Assigned NaN in score_timing.
        3. Assigned inlier (+1) in pred_timing.
        4. Not flagged by the dual detector when primary features are normal.
        """
        df_train = self._create_synthetic_training_data(n=50)
        bundle = train_dual_detector(df_train, contamination=0.05, random_state=42)

        single_packet_row = pd.DataFrame([{
            "client_mac": "00:11:22:33:44:55",
            "node_id": "Node_Client_1",
            "Node_Type": "Unverified_Mobile_Client",
            "Data_Label": "real_observed_traffic",
            "Window_ID": 1,
            "Bin_Index": 0,
            "bin_start_timestamp": 1000.0,
            "bin_end_timestamp": 1001.0,
            "packet_count": 1,
            "packet_rate": 1.0,
            "mean_packet_size": 320.0,
            "packet_size_std": 0.0,
            "mean_IAT": np.nan,
            "IAT_std": np.nan
        }])

        res = evaluate_dual_detector(bundle, single_packet_row)

        self.assertEqual(res["timing_status"].iloc[0], "UNAVAILABLE_N_LT_3")
        self.assertTrue(np.isnan(res["score_timing"].iloc[0]))
        self.assertEqual(res["pred_timing"].iloc[0], 1)
        self.assertEqual(res["pred_dual"].iloc[0], 1)
        self.assertEqual(res["dual_reason"].iloc[0], "NORMAL_QUIET_TIMING_UNAVAILABLE")

    def test_gating_boundary_n2_vs_n3(self):
        """
        Verify the exact gating boundary:
        - N = 2 packets: Timing is UNAVAILABLE (sample variance ddof=1 is invalid).
        - N = 3 packets: Timing is ACTIVE (sample variance ddof=1 has >= 1 dof).
        """
        df_train = self._create_synthetic_training_data(n=50)
        bundle = train_dual_detector(df_train, contamination=0.05, random_state=42)

        boundary_df = pd.DataFrame([
            {
                "client_mac": "00:11:22:33:44:55",
                "node_id": "Node_Client_1",
                "Node_Type": "Unverified_Mobile_Client",
                "Data_Label": "real_observed_traffic",
                "Window_ID": 1,
                "Bin_Index": 0,
                "bin_start_timestamp": 1000.0,
                "bin_end_timestamp": 1001.0,
                "packet_count": 2,
                "packet_rate": 2.0,
                "mean_packet_size": 300.0,
                "packet_size_std": 20.0,
                "mean_IAT": 0.45,
                "IAT_std": 0.0
            },
            {
                "client_mac": "00:11:22:33:44:55",
                "node_id": "Node_Client_1",
                "Node_Type": "Unverified_Mobile_Client",
                "Data_Label": "real_observed_traffic",
                "Window_ID": 2,
                "Bin_Index": 1,
                "bin_start_timestamp": 1001.0,
                "bin_end_timestamp": 1002.0,
                "packet_count": 3,
                "packet_rate": 3.0,
                "mean_packet_size": 300.0,
                "packet_size_std": 20.0,
                "mean_IAT": 0.30,
                "IAT_std": 0.05
            }
        ])

        res = evaluate_dual_detector(bundle, boundary_df)

        self.assertEqual(res["timing_status"].iloc[0], "UNAVAILABLE_N_LT_3")
        self.assertEqual(res["timing_status"].iloc[1], "ACTIVE")
        self.assertTrue(np.isnan(res["score_timing"].iloc[0]))
        self.assertFalse(np.isnan(res["score_timing"].iloc[1]))

    def test_overwrite_protection(self):
        """
        Verify that run_dual_detector_experiment raises FileExistsError
        when output files already exist and overwrite=False.
        """
        df_train = self._create_synthetic_training_data(n=50)
        df_eval = self._create_synthetic_training_data(n=30)
        df_eval.to_csv(self.s2_csv, index=False)

        # Create dummy synthetic scenarios
        df_synth = df_eval.copy()
        df_synth["scenario"] = "normal_like"
        df_synth["is_anomaly"] = 0
        df_synth.to_csv(self.synth_csv, index=False)

        # First run succeeds
        run_dual_detector_experiment(
            session1_csv_path=self.s1_csv,
            session2_csv_path=self.s2_csv,
            synthetic_scenarios_path=self.synth_csv,
            output_dir=self.out_dir,
            contamination=0.05,
            random_state=42,
            overwrite=False
        )

        # Second run without overwrite must raise FileExistsError
        with self.assertRaises(FileExistsError):
            run_dual_detector_experiment(
                session1_csv_path=self.s1_csv,
                session2_csv_path=self.s2_csv,
                synthetic_scenarios_path=self.synth_csv,
                output_dir=self.out_dir,
                contamination=0.05,
                random_state=42,
                overwrite=False
            )


if __name__ == "__main__":
    unittest.main()
