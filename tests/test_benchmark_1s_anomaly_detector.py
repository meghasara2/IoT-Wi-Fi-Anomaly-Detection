"""
Unit tests for the standalone 1-second network feature anomaly detection benchmark.

Tests cover:
1. Safeguard 1: Sample size and contamination setting validation (rejection of too small samples or invalid contamination).
2. Feature matrix isolation (exclusion of node_id, MACs, timestamps, and metadata).
3. 5-feature missing IAT handling (training-median imputation and explicit binary missingness indicators; no hardcoded 1.0s or 0.0s).
4. Determinism (reproducible results with fixed random seed).
5. Pooled and node-specific model execution.
6. Safeguard 2: Distinction between continuous decision_function scores and discrete predictions.
7. Overwrite protection guards.
8. Input validation on missing or corrupted columns.
"""

import math
import os
import shutil
import tempfile
import unittest
import pandas as pd
import numpy as np

from src.benchmark_1s_anomaly_detector import (
    validate_input_dataset,
    check_sample_size_and_contamination,
    preprocess_features,
    evaluate_model_partition,
    run_full_benchmark,
    run_benchmark_pipeline,
    FEATURE_COLS_3,
    FEATURE_COLS_5_RAW
)


class TestBenchmark1sAnomalyDetector(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.input_csv = os.path.join(self.test_dir, "input_features.csv")
        self.out_pred = os.path.join(self.test_dir, "time_1s_benchmark_predictions.csv")
        self.out_summ = os.path.join(self.test_dir, "time_1s_benchmark_summary.csv")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_synthetic_1s_dataset(self, n1=30, n2=30):
        """Creates a synthetic DataFrame matching the 1-second feature schema."""
        rows = []
        for i in range(n1):
            is_single = (i % 5 == 0)
            rows.append({
                "client_mac": "00:11:22:33:44:55",
                "node_id": "Node_Client_1",
                "Node_Type": "Unverified_Mobile_Client",
                "Data_Label": "real_observed_traffic",
                "Window_ID": i + 1,
                "Bin_Index": i,
                "bin_start_timestamp": 1000.0 + i,
                "bin_end_timestamp": 1001.0 + i,
                "packet_count": 1 if is_single else 10,
                "packet_rate": 1.0 if is_single else 10.0,
                "mean_packet_size": 100.0 + i,
                "packet_size_std": 20.0,
                "mean_IAT": np.nan if is_single else 0.05 + (i * 0.001),
                "IAT_std": np.nan if is_single else 0.01 + (i * 0.0005)
            })

        for j in range(n2):
            is_single = (j % 4 == 0)
            rows.append({
                "client_mac": "66:77:88:99:AA:BB",
                "node_id": "Node_Client_2",
                "Node_Type": "Unverified_Mobile_Client",
                "Data_Label": "real_observed_traffic",
                "Window_ID": j + 1,
                "Bin_Index": j,
                "bin_start_timestamp": 1000.0 + j,
                "bin_end_timestamp": 1001.0 + j,
                "packet_count": 1 if is_single else 20,
                "packet_rate": 1.0 if is_single else 20.0,
                "mean_packet_size": 300.0 + j,
                "packet_size_std": 40.0,
                "mean_IAT": np.nan if is_single else 0.02 + (j * 0.001),
                "IAT_std": np.nan if is_single else 0.005 + (j * 0.0002)
            })

        df = pd.DataFrame(rows)
        df.to_csv(self.input_csv, index=False)
        return df

    def test_sample_size_and_contamination_guard(self):
        """
        Safeguard 1: Check that very small samples or invalid contamination settings
        raise clear ValueErrors.
        """
        # Too small sample size (< 15)
        with self.assertRaises(ValueError) as ctx:
            check_sample_size_and_contamination(n_samples=10, contamination=0.05, client_name="TinyClient")
        self.assertIn("too small", str(ctx.exception))

        # Sample size yields < 1 expected outlier (e.g. 20 samples * 0.01 = 0.2 < 1.0)
        with self.assertRaises(ValueError) as ctx:
            check_sample_size_and_contamination(n_samples=20, contamination=0.01, client_name="SmallClient")
        self.assertIn("fewer than 1 expected outlier", str(ctx.exception))

        # Invalid contamination ranges (<= 0 or > 0.5)
        with self.assertRaises(ValueError):
            check_sample_size_and_contamination(n_samples=50, contamination=0.0, client_name="C1")
        with self.assertRaises(ValueError):
            check_sample_size_and_contamination(n_samples=50, contamination=0.6, client_name="C1")

        # Valid setting should not raise
        check_sample_size_and_contamination(n_samples=50, contamination=0.05, client_name="ValidClient")

    def test_feature_matrix_isolation(self):
        """
        Asserts that metadata columns (node_id, client_mac, timestamps, etc.)
        are strictly excluded from the ML feature matrix.
        """
        df = self._create_synthetic_1s_dataset(n1=20, n2=20)

        # 3-feature mode
        X_3, names_3, _ = preprocess_features(df, experiment="3-feature")
        self.assertEqual(X_3.shape[1], 3)
        self.assertEqual(names_3, FEATURE_COLS_3)
        self.assertNotIn("node_id", names_3)
        self.assertNotIn("client_mac", names_3)
        self.assertNotIn("bin_start_timestamp", names_3)

        # 5-feature mode
        X_5, names_5, _ = preprocess_features(df, experiment="5-feature")
        # 3 base + 2 imputed + 2 indicators = 7 features
        self.assertEqual(X_5.shape[1], 7)
        self.assertNotIn("node_id", names_5)
        self.assertNotIn("client_mac", names_5)

    def test_5_feature_missing_iat_imputation_and_indicators(self):
        """
        Verify that missing IAT statistics produce explicit missingness indicators
        and median imputation without hardcoded 1.0 or 0.0.
        """
        df = pd.DataFrame({
            "packet_rate": [1.0, 2.0, 3.0, 4.0],
            "mean_packet_size": [100.0, 200.0, 300.0, 400.0],
            "packet_size_std": [10.0, 20.0, 30.0, 40.0],
            "mean_IAT": [np.nan, 0.10, 0.20, 0.30],
            "IAT_std": [np.nan, 0.01, 0.02, 0.03],
            "node_id": ["C1"] * 4
        })

        X, names, imputer = preprocess_features(df, experiment="5-feature")

        # Missing indicator columns are the last 2 columns
        mean_iat_miss_idx = names.index("mean_iat_missing")
        iat_std_miss_idx = names.index("iat_std_missing")

        # Row 0 had NaNs -> indicators must be 1.0
        self.assertEqual(X[0, mean_iat_miss_idx], 1.0)
        self.assertEqual(X[0, iat_std_miss_idx], 1.0)

        # Rows 1..3 had values -> indicators must be 0.0
        self.assertEqual(X[1, mean_iat_miss_idx], 0.0)
        self.assertEqual(X[1, iat_std_miss_idx], 0.0)

        # Imputed value for row 0 must be median of [0.10, 0.20, 0.30] = 0.20
        # and NOT hardcoded 1.0s or 0.0
        mean_iat_col_idx = names.index("mean_IAT_imputed")
        self.assertAlmostEqual(X[0, mean_iat_col_idx], 0.20, places=5)
        self.assertNotEqual(X[0, mean_iat_col_idx], 1.0)

        iat_std_col_idx = names.index("IAT_std_imputed")
        self.assertAlmostEqual(X[0, iat_std_col_idx], 0.02, places=5)
        self.assertNotEqual(X[0, iat_std_col_idx], 0.0)

    def test_deterministic_output(self):
        """
        Verify that running the benchmark with a fixed random_state produces
        100% identical decision function scores and outlier classifications.
        """
        df = self._create_synthetic_1s_dataset(n1=25, n2=25)

        df_res1, summ1 = run_full_benchmark(df, contamination=0.05, random_state=42)
        df_res2, summ2 = run_full_benchmark(df, contamination=0.05, random_state=42)

        # Check exact equality of score and prediction columns
        cols_to_check = [c for c in df_res1.columns if c.startswith("pred_") or c.startswith("score_")]
        for col in cols_to_check:
            self.assertTrue(df_res1[col].equals(df_res2[col]))

        # Check summary exact equality
        self.assertTrue(summ1["score_min"].equals(summ2["score_min"]))
        self.assertTrue(summ1["outlier_count"].equals(summ2["outlier_count"]))

    def test_node_specific_and_pooled_execution(self):
        """
        Verify that both pooled and node-specific models execute and populate
        separate prediction and score columns in the merged output.
        """
        df = self._create_synthetic_1s_dataset(n1=25, n2=25)
        df_res, df_summary = run_full_benchmark(df, contamination=0.05, random_state=42)

        # Total rows preserved
        self.assertEqual(len(df_res), 50)

        # Columns expected
        expected_cols = [
            "pred_3-feature_pooled", "score_3-feature_pooled",
            "pred_3-feature_node_specific", "score_3-feature_node_specific",
            "pred_5-feature_pooled", "score_5-feature_pooled",
            "pred_5-feature_node_specific", "score_5-feature_node_specific"
        ]
        for col in expected_cols:
            self.assertIn(col, df_res.columns)
            self.assertEqual(df_res[col].isna().sum(), 0)

        # Summary should have 6 entries:
        # 3-feature pooled, 3-feature Node1, 3-feature Node2,
        # 5-feature pooled, 5-feature Node1, 5-feature Node2
        self.assertEqual(len(df_summary), 6)
        scopes = set(df_summary["model_scope"])
        self.assertEqual(scopes, {"pooled", "node_specific"})

    def test_distinguish_decision_function_from_prediction(self):
        """
        Safeguard 2: Verify that decision_function scores are continuous,
        and that flagged outliers (pred == -1) correspond strictly to lower scores.
        """
        df = self._create_synthetic_1s_dataset(n1=30, n2=30)
        df_res, df_summary = run_full_benchmark(df, contamination=0.10, random_state=42)

        scores = df_res["score_3-feature_pooled"]
        preds = df_res["pred_3-feature_pooled"]

        # Continuous scores
        self.assertTrue(len(np.unique(scores)) > 10)

        # Max outlier score must be strictly less than min inlier score
        outlier_scores = scores[preds == -1]
        inlier_scores = scores[preds == 1]

        if len(outlier_scores) > 0 and len(inlier_scores) > 0:
            self.assertLess(outlier_scores.max(), inlier_scores.min())

    def test_overwrite_protection(self):
        """
        Verify that run_benchmark_pipeline refuses to overwrite existing files
        unless overwrite=True.
        """
        self._create_synthetic_1s_dataset(n1=20, n2=20)

        # Create dummy existing file
        with open(self.out_pred, "w") as f:
            f.write("existing")

        with self.assertRaises(FileExistsError):
            run_benchmark_pipeline(
                input_csv_path=self.input_csv,
                output_predictions_path=self.out_pred,
                output_summary_path=self.out_summ,
                contamination=0.05,
                overwrite=False
            )

    def test_invalid_input_validation(self):
        """
        Verify validate_input_dataset raises ValueError on empty or incomplete input.
        """
        with self.assertRaises(ValueError):
            validate_input_dataset(pd.DataFrame())

        # Missing required feature
        df_incomplete = pd.DataFrame({"packet_rate": [1.0], "node_id": ["C1"]})
        with self.assertRaises(ValueError):
            validate_input_dataset(df_incomplete)


if __name__ == "__main__":
    unittest.main()
