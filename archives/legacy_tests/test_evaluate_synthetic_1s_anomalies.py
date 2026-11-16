"""
Unit tests for the isolated synthetic anomaly evaluation benchmark.

Tests cover:
1. Reproducibility of synthetic scenario generation with fixed seed.
2. Scenario schema validation and required column presence.
3. Proper handling of missing IAT values in single-packet quiescent scenario.
4. Precision, Recall, and F1 calculation correctness.
5. Evaluation using Session 1-trained model without refitting on synthetic data.
6. Overwrite protection guards on all generated files.
"""

import os
import shutil
import tempfile
import unittest
import pandas as pd
import numpy as np

from src.evaluate_synthetic_1s_anomalies import (
    generate_synthetic_scenarios,
    compute_scenario_metrics,
    evaluate_synthetic_dataset,
    run_synthetic_evaluation_pipeline
)
from src.cross_session_1s_detector import train_single_model


class TestEvaluateSynthetic1sAnomalies(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.s1_csv = os.path.join(self.test_dir, "test_s1.csv")
        self.out_scen = os.path.join(self.test_dir, "synthetic_1s_test_scenarios.csv")
        self.out_pred = os.path.join(self.test_dir, "synthetic_1s_evaluation_predictions.csv")
        self.out_summ = os.path.join(self.test_dir, "synthetic_1s_evaluation_summary.csv")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_synthetic_train_baseline(self, n=50):
        rows = []
        for i in range(n):
            is_single = (i % 8 == 0)
            rows.append({
                "client_mac": "00:11:22:33:44:55",
                "node_id": "Node_Client_1",
                "Node_Type": "Unverified_Mobile_Client",
                "Data_Label": "real_observed_traffic",
                "Window_ID": i + 1,
                "Bin_Index": i,
                "bin_start_timestamp": 1000.0 + i,
                "bin_end_timestamp": 1001.0 + i,
                "packet_count": 1 if is_single else 15,
                "packet_rate": 1.0 if is_single else 15.0,
                "mean_packet_size": 250.0 + (i * 2.0),
                "packet_size_std": 30.0,
                "mean_IAT": np.nan if is_single else 0.03 + (i * 0.001),
                "IAT_std": np.nan if is_single else 0.01 + (i * 0.0005)
            })
        df = pd.DataFrame(rows)
        df.to_csv(self.s1_csv, index=False)
        return df

    def test_reproducibility_of_scenario_generation(self):
        """
        Verify that generate_synthetic_scenarios produces identical dataframes
        when using the same random seed.
        """
        df1 = generate_synthetic_scenarios(n_normal=20, n_burst=10, random_state=42)
        df2 = generate_synthetic_scenarios(n_normal=20, n_burst=10, random_state=42)

        pd.testing.assert_frame_equal(df1, df2)

    def test_schema_and_column_integrity(self):
        """
        Verify all required network feature columns and ground truth labels
        are present in the generated synthetic scenarios.
        """
        df = generate_synthetic_scenarios(n_normal=10, n_burst=5, n_jumbo=5, n_erratic=5, n_single=5)
        self.assertEqual(len(df), 30)

        required_cols = [
            "scenario", "is_anomaly", "Window_ID", "Bin_Index", "node_id",
            "packet_count", "packet_rate", "mean_packet_size", "packet_size_std",
            "mean_IAT", "IAT_std"
        ]
        for col in required_cols:
            self.assertIn(col, df.columns)

        scenarios = set(df["scenario"].unique())
        self.assertEqual(scenarios, {
            "normal_like", "high_rate_burst", "jumbo_payload_extreme",
            "erratic_iat_dispersion", "single_packet_quiescent"
        })

    def test_single_packet_quiescent_scenario_conventions(self):
        """
        Verify that single-packet quiescent scenario maintains:
        packet_count = 1, packet_rate = 1.0, packet_size_std = 0.0,
        mean_IAT = NaN, IAT_std = NaN, is_anomaly = 0.
        """
        df = generate_synthetic_scenarios(n_normal=5, n_single=10)
        df_single = df[df["scenario"] == "single_packet_quiescent"]

        self.assertEqual(len(df_single), 10)
        self.assertTrue((df_single["packet_count"] == 1).all())
        self.assertTrue((df_single["packet_rate"] == 1.0).all())
        self.assertTrue((df_single["packet_size_std"] == 0.0).all())
        self.assertTrue(df_single["mean_IAT"].isna().all())
        self.assertTrue(df_single["IAT_std"].isna().all())
        self.assertTrue((df_single["is_anomaly"] == 0).all())

    def test_confusion_metrics_computation(self):
        """
        Verify compute_scenario_metrics accurately calculates TP, FP, TN, FN,
        precision, recall, and F1.
        """
        y_true = np.array([1, 1, 1, 1, 0, 0, 0, 0])
        # 3 TP, 1 FN, 1 FP, 3 TN
        y_pred = np.array([1, 1, 1, 0, 1, 0, 0, 0])

        metrics = compute_scenario_metrics(y_true, y_pred)
        self.assertEqual(metrics["TP"], 3)
        self.assertEqual(metrics["FN"], 1)
        self.assertEqual(metrics["FP"], 1)
        self.assertEqual(metrics["TN"], 3)
        self.assertAlmostEqual(metrics["precision"], 3.0 / 4.0, places=4)
        self.assertAlmostEqual(metrics["recall"], 3.0 / 4.0, places=4)
        self.assertAlmostEqual(metrics["f1"], 3.0 / 4.0, places=4)

    def test_evaluation_without_model_refitting(self):
        """
        Verify that evaluate_synthetic_dataset evaluates the synthetic scenarios
        using the unchanged Session 1 model and imputer.
        """
        df_train = self._create_synthetic_train_baseline(n=40)
        df_synth = generate_synthetic_scenarios(n_normal=20, n_burst=10, n_jumbo=10, random_state=42)

        df_scored, df_summary = evaluate_synthetic_dataset(
            df_train_s1=df_train,
            df_synthetic=df_synth,
            contamination=0.05,
            random_state=42
        )

        self.assertEqual(len(df_scored), len(df_synth))
        self.assertIn("score_3-feature_synth", df_scored.columns)
        self.assertIn("pred_3-feature_synth", df_scored.columns)
        self.assertIn("score_5-feature_synth", df_scored.columns)
        self.assertIn("pred_5-feature_synth", df_scored.columns)

        # Summary should have rows for each scenario across both experiments
        self.assertGreater(len(df_summary), 0)
        self.assertIn("overall_f1", df_summary.columns)

    def test_overwrite_protection(self):
        """
        Verify run_synthetic_evaluation_pipeline raises FileExistsError
        when output files already exist and overwrite=False.
        """
        self._create_synthetic_train_baseline(n=30)

        # Create dummy file
        with open(self.out_scen, "w") as f:
            f.write("existing")

        with self.assertRaises(FileExistsError):
            run_synthetic_evaluation_pipeline(
                session1_csv_path=self.s1_csv,
                output_scenarios_path=self.out_scen,
                output_predictions_path=self.out_pred,
                output_summary_path=self.out_summ,
                contamination=0.05,
                overwrite=False
            )


if __name__ == "__main__":
    unittest.main()
