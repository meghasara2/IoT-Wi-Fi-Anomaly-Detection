"""
Unit tests for the Cross-Session Generalization Detector (Train S1 -> Evaluate S2).

Tests cover:
1. Training isolation: imputer and model are fitted on Session 1 only; Session 2 is transformed without refitting.
2. Threshold consistency: verifying that Session 1 fitted offset_ is applied to Session 2, and pred == -1 strictly matches score < 0.
3. Determinism: identical results across repeated runs with random_state=42.
4. Column preservation: Session 2 features and metadata are preserved in output.
5. Overwrite protection: refusal to overwrite existing output files unless overwrite=True.
6. Execution coverage: pooled and node-specific cross-session execution.
"""

import os
import shutil
import tempfile
import unittest
import pandas as pd
import numpy as np

from src.cross_session_1s_detector import (
    train_single_model,
    evaluate_single_model,
    run_cross_session_generalization,
    run_cross_session_pipeline
)


class TestCrossSession1sDetector(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.s1_csv = os.path.join(self.test_dir, "s1_features.csv")
        self.s2_csv = os.path.join(self.test_dir, "s2_features.csv")
        self.out_pred = os.path.join(self.test_dir, "cross_session_s1_to_s2_predictions.csv")
        self.out_summ = os.path.join(self.test_dir, "cross_session_s1_to_s2_summary.csv")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_synthetic_session(self, path, n_c1=30, n_c2=30, rate_offset=0.0):
        rows = []
        for i in range(n_c1):
            is_single = (i % 6 == 0)
            rows.append({
                "client_mac": "00:11:22:33:44:55",
                "node_id": "Node_Client_1",
                "Node_Type": "Unverified_Mobile_Client",
                "Data_Label": "real_observed_traffic",
                "Window_ID": i + 1,
                "Bin_Index": i,
                "bin_start_timestamp": 1000.0 + i,
                "bin_end_timestamp": 1001.0 + i,
                "packet_count": 1 if is_single else int(10 + rate_offset),
                "packet_rate": 1.0 if is_single else float(10 + rate_offset),
                "mean_packet_size": 150.0 + i,
                "packet_size_std": 25.0,
                "mean_IAT": np.nan if is_single else 0.04 + (i * 0.001),
                "IAT_std": np.nan if is_single else 0.01 + (i * 0.0005)
            })

        for j in range(n_c2):
            is_single = (j % 5 == 0)
            rows.append({
                "client_mac": "66:77:88:99:AA:BB",
                "node_id": "Node_Client_2",
                "Node_Type": "Unverified_Mobile_Client",
                "Data_Label": "real_observed_traffic",
                "Window_ID": j + 1,
                "Bin_Index": j,
                "bin_start_timestamp": 1000.0 + j,
                "bin_end_timestamp": 1001.0 + j,
                "packet_count": 1 if is_single else int(15 + rate_offset),
                "packet_rate": 1.0 if is_single else float(15 + rate_offset),
                "mean_packet_size": 320.0 + j,
                "packet_size_std": 35.0,
                "mean_IAT": np.nan if is_single else 0.03 + (j * 0.001),
                "IAT_std": np.nan if is_single else 0.008 + (j * 0.0003)
            })

        df = pd.DataFrame(rows)
        df.to_csv(path, index=False)
        return df

    def test_imputer_and_model_training_isolation(self):
        """
        Verify that for 5-feature experiment:
        - The imputer is fitted strictly on Session 1 training data.
        - Session 2 is transformed using the Session 1 imputer without refitting.
        """
        df_s1 = self._create_synthetic_session(self.s1_csv, n_c1=25, n_c2=25, rate_offset=0.0)
        df_s2 = self._create_synthetic_session(self.s2_csv, n_c1=25, n_c2=25, rate_offset=20.0)

        clf, imputer, feature_names, meta = train_single_model(
            df_train=df_s1,
            experiment="5-feature",
            contamination=0.05,
            random_state=42,
            client_name="TEST_POOL"
        )

        self.assertIsNotNone(imputer)
        # Verify imputer statistics match Session 1 median, not Session 2
        s1_iat_median = df_s1["mean_IAT"].dropna().median()
        self.assertAlmostEqual(imputer.statistics_[0], s1_iat_median, places=4)

        # Evaluate on S2
        scores, preds = evaluate_single_model(clf, imputer, df_s2, experiment="5-feature")
        self.assertEqual(len(scores), len(df_s2))
        self.assertEqual(len(preds), len(df_s2))

        # Imputer statistics should remain strictly unchanged after evaluating S2
        self.assertAlmostEqual(imputer.statistics_[0], s1_iat_median, places=4)

    def test_threshold_consistency_between_score_and_prediction(self):
        """
        Verify that evaluating S2 strictly applies the fitted offset_:
        decision_function < 0 is mathematically identical to pred == -1.
        """
        df_s1 = self._create_synthetic_session(self.s1_csv, n_c1=30, n_c2=30)
        df_s2 = self._create_synthetic_session(self.s2_csv, n_c1=20, n_c2=20, rate_offset=50.0)

        df_res, df_summ = run_cross_session_generalization(df_s1, df_s2, contamination=0.05, random_state=42)

        for exp in ["3-feature", "5-feature"]:
            scores = df_res[f"score_cross_{exp}_pooled"]
            preds = df_res[f"pred_cross_{exp}_pooled"]

            expected_preds = np.where(scores < 0.0, -1, 1)
            np.testing.assert_array_equal(preds.values, expected_preds)

    def test_deterministic_reproducibility(self):
        """
        Verify that running cross-session generalization twice with random_state=42
        produces 100% identical predictions and scores.
        """
        df_s1 = self._create_synthetic_session(self.s1_csv, n_c1=25, n_c2=25)
        df_s2 = self._create_synthetic_session(self.s2_csv, n_c1=25, n_c2=25)

        res1, summ1 = run_cross_session_generalization(df_s1, df_s2, contamination=0.05, random_state=42)
        res2, summ2 = run_cross_session_generalization(df_s1, df_s2, contamination=0.05, random_state=42)

        for col in [c for c in res1.columns if c.startswith("score_") or c.startswith("pred_")]:
            self.assertTrue(res1[col].equals(res2[col]))

        self.assertTrue(summ1["fitted_offset"].equals(summ2["fitted_offset"]))
        self.assertTrue(summ1["eval_outlier_count"].equals(summ2["eval_outlier_count"]))

    def test_output_structure_and_row_preservation(self):
        """
        Verify that Session 2 rows are fully preserved and augmented with all 4 model outputs.
        """
        df_s1 = self._create_synthetic_session(self.s1_csv, n_c1=25, n_c2=25)
        df_s2 = self._create_synthetic_session(self.s2_csv, n_c1=20, n_c2=20)

        res, summ = run_cross_session_generalization(df_s1, df_s2, contamination=0.05, random_state=42)

        self.assertEqual(len(res), len(df_s2))
        expected_cols = [
            "pred_cross_3-feature_pooled", "score_cross_3-feature_pooled",
            "pred_cross_3-feature_node_specific", "score_cross_3-feature_node_specific",
            "pred_cross_5-feature_pooled", "score_cross_5-feature_pooled",
            "pred_cross_5-feature_node_specific", "score_cross_5-feature_node_specific"
        ]
        for c in expected_cols:
            self.assertIn(c, res.columns)
            self.assertEqual(res[c].isna().sum(), 0)

        # Summary should have 6 entries:
        # 3-feature pooled, 3-feature Node1, 3-feature Node2,
        # 5-feature pooled, 5-feature Node1, 5-feature Node2
        self.assertEqual(len(summ), 6)

    def test_pipeline_overwrite_protection(self):
        """
        Verify that run_cross_session_pipeline refuses to overwrite existing files
        unless overwrite=True.
        """
        self._create_synthetic_session(self.s1_csv, n_c1=20, n_c2=20)
        self._create_synthetic_session(self.s2_csv, n_c1=20, n_c2=20)

        # Create dummy existing file
        with open(self.out_pred, "w") as f:
            f.write("existing")

        with self.assertRaises(FileExistsError):
            run_cross_session_pipeline(
                session1_csv_path=self.s1_csv,
                session2_csv_path=self.s2_csv,
                output_predictions_path=self.out_pred,
                output_summary_path=self.out_summ,
                contamination=0.05,
                overwrite=False
            )


if __name__ == "__main__":
    unittest.main()
