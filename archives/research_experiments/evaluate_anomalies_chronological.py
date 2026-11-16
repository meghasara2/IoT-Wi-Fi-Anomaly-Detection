"""
Experimental Script: Chronological Anomaly Detection Evaluation
File: src/evaluate_anomalies_chronological.py

Purpose:
  Evaluates Node-Specific Isolation Forest models using a strict chronological
  train/test split on synthetic normal IoT feature windows, eliminating temporal
  shuffling leakage.

Important Experimental Disclaimers:
  1. The anomaly windows evaluated here are from independently generated synthetic
     scenarios (data/processed/anomaly_5node_features.csv), NOT real physical attack captures.
  2. Isolation Forest is fitted strictly on the earlier 80% normal baseline.
  3. No anomaly data is used during fitting or threshold tuning.
  4. Precision and F1 scores depend directly on the relative test-set prevalence
     of normal vs. anomaly samples, which is documented explicitly without artificial resampling.
"""

import sys
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest


FEATURE_COLS = [
    "mean_IAT",
    "IAT_std",
    "packet_rate",
    "mean_packet_size",
    "packet_size_std"
]

METADATA_COLS = ["Node_ID", "Node_Type", "Window_ID"]


def validate_input_data(df_normal: pd.DataFrame, df_anomaly: pd.DataFrame):
    """
    Validates schemas, non-emptiness, and required features of input datasets.
    """
    for name, df in [("Normal", df_normal), ("Anomaly", df_anomaly)]:
        if df.empty:
            raise ValueError(f"{name} dataset is empty.")
        missing_feats = [col for col in FEATURE_COLS if col not in df.columns]
        if missing_feats:
            raise KeyError(f"{name} dataset is missing required feature columns: {missing_feats}")
        missing_meta = [col for col in METADATA_COLS if col not in df.columns]
        if missing_meta:
            raise KeyError(f"{name} dataset is missing required metadata columns: {missing_meta}")


def compute_chronological_evaluation(
    normal_features_path: Path,
    anomaly_features_path: Path,
    output_dir: Path,
    train_ratio: float = 0.8,
    contamination: float = 0.05,
    random_state: int = 42
):
    """
    Performs chronological train/test split per Node_ID, fits Isolation Forest on normal baseline,
    and calculates classification metrics on held-out normal and synthetic anomaly windows.
    """
    # 1. Output safety: Refuse to overwrite existing directory or files
    detailed_output_file = output_dir / "chronological_predictions_detailed.csv"
    summary_output_file = output_dir / "chronological_metrics_summary.csv"

    if detailed_output_file.exists():
        raise FileExistsError(f"Target detailed output file already exists: {detailed_output_file}. Aborting to prevent overwrite.")
    if summary_output_file.exists():
        raise FileExistsError(f"Target summary output file already exists: {summary_output_file}. Aborting to prevent overwrite.")

    # 2. Input file existence check
    if not normal_features_path.exists():
        raise FileNotFoundError(f"Normal features file not found: {normal_features_path}")
    if not anomaly_features_path.exists():
        raise FileNotFoundError(f"Anomaly features file not found: {anomaly_features_path}")

    df_normal = pd.read_csv(normal_features_path)
    df_anomaly = pd.read_csv(anomaly_features_path)

    validate_input_data(df_normal, df_anomaly)

    print("=" * 80)
    print("EXPERIMENTAL EVALUATION: CHRONOLOGICAL ISOLATION FOREST")
    print("Status: Synthetic Benchmark (Not Real Cyberattack Traffic)")
    print(f"Normal Feature Source:  {normal_features_path}")
    print(f"Anomaly Feature Source: {anomaly_features_path}")
    print(f"Split Mode: Chronological (First {train_ratio*100:.0f}% Train / Later {(1-train_ratio)*100:.0f}% Test)")
    print("=" * 80)

    all_detailed_records = []
    summary_records = []

    unique_nodes = df_normal["Node_ID"].unique()

    for node_id in unique_nodes:
        # Filter node data and enforce strict chronological order by Window_ID
        df_node_norm = df_normal[df_normal["Node_ID"] == node_id].sort_values("Window_ID").reset_index(drop=True)
        df_node_anom = df_anomaly[df_anomaly["Node_ID"] == node_id].sort_values("Window_ID").reset_index(drop=True)

        n_norm = len(df_node_norm)
        n_anom = len(df_node_anom)

        if n_norm < 10:
            raise ValueError(f"Node {node_id} has insufficient normal windows ({n_norm}) for reliable evaluation.")

        # Determine chronological cutoff index (strict temporal split without shuffling)
        split_idx = int(n_norm * train_ratio)
        df_train_norm = df_node_norm.iloc[:split_idx].copy()
        df_test_norm = df_node_norm.iloc[split_idx:].copy()

        n_train = len(df_train_norm)
        n_test_norm = len(df_test_norm)

        # Transparency warning for small sample sizes
        small_sample_warning = ""
        if n_test_norm < 15:
            small_sample_warning = f"CAUTION: Very small normal test sample (N={n_test_norm}). FPR estimates have high variance."

        # Fit Isolation Forest strictly on earlier normal baseline
        clf = IsolationForest(
            contamination=contamination,
            random_state=random_state
        )
        clf.fit(df_train_norm[FEATURE_COLS])

        # Evaluate on unseen later normal windows
        # Note: Isolation Forest returns -1 for anomaly, +1 for inlier
        norm_preds = clf.predict(df_test_norm[FEATURE_COLS])
        norm_scores = clf.decision_function(df_test_norm[FEATURE_COLS])

        df_test_norm["ground_truth"] = "normal"
        df_test_norm["ground_truth_binary"] = 0  # 0 = Normal
        df_test_norm["raw_prediction"] = norm_preds
        df_test_norm["predicted_anomaly"] = (norm_preds == -1).astype(int)  # 1 = Anomaly
        df_test_norm["anomaly_score"] = norm_scores
        df_test_norm["evaluation_split"] = "chronological_test_normal"

        # Evaluate on synthetic anomaly windows
        anom_preds = clf.predict(df_node_anom[FEATURE_COLS])
        anom_scores = clf.decision_function(df_node_anom[FEATURE_COLS])

        df_node_anom_eval = df_node_anom.copy()
        df_node_anom_eval["ground_truth"] = "synthetic_anomaly"
        df_node_anom_eval["ground_truth_binary"] = 1  # 1 = Anomaly
        df_node_anom_eval["raw_prediction"] = anom_preds
        df_node_anom_eval["predicted_anomaly"] = (anom_preds == -1).astype(int)
        df_node_anom_eval["anomaly_score"] = anom_scores
        df_node_anom_eval["evaluation_split"] = "synthetic_anomaly_test"

        # Combine into unified node evaluation table
        df_combined_node_test = pd.concat([df_test_norm, df_node_anom_eval], ignore_index=True)
        all_detailed_records.append(df_combined_node_test)

        # Calculate Confusion Matrix
        # Binary definition: Positive = Anomaly (1), Negative = Normal (0)
        # True Positive (TP): Anomaly correctly flagged as anomaly
        # False Positive (FP): Normal incorrectly flagged as anomaly (False Alarm)
        # True Negative (TN): Normal correctly flagged as normal
        # False Negative (FN): Anomaly missed (flagged as normal)
        tp = int(((df_combined_node_test["ground_truth_binary"] == 1) & (df_combined_node_test["predicted_anomaly"] == 1)).sum())
        fp = int(((df_combined_node_test["ground_truth_binary"] == 0) & (df_combined_node_test["predicted_anomaly"] == 1)).sum())
        tn = int(((df_combined_node_test["ground_truth_binary"] == 0) & (df_combined_node_test["predicted_anomaly"] == 0)).sum())
        fn = int(((df_combined_node_test["ground_truth_binary"] == 1) & (df_combined_node_test["predicted_anomaly"] == 0)).sum())

        # Metrics
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0  # Detection Rate
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0

        node_type = df_node_norm["Node_Type"].iloc[0]

        summary_records.append({
            "Node_ID": node_id,
            "Node_Type": node_type,
            "Train_Windows_Normal": n_train,
            "Test_Windows_Normal": n_test_norm,
            "Test_Windows_Anomaly": n_anom,
            "Total_Test_Windows": len(df_combined_node_test),
            "True_Positives_TP": tp,
            "False_Positives_FP": fp,
            "True_Negatives_TN": tn,
            "False_Negatives_FN": fn,
            "False_Positive_Rate_FPR": round(fpr, 4),
            "Recall_Detection_Rate": round(recall, 4),
            "Precision": round(precision, 4),
            "F1_Score": round(f1, 4),
            "Accuracy": round(accuracy, 4),
            "Sample_Size_Notes": small_sample_warning if small_sample_warning else "Adequate"
        })

    df_detailed = pd.concat(all_detailed_records, ignore_index=True)
    df_summary = pd.DataFrame(summary_records)

    # 3. Create output directory if not present and persist outputs
    output_dir.mkdir(parents=True, exist_ok=True)
    df_detailed.to_csv(detailed_output_file, index=False)
    df_summary.to_csv(summary_output_file, index=False)

    print("\n" + "-" * 80)
    print("CHRONOLOGICAL EVALUATION SUMMARY RESULTS:")
    print("-" * 80)
    print(df_summary.to_string(index=False))

    print(f"\nOutputs saved:")
    print(f"  - Detailed Predictions: {detailed_output_file}")
    print(f"  - Metrics Summary:      {summary_output_file}")

    return df_detailed, df_summary


def main():
    project_root = Path(__file__).parent.parent
    normal_features_csv = project_root / "data" / "processed" / "normal_5node_features.csv"
    anomaly_features_csv = project_root / "data" / "processed" / "anomaly_5node_features.csv"
    output_directory = project_root / "data" / "processed" / "chronological_evaluation"

    try:
        compute_chronological_evaluation(
            normal_features_path=normal_features_csv,
            anomaly_features_path=anomaly_features_csv,
            output_dir=output_directory,
            train_ratio=0.8,
            contamination=0.05,
            random_state=42
        )
    except Exception as e:
        print(f"Error during chronological evaluation: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
