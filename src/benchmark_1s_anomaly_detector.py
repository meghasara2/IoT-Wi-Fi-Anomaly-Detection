"""
Standalone Experimental Benchmark for Fixed 1-Second Network Features
File: src/benchmark_1s_anomaly_detector.py

Purpose:
  Evaluates unsupervised Isolation Forest models on the experimental 1-second
  network traffic dataset (time_1s_pcap_features_uplink.csv).

Experimental Design & Boundaries:
  1. Compares two feature regimes:
     - Experiment A: 3-feature baseline ('packet_rate', 'mean_packet_size', 'packet_size_std')
     - Experiment B: 5-feature experiment (baseline + 'mean_IAT', 'IAT_std') with explicit
       missingness indicators and training-median imputation (no hardcoded 1.0s or assumed zero std).
  2. Evaluates both Pooled and Node-Specific model configurations.
  3. Enforces strict safeguards on sample size and contamination settings.
  4. Keeps 'node_id' purely for grouping/reporting; excludes all metadata, timestamps,
     labels, and environmental sensor fields from ML feature matrices.
  5. Distinguishes decision_function scores (continuous isolation depth) from discrete
     predictions (outlier flagging via thresholding).
  6. Zero connection to production databases (iot_anomaly.db), models, or dashboard.
"""

import sys
import math
import argparse
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional, Union

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer


FEATURE_COLS_3 = ["packet_rate", "mean_packet_size", "packet_size_std"]
FEATURE_COLS_5_RAW = ["packet_rate", "mean_packet_size", "packet_size_std", "mean_IAT", "IAT_std"]
METADATA_COLS = ["client_mac", "node_id", "Node_Type", "Data_Label", "Window_ID", "Bin_Index", "bin_start_timestamp", "bin_end_timestamp"]


def validate_input_dataset(df: pd.DataFrame) -> None:
    """
    Validates that the input DataFrame has required columns and is not empty.
    """
    if df.empty:
        raise ValueError("Input network feature DataFrame is empty.")

    required = set(FEATURE_COLS_5_RAW) | {"node_id"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Input DataFrame is missing required columns: {sorted(list(missing))}")

    # Check non-negative packet rates and sizes
    if (df["packet_rate"] < 0).any():
        raise ValueError("Found negative packet_rate values in input dataset.")
    if (df["mean_packet_size"] < 0).any():
        raise ValueError("Found negative mean_packet_size values in input dataset.")


def check_sample_size_and_contamination(
    n_samples: int,
    contamination: Union[float, str],
    client_name: str,
    min_samples: int = 15
) -> None:
    """
    Safeguard 1: Validates that sample size is sufficient for the chosen contamination setting.
    Raises clear ValueError for invalid or unstable configurations.
    """
    if n_samples < min_samples:
        raise ValueError(
            f"Sample size for '{client_name}' ({n_samples}) is too small for stable Isolation Forest "
            f"modeling (minimum required: {min_samples}). Cannot reliably fit trees."
        )

    if isinstance(contamination, str):
        if contamination != "auto":
            raise ValueError(f"Invalid string contamination setting '{contamination}'. Must be 'auto' or a float in (0, 0.5].")
        return

    if not isinstance(contamination, (int, float)):
        raise TypeError(f"Contamination must be float or 'auto', got {type(contamination).__name__}.")

    if contamination <= 0.0 or contamination > 0.5:
        raise ValueError(f"Contamination setting ({contamination}) must be in range (0.0, 0.5].")

    expected_outliers = n_samples * contamination
    if expected_outliers < 1.0:
        raise ValueError(
            f"Sample size for '{client_name}' ({n_samples}) with contamination={contamination} "
            f"yields fewer than 1 expected outlier ({expected_outliers:.2f} < 1.0). "
            f"Increase sample size or use a higher contamination setting."
        )


def preprocess_features(
    df: pd.DataFrame,
    experiment: str = "5-feature",
    imputer: Optional[SimpleImputer] = None
) -> Tuple[np.ndarray, List[str], Optional[SimpleImputer]]:
    """
    Prepares the numerical feature matrix.
    - 3-feature mode: uses packet_rate, mean_packet_size, packet_size_std.
    - 5-feature mode: adds mean_IAT and IAT_std, appends explicit binary missingness indicators
      ('mean_iat_missing', 'iat_std_missing'), and imputes missing IAT using training-data median.
      Does NOT hardcode 1.0s or assume zero std dev.
    """
    if experiment == "3-feature":
        X = df[FEATURE_COLS_3].copy().values.astype(float)
        return X, FEATURE_COLS_3.copy(), None

    elif experiment == "5-feature":
        # Extract base 3 features
        X_base = df[FEATURE_COLS_3].copy().values.astype(float)

        # Binary missingness indicators
        mean_iat_missing = df["mean_IAT"].isna().astype(float).values.reshape(-1, 1)
        iat_std_missing = df["IAT_std"].isna().astype(float).values.reshape(-1, 1)

        # IAT values to impute
        iat_raw = df[["mean_IAT", "IAT_std"]].copy().values.astype(float)

        if imputer is None:
            imputer = SimpleImputer(strategy="median")
            iat_imputed = imputer.fit_transform(iat_raw)
        else:
            iat_imputed = imputer.transform(iat_raw)

        # Combine: 3 base + 2 imputed IAT + 2 indicators = 7 features
        X = np.hstack([X_base, iat_imputed, mean_iat_missing, iat_std_missing])
        feature_names = FEATURE_COLS_3 + ["mean_IAT_imputed", "IAT_std_imputed", "mean_iat_missing", "iat_std_missing"]
        return X, feature_names, imputer

    else:
        raise ValueError(f"Unknown experiment mode: '{experiment}'. Expected '3-feature' or '5-feature'.")


def evaluate_model_partition(
    df_partition: pd.DataFrame,
    experiment: str,
    scope: str,
    client_name: str,
    contamination: float = 0.05,
    random_state: int = 42
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Evaluates an Isolation Forest on a specific data partition (either pooled or a single node).
    Returns augmented dataframe slice and summary metrics.
    """
    n_samples = len(df_partition)
    check_sample_size_and_contamination(n_samples, contamination, client_name)

    X, feature_names, imputer = preprocess_features(df_partition, experiment=experiment)

    clf = IsolationForest(
        contamination=contamination,
        random_state=random_state,
        n_estimators=100
    )
    clf.fit(X)

    # Predictions: 1 = inlier, -1 = outlier
    preds = clf.predict(X)
    # Decision function: continuous isolation score (lower / more negative = more anomalous)
    scores = clf.decision_function(X)

    df_res = df_partition.copy()
    col_pred = f"pred_{experiment}_{scope}"
    col_score = f"score_{experiment}_{scope}"
    df_res[col_pred] = preds
    df_res[col_score] = scores

    outlier_count = int((preds == -1).sum())
    inlier_count = int((preds == 1).sum())
    outlier_pct = float(outlier_count / n_samples * 100.0)

    summary_entry = {
        "experiment": experiment,
        "model_scope": scope,
        "client_name": client_name,
        "n_samples": n_samples,
        "feature_count": X.shape[1],
        "feature_names": ";".join(feature_names),
        "contamination_setting": contamination,
        "outlier_count": outlier_count,
        "inlier_count": inlier_count,
        "outlier_pct": round(outlier_pct, 2),
        "score_min": float(np.min(scores)),
        "score_p25": float(np.percentile(scores, 25)),
        "score_median": float(np.median(scores)),
        "score_p75": float(np.percentile(scores, 75)),
        "score_p95": float(np.percentile(scores, 95)),
        "score_max": float(np.max(scores)),
        "score_std": float(np.std(scores)),
        "decision_function_meaning": (
            "Continuous isolation depth: lower (more negative) values indicate greater statistical abnormality; "
            "higher positive values indicate typicality."
        ),
        "contamination_role": (
            "The contamination parameter sets the percentile offset separating inliers (+1) and outliers (-1). "
            "Changing contamination primarily alters this decision boundary rather than demonstrating detection efficacy."
        ),
        "sample_size_warning": (
            f"N={n_samples} is a small observational sample. Tree path lengths have high estimator variance; "
            "flagged statistical outliers are NOT confirmed attacks."
        )
    }

    return df_res, summary_entry


def run_full_benchmark(
    df_input: pd.DataFrame,
    contamination: float = 0.05,
    random_state: int = 42
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Runs all 4 experimental benchmark combinations:
    1. 3-Feature Pooled
    2. 3-Feature Node-Specific
    3. 5-Feature Pooled
    4. 5-Feature Node-Specific
    """
    validate_input_dataset(df_input)

    df_combined = df_input.copy()
    summaries = []

    experiments = ["3-feature", "5-feature"]
    nodes = df_input["node_id"].unique()

    for exp in experiments:
        # --- A. Pooled Model ---
        _, summ_pooled = evaluate_model_partition(
            df_partition=df_input,
            experiment=exp,
            scope="pooled",
            client_name="ALL_POOLED",
            contamination=contamination,
            random_state=random_state
        )
        # Compute predictions across entire df for merged table
        X_p, _, _ = preprocess_features(df_input, experiment=exp)
        clf_p = IsolationForest(contamination=contamination, random_state=random_state, n_estimators=100)
        clf_p.fit(X_p)
        df_combined[f"pred_{exp}_pooled"] = clf_p.predict(X_p)
        df_combined[f"score_{exp}_pooled"] = clf_p.decision_function(X_p)
        summaries.append(summ_pooled)

        # --- B. Node-Specific Model ---
        pred_node_col = f"pred_{exp}_node_specific"
        score_node_col = f"score_{exp}_node_specific"
        df_combined[pred_node_col] = np.nan
        df_combined[score_node_col] = np.nan

        for node in sorted(nodes):
            df_node = df_input[df_input["node_id"] == node].copy()
            df_node_res, summ_node = evaluate_model_partition(
                df_partition=df_node,
                experiment=exp,
                scope="node_specific",
                client_name=str(node),
                contamination=contamination,
                random_state=random_state
            )
            df_combined.loc[df_combined["node_id"] == node, pred_node_col] = df_node_res[f"pred_{exp}_node_specific"]
            df_combined.loc[df_combined["node_id"] == node, score_node_col] = df_node_res[f"score_{exp}_node_specific"]
            summaries.append(summ_node)

    df_summary = pd.DataFrame(summaries)
    return df_combined, df_summary


def run_benchmark_pipeline(
    input_csv_path: Union[str, Path],
    output_predictions_path: Union[str, Path],
    output_summary_path: Union[str, Path],
    contamination: float = 0.05,
    random_state: int = 42,
    overwrite: bool = False
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Orchestrates input loading, benchmark execution, overwrite guards, and CSV persistence.
    """
    in_p = Path(input_csv_path)
    out_pred_p = Path(output_predictions_path)
    out_summ_p = Path(output_summary_path)

    if not in_p.exists():
        raise FileNotFoundError(f"Input feature file not found: {in_p}")

    if not overwrite:
        if out_pred_p.exists():
            raise FileExistsError(f"Target prediction output file already exists: {out_pred_p}. Aborting to prevent overwrite.")
        if out_summ_p.exists():
            raise FileExistsError(f"Target summary output file already exists: {out_summ_p}. Aborting to prevent overwrite.")

    df_input = pd.read_csv(in_p)
    df_pred, df_summary = run_full_benchmark(
        df_input=df_input,
        contamination=contamination,
        random_state=random_state
    )

    out_pred_p.parent.mkdir(parents=True, exist_ok=True)
    df_pred.to_csv(out_pred_p, index=False)
    df_summary.to_csv(out_summ_p, index=False)

    return df_pred, df_summary


def main():
    parser = argparse.ArgumentParser(
        description="Run standalone experimental benchmark for fixed 1-second network features."
    )
    parser.add_argument(
        "--input-csv",
        type=str,
        default="data/processed/experimental_time_windows/time_1s_pcap_features_uplink.csv",
        help="Path to 1-second network features CSV"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data/processed/experimental_time_windows",
        help="Directory to save experimental benchmark outputs"
    )
    parser.add_argument(
        "--output-predictions",
        type=str,
        default=None,
        help="Optional explicit path/filename for predictions CSV (overrides --output-dir default)"
    )
    parser.add_argument(
        "--output-summary",
        type=str,
        default=None,
        help="Optional explicit path/filename for summary CSV (overrides --output-dir default)"
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.05,
        help="Isolation Forest contamination setting (default: 0.05)"
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Deterministic random seed (default: 42)"
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow overwriting existing output CSV files"
    )

    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    in_p = project_root / args.input_csv if not Path(args.input_csv).is_absolute() else Path(args.input_csv)
    out_dir = project_root / args.output_dir if not Path(args.output_dir).is_absolute() else Path(args.output_dir)

    if args.output_predictions:
        out_pred_p = project_root / args.output_predictions if not Path(args.output_predictions).is_absolute() else Path(args.output_predictions)
    else:
        out_pred_p = out_dir / "time_1s_benchmark_predictions.csv"

    if args.output_summary:
        out_summ_p = project_root / args.output_summary if not Path(args.output_summary).is_absolute() else Path(args.output_summary)
    else:
        out_summ_p = out_dir / "time_1s_benchmark_summary.csv"

    print("=" * 80)
    print("EXPERIMENTAL 1-SECOND NETWORK FEATURE ANOMALY BENCHMARK")
    print("=" * 80)
    print(f"Input Features:      {in_p}")
    print(f"Contamination:       {args.contamination}")
    print(f"Random State:        {args.random_state}")
    print(f"Predictions Target:  {out_pred_p}")
    print(f"Summary Target:      {out_summ_p}")
    print("=" * 80)

    df_pred, df_summary = run_benchmark_pipeline(
        input_csv_path=in_p,
        output_predictions_path=out_pred_p,
        output_summary_path=out_summ_p,
        contamination=args.contamination,
        random_state=args.random_state,
        overwrite=args.overwrite
    )

    print("\nBENCHMARK EXECUTION COMPLETE:")
    print(f"  Total Windows Evaluated: {len(df_pred)}")
    print(f"  Summary Configurations:  {len(df_summary)}")
    print("\n--- Summary Results ---")
    cols_to_print = [
        "experiment", "model_scope", "client_name", "n_samples",
        "contamination_setting", "outlier_count", "outlier_pct",
        "score_min", "score_median", "score_max"
    ]
    print(df_summary[cols_to_print].to_string(index=False))
    print("\n" + "=" * 80)
    print("SCIENTIFIC SAFEGUARD NOTICE:")
    print("  1. Decision-Function vs Predictions: Lower scores reflect higher isolation depth.")
    print("     Contamination shifts the decision threshold quantile; it does NOT prove attack detection.")
    print("  2. Outliers != Attacks: Ground-truth attack labels are not present in this real capture trace.")
    print("=" * 80)


if __name__ == "__main__":
    main()
