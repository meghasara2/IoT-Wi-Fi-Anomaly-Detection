"""
Synthetic Anomaly Benchmark Evaluation: Fixed 1-Second Time Windows
File: src/evaluate_synthetic_1s_anomalies.py

Purpose:
  Evaluates the Session 1-trained Isolation Forest models on controlled,
  reproducible synthetic 1-second feature scenarios (normal-like baseline,
  high packet-rate bursts, jumbo payloads, erratic IAT dispersion, and
  single-packet quiescent windows).

Scientific Boundaries & Methodology:
  1. Training Integrity:
     - Models and preprocessing (imputers) are trained SOLELY on Session 1
       (time_1s_session1_pcap_features_uplink.csv).
     - Synthetic data is NEVER used during model training or threshold fitting.
  2. Ground-Truth Benchmarking:
     - Synthetic scenarios are explicitly labelled by category ('normal_like',
       'high_rate_burst', 'jumbo_payload_extreme', 'erratic_iat_dispersion',
       'single_packet_quiescent') with a ground-truth binary label (is_anomaly).
     - Precision, Recall, and F1 are calculated strictly for the synthetic benchmark
       to evaluate feature sensitivities; these metrics do NOT describe real-world
       cyberattack detection accuracy.
  3. Consistent Threshold Application:
     - Evaluates the unchanged Session 1-derived decision boundary (offset_).
     - Lower decision-function scores indicate more anomalous observations.
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

try:
    from src.cross_session_1s_detector import (
        train_single_model,
        evaluate_single_model
    )
    from src.benchmark_1s_anomaly_detector import (
        validate_input_dataset,
        preprocess_features,
        FEATURE_COLS_3,
        FEATURE_COLS_5_RAW
    )
except ModuleNotFoundError:
    from cross_session_1s_detector import (
        train_single_model,
        evaluate_single_model
    )
    from benchmark_1s_anomaly_detector import (
        validate_input_dataset,
        preprocess_features,
        FEATURE_COLS_3,
        FEATURE_COLS_5_RAW
    )


def generate_synthetic_scenarios(
    n_normal: int = 50,
    n_burst: int = 20,
    n_jumbo: int = 20,
    n_erratic: int = 20,
    n_single: int = 20,
    random_state: int = 42
) -> pd.DataFrame:
    """
    Generates reproducible synthetic 1-second feature scenarios anchored in
    observed Session 1 physics but covering controlled stress/anomaly conditions.
    """
    rng = np.random.RandomState(random_state)
    records = []
    window_seq = 0

    # -------------------------------------------------------------------------
    # Scenario 1: normal_like (is_anomaly = 0)
    # Typical mobile traffic within Session 1 interquartile bounds
    # -------------------------------------------------------------------------
    for _ in range(n_normal):
        window_seq += 1
        pkt_cnt = int(rng.randint(6, 40))
        pkt_rate = float(pkt_cnt) / 1.0
        mean_size = float(rng.uniform(220.0, 520.0))
        size_std = float(rng.uniform(260.0, 520.0))
        # Pacing corresponding to uniform arrival with small jitter
        mean_iat = float(1.0 / pkt_rate * rng.uniform(0.7, 1.3))
        iat_std = float(mean_iat * rng.uniform(0.3, 0.8))

        records.append({
            "scenario": "normal_like",
            "is_anomaly": 0,
            "Window_ID": window_seq,
            "Bin_Index": window_seq - 1,
            "node_id": "Node_Client_1",
            "client_mac": "ca:34:ea:92:d3:9e",
            "packet_count": pkt_cnt,
            "packet_rate": pkt_rate,
            "mean_packet_size": round(mean_size, 4),
            "packet_size_std": round(size_std, 4),
            "mean_IAT": round(mean_iat, 6),
            "IAT_std": round(iat_std, 6)
        })

    # -------------------------------------------------------------------------
    # Scenario 2: high_rate_burst (is_anomaly = 1)
    # Severe volumetric flood well beyond normal 95th percentile (300 to 1200 pkts/s)
    # -------------------------------------------------------------------------
    for _ in range(n_burst):
        window_seq += 1
        pkt_cnt = int(rng.randint(350, 1200))
        pkt_rate = float(pkt_cnt) / 1.0
        mean_size = float(rng.uniform(80.0, 220.0))  # Flood/ACK payloads
        size_std = float(rng.uniform(10.0, 80.0))
        mean_iat = float(1.0 / pkt_rate * rng.uniform(0.8, 1.2))
        iat_std = float(mean_iat * rng.uniform(0.1, 0.5))

        records.append({
            "scenario": "high_rate_burst",
            "is_anomaly": 1,
            "Window_ID": window_seq,
            "Bin_Index": window_seq - 1,
            "node_id": "Node_Client_1",
            "client_mac": "ca:34:ea:92:d3:9e",
            "packet_count": pkt_cnt,
            "packet_rate": pkt_rate,
            "mean_packet_size": round(mean_size, 4),
            "packet_size_std": round(size_std, 4),
            "mean_IAT": round(mean_iat, 6),
            "IAT_std": round(iat_std, 6)
        })

    # -------------------------------------------------------------------------
    # Scenario 3: jumbo_payload_extreme (is_anomaly = 1)
    # Abnormally large frames near MTU ceiling (1350 to 1500 B) with low variance
    # -------------------------------------------------------------------------
    for _ in range(n_jumbo):
        window_seq += 1
        pkt_cnt = int(rng.randint(8, 30))
        pkt_rate = float(pkt_cnt) / 1.0
        mean_size = float(rng.uniform(1380.0, 1500.0))
        size_std = float(rng.uniform(5.0, 40.0))
        mean_iat = float(1.0 / pkt_rate * rng.uniform(0.8, 1.2))
        iat_std = float(mean_iat * rng.uniform(0.2, 0.6))

        records.append({
            "scenario": "jumbo_payload_extreme",
            "is_anomaly": 1,
            "Window_ID": window_seq,
            "Bin_Index": window_seq - 1,
            "node_id": "Node_Client_1",
            "client_mac": "ca:34:ea:92:d3:9e",
            "packet_count": pkt_cnt,
            "packet_rate": pkt_rate,
            "mean_packet_size": round(mean_size, 4),
            "packet_size_std": round(size_std, 4),
            "mean_IAT": round(mean_iat, 6),
            "IAT_std": round(iat_std, 6)
        })

    # -------------------------------------------------------------------------
    # Scenario 4: erratic_iat_dispersion (is_anomaly = 1)
    # Severe timing irregularity / jitter with high intra-window IAT std dev
    # -------------------------------------------------------------------------
    for _ in range(n_erratic):
        window_seq += 1
        pkt_cnt = int(rng.randint(3, 8))
        pkt_rate = float(pkt_cnt) / 1.0
        mean_size = float(rng.uniform(120.0, 450.0))
        size_std = float(rng.uniform(80.0, 250.0))
        mean_iat = float(rng.uniform(0.20, 0.45))
        iat_std = float(rng.uniform(0.32, 0.50))  # Extreme dispersion

        records.append({
            "scenario": "erratic_iat_dispersion",
            "is_anomaly": 1,
            "Window_ID": window_seq,
            "Bin_Index": window_seq - 1,
            "node_id": "Node_Client_1",
            "client_mac": "ca:34:ea:92:d3:9e",
            "packet_count": pkt_cnt,
            "packet_rate": pkt_rate,
            "mean_packet_size": round(mean_size, 4),
            "packet_size_std": round(size_std, 4),
            "mean_IAT": round(mean_iat, 6),
            "IAT_std": round(iat_std, 6)
        })

    # -------------------------------------------------------------------------
    # Scenario 5: single_packet_quiescent (is_anomaly = 0)
    # Quiet background heartbeat: 1 packet in the second, missing IAT metrics
    # -------------------------------------------------------------------------
    for _ in range(n_single):
        window_seq += 1
        mean_size = float(rng.uniform(66.0, 120.0))

        records.append({
            "scenario": "single_packet_quiescent",
            "is_anomaly": 0,
            "Window_ID": window_seq,
            "Bin_Index": window_seq - 1,
            "node_id": "Node_Client_1",
            "client_mac": "ca:34:ea:92:d3:9e",
            "packet_count": 1,
            "packet_rate": 1.0,
            "mean_packet_size": round(mean_size, 4),
            "packet_size_std": 0.0,
            "mean_IAT": np.nan,
            "IAT_std": np.nan
        })

    df = pd.DataFrame(records)
    return df


def compute_scenario_metrics(
    y_true: np.ndarray,
    y_pred_outlier: np.ndarray
) -> Dict[str, Any]:
    """
    Computes confusion matrix and classification metrics for synthetic scenarios.
    y_true: 1 if anomaly scenario, 0 if normal-type scenario
    y_pred_outlier: 1 if model predicted outlier (-1), 0 if inlier (+1)
    """
    tp = int(np.sum((y_true == 1) & (y_pred_outlier == 1)))
    fp = int(np.sum((y_true == 0) & (y_pred_outlier == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred_outlier == 0)))
    fn = int(np.sum((y_true == 1) & (y_pred_outlier == 0)))

    precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = float(2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return {
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4)
    }


def evaluate_synthetic_dataset(
    df_train_s1: pd.DataFrame,
    df_synthetic: pd.DataFrame,
    contamination: float = 0.05,
    random_state: int = 42
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Fits models on Session 1 only, evaluates synthetic scenarios, and computes
    per-scenario and aggregate benchmark metrics.
    """
    validate_input_dataset(df_train_s1)
    validate_input_dataset(df_synthetic)

    df_scored = df_synthetic.copy()
    summary_records = []

    experiments = ["3-feature", "5-feature"]

    for exp in experiments:
        # Fit model on Session 1
        clf, imputer, feature_names, meta = train_single_model(
            df_train=df_train_s1,
            experiment=exp,
            contamination=contamination,
            random_state=random_state,
            client_name="SESSION1_POOLED"
        )

        # Evaluate on Synthetic Data
        scores, preds = evaluate_single_model(
            clf=clf,
            imputer=imputer,
            df_eval=df_synthetic,
            experiment=exp
        )

        col_score = f"score_{exp}_synth"
        col_pred = f"pred_{exp}_synth"
        df_scored[col_score] = scores
        df_scored[col_pred] = preds

        # Convert predictions to binary: outlier (-1) -> 1, inlier (+1) -> 0
        y_pred_binary = (preds == -1).astype(int)
        y_true_binary = df_synthetic["is_anomaly"].values.astype(int)

        # 1. Overall benchmark classification metrics
        overall_metrics = compute_scenario_metrics(y_true_binary, y_pred_binary)

        # 2. Per-scenario statistics
        for sc in sorted(df_synthetic["scenario"].unique()):
            sc_mask = df_synthetic["scenario"] == sc
            sc_scores = scores[sc_mask]
            sc_preds = preds[sc_mask]
            sc_cnt = len(sc_scores)
            sc_outliers = int((sc_preds == -1).sum())
            sc_pct = float(sc_outliers / sc_cnt * 100.0)
            is_anom_flag = int(df_synthetic.loc[sc_mask, "is_anomaly"].iloc[0])

            summary_records.append({
                "experiment": exp,
                "scenario": sc,
                "is_anomaly_ground_truth": is_anom_flag,
                "sample_count": sc_cnt,
                "flagged_outliers": sc_outliers,
                "flagged_pct": round(sc_pct, 2),
                "score_min": float(np.min(sc_scores)),
                "score_p25": float(np.percentile(sc_scores, 25)),
                "score_median": float(np.median(sc_scores)),
                "score_p75": float(np.percentile(sc_scores, 75)),
                "score_p95": float(np.percentile(sc_scores, 95)),
                "score_max": float(np.max(sc_scores)),
                "score_std": float(np.std(sc_scores)),
                "model_fitted_offset": meta["fitted_offset"],
                "TP_scenario": int((is_anom_flag == 1) and sc_outliers),
                "FP_scenario": int((is_anom_flag == 0) and sc_outliers),
                "overall_precision": overall_metrics["precision"],
                "overall_recall": overall_metrics["recall"],
                "overall_f1": overall_metrics["f1"],
                "feature_count": len(feature_names),
                "features_used": ";".join(feature_names)
            })

    df_summary = pd.DataFrame(summary_records)
    return df_scored, df_summary


def run_synthetic_evaluation_pipeline(
    session1_csv_path: Union[str, Path],
    output_scenarios_path: Union[str, Path],
    output_predictions_path: Union[str, Path],
    output_summary_path: Union[str, Path],
    contamination: float = 0.05,
    random_state: int = 42,
    overwrite: bool = False
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Generates synthetic scenarios, evaluates using Session 1-trained model,
    enforces overwrite guards, and saves results.
    """
    s1_p = Path(session1_csv_path)
    scen_p = Path(output_scenarios_path)
    pred_p = Path(output_predictions_path)
    summ_p = Path(output_summary_path)

    if not s1_p.exists():
        raise FileNotFoundError(f"Session 1 features CSV not found: {s1_p}")

    if not overwrite:
        for p in [scen_p, pred_p, summ_p]:
            if p.exists():
                raise FileExistsError(f"Target file already exists: {p}. Aborting to prevent overwrite.")

    # 1. Load Session 1 training baseline
    df_s1 = pd.read_csv(s1_p)

    # 2. Generate reproducible synthetic dataset
    df_synth = generate_synthetic_scenarios(
        n_normal=50,
        n_burst=20,
        n_jumbo=20,
        n_erratic=20,
        n_single=20,
        random_state=random_state
    )

    # 3. Evaluate synthetic scenarios with unchanged Session 1 model
    df_scored, df_summary = evaluate_synthetic_dataset(
        df_train_s1=df_s1,
        df_synthetic=df_synth,
        contamination=contamination,
        random_state=random_state
    )

    # 4. Save outputs safely
    for p in [scen_p, pred_p, summ_p]:
        p.parent.mkdir(parents=True, exist_ok=True)

    df_synth.to_csv(scen_p, index=False)
    df_scored.to_csv(pred_p, index=False)
    df_summary.to_csv(summ_p, index=False)

    return df_synth, df_scored, df_summary


def main():
    parser = argparse.ArgumentParser(
        description="Run isolated synthetic anomaly evaluation with Session 1-trained model."
    )
    parser.add_argument(
        "--session1-csv",
        type=str,
        default="data/processed/experimental_time_windows/time_1s_session1_pcap_features_uplink.csv",
        help="Path to Session 1 features CSV (training data)"
    )
    parser.add_argument(
        "--output-scenarios",
        type=str,
        default="data/processed/experimental_time_windows/synthetic_1s_test_scenarios.csv",
        help="Path to save generated synthetic test scenarios"
    )
    parser.add_argument(
        "--output-predictions",
        type=str,
        default="data/processed/experimental_time_windows/synthetic_1s_evaluation_predictions.csv",
        help="Path to save synthetic predictions CSV"
    )
    parser.add_argument(
        "--output-summary",
        type=str,
        default="data/processed/experimental_time_windows/synthetic_1s_evaluation_summary.csv",
        help="Path to save synthetic evaluation summary CSV"
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
    s1_p = project_root / args.session1_csv if not Path(args.session1_csv).is_absolute() else Path(args.session1_csv)
    scen_p = project_root / args.output_scenarios if not Path(args.output_scenarios).is_absolute() else Path(args.output_scenarios)
    pred_p = project_root / args.output_predictions if not Path(args.output_predictions).is_absolute() else Path(args.output_predictions)
    summ_p = project_root / args.output_summary if not Path(args.output_summary).is_absolute() else Path(args.output_summary)

    print("=" * 80)
    print("SYNTHETIC 1-SECOND ANOMALY EVALUATION BENCHMARK")
    print("=" * 80)
    print(f"Session 1 Training Features: {s1_p}")
    print(f"Synthetic Scenarios Output:  {scen_p}")
    print(f"Predictions Output:          {pred_p}")
    print(f"Summary Output:              {summ_p}")
    print(f"Contamination:               {args.contamination}")
    print(f"Random State:                {args.random_state}")
    print("=" * 80)

    df_synth, df_scored, df_summary = run_synthetic_evaluation_pipeline(
        session1_csv_path=s1_p,
        output_scenarios_path=scen_p,
        output_predictions_path=pred_p,
        output_summary_path=summ_p,
        contamination=args.contamination,
        random_state=args.random_state,
        overwrite=args.overwrite
    )

    print("\nSYNTHETIC BENCHMARK EVALUATION COMPLETE:")
    print(f"  Total Synthetic Windows: {len(df_scored)}")
    print("\n--- Per-Scenario Results ---")
    cols = [
        "experiment", "scenario", "is_anomaly_ground_truth", "sample_count",
        "flagged_outliers", "flagged_pct", "score_min", "score_median", "score_max"
    ]
    print(df_summary[cols].to_string(index=False))

    print("\n--- Overall Benchmark Classification Metrics ---")
    for exp in ["3-feature", "5-feature"]:
        sub = df_summary[df_summary["experiment"] == exp].iloc[0]
        print(f"  [{exp.upper()}] Precision: {sub['overall_precision']:.4f} | Recall: {sub['overall_recall']:.4f} | F1: {sub['overall_f1']:.4f}")

    print("\n" + "=" * 80)
    print("SCIENTIFIC BENCHMARK NOTICE:")
    print("  Models were trained solely on Session 1 real capture baseline.")
    print("  Synthetic test scenarios are separate and were never used in training.")
    print("  Precision/Recall/F1 describe synthetic scenario sensitivity, NOT real attack detection.")
    print("=" * 80)


if __name__ == "__main__":
    main()
