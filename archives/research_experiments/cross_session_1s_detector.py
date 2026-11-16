"""
Cross-Session Generalization Detector: Fixed 1-Second Time Windows
File: src/cross_session_1s_detector.py

Purpose:
  Evaluates cross-session generalization by training unsupervised Isolation Forest
  models strictly on Session 1 network features, and applying the unchanged fitted
  models and preprocessing to evaluate Session 2.

Core Scientific Boundaries & Methodology:
  1. Train on Session 1 ONLY:
     - Isolation Forest estimators are fitted solely on Session 1 (time_1s_session1_pcap_features_uplink.csv).
     - Missing IAT imputer (SimpleImputer) is fitted solely on Session 1 IAT columns.
  2. Evaluate on Session 2 WITHOUT Refitting:
     - Session 2 (time_1s_pcap_features_uplink.csv) is transformed using the Session 1 imputer.
     - Predictions and decision_function scores are computed using the Session 1 fitted model.
     - Neither the model nor the imputer is ever refitted or updated on Session 2 data.
  3. Consistent Threshold Application:
     - scikit-learn's IsolationForest computes an internal threshold (offset_) during training
       based on the training contamination setting.
     - Calling clf.decision_function(X_eval) evaluates (score_samples(X_eval) - clf.offset_).
     - Calling clf.predict(X_eval) evaluates (decision_function(X_eval) < 0) -> -1 (outlier).
     - Thus, the exact decision boundary derived from Session 1 is preserved and applied to Session 2.
  4. Isolation:
     - No database, dashboard, or production model interaction.
     - Preserves all Session 1 and Session 2 files; outputs saved to dedicated paths.
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
    from src.benchmark_1s_anomaly_detector import (
        validate_input_dataset,
        check_sample_size_and_contamination,
        preprocess_features,
        FEATURE_COLS_3,
        FEATURE_COLS_5_RAW
    )
except ModuleNotFoundError:
    from benchmark_1s_anomaly_detector import (
        validate_input_dataset,
        check_sample_size_and_contamination,
        preprocess_features,
        FEATURE_COLS_3,
        FEATURE_COLS_5_RAW
    )


def train_single_model(
    df_train: pd.DataFrame,
    experiment: str,
    contamination: float = 0.05,
    random_state: int = 42,
    client_name: str = "ALL_POOLED"
) -> Tuple[IsolationForest, Optional[SimpleImputer], List[str], Dict[str, Any]]:
    """
    Trains an Isolation Forest and fits feature preprocessing solely on training data (Session 1).
    """
    n_train = len(df_train)
    check_sample_size_and_contamination(n_train, contamination, client_name)

    X_train, feature_names, imputer = preprocess_features(df_train, experiment=experiment, imputer=None)

    clf = IsolationForest(
        contamination=contamination,
        random_state=random_state,
        n_estimators=100
    )
    clf.fit(X_train)

    train_scores = clf.decision_function(X_train)
    train_preds = clf.predict(X_train)

    train_meta = {
        "client_name": client_name,
        "experiment": experiment,
        "n_train_samples": n_train,
        "fitted_offset": float(clf.offset_),
        "train_outlier_count": int((train_preds == -1).sum()),
        "train_score_min": float(np.min(train_scores)),
        "train_score_median": float(np.median(train_scores)),
        "train_score_max": float(np.max(train_scores)),
        "feature_names": feature_names
    }

    if experiment == "5-feature" and imputer is not None:
        train_meta["fitted_median_mean_IAT"] = float(imputer.statistics_[0])
        train_meta["fitted_median_IAT_std"] = float(imputer.statistics_[1])

    return clf, imputer, feature_names, train_meta


def evaluate_single_model(
    clf: IsolationForest,
    imputer: Optional[SimpleImputer],
    df_eval: pd.DataFrame,
    experiment: str
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Evaluates an unchanged fitted model on evaluation data (Session 2).
    Preprocesses data using the passed (Session 1 fitted) imputer without refitting.
    """
    X_eval, _, _ = preprocess_features(df_eval, experiment=experiment, imputer=imputer)

    scores = clf.decision_function(X_eval)
    preds = clf.predict(X_eval)

    return scores, preds


def run_cross_session_generalization(
    df_s1: pd.DataFrame,
    df_s2: pd.DataFrame,
    contamination: float = 0.05,
    random_state: int = 42
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Coordinates cross-session training on Session 1 and evaluation on Session 2.
    Evaluates both pooled and node-specific configurations for 3-feature and 5-feature experiments.
    """
    validate_input_dataset(df_s1)
    validate_input_dataset(df_s2)

    df_s2_augmented = df_s2.copy()
    summary_records = []

    experiments = ["3-feature", "5-feature"]
    nodes = sorted(list(df_s2["node_id"].unique()))

    for exp in experiments:
        # =====================================================================
        # 1. POOLED MODEL (Trained on S1 pooled -> Applied to S2 pooled)
        # =====================================================================
        clf_p, imp_p, feat_p, meta_p = train_single_model(
            df_train=df_s1,
            experiment=exp,
            contamination=contamination,
            random_state=random_state,
            client_name="ALL_POOLED"
        )

        scores_p, preds_p = evaluate_single_model(
            clf=clf_p,
            imputer=imp_p,
            df_eval=df_s2,
            experiment=exp
        )

        pred_col_p = f"pred_cross_{exp}_pooled"
        score_col_p = f"score_cross_{exp}_pooled"
        df_s2_augmented[pred_col_p] = preds_p
        df_s2_augmented[score_col_p] = scores_p

        n_s2 = len(df_s2)
        outliers_s2_p = int((preds_p == -1).sum())
        outlier_pct_s2_p = float(outliers_s2_p / n_s2 * 100.0)

        summary_records.append({
            "experiment": exp,
            "model_scope": "pooled",
            "client_name": "ALL_POOLED",
            "train_session": "Session 1",
            "eval_session": "Session 2",
            "n_train_samples": len(df_s1),
            "n_eval_samples": n_s2,
            "fitted_offset": meta_p["fitted_offset"],
            "eval_outlier_count": outliers_s2_p,
            "eval_inlier_count": int((preds_p == 1).sum()),
            "eval_outlier_pct": round(outlier_pct_s2_p, 2),
            "eval_score_min": float(np.min(scores_p)),
            "eval_score_p25": float(np.percentile(scores_p, 25)),
            "eval_score_median": float(np.median(scores_p)),
            "eval_score_p75": float(np.percentile(scores_p, 75)),
            "eval_score_p95": float(np.percentile(scores_p, 95)),
            "eval_score_max": float(np.max(scores_p)),
            "eval_score_std": float(np.std(scores_p)),
            "feature_count": len(feat_p),
            "feature_names": ";".join(feat_p),
            "threshold_mechanism": (
                f"Trained on S1 with contamination={contamination} (offset={meta_p['fitted_offset']:.6f}). "
                "Evaluating S2 applies this exact S1 boundary: score_samples(S2) < offset -> outlier (-1)."
            ),
            "generalization_notes": (
                "Unchanged S1 model applied to S2. Outlier count in S2 reflects whether S2 traffic distribution "
                "aligns with S1 learned density; flagged points are statistical outliers, not confirmed attacks."
            )
        })

        # =====================================================================
        # 2. NODE-SPECIFIC MODELS (Trained per node on S1 -> Applied per node on S2)
        # =====================================================================
        pred_col_n = f"pred_cross_{exp}_node_specific"
        score_col_n = f"score_cross_{exp}_node_specific"
        df_s2_augmented[pred_col_n] = np.nan
        df_s2_augmented[score_col_n] = np.nan

        for node in nodes:
            df_s1_node = df_s1[df_s1["node_id"] == node].copy()
            df_s2_node = df_s2[df_s2["node_id"] == node].copy()

            if df_s1_node.empty:
                raise ValueError(f"Client '{node}' present in Session 2 but missing in Session 1 training data.")

            clf_n, imp_n, feat_n, meta_n = train_single_model(
                df_train=df_s1_node,
                experiment=exp,
                contamination=contamination,
                random_state=random_state,
                client_name=str(node)
            )

            scores_n, preds_n = evaluate_single_model(
                clf=clf_n,
                imputer=imp_n,
                df_eval=df_s2_node,
                experiment=exp
            )

            # Assign to corresponding subset
            node_idx = df_s2_augmented["node_id"] == node
            df_s2_augmented.loc[node_idx, pred_col_n] = preds_n
            df_s2_augmented.loc[node_idx, score_col_n] = scores_n

            n_eval_node = len(df_s2_node)
            outliers_node = int((preds_n == -1).sum())
            outlier_pct_node = float(outliers_node / n_eval_node * 100.0)

            summary_records.append({
                "experiment": exp,
                "model_scope": "node_specific",
                "client_name": str(node),
                "train_session": "Session 1",
                "eval_session": "Session 2",
                "n_train_samples": len(df_s1_node),
                "n_eval_samples": n_eval_node,
                "fitted_offset": meta_n["fitted_offset"],
                "eval_outlier_count": outliers_node,
                "eval_inlier_count": int((preds_n == 1).sum()),
                "eval_outlier_pct": round(outlier_pct_node, 2),
                "eval_score_min": float(np.min(scores_n)),
                "eval_score_p25": float(np.percentile(scores_n, 25)),
                "eval_score_median": float(np.median(scores_n)),
                "eval_score_p75": float(np.percentile(scores_n, 75)),
                "eval_score_p95": float(np.percentile(scores_n, 95)),
                "eval_score_max": float(np.max(scores_n)),
                "eval_score_std": float(np.std(scores_n)),
                "feature_count": len(feat_n),
                "feature_names": ";".join(feat_n),
                "threshold_mechanism": (
                    f"Node-specific S1 model (offset={meta_n['fitted_offset']:.6f}). "
                    "Evaluated on S2 node traffic: decision_function < 0 -> outlier (-1)."
                ),
                "generalization_notes": (
                    f"Trained on S1 {node} (N={len(df_s1_node)}). Evaluated on S2 {node} (N={n_eval_node})."
                )
            })

    df_summary = pd.DataFrame(summary_records)
    return df_s2_augmented, df_summary


def run_cross_session_pipeline(
    session1_csv_path: Union[str, Path],
    session2_csv_path: Union[str, Path],
    output_predictions_path: Union[str, Path],
    output_summary_path: Union[str, Path],
    contamination: float = 0.05,
    random_state: int = 42,
    overwrite: bool = False
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Loads Session 1 and Session 2, enforces overwrite guards, runs generalization, and writes outputs.
    """
    s1_p = Path(session1_csv_path)
    s2_p = Path(session2_csv_path)
    out_pred_p = Path(output_predictions_path)
    out_summ_p = Path(output_summary_path)

    if not s1_p.exists():
        raise FileNotFoundError(f"Session 1 features CSV not found: {s1_p}")
    if not s2_p.exists():
        raise FileNotFoundError(f"Session 2 features CSV not found: {s2_p}")

    if not overwrite:
        if out_pred_p.exists():
            raise FileExistsError(f"Target predictions file already exists: {out_pred_p}. Aborting to prevent overwrite.")
        if out_summ_p.exists():
            raise FileExistsError(f"Target summary file already exists: {out_summ_p}. Aborting to prevent overwrite.")

    df_s1 = pd.read_csv(s1_p)
    df_s2 = pd.read_csv(s2_p)

    df_s2_pred, df_summary = run_cross_session_generalization(
        df_s1=df_s1,
        df_s2=df_s2,
        contamination=contamination,
        random_state=random_state
    )

    out_pred_p.parent.mkdir(parents=True, exist_ok=True)
    df_s2_pred.to_csv(out_pred_p, index=False)
    df_summary.to_csv(out_summ_p, index=False)

    return df_s2_pred, df_summary


def main():
    parser = argparse.ArgumentParser(
        description="Run cross-session Isolation Forest generalization test (Train on S1 -> Evaluate on S2)."
    )
    parser.add_argument(
        "--session1-csv",
        type=str,
        default="data/processed/experimental_time_windows/time_1s_session1_pcap_features_uplink.csv",
        help="Path to Session 1 features CSV (training data)"
    )
    parser.add_argument(
        "--session2-csv",
        type=str,
        default="data/processed/experimental_time_windows/time_1s_pcap_features_uplink.csv",
        help="Path to Session 2 features CSV (evaluation data)"
    )
    parser.add_argument(
        "--output-predictions",
        type=str,
        default="data/processed/experimental_time_windows/cross_session_s1_to_s2_predictions.csv",
        help="Path to save Session 2 predictions augmented with cross-session scores"
    )
    parser.add_argument(
        "--output-summary",
        type=str,
        default="data/processed/experimental_time_windows/cross_session_s1_to_s2_summary.csv",
        help="Path to save cross-session evaluation summary CSV"
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
        help="Allow overwriting output files if they exist"
    )

    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    s1_p = project_root / args.session1_csv if not Path(args.session1_csv).is_absolute() else Path(args.session1_csv)
    s2_p = project_root / args.session2_csv if not Path(args.session2_csv).is_absolute() else Path(args.session2_csv)
    out_pred_p = project_root / args.output_predictions if not Path(args.output_predictions).is_absolute() else Path(args.output_predictions)
    out_summ_p = project_root / args.output_summary if not Path(args.output_summary).is_absolute() else Path(args.output_summary)

    print("=" * 80)
    print("CROSS-SESSION GENERALIZATION BENCHMARK (TRAIN S1 -> EVALUATE S2)")
    print("=" * 80)
    print(f"Training Data (S1):    {s1_p}")
    print(f"Evaluation Data (S2):  {s2_p}")
    print(f"Contamination Setting: {args.contamination}")
    print(f"Random State:          {args.random_state}")
    print(f"Predictions Target:    {out_pred_p}")
    print(f"Summary Target:        {out_summ_p}")
    print("=" * 80)

    df_preds, df_summary = run_cross_session_pipeline(
        session1_csv_path=s1_p,
        session2_csv_path=s2_p,
        output_predictions_path=out_pred_p,
        output_summary_path=out_summ_p,
        contamination=args.contamination,
        random_state=args.random_state,
        overwrite=args.overwrite
    )

    print("\nCROSS-SESSION BENCHMARK COMPLETE:")
    print(f"  Session 2 Windows Evaluated: {len(df_preds)}")
    print(f"  Configurations Evaluated:    {len(df_summary)}")
    print("\n--- Summary Results ---")
    cols = [
        "experiment", "model_scope", "client_name", "n_train_samples", "n_eval_samples",
        "fitted_offset", "eval_outlier_count", "eval_outlier_pct",
        "eval_score_min", "eval_score_median", "eval_score_max"
    ]
    print(df_summary[cols].to_string(index=False))
    print("\n" + "=" * 80)
    print("SCIENTIFIC NOTICE:")
    print("  Models were trained solely on Session 1 without any data from Session 2.")
    print("  Predictions on Session 2 reflect how well Session 2 traffic aligns with the Session 1 baseline.")
    print("  Statistical outliers are NOT verified attacks.")
    print("=" * 80)


if __name__ == "__main__":
    main()
