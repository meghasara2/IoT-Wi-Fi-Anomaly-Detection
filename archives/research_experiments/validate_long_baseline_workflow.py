"""
Long-Duration Baseline Validation Workflow for Experimental Dual-Detector
File: src/validate_long_baseline_workflow.py

Purpose:
  Provides an isolated, repeatable workflow to process and evaluate longer-duration
  (e.g., >= 10 minute) network capture sessions and optional sensor telemetry against
  the frozen Session 1-trained Dual Detector.

Workflow Stages:
  1. Feature Extraction: Extracts fixed 1-second non-overlapping feature windows from PCAP
     using src/extract_pcap_time_windows.py (or loads pre-extracted feature CSV).
  2. Sensor Alignment (Optional): Aligns physical sensor telemetry records within +-2.0s
     tolerance if a valid sensor database is provided.
  3. Frozen Model Scoring: Applies the unchanged Session 1-trained Dual Detector
     (Primary 3-feature + Gated Timing N >= 3) to the new session without refitting.
  4. Comprehensive Metric Reporting: Generates window counts, packet-rate/IAT distributions,
     timing-unavailable rates, alert attributions, and sensor match rates.
  5. Isolated Output Generation: Writes all session artifacts to a dedicated directory with
     strict overwrite protection.
"""

import sys
import math
import argparse
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional, Union

import pandas as pd
import numpy as np

try:
    from src.dual_detector_1s import (
        train_dual_detector,
        evaluate_dual_detector,
        DualDetectorBundle,
        MIN_PACKETS_FOR_TIMING,
        FEATURE_COLS_PRIMARY,
        FEATURE_COLS_TIMING
    )
    from src.benchmark_1s_anomaly_detector import validate_input_dataset
    from src.align_time_windows_with_sensors import (
        load_sensor_telemetry,
        load_network_1s_windows,
        align_1s_windows_with_sensors
    )
    from src.extract_pcap_time_windows import (
        run_1s_extraction_pipeline
    )
except ModuleNotFoundError:
    from dual_detector_1s import (
        train_dual_detector,
        evaluate_dual_detector,
        DualDetectorBundle,
        MIN_PACKETS_FOR_TIMING,
        FEATURE_COLS_PRIMARY,
        FEATURE_COLS_TIMING
    )
    from benchmark_1s_anomaly_detector import validate_input_dataset
    from align_time_windows_with_sensors import (
        load_sensor_telemetry,
        load_network_1s_windows,
        align_1s_windows_with_sensors
    )
    from extract_pcap_time_windows import (
        run_1s_extraction_pipeline
    )


def compute_baseline_session_metrics(
    df_scored: pd.DataFrame,
    session_name: str,
    sensor_aligned: bool = False
) -> Dict[str, Any]:
    """
    Computes statistical distribution metrics and anomaly breakdown for the evaluated session.
    """
    validate_input_dataset(df_scored)
    n_windows = len(df_scored)

    # 1. Client Distribution
    clients = sorted(df_scored["node_id"].unique().tolist())
    client_counts = df_scored["node_id"].value_counts().to_dict()

    # 2. Packet Rate Distribution
    pr = df_scored["packet_rate"].values
    pr_stats = {
        "min": float(np.min(pr)),
        "p25": float(np.percentile(pr, 25)),
        "median": float(np.median(pr)),
        "p75": float(np.percentile(pr, 75)),
        "p95": float(np.percentile(pr, 95)),
        "max": float(np.max(pr)),
        "mean": float(np.mean(pr)),
        "std": float(np.std(pr))
    }

    # 3. IAT Distribution (for qualified windows N >= MIN_PACKETS_FOR_TIMING)
    mask_timing = (df_scored["packet_count"] >= MIN_PACKETS_FOR_TIMING).values
    n_timing_active = int(mask_timing.sum())
    n_timing_unavail = int(n_windows - n_timing_active)
    timing_unavail_pct = round(n_timing_unavail / n_windows * 100.0, 2) if n_windows > 0 else 0.0

    if n_timing_active > 0:
        valid_iats = df_scored.loc[mask_timing, "mean_IAT"].dropna().values
        iat_mean = float(np.mean(valid_iats)) if len(valid_iats) > 0 else np.nan
        iat_median = float(np.median(valid_iats)) if len(valid_iats) > 0 else np.nan
    else:
        iat_mean = np.nan
        iat_median = np.nan

    # 4. Outlier & Attribution Statistics
    n_prim_outliers = int((df_scored["pred_primary"] == -1).sum())
    n_timing_outliers = int((df_scored["pred_timing"] == -1).sum())
    n_dual_outliers = int((df_scored["pred_dual"] == -1).sum())
    dual_outlier_pct = round(n_dual_outliers / n_windows * 100.0, 2) if n_windows > 0 else 0.0

    reason_counts = df_scored["dual_reason"].value_counts().to_dict()

    # 5. Sensor Match Rate (if aligned)
    sensor_match_rate = np.nan
    matched_sensor_count = 0
    if sensor_aligned and "alignment_status" in df_scored.columns:
        matched_sensor_count = int((df_scored["alignment_status"] == "MATCHED_WITHIN_TOLERANCE").sum())
        sensor_match_rate = round(matched_sensor_count / n_windows * 100.0, 2) if n_windows > 0 else 0.0

    return {
        "session_name": session_name,
        "n_windows": n_windows,
        "client_count": len(clients),
        "clients": clients,
        "client_window_counts": client_counts,
        "packet_rate_stats": pr_stats,
        "timing_active_count": n_timing_active,
        "timing_unavail_count": n_timing_unavail,
        "timing_unavail_pct": timing_unavail_pct,
        "mean_IAT_qualified": round(iat_mean, 6) if not np.isnan(iat_mean) else None,
        "median_IAT_qualified": round(iat_median, 6) if not np.isnan(iat_median) else None,
        "primary_outlier_count": n_prim_outliers,
        "timing_outlier_count": n_timing_outliers,
        "dual_outlier_count": n_dual_outliers,
        "dual_outlier_pct": dual_outlier_pct,
        "dual_reason_breakdown": reason_counts,
        "sensor_aligned": sensor_aligned,
        "matched_sensor_count": matched_sensor_count,
        "sensor_match_rate_pct": sensor_match_rate
    }


def generate_session_validation_markdown(
    metrics: Dict[str, Any],
    bundle: DualDetectorBundle,
    session1_train_path: Path
) -> str:
    """
    Constructs a readable markdown validation report for the session.
    """
    sess = metrics["session_name"]
    n_win = metrics["n_windows"]
    pr = metrics["packet_rate_stats"]

    lines = [
        f"# Baseline Validation Report: {sess}",
        f"**Evaluated Windows**: {n_win}",
        f"**Frozen Baseline Model**: Trained on Session 1 (`{session1_train_path.name}`)",
        f"**Primary Fitted Offset**: {bundle.meta_primary['fitted_offset']:.6f}",
        f"**Timing Fitted Offset**: {bundle.meta_timing['fitted_offset']:.6f}",
        "",
        "---",
        "",
        "## 1. Traffic Distribution & Timing Availability",
        "",
        "| Metric | Measured Value |",
        "| :--- | :---: |",
        f"| Total 1-Second Windows | {n_win} |",
        f"| Active Client Nodes | {metrics['client_count']} ({', '.join(metrics['clients'])}) |",
        f"| Packet Rate Min / Median / Max | {pr['min']:.1f} / {pr['median']:.1f} / {pr['max']:.1f} pkts/s |",
        f"| Packet Rate Mean +- Std | {pr['mean']:.2f} +- {pr['std']:.2f} pkts/s |",
        f"| Qualified Timing Windows (N >= {MIN_PACKETS_FOR_TIMING}) | {metrics['timing_active_count']} ({100.0 - metrics['timing_unavail_pct']:.2f}%) |",
        f"| Unavailable Timing Windows (N < {MIN_PACKETS_FOR_TIMING}) | {metrics['timing_unavail_count']} ({metrics['timing_unavail_pct']}%) |",
        f"| Qualified Mean IAT | {metrics['mean_IAT_qualified']} s |",
        "",
        "---",
        "",
        "## 2. Frozen Dual-Detector Anomaly Scoring",
        "",
        "| Anomaly Detection Metric | Count / Percentage |",
        "| :--- | :---: |",
        f"| Primary Detector Flags | {metrics['primary_outlier_count']} |",
        f"| Secondary Timing Flags | {metrics['timing_outlier_count']} |",
        f"| **Dual Combined Flags** | **{metrics['dual_outlier_count']} ({metrics['dual_outlier_pct']}%)** |",
        "",
        "### Attribution Breakdown:",
    ]

    for reason, cnt in metrics["dual_reason_breakdown"].items():
        pct = round(cnt / n_win * 100.0, 2) if n_win > 0 else 0.0
        lines.append(f"- `{reason}`: {cnt} windows ({pct}%)")

    lines.extend([
        "",
        "---",
        "",
        "## 3. Physical Sensor Telemetry Alignment",
        ""
    ])

    if metrics["sensor_aligned"]:
        lines.extend([
            f"- **Sensor Alignment**: Active",
            f"- **Windows Matched with Sensor Telemetry**: {metrics['matched_sensor_count']} out of {n_win} ({metrics['sensor_match_rate_pct']}%)",
            "- **Scientific Notice**: Environmental sensor telemetry (DHT11/PIR) is stored strictly as contextual metadata and is NEVER used to label network attacks."
        ])
    else:
        lines.extend([
            "- **Sensor Alignment**: Not performed (No sensor database provided for this run)."
        ])

    lines.extend([
        "",
        "---",
        "",
        "## 4. Scientific Notice",
        "- All statistical outliers flagged are deviations from the Session 1 density envelope.",
        "- In the absence of verified real attack ground truth, flagged windows are statistical anomalies, NOT confirmed cyberattacks."
    ])

    return "\n".join(lines)


def run_session_validation_pipeline(
    session_name: str,
    features_csv_path: Optional[Union[str, Path]] = None,
    pcap_path: Optional[Union[str, Path]] = None,
    sensor_db_path: Optional[Union[str, Path]] = None,
    session1_train_path: Union[str, Path] = "data/processed/experimental_time_windows/time_1s_session1_pcap_features_uplink.csv",
    output_dir: Union[str, Path] = "data/processed/experimental_time_windows/long_baseline_validation",
    contamination: float = 0.05,
    random_state: int = 42,
    overwrite: bool = False
) -> Dict[str, Any]:
    """
    Executes the end-to-end long-baseline validation workflow for a session.
    """
    s1_p = Path(session1_train_path)
    out_dir_p = Path(output_dir)

    if not s1_p.exists():
        raise FileNotFoundError(f"Session 1 baseline training CSV not found: {s1_p}")

    out_features_csv = out_dir_p / f"{session_name}_1s_features.csv"
    out_aligned_csv = out_dir_p / f"{session_name}_1s_traffic_sensor_aligned.csv"
    out_preds_csv = out_dir_p / f"{session_name}_dual_detector_predictions.csv"
    out_summary_csv = out_dir_p / f"{session_name}_validation_summary.csv"
    out_report_md = out_dir_p / f"{session_name}_session_report.md"

    # Overwrite protection
    if not overwrite:
        for p in [out_preds_csv, out_summary_csv, out_report_md]:
            if p.exists():
                raise FileExistsError(f"Target validation artifact already exists: {p}. Overwrite guard blocked execution.")

    # 1. Obtain 1-second feature DataFrame
    if features_csv_path is not None:
        f_p = Path(features_csv_path)
        if not f_p.exists():
            raise FileNotFoundError(f"Features CSV not found: {f_p}")
        df_features = pd.read_csv(f_p)
    elif pcap_path is not None:
        pc_p = Path(pcap_path)
        if not pc_p.exists():
            raise FileNotFoundError(f"PCAP file not found: {pc_p}")
        out_summary_temp = out_dir_p / f"{session_name}_pcap_summary.csv"
        df_features, _ = run_1s_extraction_pipeline(
            pcap_path=pc_p,
            output_features_path=out_features_csv,
            output_summary_path=out_summary_temp,
            direction="uplink",
            include_empty=False,
            overwrite=overwrite
        )
    else:
        raise ValueError("Must provide either 'features_csv_path' or 'pcap_path' to run validation.")

    validate_input_dataset(df_features)

    # 2. Sensor Alignment (if sensor DB is provided)
    sensor_aligned = False
    df_aligned = df_features.copy()
    if sensor_db_path is not None:
        s_db_p = Path(sensor_db_path)
        if s_db_p.exists():
            df_sensor = load_sensor_telemetry(s_db_p)
            df_net_win = df_features.copy()
            if "window_center_epoch" not in df_net_win.columns:
                if "bin_start_timestamp" in df_net_win.columns and "bin_end_timestamp" in df_net_win.columns:
                    df_net_win["window_center_epoch"] = (df_net_win["bin_start_timestamp"] + df_net_win["bin_end_timestamp"]) / 2.0
            df_aligned = align_1s_windows_with_sensors(df_net_win, df_sensor, tolerance_sec=2.0)
            sensor_aligned = True
            out_aligned_csv.parent.mkdir(parents=True, exist_ok=True)
            df_aligned.to_csv(out_aligned_csv, index=False)

    # 3. Train Frozen Dual Detector strictly on Session 1
    df_s1 = pd.read_csv(s1_p)
    dual_bundle = train_dual_detector(
        df_train_s1=df_s1,
        contamination=contamination,
        random_state=random_state
    )

    # 4. Evaluate target session
    df_scored = evaluate_dual_detector(dual_bundle, df_aligned)

    # 5. Compute comprehensive statistical metrics
    metrics = compute_baseline_session_metrics(
        df_scored=df_scored,
        session_name=session_name,
        sensor_aligned=sensor_aligned
    )

    # 6. Save outputs
    out_dir_p.mkdir(parents=True, exist_ok=True)
    df_scored.to_csv(out_preds_csv, index=False)

    df_summary = pd.DataFrame([{
        "session_name": session_name,
        "n_windows": metrics["n_windows"],
        "client_count": metrics["client_count"],
        "packet_rate_median": metrics["packet_rate_stats"]["median"],
        "packet_rate_mean": metrics["packet_rate_stats"]["mean"],
        "timing_active_count": metrics["timing_active_count"],
        "timing_unavail_count": metrics["timing_unavail_count"],
        "timing_unavail_pct": metrics["timing_unavail_pct"],
        "primary_outlier_count": metrics["primary_outlier_count"],
        "timing_outlier_count": metrics["timing_outlier_count"],
        "dual_outlier_count": metrics["dual_outlier_count"],
        "dual_outlier_pct": metrics["dual_outlier_pct"],
        "sensor_aligned": metrics["sensor_aligned"],
        "sensor_match_rate_pct": metrics["sensor_match_rate_pct"]
    }])
    df_summary.to_csv(out_summary_csv, index=False)

    report_md = generate_session_validation_markdown(
        metrics=metrics,
        bundle=dual_bundle,
        session1_train_path=s1_p
    )
    with open(out_report_md, "w", encoding="utf-8") as f:
        f.write(report_md)

    return {
        "metrics": metrics,
        "df_scored": df_scored,
        "df_summary": df_summary,
        "out_files": [out_preds_csv, out_summary_csv, out_report_md] + ([out_aligned_csv] if sensor_aligned else [])
    }


def main():
    parser = argparse.ArgumentParser(
        description="Run isolated long-duration baseline validation for the dual detector."
    )
    parser.add_argument("--session-name", type=str, required=True, help="Unique name for the session (e.g. session3_10min)")
    parser.add_argument("--features-csv", type=str, default=None, help="Path to pre-extracted 1s features CSV")
    parser.add_argument("--pcap", type=str, default=None, help="Path to raw PCAP file to extract and evaluate")
    parser.add_argument("--sensor-db", type=str, default=None, help="Path to SQLite sensor database")
    parser.add_argument(
        "--session1-train",
        type=str,
        default="data/processed/experimental_time_windows/time_1s_session1_pcap_features_uplink.csv",
        help="Path to Session 1 baseline features CSV (frozen training data)"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data/processed/experimental_time_windows/long_baseline_validation",
        help="Directory to save validation outputs"
    )
    parser.add_argument("--contamination", type=float, default=0.05, help="Contamination parameter (default: 0.05)")
    parser.add_argument("--random-state", type=int, default=42, help="Random seed (default: 42)")
    parser.add_argument("--overwrite", action="store_true", help="Allow overwriting target files")

    args = parser.parse_args()

    print("=" * 80)
    print(f"LONG-DURATION BASELINE VALIDATION: {args.session_name}")
    print("=" * 80)

    res = run_session_validation_pipeline(
        session_name=args.session_name,
        features_csv_path=args.features_csv,
        pcap_path=args.pcap,
        sensor_db_path=args.sensor_db,
        session1_train_path=args.session1_train,
        output_dir=args.output_dir,
        contamination=args.contamination,
        random_state=args.random_state,
        overwrite=args.overwrite
    )

    print("\nVALIDATION COMPLETED SUCCESSFULLY.")
    for p in res["out_files"]:
        print(f"  Artifact: {p}")
    print("\n--- Summary ---")
    print(res["df_summary"].to_string(index=False))


if __name__ == "__main__":
    main()
