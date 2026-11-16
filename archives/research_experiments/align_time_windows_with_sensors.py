"""
Experimental 1-Second Time-Window & Sensor Telemetry Alignment
File: src/align_time_windows_with_sensors.py

Purpose:
  Performs an offline, read-only temporal alignment between experimental
  fixed 1-second network feature windows (time_1s_pcap_features_uplink.csv)
  and physical sensor telemetry (synchronized2_sensor_telemetry.db).

Scientific & Architectural Boundaries:
  - Read-only on inputs; does NOT modify network CSV or sensor database.
  - Uses center timestamp of each 1-second window for nearest-time alignment.
  - Configurable matching tolerance (default: ±2.0 seconds).
  - Preserves EVERY network window, including unmatched windows.
  - Distinguishes environmental context from traffic anomalies:
    NEVER feeds sensor readings into anomaly models, and NEVER labels traffic
    as malicious/benign based on sensor states.
  - Retains NaN for missing or invalid DHT readings; NEVER replaces missing values with zero.
"""

import sys
import sqlite3
import argparse
from pathlib import Path
from typing import Optional, Union, Tuple
import pandas as pd
import numpy as np
import datetime


def load_network_1s_windows(csv_path: Union[str, Path]) -> pd.DataFrame:
    """
    Loads 1-second network feature windows and computes window center timestamps.
    Adapts safely to column name variants.
    """
    csv_p = Path(csv_path)
    if not csv_p.exists():
        raise FileNotFoundError(f"Network features CSV not found: {csv_p}")

    df = pd.read_csv(csv_p)
    if df.empty:
        return df

    # Adapt to column naming safely
    if "bin_start_timestamp" in df.columns and "bin_end_timestamp" in df.columns:
        start_col = "bin_start_timestamp"
        end_col = "bin_end_timestamp"
    elif "Window_Start_Time" in df.columns and "Window_End_Time" in df.columns:
        start_col = "Window_Start_Time"
        end_col = "Window_End_Time"
    elif "Window_Start_Epoch" in df.columns and "Window_End_Epoch" in df.columns:
        start_col = "Window_Start_Epoch"
        end_col = "Window_End_Epoch"
    else:
        raise KeyError(
            f"Could not find start/end timestamp columns in {csv_p}. "
            f"Available columns: {list(df.columns)}"
        )

    # Compute exact window center timestamp
    df["window_center_epoch"] = (df[start_col] + df[end_col]) / 2.0
    return df


def load_sensor_telemetry(db_path: Union[str, Path]) -> pd.DataFrame:
    """
    Loads sensor telemetry records from SQLite in read-only mode and
    converts UTC captured_at strings to epoch seconds.
    Enforces NaN for invalid DHT readings.
    """
    db_p = Path(db_path)
    if not db_p.exists():
        raise FileNotFoundError(f"Sensor database not found: {db_p}")

    # Use read-only URI mode to prevent any database modification
    conn = sqlite3.connect(f"file:{db_p.resolve().as_posix()}?mode=ro", uri=True)
    try:
        # Check if table exists
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sensor_telemetry';")
        if not cur.fetchone():
            return pd.DataFrame()

        query = """
        SELECT telemetry_id, node_id AS sensor_node_id, sequence_num, uptime_ms AS sensor_uptime_ms,
               temperature_c, humidity_pct, dht_valid, motion_detected, captured_at
        FROM sensor_telemetry
        ORDER BY telemetry_id ASC;
        """
        df_sensor = pd.read_sql_query(query, conn)
    finally:
        conn.close()

    if df_sensor.empty:
        return df_sensor

    # Convert captured_at ('YYYY-MM-DD HH:MM:SS' UTC) to Unix epoch seconds
    epoch_timestamps = []
    for ts_str in df_sensor["captured_at"]:
        try:
            dt = datetime.datetime.strptime(str(ts_str), "%Y-%m-%d %H:%M:%S").replace(tzinfo=datetime.timezone.utc)
            epoch_timestamps.append(dt.timestamp())
        except (ValueError, TypeError):
            epoch_timestamps.append(np.nan)

    df_sensor["sensor_epoch"] = epoch_timestamps

    # Ensure invalid DHT readings are explicitly NaN
    invalid_dht_mask = (df_sensor["dht_valid"] == 0) | (df_sensor["dht_valid"].isna())
    df_sensor.loc[invalid_dht_mask, "temperature_c"] = np.nan
    df_sensor.loc[invalid_dht_mask, "humidity_pct"] = np.nan

    return df_sensor


def align_1s_windows_with_sensors(
    df_net: pd.DataFrame,
    df_sensor: pd.DataFrame,
    tolerance_sec: float = 2.0
) -> pd.DataFrame:
    """
    Performs nearest-time alignment between 1-second network windows and sensor telemetry.
    
    Guarantees:
    - Every network window is preserved (len(output) == len(df_net)).
    - Matching uses nearest sensor record within tolerance_sec.
    - If unmatched, sensor fields and time_delta_sec are NaN.
    - If DHT invalid, temperature_c and humidity_pct are NaN (never zero).
    - Alignment status is explicitly labeled.
    """
    if df_net.empty:
        return pd.DataFrame()

    context_cols = [
        "telemetry_id", "sensor_node_id", "sensor_sequence_num", "sensor_uptime_ms",
        "sensor_captured_at", "sensor_epoch", "time_delta_sec",
        "temperature_c", "humidity_pct", "dht_valid", "motion_detected",
        "alignment_status"
    ]

    # Preserve original ordering
    df_net_with_orig_idx = df_net.copy()
    df_net_with_orig_idx["_orig_idx"] = np.arange(len(df_net))
    df_net_sorted = df_net_with_orig_idx.sort_values("window_center_epoch").reset_index(drop=True)

    if df_sensor.empty or df_sensor["sensor_epoch"].dropna().empty:
        df_out = df_net_sorted.copy()
        for col in context_cols:
            df_out[col] = np.nan
        df_out["alignment_status"] = "UNMATCHED_NO_SENSOR_DATA"
        return df_out.sort_values("_orig_idx").drop(columns=["_orig_idx"]).reset_index(drop=True)

    df_sensor_clean = df_sensor.dropna(subset=["sensor_epoch"]).copy()
    df_sensor_sorted = df_sensor_clean.sort_values("sensor_epoch").reset_index(drop=True)

    rename_map = {
        "sequence_num": "sensor_sequence_num",
        "captured_at": "sensor_captured_at"
    }
    df_sensor_prep = df_sensor_sorted.rename(columns=rename_map)

    # Perform nearest-time merge_asof
    merged = pd.merge_asof(
        df_net_sorted,
        df_sensor_prep,
        left_on="window_center_epoch",
        right_on="sensor_epoch",
        direction="nearest",
        tolerance=tolerance_sec
    )

    # Compute absolute time difference for matched rows
    has_match = merged["telemetry_id"].notna()
    merged["time_delta_sec"] = np.where(
        has_match,
        (merged["window_center_epoch"] - merged["sensor_epoch"]).abs(),
        np.nan
    )

    merged["alignment_status"] = np.where(
        has_match,
        "MATCHED_WITHIN_TOLERANCE",
        "UNMATCHED_OUTSIDE_TOLERANCE"
    )

    # Re-verify that invalid DHT readings remain NaN in merged output
    invalid_dht = (merged["dht_valid"] == 0) | (merged["dht_valid"].isna())
    merged.loc[invalid_dht, "temperature_c"] = np.nan
    merged.loc[invalid_dht, "humidity_pct"] = np.nan

    # Restore original row ordering
    df_final = merged.sort_values("_orig_idx").drop(columns=["_orig_idx"]).reset_index(drop=True)
    return df_final


def run_alignment(
    csv_path: Union[str, Path],
    db_path: Union[str, Path],
    output_path: Union[str, Path],
    tolerance_sec: float = 2.0,
    overwrite: bool = False
) -> pd.DataFrame:
    """
    Loads network features and sensor telemetry, performs alignment,
    validates overwrite guards, and saves to CSV.
    """
    out_p = Path(output_path)
    if out_p.exists() and not overwrite:
        raise FileExistsError(
            f"Output file already exists at '{out_p}'. "
            "Aborting alignment to prevent overwriting."
        )

    df_net = load_network_1s_windows(csv_path)
    df_sensor = load_sensor_telemetry(db_path)
    df_aligned = align_1s_windows_with_sensors(df_net, df_sensor, tolerance_sec=tolerance_sec)

    out_p.parent.mkdir(parents=True, exist_ok=True)
    df_aligned.to_csv(out_p, index=False)

    return df_aligned


def main():
    parser = argparse.ArgumentParser(
        description="Align 1-second network feature windows with sensor telemetry."
    )
    parser.add_argument(
        "--network-csv",
        type=str,
        default="data/processed/experimental_time_windows/time_1s_pcap_features_uplink.csv",
        help="Path to 1-second network feature CSV"
    )
    parser.add_argument(
        "--sensor-db",
        type=str,
        default="data/telemetry_test/synchronized2_sensor_telemetry.db",
        help="Path to sensor SQLite database"
    )
    parser.add_argument(
        "--output-csv",
        type=str,
        default="data/processed/experimental_time_windows/time_1s_traffic_sensor_aligned.csv",
        help="Path to output aligned CSV"
    )
    parser.add_argument(
        "--tolerance-sec",
        type=float,
        default=2.0,
        help="Maximum absolute time delta in seconds for matching"
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow overwriting output CSV if it already exists"
    )

    args = parser.parse_args()

    df_aligned = run_alignment(
        csv_path=args.network_csv,
        db_path=args.sensor_db,
        output_path=args.output_csv,
        tolerance_sec=args.tolerance_sec,
        overwrite=args.overwrite
    )

    total_rows = len(df_aligned)
    matched_cnt = (df_aligned["alignment_status"] == "MATCHED_WITHIN_TOLERANCE").sum()
    unmatched_cnt = total_rows - matched_cnt
    missing_temp = df_aligned["temperature_c"].isna().sum()
    missing_hum = df_aligned["humidity_pct"].isna().sum()
    missing_motion = df_aligned["motion_detected"].isna().sum()

    print("=" * 80)
    print("EXPERIMENTAL 1-SECOND TRAFFIC & SENSOR ALIGNMENT COMPLETE")
    print(f"Total Network Windows:      {total_rows}")
    print(f"Matched Within Tolerance:   {matched_cnt}")
    print(f"Unmatched Windows:          {unmatched_cnt}")
    print(f"Missing Temperature:        {missing_temp}")
    print(f"Missing Humidity:           {missing_hum}")
    print(f"Missing Motion State:       {missing_motion}")
    print(f"Output saved to:            {args.output_csv}")
    print("=" * 80)


if __name__ == "__main__":
    main()
