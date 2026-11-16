"""
Offline Temporal Alignment Prototype
File: src/correlate_traffic_and_sensors.py

Purpose:
  Performs an offline, read-only temporal alignment between network traffic
  feature windows (real_pcap_node_features_uplink.csv) and physical sensor
  readings (sensor_telemetry_test.db).

Scientific & Architectural Boundaries:
  - Preserves all 5 existing network features unchanged.
  - Temperature, humidity, and PIR motion are stored strictly as environmental context.
  - Does NOT feed environmental readings into any anomaly detection model.
  - Does NOT declare network anomalies benign or malicious based on motion.
  - Uses nearest-time matching with a configurable tolerance (default: 2.0s).
  - Explicitly leaves unmatched windows as NaN/missing; never fabricates values.
  - Reports actual time ranges and gap findings transparently.
"""

import sys
import sqlite3
import argparse
from pathlib import Path
import pandas as pd
import numpy as np
import datetime


def load_network_windows(csv_path: Path) -> pd.DataFrame:
    """
    Loads network feature windows and validates time columns.
    """
    if not csv_path.exists():
        raise FileNotFoundError(f"Network features CSV not found: {csv_path}")

    df = pd.read_csv(csv_path)
    required_cols = [
        "Node_ID", "Window_ID", "Window_Start_Time", "Window_End_Time",
        "mean_IAT", "IAT_std", "packet_rate", "mean_packet_size", "packet_size_std"
    ]
    for col in required_cols:
        if col not in df.columns:
            raise KeyError(f"Missing required network feature column: '{col}'")

    # Center-time of window in UNIX epoch seconds
    df["window_center_epoch"] = (df["Window_Start_Time"] + df["Window_End_Time"]) / 2.0
    return df


def load_sensor_telemetry(db_path: Path) -> pd.DataFrame:
    """
    Loads sensor telemetry from SQLite in read-only mode and parses timestamps to epoch seconds.
    """
    if not db_path.exists():
        raise FileNotFoundError(f"Sensor database not found: {db_path}")

    conn = sqlite3.connect(f"file:{db_path.resolve().as_posix()}?mode=ro", uri=True)
    try:
        query = """
        SELECT telemetry_id, node_id AS sensor_node_id, sequence_num, uptime_ms,
               temperature_c, humidity_pct, dht_valid, motion_detected, captured_at
        FROM sensor_telemetry
        ORDER BY telemetry_id ASC;
        """
        df_sensor = pd.read_sql_query(query, conn)
    finally:
        conn.close()

    if df_sensor.empty:
        return df_sensor

    # SQLite 'CURRENT_TIMESTAMP' generates strings formatted as 'YYYY-MM-DD HH:MM:SS' in UTC.
    # We parse this explicitly as UTC and compute the Unix epoch seconds.
    epoch_timestamps = []
    for ts_str in df_sensor["captured_at"]:
        try:
            dt = datetime.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=datetime.timezone.utc)
            epoch_timestamps.append(dt.timestamp())
        except (ValueError, TypeError):
            epoch_timestamps.append(np.nan)

    df_sensor["sensor_epoch"] = epoch_timestamps
    return df_sensor


def correlate_traffic_with_sensors(
    df_net: pd.DataFrame,
    df_sensor: pd.DataFrame,
    tolerance_sec: float = 2.0
) -> pd.DataFrame:
    """
    Performs nearest-time alignment using merge_asof with a strict tolerance window.
    Unmatched rows have sensor columns set to NaN/None.
    """
    if df_net.empty:
        return pd.DataFrame()

    # Sort dataframes by alignment key (mandatory for merge_asof)
    df_net_sorted = df_net.sort_values("window_center_epoch").reset_index(drop=True)

    if df_sensor.empty or df_sensor["sensor_epoch"].dropna().empty:
        # No sensor readings available; return network dataframe with null context columns
        df_out = df_net_sorted.copy()
        for col in ["telemetry_id", "sensor_node_id", "sequence_num", "sensor_uptime_ms",
                    "sensor_temp_c", "sensor_humidity_pct", "sensor_dht_valid",
                    "sensor_motion_detected", "sensor_captured_at", "time_delta_sec", "alignment_status"]:
            df_out[col] = np.nan
        df_out["alignment_status"] = "UNMATCHED_NO_SENSOR_DATA"
        return df_out

    df_sensor_sorted = df_sensor.dropna(subset=["sensor_epoch"]).sort_values("sensor_epoch").reset_index(drop=True)

    sensor_rename = {
        "uptime_ms": "sensor_uptime_ms",
        "temperature_c": "sensor_temp_c",
        "humidity_pct": "sensor_humidity_pct",
        "dht_valid": "sensor_dht_valid",
        "motion_detected": "sensor_motion_detected",
        "captured_at": "sensor_captured_at"
    }
    df_sensor_renamed = df_sensor_sorted.rename(columns=sensor_rename)

    # Perform nearest-time asof merge
    merged = pd.merge_asof(
        df_net_sorted,
        df_sensor_renamed,
        left_on="window_center_epoch",
        right_on="sensor_epoch",
        direction="nearest",
        tolerance=tolerance_sec
    )

    # Compute absolute time difference where a match was found
    merged["time_delta_sec"] = (merged["window_center_epoch"] - merged["sensor_epoch"]).abs()
    merged["alignment_status"] = np.where(
        merged["telemetry_id"].notna(),
        "MATCHED_WITHIN_TOLERANCE",
        "UNMATCHED_OUTSIDE_TOLERANCE"
    )

    return merged


def run_alignment_pipeline(
    csv_path: Path,
    db_path: Path,
    output_path: Path,
    tolerance_sec: float = 2.0
) -> pd.DataFrame:
    """
    Executes the alignment and writes output to the specified path.
    """
    print("=" * 80)
    print("OFFLINE TRAFFIC & SENSOR TEMPORAL ALIGNMENT PROTOTYPE")
    print("=" * 80)
    print(f"Network Features Input: {csv_path}")
    print(f"Sensor Database Input:  {db_path}")
    print(f"Tolerance Window:       ±{tolerance_sec:.1f} seconds")

    df_net = load_network_windows(csv_path)
    df_sensor = load_sensor_telemetry(db_path)

    net_min = df_net["window_center_epoch"].min()
    net_max = df_net["window_center_epoch"].max()
    net_dt_min = datetime.datetime.fromtimestamp(net_min, tz=datetime.timezone.utc)
    net_dt_max = datetime.datetime.fromtimestamp(net_max, tz=datetime.timezone.utc)

    print(f"\n[NETWORK TIMING SUMMARY]")
    print(f"  Total Windows: {len(df_net)}")
    print(f"  Time Range UTC: {net_dt_min.strftime('%Y-%m-%d %H:%M:%S')} to {net_dt_max.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Epoch Span:     {net_min:.2f} to {net_max:.2f} ({net_max - net_min:.2f}s span)")

    if not df_sensor.empty:
        s_min = df_sensor["sensor_epoch"].min()
        s_max = df_sensor["sensor_epoch"].max()
        s_dt_min = datetime.datetime.fromtimestamp(s_min, tz=datetime.timezone.utc)
        s_dt_max = datetime.datetime.fromtimestamp(s_max, tz=datetime.timezone.utc)
        print(f"\n[SENSOR TIMING SUMMARY]")
        print(f"  Total Telemetry Records: {len(df_sensor)}")
        print(f"  Time Range UTC:          {s_dt_min.strftime('%Y-%m-%d %H:%M:%S')} to {s_dt_max.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Epoch Span:              {s_min:.2f} to {s_max:.2f} ({s_max - s_min:.2f}s span)")

        # Report time gap between disparate sessions
        gap_sec = s_min - net_max
        print(f"\n[CHRONOLOGICAL RELATIONSHIP ANALYSIS]")
        if gap_sec > tolerance_sec:
            print(f"  NOTE: Sensor readings were recorded {gap_sec/60.0:.1f} minutes AFTER the PCAP capture.")
            print(f"  Since these were separate capture sessions, 0 rows will fall within the ±{tolerance_sec}s window.")
            print(f"  All network feature rows are preserved with sensor context correctly marked UNMATCHED.")
        elif -gap_sec > tolerance_sec:
            print(f"  NOTE: Sensor readings were recorded prior to the PCAP capture.")
        else:
            print(f"  Sensor readings overlap with network windows!")

    # Perform alignment
    df_aligned = correlate_traffic_with_sensors(df_net, df_sensor, tolerance_sec=tolerance_sec)

    matched_count = (df_aligned["alignment_status"] == "MATCHED_WITHIN_TOLERANCE").sum()
    unmatched_count = (df_aligned["alignment_status"] != "MATCHED_WITHIN_TOLERANCE").sum()

    print(f"\n[ALIGNMENT RESULTS]")
    print(f"  Total Aligned Rows: {len(df_aligned)}")
    print(f"  Matched within ±{tolerance_sec}s: {matched_count}")
    print(f"  Unmatched (Sensor fields NaN): {unmatched_count}")

    # Output to target file
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df_aligned.to_csv(output_path, index=False)
    print(f"\n[OUTPUT SAVED]: {output_path}")

    return df_aligned


def main():
    parser = argparse.ArgumentParser(description="Temporal alignment between network windows and sensor telemetry.")
    parser.add_argument("--net-csv", type=str, default="data/processed/real_pcap_node_features_uplink.csv", help="Uplink network features CSV")
    parser.add_argument("--sensor-db", type=str, default="data/telemetry_test/sensor_telemetry_test.db", help="Sensor SQLite DB")
    parser.add_argument("--output", type=str, default="data/processed/traffic_sensor_alignment_test.csv", help="Output aligned CSV")
    parser.add_argument("--tolerance", type=float, default=2.0, help="Nearest-neighbor time tolerance in seconds (default: 2.0)")
    args = parser.parse_args()

    project_root = Path(__file__).parent.parent
    net_csv_path = project_root / args.net_csv if not Path(args.net_csv).is_absolute() else Path(args.net_csv)
    sensor_db_path = project_root / args.sensor_db if not Path(args.sensor_db).is_absolute() else Path(args.sensor_db)
    output_path = project_root / args.output if not Path(args.output).is_absolute() else Path(args.output)

    run_alignment_pipeline(
        csv_path=net_csv_path,
        db_path=sensor_db_path,
        output_path=output_path,
        tolerance_sec=args.tolerance
    )


if __name__ == "__main__":
    main()
