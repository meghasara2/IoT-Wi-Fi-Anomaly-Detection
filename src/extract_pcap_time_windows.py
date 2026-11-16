"""
Experimental PCAP Feature Extractor: Fixed 1-Second Time Windows
File: src/extract_pcap_time_windows.py

Purpose:
  Extracts network traffic features using uniform, non-overlapping 1.0-second
  time windows per client device from PCAP captures.

Design Principles:
  - packet_rate = packet_count / 1.0 (captured packets per second in host buffer,
    not over-the-air physical transmission rate).
  - Eliminates extreme multi-million packet rate anomalies caused by microsecond-scale
    10-packet burst denominators.
  - Supports sparse reporting (default) and continuous bins (--include-empty).
  - Preserves client identity, bin start/end UTC and epoch timestamps.
  - Keeps all 5 primary feature names:
      mean_IAT, IAT_std, packet_rate, mean_packet_size, packet_size_std.
"""

import sys
import math
import subprocess
import argparse
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
import pandas as pd
import numpy as np
import datetime

# Default tool path
TSHARK_DEFAULT_PATH = r"C:\Program Files\Wireshark\tshark.exe"
HOTSPOT_SUBNET_PREFIX = "192.168.137."

# Default Client Registry
CLIENT_REGISTRY = {
    "ca:34:ea:92:d3:9e": {
        "node_id": "Node_Client_1",
        "ip": "192.168.137.201",
        "device_type": "Unverified_Mobile_Client",
        "label": "real_observed_traffic"
    },
    "e6:2e:db:73:1c:25": {
        "node_id": "Node_Client_2",
        "ip": "192.168.137.6",
        "device_type": "Unverified_Mobile_Client",
        "label": "real_observed_traffic"
    }
}
IP_TO_REGISTRY = {info["ip"]: (mac, info) for mac, info in CLIENT_REGISTRY.items()}


def parse_pcap_frames(pcap_path: Path, tshark_path: str = TSHARK_DEFAULT_PATH) -> pd.DataFrame:
    """
    Invokes tshark to parse PCAP frames into a structured DataFrame.
    """
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    tshark_bin = Path(tshark_path)
    if not tshark_bin.exists():
        raise FileNotFoundError(f"tshark executable not found at: {tshark_path}")

    cmd = [
        str(tshark_bin),
        "-r", str(pcap_path),
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "eth.src",
        "-e", "eth.dst",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "_ws.col.Protocol",
        "-E", "separator=\t",
        "-E", "occurrence=f"
    ]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    records = []
    malformed_rows = 0

    for line in proc.stdout:
        parts = line.strip("\r\n").split("\t")
        if len(parts) < 8:
            malformed_rows += 1
            continue

        frame_num, time_epoch, frame_len, eth_src, eth_dst, ip_src, ip_dst, protocol = parts

        try:
            timestamp = float(time_epoch)
            pkt_len = int(frame_len)
            f_num = int(frame_num) if frame_num.isdigit() else 0
        except (ValueError, TypeError):
            malformed_rows += 1
            continue

        if pkt_len < 0:
            malformed_rows += 1
            continue

        records.append({
            "frame_number": f_num,
            "timestamp": timestamp,
            "packet_size": pkt_len,
            "eth_src": eth_src.lower() if eth_src else "",
            "eth_dst": eth_dst.lower() if eth_dst else "",
            "ip_src": ip_src if ip_src else "",
            "ip_dst": ip_dst if ip_dst else "",
            "protocol": protocol if protocol else "UNKNOWN"
        })

    proc.stdout.close()
    proc.wait()

    if proc.returncode != 0:
        err = proc.stderr.read()
        print(f"Warning: tshark exited with code {proc.returncode}: {err.strip()}")
    proc.stderr.close()

    df = pd.DataFrame(records)
    return df


def filter_and_attribute_traffic(df: pd.DataFrame, direction: str = "uplink") -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Attributes packets strictly to registered client devices by MAC/IP and direction.
    """
    if df.empty:
        return pd.DataFrame(), pd.DataFrame()

    matched_records = []
    known_macs = set(CLIENT_REGISTRY.keys())
    known_ips = set(info["ip"] for info in CLIENT_REGISTRY.values())

    counts = {
        "total_parsed": len(df),
        "attributed": 0,
        "per_client": {info["node_id"]: 0 for info in CLIENT_REGISTRY.values()},
        "uplink_count": {info["node_id"]: 0 for info in CLIENT_REGISTRY.values()},
        "downlink_count": {info["node_id"]: 0 for info in CLIENT_REGISTRY.values()},
        "infrastructure": 0,
        "unregistered": 0
    }

    for row in df.itertuples(index=False):
        eth_src = row.eth_src
        eth_dst = row.eth_dst
        ip_src = row.ip_src
        ip_dst = row.ip_dst

        # Filter broadcast / multicast
        if eth_dst.startswith("ff:ff:ff") or eth_dst.startswith("01:00:5e") or eth_dst.startswith("33:33:"):
            counts["infrastructure"] += 1
            continue

        matched_node = None
        matched_dir = None

        if eth_src in known_macs:
            matched_node = CLIENT_REGISTRY[eth_src]["node_id"]
            matched_dir = "uplink"
        elif eth_dst in known_macs:
            matched_node = CLIENT_REGISTRY[eth_dst]["node_id"]
            matched_dir = "downlink"
        elif ip_src in known_ips:
            matched_node = IP_TO_REGISTRY[ip_src][1]["node_id"]
            matched_dir = "uplink"
        elif ip_dst in known_ips:
            matched_node = IP_TO_REGISTRY[ip_dst][1]["node_id"]
            matched_dir = "downlink"

        if matched_node is not None:
            if direction != "both" and matched_dir != direction:
                continue

            node_info = next(v for v in CLIENT_REGISTRY.values() if v["node_id"] == matched_node)
            matched_records.append({
                "frame_number": row.frame_number,
                "timestamp": row.timestamp,
                "packet_size": row.packet_size,
                "node_id": matched_node,
                "node_type": node_info["device_type"],
                "data_label": node_info["label"],
                "direction": matched_dir,
                "protocol": row.protocol
            })
            counts["attributed"] += 1
            counts["per_client"][matched_node] += 1
            if matched_dir == "uplink":
                counts["uplink_count"][matched_node] += 1
            else:
                counts["downlink_count"][matched_node] += 1
        else:
            counts["unregistered"] += 1

    df_attributed = pd.DataFrame(matched_records)

    # Attribution summary
    summary_rows = []
    for mac, info in CLIENT_REGISTRY.items():
        nid = info["node_id"]
        summary_rows.append({
            "Node_ID": nid,
            "MAC_Address": mac,
            "Assigned_IP": info["ip"],
            "Device_Type": info["device_type"],
            "Label": info["label"],
            "Attributed_Packets": counts["per_client"][nid],
            "Uplink_Packets": counts["uplink_count"][nid],
            "Downlink_Packets": counts["downlink_count"][nid]
        })
    df_summary = pd.DataFrame(summary_rows)
    return df_attributed, df_summary


def validate_raw_frame_records(df: pd.DataFrame) -> None:
    """
    Validates that a DataFrame of raw frames contains required columns,
    valid packet lengths (> 0), and valid numeric timestamps.
    """
    required_cols = {"frame_number", "timestamp", "packet_size"}
    missing = required_cols - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns in frame records: {missing}")

    if not df.empty:
        if (df["packet_size"] <= 0).any():
            invalid_cnt = (df["packet_size"] <= 0).sum()
            raise ValueError(f"Found {invalid_cnt} frames with invalid packet_size <= 0.")
        if df["timestamp"].isna().any():
            raise ValueError("Found NaN timestamps in frame records.")


def compute_1s_features_for_client(
    client_id: str,
    df_client: pd.DataFrame,
    start_epoch: Optional[float] = None,
    end_epoch: Optional[float] = None,
    include_empty: bool = False
) -> pd.DataFrame:
    """
    Computes fixed 1-second non-overlapping time window features for a single client.
    Bins are defined as [start_epoch + k, start_epoch + k + 1.0).

    Formula & Conventions:
    - packet_rate = packet_count / 1.0 (captured packets per 1-second bin)
    - If packet_count == 0:
        mean_IAT = NaN, IAT_std = NaN, mean_packet_size = NaN, packet_size_std = NaN
    - If packet_count == 1:
        mean_IAT = NaN, IAT_std = NaN, mean_packet_size = size, packet_size_std = 0.0
    - If packet_count == 2:
        mean_IAT = Delta t, IAT_std = 0.0, packet_size_std = sample std
    - If packet_count >= 3:
        mean_IAT = mean(Delta t), IAT_std = sample std(Delta t), packet_size_std = sample std
    """
    validate_raw_frame_records(df_client)

    if df_client.empty:
        if not include_empty or start_epoch is None or end_epoch is None:
            return pd.DataFrame()

    node_id = df_client["node_id"].iloc[0] if "node_id" in df_client.columns and not df_client.empty else client_id
    client_mac = df_client["client_mac"].iloc[0] if "client_mac" in df_client.columns and not df_client.empty else client_id
    node_type = df_client["node_type"].iloc[0] if "node_type" in df_client.columns and not df_client.empty else "Unverified_Mobile_Client"
    data_label = df_client["data_label"].iloc[0] if "data_label" in df_client.columns and not df_client.empty else "real_observed_traffic"

    # Enforce strict chronological order by (timestamp, frame_number)
    df_sorted = df_client.sort_values(by=["timestamp", "frame_number"]).reset_index(drop=True)

    if start_epoch is None:
        start_epoch = float(math.floor(df_sorted["timestamp"].min())) if not df_sorted.empty else 0.0
    if end_epoch is None:
        end_epoch = float(math.floor(df_sorted["timestamp"].max()) + 1.0) if not df_sorted.empty else start_epoch + 1.0

    num_bins = int(math.ceil(end_epoch - start_epoch))
    if num_bins <= 0:
        num_bins = 1

    window_rows = []
    window_seq = 0

    for k in range(num_bins):
        bin_start = start_epoch + float(k)
        bin_end = bin_start + 1.0

        # Slicing: strictly half-open [bin_start, bin_end)
        mask = (df_sorted["timestamp"] >= bin_start) & (df_sorted["timestamp"] < bin_end)

        bin_packets = df_sorted[mask]
        n_pkts = len(bin_packets)

        if n_pkts == 0 and not include_empty:
            continue

        window_seq += 1

        # 1. Packet rate = packet_count / 1.0 (captured packets per second)
        packet_rate = float(n_pkts) / 1.0

        # 2. IAT & Size metrics based on packet count
        if n_pkts == 0:
            mean_iat = np.nan
            iat_std = np.nan
            mean_packet_size = np.nan
            packet_size_std = np.nan
        elif n_pkts == 1:
            mean_iat = np.nan
            iat_std = np.nan
            mean_packet_size = float(bin_packets["packet_size"].iloc[0])
            packet_size_std = 0.0
        elif n_pkts == 2:
            iats = bin_packets["timestamp"].diff().dropna()
            mean_iat = float(iats.iloc[0])
            iat_std = 0.0
            mean_packet_size = float(bin_packets["packet_size"].mean())
            packet_size_std = float(bin_packets["packet_size"].std())
            if pd.isna(packet_size_std):
                packet_size_std = 0.0
        else:  # n_pkts >= 3
            iats = bin_packets["timestamp"].diff().dropna()
            mean_iat = float(iats.mean())
            iat_std = float(iats.std())
            if pd.isna(iat_std):
                iat_std = 0.0
            mean_packet_size = float(bin_packets["packet_size"].mean())
            packet_size_std = float(bin_packets["packet_size"].std())
            if pd.isna(packet_size_std):
                packet_size_std = 0.0

        dt_start_utc = datetime.datetime.fromtimestamp(bin_start, tz=datetime.timezone.utc)
        dt_end_utc = datetime.datetime.fromtimestamp(bin_end, tz=datetime.timezone.utc)

        window_rows.append({
            "client_mac": client_mac,
            "node_id": node_id,
            "Node_Type": node_type,
            "Data_Label": data_label,
            "Window_ID": window_seq,
            "Bin_Index": k,
            "bin_start_timestamp": bin_start,
            "bin_end_timestamp": bin_end,
            "Window_Start_UTC": dt_start_utc.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "Window_End_UTC": dt_end_utc.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "packet_count": n_pkts,
            "mean_IAT": mean_iat,
            "IAT_std": iat_std,
            "packet_rate": packet_rate,
            "mean_packet_size": mean_packet_size,
            "packet_size_std": packet_size_std
        })

    return pd.DataFrame(window_rows)


def extract_1s_features_from_dataframe(
    df_attributed: pd.DataFrame,
    include_empty: bool = False
) -> pd.DataFrame:
    """
    Core function to process attributed traffic into 1-second window features,
    grouped by client identity (MAC or node_id).
    """
    if df_attributed.empty:
        return pd.DataFrame()

    validate_raw_frame_records(df_attributed)

    group_col = "client_mac" if "client_mac" in df_attributed.columns else "node_id"

    global_start = float(math.floor(df_attributed["timestamp"].min()))
    global_end = float(math.floor(df_attributed["timestamp"].max()) + 1.0)

    all_windows = []
    for client_val in df_attributed[group_col].unique():
        df_client = df_attributed[df_attributed[group_col] == client_val]
        df_feat = compute_1s_features_for_client(
            client_id=str(client_val),
            df_client=df_client,
            start_epoch=global_start,
            end_epoch=global_end,
            include_empty=include_empty
        )
        if not df_feat.empty:
            all_windows.append(df_feat)

    if not all_windows:
        return pd.DataFrame()

    df_out = pd.concat(all_windows, ignore_index=True)
    return df_out


def run_1s_extraction_pipeline(
    pcap_path: Any,
    output_features_path: Any,
    output_summary_path: Any,
    direction: str = "uplink",
    include_empty: bool = False,
    overwrite: bool = False
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Reads PCAP, attributes traffic, extracts 1-second features, and saves safely to disk.
    """
    pcap_path = Path(pcap_path)
    output_features_path = Path(output_features_path)
    output_summary_path = Path(output_summary_path)

    # Overwrite protection
    if not overwrite:
        if output_features_path.exists():
            raise FileExistsError(f"Target feature file already exists: {output_features_path}. Aborting to prevent overwrite.")
        if output_summary_path.exists():
            raise FileExistsError(f"Target summary file already exists: {output_summary_path}. Aborting to prevent overwrite.")

    print("=" * 80)
    print("EXPERIMENTAL FIXED 1-SECOND PCAP FEATURE EXTRACTOR")
    print(f"Capture Input:     {pcap_path}")
    print(f"Traffic Direction: {direction.upper()}")
    print(f"Empty Windows:     {'INCLUDED' if include_empty else 'SPARSE (Omitted)'}")
    print("=" * 80)

    df_raw = parse_pcap_frames(pcap_path)
    if df_raw.empty:
        print("Warning: No valid frames parsed from capture.")
        return pd.DataFrame(), pd.DataFrame()

    df_attr, df_summary = filter_and_attribute_traffic(df_raw, direction=direction)
    df_features = extract_1s_features_from_dataframe(df_attr, include_empty=include_empty)

    # Save to disk
    output_features_path.parent.mkdir(parents=True, exist_ok=True)
    df_features.to_csv(output_features_path, index=False)
    df_summary.to_csv(output_summary_path, index=False)

    print(f"\nExtraction complete:")
    print(f"  Total 1-second feature windows: {len(df_features)}")
    print(f"  Features saved to: {output_features_path}")
    print(f"  Summary saved to:  {output_summary_path}")

    return df_features, df_summary


def main():
    parser = argparse.ArgumentParser(description="Extract fixed 1-second time window features from PCAP.")
    parser.add_argument("--pcap", type=str, required=True, help="Path to PCAP/PCAPNG file")
    parser.add_argument("--direction", type=str, choices=["uplink", "downlink", "both"], default="uplink", help="Traffic direction")
    parser.add_argument("--include-empty", action="store_true", help="Include empty 1-second bins with 0 packet count")
    parser.add_argument("--output-features", type=str, default="data/processed/experimental_time_windows/time_1s_pcap_features_uplink.csv")
    parser.add_argument("--output-summary", type=str, default="data/processed/experimental_time_windows/time_1s_pcap_summary_uplink.csv")
    args = parser.parse_args()

    project_root = Path(__file__).parent.parent
    pcap_path = project_root / args.pcap if not Path(args.pcap).is_absolute() else Path(args.pcap)
    out_feat = project_root / args.output_features if not Path(args.output_features).is_absolute() else Path(args.output_features)
    out_summ = project_root / args.output_summary if not Path(args.output_summary).is_absolute() else Path(args.output_summary)

    run_1s_extraction_pipeline(
        pcap_path=pcap_path,
        output_features_path=out_feat,
        output_summary_path=out_summ,
        direction=args.direction,
        include_empty=args.include_empty
    )


if __name__ == "__main__":
    main()
