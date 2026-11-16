import subprocess
import sys
from pathlib import Path
import pandas as pd
import numpy as np

# Configurable TShark Path
TSHARK_DEFAULT_PATH = r"C:\Program Files\Wireshark\tshark.exe"

# Hotspot subnet configuration
HOTSPOT_SUBNET_PREFIX = "192.168.137."

# Configurable Client Node Registry
# Devices are assigned neutral Node IDs with unverified status until physically verified.
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

# Lookup by IP as fallback when MAC is not resolved (e.g. higher-layer virtual framing)
IP_TO_REGISTRY = {info["ip"]: (mac, info) for mac, info in CLIENT_REGISTRY.items()}


def parse_pcap_with_tshark(pcap_path: Path, tshark_path: str = TSHARK_DEFAULT_PATH) -> pd.DataFrame:
    """
    Executes tshark as a subprocess to extract relevant packet fields without external Python dependencies.
    """
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    tshark_bin = Path(tshark_path)
    if not tshark_bin.exists():
        raise FileNotFoundError(f"tshark executable not found at: {tshark_path}")

    # Extract frame number, timestamp (epoch with microsecond/nanosecond precision), length, MACs, IPs
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

    print(f"Parsing PCAP using tshark: {pcap_path.name}...")
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
        except (ValueError, TypeError):
            malformed_rows += 1
            continue

        records.append({
            "frame_number": int(frame_num) if frame_num.isdigit() else 0,
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
        print(f"Warning: tshark exited with returncode {proc.returncode}: {err.strip()}")
    proc.stderr.close()

    df = pd.DataFrame(records)
    print(f"Extraction complete: {len(df):,} valid packet records parsed ({malformed_rows} malformed lines ignored).")
    return df


def attribute_traffic(df: pd.DataFrame, traffic_direction: str = "both") -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Attributes packets strictly to registered client devices.
    
    traffic_direction:
        - 'both': Include client as source (uplink) or destination (downlink)
        - 'uplink': Only packets originated by client
        - 'downlink': Only packets destined to client
    """
    if df.empty:
        return pd.DataFrame(), pd.DataFrame()

    matched_records = []
    counts = {
        "total_parsed": len(df),
        "attributed": 0,
        "per_client": {info["node_id"]: 0 for info in CLIENT_REGISTRY.values()},
        "uplink_count": {info["node_id"]: 0 for info in CLIENT_REGISTRY.values()},
        "downlink_count": {info["node_id"]: 0 for info in CLIENT_REGISTRY.values()},
        "unregistered_local": 0,
        "infrastructure_multicast_broadcast": 0,
        "skipped_other": 0
    }

    known_macs = set(CLIENT_REGISTRY.keys())
    known_ips = set(info["ip"] for info in CLIENT_REGISTRY.values())

    for row in df.itertuples(index=False):
        eth_src = row.eth_src
        eth_dst = row.eth_dst
        ip_src = row.ip_src
        ip_dst = row.ip_dst

        # Check broadcast / multicast
        if eth_dst.startswith("ff:ff:ff") or eth_dst.startswith("01:00:5e") or eth_dst.startswith("33:33:"):
            counts["infrastructure_multicast_broadcast"] += 1
            continue

        matched_node = None
        matched_direction = None

        # Check matching by MAC first (link-layer truth)
        if eth_src in known_macs:
            matched_node = CLIENT_REGISTRY[eth_src]["node_id"]
            matched_direction = "uplink"
        elif eth_dst in known_macs:
            matched_node = CLIENT_REGISTRY[eth_dst]["node_id"]
            matched_direction = "downlink"
        # Secondary fallback: match by local Hotspot IP if MAC was masked
        elif ip_src in known_ips:
            matched_node = IP_TO_REGISTRY[ip_src][1]["node_id"]
            matched_direction = "uplink"
        elif ip_dst in known_ips:
            matched_node = IP_TO_REGISTRY[ip_dst][1]["node_id"]
            matched_direction = "downlink"

        if matched_node is not None:
            # Check configured direction filter
            if traffic_direction != "both" and matched_direction != traffic_direction:
                continue

            node_info = next(v for v in CLIENT_REGISTRY.values() if v["node_id"] == matched_node)
            
            matched_records.append({
                "frame_number": row.frame_number,
                "timestamp": row.timestamp,
                "packet_size": row.packet_size,
                "node_id": matched_node,
                "node_type": node_info["device_type"],
                "data_label": node_info["label"],
                "direction": matched_direction,
                "protocol": row.protocol
            })

            counts["attributed"] += 1
            counts["per_client"][matched_node] += 1
            if matched_direction == "uplink":
                counts["uplink_count"][matched_node] += 1
            else:
                counts["downlink_count"][matched_node] += 1
        else:
            # Check if this was another local IP or unassociated traffic
            if ip_src.startswith(HOTSPOT_SUBNET_PREFIX) or ip_dst.startswith(HOTSPOT_SUBNET_PREFIX):
                counts["unregistered_local"] += 1
            else:
                counts["skipped_other"] += 1

    df_attributed = pd.DataFrame(matched_records)

    # Build attribution summary DataFrame
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
            "Downlink_Packets": counts["downlink_count"][nid],
        })

    summary_rows.append({
        "Node_ID": "UNREGISTERED_OR_MULTICAST",
        "MAC_Address": "N/A",
        "Assigned_IP": "N/A",
        "Device_Type": "Infrastructure / Non-Client",
        "Label": "skipped",
        "Attributed_Packets": counts["infrastructure_multicast_broadcast"] + counts["unregistered_local"] + counts["skipped_other"],
        "Uplink_Packets": 0,
        "Downlink_Packets": 0,
    })

    df_summary = pd.DataFrame(summary_rows)
    return df_attributed, df_summary


def compute_node_windows(node_id: str, df_node: pd.DataFrame, window_size: int = 10) -> list[dict]:
    """
    Calculates windowed traffic features matching extract_node_features.py conventions:
      - mean_IAT
      - IAT_std
      - packet_rate
      - mean_packet_size
      - packet_size_std
    Also captures window start/end timestamps and packet count.
    """
    if df_node.empty or len(df_node) < window_size:
        return []

    df_sorted = df_node.sort_values("timestamp").reset_index(drop=True)
    node_type = df_sorted["node_type"].iloc[0]
    data_label = df_sorted["data_label"].iloc[0]

    # Note: IAT is computed strictly within each 10-packet window below

    features = []

    # Sequential non-overlapping windows of window_size packets
    for window_id, i in enumerate(range(0, len(df_sorted), window_size), start=1):
        window = df_sorted.iloc[i:i + window_size]

        # Ignore incomplete final window
        if len(window) < window_size:
            break

        window_start_time = window["timestamp"].iloc[0]
        window_end_time = window["timestamp"].iloc[-1]
        duration = window_end_time - window_start_time

        # Calculate IAT metrics strictly using the 9 within-window intervals (diff().dropna())
        window_iats = window["timestamp"].diff().dropna()
        mean_iat = window_iats.mean() if not window_iats.empty else 0.0
        iat_std = window_iats.std() if len(window_iats) > 1 else 0.0
        if pd.isna(iat_std):
            iat_std = 0.0

        # Calculate packet_rate based on elapsed time between the first and last packet
        # Matches logic: (len - 1) / duration if duration > 0 else 0
        if duration > 0:
            packet_rate = (len(window) - 1) / duration
        else:
            packet_rate = 0.0

        mean_packet_size = window["packet_size"].mean()
        packet_size_std = window["packet_size"].std()
        if pd.isna(packet_size_std):
            packet_size_std = 0.0

        features.append({
            "Node_ID": node_id,
            "Node_Type": node_type,
            "Data_Label": data_label,
            "Window_ID": window_id,
            "Window_Packet_Count": len(window),
            "Window_Start_Time": window_start_time,
            "Window_End_Time": window_end_time,
            "Window_Duration_Sec": duration,
            "mean_IAT": mean_iat,
            "IAT_std": iat_std,
            "packet_rate": packet_rate,
            "mean_packet_size": mean_packet_size,
            "packet_size_std": packet_size_std
        })

    return features


def process_pcap_features(
    pcap_path: Path,
    output_features_path: Path,
    output_summary_path: Path,
    direction: str = "both",
    window_size: int = 10,
    dry_run: bool = False
):
    """
    Main extraction pipeline.
    """
    print("=" * 70)
    print("REAL PCAP FEATURE EXTRACTION PIPELINE")
    print(f"Data Category: REAL OBSERVED TRAFFIC (Not Attack-Labelled Data)")
    print(f"Traffic Direction Mode: {direction.upper()}")
    print("=" * 70)

    # 1. Check for existing files to avoid accidental overwrite
    if not dry_run:
        if output_features_path.exists():
            raise FileExistsError(f"Target feature file already exists: {output_features_path}. Halting to prevent overwrite.")
        if output_summary_path.exists():
            raise FileExistsError(f"Target summary file already exists: {output_summary_path}. Halting to prevent overwrite.")

    # 2. Parse PCAP
    df_raw = parse_pcap_with_tshark(pcap_path)

    if df_raw.empty:
        print("Warning: Capture file is empty or contained no valid frames.")
        return

    # 3. Attribute traffic to registered clients
    df_attributed, df_summary = attribute_traffic(df_raw, traffic_direction=direction)

    # 4. Compute 10-packet windows per client
    all_window_features = []
    for node_id in df_attributed["node_id"].unique():
        df_node = df_attributed[df_attributed["node_id"] == node_id].copy()
        node_features = compute_node_windows(node_id, df_node, window_size=window_size)
        all_window_features.extend(node_features)

    df_features = pd.DataFrame(all_window_features)

    # 5. Output and Summary
    print("\n" + "-" * 70)
    print("ATTRIBUTION SUMMARY:")
    print("-" * 70)
    print(df_summary.to_string(index=False))

    print("\n" + "-" * 70)
    print("FEATURE WINDOWS SUMMARY:")
    print("-" * 70)
    if not df_features.empty:
        print(f"Total 10-packet windows produced: {len(df_features)}")
        print("\nWindows per Node:")
        print(df_features["Node_ID"].value_counts().to_string())

        print("\nFirst 5 feature windows sample:")
        sample_cols = ["Node_ID", "Window_ID", "mean_IAT", "IAT_std", "packet_rate", "mean_packet_size", "packet_size_std"]
        print(df_features[sample_cols].head(5).to_string(index=False))
    else:
        print("No windows generated (insufficient packet count for window size).")

    if dry_run:
        print("\n[DRY RUN MODE]: Files were not written to disk.")
        return df_features, df_summary

    # Save to disk
    output_features_path.parent.mkdir(parents=True, exist_ok=True)
    df_features.to_csv(output_features_path, index=False)
    df_summary.to_csv(output_summary_path, index=False)

    print(f"\n[OUTPUT SAVED]:")
    print(f"  - Features: {output_features_path}")
    print(f"  - Summary:  {output_summary_path}")

    return df_features, df_summary


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Extract windowed features from real PCAP capture.")
    parser.add_argument("--pcap", type=str, default="wifi_hotspot_clients_fresh.pcapng", help="Path to pcapng file")
    parser.add_argument("--direction", type=str, choices=["both", "uplink", "downlink"], default="both", help="Traffic direction")
    parser.add_argument("--output-features", type=str, default=None, help="Custom output path for feature CSV (default: data/processed/real_pcap_node_features.csv)")
    parser.add_argument("--output-summary", type=str, default=None, help="Custom output path for summary CSV (default: data/processed/real_pcap_attribution_summary.csv)")
    parser.add_argument("--dry-run", action="store_true", help="Execute extraction in-memory without saving files")
    args = parser.parse_args()

    project_root = Path(__file__).parent.parent
    pcap_file = project_root / args.pcap
    
    if args.output_features:
        output_features = Path(args.output_features)
        if not output_features.is_absolute():
            output_features = project_root / output_features
    else:
        output_features = project_root / "data" / "processed" / "real_pcap_node_features.csv"

    if args.output_summary:
        output_summary = Path(args.output_summary)
        if not output_summary.is_absolute():
            output_summary = project_root / output_summary
    else:
        output_summary = project_root / "data" / "processed" / "real_pcap_attribution_summary.csv"

    process_pcap_features(
        pcap_path=pcap_file,
        output_features_path=output_features,
        output_summary_path=output_summary,
        direction=args.direction,
        dry_run=args.dry_run
    )


if __name__ == "__main__":
    main()
