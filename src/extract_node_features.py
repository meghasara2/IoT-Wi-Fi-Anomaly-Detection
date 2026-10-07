import pandas as pd
from pathlib import Path

def process_node_traffic(node_id, df_node):
    """
    Extracts features for a specific software-simulated node using 10-packet windows.
    """
    # Sort the node's traffic by Timestamp to ensure chronological order
    df_sorted = df_node.sort_values("Timestamp").reset_index(drop=True)
    node_type = df_sorted["Node_Type"].iloc[0]
    
    window_size = 10
    features = []
    
    # Create sequential windows of 10 packets
    for window_id, i in enumerate(range(0, len(df_sorted), window_size), start=1):
        window = df_sorted.iloc[i:i+window_size]
        
        # Ignore an incomplete final window
        if len(window) < window_size:
            break
            
        # Calculate feature metrics
        mean_iat = window["IAT"].mean()
        iat_std = window["IAT"].std()
        
        # Calculate packet_rate based on elapsed time between the first and last packet
        if len(window) > 1:
            duration = window["Timestamp"].iloc[-1] - window["Timestamp"].iloc[0]
            packet_rate = (len(window) - 1) / duration if duration > 0 else 0
        else:
            packet_rate = 0
            
        mean_packet_size = window["Packet_Size"].mean()
        packet_size_std = window["Packet_Size"].std()
        
        # Preserve metadata and append feature row
        features.append({
            "Node_ID": node_id,
            "Node_Type": node_type,
            "Window_ID": window_id,
            "mean_IAT": mean_iat,
            "IAT_std": iat_std,
            "packet_rate": packet_rate,
            "mean_packet_size": mean_packet_size,
            "packet_size_std": packet_size_std
        })
        
    return features

def main():
    # Setup paths
    current_dir = Path(__file__).parent
    project_root = current_dir.parent
    processed_dir = project_root / "data" / "processed"
    input_path = processed_dir / "normal_5node_traffic.csv"
    output_path = processed_dir / "normal_5node_features.csv"
    
    if not input_path.exists():
        print(f"Error: Could not find input file at {input_path}")
        return
        
    # Read the input CSV
    df = pd.read_csv(input_path)
    
    all_features = []
    
    # Process each Node_ID separately so we don't mix packets from different nodes
    for node_id in df["Node_ID"].unique():
        df_node = df[df["Node_ID"] == node_id].copy()
        node_features = process_node_traffic(node_id, df_node)
        all_features.extend(node_features)
        
    df_features = pd.DataFrame(all_features)
    
    # Enforce the final requested column order
    column_order = [
        "Node_ID", 
        "Node_Type", 
        "Window_ID", 
        "mean_IAT", 
        "IAT_std", 
        "packet_rate", 
        "mean_packet_size", 
        "packet_size_std"
    ]
    df_features = df_features[column_order]
    
    # Save the result
    df_features.to_csv(output_path, index=False)
    
    # Print requested summary
    print(f"--- Node Feature Extraction Complete ---")
    print(f"Total number of feature windows: {len(df_features)}")
    
    print("\nNumber of windows for each Node_ID:")
    print(df_features["Node_ID"].value_counts().to_string())
    
    print("\nFirst 10 rows:")
    print(df_features.head(10).to_string())
    
    print(f"\nOutput File: {output_path}")

if __name__ == "__main__":
    main()
