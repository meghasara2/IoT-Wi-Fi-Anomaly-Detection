import pandas as pd
from pathlib import Path

def inspect_dataset(file_path, label):
    """Reads a CSV file, filters ICMP Echo requests, calculates IAT, and extracts features."""
    if not file_path.exists():
        print(f"Error: File not found at {file_path}")
        return None

    print(f"--- Inspecting: {file_path.name} ---")
    
    # Read the dataset
    df = pd.read_csv(file_path)
    
    # Check for the correct column name for Info, as it might have extra spaces/newlines
    info_col = [col for col in df.columns if 'Info' in col][0]

    # Filter records to ICMP Echo (ping) REQUEST packets only
    df_requests = df[df[info_col].str.contains("Echo (ping) request", na=False, regex=False)].copy()
    
    # Sort the selected packets by Time
    df_requests = df_requests.sort_values(by="Time")
    
    # Calculate inter-arrival time (IAT)
    df_requests["IAT_seconds"] = df_requests["Time"].diff()
    
    # --- Feature Extraction (Stage 3) ---
    # Do not include the first request of the entire dataset (IAT is NaN)
    df_clean = df_requests.dropna(subset=["IAT_seconds"]).copy()
    
    window_size = 5
    features = []
    
    # Create sequential traffic windows of 5 request packets
    for i in range(0, len(df_clean), window_size):
        window = df_clean.iloc[i:i+window_size]
        
        if len(window) == 0:
            continue
            
        # Calculate window features
        mean_iat = window["IAT_seconds"].mean()
        iat_std = window["IAT_seconds"].std()
        
        # packet_rate = (number_of_packets - 1) / (last_timestamp - first_timestamp)
        if len(window) > 1:
            duration = window["Time"].iloc[-1] - window["Time"].iloc[0]
            packet_rate = (len(window) - 1) / duration if duration > 0 else 0
        else:
            packet_rate = 0
        
        # Use existing Length column for packet size
        mean_packet_size = window["Length"].mean()
        packet_size_std = window["Length"].std()
        
        features.append({
            "Dataset": label,
            "mean_IAT": mean_iat,
            "IAT_std": iat_std,
            "packet_rate": packet_rate,
            "mean_packet_size": mean_packet_size,
            "packet_size_std": packet_size_std
        })
    
    df_features = pd.DataFrame(features)
    print(f"--- Feature Table for {label} ---")
    # Print the resulting feature table (convert to string to ensure all columns print well)
    print(df_features.to_string())
    print("\n")
    
    return df_features

def main():
    # Find the project root relative to this Python file
    current_dir = Path(__file__).parent
    project_root = current_dir.parent
    
    # Define paths to the datasets
    data_dir = project_root / "data"
    normal_data_path = data_dir / "normal_2sec_traffic.csv"
    anomaly_data_path = data_dir / "high_rate_anomaly.csv"
    
    # Inspect each dataset
    # We do NOT call the high-rate dataset an "attack". 
    # It is a controlled high-rate anomalous-behaviour experiment.
    df_normal = inspect_dataset(normal_data_path, "Normal Traffic")
    df_anomaly = inspect_dataset(anomaly_data_path, "High-Rate Anomalous-Behaviour Experiment")

    # --- Stage 4: Save processed features ---
    # Combine the feature DataFrames
    if df_normal is not None and df_anomaly is not None:
        df_combined = pd.concat([df_normal, df_anomaly], ignore_index=True)
        
        # Create the processed data directory if it does not exist
        processed_dir = data_dir / "processed"
        processed_dir.mkdir(parents=True, exist_ok=True)
        
        # Save the combined DataFrame
        output_path = processed_dir / "traffic_features.csv"
        df_combined.to_csv(output_path, index=False)
        
        # Print confirmation
        print(f"--- Saved Processed Data ---")
        print(f"Output File: {output_path}")
        print(f"Number of feature rows saved: {len(df_combined)}")
        print(f"Columns: {list(df_combined.columns)}")
        print("\n")

if __name__ == "__main__":
    main()
