import pandas as pd
import numpy as np
from pathlib import Path
import random

def generate_node_anomaly(node_id, node_type, target_count, profile):
    """
    Generates synthetic anomalous traffic for a specific node until 
    target_count is reached.
    """
    records = []
    current_time = 0.0
    
    while len(records) < target_count:
        if profile == "Node_1":
            # Node 1 anomaly: significantly increased transmission frequency
            # (Much smaller IATs than its normal 2-3s behavior)
            iat = random.uniform(0.1, 0.5)
            size = int(random.uniform(60, 100))
            
        elif profile == "Node_2":
            # Node 2 anomaly: unusually high packet transmission rate
            # (Extremely small IAT, but packet size stays reasonable)
            iat = random.uniform(0.01, 0.05)
            size = int(random.uniform(60, 100))
            
        elif profile == "Node_3":
            # Node 3 anomaly: unusually irregular IATs
            # (Mix of normal intervals and occasional very short intervals)
            if random.random() < 0.3:
                iat = random.uniform(0.01, 0.05)
            else:
                iat = random.uniform(0.8, 1.5)
            size = int(random.uniform(60, 100))
            
        elif profile == "Node_4":
            # Node 4 anomaly: abnormal burst of many packets
            # (Clearly different from its normal occasional 2-4 packet burst)
            if random.random() < 0.1:
                burst_count = random.randint(15, 25)
                for _ in range(burst_count):
                    if len(records) >= target_count:
                        break
                    burst_iat = random.uniform(0.01, 0.05)
                    current_time += burst_iat
                    records.append({
                        "Node_ID": node_id,
                        "Node_Type": node_type,
                        "Timestamp": current_time,
                        "Packet_Size": int(random.uniform(60, 100))
                    })
                continue
            else:
                iat = random.uniform(3.0, 6.0)
                size = int(random.uniform(60, 100))
                
        elif profile == "Node_5":
            # Node 5 anomaly: unusually large packet sizes & moderate freq increase
            # (Sizes way larger than its normal 1000-1500 limit)
            iat = random.uniform(0.1, 0.2)
            size = int(random.uniform(2500, 3500))
            
        else:
            iat = 1.0
            size = 100
            
        current_time += iat
        records.append({
            "Node_ID": node_id,
            "Node_Type": node_type,
            "Timestamp": current_time,
            "Packet_Size": size
        })
        
    return records

def main():
    # 6. Keep anomaly generation deterministic
    random.seed(42)
    np.random.seed(42)
    
    # Setup paths
    current_dir = Path(__file__).parent
    project_root = current_dir.parent
    processed_dir = project_root / "data" / "processed"
    input_path = processed_dir / "normal_5node_traffic.csv"
    output_path = processed_dir / "anomaly_5node_traffic.csv"
    
    if not input_path.exists():
        print(f"Error: Could not find normal traffic file at {input_path}")
        return
        
    # 1. Load the existing normal traffic CSV
    # 2. We strictly READ this and do NOT modify the original file.
    df_normal = pd.read_csv(input_path)
    
    all_anomalies = []
    
    # 4. Use the same five node types already present
    node_mapping = {
        "Node_1": "Temperature Sensor",
        "Node_2": "Smart Light",
        "Node_3": "Smart Plug",
        "Node_4": "Motion Sensor",
        "Node_5": "Camera-like Traffic Generator"
    }
    
    print("--- Anomalous Traffic Generation ---")
    
    # --- IMPORTANT COMMENTS (Req #9) ---
    # 1. This dataset represents controlled synthetic anomalous behaviour. 
    #    These are NOT real Wi-Fi packet captures.
    # 2. In this context, an "anomaly" simply means a statistical deviation 
    #    from the node's baseline model. It does NOT automatically mean a 
    #    confirmed cyberattack. 
    # 3. The entire purpose of creating these deviations is to test whether 
    #    statistical behaviour changes are successfully detected by our 
    #    machine learning (Isolation Forest) models.
    
    for node_id, node_type in node_mapping.items():
        # 7. Generate approximately the same overall number of anomaly events 
        #    as the normal dataset by targeting the exact normal count per node.
        normal_count = len(df_normal[df_normal["Node_ID"] == node_id])
        if normal_count == 0:
            normal_count = 1000 # fallback if normal data is missing
            
        node_records = generate_node_anomaly(node_id, node_type, normal_count, node_id)
        all_anomalies.extend(node_records)
        
    df_anomaly = pd.DataFrame(all_anomalies)
    
    # 8. Keep timestamps chronological by sorting the merged dataset
    df_anomaly = df_anomaly.sort_values("Timestamp").reset_index(drop=True)
    
    # Columns match the normal raw traffic dataset.
    # IAT will be calculated later during feature extraction.
    column_order = ["Node_ID", "Node_Type", "Timestamp", "Packet_Size"]
    df_anomaly = df_anomaly[column_order]
    
    # Save the output
    df_anomaly.to_csv(output_path, index=False)
    
    # 10. Print requested output
    print(f"\nTotal generated anomaly events: {len(df_anomaly)}")
    
    print("\nEvent count per Node_ID:")
    print(df_anomaly["Node_ID"].value_counts().to_string())
    
    print("\nMinimum and Maximum Packet Size per Node:")
    grouped = df_anomaly.groupby("Node_ID")["Packet_Size"].agg(['min', 'max'])
    print(grouped.to_string())
    
    print(f"\nOutput saved to: {output_path}")

if __name__ == "__main__":
    main()
