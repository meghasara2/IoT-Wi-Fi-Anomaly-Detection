import pandas as pd
from pathlib import Path

def main():
    print("--- Stage 20A: Inspect Anomaly Dataset ---\n")
    
    # Setup paths
    current_dir = Path(__file__).parent
    project_root = current_dir.parent
    processed_dir = project_root / "data" / "processed"
    
    traffic_file = processed_dir / "anomaly_5node_traffic.csv"
    features_file = processed_dir / "anomaly_5node_features.csv"
    normal_features_file = processed_dir / "normal_5node_features.csv"
    
    failures = []
    
    # ---------------------------------------------------------
    # 1. anomaly_5node_traffic.csv
    # ---------------------------------------------------------
    print("--- anomaly_5node_traffic.csv ---")
    if not traffic_file.exists():
        print(f"File exists: False ({traffic_file})")
        failures.append("anomaly_5node_traffic.csv not found")
    else:
        print("File exists: True")
        df_traffic = pd.read_csv(traffic_file)
        
        print(f"Total number of rows: {len(df_traffic)}")
        print(f"Column names: {list(df_traffic.columns)}")
        
        unique_nodes = df_traffic["Node_ID"].nunique()
        print(f"Number of unique Node_ID values: {unique_nodes}")
        
        print("\nNode_ID row counts:")
        node_counts = df_traffic["Node_ID"].value_counts()
        for node_id, count in node_counts.items():
            print(f"  {node_id}: {count}")
            
        print(f"\nNode_Type values: {df_traffic['Node_Type'].unique().tolist()}")
        
        print("\nPacket_Size min/max per node:")
        size_agg = df_traffic.groupby("Node_ID")["Packet_Size"].agg(["min", "max"])
        for node_id, row in size_agg.iterrows():
            print(f"  {node_id}: min={row['min']}, max={row['max']}")
            
        print("\nTimestamp min/max per node:")
        time_agg = df_traffic.groupby("Node_ID")["Timestamp"].agg(["min", "max"])
        for node_id, row in time_agg.iterrows():
            print(f"  {node_id}: min={row['min']:.2f}, max={row['max']:.2f}")

    # ---------------------------------------------------------
    # 2. anomaly_5node_features.csv
    # ---------------------------------------------------------
    print("\n--- anomaly_5node_features.csv ---")
    df_features = pd.DataFrame()
    if not features_file.exists():
        print(f"File exists: False ({features_file})")
        failures.append("anomaly_5node_features.csv not found")
    else:
        print("File exists: True")
        df_features = pd.read_csv(features_file)
        
        print(f"Total number of rows: {len(df_features)}")
        print(f"Column names: {list(df_features.columns)}")
        
        unique_nodes_feat = df_features["Node_ID"].nunique()
        print(f"Number of unique Node_ID values: {unique_nodes_feat}")
        
        print("\nNumber of feature windows for each Node_ID:")
        feat_counts = df_features["Node_ID"].value_counts()
        for node_id, count in feat_counts.items():
            print(f"  {node_id}: {count}")
            
        print(f"\nNode_Type values: {df_features['Node_Type'].unique().tolist()}")
        
        req_features = ["mean_IAT", "IAT_std", "packet_rate", "mean_packet_size", "packet_size_std"]
        missing_features = [f for f in req_features if f not in df_features.columns]
        
        print(f"\nRequired ML feature columns exist: {len(missing_features) == 0}")
        if missing_features:
            print(f"  Missing: {missing_features}")
            failures.append("Missing required ML feature columns")
        else:
            # Check for missing/null values
            null_counts = df_features[req_features].isnull().sum()
            total_nulls = null_counts.sum()
            print(f"Missing/null values in ML feature columns: {total_nulls}")
            if total_nulls > 0:
                print(null_counts[null_counts > 0])
                failures.append("Missing/null values found in ML feature columns")
                
            # Check that all 5 feature columns are numeric
            non_numeric = []
            for col in req_features:
                if not pd.api.types.is_numeric_dtype(df_features[col]):
                    non_numeric.append(col)
            print(f"All 5 feature columns are numeric: {len(non_numeric) == 0}")
            if non_numeric:
                print(f"  Non-numeric columns: {non_numeric}")
                failures.append("Some ML feature columns are not numeric")
                
        # Check for duplicate (Node_ID, Window_ID) pairs
        if "Node_ID" in df_features.columns and "Window_ID" in df_features.columns:
            dups = df_features.duplicated(subset=["Node_ID", "Window_ID"]).sum()
            print(f"Duplicate (Node_ID, Window_ID) pairs: {dups}")
            if dups > 0:
                failures.append("Duplicate (Node_ID, Window_ID) pairs found")
                
        print("\nFirst 5 rows of feature dataset:")
        print(df_features.head(5).to_string())

    # ---------------------------------------------------------
    # 3. Compare with normal_5node_features.csv
    # ---------------------------------------------------------
    print("\n--- Feature Column Comparison ---")
    if not normal_features_file.exists():
        print(f"Error: {normal_features_file.name} not found for comparison.")
    elif not df_features.empty:
        # Load only columns to save memory
        df_normal = pd.read_csv(normal_features_file, nrows=0) 
        normal_cols = set(df_normal.columns)
        anomaly_cols = set(df_features.columns)
        
        in_both = normal_cols.intersection(anomaly_cols)
        only_normal = normal_cols - anomaly_cols
        only_anomaly = anomaly_cols - normal_cols
        
        print(f"Columns present in both: {sorted(list(in_both))}")
        print(f"Columns only in normal dataset: {sorted(list(only_normal))}")
        print(f"Columns only in anomaly dataset: {sorted(list(only_anomaly))}")

    # ---------------------------------------------------------
    # 4. Final Result
    # ---------------------------------------------------------
    print("\n----------------------------------------")
    if not failures:
        print("ANOMALY DATASET INSPECTION: PASS")
    else:
        print("ANOMALY DATASET INSPECTION: FAIL")
        print("Failed checks:")
        for f in failures:
            print(f" - {f}")

if __name__ == "__main__":
    main()
