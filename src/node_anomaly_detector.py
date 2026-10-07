import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest

def main():
    # Setup paths
    current_dir = Path(__file__).parent
    project_root = current_dir.parent
    processed_dir = project_root / "data" / "processed"
    input_path = processed_dir / "normal_5node_features.csv"
    output_path = processed_dir / "normal_baseline_predictions.csv"
    
    if not input_path.exists():
        print(f"Error: Could not find input file at {input_path}")
        return
        
    # 1. Load the CSV
    df = pd.read_csv(input_path)
    
    # 2. Define ML feature columns
    feature_cols = [
        "mean_IAT", 
        "IAT_std", 
        "packet_rate", 
        "mean_packet_size", 
        "packet_size_std"
    ]
    
    # 3. Why Node_ID and Node_Type are omitted as features:
    # They are strictly categorical identifiers (metadata) meant to label and separate 
    # our software-simulated traffic. If we passed them directly into the numerical 
    # model, the model would artificially try to split the data based on ID strings 
    # instead of learning purely from the continuous traffic behavior (IAT, packet_rate).
    
    all_predictions = []
    
    overall_total = 0
    overall_normal = 0
    overall_anomaly = 0
    
    print("--- Node-Specific Baseline Isolation Forest Models ---\n")
    
    # 4. We train a SEPARATE model for each node because IoT devices exhibit 
    # vastly different "normal" profiles. For example, our simulated Camera generates 
    # traffic at a high rate (e.g. 0.2s IAT), while the Motion Sensor is mostly silent 
    # (3-6s IAT). If we mixed all features into one generic model, the Camera's normal 
    # traffic might be falsely flagged as a high-rate anomaly just because it's faster 
    # than the rest of the network.
    for node_id in df["Node_ID"].unique():
        # Filter only that node's normal windows
        df_node = df[df["Node_ID"] == node_id].copy()
        
        X_train = df_node[feature_cols]
        
        # Train Isolation Forest using random_state=42 and default settings
        clf = IsolationForest(random_state=42)
        clf.fit(X_train)
        
        # Predict on the SAME normal observations used for training.
        # Why is this only a baseline sanity check? 
        # Because predicting on the training set only shows us how much of our 
        # purely normal baseline data is aggressively flagged as anomalous (false positives).
        # We can't evaluate the true accuracy until we actually simulate true 
        # anomalous traffic for the model to detect!
        preds = clf.predict(X_train)
        scores = clf.decision_function(X_train)
        
        df_node["prediction"] = preds
        df_node["anomaly_score"] = scores
        
        num_windows = len(df_node)
        num_normal = len(df_node[df_node["prediction"] == 1])
        num_anomaly = len(df_node[df_node["prediction"] == -1])
        
        overall_total += num_windows
        overall_normal += num_normal
        overall_anomaly += num_anomaly
        
        # 9. Print Node summary
        print(f"Node: {node_id}")
        print(f"  Training Windows: {num_windows}")
        print(f"  Predicted Normal (1): {num_normal}")
        print(f"  Predicted Anomaly (-1): {num_anomaly}")
        print(f"  Min Anomaly Score: {scores.min():.4f}")
        print(f"  Max Anomaly Score: {scores.max():.4f}\n")
        
        all_predictions.append(df_node)
        
    df_final = pd.concat(all_predictions, ignore_index=True)
    
    # Ensure correct column order: Metadata, ML Features, Output
    metadata_cols = ["Node_ID", "Node_Type", "Window_ID"]
    output_cols = ["prediction", "anomaly_score"]
    
    final_cols = metadata_cols + feature_cols + output_cols
    df_final = df_final[final_cols]
    
    # 8. Save the result
    df_final.to_csv(output_path, index=False)
    
    # 10. Print overall summary
    print("--- Overall Summary ---")
    print(f"Total Windows: {overall_total}")
    print(f"Total Predicted Normal: {overall_normal}")
    print(f"Total Predicted Anomaly: {overall_anomaly}")
    
    print(f"\nSaved baseline predictions to: {output_path}")

if __name__ == "__main__":
    main()
