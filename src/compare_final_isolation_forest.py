import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest
from sklearn.base import clone

def main():
    # Setup paths
    current_dir = Path(__file__).parent
    project_root = current_dir.parent
    processed_dir = project_root / "data" / "processed"
    
    normal_input = processed_dir / "normal_5node_features.csv"
    anomaly_input = processed_dir / "anomaly_5node_features.csv"
    output_path = processed_dir / "final_isolation_forest_comparison.csv"
    
    if not normal_input.exists() or not anomaly_input.exists():
        print("Error: Missing input datasets.")
        return
        
    # 1. Load both CSV files using pandas
    df_normal = pd.read_csv(normal_input)
    df_anomaly = pd.read_csv(anomaly_input)
    
    # 2. Use exactly these ML feature columns
    feature_cols = [
        "mean_IAT", 
        "IAT_std", 
        "packet_rate", 
        "mean_packet_size", 
        "packet_size_std"
    ]
    
    # 3. Node_ID, Node_Type, and Window_ID are excluded as ML features.
    
    # Compare exactly these three configurations
    # (Excluding contamination="auto" since it mirrors the Default)
    configurations = {
        "Default": IsolationForest(random_state=42),
        "contamination=0.05": IsolationForest(contamination=0.05, random_state=42),
        "contamination=0.10": IsolationForest(contamination=0.10, random_state=42)
    }
    
    results = []
    
    # Track aggregate statistics to calculate true overall rates
    config_totals = {name: {
        "normal_test_windows": 0,
        "false_positives": 0,
        "anomaly_windows": 0,
        "anomalies_detected": 0
    } for name in configurations.keys()}
    
    # --- IMPORTANT EXPERIMENTAL COMMENTS (Req #9) ---
    # 1. Why both FPR and Detection Rate are required:
    #    A model that classifies everything as "normal" will achieve a perfect 0% FPR 
    #    but will blindly miss every single attack (0% Detection Rate). Conversely, a 
    #    hyper-sensitive model might detect 100% of attacks but generate 100% false alarms.
    #    We must evaluate BOTH simultaneously to find the correct operational balance.
    #
    # 2. Why the lowest FPR alone is not sufficient:
    #    Simply forcing the 'contamination' parameter lower (e.g. to 0.05) will mathematically 
    #    force fewer false positives, but it could severely cripple the model's ability 
    #    to detect actual anomalies. This experiment proves whether the trade-off is worth it.
    #
    # 3. Why anomalous data is used ONLY for evaluation:
    #    Isolation Forest is an unsupervised algorithm designed to learn a baseline 
    #    of normality. If we injected anomaly data during training, the model would 
    #    learn those attacks as part of the "normal" baseline, breaking its logic.
    #
    # 4. Nature of the data:
    #    This experiment strictly uses controlled synthetic anomalous behaviour generated 
    #    in software. These are NOT real Wi-Fi packet captures or confirmed cyberattacks.
    
    for config_name, clf_template in configurations.items():
        # 4. Process each Node_ID separately
        for node_id in df_normal["Node_ID"].unique():
            df_node_normal = df_normal[df_normal["Node_ID"] == node_id].copy()
            df_node_anomaly = df_anomaly[df_anomaly["Node_ID"] == node_id].copy()
            
            # Split ONLY the normal feature data into 80% training / 20% testing
            df_train_normal, df_test_normal = train_test_split(
                df_node_normal,
                test_size=0.2,
                random_state=42,
                shuffle=True
            )
            
            X_train_normal = df_train_normal[feature_cols]
            X_test_normal = df_test_normal[feature_cols]
            X_test_anomaly = df_node_anomaly[feature_cols]
            
            # Create a fresh, untrained model instance
            clf = clone(clf_template)
            
            # Train the Isolation Forest ONLY on the 80% normal training data
            clf.fit(X_train_normal)
            
            # Evaluate on the unseen 20% normal test data
            normal_preds = clf.predict(X_test_normal)
            normal_test_windows = len(normal_preds)
            false_positives = sum(normal_preds == -1)
            fpr = false_positives / normal_test_windows if normal_test_windows > 0 else 0
            
            # Evaluate on the controlled anomalous feature data
            anomaly_preds = clf.predict(X_test_anomaly)
            anomaly_windows = len(anomaly_preds)
            anomalies_detected = sum(anomaly_preds == -1)
            dr = anomalies_detected / anomaly_windows if anomaly_windows > 0 else 0
            
            # Store granular node-level results
            results.append({
                "Configuration": config_name,
                "Node_ID": node_id,
                "Normal_Test_Windows": normal_test_windows,
                "False_Positives": false_positives,
                "False_Positive_Rate": fpr,
                "Anomalous_Windows": anomaly_windows,
                "Anomalies_Detected": anomalies_detected,
                "Detection_Rate": dr
            })
            
            # Accumulate global totals for this configuration
            config_totals[config_name]["normal_test_windows"] += normal_test_windows
            config_totals[config_name]["false_positives"] += false_positives
            config_totals[config_name]["anomaly_windows"] += anomaly_windows
            config_totals[config_name]["anomalies_detected"] += anomalies_detected
            
    # 8. Save the complete node-level comparison to CSV
    df_results = pd.DataFrame(results)
    df_results.to_csv(output_path, index=False)
    
    # Print a clear comparison table summarizing overall global metrics
    print("--- Overall Isolation Forest Configuration Comparison ---\n")
    
    overall_summary = []
    for config_name, totals in config_totals.items():
        n_test = totals["normal_test_windows"]
        n_fp = totals["false_positives"]
        a_test = totals["anomaly_windows"]
        a_det = totals["anomalies_detected"]
        
        # Calculate using true aggregate counts across all nodes
        overall_fpr = n_fp / n_test if n_test > 0 else 0
        overall_dr = a_det / a_test if a_test > 0 else 0
        
        overall_summary.append({
            "Configuration": config_name,
            "Total Normal Test Windows": n_test,
            "Total False Positives": n_fp,
            "Overall False Positive Rate": f"{overall_fpr:.2%}",
            "Total Anomalous Windows": a_test,
            "Total Anomalies Detected": a_det,
            "Overall Detection Rate": f"{overall_dr:.2%}"
        })
        
    df_overall = pd.DataFrame(overall_summary)
    
    # Using to_string(index=False) generates a clean tabular layout in terminal
    print(df_overall.to_string(index=False))
    
    print(f"\nDetailed node-level comparison saved to: {output_path}")

if __name__ == "__main__":
    main()
