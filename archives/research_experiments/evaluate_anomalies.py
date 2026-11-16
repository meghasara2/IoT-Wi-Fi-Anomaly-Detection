import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest

def main():
    # Setup paths
    current_dir = Path(__file__).parent
    project_root = current_dir.parent
    processed_dir = project_root / "data" / "processed"
    
    normal_input = processed_dir / "normal_5node_features.csv"
    anomaly_input = processed_dir / "anomaly_5node_features.csv"
    output_path = processed_dir / "anomaly_predictions.csv"
    
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
    
    # 3. Node_ID, Node_Type, and Window_ID are explicitly excluded from ML features.
    
    all_anomaly_predictions = []
    
    # Global aggregates for overall summary
    total_normal_test = 0
    total_false_positives = 0
    total_anomaly_test = 0
    total_anomalies_detected = 0
    
    # 14. Terminology clearly reflecting software-simulated behaviour, not real attacks
    print("--- Evaluating Models on Controlled Anomalous Behaviour ---\n")
    
    # 4. Process each Node_ID separately
    for node_id in df_normal["Node_ID"].unique():
        # 5a. Take ONLY the normal feature windows for this node
        df_node_normal = df_normal[df_normal["Node_ID"] == node_id].copy()
        
        # Take the corresponding synthetic anomalous feature windows for this node
        df_node_anomaly = df_anomaly[df_anomaly["Node_ID"] == node_id].copy()
        
        # 5b. Split the normal windows into 80% training and 20% testing
        df_train_normal, df_test_normal = train_test_split(
            df_node_normal, 
            test_size=0.2, 
            random_state=42, 
            shuffle=True
        )
        
        X_train_normal = df_train_normal[feature_cols]
        X_test_normal = df_test_normal[feature_cols]
        X_test_anomaly = df_node_anomaly[feature_cols]
        
        # 15. Explaining Model Training vs Evaluation:
        # We explicitly train the model ONLY on the 80% normal traffic baseline.
        # Anomalous data is NEVER passed to the .fit() function; it is used ONLY for evaluation.
        # This prevents the controlled anomalous data from polluting or influencing 
        # the model's learned concept of what normal behaviour looks like.
        
        # 5c. Train a separate Isolation Forest using ONLY the 80% normal training data
        clf = IsolationForest(random_state=42)
        clf.fit(X_train_normal)
        
        # 5f. Predict on the unseen normal 20% test data
        normal_preds = clf.predict(X_test_normal)
        
        # 6. Calculate normal test metrics
        normal_test_count = len(normal_preds)
        # Any -1 prediction on purely normal traffic is a False Alarm (False Positive)
        normal_false_positives = sum(normal_preds == -1)
        
        # 5f. Predict on the anomalous feature windows for that same node
        anomaly_preds = clf.predict(X_test_anomaly)
        anomaly_scores = clf.decision_function(X_test_anomaly)
        
        # 7. Calculate anomaly test metrics
        anomaly_test_count = len(anomaly_preds)
        # Any -1 prediction on anomalous traffic is a successful detection
        anomalies_detected = sum(anomaly_preds == -1)
        
        # 15. Explaining Evaluation Metrics:
        # False Positive Rate measures how much NORMAL traffic was incorrectly flagged as an anomaly.
        # Detection Rate measures how many controlled ANOMALOUS windows were correctly flagged.
        fpr = normal_false_positives / normal_test_count if normal_test_count > 0 else 0
        dr = anomalies_detected / anomaly_test_count if anomaly_test_count > 0 else 0
        
        # Aggregate global metrics across all nodes
        total_normal_test += normal_test_count
        total_false_positives += normal_false_positives
        total_anomaly_test += anomaly_test_count
        total_anomalies_detected += anomalies_detected
        
        # 10. Print a clear summary for every node
        print(f"Node: {node_id}")
        print(f"  Normal Test Windows: {normal_test_count}")
        print(f"  Normal False Positives: {normal_false_positives}")
        print(f"  False Positive Rate: {fpr:.2%}")
        print(f"  Anomalous Windows: {anomaly_test_count}")
        print(f"  Anomalies Detected: {anomalies_detected}")
        print(f"  Detection Rate: {dr:.2%}\n")
        
        # Format the anomalous dataframe for exporting
        df_node_anomaly = df_node_anomaly.copy()
        df_node_anomaly["prediction"] = anomaly_preds
        df_node_anomaly["anomaly_score"] = anomaly_scores
        
        # 13. Label actual class as anomaly because this dataset was deliberately generated 
        df_node_anomaly["actual_class"] = "anomaly"
        all_anomaly_predictions.append(df_node_anomaly)
        
    # 9. Calculate overall rates using aggregate counts, NOT simple averages of percentages
    overall_fpr = total_false_positives / total_normal_test if total_normal_test > 0 else 0
    overall_dr = total_anomalies_detected / total_anomaly_test if total_anomaly_test > 0 else 0
    
    # 11. Print an overall summary
    print("--- Overall Summary ---")
    print(f"Total Normal Test Windows: {total_normal_test}")
    print(f"Total Normal False Positives: {total_false_positives}")
    print(f"Overall False Positive Rate: {overall_fpr:.2%}")
    print(f"Total Anomalous Windows: {total_anomaly_test}")
    print(f"Total Anomalies Detected: {total_anomalies_detected}")
    print(f"Overall Detection Rate: {overall_dr:.2%}")
    
    # 12. Save all anomalous predictions
    df_final_anomaly = pd.concat(all_anomaly_predictions, ignore_index=True)
    
    output_cols = [
        "Node_ID", "Node_Type", "Window_ID", 
        "mean_IAT", "IAT_std", "packet_rate", "mean_packet_size", "packet_size_std",
        "prediction", "anomaly_score", "actual_class"
    ]
    
    df_final_anomaly = df_final_anomaly[output_cols]
    df_final_anomaly.to_csv(output_path, index=False)
    
    print(f"\nSaved detailed anomaly predictions to: {output_path}")

if __name__ == "__main__":
    main()
