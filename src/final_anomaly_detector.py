import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest

def main():
    # Setup paths
    current_dir = Path(__file__).parent
    project_root = current_dir.parent
    processed_dir = project_root / "data" / "processed"
    input_path = processed_dir / "normal_5node_features.csv"
    output_path = processed_dir / "final_normal_baseline_predictions.csv"
    
    if not input_path.exists():
        print(f"Error: Could not find input file at {input_path}")
        return
        
    # 1. Load the normal features CSV
    df = pd.read_csv(input_path)
    
    # 3. Use exactly these five ML features
    feature_cols = [
        "mean_IAT", 
        "IAT_std", 
        "packet_rate", 
        "mean_packet_size", 
        "packet_size_std"
    ]
    
    # 4 & 13. Node_ID, Node_Type, and Window_ID are explicitly metadata identifiers, 
    # not behavioural ML features. If we fed strings or sequential IDs into the 
    # model, it would learn to categorize the IDs instead of understanding the 
    # underlying traffic behaviour (IAT, packet_rate, etc.).
    metadata_cols = ["Node_ID", "Node_Type", "Window_ID"]
    
    all_test_predictions = []
    
    overall_train_count = 0
    overall_test_count = 0
    overall_false_positives = 0
    
    print("--- Final Node-Specific Isolation Forest Detector ---\n")
    
    # 13. This script implements the project's selected detector configuration. 
    # Through empirical parameter sensitivity testing (comparing FPR and Detection Rate), 
    # we determined that contamination=0.05 is the ideal balance. It significantly 
    # reduces the False Positive Rate on normal baseline traffic while still 
    # maintaining a robust Detection Rate for true anomalies.
    
    # 2. Process each Node_ID separately
    for node_id in df["Node_ID"].unique():
        df_node = df[df["Node_ID"] == node_id].copy()
        
        # 5. Split into 80% training and 20% testing
        df_train, df_test = train_test_split(
            df_node,
            test_size=0.2,
            random_state=42,
            shuffle=True
        )
        
        X_train = df_train[feature_cols]
        X_test = df_test[feature_cols]
        
        # 6 & 13. Train a separate Isolation Forest for each node using ONLY 
        # the 80% normal training data. The detector learns ONLY from normal 
        # traffic, establishing a healthy baseline without being influenced 
        # by anomalous data or testing data.
        
        # 7. Selected Configuration
        clf = IsolationForest(
            contamination=0.05,
            random_state=42
        )
        clf.fit(X_train)
        
        # 8. Predict on the unseen 20% normal test data
        preds = clf.predict(X_test)
        scores = clf.decision_function(X_test)
        
        df_test = df_test.copy()
        df_test["prediction"] = preds
        df_test["anomaly_score"] = scores
        
        train_count = len(df_train)
        test_count = len(df_test)
        
        # Prediction of -1 on normal traffic is a False Positive
        predicted_normal = sum(preds == 1)
        predicted_anomaly = sum(preds == -1)
        fpr = predicted_anomaly / test_count if test_count > 0 else 0
        
        overall_train_count += train_count
        overall_test_count += test_count
        overall_false_positives += predicted_anomaly
        
        # 11. Print node-level summary
        print(f"Node: {node_id}")
        print(f"  Training Windows: {train_count}")
        print(f"  Test Windows: {test_count}")
        print(f"  Predicted Normal (1): {predicted_normal}")
        print(f"  Predicted Anomaly (-1) [False Positives]: {predicted_anomaly}")
        print(f"  False Positive Rate: {fpr:.2%}\n")
        
        all_test_predictions.append(df_test)
        
    df_final = pd.concat(all_test_predictions, ignore_index=True)
    
    # 10. Enforce output columns exactly as requested
    output_cols = ["prediction", "anomaly_score"]
    final_cols = metadata_cols + feature_cols + output_cols
    df_final = df_final[final_cols]
    
    # 9. Save predictions
    df_final.to_csv(output_path, index=False)
    
    overall_fpr = overall_false_positives / overall_test_count if overall_test_count > 0 else 0
    
    # 12. Print overall summary
    print("--- Overall Summary ---")
    print(f"Total Training Windows: {overall_train_count}")
    print(f"Total Test Windows: {overall_test_count}")
    print(f"Total False Positives: {overall_false_positives}")
    print(f"Overall False Positive Rate: {overall_fpr:.2%}")
    
    print(f"\nSaved final baseline predictions to: {output_path}")

if __name__ == "__main__":
    main()
