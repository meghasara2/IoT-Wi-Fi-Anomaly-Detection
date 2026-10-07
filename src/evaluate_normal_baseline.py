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
    output_path = processed_dir / "normal_test_predictions.csv"
    
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
    
    # 3. Do NOT use Node_ID, Node_Type, or Window_ID as ML features
    metadata_cols = ["Node_ID", "Node_Type", "Window_ID"]
    
    all_test_predictions = []
    
    overall_train_count = 0
    overall_test_count = 0
    overall_test_normal = 0
    overall_test_anomaly = 0
    
    print("--- Train/Test Baseline Evaluation ---\n")
    
    # 4. Process each Node_ID separately
    for node_id in df["Node_ID"].unique():
        df_node = df[df["Node_ID"] == node_id].copy()
        
        # 5. Split into 80% training and 20% testing
        # Why we split: We want to evaluate the model's ability to generalize to new, 
        # unseen traffic behavior, rather than just memorizing the training data.
        df_train, df_test = train_test_split(
            df_node, 
            test_size=0.2, 
            random_state=42, 
            shuffle=True
        )
        
        X_train = df_train[feature_cols]
        X_test = df_test[feature_cols]
        
        # 6. Train a separate Isolation Forest using ONLY the 80% training data
        # Why only the training portion is used to fit: The test set must remain 
        # strictly hidden during the learning phase. If the model sees the test data 
        # while fitting, it constitutes "data leakage", which artificially inflates performance.
        clf = IsolationForest(random_state=42)
        clf.fit(X_train)
        
        # 8. Predict ONLY on the unseen 20% test data
        preds = clf.predict(X_test)
        scores = clf.decision_function(X_test)
        
        # Copy to avoid SettingWithCopyWarning
        df_test = df_test.copy()
        df_test["prediction"] = preds
        df_test["anomaly_score"] = scores
        
        # 9. Calculate metrics
        train_count = len(df_train)
        test_count = len(df_test)
        
        # Why an anomaly prediction on this test set is a false positive:
        # We know with 100% certainty that this entire dataset only contains 
        # normal, benign software-simulated traffic. There are no actual anomalies injected yet.
        # Therefore, if the Isolation Forest flags any of these test windows as 
        # an anomaly (prediction = -1), it is a False Positive.
        test_normal = len(df_test[df_test["prediction"] == 1])
        test_anomaly = len(df_test[df_test["prediction"] == -1])
        
        # 10. Define false_positive_rate
        fpr = test_anomaly / test_count if test_count > 0 else 0.0
        
        overall_train_count += train_count
        overall_test_count += test_count
        overall_test_normal += test_normal
        overall_test_anomaly += test_anomaly
        
        # 11. Print clear summary for each node
        print(f"Node: {node_id}")
        print(f"  Training Windows: {train_count}")
        print(f"  Test Windows: {test_count}")
        print(f"  Test Predicted Normal: {test_normal}")
        print(f"  Test Predicted Anomaly (False Positives): {test_anomaly}")
        print(f"  False Positive Rate: {fpr:.2%}\n")
        
        all_test_predictions.append(df_test)
        
    # 13. Save detailed test predictions
    df_final = pd.concat(all_test_predictions, ignore_index=True)
    
    # 14. Include exact columns in output
    output_cols = ["prediction", "anomaly_score"]
    final_cols = metadata_cols + feature_cols + output_cols
    df_final = df_final[final_cols]
    
    df_final.to_csv(output_path, index=False)
    
    # 12. Calculate overall FPR properly across the global test pool
    overall_fpr = overall_test_anomaly / overall_test_count if overall_test_count > 0 else 0.0
    
    # 11. Print overall summary
    print("--- Overall Summary ---")
    print(f"Total Training Windows: {overall_train_count}")
    print(f"Total Test Windows: {overall_test_count}")
    print(f"Total Test Predicted Normal: {overall_test_normal}")
    print(f"Total Test Predicted Anomaly (False Positives): {overall_test_anomaly}")
    print(f"Overall False Positive Rate: {overall_fpr:.2%}")
    
    print(f"\nSaved test predictions to: {output_path}")

if __name__ == "__main__":
    main()
