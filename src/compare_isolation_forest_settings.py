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
    input_path = processed_dir / "normal_5node_features.csv"
    output_path = processed_dir / "isolation_forest_parameter_comparison.csv"
    
    if not input_path.exists():
        print(f"Error: Could not find input file at {input_path}")
        return
        
    # 1. Load the normal features CSV
    df = pd.read_csv(input_path)
    
    # 2. Use exactly these five ML features
    feature_cols = [
        "mean_IAT", 
        "IAT_std", 
        "packet_rate", 
        "mean_packet_size", 
        "packet_size_std"
    ]
    
    # 4. Define the Isolation Forest configurations to compare objectively
    configurations = {
        "Default": IsolationForest(random_state=42),
        'contamination="auto"': IsolationForest(contamination="auto", random_state=42),
        "contamination=0.05": IsolationForest(contamination=0.05, random_state=42),
        "contamination=0.10": IsolationForest(contamination=0.10, random_state=42)
    }
    
    results = []
    
    # Track aggregate statistics to calculate true overall FPR
    config_totals = {name: {"test_windows": 0, "false_positives": 0} for name in configurations.keys()}
    
    # 13. IMPORTANT PARAMETER-SENSITIVITY EXPERIMENT COMMENT
    # This script objectively evaluates how the 'contamination' parameter affects 
    # the false-positive rate on purely normal baseline traffic. 
    # However, the final production setting MUST be selected based on BOTH 
    # the false-positive rate AND the true anomaly detection performance (on anomalous data). 
    # Simply picking the configuration with the lowest FPR might result in a 
    # blind model that misses actual anomalies/attacks (unacceptably low detection rate).
    
    for config_name, clf_template in configurations.items():
        # 2. Process each Node_ID separately
        for node_id in df["Node_ID"].unique():
            df_node = df[df["Node_ID"] == node_id]
            
            # 3. Split normal data into 80% training and 20% testing
            df_train, df_test = train_test_split(
                df_node,
                test_size=0.2,
                random_state=42,
                shuffle=True
            )
            
            X_train = df_train[feature_cols]
            X_test = df_test[feature_cols]
            
            # Create a fresh, untrained model instance for this specific node
            clf = clone(clf_template)
            
            # 5. Train ONLY on the 80% normal training data
            clf.fit(X_train)
            
            # Predict ONLY on the unseen 20% normal test data
            preds = clf.predict(X_test)
            
            train_count = len(df_train)
            test_count = len(df_test)
            
            # Prediction of -1 on normal traffic is a False Positive
            false_positives = sum(preds == -1)
            fpr = false_positives / test_count if test_count > 0 else 0
            
            results.append({
                "Configuration": config_name,
                "Node_ID": node_id,
                "Training_Windows": train_count,
                "Test_Windows": test_count,
                "False_Positives": false_positives,
                "False_Positive_Rate": fpr
            })
            
            # Accumulate global totals for this configuration
            config_totals[config_name]["test_windows"] += test_count
            config_totals[config_name]["false_positives"] += false_positives
            
    df_results = pd.DataFrame(results)
    
    # 8. Print comparison table
    print("--- Isolation Forest Parameter Sensitivity ---\n")
    print(df_results.to_string(index=False))
    
    # 9. Print overall result for each configuration
    print("\n--- Overall False Positive Rate by Configuration ---")
    for config_name, totals in config_totals.items():
        total_test = totals["test_windows"]
        total_fp = totals["false_positives"]
        
        # Calculate properly using aggregate division
        overall_fpr = total_fp / total_test if total_test > 0 else 0
        
        print(f"{config_name}:")
        print(f"  Total Test Windows: {total_test}")
        print(f"  Total False Positives: {total_fp}")
        print(f"  Overall FPR: {overall_fpr:.2%}\n")
        
    # 10. Save the complete comparison
    df_results.to_csv(output_path, index=False)
    print(f"Saved parameter comparison to: {output_path}")

if __name__ == "__main__":
    main()
