import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest

def main():
    # Load the processed dataset
    current_dir = Path(__file__).parent
    project_root = current_dir.parent
    features_path = project_root / "data" / "processed" / "traffic_features.csv"
    
    if not features_path.exists():
        print(f"Error: Could not find {features_path}")
        return
        
    df = pd.read_csv(features_path)
    
    # Define the exact feature columns to use
    feature_cols = [
        "mean_IAT", 
        "IAT_std", 
        "packet_rate", 
        "mean_packet_size", 
        "packet_size_std"
    ]
    
    # Filter the training data
    # We train ONLY on normal traffic because Isolation Forest is an unsupervised 
    # anomaly detection algorithm. By showing it only "normal" behavior during training, 
    # it learns the boundaries of normality. Anything outside these boundaries 
    # during testing will be flagged as an anomaly.
    df_train = df[df["Dataset"] == "Normal Traffic"].copy()
    X_train = df_train[feature_cols]
    
    print(f"Number of normal training rows: {len(X_train)}")
    
    # Train the Isolation Forest
    # We use a fixed random_state to ensure the results are exactly the same 
    # every time the script is run.
    clf = IsolationForest(random_state=42)
    clf.fit(X_train)
    
    # Test the detector on ALL rows (both normal and anomalous)
    X_test = df[feature_cols]
    print(f"Number of test rows: {len(X_test)}")
    
    # Add predictions and scores
    # Prediction output format for Isolation Forest:
    #  1 means the data point is considered an inlier (Normal)
    # -1 means the data point is considered an outlier (Anomaly)
    df["prediction"] = clf.predict(X_test)
    df["anomaly_score"] = clf.decision_function(X_test)
    
    # Print results
    print("\n--- Predictions for every test row ---")
    print(df[["Dataset", "prediction", "anomaly_score"]].to_string())
    
    num_normal = len(df[df["prediction"] == 1])
    num_anomaly = len(df[df["prediction"] == -1])
    
    print(f"\nNumber of rows predicted as normal (1): {num_normal}")
    print(f"Number of rows predicted as anomaly (-1): {num_anomaly}")

if __name__ == "__main__":
    main()
