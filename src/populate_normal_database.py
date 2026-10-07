import sqlite3
import pandas as pd
from pathlib import Path

def main():
    # Setup paths
    current_dir = Path(__file__).parent
    project_root = current_dir.parent
    data_dir = project_root / "data"
    
    db_path = data_dir / "iot_anomaly.db"
    
    traffic_csv = data_dir / "processed" / "normal_5node_traffic.csv"
    features_csv = data_dir / "processed" / "normal_5node_features.csv"
    predictions_csv = data_dir / "processed" / "final_normal_baseline_predictions.csv"
    
    # Ensure database exists
    if not db_path.exists():
        print(f"Error: Database not found at {db_path}. Please run Stage 16 first.")
        return
        
    # Ensure input files exist
    for path in [traffic_csv, features_csv, predictions_csv]:
        if not path.exists():
            print(f"Error: CSV file not found at {path}")
            return
            
    # 1. Load data using pandas
    df_traffic = pd.read_csv(traffic_csv)
    df_features = pd.read_csv(features_csv)
    df_predictions = pd.read_csv(predictions_csv)
    
    # 6. Set actual_class = "normal" for the baseline predictions
    df_predictions["actual_class"] = "normal"
    
    # 1. Connect to sqlite3
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Enable foreign key enforcement for data integrity
    cursor.execute("PRAGMA foreign_keys = ON;")
    
    # 7. Verify that every Node_ID exists in the nodes table BEFORE inserting
    cursor.execute("SELECT node_id FROM nodes")
    existing_nodes = {row[0] for row in cursor.fetchall()}
    
    all_csv_nodes = set(df_traffic["Node_ID"]).union(df_features["Node_ID"], df_predictions["Node_ID"])
    missing_nodes = all_csv_nodes - existing_nodes
    
    if missing_nodes:
        print(f"Error: The following Node_IDs are missing from the SQLite 'nodes' table: {missing_nodes}")
        conn.close()
        return
        
    # 12. IMPORTANT ARCHITECTURE COMMENT
    # Why the database stores raw observations, feature windows, and model predictions separately:
    # 1. Data Integrity: Raw IoT observations (timestamp, size) are high-frequency event streams.
    #    Feature windows are aggregated statistical summaries. They exist at entirely different granularities.
    # 2. Reusability: By storing raw traffic independently, we can easily change our window size 
    #    (e.g., from 10 to 50 packets) or feature calculations later without destroying the original synthetic baseline data.
    # 3. Model Independence: Predictions are mapped separately to allow us to test multiple 
    #    anomaly detection algorithms on the exact same feature windows in the future, 
    #    without cluttering the feature table itself.
    
    # 4. Insert normal raw traffic observations (SAFELY checking idempotency)
    cursor.execute("SELECT COUNT(*) FROM traffic_observations")
    current_traffic_count = cursor.fetchone()[0]
    
    expected_normal_traffic_count = 9073
    traffic_inserted = 0
    traffic_skipped = False
    
    if current_traffic_count >= expected_normal_traffic_count:
        # If the expected number of normal rows (or more) already exists, skip to avoid duplicates.
        traffic_skipped = True
    else:
        traffic_data = df_traffic[["Node_ID", "Timestamp", "Packet_Size"]].values.tolist()
        cursor.executemany('''
            INSERT INTO traffic_observations (node_id, timestamp, packet_size)
            VALUES (?, ?, ?)
        ''', traffic_data)
        traffic_inserted = cursor.rowcount
    
    # 5. Insert normal feature windows
    feature_data = df_features[[
        "Node_ID", "Window_ID", "mean_IAT", "IAT_std", 
        "packet_rate", "mean_packet_size", "packet_size_std"
    ]].values.tolist()
    
    # 8. Use INSERT OR IGNORE to respect the UNIQUE(node_id, window_id) constraint
    cursor.executemany('''
        INSERT OR IGNORE INTO feature_windows (
            node_id, window_id, mean_iat, iat_std, packet_rate, mean_packet_size, packet_size_std
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', feature_data)
    features_inserted = cursor.rowcount
    
    # 6. Insert final normal baseline predictions
    pred_data = df_predictions[[
        "Node_ID", "Window_ID", "prediction", "anomaly_score", "actual_class"
    ]].values.tolist()
    
    # 8. Use INSERT OR IGNORE to respect the UNIQUE(node_id, window_id) constraint
    cursor.executemany('''
        INSERT OR IGNORE INTO anomaly_predictions (
            node_id, window_id, prediction, anomaly_score, actual_class
        ) VALUES (?, ?, ?, ?, ?)
    ''', pred_data)
    predictions_inserted = cursor.rowcount
    
    # 9. Commit all changes
    conn.commit()
    
    # 10. Query total rows currently present in each table
    cursor.execute("SELECT COUNT(*) FROM traffic_observations")
    total_traffic = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM feature_windows")
    total_features = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM anomaly_predictions")
    total_predictions = cursor.fetchone()[0]
    
    conn.close()
    
    # 10 & 11. Print output
    print("--- SQLite Database Population: Normal Baseline ---")
    
    if traffic_skipped:
        print(f"Traffic observations skipped (Normal baseline already present).")
    else:
        print(f"Traffic observations inserted: {traffic_inserted}")
        
    print(f"Feature windows inserted: {features_inserted}")
    print(f"Anomaly predictions inserted: {predictions_inserted}")
    
    print("\n--- Current Database Totals ---")
    print(f"traffic_observations total rows: {total_traffic}")
    print(f"feature_windows total rows: {total_features}")
    print(f"anomaly_predictions total rows: {total_predictions}")
    print("\nSuccessfully populated the database with normal baseline data!")

if __name__ == "__main__":
    main()
