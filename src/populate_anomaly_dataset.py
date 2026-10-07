import sqlite3
import pandas as pd
from pathlib import Path

def get_counts(cursor):
    """Helper to safely fetch counts of baseline tables."""
    tables = ["nodes", "traffic_observations", "feature_windows", "anomaly_predictions", "datasets", "prediction_runs"]
    counts = {}
    for table in tables:
        try:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            counts[table] = cursor.fetchone()[0]
        except sqlite3.OperationalError:
            counts[table] = -1
    return counts

def print_counts(counts):
    """Helper to print table counts clearly."""
    for table, count in counts.items():
        print(f"  {table} = {count}")

def main():
    print("--- Stage 20B: Anomaly Dataset Integration ---")
    
    # Setup paths
    current_dir = Path(__file__).parent
    project_root = current_dir.parent
    data_dir = project_root / "data"
    
    db_path = data_dir / "iot_anomaly.db"
    csv_path = data_dir / "processed" / "anomaly_5node_features.csv"
    
    # ---------------------------------------------------------
    # STEP 1 — SAFETY CHECKS
    # ---------------------------------------------------------
    if not db_path.exists():
        print(f"Error: Database not found at {db_path}")
        print("\nANOMALY DATASET INSERTION: FAIL")
        return
        
    if not csv_path.exists():
        print(f"Error: CSV file not found at {csv_path}")
        print("\nANOMALY DATASET INSERTION: FAIL")
        return
        
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("PRAGMA foreign_keys = ON;")
    
    expected_original_counts = {
        "nodes": 5,
        "traffic_observations": 9073,
        "feature_windows": 905,
        "anomaly_predictions": 183,
        "datasets": 1,
        "prediction_runs": 1
    }
    
    orig_counts = get_counts(cursor)
    
    # If counts do not match exactly, abort safely before any transaction begins
    if orig_counts != expected_original_counts:
        print("\nError: The original database counts do not match the expected verified state.")
        print("Actual counts:")
        print_counts(orig_counts)
        print("Expected counts:")
        print_counts(expected_original_counts)
        print("\nANOMALY DATASET INSERTION: FAIL")
        conn.close()
        return
        
    print("\nOriginal counts:")
    print_counts(orig_counts)
    
    # Verify the existing normal dataset is intact
    cursor.execute('''
        SELECT * FROM datasets 
        WHERE dataset_id = 1 AND dataset_name = 'Normal Simulated Traffic' AND dataset_type = 'normal'
    ''')
    if cursor.fetchone() is None:
        print("\nError: The existing normal dataset (id=1) was not found or is misconfigured.")
        print("\nANOMALY DATASET INSERTION: FAIL")
        conn.close()
        return
        
    # ---------------------------------------------------------
    # STEP 6 — IDEMPOTENCY / SAFETY
    # ---------------------------------------------------------
    cursor.execute('''
        SELECT dataset_id FROM datasets 
        WHERE dataset_name = 'Controlled Synthetic Anomalous Behaviour' 
        AND dataset_type = 'controlled_anomaly'
    ''')
    existing_ds = cursor.fetchone()
    
    if existing_ds:
        dataset_id = existing_ds[0]
        print(f"\nAnomaly dataset already exists with dataset_id {dataset_id}. Checking integrity...")
        cursor.execute("SELECT COUNT(*) FROM feature_windows WHERE dataset_id = ?", (dataset_id,))
        ds_count = cursor.fetchone()[0]
        if ds_count == 904:
            print("Dataset is already properly integrated with exactly 904 feature windows.")
            print("\nANOMALY DATASET INSERTION: PASS")
        else:
            print(f"Dataset exists but has {ds_count} rows instead of expected 904.")
            print("\nANOMALY DATASET INSERTION: FAIL")
        conn.close()
        return
        
    df_anomaly = pd.read_csv(csv_path)
    
    failures = []
    def report_check(name, passed, detail=""):
        if not passed:
            failures.append(f"{name}: {detail}")
            
    # ---------------------------------------------------------
    # TRANSACTION
    # ---------------------------------------------------------
    try:
        cursor.execute("BEGIN TRANSACTION;")
        
        # Verify Node_IDs exist in nodes table before inserting
        cursor.execute("SELECT node_id FROM nodes")
        db_nodes = {row[0] for row in cursor.fetchall()}
        csv_nodes = set(df_anomaly["Node_ID"])
        unknown_nodes = csv_nodes - db_nodes
        
        if unknown_nodes:
            raise Exception(f"Unknown Node_ID(s) found in CSV: {unknown_nodes}")
        
        # STEP 2 — CREATE ANOMALY DATASET
        cursor.execute('''
            INSERT INTO datasets (dataset_name, dataset_type)
            VALUES ("Controlled Synthetic Anomalous Behaviour", "controlled_anomaly")
        ''')
        dataset_id = cursor.lastrowid
        
        print(f"\nAnomaly dataset created with dataset_id: {dataset_id}")
        
        # STEP 3 — INSERT ANOMALY FEATURE WINDOWS
        # Add the new dataset_id to the CSV data
        feature_data = df_anomaly[[
            "Node_ID", "Window_ID", "mean_IAT", "IAT_std", 
            "packet_rate", "mean_packet_size", "packet_size_std"
        ]].copy()
        feature_data.insert(0, "dataset_id", dataset_id)
        
        insert_values = feature_data.values.tolist()
        
        cursor.executemany('''
            INSERT INTO feature_windows (
                dataset_id, node_id, window_id, mean_iat, iat_std, packet_rate, mean_packet_size, packet_size_std
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', insert_values)
        
        features_inserted = cursor.rowcount
        print(f"Anomaly feature windows inserted: {features_inserted}")
        
        # ---------------------------------------------------------
        # STEP 5 — POST-INSERT VERIFICATION (Before Commit)
        # ---------------------------------------------------------
        final_counts = get_counts(cursor)
        
        print("\nFinal counts:")
        print_counts(final_counts)
        
        report_check("datasets count = 2", final_counts["datasets"] == 2, f"Found {final_counts['datasets']}")
        report_check("feature_windows count = 1809", final_counts["feature_windows"] == 1809, f"Found {final_counts['feature_windows']}")
        report_check("traffic_observations count = 9073", final_counts["traffic_observations"] == 9073, f"Found {final_counts['traffic_observations']}")
        report_check("anomaly_predictions count = 183", final_counts["anomaly_predictions"] == 183, f"Found {final_counts['anomaly_predictions']}")
        report_check("prediction_runs count = 1", final_counts["prediction_runs"] == 1, f"Found {final_counts['prediction_runs']}")
        report_check("nodes count = 5", final_counts["nodes"] == 5, f"Found {final_counts['nodes']}")
        
        cursor.execute("SELECT COUNT(*) FROM feature_windows WHERE dataset_id = ?", (dataset_id,))
        anom_count = cursor.fetchone()[0]
        report_check("anomaly dataset contains exactly 904 feature windows", anom_count == 904, f"Found {anom_count}")
        
        cursor.execute("SELECT COUNT(*) FROM feature_windows WHERE dataset_id = 1")
        norm_count = cursor.fetchone()[0]
        report_check("normal dataset still contains exactly 905 feature windows", norm_count == 905, f"Found {norm_count}")
        
        cursor.execute('''
            SELECT dataset_id, node_id, window_id, COUNT(*) 
            FROM feature_windows 
            GROUP BY dataset_id, node_id, window_id 
            HAVING COUNT(*) > 1
        ''')
        fw_dups = cursor.fetchall()
        report_check("No duplicate (dataset_id, node_id, window_id)", len(fw_dups) == 0, f"Duplicates found: {fw_dups}")
        
        # Null check for new anomaly rows
        cursor.execute('''
            SELECT COUNT(*) FROM feature_windows 
            WHERE dataset_id = ? AND (
                mean_iat IS NULL OR iat_std IS NULL OR 
                packet_rate IS NULL OR mean_packet_size IS NULL OR 
                packet_size_std IS NULL
            )
        ''', (dataset_id,))
        null_count = cursor.fetchone()[0]
        report_check("No NULL ML feature values for anomaly rows", null_count == 0, f"Found {null_count} NULL rows")
        
        # Foreign key integrity check
        cursor.execute("PRAGMA foreign_key_check;")
        fk_violations = cursor.fetchall()
        report_check("PRAGMA foreign_key_check returns zero violations", len(fk_violations) == 0, f"Violations: {fk_violations}")
        
        if failures:
            raise Exception("Post-insertion verification checks failed.")
            
        # STEP 4 — TRANSACTION SAFETY (Commit only if all passed)
        conn.commit()
        print("\nIntegrity checks:\nPASS")
        print("\nANOMALY DATASET INSERTION: PASS")
        
    except Exception as e:
        conn.rollback()
        print(f"\nIntegrity checks:\nFAIL")
        for f in failures:
            print(f" -> {f}")
        if not failures:
            print(f" -> Error: {e}")
        print(f"\nANOMALY DATASET INSERTION: FAIL")
        
    finally:
        conn.close()

if __name__ == "__main__":
    main()
