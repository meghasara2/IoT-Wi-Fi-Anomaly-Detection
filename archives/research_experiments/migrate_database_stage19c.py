import sqlite3
import shutil
from pathlib import Path

def get_counts(cursor):
    """Helper to safely fetch counts of baseline tables."""
    tables = ["nodes", "traffic_observations", "feature_windows", "anomaly_predictions"]
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

def check_unique_constraint(cursor, table, expected_columns):
    """Verifies that a UNIQUE constraint exists on the specified table matching the exact column order."""
    cursor.execute(f"PRAGMA index_list('{table}')")
    indices = cursor.fetchall()
    
    for idx in indices:
        # idx[2] represents whether the index is unique (1 = True, 0 = False)
        if idx[2] == 1:
            idx_name = idx[1]
            cursor.execute(f"PRAGMA index_info('{idx_name}')")
            cols = cursor.fetchall()
            # cols[2] is the column name in the index_info result
            col_names = [c[2] for c in cols]
            if col_names == expected_columns:
                return True
    return False

def check_fk_constraint(cursor, table, expected_fks):
    """
    Verifies that the foreign keys exist on the table.
    expected_fks is a list of tuples: (from_column, target_table, to_column)
    """
    cursor.execute(f"PRAGMA foreign_key_list('{table}')")
    fks = cursor.fetchall()
    
    # PRAGMA foreign_key_list output mapping:
    # fks[2] = target table
    # fks[3] = from column (local)
    # fks[4] = to column (target)
    matched_fks = [(fk[3], fk[2], fk[4]) for fk in fks]
    
    for efk in expected_fks:
        if efk not in matched_fks:
            return False, f"Missing FK {efk}. Found: {matched_fks}"
    return True, ""

def main():
    print("--- Stage 19C Database Migration ---")
    
    # 1. Setup paths
    current_dir = Path(__file__).parent
    project_root = current_dir.parent
    data_dir = project_root / "data"
    
    db_path = data_dir / "iot_anomaly.db"
    backup_path = data_dir / "iot_anomaly_backup_before_stage19c.db"
    
    if not db_path.exists():
        print(f"Error: Database not found at {db_path}")
        print("\nDATABASE MIGRATION: FAIL")
        return
        
    # 2. Refuse to overwrite backup silently
    if backup_path.exists():
        print(f"\nBackup: FAIL")
        print(f"Error: Backup file already exists at {backup_path}.")
        print("Refusing to silently overwrite a previous backup. Please remove it manually if you intend to run this migration again.")
        print("\nDATABASE MIGRATION: FAIL")
        return
        
    # 1. Create physical backup
    try:
        shutil.copy2(db_path, backup_path)
        print("\nBackup:\nPASS")
    except Exception as e:
        print(f"\nBackup:\nFAIL ({e})")
        print("\nDATABASE MIGRATION: FAIL")
        return
        
    # Open Database connection
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Record original counts before migration
    orig_counts = get_counts(cursor)
    print("\nOriginal counts:")
    print_counts(orig_counts)
    
    expected_original_counts = {
        "nodes": 5,
        "traffic_observations": 9073,
        "feature_windows": 905,
        "anomaly_predictions": 183,
    }
    
    # Pre-migration safety check
    if orig_counts != expected_original_counts:
        print("\nError: The original database counts do not match the expected verified state.")
        print("Actual counts:")
        print_counts(orig_counts)
        print("Expected counts:")
        print_counts(expected_original_counts)
        print("\nDATABASE MIGRATION: FAIL")
        conn.close()
        return
    
    failures = []
    def report_check(name, passed, detail=""):
        if not passed:
            failures.append(f"{name}: {detail}")
            
    # --- MIGRATION TRANSACTION ---
    try:
        # Disable foreign keys temporarily for safe table replacement
        cursor.execute("PRAGMA foreign_keys = OFF;")
        cursor.execute("BEGIN TRANSACTION;")
        
        # --- DATASETS TABLE ---
        cursor.execute('''
            CREATE TABLE datasets (
                dataset_id INTEGER PRIMARY KEY AUTOINCREMENT,
                dataset_name TEXT NOT NULL,
                dataset_type TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO datasets (dataset_name, dataset_type)
            VALUES ("Normal Simulated Traffic", "normal")
        ''')
        dataset_id = cursor.lastrowid
        
        # --- PREDICTION RUNS TABLE ---
        cursor.execute('''
            CREATE TABLE prediction_runs (
                run_id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_name TEXT NOT NULL,
                dataset_id INTEGER NOT NULL,
                description TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(dataset_id) REFERENCES datasets(dataset_id)
            )
        ''')
        
        cursor.execute('''
            INSERT INTO prediction_runs (run_name, dataset_id, description)
            VALUES (
                "Baseline Isolation Forest", 
                ?, 
                "Initial normal baseline using Isolation Forest contamination=0.05 with 80/20 normal train-test evaluation."
            )
        ''', (dataset_id,))
        run_id = cursor.lastrowid
        
        # --- FEATURE WINDOWS REPLACEMENT ---
        cursor.execute('''
            CREATE TABLE new_feature_windows (
                feature_id INTEGER PRIMARY KEY AUTOINCREMENT,
                dataset_id INTEGER NOT NULL,
                node_id TEXT NOT NULL,
                window_id INTEGER NOT NULL,
                mean_iat REAL NOT NULL,
                iat_std REAL NOT NULL,
                packet_rate REAL NOT NULL,
                mean_packet_size REAL NOT NULL,
                packet_size_std REAL NOT NULL,
                FOREIGN KEY(dataset_id) REFERENCES datasets(dataset_id),
                FOREIGN KEY(node_id) REFERENCES nodes(node_id),
                UNIQUE(dataset_id, node_id, window_id)
            )
        ''')
        
        cursor.execute('''
            INSERT INTO new_feature_windows (
                feature_id, dataset_id, node_id, window_id, 
                mean_iat, iat_std, packet_rate, mean_packet_size, packet_size_std
            )
            SELECT 
                feature_id, ?, node_id, window_id, 
                mean_iat, iat_std, packet_rate, mean_packet_size, packet_size_std
            FROM feature_windows
        ''', (dataset_id,))
        
        cursor.execute("DROP TABLE feature_windows")
        cursor.execute("ALTER TABLE new_feature_windows RENAME TO feature_windows")
        
        # --- ANOMALY PREDICTIONS REPLACEMENT ---
        cursor.execute('''
            CREATE TABLE new_anomaly_predictions (
                prediction_id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                node_id TEXT NOT NULL,
                window_id INTEGER NOT NULL,
                prediction INTEGER NOT NULL,
                anomaly_score REAL NOT NULL,
                actual_class TEXT,
                FOREIGN KEY(run_id) REFERENCES prediction_runs(run_id),
                FOREIGN KEY(node_id) REFERENCES nodes(node_id),
                UNIQUE(run_id, node_id, window_id)
            )
        ''')
        
        cursor.execute('''
            INSERT INTO new_anomaly_predictions (
                prediction_id, run_id, node_id, window_id, prediction, anomaly_score, actual_class
            )
            SELECT 
                prediction_id, ?, node_id, window_id, prediction, anomaly_score, actual_class
            FROM anomaly_predictions
        ''', (run_id,))
        
        cursor.execute("DROP TABLE anomaly_predictions")
        cursor.execute("ALTER TABLE new_anomaly_predictions RENAME TO anomaly_predictions")
        
        # --- IN-TRANSACTION VERIFICATION ---
        # Perform all verification checks here BEFORE committing to ensure database safety
        
        final_counts = get_counts(cursor)
        cursor.execute("SELECT COUNT(*) FROM datasets")
        final_counts["datasets"] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM prediction_runs")
        final_counts["prediction_runs"] = cursor.fetchone()[0]
        
        # 1. Baseline count checks
        report_check("nodes count", final_counts.get("nodes", -1) == 5, f"Found {final_counts.get('nodes', -1)}")
        report_check("traffic_observations count", final_counts.get("traffic_observations", -1) == 9073, f"Found {final_counts.get('traffic_observations', -1)}")
        report_check("feature_windows count", final_counts.get("feature_windows", -1) == 905, f"Found {final_counts.get('feature_windows', -1)}")
        report_check("anomaly_predictions count", final_counts.get("anomaly_predictions", -1) == 183, f"Found {final_counts.get('anomaly_predictions', -1)}")
        report_check("datasets count", final_counts.get("datasets", -1) == 1, f"Found {final_counts.get('datasets', -1)}")
        report_check("prediction_runs count", final_counts.get("prediction_runs", -1) == 1, f"Found {final_counts.get('prediction_runs', -1)}")
        
        # 2. PRAGMA foreign_key_check
        cursor.execute("PRAGMA foreign_key_check;")
        fk_violations = cursor.fetchall()
        report_check("Foreign key check returns zero violations", len(fk_violations) == 0, f"Violations: {fk_violations}")
        
        # 3. Data Integrity Checks
        cursor.execute("SELECT COUNT(*) FROM feature_windows WHERE dataset_id != ?", (dataset_id,))
        bad_fw_ds = cursor.fetchone()[0]
        report_check("Every feature_window has normal dataset_id", bad_fw_ds == 0, f"Found {bad_fw_ds} unmatched rows")
        
        cursor.execute("SELECT COUNT(*) FROM anomaly_predictions WHERE run_id != ?", (run_id,))
        bad_ap_run = cursor.fetchone()[0]
        report_check("Every anomaly_prediction has baseline run_id", bad_ap_run == 0, f"Found {bad_ap_run} unmatched rows")
        
        cursor.execute('''
            SELECT COUNT(*)
            FROM anomaly_predictions ap
            LEFT JOIN feature_windows fw 
              ON ap.node_id = fw.node_id AND ap.window_id = fw.window_id AND fw.dataset_id = ?
            WHERE fw.feature_id IS NULL
        ''', (dataset_id,))
        orphaned = cursor.fetchone()[0]
        report_check("Every prediction has matching feature_window", orphaned == 0, f"Found {orphaned} orphaned predictions")
        
        # 4. Duplicate checks
        cursor.execute('''
            SELECT dataset_id, node_id, window_id, COUNT(*) 
            FROM feature_windows 
            GROUP BY dataset_id, node_id, window_id 
            HAVING COUNT(*) > 1
        ''')
        fw_dups = cursor.fetchall()
        report_check("No duplicates in feature_windows", len(fw_dups) == 0, f"Duplicates found: {fw_dups}")
        
        cursor.execute('''
            SELECT run_id, node_id, window_id, COUNT(*) 
            FROM anomaly_predictions 
            GROUP BY run_id, node_id, window_id 
            HAVING COUNT(*) > 1
        ''')
        ap_dups = cursor.fetchall()
        report_check("No duplicates in anomaly_predictions", len(ap_dups) == 0, f"Duplicates found: {ap_dups}")
        
        # 5. Schema Meta-data constraints verification (UNIQUE)
        fw_unique_ok = check_unique_constraint(cursor, 'feature_windows', ['dataset_id', 'node_id', 'window_id'])
        report_check("feature_windows exact UNIQUE constraint exists", fw_unique_ok, "Missing or incorrect UNIQUE constraint")
        
        ap_unique_ok = check_unique_constraint(cursor, 'anomaly_predictions', ['run_id', 'node_id', 'window_id'])
        report_check("anomaly_predictions exact UNIQUE constraint exists", ap_unique_ok, "Missing or incorrect UNIQUE constraint")
        
        # 6. Schema Meta-data constraints verification (FOREIGN KEYS)
        fw_fk_ok, fw_fk_err = check_fk_constraint(cursor, 'feature_windows', [
            ('dataset_id', 'datasets', 'dataset_id'),
            ('node_id', 'nodes', 'node_id')
        ])
        report_check("feature_windows exact FK constraints exist", fw_fk_ok, fw_fk_err)
        
        pr_fk_ok, pr_fk_err = check_fk_constraint(cursor, 'prediction_runs', [
            ('dataset_id', 'datasets', 'dataset_id')
        ])
        report_check("prediction_runs exact FK constraints exist", pr_fk_ok, pr_fk_err)
        
        ap_fk_ok, ap_fk_err = check_fk_constraint(cursor, 'anomaly_predictions', [
            ('run_id', 'prediction_runs', 'run_id'),
            ('node_id', 'nodes', 'node_id')
        ])
        report_check("anomaly_predictions exact FK constraints exist", ap_fk_ok, ap_fk_err)

        # 7. Data value sanity checks
        cursor.execute("SELECT DISTINCT actual_class FROM anomaly_predictions")
        classes = {row[0] for row in cursor.fetchall()}
        report_check("actual_class values are 'normal'", classes == {"normal"} or not classes, f"Found classes: {classes}")
        
        cursor.execute("SELECT DISTINCT prediction FROM anomaly_predictions")
        preds = {row[0] for row in cursor.fetchall()}
        report_check("prediction values are 1 or -1", len(preds - {1, -1}) == 0, f"Found prediction values: {preds}")
        
        cursor.execute("SELECT COUNT(*) FROM nodes")
        nodes_cnt = cursor.fetchone()[0]
        report_check("nodes table still contains 5 records", nodes_cnt == 5, f"Found {nodes_cnt} records")
        
        # --- FINAL COMMIT/ROLLBACK DECISION ---
        if failures:
            raise Exception("One or more integrity checks failed during the transaction.")
            
        # Commit safely ONLY because all checks have explicitly passed
        conn.commit()
        # Restore foreign keys
        cursor.execute("PRAGMA foreign_keys = ON;")
        
        print("\nFinal counts:")
        print_counts(final_counts)
        print("\nMigration:\nPASS")
        print("\nIntegrity checks:\nPASS")
        print("\nDATABASE MIGRATION: PASS")
        
    except Exception as e:
        # Rollback the transaction entirely if ANY error or failure occurred
        conn.rollback()
        # Restore foreign keys even on failure to leave DB operational
        cursor.execute("PRAGMA foreign_keys = ON;")
        
        print("\nMigration:\nFAIL")
        print("\nIntegrity checks:\nFAIL")
        for f in failures:
            print(f" -> {f}")
        print(f"\nDATABASE MIGRATION: FAIL ({e})")
        
    finally:
        conn.close()

if __name__ == "__main__":
    main()
