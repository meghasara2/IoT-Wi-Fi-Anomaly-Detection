import sqlite3
from pathlib import Path

def main():
    # Setup paths
    current_dir = Path(__file__).parent
    project_root = current_dir.parent
    db_path = project_root / "data" / "iot_anomaly.db"
    
    if not db_path.exists():
        print(f"Error: Database not found at {db_path}")
        return
        
    # 1. Use Python sqlite3 only (read-only verification)
    # 2. DO NOT modify, insert, update, or delete any database data.
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # 3. Enable foreign key enforcement
    cursor.execute("PRAGMA foreign_keys = ON;")
    
    failures = []
    
    def report_check(name, passed, detail=""):
        """Helper to cleanly print the PASS/FAIL result for each check."""
        status = "PASS" if passed else "FAIL"
        print(f"[{status}] {name}")
        if not passed:
            print(f"       -> {detail}")
            failures.append(name)
            
    print("--- SQLite Database Verification ---\n")
    
    # 4. Verify that the expected tables exist
    expected_tables = {"nodes", "traffic_observations", "feature_windows", "anomaly_predictions"}
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    existing_tables = {row[0] for row in cursor.fetchall()}
    
    tables_passed = expected_tables.issubset(existing_tables)
    report_check("Required tables exist", tables_passed, f"Missing: {expected_tables - existing_tables}")
    
    if not tables_passed:
        # If core tables are missing, we can't safely run the other queries
        print("\nDATABASE INTEGRITY: FAIL")
        print("Failed checks: Required tables exist")
        conn.close()
        return

    # 5. Print row counts for each table and verify expected values
    cursor.execute("SELECT COUNT(*) FROM nodes")
    n_nodes = cursor.fetchone()[0]
    report_check("Row count: nodes (Expected: 5)", n_nodes == 5, f"Found {n_nodes}")
    
    cursor.execute("SELECT COUNT(*) FROM traffic_observations")
    n_traffic = cursor.fetchone()[0]
    report_check("Row count: traffic_observations (Expected: 9073)", n_traffic == 9073, f"Found {n_traffic}")
    
    cursor.execute("SELECT COUNT(*) FROM feature_windows")
    n_features = cursor.fetchone()[0]
    report_check("Row count: feature_windows (Expected: 905)", n_features == 905, f"Found {n_features}")
    
    cursor.execute("SELECT COUNT(*) FROM anomaly_predictions")
    n_preds = cursor.fetchone()[0]
    report_check("Row count: anomaly_predictions (Expected: 183)", n_preds == 183, f"Found {n_preds}")
    
    # 6. Verify that every node_id appearing in the dependent tables exists in the nodes table.
    # SQLite's built-in PRAGMA foreign_key_check scans all foreign key constraints.
    cursor.execute("PRAGMA foreign_key_check;")
    fk_violations = cursor.fetchall()
    report_check("Foreign key integrity (node_id exists in nodes)", len(fk_violations) == 0, f"Violations found: {fk_violations}")
    
    # 7. Verify that feature_windows contains no duplicate (node_id, window_id)
    cursor.execute('''
        SELECT node_id, window_id, COUNT(*) 
        FROM feature_windows 
        GROUP BY node_id, window_id 
        HAVING COUNT(*) > 1
    ''')
    fw_dups = cursor.fetchall()
    report_check("No duplicates in feature_windows (node_id, window_id)", len(fw_dups) == 0, f"Found duplicates: {fw_dups}")
    
    # 8. Verify that anomaly_predictions contains no duplicate (node_id, window_id)
    cursor.execute('''
        SELECT node_id, window_id, COUNT(*) 
        FROM anomaly_predictions 
        GROUP BY node_id, window_id 
        HAVING COUNT(*) > 1
    ''')
    ap_dups = cursor.fetchall()
    report_check("No duplicates in anomaly_predictions (node_id, window_id)", len(ap_dups) == 0, f"Found duplicates: {ap_dups}")
    
    # 9. Verify that anomaly_predictions.actual_class contains only "normal"
    cursor.execute("SELECT DISTINCT actual_class FROM anomaly_predictions")
    classes = {row[0] for row in cursor.fetchall()}
    # If the table is empty (0 rows), classes will be empty, which is also technically fine, 
    # but since we expect 183 rows, we check explicitly against {"normal"}.
    report_check("actual_class contains only 'normal'", classes == {"normal"} or len(classes) == 0, f"Found classes: {classes}")
    
    # 10. Verify that prediction values contain only 1 or -1
    cursor.execute("SELECT DISTINCT prediction FROM anomaly_predictions")
    preds = {row[0] for row in cursor.fetchall()}
    invalid_preds = preds - {1, -1}
    report_check("prediction values contain only 1 or -1", len(invalid_preds) == 0, f"Found invalid predictions: {invalid_preds}")
    
    # 11. Verify that every anomaly_prediction has a corresponding feature_windows
    cursor.execute('''
        SELECT ap.node_id, ap.window_id 
        FROM anomaly_predictions ap
        LEFT JOIN feature_windows fw 
          ON ap.node_id = fw.node_id AND ap.window_id = fw.window_id
        WHERE fw.feature_id IS NULL
    ''')
    orphaned = cursor.fetchall()
    report_check("Every prediction has a corresponding feature window", len(orphaned) == 0, f"Orphaned predictions found: {orphaned}")
    
    conn.close()
    
    # 13. Print final pass/fail result
    print("\n----------------------------------------")
    if not failures:
        print("DATABASE INTEGRITY: PASS")
    else:
        print("DATABASE INTEGRITY: FAIL")
        print("Failed checks:")
        for f in failures:
            print(f" - {f}")

if __name__ == "__main__":
    main()
