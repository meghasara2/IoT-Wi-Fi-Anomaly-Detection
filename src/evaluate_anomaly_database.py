"""
Stage 20C: Controlled Synthetic Anomalous Behaviour Evaluation
Project: AI-Assisted IoT Wi-Fi Anomaly Detection (100% Software-Only)

Academic Context and Operational Scope:
--------------------------------------
This script evaluates the controlled synthetic anomalous feature dataset (dataset_id=2)
stored in SQLite using the project's final locked Isolation Forest configuration:
    IsolationForest(contamination=0.05, random_state=42)

CRITICAL EXPERIMENTAL DESIGN RULES:
1. Training Isolation:
   - Isolation Forest models are trained SOLELY on the normal baseline dataset (dataset_id=1).
   - The anomalous dataset (dataset_id=2) is NEVER used during model fitting.
   - This ensures strict unsupervised anomaly detection integrity and prevents the model
     from learning attacks as part of normal behaviour.
2. Controlled Synthetic Behaviour:
   - This evaluation utilizes controlled synthetic anomalous traffic generated in software.
   - These are deliberate statistical anomalies (IAT bursts, packet size shifts), NOT
     real-world live cyberattacks or malicious Wi-Fi captures.
3. Feature Independence:
   - Exactly five statistical features are used:
     [mean_iat, iat_std, packet_rate, mean_packet_size, packet_size_std]
   - Node identifiers, window sequences, and dataset/run metadata are excluded from ML features.
4. Per-Node Modelling:
   - Each IoT node has its own distinct traffic characteristics and is evaluated using its
     own node-specific Isolation Forest model trained on 80% normal training data.
5. Database Integrity & Idempotency:
   - Evaluated predictions are stored in SQLite table 'anomaly_predictions' under a new 'prediction_runs' record.
   - All insertions and post-insertion verifications occur within an ACID transaction.
   - The script is idempotent: if the run already exists with all 904 predictions, it reports PASS without duplicating.
"""

import sqlite3
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest

def get_counts(cursor):
    """Helper to safely fetch counts of tables."""
    tables = [
        "nodes", 
        "traffic_observations", 
        "feature_windows", 
        "anomaly_predictions", 
        "datasets", 
        "prediction_runs"
    ]
    counts = {}
    for table in tables:
        try:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            counts[table] = cursor.fetchone()[0]
        except sqlite3.OperationalError:
            counts[table] = -1
    return counts

def print_counts(counts):
    """Helper to format table counts clearly."""
    for table, count in counts.items():
        print(f"  {table} = {count}")

def main():
    print("=" * 70)
    print("STAGE 20C: CONTROLLED SYNTHETIC ANOMALOUS BEHAVIOUR EVALUATION")
    print("AI-Assisted IoT Wi-Fi Anomaly Detection (Software-Only Simulation)")
    print("=" * 70)
    
    current_dir = Path(__file__).parent
    project_root = current_dir.parent
    data_dir = project_root / "data"
    db_path = data_dir / "iot_anomaly.db"
    
    # -------------------------------------------------------------------------
    # STEP 1: VERIFY DATABASE EXISTENCE & INTEGRITY
    # -------------------------------------------------------------------------
    if not db_path.exists():
        print(f"[-] Error: Database not found at {db_path}")
        print("\nSTAGE 20C EVALUATION: FAIL")
        return
        
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON;")
    
    current_counts = get_counts(cursor)
    print("\nCurrent Database Counts:")
    print_counts(current_counts)
    
    # -------------------------------------------------------------------------
    # STEP 2: VERIFY DATASETS (dataset_id=1 and dataset_id=2)
    # -------------------------------------------------------------------------
    cursor.execute("SELECT dataset_id, dataset_name, dataset_type FROM datasets ORDER BY dataset_id")
    datasets = cursor.fetchall()
    
    dataset_map = {row[0]: {"name": row[1], "type": row[2]} for row in datasets}
    
    if 1 not in dataset_map or dataset_map[1]["type"] != "normal":
        print("[-] Error: Normal baseline dataset (dataset_id=1) not found or invalid.")
        print("\nSTAGE 20C EVALUATION: FAIL")
        conn.close()
        return
        
    if 2 not in dataset_map or dataset_map[2]["type"] != "controlled_anomaly":
        print("[-] Error: Controlled anomaly dataset (dataset_id=2) not found or invalid.")
        print("\nSTAGE 20C EVALUATION: FAIL")
        conn.close()
        return
        
    print("\n[+] Verified Datasets:")
    print(f"  dataset_id=1: '{dataset_map[1]['name']}' (type: {dataset_map[1]['type']})")
    print(f"  dataset_id=2: '{dataset_map[2]['name']}' (type: {dataset_map[2]['type']})")
    
    # -------------------------------------------------------------------------
    # STEP 3: IDEMPOTENCY CHECK
    # -------------------------------------------------------------------------
    run_name = "Final Isolation Forest - Controlled Anomaly Evaluation"
    cursor.execute("SELECT run_id, dataset_id, created_at FROM prediction_runs WHERE run_name = ?", (run_name,))
    existing_run = cursor.fetchone()
    
    if existing_run:
        existing_run_id = existing_run[0]
        cursor.execute("SELECT COUNT(*) FROM anomaly_predictions WHERE run_id = ?", (existing_run_id,))
        pred_count = cursor.fetchone()[0]
        
        print(f"\n[!] Existing prediction run found: run_id={existing_run_id} ('{run_name}')")
        print(f"    Predictions count for this run: {pred_count}")
        
        if pred_count == 904:
            # Check constraints on existing run
            cursor.execute("SELECT DISTINCT actual_class FROM anomaly_predictions WHERE run_id = ?", (existing_run_id,))
            classes = {row[0] for row in cursor.fetchall()}
            cursor.execute("SELECT DISTINCT prediction FROM anomaly_predictions WHERE run_id = ?", (existing_run_id,))
            preds = {row[0] for row in cursor.fetchall()}
            cursor.execute("PRAGMA foreign_key_check;")
            fk_violations = cursor.fetchall()
            
            if classes == {"anomaly"} and preds.issubset({-1, 1}) and len(fk_violations) == 0:
                print("[+] Existing anomaly evaluation verified intact with 904 predictions.")
                print("[+] Idempotency check passed: No duplicate predictions inserted.")
                print("\nSTAGE 20C EVALUATION: PASS")
                conn.close()
                return
            else:
                print("[-] Error: Existing prediction run data failed verification.")
                print(f"    Classes: {classes}, Predictions: {preds}, FK violations: {fk_violations}")
                print("\nSTAGE 20C EVALUATION: FAIL")
                conn.close()
                return
        else:
            print(f"[-] Error: Existing run_id={existing_run_id} has {pred_count} predictions instead of expected 904.")
            print("\nSTAGE 20C EVALUATION: FAIL")
            conn.close()
            return

    # -------------------------------------------------------------------------
    # STEP 4: LOAD NORMAL AND ANOMALOUS FEATURE WINDOWS
    # -------------------------------------------------------------------------
    feature_cols = [
        "mean_iat", 
        "iat_std", 
        "packet_rate", 
        "mean_packet_size", 
        "packet_size_std"
    ]
    
    print("\nLoading feature datasets from SQLite...")
    df_normal = pd.read_sql_query(
        "SELECT feature_id, dataset_id, node_id, window_id, mean_iat, iat_std, packet_rate, mean_packet_size, packet_size_std "
        "FROM feature_windows WHERE dataset_id = 1 ORDER BY node_id, window_id",
        conn
    )
    df_anomaly = pd.read_sql_query(
        "SELECT feature_id, dataset_id, node_id, window_id, mean_iat, iat_std, packet_rate, mean_packet_size, packet_size_std "
        "FROM feature_windows WHERE dataset_id = 2 ORDER BY node_id, window_id",
        conn
    )
    
    print(f"  Loaded Normal Feature Windows (dataset_id=1): {len(df_normal)} rows")
    print(f"  Loaded Anomaly Feature Windows (dataset_id=2): {len(df_anomaly)} rows")
    
    if len(df_normal) != 905:
        print(f"[-] Error: Expected 905 normal feature windows, found {len(df_normal)}")
        print("\nSTAGE 20C EVALUATION: FAIL")
        conn.close()
        return
        
    if len(df_anomaly) != 904:
        print(f"[-] Error: Expected 904 anomaly feature windows, found {len(df_anomaly)}")
        print("\nSTAGE 20C EVALUATION: FAIL")
        conn.close()
        return
        
    # -------------------------------------------------------------------------
    # STEP 5: PER-NODE ISOLATION FOREST TRAINING & EVALUATION
    # -------------------------------------------------------------------------
    print("\n" + "-" * 70)
    print("PER-NODE MODEL TRAINING & CONTROLLED ANOMALY EVALUATION")
    print("Model: IsolationForest(contamination=0.05, random_state=42)")
    print("Training Data: 80% Normal Windows (dataset_id=1) only")
    print("Evaluation Data: 100% Synthetic Anomaly Windows (dataset_id=2)")
    print("-" * 70)
    
    node_ids = sorted(df_normal["node_id"].unique())
    anomaly_node_ids = sorted(df_anomaly["node_id"].unique())
    
    if node_ids != anomaly_node_ids:
        print(f"[-] Error: Node mismatch between normal ({node_ids}) and anomaly ({anomaly_node_ids})")
        print("\nSTAGE 20C EVALUATION: FAIL")
        conn.close()
        return
        
    all_anomaly_predictions = []
    node_metrics = []
    
    total_anomaly_windows = 0
    total_detected_anomalies = 0
    
    for node_id in node_ids:
        df_node_normal = df_normal[df_normal["node_id"] == node_id].copy()
        df_node_anomaly = df_anomaly[df_anomaly["node_id"] == node_id].copy()
        
        # Split normal dataset into 80% train / 20% test using standard random_state=42
        df_train_normal, _ = train_test_split(
            df_node_normal,
            test_size=0.2,
            random_state=42,
            shuffle=True
        )
        
        X_train = df_train_normal[feature_cols]
        X_anomaly = df_node_anomaly[feature_cols]
        
        # Fit final locked Isolation Forest model ONLY on normal training baseline
        clf = IsolationForest(
            contamination=0.05,
            random_state=42
        )
        clf.fit(X_train)
        
        # Predict on synthetic anomalous windows for this node
        preds = clf.predict(X_anomaly)
        scores = clf.decision_function(X_anomaly)
        
        node_total = len(preds)
        node_detected = int((preds == -1).sum())
        node_missed = int((preds == 1).sum())
        detection_rate = node_detected / node_total if node_total > 0 else 0.0
        
        total_anomaly_windows += node_total
        total_detected_anomalies += node_detected
        
        node_metrics.append({
            "node_id": node_id,
            "train_windows": len(df_train_normal),
            "anomaly_windows": node_total,
            "detected": node_detected,
            "missed": node_missed,
            "detection_rate": detection_rate
        })
        
        # Prepare prediction records for DB insertion
        for (_, row), p, s in zip(df_node_anomaly.iterrows(), preds, scores):
            all_anomaly_predictions.append((
                node_id,
                int(row["window_id"]),
                int(p),
                float(s),
                "anomaly"
            ))
            
    # Print per-node performance summary
    print(f"\n{'Node ID':<10} | {'Normal Train':<12} | {'Anomaly Win':<12} | {'Detected (-1)':<14} | {'Missed (1)':<12} | {'Detection Rate':<14}")
    print("-" * 88)
    for m in node_metrics:
        print(f"{m['node_id']:<10} | {m['train_windows']:<12} | {m['anomaly_windows']:<12} | {m['detected']:<14} | {m['missed']:<12} | {m['detection_rate']:>12.2%}")
    print("-" * 88)
    
    overall_detection_rate = total_detected_anomalies / total_anomaly_windows if total_anomaly_windows > 0 else 0.0
    print(f"\n--- OVERALL PERFORMANCE SUMMARY ---")
    print(f"Total Controlled Anomaly Windows: {total_anomaly_windows}")
    print(f"Total Anomalies Correctly Detected: {total_detected_anomalies}")
    print(f"Total Anomalies Missed (False Negatives): {total_anomaly_windows - total_detected_anomalies}")
    print(f"Overall Detection Rate: {overall_detection_rate:.2%}")
    
    # -------------------------------------------------------------------------
    # STEP 6: DATABASE TRANSACTION & INSERTION
    # -------------------------------------------------------------------------
    print("\n" + "-" * 70)
    print("DATABASE TRANSACTION: INSERTING PREDICTION RUN & PREDICTIONS")
    print("-" * 70)
    
    failures = []
    def report_check(name, passed, detail=""):
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {name}")
        if not passed:
            print(f"         -> {detail}")
            failures.append(name)

    try:
        cursor.execute("BEGIN TRANSACTION;")
        
        # 1. Create prediction run
        run_description = (
            "Evaluation of controlled synthetic anomalous behaviour using final locked "
            "Isolation Forest (contamination=0.05, random_state=42) trained exclusively on normal baseline traffic."
        )
        cursor.execute('''
            INSERT INTO prediction_runs (run_name, dataset_id, description)
            VALUES (?, ?, ?)
        ''', (run_name, 2, run_description))
        
        new_run_id = cursor.lastrowid
        print(f"[+] Created prediction_runs record: run_id={new_run_id}")
        print(f"    Name: '{run_name}'")
        print(f"    Target Dataset: dataset_id=2")
        
        # 2. Insert predictions
        prediction_insert_data = [
            (new_run_id, item[0], item[1], item[2], item[3], item[4])
            for item in all_anomaly_predictions
        ]
        
        cursor.executemany('''
            INSERT INTO anomaly_predictions (
                run_id, node_id, window_id, prediction, anomaly_score, actual_class
            ) VALUES (?, ?, ?, ?, ?, ?)
        ''', prediction_insert_data)
        
        rows_inserted = cursor.rowcount
        print(f"[+] Inserted {rows_inserted} anomaly predictions into anomaly_predictions.")
        
        # ---------------------------------------------------------------------
        # STEP 7: IN-TRANSACTION VERIFICATION CHECKS
        # ---------------------------------------------------------------------
        print("\nExecuting In-Transaction Verification Checks:")
        
        # Check A: Exact count for this run_id
        cursor.execute("SELECT COUNT(*) FROM anomaly_predictions WHERE run_id = ?", (new_run_id,))
        count_run_preds = cursor.fetchone()[0]
        report_check(
            "Inserted prediction count for run_id is exactly 904",
            count_run_preds == 904,
            f"Expected 904, found {count_run_preds}"
        )
        
        # Check B: Total anomaly_predictions count equals 183 + 904 = 1087
        cursor.execute("SELECT COUNT(*) FROM anomaly_predictions")
        total_preds = cursor.fetchone()[0]
        report_check(
            "Total anomaly_predictions row count is 1087 (183 normal + 904 anomaly)",
            total_preds == 1087,
            f"Expected 1087, found {total_preds}"
        )
        
        # Check C: actual_class contains only "anomaly" for this run_id
        cursor.execute("SELECT DISTINCT actual_class FROM anomaly_predictions WHERE run_id = ?", (new_run_id,))
        classes_in_run = {row[0] for row in cursor.fetchall()}
        report_check(
            "actual_class contains only 'anomaly' for new run",
            classes_in_run == {"anomaly"},
            f"Found classes: {classes_in_run}"
        )
        
        # Check D: prediction values contain only 1 or -1
        cursor.execute("SELECT DISTINCT prediction FROM anomaly_predictions WHERE run_id = ?", (new_run_id,))
        preds_in_run = {row[0] for row in cursor.fetchall()}
        report_check(
            "Prediction values contain only 1 or -1",
            preds_in_run.issubset({-1, 1}) and len(preds_in_run) > 0,
            f"Found predictions: {preds_in_run}"
        )
        
        # Check E: No duplicate (run_id, node_id, window_id) in anomaly_predictions
        cursor.execute('''
            SELECT node_id, window_id, COUNT(*) 
            FROM anomaly_predictions 
            WHERE run_id = ? 
            GROUP BY node_id, window_id 
            HAVING COUNT(*) > 1
        ''', (new_run_id,))
        dups = cursor.fetchall()
        report_check(
            "No duplicate (node_id, window_id) for this run",
            len(dups) == 0,
            f"Found duplicates: {dups}"
        )
        
        # Check F: PRAGMA foreign_key_check passes with 0 violations
        cursor.execute("PRAGMA foreign_key_check;")
        fk_violations = cursor.fetchall()
        report_check(
            "Foreign key integrity check (PRAGMA foreign_key_check)",
            len(fk_violations) == 0,
            f"Violations found: {fk_violations}"
        )
        
        # ---------------------------------------------------------------------
        # STEP 8: COMMIT OR ROLLBACK
        # ---------------------------------------------------------------------
        if len(failures) == 0:
            conn.commit()
            print("\n[+] Transaction committed successfully.")
            
            final_counts = get_counts(cursor)
            print("\nFinal Verified Database Counts:")
            print_counts(final_counts)
            
            print("\n" + "=" * 70)
            print("STAGE 20C EVALUATION: PASS")
            print("=" * 70)
        else:
            conn.rollback()
            print(f"\n[-] Verification failed ({len(failures)} failures). Transaction rolled back.")
            print(f"    Failed checks: {failures}")
            print("\nSTAGE 20C EVALUATION: FAIL")
            
    except Exception as e:
        conn.rollback()
        print(f"\n[-] Unexpected transaction exception: {e}. Transaction rolled back.")
        print("\nSTAGE 20C EVALUATION: FAIL")
    finally:
        conn.close()

if __name__ == "__main__":
    main()
