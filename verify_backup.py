import sqlite3
import os

def verify_backup(db_path):
    print(f"Verifying backup database: {db_path}")
    if not os.path.exists(db_path):
        print("Error: Backup file not found!")
        return

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        print(f"\nTables found ({len(tables)}): {', '.join(tables)}")
        
        expected_tables = ['nodes', 'traffic_observations', 'feature_windows', 'anomaly_predictions', 'datasets', 'prediction_runs']
        missing = [t for t in expected_tables if t not in tables]
        if missing:
            print(f"WARNING: Missing expected tables: {missing}")
        else:
            print("SUCCESS: All expected tables are present.")

        # Check records
        print("\nRecord Counts:")
        for table in expected_tables:
            if table in tables:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                count = cursor.fetchone()[0]
                print(f" - {table}: {count} records")

        conn.close()
        print("\nBackup verification completed successfully.")
    except Exception as e:
        print(f"Failed to verify backup: {e}")

if __name__ == '__main__':
    verify_backup('data/iot_anomaly_backup_20261010.db')
