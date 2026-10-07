import sqlite3
from pathlib import Path

def main():
    # 2. Create the data directory if it does not already exist
    current_dir = Path(__file__).parent
    project_root = current_dir.parent
    data_dir = project_root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    
    # 3. Define the database path
    db_path = data_dir / "iot_anomaly.db"
    
    # 1. Use Python's built-in sqlite3 module
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # 6. Enable foreign key enforcement
    cursor.execute("PRAGMA foreign_keys = ON;")
    
    # 4 & 10 & 11. Create tables using IF NOT EXISTS and add comments explaining them.
    
    # TABLE 1: nodes
    # Purpose: Stores the profile metadata for the five software-defined IoT nodes.
    # 5. nodes.node_id is unique through its PRIMARY KEY constraint.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS nodes (
            node_id TEXT PRIMARY KEY,
            node_type TEXT NOT NULL
        )
    ''')
    
    # TABLE 2: traffic_observations
    # Purpose: Stores the raw synthetic IoT traffic (packet size, timestamp) generated for each node.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic_observations (
            observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT NOT NULL,
            timestamp REAL NOT NULL,
            packet_size REAL NOT NULL,
            FOREIGN KEY(node_id) REFERENCES nodes(node_id)
        )
    ''')
    
    # TABLE 3: feature_windows
    # Purpose: Stores the extracted behavioural ML features for sequential 10-packet windows.
    # 5. UNIQUE constraint prevents duplicate (node_id, window_id) entries.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS feature_windows (
            feature_id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT NOT NULL,
            window_id INTEGER NOT NULL,
            mean_iat REAL NOT NULL,
            iat_std REAL NOT NULL,
            packet_rate REAL NOT NULL,
            mean_packet_size REAL NOT NULL,
            packet_size_std REAL NOT NULL,
            FOREIGN KEY(node_id) REFERENCES nodes(node_id),
            UNIQUE(node_id, window_id)
        )
    ''')
    
    # TABLE 4: anomaly_predictions
    # Purpose: Stores the Isolation Forest prediction results for the feature windows.
    # 5. UNIQUE constraint prevents duplicate predictions for the same (node_id, window_id).
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS anomaly_predictions (
            prediction_id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT NOT NULL,
            window_id INTEGER NOT NULL,
            prediction INTEGER NOT NULL,
            anomaly_score REAL NOT NULL,
            actual_class TEXT,
            FOREIGN KEY(node_id) REFERENCES nodes(node_id),
            UNIQUE(node_id, window_id)
        )
    ''')
    
    # 7. Insert the five node definitions into the nodes table.
    # The five nodes are explicitly defined here.
    nodes_data = [
        ("Node_1", "Temperature Sensor"),
        ("Node_2", "Smart Light"),
        ("Node_3", "Smart Plug"),
        ("Node_4", "Motion Sensor"),
        ("Node_5", "Camera-like Traffic Generator")
    ]
    
    # Use INSERT OR IGNORE so running the script multiple times does not create duplicates.
    cursor.executemany('''
        INSERT OR IGNORE INTO nodes (node_id, node_type)
        VALUES (?, ?)
    ''', nodes_data)
    
    # Commit changes
    conn.commit()
    
    # Retrieve the list of created tables to print (filtering out SQLite's internal sequence table)
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall() if row[0] != "sqlite_sequence"]
    
    conn.close()
    
    # 9. Print required outputs
    print("--- SQLite Database Setup Complete ---")
    print(f"Database Path: {db_path}")
    print(f"Created Tables: {', '.join(tables)}")
    print(f"Number of nodes inserted (or verified if existing): {len(nodes_data)}")
    print("Confirmation: Database and schema were created successfully.")

if __name__ == "__main__":
    main()
