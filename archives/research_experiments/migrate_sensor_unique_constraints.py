
import sqlite3
from pathlib import Path

DB_PATH = Path("data/live_monitoring.db")


def migrate():
    if not DB_PATH.exists():
        raise FileNotFoundError(DB_PATH)

    conn = sqlite3.connect(DB_PATH, timeout=15)

    try:
        # Disable FK checks before starting the transaction.
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.execute("BEGIN IMMEDIATE")

        expected = {
            "live_sensor_telemetry": 755,
            "live_pir_events": 755,
        }

        for table, count in expected.items():
            actual = conn.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]

            if actual != count:
                raise RuntimeError(
                    f"{table}: expected {count} rows, found {actual}. "
                    "Migration cancelled."
                )

        # Rebuild DHT11 telemetry table.
        conn.execute("""
            CREATE TABLE live_sensor_telemetry_new (
                telemetry_id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER,
                physical_node_id TEXT NOT NULL DEFAULT 'esp32_gateway',
                logical_node_id TEXT NOT NULL DEFAULT 'Node_1',
                sequence_num INTEGER NOT NULL,
                uptime_ms INTEGER NOT NULL,
                temperature_c REAL,
                humidity_pct REAL,
                dht_valid INTEGER NOT NULL DEFAULT 0,
                captured_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                sensor_epoch REAL,
                UNIQUE(run_id, physical_node_id, sequence_num),
                FOREIGN KEY (run_id) REFERENCES collector_status(run_id)
            )
        """)

        conn.execute("""
            INSERT INTO live_sensor_telemetry_new
            SELECT * FROM live_sensor_telemetry
        """)

        conn.execute("DROP TABLE live_sensor_telemetry")
        conn.execute("""
            ALTER TABLE live_sensor_telemetry_new
            RENAME TO live_sensor_telemetry
        """)

        # Rebuild PIR events table.
        conn.execute("""
            CREATE TABLE live_pir_events_new (
                pir_id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER,
                physical_node_id TEXT NOT NULL DEFAULT 'esp32_gateway',
                logical_node_id TEXT NOT NULL DEFAULT 'Node_2',
                sequence_num INTEGER NOT NULL,
                uptime_ms INTEGER NOT NULL,
                motion_detected INTEGER NOT NULL,
                captured_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                sensor_epoch REAL,
                UNIQUE(run_id, physical_node_id, sequence_num),
                FOREIGN KEY (run_id) REFERENCES collector_status(run_id)
            )
        """)

        conn.execute("""
            INSERT INTO live_pir_events_new
            SELECT * FROM live_pir_events
        """)

        conn.execute("DROP TABLE live_pir_events")
        conn.execute("""
            ALTER TABLE live_pir_events_new
            RENAME TO live_pir_events
        """)

        # Restore the original secondary indexes.
        conn.execute("""
            CREATE INDEX idx_sensor_run
            ON live_sensor_telemetry(run_id, captured_at)
        """)

        conn.execute("""
            CREATE INDEX idx_pir_run
            ON live_pir_events(run_id, captured_at)
        """)

        # Verify row counts before committing.
        for table, count in expected.items():
            actual = conn.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]

            if actual != count:
                raise RuntimeError(
                    f"Verification failed for {table}: {actual}"
                )

        conn.commit()
        print("Migration completed successfully.")
        print("DHT11 records preserved: 755")
        print("PIR records preserved: 755")

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


if __name__ == "__main__":
    migrate()
