import sqlite3

conn = sqlite3.connect("data/live_monitoring.db")

print("COLLECTOR STATUS:")
print(conn.execute(
    "SELECT * FROM collector_status"
).fetchall())

print("\nDHT11 RECORDS:")
print(conn.execute("""
    SELECT run_id, COUNT(*),
           SUM(CASE WHEN dht_valid = 1 THEN 1 ELSE 0 END)
    FROM live_sensor_telemetry
    GROUP BY run_id
    ORDER BY run_id DESC
    LIMIT 3
""").fetchall())

print("\nPIR RECORDS:")
print(conn.execute("""
    SELECT run_id, COUNT(*),
           SUM(motion_detected)
    FROM live_pir_events
    GROUP BY run_id
    ORDER BY run_id DESC
    LIMIT 3
""").fetchall())

conn.close()