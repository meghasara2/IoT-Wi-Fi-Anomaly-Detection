"""
Inspect data/live_monitoring.db structure and outbox status.
File: scripts/inspect_local_db.py
"""
import sqlite3
from pathlib import Path

db_path = Path("data/live_monitoring.db")
print(f"Database exists: {db_path.exists()}")
if db_path.exists():
    print(f"Database size: {db_path.stat().st_size:,} bytes")
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    
    # Check integrity
    cur.execute("PRAGMA integrity_check;")
    print(f"Integrity check: {cur.fetchone()[0]}")
    
    # Check tables
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
    tables = [r[0] for r in cur.fetchall()]
    print(f"Tables in DB ({len(tables)}): {tables}")
    
    # Check row counts in tables
    print("\nTable row counts:")
    for t in tables:
        cur.execute(f"SELECT COUNT(*) FROM {t};")
        cnt = cur.fetchone()[0]
        print(f"  - {t}: {cnt} rows")
        
    # Check outbox details
    if "cloud_sync_outbox" in tables:
        print("\nOutbox Schema & Status:")
        cur.execute("SELECT status, COUNT(*) FROM cloud_sync_outbox GROUP BY status;")
        statuses = cur.fetchall()
        print(f"  Status breakdown: {statuses}")
        
        cur.execute("SELECT table_name, status, COUNT(*) FROM cloud_sync_outbox GROUP BY table_name, status;")
        breakdown = cur.fetchall()
        print(f"  Table breakdown: {breakdown}")
        
        cur.execute("SELECT MIN(created_at), MAX(created_at) FROM cloud_sync_outbox;")
        time_range = cur.fetchone()
        print(f"  Outbox time range: {time_range}")
    else:
        print("\nOutbox table 'cloud_sync_outbox' does not exist yet.")

    conn.close()
else:
    print("data/live_monitoring.db does not exist.")
