import json
from pathlib import Path

# Inspect actual records in database to see real evidence_json structure!
import sqlite3

db_path = Path("data/stage9_demo_live_monitoring.db")
conn = sqlite3.connect(f"file:{db_path.resolve().as_posix()}?mode=ro", uri=True)
cur = conn.cursor()

rows = cur.execute("SELECT event_id, category, status, severity, source_mac, target_ip, evidence_json FROM live_attack_events LIMIT 10;").fetchall()
print(f"Total attack rows sampled: {len(rows)}")
for r in rows:
    ev = json.loads(r[6])
    print(f"\n--- Event {r[0]} ({r[1]} - {r[2]}):")
    print(f"  source_mac: {r[4]}")
    print(f"  target_ip: {r[5]}")
    print(f"  evidence_json keys: {list(ev.keys())}")
    for k, v in ev.items():
        if any(term in k.lower() for term in ['ip', 'mac', 'host', 'addr']):
            print(f"    [SENSITIVE KEY] {k}: {v}")

