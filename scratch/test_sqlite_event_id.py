import sqlite3
import uuid

# Let's inspect data/stage9_demo_live_monitoring.db
conn = sqlite3.connect("file:data/stage9_demo_live_monitoring.db?mode=ro", uri=True)
cur = conn.cursor()

rows = cur.execute("SELECT event_id, run_id, timestamp_epoch, category, source_mac, target_ip FROM live_attack_events;").fetchall()
print(f"Total historical attack events in Stage 9.2 demo: {len(rows)}")

NAMESPACE = uuid.UUID("a3b8c4d6-e2f1-4b9a-8c3d-7e5f6a1b2c3d")

generated_uuids = set()
for r in rows:
    eid, rid, ts, cat, smac, tip = r
    u = uuid.uuid5(NAMESPACE, f"{rid}:{eid}")
    print(f"Historical Event #{eid} (run_id={rid}, {cat}): UUID={u}")
    assert u not in generated_uuids
    generated_uuids.add(u)

print("Assertion passed: All historical events reconstruct 100% unique, stable UUIDs from (run_id, event_id)!")

