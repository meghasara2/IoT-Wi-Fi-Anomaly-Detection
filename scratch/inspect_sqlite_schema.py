import sqlite3
import json
from pathlib import Path

db_path = Path("data/stage9_demo_live_monitoring.db").resolve()
conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
cur = conn.cursor()

tables = cur.execute(
    "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;"
).fetchall()

schema_info = {}
for name, sql in tables:
    cols = cur.execute(f"PRAGMA table_info({name});").fetchall()
    fks = cur.execute(f"PRAGMA foreign_key_list({name});").fetchall()
    idxs = cur.execute(f"PRAGMA index_list({name});").fetchall()
    idx_details = []
    for idx in idxs:
        idx_name = idx[1]
        idx_unique = idx[2]
        cols_in_idx = [c[2] for c in cur.execute(f"PRAGMA index_info({idx_name});").fetchall()]
        idx_details.append({"name": idx_name, "unique": bool(idx_unique), "cols": cols_in_idx})
    
    schema_info[name] = {
        "sql": sql,
        "columns": [
            {
                "cid": c[0],
                "name": c[1],
                "type": c[2],
                "notnull": bool(c[3]),
                "dflt_value": c[4],
                "pk": bool(c[5])
            }
            for c in cols
        ],
        "foreign_keys": [
            {
                "id": f[0],
                "seq": f[1],
                "table": f[2],
                "from": f[3],
                "to": f[4],
                "on_update": f[5],
                "on_delete": f[6],
                "match": f[7]
            }
            for f in fks
        ],
        "indexes": idx_details
    }

output_path = Path("scratch/sqlite_schema_dump.json")
with open(output_path, "w", encoding="utf-8") as f:
    json.dump(schema_info, f, indent=2)

print(f"Schema dumped to {output_path}. Found {len(tables)} tables: {list(schema_info.keys())}")

