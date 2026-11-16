import sqlite3, os
from pathlib import Path

data_dir = Path('data')
dbs = list(data_dir.glob('*.db'))
for db in sorted(dbs):
    size_kb = os.path.getsize(db) / 1024
    print(f"=== {db.name} ({size_kb:.1f} KB) ===")
    try:
        conn = sqlite3.connect(str(db))
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        tables = [r[0] for r in cur.fetchall()]
        print(f"  Tables ({len(tables)}):", tables)
        for t in tables:
            cur.execute(f"SELECT count(*) FROM {t}")
            cnt = cur.fetchone()[0]
            print(f"    • {t}: {cnt} rows")
        conn.close()
    except Exception as e:
        print(f"  Error: {e}")

