import sqlite3
from pathlib import Path

p1 = Path("data/live_monitoring.db")
p2 = Path("data/stage9_demo_live_monitoring.db")

for p in [p1, p2]:
    if p.exists():
        conn = sqlite3.connect(f"file:{p.resolve().as_posix()}?mode=ro", uri=True)
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;").fetchall()
        print(f"{p.name}: {[t[0] for t in tables]}")
    else:
        print(f"{p.name} does not exist")

