with open("src/live_collector.py", "r", encoding="utf-8") as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if "_insert_attack_event(" in line and not line.strip().startswith("def "):
        print(f"\n=== Call at Line {i+1} ===")
        start = max(0, i - 4)
        end = min(len(lines), i + 10)
        for k in range(start, end):
            print(f"{k+1}: {lines[k].rstrip()}")

