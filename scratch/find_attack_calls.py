with open("src/live_collector.py", "r", encoding="utf-8") as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if "_insert_attack_event" in line and not line.strip().startswith("def "):
        print(f"Line {i+1}: {line.strip()}")
        for k in range(max(0, i-5), min(len(lines), i+15)):
            print(f"  {k+1}: {lines[k].rstrip()}")

