with open("src/live_collector.py", "r", encoding="utf-8") as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if "def _insert_attack_event" in line:
        for j in range(i, min(i + 50, len(lines))):
            print(f"{j+1}: {lines[j].rstrip()}")
        break

