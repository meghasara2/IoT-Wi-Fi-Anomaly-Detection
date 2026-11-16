with open("src/live_collector.py", "r", encoding="utf-8") as f:
    lines = f.readlines()

for k in range(1500, 1535):
    print(f"{k+1}: {lines[k].rstrip()}")

