with open("src/live_collector.py", "r", encoding="utf-8") as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if "def _compute_port_scan_fingerprint" in line:
        for k in range(i, min(len(lines), i+25)):
            print(f"{k+1}: {lines[k].rstrip()}")
        break

