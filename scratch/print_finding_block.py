with open("src/attack_detector.py", "r", encoding="utf-8") as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if "findings.append" in line:
        print(f"Line {i+1}:")
        for k in range(max(0, i-2), min(len(lines), i+30)):
            print(f"  {k+1}: {lines[k].rstrip()}")
        break

