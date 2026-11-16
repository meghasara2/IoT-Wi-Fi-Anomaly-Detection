with open("src/attack_detector.py", "r", encoding="utf-8") as f:
    for i, line in enumerate(f):
        if "AttackDetectionResult" in line:
            print(f"Line {i+1}: {line.strip()}")
            for k in range(max(0, i-2), min(len(open("src/attack_detector.py").readlines()), i+25)):
                pass

