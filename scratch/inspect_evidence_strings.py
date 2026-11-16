import re

with open('src/attack_detector.py', 'r', encoding='utf-8') as f:
    text = f.read()

for key in ['verdict', 'reason', 'initial_capability', 'limitations_or_remedy']:
    matches = re.findall(rf'"{key}"\s*:\s*([^,\n}}]+)', text)
    print(f"=== {key} ({len(matches)} occurrences) ===")
    for m in sorted(set(matches)):
        print(" ", m.strip())

