import re

with open("src/attack_detector.py", "r", encoding="utf-8") as f:
    text = f.read()

# Look for evidence dict assignments
evidence_blocks = re.findall(r'evidence\s*=\s*\{([^}]+)\}', text)
print(f"Found {len(evidence_blocks)} evidence dictionaries in attack_detector.py:")
for i, blk in enumerate(evidence_blocks):
    print(f"\n--- Block {i+1}:")
    for line in blk.strip().splitlines()[:8]:
        print(f"  {line.strip()}")

