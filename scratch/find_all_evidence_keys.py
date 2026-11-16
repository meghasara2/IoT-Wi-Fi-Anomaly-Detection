import re

with open('src/attack_detector.py', 'r', encoding='utf-8') as f:
    text = f.read()

# Look for evidence dictionaries
evidence_blocks = re.findall(r'evidence\s*=\s*\{([^}]+)\}', text)
print(f"Found {len(evidence_blocks)} evidence dict blocks.")

all_keys = set()
for b in evidence_blocks:
    keys = re.findall(r'"([a-zA-Z0-9_]+)":', b)
    all_keys.update(keys)

print("All keys ever placed in evidence dicts:")
for k in sorted(all_keys):
    print(f"  • {k}")

