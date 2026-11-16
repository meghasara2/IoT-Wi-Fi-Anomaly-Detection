import re

with open('src/attack_detector.py', 'r', encoding='utf-8') as f:
    text = f.read()

lims = set(re.findall(r'"limitations_or_remedy":\s*"([^"]+)"', text))
print("--- limitations_or_remedy ---")
for l in lims:
    print(f"• {l}")

verdicts = set(re.findall(r'"verdict":\s*"([^"]+)"', text))
print("\n--- verdict ---")
for v in verdicts:
    print(f"• {v}")

reasons = set(re.findall(r'"reason":\s*"([^"]+)"', text))
print("\n--- reason ---")
for r in reasons:
    print(f"• {r}")

