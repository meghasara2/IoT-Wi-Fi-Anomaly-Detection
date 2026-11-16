with open("src/attack_detector.py", "r", encoding="utf-8") as f:
    text = f.read()

import re
m = re.search(r'findings\.append\(\{([^}]+)\}\)', text)
if m:
    print("Finding appended in attack_detector:")
    print(m.group(1))

