import re

with open('src/live_stream_extractor.py', 'r', encoding='utf-8') as f:
    text = f.read()

for m in re.finditer(r'["\']node_id["\'].*?[,\n]', text):
    print(m.group(0).strip())

with open('src/live_stream_extractor.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()
for i, line in enumerate(lines):
    if 'device_registry.get' in line or 'node_id' in line:
        if any(k in line for k in ['Unknown', 'None', 'device_registry', 'resolve', 'node_id =']):
            print(f"{i+1}: {line.strip()}")

