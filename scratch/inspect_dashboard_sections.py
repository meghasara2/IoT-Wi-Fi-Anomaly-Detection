import re

with open('src/live_dashboard.py', 'r', encoding='utf-8') as f:
    text = f.read()

headers = re.findall(r'<div class=[\'"]section-header[\'"][^>]*>(.*?)</div>', text)
print(f"Found {len(headers)} section headers:")
for i, h in enumerate(headers, 1):
    clean = re.sub(r'<[^>]+>', '', h).strip()
    print(f"  {i}. {clean}")

# Also look for st.header or st.subheader
subheaders = re.findall(r'st\.(?:sub)?header\([\'"]([^\'"]+)[\'"]\)', text)
print(f"\nFound {len(subheaders)} st.header/subheader calls:")
for sh in subheaders:
    print(f"  • {sh}")

