import re

test_mac = "ca:34:ea:92:d3:9e"
oui = test_mac[:8]
last = test_mac[15:]
masked = f"{oui}:**:**:{last}"
print(f"Masked MAC: {masked}")

test_ip = "192.168.137.101"
masked_ip = re.sub(r'\.[0-9]+$', '.***', test_ip)
print(f"Masked IP: {masked_ip}")

