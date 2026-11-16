import re

text = "Investigate host 192.168.137.101 (MAC: ca:34:ea:92:d3:9e) for scanning tools. Verify if endpoint is an authorized administrator. Do NOT automatically disconnect client."

sanitized_mac = re.sub(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', 'PROTECTED_MAC', text)
sanitized_all = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'PROTECTED_IP', sanitized_mac)

print("Original text:")
print(text)
print("\nSanitized text:")
print(sanitized_all)
assert "192.168.137.101" not in sanitized_all
assert "ca:34:ea:92:d3:9e" not in sanitized_all
print("\nAssertion passed: Zero MAC or IP identifiers remain in sanitized text!")

