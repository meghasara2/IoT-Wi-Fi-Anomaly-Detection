# Test Allowlist Action Generation
categories = [
    'Denial_of_Service',
    'Reconnaissance_Port_Scan',
    'Spoofing_Impersonation',
    'Deauthentication_Disassociation_Abuse',
    'Replay_Attack'
]

def get_public_action(category):
    actions = {
        'Denial_of_Service': 'Inspect high-rate traffic flow and rate-limit source endpoint if unauthorized.',
        'Reconnaissance_Port_Scan': 'Inspect transport-layer probing activity and verify if scanning host is an authorized network administrator.',
        'Spoofing_Impersonation': 'Audit IP-to-MAC gateway binding table and inspect physical switch/AP port for conflicting ARP claims.',
        'Deauthentication_Disassociation_Abuse': 'Audit 802.11 management frames for 802.11w Protected Management Frames (PMF) enforcement.',
        'Replay_Attack': 'Inspect packet sequence counters and verify transport-layer TLS/crypto nonce validation.'
    }
    return actions.get(category, 'Review security alert triage logs.')

import re
for cat in categories:
    act = get_public_action(cat)
    print(f"{cat}: {act}")
    # Verify zero IPs, zero MACs
    assert not re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', act)
    assert not re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', act)

print("\nAllowlist Action verification passed 100%!")

