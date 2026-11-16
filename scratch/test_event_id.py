import uuid

NAMESPACE_IOT = uuid.UUID("a3b8c4d6-e2f1-4b9a-8c3d-7e5f6a1b2c3d")

def generate_stable_attack_event_id(run_id, local_event_id, timestamp_epoch, category, source_mac=None, target_ip=None, evidence_sig=None):
    raw_str = f"{run_id}:{local_event_id}:{timestamp_epoch:.6f}:{category}:{source_mac or ''}:{target_ip or ''}:{evidence_sig or ''}"
    return str(uuid.uuid5(NAMESPACE_IOT, raw_str))

# Test repeatability
id1 = generate_stable_attack_event_id(1, 42, 1731682800.5, "Reconnaissance_Port_Scan", "ca:34:ea:92:d3:9e", "192.168.137.1")
id2 = generate_stable_attack_event_id(1, 42, 1731682800.5, "Reconnaissance_Port_Scan", "ca:34:ea:92:d3:9e", "192.168.137.1")
print(f"Repeatable ID across retries: {id1 == id2} -> {id1}")

# Test distinct findings in same window
id3 = generate_stable_attack_event_id(1, 43, 1731682800.5, "Reconnaissance_Port_Scan", "ca:34:ea:92:d3:9e", "192.168.137.101")
print(f"Distinct finding has different ID: {id1 != id3} -> {id3}")

