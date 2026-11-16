with open('scratch/test_section0_harness.py', 'r', encoding='utf-8') as f:
    text = f.read()

replacements = [
    ("IF uq_cols IS NOT NULL THEN\n                    RAISE EXCEPTION 'Schema Reconciliation Failure: Constraint uq_station_pseudonym on station_pseudonym_map has incompatible definition (found: %, expected: pseudonym_id).', uq_cols;\n                ELSE",
     "IF uq_cols IS NOT NULL AND uq_cols <> 'pseudonym_id' THEN\n                    RAISE EXCEPTION 'Schema Reconciliation Failure: Constraint uq_station_pseudonym on station_pseudonym_map has incompatible definition (found: %, expected: pseudonym_id).', uq_cols;\n                ELSIF uq_cols IS NULL THEN"),
     
    ("IF uq_cols IS NOT NULL THEN\n                    RAISE EXCEPTION 'Schema Reconciliation Failure: Constraint uq_traffic_window_run_mac_epoch on live_traffic_windows has incompatible definition (found: %, expected: run_id,client_mac,bin_start_epoch).', uq_cols;\n                ELSE",
     "IF uq_cols IS NOT NULL AND uq_cols <> 'run_id,client_mac,bin_start_epoch' THEN\n                    RAISE EXCEPTION 'Schema Reconciliation Failure: Constraint uq_traffic_window_run_mac_epoch on live_traffic_windows has incompatible definition (found: %, expected: run_id,client_mac,bin_start_epoch).', uq_cols;\n                ELSIF uq_cols IS NULL THEN"),

    ("IF uq_cols IS NOT NULL THEN\n                    RAISE EXCEPTION 'Schema Reconciliation Failure: Constraint uq_live_alerts_window on live_alerts has incompatible definition (found: %, expected: window_id).', uq_cols;\n                ELSE",
     "IF uq_cols IS NOT NULL AND uq_cols <> 'window_id' THEN\n                    RAISE EXCEPTION 'Schema Reconciliation Failure: Constraint uq_live_alerts_window on live_alerts has incompatible definition (found: %, expected: window_id).', uq_cols;\n                ELSIF uq_cols IS NULL THEN"),

    ("IF uq_cols IS NOT NULL THEN\n                    RAISE EXCEPTION 'Schema Reconciliation Failure: Constraint uq_unknown_mac_run on unknown_device_obs has incompatible definition (found: %, expected: run_id,observed_mac).', uq_cols;\n                ELSE",
     "IF uq_cols IS NOT NULL AND uq_cols <> 'run_id,observed_mac' THEN\n                    RAISE EXCEPTION 'Schema Reconciliation Failure: Constraint uq_unknown_mac_run on unknown_device_obs has incompatible definition (found: %, expected: run_id,observed_mac).', uq_cols;\n                ELSIF uq_cols IS NULL THEN"),

    ("IF uq_cols IS NOT NULL THEN\n                    RAISE EXCEPTION 'Schema Reconciliation Failure: Constraint uq_sensor_telemetry on live_sensor_telemetry has incompatible definition (found: %, expected: run_id,physical_node_id,sequence_num).', uq_cols;\n                ELSE",
     "IF uq_cols IS NOT NULL AND uq_cols <> 'run_id,physical_node_id,sequence_num' THEN\n                    RAISE EXCEPTION 'Schema Reconciliation Failure: Constraint uq_sensor_telemetry on live_sensor_telemetry has incompatible definition (found: %, expected: run_id,physical_node_id,sequence_num).', uq_cols;\n                ELSIF uq_cols IS NULL THEN"),

    ("IF uq_cols IS NOT NULL THEN\n                    RAISE EXCEPTION 'Schema Reconciliation Failure: Constraint uq_pir_events on live_pir_events has incompatible definition (found: %, expected: run_id,physical_node_id,sequence_num).', uq_cols;\n                ELSE",
     "IF uq_cols IS NOT NULL AND uq_cols <> 'run_id,physical_node_id,sequence_num' THEN\n                    RAISE EXCEPTION 'Schema Reconciliation Failure: Constraint uq_pir_events on live_pir_events has incompatible definition (found: %, expected: run_id,physical_node_id,sequence_num).', uq_cols;\n                ELSIF uq_cols IS NULL THEN"),

    ("IF uq_cols IS NOT NULL THEN\n                    RAISE EXCEPTION 'Schema Reconciliation Failure: Constraint uq_attack_event_uuid on live_attack_events has incompatible definition (found: %, expected: event_uuid).', uq_cols;\n                ELSE",
     "IF uq_cols IS NOT NULL AND uq_cols <> 'event_uuid' THEN\n                    RAISE EXCEPTION 'Schema Reconciliation Failure: Constraint uq_attack_event_uuid on live_attack_events has incompatible definition (found: %, expected: event_uuid).', uq_cols;\n                ELSIF uq_cols IS NULL THEN"),
]

for old, new in replacements:
    assert old in text, f'Pattern not found: {old[:50]}'
    text = text.replace(old, new)

with open('scratch/test_section0_harness.py', 'w', encoding='utf-8') as f:
    f.write(text)

print('Updated all 7 constraint checks successfully')
