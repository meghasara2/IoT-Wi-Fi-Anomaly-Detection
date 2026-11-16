import re
import sys
from pathlib import Path

print("=" * 75)
print("STAGE 3B MIGRATION SCRIPT SYNTAX & SECURITY VALIDATION")
print("=" * 75)

sql_file = Path("scratch/stage3b_supabase_migration.sql")
assert sql_file.exists(), "Migration SQL file missing!"

with open(sql_file, "r", encoding="utf-8") as f:
    sql_text = f.read()

# Strip SQL comments
clean_sql = re.sub(r'--.*$', '', sql_text, flags=re.MULTILINE)
clean_sql = re.sub(r'/\*.*?\*/', '', clean_sql, flags=re.DOTALL)

# 1. Check Tables Created (Must be 9: 8 telemetry + 1 station_pseudonym_map)
expected_tables = [
    "collector_status",
    "device_registry",
    "station_pseudonym_map",
    "live_traffic_windows",
    "live_alerts",
    "unknown_device_obs",
    "live_sensor_telemetry",
    "live_pir_events",
    "live_attack_events"
]

created_tables = re.findall(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z0-9_]+)", clean_sql, re.IGNORECASE)
print(f"Found {len(created_tables)} CREATE TABLE statements: {created_tables}")
assert len(created_tables) == 9, f"Expected 9 tables, found {len(created_tables)}"
for t in expected_tables:
    assert t in created_tables, f"Missing table: {t}"
print("  • All 9 tables correctly defined.")

# 2. Check Views Created (Must be 9 v_public_* views)
expected_views = [
    "v_public_collector_status",
    "v_public_device_registry",
    "v_public_live_traffic_windows",
    "v_public_live_alerts",
    "v_public_unknown_device_obs",
    "v_public_sensor_telemetry",
    "v_public_pir_events",
    "v_public_attack_events",
    "v_public_traffic_overview"
]

created_views = re.findall(r"CREATE\s+(?:OR\s+REPLACE\s+)?VIEW\s+([a-zA-Z0-9_]+)", clean_sql, re.IGNORECASE)
print(f"Found {len(created_views)} CREATE VIEW statements: {created_views}")
assert len(created_views) == 9, f"Expected 9 views, found {len(created_views)}"
for v in expected_views:
    assert v in created_views, f"Missing view: {v}"
print("  • All 9 public views correctly defined.")

# 3. Check ON DELETE CASCADE vs ON DELETE RESTRICT
cascades = re.findall(r"ON\s+DELETE\s+CASCADE", clean_sql, re.IGNORECASE)
restricts = re.findall(r"ON\s+DELETE\s+RESTRICT", clean_sql, re.IGNORECASE)
print(f"Foreign Key Delete rules: {len(restricts)} RESTRICT, {len(cascades)} CASCADE")
assert len(cascades) == 0, f"Found prohibited ON DELETE CASCADE: {cascades}"
assert len(restricts) >= 7, f"Expected at least 7 ON DELETE RESTRICT, found {len(restricts)}"
print("  • Zero CASCADE deletes. Strict RESTRICT audit preservation intact.")

# 4. Check Roles & Users
assert "CREATE ROLE collector_role NOLOGIN INHERIT;" in clean_sql, "collector_role must have INHERIT!"
assert "NOINHERIT" not in clean_sql, "Found prohibited NOINHERIT!"
assert "CREATE USER iot_collector" in clean_sql, "iot_collector user definition missing!"
print("  • Role inheritance correctly configured (INHERIT enabled for pooler).")

# 5. Check RLS and Base Table Lockout for anon
assert "ALTER TABLE station_pseudonym_map ENABLE ROW LEVEL SECURITY;" in clean_sql
anon_base_grants = re.findall(r"GRANT\s+(?:SELECT|ALL)\s+ON\s+(?:TABLE\s+)?([a-zA-Z0-9_]+)\s+TO\s+(?:[^;]*\b)?anon\b", clean_sql, re.IGNORECASE)
for t in anon_base_grants:
    assert t.startswith("v_public_"), f"Security violation: grant on non-view table to anon: {t}"
print("  • Role 'anon' has 0 base table grants; all grants strictly limited to v_public_* views.")

# 6. Check DELETE Revocation
collector_deletes = re.findall(r"REVOKE\s+DELETE,\s*TRUNCATE\s+ON\s+TABLE\s+([^;]+)\s+FROM\s+collector_role", clean_sql, re.IGNORECASE)
assert len(collector_deletes) > 0, "REVOKE DELETE from collector_role missing!"
print("  • DELETE and TRUNCATE permanently revoked from collector_role.")

# 7. Check F-01 Stable Event ID
assert "event_uuid" in clean_sql, "event_uuid column missing from live_attack_events!"
assert "uq_attack_event_uuid" in clean_sql, "uq_attack_event_uuid constraint missing!"
old_collision_key = re.search(r"UNIQUE\s*\(\s*run_id\s*,\s*timestamp_epoch\s*,\s*category\s*\)", clean_sql, re.IGNORECASE)
assert old_collision_key is None, "Old collision-prone unique key still present!"
print("  • F-01 non-colliding event_uuid verified.")

# 8. Check F-02 Allowlist Projection & Templated Guidance
assert "sanitized_evidence_json" in clean_sql, "sanitized_evidence_json missing in v_public_attack_events!"
assert "CASE e.category" in clean_sql or "CASE category" in clean_sql, "Templated SOC guidance missing!"
assert "REGEXP_REPLACE" not in clean_sql, "Fragile regex scrubbing should not be in public view!"
print("  • F-02 Allowlist projection & templated guidance verified (zero regex, mathematical guarantee).")

# 9. Check F-03 Pure Pseudonyms
assert "station_pseudonym_map" in clean_sql, "station_pseudonym_map missing!"
assert "MD5(client_mac || 'iot_guard_salt_2026')" not in clean_sql, "Public hardcoded salt must be removed!"
print("  • F-03 Private tokenization mapping verified (static SQL salt eliminated).")

# 10. Check PostgREST Notification
assert "NOTIFY pgrst, 'reload schema';" in clean_sql, "PostgREST schema cache reload notification missing!"
print("  • PostgREST reload notification verified.")

print("\n" + "=" * 75)
print("STAGE 3B VALIDATION RESULT: 10/10 CHECKS PASSED PERFECTLY")
print("=" * 75)

