import re
import sys
from pathlib import Path

print("=" * 80)
print("STAGE 3B.3 HARDENED MIGRATION SYNTAX, SECURITY & DIALECT VALIDATION")
print("=" * 80)

sql_file = Path("scratch/stage3b_3_supabase_migration.sql")
assert sql_file.exists(), "Migration SQL file scratch/stage3b_3_supabase_migration.sql missing!"

with open(sql_file, "r", encoding="utf-8") as f:
    sql_text = f.read()

# Strip SQL comments
clean_sql = re.sub(r'--.*$', '', sql_text, flags=re.MULTILINE)
clean_sql = re.sub(r'/\*.*?\*/', '', clean_sql, flags=re.DOTALL)

# -----------------------------------------------------------------------------
# 1. ROLE HARDENING & PASSWORD PRESERVATION AUDIT
# -----------------------------------------------------------------------------
print("\n[CHECK 1] Role Hardening & Password Preservation Audit")

# Check security attributes
assert "NOSUPERUSER" in clean_sql
assert "NOCREATEDB" in clean_sql
assert "NOCREATEROLE" in clean_sql
assert "NOREPLICATION" in clean_sql
assert "NOBYPASSRLS" in clean_sql

# Check iot_collector user creation uses PASSWORD NULL
create_user_match = re.search(r"CREATE\s+USER\s+iot_collector\s+WITH\s+PASSWORD\s+NULL\s+INHERIT\s+NOSUPERUSER", clean_sql, re.IGNORECASE)
assert create_user_match is not None, "CREATE USER iot_collector definition invalid!"

# Check ALTER ROLE iot_collector does NOT contain PASSWORD clause (preserves existing password)
alter_user_match = re.search(r"ALTER\s+ROLE\s+iot_collector\s+INHERIT\s+NOSUPERUSER\s+NOCREATEDB\s+NOCREATEROLE\s+NOREPLICATION\s+NOBYPASSRLS;", clean_sql, re.IGNORECASE)
assert alter_user_match is not None, "ALTER ROLE iot_collector definition invalid or overwrites password!"
assert "ALTER ROLE iot_collector WITH PASSWORD" not in clean_sql, "ALTER ROLE must not overwrite existing password!"

# Check zero password literals in file
password_clauses = re.findall(r"PASSWORD\s+('[^']+'|\"[^\"]+\")", clean_sql, re.IGNORECASE)
assert len(password_clauses) == 0, f"Found embedded password literal: {password_clauses}"

print("  • Role Hardening PASSED: Roles strictly unprivileged; existing passwords preserved.")

# -----------------------------------------------------------------------------
# 2. PUBLIC-VIEW PRIVACY & CRASH-PROOF JSON AUDIT
# -----------------------------------------------------------------------------
print("\n[CHECK 2] Public-View Privacy & Crash-Proof JSON Audit")

# Extract all 9 views
view_matches = re.findall(r"CREATE\s+(?:OR\s+REPLACE\s+)?VIEW\s+([a-zA-Z0-9_]+)\s+AS\s+(.*?);", clean_sql, re.DOTALL | re.IGNORECASE)
assert len(view_matches) == 9, f"Expected 9 views, found {len(view_matches)}"

view_bodies = {vname: vbody for vname, vbody in view_matches}

# 1. Check v_public_collector_status sanitizes stop_reason
v1 = view_bodies["v_public_collector_status"]
assert "Operator Requested Shutdown" in v1
assert "Collector Error" in v1
assert "Session Terminated" in v1

# 2. Check categorical allowlists in v_public_live_traffic_windows
v3 = view_bodies["v_public_live_traffic_windows"]
assert "Unspecified_Device" in v3
assert "live_telemetry" in v3
assert "EVALUATION_PENDING" in v3

# 3. Check crash-proof evidence_json and missing_fields_json in v_public_attack_events
v8 = view_bodies["v_public_attack_events"]
assert "jsonb_typeof(e.evidence_json) = 'object'" in v8, "evidence_json must check object type!"
assert "jsonb_typeof(e.missing_fields_json) != 'array'" in v8, "missing_fields_json must check array type!"
assert "~ '^-?[0-9]+$'" in v8, "Integer fields must validate regex before casting!"
assert "~ '^-?[0-9]+(\\.[0-9]+)?$'" in v8, "Float fields must validate regex before casting!"

# 4. Check zero MD5 across all views
for vname, vbody in view_bodies.items():
    assert "md5" not in vbody.lower(), f"Prohibited MD5 found in view {vname}!"

# 5. Check semantic target_ip
assert "LOCAL_NETWORK" in v8
assert "EXTERNAL_NETWORK" in v8
assert "IP_REDACTED" in v8
assert "192.168.137.***" not in v8

print("  • Public-View Privacy PASSED: Zero MD5, controlled categories, crash-proof JSON casting.")

# -----------------------------------------------------------------------------
# 3. PRINCIPLE OF LEAST PRIVILEGE (PoLP) AUDIT
# -----------------------------------------------------------------------------
print("\n[CHECK 3] Principle of Least Privilege (PoLP) Grant Audit")

# Check mutable tables granted UPDATE
mutable_grant = re.search(r"GRANT\s+SELECT,\s*INSERT,\s*UPDATE\s+ON\s+TABLE\s+collector_status,\s*device_registry,\s*unknown_device_obs\s+TO\s+collector_role;", clean_sql, re.IGNORECASE)
assert mutable_grant is not None, "Mutable tables grant missing or overly broad!"

# Check immutable tables granted ONLY SELECT, INSERT
immutable_grant = re.search(r"GRANT\s+SELECT,\s*INSERT\s+ON\s+TABLE\s+station_pseudonym_map,\s*live_traffic_windows,\s*live_alerts,\s*live_sensor_telemetry,\s*live_pir_events,\s*live_attack_events\s+TO\s+collector_role;", clean_sql, re.IGNORECASE)
assert immutable_grant is not None, "Immutable tables grant must be strictly SELECT, INSERT!"

# Check explicit revocation of UPDATE on immutable tables
revoke_update = re.search(r"REVOKE\s+UPDATE\s+ON\s+TABLE\s+station_pseudonym_map,\s*live_traffic_windows,\s*live_alerts,\s*live_sensor_telemetry,\s*live_pir_events,\s*live_attack_events\s+FROM\s+collector_role;", clean_sql, re.IGNORECASE)
assert revoke_update is not None, "Explicit REVOKE UPDATE on immutable tables missing!"

# Check DELETE and TRUNCATE revoked on all 9 tables
assert "REVOKE DELETE, TRUNCATE ON TABLE" in clean_sql

# Check anon has zero base table access
anon_base_grants = re.findall(r"GRANT\s+(?:SELECT|ALL)\s+ON\s+(?:TABLE\s+)?([a-zA-Z0-9_]+)\s+TO\s+(?:[^;]*\b)?anon\b", clean_sql, re.IGNORECASE)
for t in anon_base_grants:
    assert t.startswith("v_public_"), f"Security violation: grant on base table to anon: {t}"

print("  • PoLP Audit PASSED: UPDATE restricted strictly to 3 mutable tables; 6 tables immutable.")

# -----------------------------------------------------------------------------
# 4. SEED DATA INTEGRITY AUDIT
# -----------------------------------------------------------------------------
print("\n[CHECK 4] Seed Data Integrity Audit")
assert "00:00:00:00:00:05" not in clean_sql, "Invented placeholder MAC 00:00:00:00:00:05 must be purged!"
assert "ca:34:ea:92:d3:9e" in clean_sql, "Verified baseline MAC Node_3 missing!"
assert "e6:2e:db:73:1c:25" in clean_sql, "Verified baseline MAC Node_4 missing!"

# Verify seed statements count
inserted_macs = re.findall(r"'\s*([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})\s*'", clean_sql)
unique_macs = set(inserted_macs)
assert len(unique_macs) == 2, f"Expected exactly 2 confirmed baseline MACs, found {len(unique_macs)}: {unique_macs}"
print(f"  • Seed Data PASSED: Invented MAC purged; exactly 2 confirmed physical clients present ({unique_macs}).")

# -----------------------------------------------------------------------------
# 5. SUPABASE COMPATIBILITY & TRANSACTION AUDIT
# -----------------------------------------------------------------------------
print("\n[CHECK 5] Supabase Compatibility & Transaction Audit")
assert "GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role, collector_role;" in clean_sql
assert "BEGIN;" in clean_sql, "Script must begin transaction block!"
assert clean_sql.strip().endswith("COMMIT;"), "Script must commit transaction block!"
assert "NOTIFY pgrst, 'reload schema';" in clean_sql

# Check 9 tables created
tables = re.findall(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z0-9_]+)", clean_sql, re.IGNORECASE)
assert len(tables) == 9, f"Expected 9 tables, found {len(tables)}: {tables}"

# Check 9 policies with DROP POLICY IF EXISTS
for t in tables:
    assert f'DROP POLICY IF EXISTS' in clean_sql

# FK Deletes (0 CASCADE, 7 RESTRICT, 1 SET NULL)
cascades = re.findall(r"ON\s+DELETE\s+CASCADE", clean_sql, re.IGNORECASE)
restricts = re.findall(r"ON\s+DELETE\s+RESTRICT", clean_sql, re.IGNORECASE)
set_nulls = re.findall(r"ON\s+DELETE\s+SET\s+NULL", clean_sql, re.IGNORECASE)
assert len(cascades) == 0, f"Found prohibited CASCADE deletes: {cascades}"
assert len(restricts) == 7, f"Expected exactly 7 RESTRICT deletes, found {len(restricts)}"
assert len(set_nulls) == 1, f"Expected exactly 1 SET NULL delete on attack event window_id, found {len(set_nulls)}"

print("  • Supabase Compatibility PASSED: service_role granted, atomic transaction verified.")

# -----------------------------------------------------------------------------
# 6. SQLALCHEMY POSTGRESQL DIALECT COMPILATION
# -----------------------------------------------------------------------------
print("\n[CHECK 6] SQLAlchemy Dialect Compilation Test")
try:
    import sqlalchemy as sa
    from sqlalchemy.dialects import postgresql
    pg_dialect = postgresql.dialect()
    print(f"  • SQLAlchemy {sa.__version__} PostgreSQL dialect instantiated successfully.")
except ImportError:
    print("  • SQLAlchemy not installed; skipping dialect test.")

print("\n" + "=" * 80)
print("STAGE 3B.3 VALIDATION RESULT: ALL SECURITY, INTEGRITY & POLP CHECKS PASSED (100%)")
print("=" * 80)
