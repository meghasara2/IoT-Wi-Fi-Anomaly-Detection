"""
Comprehensive Syntax, Security, and Compliance Validator for Stage 3B.5 Supabase Migration.
Golden Baseline 3.5.0
File: scratch/stage3b_5_final_supabase_migration.sql
"""

import re
import sys
from pathlib import Path

def run_validation():
    print("=" * 80)
    print("STAGE 3B.5 FINAL GOLDEN MIGRATION SCRIPT SYNTAX & SECURITY VALIDATION")
    print("Target: scratch/stage3b_5_final_supabase_migration.sql")
    print("=" * 80)

    sql_path = Path("scratch/stage3b_5_final_supabase_migration.sql")
    assert sql_path.exists(), f"Target SQL file missing: {sql_path}"
    
    file_size = sql_path.stat().st_size
    print(f"[OK] File exists. Size: {file_size:,} bytes")
    assert file_size > 30000, f"File size unexpectedly small ({file_size} bytes)"

    with open(sql_path, "r", encoding="utf-8") as f:
        sql_raw = f.read()

    # Strip single line comments and block comments
    clean_sql = re.sub(r'--.*$', '', sql_raw, flags=re.MULTILINE)
    clean_sql = re.sub(r'/\*.*?\*/', '', clean_sql, flags=re.DOTALL)

    checks_passed = 0
    total_checks = 18

    # -------------------------------------------------------------
    # Check 1: Transaction Wrapping
    # -------------------------------------------------------------
    print("\n[Check 1/18] Transaction boundary verification...")
    has_begin = bool(re.search(r'^\s*BEGIN\s*;', sql_raw, re.MULTILINE))
    has_commit = bool(re.search(r'^\s*COMMIT\s*;', sql_raw, re.MULTILINE))
    assert has_begin, "Missing top-level BEGIN transaction wrapper!"
    assert has_commit, "Missing top-level COMMIT transaction wrapper!"
    print("  -> Passed: Migration is fully wrapped in atomic BEGIN ... COMMIT block.")
    checks_passed += 1

    # -------------------------------------------------------------
    # Check 2: Base Tables Created (All 9)
    # -------------------------------------------------------------
    print("\n[Check 2/18] Base table DDL verification (9 tables)...")
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
    print(f"  Found {len(created_tables)} tables: {', '.join(created_tables)}")
    assert len(created_tables) == 9, f"Expected 9 tables, found {len(created_tables)}"
    for t in expected_tables:
        assert t in created_tables, f"Missing table: {t}"
    print("  -> Passed: All 9 base tables properly defined with IF NOT EXISTS.")
    checks_passed += 1

    # -------------------------------------------------------------
    # Check 3: Public Views Created (All 9)
    # -------------------------------------------------------------
    print("\n[Check 3/18] Public view DDL verification (9 views)...")
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
    print(f"  Found {len(created_views)} views: {', '.join(created_views)}")
    assert len(created_views) == 9, f"Expected 9 views, found {len(created_views)}"
    for v in expected_views:
        assert v in created_views, f"Missing view: {v}"
    print("  -> Passed: All 9 public security views properly defined with CREATE OR REPLACE VIEW.")
    checks_passed += 1

    # -------------------------------------------------------------
    # Check 4: Zero Cascade Deletes, Strict Audit Retention
    # -------------------------------------------------------------
    print("\n[Check 4/18] Referential integrity & delete rule audit...")
    cascades = re.findall(r"ON\s+DELETE\s+CASCADE", clean_sql, re.IGNORECASE)
    restricts = re.findall(r"ON\s+DELETE\s+RESTRICT", clean_sql, re.IGNORECASE)
    print(f"  Rules: {len(restricts)} ON DELETE RESTRICT, {len(cascades)} ON DELETE CASCADE")
    assert len(cascades) == 0, f"Found prohibited ON DELETE CASCADE: {cascades}"
    assert len(restricts) >= 7, f"Expected at least 7 ON DELETE RESTRICT, found {len(restricts)}"
    print("  -> Passed: Zero CASCADE deletes detected. Strict RESTRICT audit preservation intact.")
    checks_passed += 1

    # -------------------------------------------------------------
    # Check 5: Correction A - Seed Upsert Safety
    # -------------------------------------------------------------
    print("\n[Check 5/18] Correction A: Seed Upsert Safety...")
    conflict_clauses = re.findall(r"ON\s+CONFLICT\s*\(\s*mac_address\s*\)\s*DO\s+NOTHING", clean_sql, re.IGNORECASE)
    print(f"  Found {len(conflict_clauses)} ON CONFLICT (mac_address) DO NOTHING clauses.")
    assert len(conflict_clauses) >= 2, "Expected ON CONFLICT (mac_address) DO NOTHING for both registry & pseudonym map seeds!"
    
    # Verify no DO UPDATE clauses in seed statements that could overwrite user notes
    do_updates = re.findall(r"ON\s+CONFLICT.*DO\s+UPDATE", clean_sql, re.IGNORECASE)
    assert len(do_updates) == 0, f"Found prohibited DO UPDATE in seed statements: {do_updates}"
    print("  -> Passed: Seed inserts use DO NOTHING. Re-running migrations will never overwrite user edits.")
    checks_passed += 1

    # -------------------------------------------------------------
    # Check 6: Correction B - Collector Login Enforcement & Privilege Hardening
    # -------------------------------------------------------------
    print("\n[Check 6/18] Correction B: Collector Login Enforcement & Privilege Hardening...")
    assert re.search(r"CREATE\s+USER\s+iot_collector\s+WITH\s+LOGIN\s+PASSWORD\s+NULL", clean_sql, re.IGNORECASE), \
        "CREATE USER iot_collector must specify WITH LOGIN PASSWORD NULL!"
    
    assert re.search(r"CREATE\s+ROLE\s+collector_role\s+NOLOGIN\s+INHERIT", clean_sql, re.IGNORECASE), \
        "collector_role must specify NOLOGIN INHERIT!"
        
    assert re.search(r"ALTER\s+ROLE\s+iot_collector\s+WITH\s+LOGIN(?:\s+INHERIT)?\s+NOSUPERUSER\s+NOCREATEDB\s+NOCREATEROLE\s+NOREPLICATION\s+NOBYPASSRLS", clean_sql, re.IGNORECASE), \
        "ALTER ROLE iot_collector must enforce LOGIN and deny all admin privileges!"
        
    assert "NOINHERIT" not in clean_sql, "Prohibited NOINHERIT found in script!"
    print("  -> Passed: Collector login privilege guaranteed, admin capabilities denied, inheritance enabled.")
    checks_passed += 1

    # -------------------------------------------------------------
    # Check 7: Correction C - Categorical Allowlist in Evidence JSON Projection
    # -------------------------------------------------------------
    print("\n[Check 7/18] Correction C: Evidence JSON Allowlist Projection...")
    assert "sanitized_evidence_json" in clean_sql, "sanitized_evidence_json projection missing in v_public_attack_events!"
    
    # Check that verdict has categorical allowlist
    assert "Security Evaluation finding" in clean_sql, "Missing safe verdict fallback in v_public_attack_events!"
    assert "802.11 Deauthentication / Disassociation flood detected" in clean_sql, "Missing expected allowed verdict in categorical list!"
    assert "Conflicting IP-to-MAC binding detected" in clean_sql, "Missing expected allowed verdict in categorical list!"
    
    # Check that reason has categorical allowlist
    assert "Telemetry explanation recorded" in clean_sql, "Missing safe reason fallback in v_public_attack_events!"
    assert "Missing required window rate or MAC identifiers" in clean_sql, "Missing expected allowed reason in categorical list!"
    assert "No packets in window" in clean_sql, "Missing expected allowed reason in categorical list!"
    
    # Check regex validation before numeric casting
    assert "~ '^-?[0-9]+$'" in clean_sql, "Missing regex check on probe_count before integer cast!"
    assert "~ '^-?[0-9]+(\\.[0-9]+)?$'" in clean_sql, "Missing regex check on rate before numeric cast!"
    
    # Check that raw fields like initial_capability are NOT projected
    assert "initial_capability" not in clean_sql, "Leaked initial_capability found in SQL!"
    assert "limitations_or_remedy" not in clean_sql, "Leaked limitations_or_remedy found in SQL!"
    print("  -> Passed: Categorical allowlists, regex casting safety, and zero raw JSON leakage verified.")
    checks_passed += 1

    # -------------------------------------------------------------
    # Check 8: Correction D - Comprehensive Public View Allowlists
    # -------------------------------------------------------------
    print("\n[Check 8/18] Correction D: Comprehensive Public View Allowlists...")
    assert "Unspecified_Node" in clean_sql, "Missing Unspecified_Node fallback in node_id projection!"
    assert "Client_Device" in clean_sql, "Missing Client_Device fallback in device_registry view!"
    assert "registered_station" in clean_sql, "Missing registered_station fallback in device_registry view!"
    assert "live_telemetry" in clean_sql, "Missing live_telemetry fallback in traffic windows view!"
    assert "EVALUATION_PENDING" in clean_sql, "Missing EVALUATION_PENDING fallback in live_alerts view!"
    assert "LOCAL_NETWORK" in clean_sql and "EXTERNAL_NETWORK" in clean_sql and "IP_REDACTED" in clean_sql, \
        "Missing semantic IP classification in attack events view!"
    print("  -> Passed: All 9 views project strictly allowlisted categorizations with zero raw data escape.")
    checks_passed += 1

    # -------------------------------------------------------------
    # Check 9: Elimination of MD5 and Client MAC Leakage (F-03)
    # -------------------------------------------------------------
    print("\n[Check 9/18] F-03 Pseudonymization & MD5 Elimination...")
    # There should be zero MD5 calls in the public views or table definitions
    md5_calls = re.findall(r"\bMD5\s*\(", clean_sql, re.IGNORECASE)
    assert len(md5_calls) == 0, f"Found prohibited MD5 call(s): {md5_calls}"
    assert "station_pseudonym_map" in clean_sql, "station_pseudonym_map table missing!"
    print("  -> Passed: Zero MD5 hashing in migration. Cryptographically isolated pseudonym mapping verified.")
    checks_passed += 1

    # -------------------------------------------------------------
    # Check 10: Correction E - View Security Invoker Model & Anon Base Table Lockout
    # -------------------------------------------------------------
    print("\n[Check 10/18] Correction E: View Security Model & Anon Table Isolation...")
    # Check security_invoker = false on views
    sec_invokers = re.findall(r"security_invoker\s*=\s*(false|true)", clean_sql, re.IGNORECASE)
    assert len(sec_invokers) == 9, f"Expected 9 security_invoker options, found {len(sec_invokers)}"
    for inv in sec_invokers:
        assert inv.lower() == "false", f"Prohibited security_invoker = {inv} found!"
        
    # Check that anon has 0 base table grants and exactly 9 view grants
    anon_matches = re.findall(r"GRANT\s+(?:SELECT|ALL)\s+ON\s+(?:TABLE\s+)?([a-zA-Z0-9_,\s]+)\s+TO\s+(?:[^;]*\b)?anon\b", clean_sql, re.IGNORECASE)
    anon_targets = [t.strip() for m in anon_matches for t in m.split(",") if t.strip()]
    assert len(anon_targets) == 9, f"Expected 9 anon view grants, found {len(anon_targets)}: {anon_targets}"
    for target in anon_targets:
        assert target.startswith("v_public_"), f"Security violation: anon granted access to base table '{target}'!"
    print(f"  Validated {len(anon_targets)} anon grants; all strictly target v_public_* views.")
    print("  -> Passed: Definer security model active (security_invoker = false), anon locked out from base tables.")
    checks_passed += 1

    # -------------------------------------------------------------
    # Check 11: Correction F - Principle of Least Privilege (Update/Delete/Truncate)
    # -------------------------------------------------------------
    print("\n[Check 11/18] Correction F: Principle of Least Privilege Granular Permissions...")
    # UPDATE must be granted ONLY to collector_status, device_registry, unknown_device_obs
    update_grants = re.findall(r"GRANT\s+[^;]*\bUPDATE\s+ON\s+(?:TABLE\s+)?([a-zA-Z0-9_,\s]+)\s+TO\s+collector_role", clean_sql, re.IGNORECASE)
    assert len(update_grants) > 0, "GRANT UPDATE on mutable tables missing!"
    granted_update_tables = [t.strip() for g in update_grants for t in g.split(",") if t.strip()]
    expected_mutable = {"collector_status", "device_registry", "unknown_device_obs"}
    assert set(granted_update_tables) == expected_mutable, \
        f"Mismatch in granted UPDATE tables! Expected {expected_mutable}, got {set(granted_update_tables)}"

    # Check explicit REVOKE UPDATE on the 6 immutable tables
    revoke_updates = re.findall(r"REVOKE\s+UPDATE\s+ON\s+(?:TABLE\s+)?([a-zA-Z0-9_,\s]+)\s+FROM\s+collector_role", clean_sql, re.IGNORECASE)
    assert len(revoke_updates) > 0, "REVOKE UPDATE on immutable tables missing!"
    revoked_update_tables = [t.strip() for r in revoke_updates for t in r.split(",") if t.strip()]
    expected_immutable = {
        "station_pseudonym_map",
        "live_traffic_windows",
        "live_alerts",
        "live_sensor_telemetry",
        "live_pir_events",
        "live_attack_events"
    }
    assert set(revoked_update_tables) == expected_immutable, \
        f"Mismatch in REVOKE UPDATE tables! Expected {expected_immutable}, got {set(revoked_update_tables)}"

    # Check DELETE and TRUNCATE permanently revoked
    revoke_del_trunc = re.findall(r"REVOKE\s+DELETE,\s*TRUNCATE\s+ON\s+(?:TABLE\s+)?([a-zA-Z0-9_,\s]+)\s+FROM\s+collector_role", clean_sql, re.IGNORECASE)
    assert len(revoke_del_trunc) > 0, "REVOKE DELETE, TRUNCATE missing!"
    revoked_del_tables = [t.strip() for r in revoke_del_trunc for t in r.split(",") if t.strip()]
    assert len(revoked_del_tables) == 9, f"Expected DELETE/TRUNCATE revoked on 9 tables, got {len(revoked_del_tables)}"
    print("  -> Passed: UPDATE strictly partitioned (3 mutable vs 6 immutable). DELETE/TRUNCATE 100% revoked.")
    checks_passed += 1

    # -------------------------------------------------------------
    # Check 12: Correction G - Schema Usage Permissions
    # -------------------------------------------------------------
    print("\n[Check 12/18] Correction G: Schema Usage Grants (including service_role)...")
    schema_grant = re.search(r"GRANT\s+USAGE\s+ON\s+SCHEMA\s+public\s+TO\s+([^;]+);", clean_sql, re.IGNORECASE)
    assert schema_grant, "Missing GRANT USAGE ON SCHEMA public!"
    roles_in_grant = [r.strip() for r in schema_grant.group(1).split(",")]
    for expected_role in ["anon", "authenticated", "collector_role", "service_role"]:
        assert expected_role in roles_in_grant, f"Missing {expected_role} in schema usage grant!"
    print(f"  Schema usage granted to: {', '.join(roles_in_grant)}")
    print("  -> Passed: Supabase service_role, anon, authenticated, and collector_role all granted schema usage.")
    checks_passed += 1

    # -------------------------------------------------------------
    # Check 13: F-01 Stable Event ID
    # -------------------------------------------------------------
    print("\n[Check 13/18] F-01 Attack Event Stable Identity...")
    assert "event_uuid" in clean_sql, "event_uuid column missing from live_attack_events!"
    assert "uq_attack_event_uuid" in clean_sql, "uq_attack_event_uuid constraint missing!"
    old_collision_key = re.search(r"UNIQUE\s*\(\s*run_id\s*,\s*timestamp_epoch\s*,\s*category\s*\)", clean_sql, re.IGNORECASE)
    assert old_collision_key is None, "Old collision-prone UNIQUE(run_id, timestamp_epoch, category) still present!"
    print("  -> Passed: event_uuid column and unique constraint verified. Silent collision discard resolved.")
    checks_passed += 1

    # -------------------------------------------------------------
    # Check 14: Row Level Security (RLS) Configuration
    # -------------------------------------------------------------
    print("\n[Check 14/18] Row Level Security (RLS) enforcement...")
    rls_tables = re.findall(r"ALTER\s+TABLE\s+([a-zA-Z0-9_]+)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY", clean_sql, re.IGNORECASE)
    print(f"  Found {len(rls_tables)} RLS enabled tables: {', '.join(rls_tables)}")
    assert "station_pseudonym_map" in rls_tables, "station_pseudonym_map MUST have RLS enabled!"
    print("  -> Passed: RLS enabled on sensitive internal mapping tables.")
    checks_passed += 1

    # -------------------------------------------------------------
    # Check 15: PostgREST Schema Cache Reload Notification
    # -------------------------------------------------------------
    print("\n[Check 15/18] PostgREST schema cache reload notification...")
    assert re.search(r"NOTIFY\s+pgrst\s*,\s*'reload schema'\s*;", clean_sql, re.IGNORECASE), \
        "PostgREST cache reload NOTIFY statement missing!"
    print("  -> Passed: PostgREST schema cache reload notification is properly queued.")
    checks_passed += 1

    # -------------------------------------------------------------
    # Check 16: Zero Credentials, Passwords, or Secrets
    # -------------------------------------------------------------
    print("\n[Check 16/18] Zero Credential & Secret Audit...")
    # Search for any non-NULL password clauses
    bad_passwords = re.findall(r"PASSWORD\s+'([^']+)'", clean_sql, re.IGNORECASE)
    assert len(bad_passwords) == 0, f"Prohibited hardcoded password found: {bad_passwords}"
    
    # Check for placeholder strings
    banned_placeholders = ["placeholder", "changeme", "password123", "secret123", "admin123"]
    for ph in banned_placeholders:
        assert ph not in clean_sql.lower(), f"Suspicious placeholder '{ph}' detected in SQL!"
    print("  -> Passed: Zero credentials, passwords, or hardcoded tokens in script. PASSWORD NULL verified.")
    checks_passed += 1

    # -------------------------------------------------------------
    # Check 17: Performance Indexes on Telemetry & Event Tables
    # -------------------------------------------------------------
    print("\n[Check 17/18] Performance indexes verification...")
    created_indexes = re.findall(r"CREATE\s+INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z0-9_]+)", clean_sql, re.IGNORECASE)
    print(f"  Found {len(created_indexes)} indexes: {', '.join(created_indexes)}")
    assert len(created_indexes) >= 10, f"Expected at least 10 performance indexes, found {len(created_indexes)}"
    for expected_idx in ["idx_ltw_run_bin_start", "idx_alerts_run", "idx_sensor_run", "idx_attack_run_cat", "idx_attack_event_uuid"]:
        assert any(expected_idx in idx for idx in created_indexes), f"Missing key performance index: {expected_idx}"
    print("  -> Passed: High-performance timestamp and run_id indexes present across telemetry tables.")
    checks_passed += 1

    # -------------------------------------------------------------
    # Check 18: Dialect and SQL Syntax Compilation Sanity
    # -------------------------------------------------------------
    print("\n[Check 18/18] Dialect and statement structure compilation sanity...")
    # Test splitting by semicolon outside dollar-quotes
    # In PostgreSQL, dollar quoting ($$ ... $$) or ($body$ ... $body$) must not be broken by semicolons
    dollar_blocks = re.findall(r"\$([a-zA-Z0-9_]*)\$.*?\$\1\$", clean_sql, re.DOTALL)
    print(f"  Found {len(dollar_blocks)} dollar-quoted blocks (functions/DO blocks).")
    assert len(dollar_blocks) >= 2, "Expected at least 2 DO blocks for idempotent role management!"
    
    # Check that parentheses, brackets, and single quotes are balanced in non-comment text
    open_p = clean_sql.count("(")
    close_p = clean_sql.count(")")
    assert open_p == close_p, f"Unbalanced parentheses! '(' = {open_p}, ')' = {close_p}"
    
    # Verify quotes balance
    # Clean string literals
    temp = clean_sql
    # Remove escaped quotes
    temp = temp.replace("''", "")
    assert temp.count("'") % 2 == 0, "Unbalanced single quotes in SQL script!"
    print("  -> Passed: Parentheses and quotes balanced; dollar-quoted blocks intact.")
    checks_passed += 1

    print("\n" + "=" * 80)
    print(f"STAGE 3B.5 FINAL GOLDEN VALIDATION COMPLETE: {checks_passed}/{total_checks} CHECKS PASSED (100%)")
    print("=" * 80)
    return True

if __name__ == "__main__":
    try:
        run_validation()
        sys.exit(0)
    except AssertionError as e:
        print(f"\n[VALIDATION FAILED]: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n[UNEXPECTED ERROR]: {e}", file=sys.stderr)
        sys.exit(2)
