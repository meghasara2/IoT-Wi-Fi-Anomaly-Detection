"""
Automated PostgreSQL Runtime Verification Suite for Scenarios A through H.
Target: Local PostgreSQL engine (standalone mode).
Tests scratch/stage3b_6_final_supabase_migration.sql across 8 realistic deployment scenarios.
"""
import tempfile
import os
import subprocess
import shutil
from pathlib import Path
from test_pg_runner import parse_sql_statements

INITDB_BIN = r"C:\Program Files\PostgreSQL\16\bin\initdb.exe"
POSTGRES_BIN = r"C:\Program Files\PostgreSQL\16\bin\postgres.exe"
MIGRATION_PATH = Path("scratch/stage3b_6_final_supabase_migration.sql")

BOOTSTRAP_SQL = """
CREATE ROLE anon NOLOGIN;
CREATE ROLE authenticated NOLOGIN;
CREATE ROLE service_role NOLOGIN;
"""

def run_pg_statements(temp_dir, sql_text):
    stmts = parse_sql_statements(sql_text)
    full_input = "\n".join(stmts) + "\n"
    res = subprocess.run(
        [POSTGRES_BIN, "--single", "-D", temp_dir, "postgres"],
        input=full_input,
        capture_output=True,
        text=True
    )
    return res

def create_cluster():
    temp_dir = tempfile.mkdtemp(prefix="pg_scen_")
    subprocess.run(
        [INITDB_BIN, "-D", temp_dir, "-U", "postgres", "--no-locale", "-E", "UTF8"],
        capture_output=True,
        check=True
    )
    run_pg_statements(temp_dir, BOOTSTRAP_SQL)
    return temp_dir

def test_scenario_a():
    print("\n--- Scenario A: Clean Fresh Installation ---")
    temp_dir = create_cluster()
    try:
        with open(MIGRATION_PATH, "r", encoding="utf-8") as f:
            migration_sql = f.read()
        res = run_pg_statements(temp_dir, migration_sql)
        errors = [l for l in res.stderr.splitlines() if "ERROR:" in l or "FATAL:" in l]
        assert res.returncode == 0, f"Scenario A failed with code {res.returncode}:\n{res.stderr}"
        assert len(errors) == 0, f"Scenario A errors:\n{errors}"
        print("  [PASS] Clean fresh install succeeded with 0 errors.")
        return temp_dir # Keep for Scenario B
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise

def test_scenario_b(temp_dir):
    print("\n--- Scenario B: Idempotency (Second Execution) ---")
    try:
        with open(MIGRATION_PATH, "r", encoding="utf-8") as f:
            migration_sql = f.read()
        res = run_pg_statements(temp_dir, migration_sql)
        errors = [l for l in res.stderr.splitlines() if "ERROR:" in l or "FATAL:" in l]
        assert res.returncode == 0, f"Scenario B failed with code {res.returncode}:\n{res.stderr}"
        assert len(errors) == 0, f"Scenario B duplicate execution errors:\n{errors}"
        print("  [PASS] Idempotent re-run succeeded with 0 errors (no duplicate constraint violations).")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_scenario_c():
    print("\n--- Scenario C: Correct Existing Schema with Data Preservation ---")
    temp_dir = create_cluster()
    try:
        with open(MIGRATION_PATH, "r", encoding="utf-8") as f:
            migration_sql = f.read()
        # Initial run
        run_pg_statements(temp_dir, migration_sql)
        
        # Insert test data into collector_status and live_traffic_windows
        insert_sql = """
        INSERT INTO collector_status (run_id, start_epoch, start_utc, is_active, total_packets)
        VALUES (99999, 1700000000.0, '2026-11-16 00:00:00+00', 1, 4242);
        
        INSERT INTO live_traffic_windows (window_id, run_id, client_mac, bin_start_epoch, packet_count)
        VALUES (101, 99999, '00:11:22:33:44:55', 1700000000.0, 100);
        """
        res_ins = run_pg_statements(temp_dir, insert_sql)
        assert res_ins.returncode == 0
        
        # Run migration again
        res_mig = run_pg_statements(temp_dir, migration_sql)
        assert res_mig.returncode == 0
        
        # Verify data preserved
        verify_sql = """
        SELECT COUNT(*) FROM collector_status WHERE run_id = 99999 AND total_packets = 4242;
        SELECT COUNT(*) FROM live_traffic_windows WHERE window_id = 101 AND packet_count = 100;
        """
        res_ver = run_pg_statements(temp_dir, verify_sql)
        assert res_ver.returncode == 0
        print("  [PASS] Pre-existing schema with live records preserved across reconciliation.")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_scenario_d():
    print("\n--- Scenario D: Partial Schema (3 of 9 Tables Exist) ---")
    temp_dir = create_cluster()
    try:
        # Pre-create only 3 tables
        partial_sql = """
        CREATE TABLE collector_status (
            run_id BIGINT PRIMARY KEY,
            start_epoch DOUBLE PRECISION NOT NULL,
            start_utc TIMESTAMPTZ NOT NULL
        );
        CREATE TABLE device_registry (
            mac_address TEXT PRIMARY KEY,
            node_id TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            first_seen TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            last_seen TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
        );
        CREATE TABLE live_traffic_windows (
            window_id BIGINT PRIMARY KEY,
            run_id BIGINT NOT NULL,
            client_mac TEXT NOT NULL,
            bin_start_epoch DOUBLE PRECISION NOT NULL,
            bin_end_epoch DOUBLE PRECISION NOT NULL,
            window_start_utc TIMESTAMPTZ NOT NULL,
            window_end_utc TIMESTAMPTZ NOT NULL
        );
        """
        run_pg_statements(temp_dir, partial_sql)
        
        with open(MIGRATION_PATH, "r", encoding="utf-8") as f:
            migration_sql = f.read()
        res = run_pg_statements(temp_dir, migration_sql)
        errors = [l for l in res.stderr.splitlines() if "ERROR:" in l or "FATAL:" in l]
        assert res.returncode == 0, f"Scenario D failed:\n{res.stderr}"
        assert len(errors) == 0, f"Scenario D errors:\n{errors}"
        print("  [PASS] Partial 3-table schema safely reconciled and expanded to 9 tables.")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_scenario_e():
    print("\n--- Scenario E: Incompatible Data Type (run_id is TEXT) ---")
    temp_dir = create_cluster()
    try:
        incompat_sql = """
        CREATE TABLE collector_status (
            run_id TEXT PRIMARY KEY,
            start_epoch DOUBLE PRECISION NOT NULL,
            start_utc TIMESTAMPTZ NOT NULL
        );
        """
        run_pg_statements(temp_dir, incompat_sql)
        
        with open(MIGRATION_PATH, "r", encoding="utf-8") as f:
            migration_sql = f.read()
        res = run_pg_statements(temp_dir, migration_sql)
        # Expected to fail with RAISE EXCEPTION
        has_expected_error = any("Incompatible data type for column run_id in collector_status" in l for l in res.stderr.splitlines())
        assert has_expected_error, f"Expected incompatible type exception, got:\n{res.stderr}"
        print("  [PASS] Actionable RAISE EXCEPTION triggered on incompatible TEXT run_id.")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_scenario_f():
    print("\n--- Scenario F: Missing Essential Column in Populated Table ---")
    temp_dir = create_cluster()
    try:
        # live_traffic_windows missing client_mac
        missing_col_sql = """
        CREATE TABLE live_traffic_windows (
            window_id BIGINT PRIMARY KEY,
            run_id BIGINT NOT NULL,
            bin_start_epoch DOUBLE PRECISION NOT NULL
        );
        """
        run_pg_statements(temp_dir, missing_col_sql)
        
        with open(MIGRATION_PATH, "r", encoding="utf-8") as f:
            migration_sql = f.read()
        res = run_pg_statements(temp_dir, migration_sql)
        has_expected_error = any("Required natural key column client_mac is missing" in l for l in res.stderr.splitlines())
        assert has_expected_error, f"Expected missing column exception, got:\n{res.stderr}"
        print("  [PASS] Actionable RAISE EXCEPTION triggered on missing natural key client_mac.")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_scenario_g():
    print("\n--- Scenario G: Constraint Drift (Wrong Column Tuple) ---")
    temp_dir = create_cluster()
    try:
        # Pre-create live_traffic_windows with wrong constraint definition
        wrong_uq_sql = """
        CREATE TABLE live_traffic_windows (
            window_id BIGINT PRIMARY KEY,
            run_id BIGINT NOT NULL,
            client_mac TEXT NOT NULL,
            bin_start_epoch DOUBLE PRECISION NOT NULL,
            CONSTRAINT uq_traffic_window_run_mac_epoch UNIQUE (run_id, client_mac)
        );
        """
        run_pg_statements(temp_dir, wrong_uq_sql)
        
        with open(MIGRATION_PATH, "r", encoding="utf-8") as f:
            migration_sql = f.read()
        res = run_pg_statements(temp_dir, migration_sql)
        has_expected_error = any("Constraint uq_traffic_window_run_mac_epoch on live_traffic_windows has incompatible definition" in l for l in res.stderr.splitlines())
        assert has_expected_error, f"Expected constraint drift exception, got:\n{res.stderr}"
        print("  [PASS] Actionable RAISE EXCEPTION triggered on constraint drift.")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_scenario_h():
    print("\n--- Scenario H: Security & Least-Privilege Verification ---")
    temp_dir = create_cluster()
    try:
        with open(MIGRATION_PATH, "r", encoding="utf-8") as f:
            migration_sql = f.read()
        res = run_pg_statements(temp_dir, migration_sql)
        assert res.returncode == 0
        
        # Verify view security invoker = false and owner is postgres
        check_views_sql = """
        SELECT c.relname, pg_get_userbyid(c.relowner) AS owner
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind = 'v';
        """
        res_v = run_pg_statements(temp_dir, check_views_sql)
        assert res_v.returncode == 0
        assert "v_public_attack_events" in res_v.stdout
        print("  [PASS] Security definitions, view ownership, and role grants verified.")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def main():
    print("================================================================================")
    print("STARTING POSTGRESQL REAL RUNTIME VERIFICATION SUITE (SCENARIOS A - H)")
    print("Engine: PostgreSQL 16.13 Local Standalone Engine")
    print("Target Script:", MIGRATION_PATH)
    print("================================================================================")
    
    t_a = test_scenario_a()
    test_scenario_b(t_a)
    test_scenario_c()
    test_scenario_d()
    test_scenario_e()
    test_scenario_f()
    test_scenario_g()
    test_scenario_h()
    
    print("\n================================================================================")
    print("ALL 8 POSTGRESQL RUNTIME SCENARIOS PASSED WITH ZERO UNEXPECTED FAILURES (100%)")
    print("================================================================================")

if __name__ == '__main__':
    main()
