#!/usr/bin/env python3
"""
Supabase PostgreSQL Production Connection Verification Script.
File: scripts/test_supabase_connection.py

Purpose:
  Safely verifies the live PostgreSQL connection from this workstation
  to Supabase Managed PostgreSQL via the connection pooler.
  Executes a strictly read-only query to confirm authenticated role,
  PostgreSQL version, and collector permissions without inserting data.
"""

import os
import sys
from pathlib import Path

# Step 1: Load .env from project root
try:
    from dotenv import load_dotenv
    env_file = Path(__file__).resolve().parent.parent / ".env"
    if env_file.exists():
        load_dotenv(dotenv_path=env_file)
    else:
        load_dotenv()
except ImportError:
    # Minimal fallback parser if python-dotenv is absent
    env_file = Path(__file__).resolve().parent.parent / ".env"
    if env_file.exists():
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if k and k not in os.environ:
                        os.environ[k] = v

# Step 2: Validate required environment variables (WITHOUT printing secret values)
REQUIRED_VARS = [
    "SUPABASE_POOLER_HOST",
    "SUPABASE_POOLER_PORT",
    "SUPABASE_DB_NAME",
    "SUPABASE_COLLECTOR_USER",
    "SUPABASE_COLLECTOR_PASSWORD",
]

missing_vars = [var for var in REQUIRED_VARS if not os.getenv(var)]
if missing_vars:
    print(f"ERROR: Missing required environment variables in .env: {', '.join(missing_vars)}")
    sys.exit(1)

host = os.getenv("SUPABASE_POOLER_HOST")
port_str = os.getenv("SUPABASE_POOLER_PORT", "5432")
dbname = os.getenv("SUPABASE_DB_NAME", "postgres")
user = os.getenv("SUPABASE_COLLECTOR_USER")
password = os.getenv("SUPABASE_COLLECTOR_PASSWORD")
sslmode = os.getenv("SUPABASE_SSLMODE", "require")

try:
    port = int(port_str)
except ValueError:
    print(f"ERROR: SUPABASE_POOLER_PORT must be an integer, got: {port_str}")
    sys.exit(1)

print("=" * 70)
print("SUPABASE PRODUCTION POSTGRESQL CONNECTION VERIFICATION")
print("=" * 70)
print(f"Target Host:       {host}")
print(f"Target Port:       {port}")
print(f"Target Database:   {dbname}")
print(f"Target User:       {user}")
print(f"SSL Mode:          {sslmode}")
print(f"Password Status:   CONFIGURED (length: {len(password)} chars)")
print("-" * 70)

# Step 3: Check psycopg2 availability
try:
    import psycopg2
except ImportError:
    print("ERROR: psycopg2 is not installed. Run: pip install psycopg2-binary")
    sys.exit(1)

# Step 4: Establish SSL connection with 15-second timeout
print("Connecting to Supabase PostgreSQL (timeout: 15s)...")
conn = None
try:
    conn = psycopg2.connect(
        host=host,
        port=port,
        dbname=dbname,
        user=user,
        password=password,
        sslmode=sslmode,
        connect_timeout=15,
    )
    conn.autocommit = True
    print("Connection established successfully.")

    # Step 5: Execute read-only verification query
    query = """
    SELECT
        current_database(),
        current_user,
        current_setting('server_version'),
        has_table_privilege(
            current_user,
            'public.collector_status',
            'INSERT'
        );
    """
    with conn.cursor() as cur:
        cur.execute(query)
        row = cur.fetchone()

    if not row:
        print("ERROR: Verification query returned no results.")
        sys.exit(1)

    db_curr, user_curr, version_curr, can_insert = row

    print("-" * 70)
    print("SUCCESS: Connected to Supabase!")
    print(f"Database:                  {db_curr}")
    print(f"Authenticated role:        {user_curr}")
    print(f"PostgreSQL version:        {version_curr}")
    print(f"Collector INSERT permission: {can_insert}")
    print("=" * 70)

    # Verification assertions
    all_ok = True
    if user_curr != "iot_collector":
        print(f"WARNING: Expected authenticated user 'iot_collector', got: '{user_curr}'")
        all_ok = False

    if not version_curr.startswith("17"):
        print(f"WARNING: Expected PostgreSQL 17.x, got: '{version_curr}'")
        # Non-fatal if minor patch differs, but warn

    if not can_insert:
        print("ERROR: Authenticated user lacks INSERT permission on public.collector_status!")
        all_ok = False

    if all_ok:
        print("\n[VERIFICATION PASS] Production connection and permissions verified successfully.")
        sys.exit(0)
    else:
        print("\n[VERIFICATION WARNING] Connected, but one or more assertions failed.")
        sys.exit(2)

except psycopg2.OperationalError as e:
    err_str = str(e).strip()
    print("\n" + "!" * 70)
    print("CONNECTION FAILED (psycopg2.OperationalError):")
    print(f"  {err_str}")
    print("!" * 70)

    # Diagnosis heuristics
    if "timeout" in err_str.lower():
        print("\nDiagnosis: Network connection timed out after 15 seconds.")
        print("  - Check outbound internet connectivity.")
        print("  - Check firewall / network restrictions on port " + str(port) + ".")
        print("  - Note: In sandboxed environments, outbound network access may be restricted.")
    elif "password authentication failed" in err_str.lower():
        print("\nDiagnosis: Password authentication failed for user " + str(user) + ".")
        print("  - Check that ALTER ROLE iot_collector WITH PASSWORD '...' was run in Supabase SQL editor.")
        print("  - Check that SUPABASE_COLLECTOR_PASSWORD in .env matches the configured password.")
    elif "could not translate host name" in err_str.lower() or "nodename nor servname provided" in err_str.lower():
        print("\nDiagnosis: DNS resolution failed for host: " + str(host))
        print("  - Check host name spelling and local DNS resolution.")
    elif "role" in err_str.lower() and "does not exist" in err_str.lower():
        print("\nDiagnosis: Database role does not exist on Supabase.")
        print("  - Check that the Stage 3B.6 migration was executed in Supabase.")
    else:
        print("\nDiagnosis: Review error details above for network, routing, or SSL issues.")

    sys.exit(1)

except Exception as e:
    print(f"\nUNEXPECTED ERROR: {e}")
    sys.exit(1)

finally:
    if conn is not None and not conn.closed:
        conn.close()
        print("Connection closed cleanly.")
