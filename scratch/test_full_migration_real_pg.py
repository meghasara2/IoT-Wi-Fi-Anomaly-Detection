"""
Test executing scratch/stage3b_6_final_supabase_migration.sql on real PostgreSQL 16 standalone instance.
"""
import tempfile
import os
import subprocess
import shutil
from pathlib import Path
from test_pg_runner import parse_sql_statements

def test_migration_execution():
    sql_path = Path("scratch/stage3b_6_final_supabase_migration.sql")
    assert sql_path.exists()
    
    with open(sql_path, "r", encoding="utf-8") as f:
        sql_content = f.read()
        
    stmts = parse_sql_statements(sql_content)
    print(f"Parsed {len(stmts)} statements from {sql_path.name}")
    
    temp_dir = tempfile.mkdtemp(prefix="pg_migration_")
    initdb = r"C:\Program Files\PostgreSQL\16\bin\initdb.exe"
    subprocess.run([initdb, "-D", temp_dir, "-U", "postgres", "--no-locale", "-E", "UTF8"], capture_output=True, check=True)
    
    # In Supabase, postgres extension / roles anon, authenticated, service_role exist by default.
    # For a clean vanilla local postgres, create these roles so Supabase grants succeed:
    bootstrap_sql = """
    CREATE ROLE anon NOLOGIN;
    CREATE ROLE authenticated NOLOGIN;
    CREATE ROLE service_role NOLOGIN;
    """
    bootstrap_stmts = parse_sql_statements(bootstrap_sql)
    
    all_stmts = bootstrap_stmts + stmts
    full_input = "\n".join(all_stmts) + "\n"
    
    postgres_bin = r"C:\Program Files\PostgreSQL\16\bin\postgres.exe"
    res = subprocess.run([postgres_bin, "--single", "-D", temp_dir, "postgres"], input=full_input, capture_output=True, text=True)
    
    print("Return code:", res.returncode)
    if res.returncode != 0:
        print("STDERR:\n", res.stderr)
    else:
        # Check stderr for any errors
        errors = [line for line in res.stderr.splitlines() if "ERROR:" in line or "FATAL:" in line]
        if errors:
            print(f"Found {len(errors)} errors in stderr:")
            for e in errors[:10]:
                print("  ", e)
        else:
            print("Migration executed with ZERO errors in stderr!")
            
    shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == '__main__':
    test_migration_execution()
