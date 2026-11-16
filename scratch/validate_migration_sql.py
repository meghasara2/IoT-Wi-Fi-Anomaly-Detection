import re
from pathlib import Path

sql_path = Path("scratch/stage2_supabase_migration.sql")
with open(sql_path, "r", encoding="utf-8") as f:
    sql = f.read()

# Check balanced parentheses
open_p = sql.count("(")
close_p = sql.count(")")
print(f"Parentheses: {open_p} open, {close_p} close. Balanced: {open_p == close_p}")

# List table names created
tables = re.findall(r"CREATE TABLE IF NOT EXISTS\s+([a-zA-Z0-9_]+)", sql)
print(f"Tables created ({len(tables)}): {tables}")

# List views created
views = re.findall(r"CREATE OR REPLACE VIEW\s+([a-zA-Z0-9_]+)", sql)
print(f"Views created ({len(views)}): {views}")

# List policies created
policies = re.findall(r'CREATE POLICY\s+"([^"]+)"', sql)
print(f"Policies created ({len(policies)}): {policies}")

# Check unique constraints
uniques = re.findall(r"CONSTRAINT\s+([a-zA-Z0-9_]+)\s+UNIQUE", sql)
print(f"Unique constraints ({len(uniques)}): {uniques}")

# Check check constraints
checks = re.findall(r"CONSTRAINT\s+([a-zA-Z0-9_]+)\s+CHECK", sql)
print(f"Check constraints ({len(checks)}): {checks}")

# Check foreign keys
fks = re.findall(r"REFERENCES\s+([a-zA-Z0-9_]+)\(([a-zA-Z0-9_]+)\)", sql)
print(f"Foreign keys ({len(fks)}): {fks}")

