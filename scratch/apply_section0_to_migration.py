import sys
sys.path.insert(0, 'scratch')
with open('scratch/stage3b_6_final_supabase_migration.sql', 'r', encoding='utf-8') as f:
    sql = f.read()

from test_section0_harness import section0_sql

marker_start = '-- 0. PREFLIGHT SCHEMA RECONCILIATION & IDEMPOTENCY AUDIT'
marker_end = '-- 1. LEAST-PRIVILEGE ROLE & USER ARCHITECTURE (CORRECTION B ENFORCED)'

idx_start = sql.find(marker_start)
idx_end = sql.find(marker_end)

line_start = sql.rfind('-- ------', 0, idx_start)
line_end = sql.rfind('-- ------', 0, idx_end)

new_sql = sql[:line_start] + section0_sql.strip() + '\n\n\n' + sql[line_end:]

with open('scratch/stage3b_6_final_supabase_migration.sql', 'w', encoding='utf-8') as f:
    f.write(new_sql)

print('Updated scratch/stage3b_6_final_supabase_migration.sql successfully')
