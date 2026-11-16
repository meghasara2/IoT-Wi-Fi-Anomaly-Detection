"""
Generator script for Stage 3B.6 Golden Supabase Migration.
Baseline 3.6.0
Applies all 5 required security corrections to stage3b_5_final_supabase_migration.sql:
1. Public station identifier: strictly mapped in v_public_device_registry (no raw node_id exposure).
2. Pseudonym validation: strict allowlist across all public views (zero raw MAC or unvetted fallback).
3. Numeric evidence safety: bounds-checked regex (^[0-9]{1,9}$ for int, ^[0-9]{1,8}(\\.[0-9]{1,4})?$ for float) preventing overflow/crashes.
4. View ownership: explicit ALTER VIEW ... OWNER TO postgres for all 9 views.
5. Schema idempotency: preflight schema reconciliation block distinguishing fresh install from upgrade.
"""

import re
from pathlib import Path

def generate_stage3b_6():
    src_path = Path("scratch/stage3b_5_final_supabase_migration.sql")
    dst_path = Path("scratch/stage3b_6_final_supabase_migration.sql")
    
    assert src_path.exists(), f"Source file {src_path} does not exist"
    
    with open(src_path, "r", encoding="utf-8") as f:
        sql = f.read()

    # 1. Update header comments and baseline version
    header_old = """-- =============================================================================
-- IoT Network Guard — Dual-Detector SOC Console
-- Stage 3B.5: Golden Cloud Schema Migration (Production Baseline 3.5.0)
-- File: scratch/stage3b_5_final_supabase_migration.sql
-- 
-- Target Platform: Supabase Managed PostgreSQL (Region: ap-south-1 / Mumbai)
-- Target Project Reference: cwqumhtzeiqrfhlesksw
-- Target PostgreSQL Version: 17.6
-- Schema Baseline: 3.5.0 (Definitive Golden Security & Integrity Baseline)
-- 
-- Summary of Stage 3B.5 Architectural & Security Corrections:
--   1. [Correction A - Seed Upsert Safety]: Changed seed statements from 'DO UPDATE'
--      to 'ON CONFLICT (mac_address) DO NOTHING'. Re-running the migration will NEVER
--      overwrite operator-customized device labels, notes, or pseudonym tokens.
--   2. [Correction B - Collector LOGIN Enforcement]: Explicitly enforced 'LOGIN' on
--      iot_collector in both creation and ALTER branches, guaranteeing login capability
--      while preserving pre-existing passwords on rerun without replacement.
--   3. [Correction C - Categorical Evidence Projections]: Replaced free-form strings
--      ('verdict', 'reason') in sanitized_evidence_json with strict categorical allowlists.
--      Purged unused 'initial_capability' and 'limitations_or_remedy' fields.
--   4. [Correction D - Comprehensive Public View Allowlists]: Enforced strict categorical
--      allowlists on 'node_id', 'device_type', 'label', 'node_type', 'data_label',
--      'dual_reason', 'stop_reason', and 'target_ip' across all 9 public views.
--      Zero MD5 hashing; zero raw MACs; zero internal file paths or stack traces.
--   5. [Correction E - View Security Architecture]: Verified view owner semantics
--      (security_invoker = false) with complete base table lockout for 'anon'.
--      The sanitized view projection serves as the immutable data boundary.
--   6. [Correction F - PoLP Access Enforcement]: UPDATE restricted strictly to 3 mutable
--      tables (collector_status, device_registry, unknown_device_obs); permanently revoked
--      from all 6 immutable tables. DELETE and TRUNCATE permanently revoked.
--   7. [Correction G - Supabase System Compatibility]: Granted USAGE on schema public to
--      'service_role' alongside anon, authenticated, and collector_role for Supabase Studio.
-- ============================================================================="""

    header_new = """-- =============================================================================
-- IoT Network Guard — Dual-Detector SOC Console
-- Stage 3B.6: Golden Cloud Schema Migration (Production Baseline 3.6.0)
-- File: scratch/stage3b_6_final_supabase_migration.sql
-- 
-- Target Platform: Supabase Managed PostgreSQL (Region: ap-south-1 / Mumbai)
-- Target Project Reference: cwqumhtzeiqrfhlesksw
-- Target PostgreSQL Version: 17.6
-- Schema Baseline: 3.6.0 (Definitive Production Security & Idempotency Baseline)
-- 
-- Summary of Stage 3B.6 Architectural & Security Corrections:
--   1. [Correction 1 - Public Station Identifier]: Fixed v_public_device_registry
--      to strictly enforce categorical mapping on 'public_station_id', preventing
--      unrestricted node_id string exposure.
--   2. [Correction 2 - Strict Pseudonym Validation]: All 9 public views strictly
--      validate station tokens and pseudonyms against approved allowlist ('Node_1'..'Node_5').
--      Zero raw MAC addresses or unvetted fallback tokens can ever leak.
--   3. [Correction 3 - Numeric Evidence Bounds Checking]: Bounds-checked regex
--      ('^[0-9]{1,9}$' for int, '^[0-9]{1,8}(\\.[0-9]{1,4})?$' for float) guarantees
--      100% immunity to integer and floating-point overflow crashes.
--   4. [Correction 4 - View Ownership Anchoring]: Explicitly executed ALTER VIEW ...
--      OWNER TO postgres for all 9 views, ensuring security_invoker = false works
--      with definitive base table permissions.
--   5. [Correction 5 - Schema Idempotency & Preflight]: Implemented preflight DO block
--      distinguishing clean fresh install from existing schema reconciliation, verifying
--      required columns and safely dropping obsolete collision constraints.
-- ============================================================================="""

    assert header_old in sql, "Could not find expected header in stage3b_5"
    sql = sql.replace(header_old, header_new)

    # 2. Add Section 0: Preflight Schema Reconciliation Block right after BEGIN;
    preflight_block = """BEGIN;

-- -----------------------------------------------------------------------------
-- 0. PREFLIGHT SCHEMA RECONCILIATION & IDEMPOTENCY AUDIT
-- -----------------------------------------------------------------------------
-- Distinguishes clean fresh-install from schema-reconciliation.
-- Verifies that existing tables from earlier prototypes or migrations are
-- safely reconciled to the 3.6.0 schema without silent corruption or drift.
DO $$
DECLARE
    table_count INT;
    has_event_uuid BOOLEAN := FALSE;
    rec RECORD;
BEGIN
    -- Check how many target tables currently exist in public schema
    SELECT COUNT(*) INTO table_count 
    FROM information_schema.tables 
    WHERE table_schema = 'public' 
      AND table_name IN (
        'collector_status', 'device_registry', 'station_pseudonym_map',
        'live_traffic_windows', 'live_alerts', 'unknown_device_obs',
        'live_sensor_telemetry', 'live_pir_events', 'live_attack_events'
      );

    IF table_count = 0 THEN
        RAISE NOTICE 'Preflight: Clean fresh install detected (0 of 9 tables exist). Proceeding with standard DDL deployment.';
    ELSE
        RAISE NOTICE 'Preflight: Existing schema detected (% of 9 tables exist). Initiating safe schema reconciliation.', table_count;
        
        -- Reconciliation 1: Check live_attack_events for event_uuid column
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'live_attack_events') THEN
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_schema = 'public' AND table_name = 'live_attack_events' AND column_name = 'event_uuid'
            ) INTO has_event_uuid;

            IF NOT has_event_uuid THEN
                RAISE NOTICE 'Reconciliation: Adding missing event_uuid column to existing live_attack_events table...';
                ALTER TABLE live_attack_events ADD COLUMN event_uuid UUID DEFAULT gen_random_uuid();
                UPDATE live_attack_events SET event_uuid = gen_random_uuid() WHERE event_uuid IS NULL;
                ALTER TABLE live_attack_events ALTER COLUMN event_uuid SET NOT NULL;
            END IF;

            -- Reconciliation 2: Drop obsolete collision-prone unique constraint if present
            FOR rec IN (
                SELECT c.conname
                FROM pg_constraint c
                JOIN pg_class t ON c.conrelid = t.oid
                JOIN pg_namespace n ON t.relnamespace = n.oid
                WHERE n.nspname = 'public' 
                  AND t.relname = 'live_attack_events' 
                  AND c.contype = 'u'
                  AND c.conname NOT IN ('uq_attack_event_uuid')
            ) LOOP
                RAISE NOTICE 'Reconciliation: Dropping legacy unique constraint "%" from live_attack_events...', rec.conname;
                EXECUTE format('ALTER TABLE live_attack_events DROP CONSTRAINT IF EXISTS %I', rec.conname);
            END LOOP;

            -- Reconciliation 3: Ensure uq_attack_event_uuid constraint exists
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint c
                JOIN pg_class t ON c.conrelid = t.oid
                JOIN pg_namespace n ON t.relnamespace = n.oid
                WHERE n.nspname = 'public' AND t.relname = 'live_attack_events' AND c.conname = 'uq_attack_event_uuid'
            ) THEN
                RAISE NOTICE 'Reconciliation: Adding uq_attack_event_uuid constraint to live_attack_events...';
                ALTER TABLE live_attack_events ADD CONSTRAINT uq_attack_event_uuid UNIQUE (event_uuid);
            END IF;
        END IF;

        -- Reconciliation 4: Verify critical column types on existing tables
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'collector_status') THEN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_schema = 'public' AND table_name = 'collector_status' AND column_name = 'run_id' AND data_type = 'text'
            ) THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Incompatible data type for column run_id in collector_status. Expected TEXT.';
            END IF;
        END IF;

        RAISE NOTICE 'Preflight: Schema reconciliation completed successfully.';
    END IF;
END $$;
"""

    assert "BEGIN;" in sql, "Could not find BEGIN; in stage3b_5"
    sql = sql.replace("BEGIN;\n", preflight_block + "\n", 1)

    # 3. Correction 1: Fix v_public_device_registry public_station_id
    v2_target = """CREATE OR REPLACE VIEW v_public_device_registry WITH (security_invoker = false) AS
SELECT 
    node_id AS public_station_id,
    CASE 
        WHEN node_id IN ('Node_3', 'Node_4', 'Node_5') THEN node_id
        ELSE 'Unspecified_Node'
    END AS node_id,"""

    v2_replacement = """CREATE OR REPLACE VIEW v_public_device_registry WITH (security_invoker = false) AS
SELECT 
    -- Strict allowlist enforcement for public station identifier (Correction 1)
    CASE 
        WHEN node_id IN ('Node_3', 'Node_4', 'Node_5') THEN node_id
        ELSE 'Unspecified_Node'
    END AS public_station_id,
    CASE 
        WHEN node_id IN ('Node_3', 'Node_4', 'Node_5') THEN node_id
        ELSE 'Unspecified_Node'
    END AS node_id,"""

    assert v2_target in sql, "Could not find v2_target in stage3b_5"
    sql = sql.replace(v2_target, v2_replacement)

    # 4. Correction 2: Strict Pseudonym Validation Across Views
    # View 3: v_public_live_traffic_windows
    v3_target = """    COALESCE(
        m.pseudonym_id, 
        CASE 
            WHEN w.node_id IN ('Node_3', 'Node_4', 'Node_5') THEN w.node_id
            ELSE 'UNMAPPED_STATION'
        END
    ) AS public_station_id,"""

    v3_replacement = """    -- Strict allowlist enforcement for public pseudonym / station identifier (Correction 2)
    CASE 
        WHEN m.pseudonym_id IN ('Node_3', 'Node_4', 'Node_5') THEN m.pseudonym_id
        WHEN w.node_id IN ('Node_3', 'Node_4', 'Node_5') THEN w.node_id
        ELSE 'UNMAPPED_STATION'
    END AS public_station_id,"""

    assert v3_target in sql, "Could not find v3_target in stage3b_5"
    sql = sql.replace(v3_target, v3_replacement)

    # View 4: v_public_live_alerts
    v4_target = """    COALESCE(
        m.pseudonym_id, 
        CASE 
            WHEN a.node_id IN ('Node_3', 'Node_4', 'Node_5') THEN a.node_id
            ELSE 'UNMAPPED_STATION'
        END
    ) AS public_station_id,"""

    v4_replacement = """    -- Strict allowlist enforcement for public pseudonym / station identifier (Correction 2)
    CASE 
        WHEN m.pseudonym_id IN ('Node_3', 'Node_4', 'Node_5') THEN m.pseudonym_id
        WHEN a.node_id IN ('Node_3', 'Node_4', 'Node_5') THEN a.node_id
        ELSE 'UNMAPPED_STATION'
    END AS public_station_id,"""

    assert v4_target in sql, "Could not find v4_target in stage3b_5"
    sql = sql.replace(v4_target, v4_replacement)

    # View 5: v_public_unknown_device_obs
    v5_target = """    COALESCE(m.pseudonym_id, 'UNREGISTERED_STATION') AS public_device_alias,"""
    v5_replacement = """    -- Strict allowlist enforcement for public device alias (Correction 2)
    CASE 
        WHEN m.pseudonym_id IN ('Node_3', 'Node_4', 'Node_5') THEN m.pseudonym_id
        ELSE 'UNREGISTERED_STATION'
    END AS public_device_alias,"""

    assert v5_target in sql, "Could not find v5_target in stage3b_5"
    sql = sql.replace(v5_target, v5_replacement)

    # View 6: v_public_sensor_telemetry
    v6_target = """CREATE OR REPLACE VIEW v_public_sensor_telemetry WITH (security_invoker = false) AS
SELECT 
    telemetry_id,
    run_id,
    'esp32_gateway' AS physical_node_id,
    logical_node_id,"""

    v6_replacement = """CREATE OR REPLACE VIEW v_public_sensor_telemetry WITH (security_invoker = false) AS
SELECT 
    telemetry_id,
    run_id,
    'esp32_gateway' AS physical_node_id,
    -- Strict allowlist enforcement for sensor logical_node_id (Correction 2)
    CASE 
        WHEN logical_node_id IN ('Node_1', 'Node_2', 'Node_3', 'Node_4', 'Node_5') THEN logical_node_id
        ELSE 'Node_1'
    END AS logical_node_id,"""

    assert v6_target in sql, "Could not find v6_target in stage3b_5"
    sql = sql.replace(v6_target, v6_replacement)

    # View 7: v_public_pir_events
    v7_target = """CREATE OR REPLACE VIEW v_public_pir_events WITH (security_invoker = false) AS
SELECT 
    pir_id,
    run_id,
    'esp32_gateway' AS physical_node_id,
    logical_node_id,"""

    v7_replacement = """CREATE OR REPLACE VIEW v_public_pir_events WITH (security_invoker = false) AS
SELECT 
    pir_id,
    run_id,
    'esp32_gateway' AS physical_node_id,
    -- Strict allowlist enforcement for PIR logical_node_id (Correction 2)
    CASE 
        WHEN logical_node_id IN ('Node_1', 'Node_2', 'Node_3', 'Node_4', 'Node_5') THEN logical_node_id
        ELSE 'Node_2'
    END AS logical_node_id,"""

    assert v7_target in sql, "Could not find v7_target in stage3b_5"
    sql = sql.replace(v7_target, v7_replacement)

    # View 8: v_public_attack_events source_station_id
    v8_station_target = """    -- Neutral alias fallback; zero MD5 or raw MAC
    CASE 
        WHEN e.source_mac IS NOT NULL THEN 
            COALESCE(m.pseudonym_id, 'ATTACKER_UNMAPPED')
        ELSE NULL 
    END AS source_station_id,"""

    v8_station_replacement = """    -- Strict allowlist enforcement for source_station_id: zero raw MAC or unvetted token (Correction 2)
    CASE 
        WHEN e.source_mac IS NOT NULL AND m.pseudonym_id IN ('Node_3', 'Node_4', 'Node_5') THEN m.pseudonym_id
        WHEN e.source_mac IS NOT NULL THEN 'ATTACKER_UNMAPPED'
        ELSE NULL 
    END AS source_station_id,"""

    assert v8_station_target in sql, "Could not find v8_station_target in stage3b_5"
    sql = sql.replace(v8_station_target, v8_station_replacement)

    # 5. Correction 3: Numeric Evidence Bounds Checking & Overflow Immunity
    numeric_target = """                -- Numeric fields pre-validated with regex before casting (crash-proof)
                'probe_counts', CASE WHEN (e.evidence_json->>'probe_counts') ~ '^-?[0-9]+$' THEN (e.evidence_json->>'probe_counts')::int ELSE NULL END,
                'distinct_ports_count', CASE WHEN (e.evidence_json->>'distinct_ports_count') ~ '^-?[0-9]+$' THEN (e.evidence_json->>'distinct_ports_count')::int ELSE NULL END,
                'distinct_hosts_count', CASE WHEN (e.evidence_json->>'distinct_hosts_count') ~ '^-?[0-9]+$' THEN (e.evidence_json->>'distinct_hosts_count')::int ELSE NULL END,
                'tcp_syn_count', CASE WHEN (e.evidence_json->>'tcp_syn_count') ~ '^-?[0-9]+$' THEN (e.evidence_json->>'tcp_syn_count')::int ELSE NULL END,
                'udp_probe_count', CASE WHEN (e.evidence_json->>'udp_probe_count') ~ '^-?[0-9]+$' THEN (e.evidence_json->>'udp_probe_count')::int ELSE NULL END,
                'current_rate_pps', CASE WHEN (e.evidence_json->>'current_rate_pps') ~ '^-?[0-9]+(\\.[0-9]+)?$' THEN (e.evidence_json->>'current_rate_pps')::float ELSE NULL END,
                'rate_threshold_pps', CASE WHEN (e.evidence_json->>'rate_threshold_pps') ~ '^-?[0-9]+(\\.[0-9]+)?$' THEN (e.evidence_json->>'rate_threshold_pps')::float ELSE NULL END,
                'consecutive_windows', CASE WHEN (e.evidence_json->>'consecutive_windows') ~ '^-?[0-9]+$' THEN (e.evidence_json->>'consecutive_windows')::int ELSE NULL END,
                'target_concentration', CASE WHEN (e.evidence_json->>'target_concentration') ~ '^-?[0-9]+(\\.[0-9]+)?$' THEN (e.evidence_json->>'target_concentration')::float ELSE NULL END,
                'is_vertical_scan', CASE WHEN (e.evidence_json->>'is_vertical_scan') IN ('true', 'false') THEN (e.evidence_json->>'is_vertical_scan')::boolean ELSE NULL END,
                'is_horizontal_sweep', CASE WHEN (e.evidence_json->>'is_horizontal_sweep') IN ('true', 'false') THEN (e.evidence_json->>'is_horizontal_sweep')::boolean ELSE NULL END,
                'total_mgmt_frames', CASE WHEN (e.evidence_json->>'total_mgmt_frames') ~ '^-?[0-9]+$' THEN (e.evidence_json->>'total_mgmt_frames')::int ELSE NULL END,
                'deauth_count', CASE WHEN (e.evidence_json->>'deauth_count') ~ '^-?[0-9]+$' THEN (e.evidence_json->>'deauth_count')::int ELSE NULL END,"""

    numeric_replacement = """                -- Numeric fields bounds-checked before casting: 100% immune to integer/float overflow (Correction 3)
                'probe_counts', CASE WHEN (e.evidence_json->>'probe_counts') ~ '^[0-9]{1,9}$' THEN (e.evidence_json->>'probe_counts')::int ELSE NULL END,
                'distinct_ports_count', CASE WHEN (e.evidence_json->>'distinct_ports_count') ~ '^[0-9]{1,9}$' THEN (e.evidence_json->>'distinct_ports_count')::int ELSE NULL END,
                'distinct_hosts_count', CASE WHEN (e.evidence_json->>'distinct_hosts_count') ~ '^[0-9]{1,9}$' THEN (e.evidence_json->>'distinct_hosts_count')::int ELSE NULL END,
                'tcp_syn_count', CASE WHEN (e.evidence_json->>'tcp_syn_count') ~ '^[0-9]{1,9}$' THEN (e.evidence_json->>'tcp_syn_count')::int ELSE NULL END,
                'udp_probe_count', CASE WHEN (e.evidence_json->>'udp_probe_count') ~ '^[0-9]{1,9}$' THEN (e.evidence_json->>'udp_probe_count')::int ELSE NULL END,
                'current_rate_pps', CASE WHEN (e.evidence_json->>'current_rate_pps') ~ '^[0-9]{1,8}(\\.[0-9]{1,4})?$' THEN (e.evidence_json->>'current_rate_pps')::float ELSE NULL END,
                'rate_threshold_pps', CASE WHEN (e.evidence_json->>'rate_threshold_pps') ~ '^[0-9]{1,8}(\\.[0-9]{1,4})?$' THEN (e.evidence_json->>'rate_threshold_pps')::float ELSE NULL END,
                'consecutive_windows', CASE WHEN (e.evidence_json->>'consecutive_windows') ~ '^[0-9]{1,9}$' THEN (e.evidence_json->>'consecutive_windows')::int ELSE NULL END,
                'target_concentration', CASE WHEN (e.evidence_json->>'target_concentration') ~ '^[0-9]{1,3}(\\.[0-9]{1,4})?$' THEN (e.evidence_json->>'target_concentration')::float ELSE NULL END,
                'is_vertical_scan', CASE WHEN (e.evidence_json->>'is_vertical_scan') IN ('true', 'false') THEN (e.evidence_json->>'is_vertical_scan')::boolean ELSE NULL END,
                'is_horizontal_sweep', CASE WHEN (e.evidence_json->>'is_horizontal_sweep') IN ('true', 'false') THEN (e.evidence_json->>'is_horizontal_sweep')::boolean ELSE NULL END,
                'total_mgmt_frames', CASE WHEN (e.evidence_json->>'total_mgmt_frames') ~ '^[0-9]{1,9}$' THEN (e.evidence_json->>'total_mgmt_frames')::int ELSE NULL END,
                'deauth_count', CASE WHEN (e.evidence_json->>'deauth_count') ~ '^[0-9]{1,9}$' THEN (e.evidence_json->>'deauth_count')::int ELSE NULL END,"""

    assert numeric_target in sql, "Could not find numeric_target in stage3b_5"
    sql = sql.replace(numeric_target, numeric_replacement)

    # 6. Correction 4: View Ownership Anchoring
    # Add explicit ALTER VIEW ... OWNER TO postgres for all 9 views right after View 9
    v9_end_target = """FROM live_traffic_windows w
GROUP BY w.run_id;"""

    v9_end_replacement = """FROM live_traffic_windows w
GROUP BY w.run_id;

-- ─── View Ownership & Definer Execution Verification (Correction 4) ─────────
-- Explicitly anchor ownership of all 9 views to postgres (the base table owner).
-- With security_invoker = false, queries execute with postgres definer permissions,
-- ensuring that anon/authenticated roles can query the sanitized views without
-- requiring direct permissions on the underlying base tables.
ALTER VIEW v_public_collector_status OWNER TO postgres;
ALTER VIEW v_public_device_registry OWNER TO postgres;
ALTER VIEW v_public_live_traffic_windows OWNER TO postgres;
ALTER VIEW v_public_live_alerts OWNER TO postgres;
ALTER VIEW v_public_unknown_device_obs OWNER TO postgres;
ALTER VIEW v_public_sensor_telemetry OWNER TO postgres;
ALTER VIEW v_public_pir_events OWNER TO postgres;
ALTER VIEW v_public_attack_events OWNER TO postgres;
ALTER VIEW v_public_traffic_overview OWNER TO postgres;"""

    assert v9_end_target in sql, "Could not find v9_end_target in stage3b_5"
    sql = sql.replace(v9_end_target, v9_end_replacement)

    # Write output file
    with open(dst_path, "w", encoding="utf-8") as f:
        f.write(sql)

    print(f"Successfully generated {dst_path} ({dst_path.stat().st_size:,} bytes)")

if __name__ == "__main__":
    generate_stage3b_6()
