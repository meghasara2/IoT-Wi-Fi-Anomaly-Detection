-- =============================================================================
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
--      ('^[0-9]{1,9}$' for int, '^[0-9]{1,8}(\.[0-9]{1,4})?$' for float) guarantees
--      100% immunity to integer and floating-point overflow crashes.
--   4. [Correction 4 - View Ownership Anchoring]: Explicitly executed ALTER VIEW ...
--      OWNER TO postgres for all 9 views, ensuring security_invoker = false works
--      with definitive base table permissions.
--   5. [Correction 5 - Schema Idempotency & Preflight]: Implemented preflight DO block
--      distinguishing clean fresh install from existing schema reconciliation, verifying
--      required columns and safely dropping obsolete collision constraints.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 0. PRAGMAS & EXTENSIONS (PRE-TRANSACTION SETUP)
-- -----------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

SET timezone = 'UTC';

-- -----------------------------------------------------------------------------
-- BEGIN ATOMIC TRANSACTION
-- -----------------------------------------------------------------------------
BEGIN;

-- -----------------------------------------------------------------------------
-- 0. PREFLIGHT SCHEMA RECONCILIATION & IDEMPOTENCY AUDIT
-- -----------------------------------------------------------------------------
-- Distinguishes clean fresh-install from schema-reconciliation.
-- Verifies that existing tables from earlier prototypes or migrations are
-- safely reconciled across all 9 target tables to the 3.6.0 schema without
-- silent corruption or drift. Audits all required primary, foreign key, identity,
-- and constraint columns. Safely widens types where compatible, adds
-- unambiguous missing columns, and raises actionable exceptions on incompatible drift.
DO $$
DECLARE
    table_count INT;
    has_event_uuid BOOLEAN := FALSE;
    col_type TEXT;
    pk_cols TEXT;
    uq_cols TEXT;
    existing_uq_name TEXT;
    has_identity BOOLEAN;
    row_count BIGINT;
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
        RAISE NOTICE 'Preflight: Existing schema detected (% of 9 tables exist). Initiating safe 9-table schema reconciliation.', table_count;
        
        -- =====================================================================
        -- Table 1: collector_status
        -- =====================================================================
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'collector_status') THEN
            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'collector_status' AND column_name = 'run_id';
            -- Verification: column_name = 'run_id' AND data_type = 'bigint'
            
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required primary key column run_id is missing from existing collector_status table. Cannot safely reconcile collector sessions.';
            ELSIF col_type = 'integer' THEN
                RAISE NOTICE 'Reconciliation: Widening collector_status.run_id from INTEGER to BIGINT...';
                ALTER TABLE collector_status ALTER COLUMN run_id TYPE BIGINT;
            ELSIF col_type <> 'bigint' THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Incompatible data type for column run_id in collector_status. Expected BIGINT, found %.', col_type;
            END IF;

            -- Validate PK constraint definition
            pk_cols := NULL;
            SELECT string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum)) INTO pk_cols
            FROM pg_constraint c
            JOIN pg_class t ON c.conrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
            WHERE n.nspname = 'public' AND t.relname = 'collector_status' AND c.contype = 'p';

            IF pk_cols IS NOT NULL THEN
                IF pk_cols <> 'run_id' THEN
                    RAISE EXCEPTION 'Schema Reconciliation Failure: Table collector_status has incompatible primary key (found: %, expected: run_id).', pk_cols;
                END IF;
            ELSE
                RAISE NOTICE 'Reconciliation: Adding PRIMARY KEY (run_id) constraint to collector_status...';
                ALTER TABLE collector_status ADD PRIMARY KEY (run_id);
            END IF;

            -- Validate identity / default generation behavior
            has_identity := FALSE;
            SELECT (a.attidentity IN ('a', 'd') OR d.adbin IS NOT NULL) INTO has_identity
            FROM pg_attribute a
            LEFT JOIN pg_attrdef d ON a.attrelid = d.adrelid AND a.attnum = d.adnum
            JOIN pg_class t ON a.attrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            WHERE n.nspname = 'public' AND t.relname = 'collector_status' AND a.attname = 'run_id';

            IF NOT COALESCE(has_identity, FALSE) THEN
                RAISE NOTICE 'Reconciliation: Adding GENERATED BY DEFAULT AS IDENTITY to collector_status.run_id...';
                ALTER TABLE collector_status ALTER COLUMN run_id ADD GENERATED BY DEFAULT AS IDENTITY;
            END IF;

            -- Safely add non-essential / lifecycle columns with valid defaults
            ALTER TABLE collector_status ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp();
            ALTER TABLE collector_status ADD COLUMN IF NOT EXISTS last_heartbeat TIMESTAMPTZ;
            ALTER TABLE collector_status ADD COLUMN IF NOT EXISTS interface_index INTEGER;
            ALTER TABLE collector_status ADD COLUMN IF NOT EXISTS interface_name TEXT;
            ALTER TABLE collector_status ADD COLUMN IF NOT EXISTS serial_port TEXT;
            ALTER TABLE collector_status ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'STARTING';
            ALTER TABLE collector_status ADD COLUMN IF NOT EXISTS stop_reason TEXT;
            ALTER TABLE collector_status ADD COLUMN IF NOT EXISTS packets_parsed BIGINT NOT NULL DEFAULT 0;
            ALTER TABLE collector_status ADD COLUMN IF NOT EXISTS windows_emitted BIGINT NOT NULL DEFAULT 0;
            ALTER TABLE collector_status ADD COLUMN IF NOT EXISTS sensor_records BIGINT NOT NULL DEFAULT 0;
            ALTER TABLE collector_status ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp();
            ALTER TABLE collector_status ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp();
        END IF;

        -- =====================================================================
        -- Table 2: device_registry
        -- =====================================================================
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'device_registry') THEN
            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'device_registry' AND column_name = 'mac_address';
            
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required primary key column mac_address is missing from existing device_registry table. Cannot fabricate registered station MAC identities.';
            ELSIF col_type NOT IN ('text', 'character varying') THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Incompatible data type for column mac_address in device_registry. Expected TEXT, found %.', col_type;
            END IF;

            pk_cols := NULL;
            SELECT string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum)) INTO pk_cols
            FROM pg_constraint c
            JOIN pg_class t ON c.conrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
            WHERE n.nspname = 'public' AND t.relname = 'device_registry' AND c.contype = 'p';

            IF pk_cols IS NOT NULL THEN
                IF pk_cols <> 'mac_address' THEN
                    RAISE EXCEPTION 'Schema Reconciliation Failure: Table device_registry has incompatible primary key (found: %, expected: mac_address).', pk_cols;
                END IF;
            ELSE
                RAISE NOTICE 'Reconciliation: Adding PRIMARY KEY (mac_address) constraint to device_registry...';
                ALTER TABLE device_registry ADD PRIMARY KEY (mac_address);
            END IF;

            ALTER TABLE device_registry ADD COLUMN IF NOT EXISTS node_id TEXT NOT NULL DEFAULT 'Unspecified_Node';
            ALTER TABLE device_registry ADD COLUMN IF NOT EXISTS device_type TEXT NOT NULL DEFAULT 'Phone_Client';
            ALTER TABLE device_registry ADD COLUMN IF NOT EXISTS label TEXT NOT NULL DEFAULT 'real_observed_traffic';
            ALTER TABLE device_registry ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ;
            ALTER TABLE device_registry ADD COLUMN IF NOT EXISTS notes TEXT;
            ALTER TABLE device_registry ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp();
        END IF;

        -- =====================================================================
        -- Table 3: station_pseudonym_map
        -- =====================================================================
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'station_pseudonym_map') THEN
            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'station_pseudonym_map' AND column_name = 'mac_address';
            
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required primary key column mac_address is missing from existing station_pseudonym_map table. Cannot fabricate privacy mapping hardware MACs.';
            ELSIF col_type NOT IN ('text', 'character varying') THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Incompatible data type for column mac_address in station_pseudonym_map. Expected TEXT, found %.', col_type;
            END IF;

            pk_cols := NULL;
            SELECT string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum)) INTO pk_cols
            FROM pg_constraint c
            JOIN pg_class t ON c.conrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
            WHERE n.nspname = 'public' AND t.relname = 'station_pseudonym_map' AND c.contype = 'p';

            IF pk_cols IS NOT NULL THEN
                IF pk_cols <> 'mac_address' THEN
                    RAISE EXCEPTION 'Schema Reconciliation Failure: Table station_pseudonym_map has incompatible primary key (found: %, expected: mac_address).', pk_cols;
                END IF;
            ELSE
                RAISE NOTICE 'Reconciliation: Adding PRIMARY KEY (mac_address) constraint to station_pseudonym_map...';
                ALTER TABLE station_pseudonym_map ADD PRIMARY KEY (mac_address);
            END IF;

            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'station_pseudonym_map' AND column_name = 'pseudonym_id';
            
            IF col_type IS NULL THEN
                row_count := 0;
                EXECUTE 'SELECT COUNT(*) FROM station_pseudonym_map' INTO row_count;
                IF row_count > 0 THEN
                    RAISE EXCEPTION 'Schema Reconciliation Failure: Column pseudonym_id is missing from non-empty station_pseudonym_map table. Cannot fabricate cryptographic privacy pseudonyms.';
                ELSE
                    ALTER TABLE station_pseudonym_map ADD COLUMN pseudonym_id TEXT NOT NULL;
                END IF;
            ELSIF col_type NOT IN ('text', 'character varying') THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Incompatible data type for column pseudonym_id in station_pseudonym_map. Expected TEXT, found %.', col_type;
            END IF;

            -- Validate unique constraint on pseudonym_id
            existing_uq_name := NULL;
            SELECT c.conname INTO existing_uq_name
            FROM pg_constraint c
            JOIN pg_class t ON c.conrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
            WHERE n.nspname = 'public' AND t.relname = 'station_pseudonym_map' AND c.contype = 'u'
            GROUP BY c.conname
            HAVING string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum)) = 'pseudonym_id'
            LIMIT 1;

            IF existing_uq_name IS NOT NULL THEN
                RAISE NOTICE 'Reconciliation: Validated existing unique constraint "%" covering (pseudonym_id) on station_pseudonym_map.', existing_uq_name;
            ELSE
                uq_cols := NULL;
                SELECT string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum)) INTO uq_cols
                FROM pg_constraint c
                JOIN pg_class t ON c.conrelid = t.oid
                JOIN pg_namespace n ON t.relnamespace = n.oid
                JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
                WHERE n.nspname = 'public' AND t.relname = 'station_pseudonym_map' AND c.conname = 'uq_station_pseudonym';

                IF uq_cols IS NOT NULL AND uq_cols <> 'pseudonym_id' THEN
                    RAISE EXCEPTION 'Schema Reconciliation Failure: Constraint uq_station_pseudonym on station_pseudonym_map has incompatible definition (found: %, expected: pseudonym_id).', uq_cols;
                ELSIF uq_cols IS NULL THEN
                    RAISE NOTICE 'Reconciliation: Adding uq_station_pseudonym constraint to station_pseudonym_map...';
                    ALTER TABLE station_pseudonym_map ADD CONSTRAINT uq_station_pseudonym UNIQUE (pseudonym_id);
                END IF;
            END IF;

            ALTER TABLE station_pseudonym_map ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp();
        END IF;

        -- =====================================================================
        -- Table 4: live_traffic_windows
        -- =====================================================================
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'live_traffic_windows') THEN
            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'live_traffic_windows' AND column_name = 'window_id';
            
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required primary key column window_id is missing from existing live_traffic_windows table. Cannot safely reconcile historical traffic windows.';
            ELSIF col_type = 'integer' THEN
                RAISE NOTICE 'Reconciliation: Widening live_traffic_windows.window_id from INTEGER to BIGINT...';
                ALTER TABLE live_traffic_windows ALTER COLUMN window_id TYPE BIGINT;
            ELSIF col_type <> 'bigint' THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Incompatible data type for column window_id in live_traffic_windows. Expected BIGINT, found %.', col_type;
            END IF;

            pk_cols := NULL;
            SELECT string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum)) INTO pk_cols
            FROM pg_constraint c
            JOIN pg_class t ON c.conrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
            WHERE n.nspname = 'public' AND t.relname = 'live_traffic_windows' AND c.contype = 'p';

            IF pk_cols IS NOT NULL THEN
                IF pk_cols <> 'window_id' THEN
                    RAISE EXCEPTION 'Schema Reconciliation Failure: Table live_traffic_windows has incompatible primary key (found: %, expected: window_id).', pk_cols;
                END IF;
            ELSE
                RAISE NOTICE 'Reconciliation: Adding PRIMARY KEY (window_id) constraint to live_traffic_windows...';
                ALTER TABLE live_traffic_windows ADD PRIMARY KEY (window_id);
            END IF;

            has_identity := FALSE;
            SELECT (a.attidentity IN ('a', 'd') OR d.adbin IS NOT NULL) INTO has_identity
            FROM pg_attribute a
            LEFT JOIN pg_attrdef d ON a.attrelid = d.adrelid AND a.attnum = d.adnum
            JOIN pg_class t ON a.attrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            WHERE n.nspname = 'public' AND t.relname = 'live_traffic_windows' AND a.attname = 'window_id';

            IF NOT COALESCE(has_identity, FALSE) THEN
                RAISE NOTICE 'Reconciliation: Adding GENERATED BY DEFAULT AS IDENTITY to live_traffic_windows.window_id...';
                ALTER TABLE live_traffic_windows ALTER COLUMN window_id ADD GENERATED BY DEFAULT AS IDENTITY;
            END IF;

            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'live_traffic_windows' AND column_name = 'run_id';
            
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required foreign key column run_id is missing from existing live_traffic_windows table. Cannot fabricate session relationships for historical traffic windows.';
            ELSIF col_type = 'integer' THEN
                RAISE NOTICE 'Reconciliation: Widening live_traffic_windows.run_id from INTEGER to BIGINT...';
                ALTER TABLE live_traffic_windows ALTER COLUMN run_id TYPE BIGINT;
            ELSIF col_type <> 'bigint' THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Incompatible data type for column run_id in live_traffic_windows. Expected BIGINT, found %.', col_type;
            END IF;

            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'live_traffic_windows' AND column_name = 'client_mac';
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required natural key column client_mac is missing from existing live_traffic_windows table. Cannot fabricate client MACs for historical traffic windows.';
            ELSIF col_type NOT IN ('text', 'character varying') THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Incompatible data type for column client_mac in live_traffic_windows. Expected TEXT, found %.', col_type;
            END IF;

            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'live_traffic_windows' AND column_name = 'bin_start_epoch';
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required timestamp column bin_start_epoch is missing from existing live_traffic_windows table. Cannot fabricate window start epochs.';
            ELSIF col_type NOT IN ('double precision', 'real', 'numeric') THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Incompatible data type for column bin_start_epoch in live_traffic_windows. Expected DOUBLE PRECISION, found %.', col_type;
            END IF;

            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'live_traffic_windows' AND column_name = 'bin_end_epoch';
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required timestamp column bin_end_epoch is missing from existing live_traffic_windows table. Cannot fabricate window end epochs.';
            END IF;

            ALTER TABLE live_traffic_windows ADD COLUMN IF NOT EXISTS node_id TEXT NOT NULL DEFAULT 'Unspecified_Node';
            ALTER TABLE live_traffic_windows ADD COLUMN IF NOT EXISTS node_type TEXT;
            ALTER TABLE live_traffic_windows ADD COLUMN IF NOT EXISTS data_label TEXT;
            ALTER TABLE live_traffic_windows ADD COLUMN IF NOT EXISTS window_center_epoch DOUBLE PRECISION;
            ALTER TABLE live_traffic_windows ADD COLUMN IF NOT EXISTS window_start_utc TIMESTAMPTZ;
            ALTER TABLE live_traffic_windows ADD COLUMN IF NOT EXISTS window_end_utc TIMESTAMPTZ;
            ALTER TABLE live_traffic_windows ADD COLUMN IF NOT EXISTS packet_count INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE live_traffic_windows ADD COLUMN IF NOT EXISTS mean_IAT DOUBLE PRECISION;
            ALTER TABLE live_traffic_windows ADD COLUMN IF NOT EXISTS IAT_std DOUBLE PRECISION;
            ALTER TABLE live_traffic_windows ADD COLUMN IF NOT EXISTS packet_rate DOUBLE PRECISION NOT NULL DEFAULT 0.0;
            ALTER TABLE live_traffic_windows ADD COLUMN IF NOT EXISTS mean_packet_size DOUBLE PRECISION;
            ALTER TABLE live_traffic_windows ADD COLUMN IF NOT EXISTS packet_size_std DOUBLE PRECISION;
            ALTER TABLE live_traffic_windows ADD COLUMN IF NOT EXISTS score_primary DOUBLE PRECISION;
            ALTER TABLE live_traffic_windows ADD COLUMN IF NOT EXISTS pred_primary INTEGER;
            ALTER TABLE live_traffic_windows ADD COLUMN IF NOT EXISTS score_timing DOUBLE PRECISION;
            ALTER TABLE live_traffic_windows ADD COLUMN IF NOT EXISTS pred_timing INTEGER;
            ALTER TABLE live_traffic_windows ADD COLUMN IF NOT EXISTS timing_status TEXT;
            ALTER TABLE live_traffic_windows ADD COLUMN IF NOT EXISTS pred_dual INTEGER;
            ALTER TABLE live_traffic_windows ADD COLUMN IF NOT EXISTS dual_reason TEXT;
            ALTER TABLE live_traffic_windows ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp();

            -- Validate natural unique constraint definition
            existing_uq_name := NULL;
            SELECT c.conname INTO existing_uq_name
            FROM pg_constraint c
            JOIN pg_class t ON c.conrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
            WHERE n.nspname = 'public' AND t.relname = 'live_traffic_windows' AND c.contype = 'u'
            GROUP BY c.conname
            HAVING string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum)) = 'run_id,client_mac,bin_start_epoch'
            LIMIT 1;

            IF existing_uq_name IS NOT NULL THEN
                RAISE NOTICE 'Reconciliation: Validated existing unique constraint "%" covering (run_id, client_mac, bin_start_epoch) on live_traffic_windows.', existing_uq_name;
            ELSE
                uq_cols := NULL;
                SELECT string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum)) INTO uq_cols
                FROM pg_constraint c
                JOIN pg_class t ON c.conrelid = t.oid
                JOIN pg_namespace n ON t.relnamespace = n.oid
                JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
                WHERE n.nspname = 'public' AND t.relname = 'live_traffic_windows' AND c.conname = 'uq_traffic_window_run_mac_epoch';

                IF uq_cols IS NOT NULL AND uq_cols <> 'run_id,client_mac,bin_start_epoch' THEN
                    RAISE EXCEPTION 'Schema Reconciliation Failure: Constraint uq_traffic_window_run_mac_epoch on live_traffic_windows has incompatible definition (found: %, expected: run_id,client_mac,bin_start_epoch).', uq_cols;
                ELSIF uq_cols IS NULL THEN
                    RAISE NOTICE 'Reconciliation: Adding uq_traffic_window_run_mac_epoch constraint to live_traffic_windows...';
                    ALTER TABLE live_traffic_windows ADD CONSTRAINT uq_traffic_window_run_mac_epoch UNIQUE (run_id, client_mac, bin_start_epoch);
                END IF;
            END IF;
        END IF;

        -- =====================================================================
        -- Table 5: live_alerts
        -- =====================================================================
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'live_alerts') THEN
            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'live_alerts' AND column_name = 'alert_id';
            
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required primary key column alert_id is missing from existing live_alerts table. Cannot safely reconcile historical alerts.';
            ELSIF col_type = 'integer' THEN
                RAISE NOTICE 'Reconciliation: Widening live_alerts.alert_id from INTEGER to BIGINT...';
                ALTER TABLE live_alerts ALTER COLUMN alert_id TYPE BIGINT;
            ELSIF col_type <> 'bigint' THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Incompatible data type for column alert_id in live_alerts. Expected BIGINT, found %.', col_type;
            END IF;

            pk_cols := NULL;
            SELECT string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum)) INTO pk_cols
            FROM pg_constraint c
            JOIN pg_class t ON c.conrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
            WHERE n.nspname = 'public' AND t.relname = 'live_alerts' AND c.contype = 'p';

            IF pk_cols IS NOT NULL THEN
                IF pk_cols <> 'alert_id' THEN
                    RAISE EXCEPTION 'Schema Reconciliation Failure: Table live_alerts has incompatible primary key (found: %, expected: alert_id).', pk_cols;
                END IF;
            ELSE
                RAISE NOTICE 'Reconciliation: Adding PRIMARY KEY (alert_id) constraint to live_alerts...';
                ALTER TABLE live_alerts ADD PRIMARY KEY (alert_id);
            END IF;

            has_identity := FALSE;
            SELECT (a.attidentity IN ('a', 'd') OR d.adbin IS NOT NULL) INTO has_identity
            FROM pg_attribute a
            LEFT JOIN pg_attrdef d ON a.attrelid = d.adrelid AND a.attnum = d.adnum
            JOIN pg_class t ON a.attrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            WHERE n.nspname = 'public' AND t.relname = 'live_alerts' AND a.attname = 'alert_id';

            IF NOT COALESCE(has_identity, FALSE) THEN
                RAISE NOTICE 'Reconciliation: Adding GENERATED BY DEFAULT AS IDENTITY to live_alerts.alert_id...';
                ALTER TABLE live_alerts ALTER COLUMN alert_id ADD GENERATED BY DEFAULT AS IDENTITY;
            END IF;

            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'live_alerts' AND column_name = 'window_id';
            
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required foreign key column window_id is missing from existing live_alerts table. Cannot reconstruct alert-to-window relationships.';
            ELSIF col_type = 'integer' THEN
                RAISE NOTICE 'Reconciliation: Widening live_alerts.window_id from INTEGER to BIGINT...';
                ALTER TABLE live_alerts ALTER COLUMN window_id TYPE BIGINT;
            ELSIF col_type <> 'bigint' THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Incompatible data type for column window_id in live_alerts. Expected BIGINT, found %.', col_type;
            END IF;

            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'live_alerts' AND column_name = 'run_id';
            
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required foreign key column run_id is missing from existing live_alerts table. Cannot fabricate session relationships for historical alerts.';
            ELSIF col_type = 'integer' THEN
                RAISE NOTICE 'Reconciliation: Widening live_alerts.run_id from INTEGER to BIGINT...';
                ALTER TABLE live_alerts ALTER COLUMN run_id TYPE BIGINT;
            ELSIF col_type <> 'bigint' THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Incompatible data type for column run_id in live_alerts. Expected BIGINT, found %.', col_type;
            END IF;

            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'live_alerts' AND column_name = 'dual_reason';
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required column dual_reason is missing from existing live_alerts table. Cannot fabricate historical alert classifications.';
            END IF;

            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'live_alerts' AND column_name = 'bin_start_epoch';
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required timestamp column bin_start_epoch is missing from existing live_alerts table. Cannot fabricate alert start epochs.';
            END IF;

            ALTER TABLE live_alerts ADD COLUMN IF NOT EXISTS client_mac TEXT;
            ALTER TABLE live_alerts ADD COLUMN IF NOT EXISTS node_id TEXT NOT NULL DEFAULT 'Unspecified_Node';
            ALTER TABLE live_alerts ADD COLUMN IF NOT EXISTS window_start_utc TIMESTAMPTZ;
            ALTER TABLE live_alerts ADD COLUMN IF NOT EXISTS score_primary DOUBLE PRECISION;
            ALTER TABLE live_alerts ADD COLUMN IF NOT EXISTS score_timing DOUBLE PRECISION;
            ALTER TABLE live_alerts ADD COLUMN IF NOT EXISTS packet_rate DOUBLE PRECISION;
            ALTER TABLE live_alerts ADD COLUMN IF NOT EXISTS mean_packet_size DOUBLE PRECISION;
            ALTER TABLE live_alerts ADD COLUMN IF NOT EXISTS packet_count INTEGER;
            ALTER TABLE live_alerts ADD COLUMN IF NOT EXISTS acknowledged INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE live_alerts ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp();

            -- Validate unique constraint definition on window_id
            existing_uq_name := NULL;
            SELECT c.conname INTO existing_uq_name
            FROM pg_constraint c
            JOIN pg_class t ON c.conrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
            WHERE n.nspname = 'public' AND t.relname = 'live_alerts' AND c.contype = 'u'
            GROUP BY c.conname
            HAVING string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum)) = 'window_id'
            LIMIT 1;

            IF existing_uq_name IS NOT NULL THEN
                RAISE NOTICE 'Reconciliation: Validated existing unique constraint "%" covering (window_id) on live_alerts.', existing_uq_name;
            ELSE
                uq_cols := NULL;
                SELECT string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum)) INTO uq_cols
                FROM pg_constraint c
                JOIN pg_class t ON c.conrelid = t.oid
                JOIN pg_namespace n ON t.relnamespace = n.oid
                JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
                WHERE n.nspname = 'public' AND t.relname = 'live_alerts' AND c.conname = 'uq_live_alerts_window';

                IF uq_cols IS NOT NULL AND uq_cols <> 'window_id' THEN
                    RAISE EXCEPTION 'Schema Reconciliation Failure: Constraint uq_live_alerts_window on live_alerts has incompatible definition (found: %, expected: window_id).', uq_cols;
                ELSIF uq_cols IS NULL THEN
                    RAISE NOTICE 'Reconciliation: Adding uq_live_alerts_window constraint to live_alerts...';
                    ALTER TABLE live_alerts ADD CONSTRAINT uq_live_alerts_window UNIQUE (window_id);
                END IF;
            END IF;
        END IF;

        -- =====================================================================
        -- Table 6: unknown_device_obs
        -- =====================================================================
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'unknown_device_obs') THEN
            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'unknown_device_obs' AND column_name = 'obs_id';
            
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required primary key column obs_id is missing from existing unknown_device_obs table. Cannot safely reconcile unknown observations.';
            ELSIF col_type = 'integer' THEN
                RAISE NOTICE 'Reconciliation: Widening unknown_device_obs.obs_id from INTEGER to BIGINT...';
                ALTER TABLE unknown_device_obs ALTER COLUMN obs_id TYPE BIGINT;
            ELSIF col_type <> 'bigint' THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Incompatible data type for column obs_id in unknown_device_obs. Expected BIGINT, found %.', col_type;
            END IF;

            pk_cols := NULL;
            SELECT string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum)) INTO pk_cols
            FROM pg_constraint c
            JOIN pg_class t ON c.conrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
            WHERE n.nspname = 'public' AND t.relname = 'unknown_device_obs' AND c.contype = 'p';

            IF pk_cols IS NOT NULL THEN
                IF pk_cols <> 'obs_id' THEN
                    RAISE EXCEPTION 'Schema Reconciliation Failure: Table unknown_device_obs has incompatible primary key (found: %, expected: obs_id).', pk_cols;
                END IF;
            ELSE
                RAISE NOTICE 'Reconciliation: Adding PRIMARY KEY (obs_id) constraint to unknown_device_obs...';
                ALTER TABLE unknown_device_obs ADD PRIMARY KEY (obs_id);
            END IF;

            has_identity := FALSE;
            SELECT (a.attidentity IN ('a', 'd') OR d.adbin IS NOT NULL) INTO has_identity
            FROM pg_attribute a
            LEFT JOIN pg_attrdef d ON a.attrelid = d.adrelid AND a.attnum = d.adnum
            JOIN pg_class t ON a.attrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            WHERE n.nspname = 'public' AND t.relname = 'unknown_device_obs' AND a.attname = 'obs_id';

            IF NOT COALESCE(has_identity, FALSE) THEN
                RAISE NOTICE 'Reconciliation: Adding GENERATED BY DEFAULT AS IDENTITY to unknown_device_obs.obs_id...';
                ALTER TABLE unknown_device_obs ALTER COLUMN obs_id ADD GENERATED BY DEFAULT AS IDENTITY;
            END IF;

            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'unknown_device_obs' AND column_name = 'run_id';
            
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required foreign key column run_id is missing from existing unknown_device_obs table. Cannot fabricate session relationships for unknown devices.';
            ELSIF col_type = 'integer' THEN
                RAISE NOTICE 'Reconciliation: Widening unknown_device_obs.run_id from INTEGER to BIGINT...';
                ALTER TABLE unknown_device_obs ALTER COLUMN run_id TYPE BIGINT;
            ELSIF col_type <> 'bigint' THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Incompatible data type for column run_id in unknown_device_obs. Expected BIGINT, found %.', col_type;
            END IF;

            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'unknown_device_obs' AND column_name = 'observed_mac';
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required identifier column observed_mac is missing from existing unknown_device_obs table. Cannot fabricate observed unknown MACs.';
            ELSIF col_type NOT IN ('text', 'character varying') THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Incompatible data type for column observed_mac in unknown_device_obs. Expected TEXT, found %.', col_type;
            END IF;

            ALTER TABLE unknown_device_obs ADD COLUMN IF NOT EXISTS first_seen_utc TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp();
            ALTER TABLE unknown_device_obs ADD COLUMN IF NOT EXISTS last_seen_utc TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp();
            ALTER TABLE unknown_device_obs ADD COLUMN IF NOT EXISTS observation_count INTEGER NOT NULL DEFAULT 1;
            ALTER TABLE unknown_device_obs ADD COLUMN IF NOT EXISTS acknowledged INTEGER NOT NULL DEFAULT 0;

            existing_uq_name := NULL;
            SELECT c.conname INTO existing_uq_name
            FROM pg_constraint c
            JOIN pg_class t ON c.conrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
            WHERE n.nspname = 'public' AND t.relname = 'unknown_device_obs' AND c.contype = 'u'
            GROUP BY c.conname
            HAVING string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum)) = 'run_id,observed_mac'
            LIMIT 1;

            IF existing_uq_name IS NOT NULL THEN
                RAISE NOTICE 'Reconciliation: Validated existing unique constraint "%" covering (run_id, observed_mac) on unknown_device_obs.', existing_uq_name;
            ELSE
                uq_cols := NULL;
                SELECT string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum)) INTO uq_cols
                FROM pg_constraint c
                JOIN pg_class t ON c.conrelid = t.oid
                JOIN pg_namespace n ON t.relnamespace = n.oid
                JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
                WHERE n.nspname = 'public' AND t.relname = 'unknown_device_obs' AND c.conname = 'uq_unknown_mac_run';

                IF uq_cols IS NOT NULL AND uq_cols <> 'run_id,observed_mac' THEN
                    RAISE EXCEPTION 'Schema Reconciliation Failure: Constraint uq_unknown_mac_run on unknown_device_obs has incompatible definition (found: %, expected: run_id,observed_mac).', uq_cols;
                ELSIF uq_cols IS NULL THEN
                    RAISE NOTICE 'Reconciliation: Adding uq_unknown_mac_run constraint to unknown_device_obs...';
                    ALTER TABLE unknown_device_obs ADD CONSTRAINT uq_unknown_mac_run UNIQUE (run_id, observed_mac);
                END IF;
            END IF;
        END IF;

        -- =====================================================================
        -- Table 7: live_sensor_telemetry
        -- =====================================================================
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'live_sensor_telemetry') THEN
            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'live_sensor_telemetry' AND column_name = 'telemetry_id';
            
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required primary key column telemetry_id is missing from existing live_sensor_telemetry table. Cannot safely reconcile sensor telemetry.';
            ELSIF col_type = 'integer' THEN
                RAISE NOTICE 'Reconciliation: Widening live_sensor_telemetry.telemetry_id from INTEGER to BIGINT...';
                ALTER TABLE live_sensor_telemetry ALTER COLUMN telemetry_id TYPE BIGINT;
            ELSIF col_type <> 'bigint' THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Incompatible data type for column telemetry_id in live_sensor_telemetry. Expected BIGINT, found %.', col_type;
            END IF;

            pk_cols := NULL;
            SELECT string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum)) INTO pk_cols
            FROM pg_constraint c
            JOIN pg_class t ON c.conrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
            WHERE n.nspname = 'public' AND t.relname = 'live_sensor_telemetry' AND c.contype = 'p';

            IF pk_cols IS NOT NULL THEN
                IF pk_cols <> 'telemetry_id' THEN
                    RAISE EXCEPTION 'Schema Reconciliation Failure: Table live_sensor_telemetry has incompatible primary key (found: %, expected: telemetry_id).', pk_cols;
                END IF;
            ELSE
                RAISE NOTICE 'Reconciliation: Adding PRIMARY KEY (telemetry_id) constraint to live_sensor_telemetry...';
                ALTER TABLE live_sensor_telemetry ADD PRIMARY KEY (telemetry_id);
            END IF;

            has_identity := FALSE;
            SELECT (a.attidentity IN ('a', 'd') OR d.adbin IS NOT NULL) INTO has_identity
            FROM pg_attribute a
            LEFT JOIN pg_attrdef d ON a.attrelid = d.adrelid AND a.attnum = d.adnum
            JOIN pg_class t ON a.attrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            WHERE n.nspname = 'public' AND t.relname = 'live_sensor_telemetry' AND a.attname = 'telemetry_id';

            IF NOT COALESCE(has_identity, FALSE) THEN
                RAISE NOTICE 'Reconciliation: Adding GENERATED BY DEFAULT AS IDENTITY to live_sensor_telemetry.telemetry_id...';
                ALTER TABLE live_sensor_telemetry ALTER COLUMN telemetry_id ADD GENERATED BY DEFAULT AS IDENTITY;
            END IF;

            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'live_sensor_telemetry' AND column_name = 'run_id';
            
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required foreign key column run_id is missing from existing live_sensor_telemetry table. Cannot fabricate session relationships for sensor telemetry.';
            ELSIF col_type = 'integer' THEN
                RAISE NOTICE 'Reconciliation: Widening live_sensor_telemetry.run_id from INTEGER to BIGINT...';
                ALTER TABLE live_sensor_telemetry ALTER COLUMN run_id TYPE BIGINT;
            ELSIF col_type <> 'bigint' THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Incompatible data type for column run_id in live_sensor_telemetry. Expected BIGINT, found %.', col_type;
            END IF;

            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'live_sensor_telemetry' AND column_name = 'sequence_num';
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required hardware sequence_num is missing from existing live_sensor_telemetry table. Cannot fabricate physical telemetry sequence numbers.';
            END IF;

            ALTER TABLE live_sensor_telemetry ADD COLUMN IF NOT EXISTS physical_node_id TEXT NOT NULL DEFAULT 'esp32_gateway';
            ALTER TABLE live_sensor_telemetry ADD COLUMN IF NOT EXISTS logical_node_id TEXT NOT NULL DEFAULT 'Node_1';
            ALTER TABLE live_sensor_telemetry ADD COLUMN IF NOT EXISTS uptime_ms BIGINT NOT NULL DEFAULT 0;
            ALTER TABLE live_sensor_telemetry ADD COLUMN IF NOT EXISTS temperature_c DOUBLE PRECISION;
            ALTER TABLE live_sensor_telemetry ADD COLUMN IF NOT EXISTS humidity_pct DOUBLE PRECISION;
            ALTER TABLE live_sensor_telemetry ADD COLUMN IF NOT EXISTS dht_valid INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE live_sensor_telemetry ADD COLUMN IF NOT EXISTS captured_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp();
            ALTER TABLE live_sensor_telemetry ADD COLUMN IF NOT EXISTS sensor_epoch DOUBLE PRECISION;

            existing_uq_name := NULL;
            SELECT c.conname INTO existing_uq_name
            FROM pg_constraint c
            JOIN pg_class t ON c.conrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
            WHERE n.nspname = 'public' AND t.relname = 'live_sensor_telemetry' AND c.contype = 'u'
            GROUP BY c.conname
            HAVING string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum)) = 'run_id,physical_node_id,sequence_num'
            LIMIT 1;

            IF existing_uq_name IS NOT NULL THEN
                RAISE NOTICE 'Reconciliation: Validated existing unique constraint "%" covering (run_id, physical_node_id, sequence_num) on live_sensor_telemetry.', existing_uq_name;
            ELSE
                uq_cols := NULL;
                SELECT string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum)) INTO uq_cols
                FROM pg_constraint c
                JOIN pg_class t ON c.conrelid = t.oid
                JOIN pg_namespace n ON t.relnamespace = n.oid
                JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
                WHERE n.nspname = 'public' AND t.relname = 'live_sensor_telemetry' AND c.conname = 'uq_sensor_telemetry';

                IF uq_cols IS NOT NULL AND uq_cols <> 'run_id,physical_node_id,sequence_num' THEN
                    RAISE EXCEPTION 'Schema Reconciliation Failure: Constraint uq_sensor_telemetry on live_sensor_telemetry has incompatible definition (found: %, expected: run_id,physical_node_id,sequence_num).', uq_cols;
                ELSIF uq_cols IS NULL THEN
                    RAISE NOTICE 'Reconciliation: Adding uq_sensor_telemetry constraint to live_sensor_telemetry...';
                    ALTER TABLE live_sensor_telemetry ADD CONSTRAINT uq_sensor_telemetry UNIQUE (run_id, physical_node_id, sequence_num);
                END IF;
            END IF;
        END IF;

        -- =====================================================================
        -- Table 8: live_pir_events
        -- =====================================================================
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'live_pir_events') THEN
            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'live_pir_events' AND column_name = 'pir_id';
            
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required primary key column pir_id is missing from existing live_pir_events table. Cannot safely reconcile PIR events.';
            ELSIF col_type = 'integer' THEN
                RAISE NOTICE 'Reconciliation: Widening live_pir_events.pir_id from INTEGER to BIGINT...';
                ALTER TABLE live_pir_events ALTER COLUMN pir_id TYPE BIGINT;
            ELSIF col_type <> 'bigint' THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Incompatible data type for column pir_id in live_pir_events. Expected BIGINT, found %.', col_type;
            END IF;

            pk_cols := NULL;
            SELECT string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum)) INTO pk_cols
            FROM pg_constraint c
            JOIN pg_class t ON c.conrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
            WHERE n.nspname = 'public' AND t.relname = 'live_pir_events' AND c.contype = 'p';

            IF pk_cols IS NOT NULL THEN
                IF pk_cols <> 'pir_id' THEN
                    RAISE EXCEPTION 'Schema Reconciliation Failure: Table live_pir_events has incompatible primary key (found: %, expected: pir_id).', pk_cols;
                END IF;
            ELSE
                RAISE NOTICE 'Reconciliation: Adding PRIMARY KEY (pir_id) constraint to live_pir_events...';
                ALTER TABLE live_pir_events ADD PRIMARY KEY (pir_id);
            END IF;

            has_identity := FALSE;
            SELECT (a.attidentity IN ('a', 'd') OR d.adbin IS NOT NULL) INTO has_identity
            FROM pg_attribute a
            LEFT JOIN pg_attrdef d ON a.attrelid = d.adrelid AND a.attnum = d.adnum
            JOIN pg_class t ON a.attrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            WHERE n.nspname = 'public' AND t.relname = 'live_pir_events' AND a.attname = 'pir_id';

            IF NOT COALESCE(has_identity, FALSE) THEN
                RAISE NOTICE 'Reconciliation: Adding GENERATED BY DEFAULT AS IDENTITY to live_pir_events.pir_id...';
                ALTER TABLE live_pir_events ALTER COLUMN pir_id ADD GENERATED BY DEFAULT AS IDENTITY;
            END IF;

            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'live_pir_events' AND column_name = 'run_id';
            
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required foreign key column run_id is missing from existing live_pir_events table. Cannot fabricate session relationships for PIR events.';
            ELSIF col_type = 'integer' THEN
                RAISE NOTICE 'Reconciliation: Widening live_pir_events.run_id from INTEGER to BIGINT...';
                ALTER TABLE live_pir_events ALTER COLUMN run_id TYPE BIGINT;
            ELSIF col_type <> 'bigint' THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Incompatible data type for column run_id in live_pir_events. Expected BIGINT, found %.', col_type;
            END IF;

            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'live_pir_events' AND column_name = 'sequence_num';
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required hardware sequence_num is missing from existing live_pir_events table. Cannot fabricate physical PIR sequence numbers.';
            END IF;

            ALTER TABLE live_pir_events ADD COLUMN IF NOT EXISTS physical_node_id TEXT NOT NULL DEFAULT 'esp32_gateway';
            ALTER TABLE live_pir_events ADD COLUMN IF NOT EXISTS logical_node_id TEXT NOT NULL DEFAULT 'Node_2';
            ALTER TABLE live_pir_events ADD COLUMN IF NOT EXISTS uptime_ms BIGINT NOT NULL DEFAULT 0;
            ALTER TABLE live_pir_events ADD COLUMN IF NOT EXISTS motion_detected INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE live_pir_events ADD COLUMN IF NOT EXISTS captured_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp();
            ALTER TABLE live_pir_events ADD COLUMN IF NOT EXISTS sensor_epoch DOUBLE PRECISION;

            existing_uq_name := NULL;
            SELECT c.conname INTO existing_uq_name
            FROM pg_constraint c
            JOIN pg_class t ON c.conrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
            WHERE n.nspname = 'public' AND t.relname = 'live_pir_events' AND c.contype = 'u'
            GROUP BY c.conname
            HAVING string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum)) = 'run_id,physical_node_id,sequence_num'
            LIMIT 1;

            IF existing_uq_name IS NOT NULL THEN
                RAISE NOTICE 'Reconciliation: Validated existing unique constraint "%" covering (run_id, physical_node_id, sequence_num) on live_pir_events.', existing_uq_name;
            ELSE
                uq_cols := NULL;
                SELECT string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum)) INTO uq_cols
                FROM pg_constraint c
                JOIN pg_class t ON c.conrelid = t.oid
                JOIN pg_namespace n ON t.relnamespace = n.oid
                JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
                WHERE n.nspname = 'public' AND t.relname = 'live_pir_events' AND c.conname = 'uq_pir_events';

                IF uq_cols IS NOT NULL AND uq_cols <> 'run_id,physical_node_id,sequence_num' THEN
                    RAISE EXCEPTION 'Schema Reconciliation Failure: Constraint uq_pir_events on live_pir_events has incompatible definition (found: %, expected: run_id,physical_node_id,sequence_num).', uq_cols;
                ELSIF uq_cols IS NULL THEN
                    RAISE NOTICE 'Reconciliation: Adding uq_pir_events constraint to live_pir_events...';
                    ALTER TABLE live_pir_events ADD CONSTRAINT uq_pir_events UNIQUE (run_id, physical_node_id, sequence_num);
                END IF;
            END IF;
        END IF;

        -- =====================================================================
        -- Table 9: live_attack_events
        -- =====================================================================
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'live_attack_events') THEN
            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'live_attack_events' AND column_name = 'event_id';
            
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required primary key column event_id is missing from existing live_attack_events table. Cannot safely reconcile attack events.';
            ELSIF col_type = 'integer' THEN
                RAISE NOTICE 'Reconciliation: Widening live_attack_events.event_id from INTEGER to BIGINT...';
                ALTER TABLE live_attack_events ALTER COLUMN event_id TYPE BIGINT;
            ELSIF col_type <> 'bigint' THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Incompatible data type for column event_id in live_attack_events. Expected BIGINT, found %.', col_type;
            END IF;

            pk_cols := NULL;
            SELECT string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum)) INTO pk_cols
            FROM pg_constraint c
            JOIN pg_class t ON c.conrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
            WHERE n.nspname = 'public' AND t.relname = 'live_attack_events' AND c.contype = 'p';

            IF pk_cols IS NOT NULL THEN
                IF pk_cols <> 'event_id' THEN
                    RAISE EXCEPTION 'Schema Reconciliation Failure: Table live_attack_events has incompatible primary key (found: %, expected: event_id).', pk_cols;
                END IF;
            ELSE
                RAISE NOTICE 'Reconciliation: Adding PRIMARY KEY (event_id) constraint to live_attack_events...';
                ALTER TABLE live_attack_events ADD PRIMARY KEY (event_id);
            END IF;

            has_identity := FALSE;
            SELECT (a.attidentity IN ('a', 'd') OR d.adbin IS NOT NULL) INTO has_identity
            FROM pg_attribute a
            LEFT JOIN pg_attrdef d ON a.attrelid = d.adrelid AND a.attnum = d.adnum
            JOIN pg_class t ON a.attrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            WHERE n.nspname = 'public' AND t.relname = 'live_attack_events' AND a.attname = 'event_id';

            IF NOT COALESCE(has_identity, FALSE) THEN
                RAISE NOTICE 'Reconciliation: Adding GENERATED BY DEFAULT AS IDENTITY to live_attack_events.event_id...';
                ALTER TABLE live_attack_events ALTER COLUMN event_id ADD GENERATED BY DEFAULT AS IDENTITY;
            END IF;

            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'live_attack_events' AND column_name = 'run_id';
            
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required foreign key column run_id is missing from existing live_attack_events table. Cannot fabricate session relationships for attack events.';
            ELSIF col_type = 'integer' THEN
                RAISE NOTICE 'Reconciliation: Widening live_attack_events.run_id from INTEGER to BIGINT...';
                ALTER TABLE live_attack_events ALTER COLUMN run_id TYPE BIGINT;
            ELSIF col_type <> 'bigint' THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Incompatible data type for column run_id in live_attack_events. Expected BIGINT, found %.', col_type;
            END IF;

            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'live_attack_events' AND column_name = 'timestamp_epoch';
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required timestamp column timestamp_epoch is missing from existing live_attack_events table. Cannot fabricate attack event timestamps.';
            END IF;

            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'live_attack_events' AND column_name = 'timestamp_utc';
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required timestamp column timestamp_utc is missing from existing live_attack_events table. Cannot fabricate attack event timestamps.';
            END IF;

            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'live_attack_events' AND column_name = 'category';
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required column category is missing from existing live_attack_events table. Cannot fabricate detected attack categories.';
            END IF;

            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'live_attack_events' AND column_name = 'status';
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required column status is missing from existing live_attack_events table. Cannot fabricate attack verification status.';
            END IF;

            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'live_attack_events' AND column_name = 'severity';
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required column severity is missing from existing live_attack_events table. Cannot fabricate attack severity ratings.';
            END IF;

            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'live_attack_events' AND column_name = 'confidence';
            IF col_type IS NULL THEN
                RAISE EXCEPTION 'Schema Reconciliation Failure: Required detector column confidence is missing from existing live_attack_events table. Cannot fabricate frozen model confidence scores.';
            END IF;

            -- Standardize event_uuid to TEXT across upgrades safely and idempotently
            col_type := NULL;
            SELECT data_type INTO col_type FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = 'live_attack_events' AND column_name = 'event_uuid';

            IF col_type IS NULL THEN
                RAISE NOTICE 'Reconciliation: Adding missing event_uuid column to existing live_attack_events table...';
                ALTER TABLE live_attack_events ADD COLUMN event_uuid TEXT;
                UPDATE live_attack_events SET event_uuid = gen_random_uuid()::text WHERE event_uuid IS NULL;
                ALTER TABLE live_attack_events ALTER COLUMN event_uuid SET NOT NULL;
            ELSIF col_type <> 'text' THEN
                RAISE NOTICE 'Reconciliation: Standardizing event_uuid to TEXT...';
                ALTER TABLE live_attack_events ALTER COLUMN event_uuid TYPE TEXT USING event_uuid::text;
            END IF;

            IF EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'live_attack_events' 
                  AND column_name = 'event_uuid' AND is_nullable = 'YES'
            ) THEN
                UPDATE live_attack_events SET event_uuid = gen_random_uuid()::text WHERE event_uuid IS NULL;
                ALTER TABLE live_attack_events ALTER COLUMN event_uuid SET NOT NULL;
            END IF;

            ALTER TABLE live_attack_events ADD COLUMN IF NOT EXISTS window_id BIGINT;
            ALTER TABLE live_attack_events ADD COLUMN IF NOT EXISTS source_mac TEXT;
            ALTER TABLE live_attack_events ADD COLUMN IF NOT EXISTS target_ip TEXT;
            ALTER TABLE live_attack_events ADD COLUMN IF NOT EXISTS evidence_json JSONB NOT NULL DEFAULT '{}'::jsonb;
            ALTER TABLE live_attack_events ADD COLUMN IF NOT EXISTS missing_fields_json JSONB DEFAULT '[]'::jsonb;
            ALTER TABLE live_attack_events ADD COLUMN IF NOT EXISTS recommended_action TEXT;
            ALTER TABLE live_attack_events ADD COLUMN IF NOT EXISTS acknowledged INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE live_attack_events ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp();

            -- Drop specifically identified obsolete collision-prone constraint 'uq_attack_event'
            IF EXISTS (
                SELECT 1 FROM pg_constraint c
                JOIN pg_class t ON c.conrelid = t.oid
                JOIN pg_namespace n ON t.relnamespace = n.oid
                WHERE n.nspname = 'public' 
                  AND t.relname = 'live_attack_events' 
                  AND c.conname = 'uq_attack_event'
            ) THEN
                RAISE NOTICE 'Reconciliation: Dropping specifically identified legacy constraint "uq_attack_event" from live_attack_events...';
                ALTER TABLE live_attack_events DROP CONSTRAINT uq_attack_event;
            END IF;

            existing_uq_name := NULL;
            SELECT c.conname INTO existing_uq_name
            FROM pg_constraint c
            JOIN pg_class t ON c.conrelid = t.oid
            JOIN pg_namespace n ON t.relnamespace = n.oid
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
            WHERE n.nspname = 'public' AND t.relname = 'live_attack_events' AND c.contype = 'u'
            GROUP BY c.conname
            HAVING string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum)) = 'event_uuid'
            LIMIT 1;

            IF existing_uq_name IS NOT NULL THEN
                RAISE NOTICE 'Reconciliation: Validated existing unique constraint "%" covering (event_uuid) on live_attack_events.', existing_uq_name;
            ELSE
                uq_cols := NULL;
                SELECT string_agg(a.attname, ',' ORDER BY array_position(c.conkey, a.attnum)) INTO uq_cols
                FROM pg_constraint c
                JOIN pg_class t ON c.conrelid = t.oid
                JOIN pg_namespace n ON t.relnamespace = n.oid
                JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
                WHERE n.nspname = 'public' AND t.relname = 'live_attack_events' AND c.conname = 'uq_attack_event_uuid';

                IF uq_cols IS NOT NULL AND uq_cols <> 'event_uuid' THEN
                    RAISE EXCEPTION 'Schema Reconciliation Failure: Constraint uq_attack_event_uuid on live_attack_events has incompatible definition (found: %, expected: event_uuid).', uq_cols;
                ELSIF uq_cols IS NULL THEN
                    RAISE NOTICE 'Reconciliation: Adding uq_attack_event_uuid constraint to live_attack_events...';
                    ALTER TABLE live_attack_events ADD CONSTRAINT uq_attack_event_uuid UNIQUE (event_uuid);
                END IF;
            END IF;
        END IF;

        RAISE NOTICE 'Preflight: Full 9-table schema reconciliation completed successfully.';
    END IF;
END $$;


-- -----------------------------------------------------------------------------
-- 1. LEAST-PRIVILEGE ROLE & USER ARCHITECTURE (CORRECTION B ENFORCED)
-- -----------------------------------------------------------------------------

-- Ingestion Scoping Role (Non-login, strictly unprivileged)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'collector_role') THEN
        CREATE ROLE collector_role NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    ELSE
        ALTER ROLE collector_role NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    END IF;
END $$;

-- Dedicated Collector Ingestion User (For Supavisor Connection Pooler)
-- Security Guarantees:
--   1. If user does not exist, created WITH PASSWORD NULL and LOGIN enabled.
--   2. If user already exists, LOGIN and unprivileged attributes are reinforced
--      WITHOUT modifying or replacing the operator's existing password.
--   3. Strictly unprivileged (NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION, NOBYPASSRLS).
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'iot_collector') THEN
        CREATE USER iot_collector WITH LOGIN PASSWORD NULL INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    ELSE
        ALTER ROLE iot_collector WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    END IF;
END $$;

-- Ensure collector_role membership is granted to iot_collector
GRANT collector_role TO iot_collector;

-- Revoke default public schema creation privilege from PUBLIC to enforce least privilege
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- Supabase Compatibility: Grant USAGE on schema public to standard Supabase roles and collector_role
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role, collector_role;

-- -----------------------------------------------------------------------------
-- 2. BASE TABLE DEFINITIONS (STRICT AUDIT & IDEMPOTENCY)
-- -----------------------------------------------------------------------------

-- ─── Table 1: collector_status ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS collector_status (
    run_id              BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    started_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    last_heartbeat      TIMESTAMPTZ,
    interface_index     INTEGER,
    interface_name      TEXT,
    serial_port         TEXT,
    status              TEXT NOT NULL DEFAULT 'STARTING',
        CONSTRAINT chk_collector_status CHECK (status IN ('STARTING', 'RUNNING', 'STOPPED', 'ERROR')),
    stop_reason         TEXT,
    packets_parsed      BIGINT NOT NULL DEFAULT 0,
    windows_emitted     BIGINT NOT NULL DEFAULT 0,
    sensor_records      BIGINT NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

COMMENT ON TABLE collector_status IS 'Session lifecycle and heartbeat telemetry emitted by local LiveCollector.';
CREATE INDEX IF NOT EXISTS idx_collector_status_heartbeat ON collector_status(last_heartbeat DESC);
CREATE INDEX IF NOT EXISTS idx_collector_status_run_desc ON collector_status(run_id DESC);

-- ─── Table 2: device_registry ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS device_registry (
    mac_address         TEXT PRIMARY KEY,
        CONSTRAINT chk_mac_format CHECK (mac_address ~* '^([0-9a-f]{2}[:-]){5}([0-9a-f]{2})$'),
    node_id             TEXT NOT NULL,
    device_type         TEXT NOT NULL DEFAULT 'Phone_Client',
    label               TEXT NOT NULL DEFAULT 'real_observed_traffic',
    last_seen           TIMESTAMPTZ,
    notes               TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

COMMENT ON TABLE device_registry IS 'Curated inventory of registered Wi-Fi client stations.';
CREATE INDEX IF NOT EXISTS idx_device_registry_node ON device_registry(node_id);

-- ─── Table 3: station_pseudonym_map (Tokenized Privacy Layer) ────────────────
CREATE TABLE IF NOT EXISTS station_pseudonym_map (
    mac_address         TEXT PRIMARY KEY,
        CONSTRAINT chk_pseudo_mac CHECK (mac_address ~* '^([0-9a-f]{2}[:-]){5}([0-9a-f]{2})$'),
    pseudonym_id        TEXT NOT NULL UNIQUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

COMMENT ON TABLE station_pseudonym_map IS 'Protected private tokenization table decoupling public aliases from hardware MACs.';
CREATE INDEX IF NOT EXISTS idx_station_pseudonym ON station_pseudonym_map(pseudonym_id);

-- ─── Table 4: live_traffic_windows ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS live_traffic_windows (
    window_id           BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    run_id              BIGINT NOT NULL REFERENCES collector_status(run_id) ON DELETE RESTRICT,
    client_mac          TEXT NOT NULL,
    node_id             TEXT NOT NULL,
    node_type           TEXT,
    data_label          TEXT,
    bin_start_epoch     DOUBLE PRECISION NOT NULL,
    bin_end_epoch       DOUBLE PRECISION NOT NULL,
    window_center_epoch DOUBLE PRECISION,
    window_start_utc    TIMESTAMPTZ,
    window_end_utc      TIMESTAMPTZ,
    packet_count        INTEGER NOT NULL DEFAULT 0,
    mean_IAT            DOUBLE PRECISION,
    IAT_std             DOUBLE PRECISION,
    packet_rate         DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    mean_packet_size    DOUBLE PRECISION,
    packet_size_std     DOUBLE PRECISION,
    score_primary       DOUBLE PRECISION,
    pred_primary        INTEGER,
        CONSTRAINT chk_pred_primary CHECK (pred_primary IN (-1, 1) OR pred_primary IS NULL),
    score_timing        DOUBLE PRECISION,
    pred_timing         INTEGER,
        CONSTRAINT chk_pred_timing CHECK (pred_timing IN (-1, 1) OR pred_timing IS NULL),
    timing_status       TEXT,
        CONSTRAINT chk_timing_status CHECK (timing_status IN ('ACTIVE', 'UNAVAILABLE_N_LT_3') OR timing_status IS NULL),
    pred_dual           INTEGER,
        CONSTRAINT chk_pred_dual CHECK (pred_dual IN (-1, 1) OR pred_dual IS NULL),
    dual_reason         TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    
    -- Idempotency: Natural unique window key
    CONSTRAINT uq_traffic_window_run_mac_epoch UNIQUE (run_id, client_mac, bin_start_epoch)
);

COMMENT ON TABLE live_traffic_windows IS '1-second statistical feature windows scored by Dual Isolation Forest.';
CREATE INDEX IF NOT EXISTS idx_ltw_run_node ON live_traffic_windows(run_id, node_id);
CREATE INDEX IF NOT EXISTS idx_ltw_bin_start ON live_traffic_windows(bin_start_epoch DESC);
CREATE INDEX IF NOT EXISTS idx_ltw_run_bin_start ON live_traffic_windows(run_id, bin_start_epoch DESC);
CREATE INDEX IF NOT EXISTS idx_ltw_pred_dual ON live_traffic_windows(run_id, pred_dual) WHERE pred_dual = -1;

-- ─── Table 5: live_alerts ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS live_alerts (
    alert_id            BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    window_id           BIGINT NOT NULL REFERENCES live_traffic_windows(window_id) ON DELETE RESTRICT,
    run_id              BIGINT NOT NULL REFERENCES collector_status(run_id) ON DELETE RESTRICT,
    client_mac          TEXT NOT NULL,
    node_id             TEXT NOT NULL,
    bin_start_epoch     DOUBLE PRECISION NOT NULL,
    window_start_utc    TIMESTAMPTZ,
    dual_reason         TEXT NOT NULL,
    score_primary       DOUBLE PRECISION,
    score_timing        DOUBLE PRECISION,
    packet_rate         DOUBLE PRECISION,
    mean_packet_size    DOUBLE PRECISION,
    packet_count        INTEGER,
    acknowledged        INTEGER NOT NULL DEFAULT 0,
        CONSTRAINT chk_alert_ack CHECK (acknowledged IN (0, 1)),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    
    -- Idempotency: 1 alert per scored window
    CONSTRAINT uq_live_alerts_window UNIQUE (window_id)
);

COMMENT ON TABLE live_alerts IS 'Statistical anomaly alerts generated by the unsupervised Dual Isolation Forest.';
CREATE INDEX IF NOT EXISTS idx_alerts_run ON live_alerts(run_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_ack ON live_alerts(run_id, acknowledged);

-- ─── Table 6: unknown_device_obs ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS unknown_device_obs (
    obs_id              BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    run_id              BIGINT NOT NULL REFERENCES collector_status(run_id) ON DELETE RESTRICT,
    observed_mac        TEXT NOT NULL,
    first_seen_utc      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    last_seen_utc       TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    observation_count   INTEGER NOT NULL DEFAULT 1,
    acknowledged        INTEGER NOT NULL DEFAULT 0,
        CONSTRAINT chk_unknown_ack CHECK (acknowledged IN (0, 1)),
    
    -- Idempotency: 1 entry per run and MAC
    CONSTRAINT uq_unknown_mac_run UNIQUE (run_id, observed_mac)
);

COMMENT ON TABLE unknown_device_obs IS 'Observations of unregistered or randomized MAC addresses.';
CREATE INDEX IF NOT EXISTS idx_unknown_obs_run ON unknown_device_obs(run_id, last_seen_utc DESC);

-- ─── Table 7: live_sensor_telemetry ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS live_sensor_telemetry (
    telemetry_id        BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    run_id              BIGINT NOT NULL REFERENCES collector_status(run_id) ON DELETE RESTRICT,
    physical_node_id    TEXT NOT NULL DEFAULT 'esp32_gateway',
    logical_node_id     TEXT NOT NULL DEFAULT 'Node_1',
    sequence_num        INTEGER NOT NULL,
    uptime_ms           BIGINT NOT NULL,
    temperature_c       DOUBLE PRECISION,
    humidity_pct        DOUBLE PRECISION,
    dht_valid           INTEGER NOT NULL DEFAULT 0,
        CONSTRAINT chk_dht_valid CHECK (dht_valid IN (0, 1)),
    captured_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    sensor_epoch        DOUBLE PRECISION,
    
    -- Idempotency: Unique per sequence number from physical hardware
    CONSTRAINT uq_sensor_telemetry UNIQUE (run_id, physical_node_id, sequence_num)
);

COMMENT ON TABLE live_sensor_telemetry IS 'Node_1 DHT11 physical temperature and humidity telemetry.';
CREATE INDEX IF NOT EXISTS idx_sensor_run ON live_sensor_telemetry(run_id, captured_at ASC);

-- ─── Table 8: live_pir_events ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS live_pir_events (
    pir_id              BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    run_id              BIGINT NOT NULL REFERENCES collector_status(run_id) ON DELETE RESTRICT,
    physical_node_id    TEXT NOT NULL DEFAULT 'esp32_gateway',
    logical_node_id     TEXT NOT NULL DEFAULT 'Node_2',
    sequence_num        INTEGER NOT NULL,
    uptime_ms           BIGINT NOT NULL,
    motion_detected     INTEGER NOT NULL,
        CONSTRAINT chk_pir_motion CHECK (motion_detected IN (0, 1)),
    captured_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    sensor_epoch        DOUBLE PRECISION,
    
    -- Idempotency: Unique per sequence number from physical hardware
    CONSTRAINT uq_pir_events UNIQUE (run_id, physical_node_id, sequence_num)
);

COMMENT ON TABLE live_pir_events IS 'Node_2 PIR physical motion detection events.';
CREATE INDEX IF NOT EXISTS idx_pir_run ON live_pir_events(run_id, captured_at ASC);

-- ─── Table 9: live_attack_events (F-01 Stable Event ID) ─────────────────────
CREATE TABLE IF NOT EXISTS live_attack_events (
    event_id            BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    event_uuid          TEXT NOT NULL,
        CONSTRAINT uq_attack_event_uuid UNIQUE (event_uuid),
    run_id              BIGINT NOT NULL REFERENCES collector_status(run_id) ON DELETE RESTRICT,
    window_id           BIGINT REFERENCES live_traffic_windows(window_id) ON DELETE SET NULL,
    timestamp_epoch     DOUBLE PRECISION NOT NULL,
    timestamp_utc       TIMESTAMPTZ NOT NULL,
    category            TEXT NOT NULL,
        CONSTRAINT chk_attack_category CHECK (category IN (
            'Denial_of_Service',
            'Reconnaissance_Port_Scan',
            'Spoofing_Impersonation',
            'Deauthentication_Disassociation_Abuse',
            'Replay_Attack'
        )),
    status              TEXT NOT NULL,
        CONSTRAINT chk_attack_status CHECK (status IN (
            'NO_EVIDENCE',
            'INSUFFICIENT_TELEMETRY',
            'SUSPICIOUS',
            'CONFIRMED_THREAT'
        )),
    severity            TEXT NOT NULL,
        CONSTRAINT chk_attack_severity CHECK (severity IN (
            'NONE',
            'INFO',
            'LOW',
            'MEDIUM',
            'HIGH',
            'CRITICAL'
        )),
    confidence          DOUBLE PRECISION NOT NULL,
        CONSTRAINT chk_confidence_range CHECK (confidence >= 0.0 AND confidence <= 1.0),
    source_mac          TEXT,
    target_ip           TEXT,
    evidence_json       JSONB NOT NULL DEFAULT '{}'::jsonb,
    missing_fields_json JSONB DEFAULT '[]'::jsonb,
    recommended_action  TEXT,
    acknowledged        INTEGER NOT NULL DEFAULT 0,
        CONSTRAINT chk_attack_ack CHECK (acknowledged IN (0, 1)),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

COMMENT ON TABLE live_attack_events IS 'Explainable deterministic cyberattack events with stable idempotent event_uuid.';
CREATE INDEX IF NOT EXISTS idx_attack_run_cat ON live_attack_events(run_id, category, status);
CREATE INDEX IF NOT EXISTS idx_attack_timestamp ON live_attack_events(timestamp_epoch DESC);
CREATE INDEX IF NOT EXISTS idx_attack_severity ON live_attack_events(run_id, severity) WHERE severity IN ('HIGH', 'CRITICAL');
CREATE INDEX IF NOT EXISTS idx_attack_event_uuid ON live_attack_events(event_uuid);

-- -----------------------------------------------------------------------------
-- 3. SANITIZED PUBLIC VIEWS (COMPLETE TEXT VALIDATION & CRASH-PROOF CASTS)
-- -----------------------------------------------------------------------------

-- ─── View 1: v_public_collector_status (Sanitized Stop Reason) ───────────────
CREATE OR REPLACE VIEW v_public_collector_status WITH (security_invoker = false) AS
SELECT 
    run_id,
    started_at,
    last_heartbeat,
    ROUND(EXTRACT(EPOCH FROM (clock_timestamp() - last_heartbeat))::numeric, 1) AS heartbeat_age_seconds,
    CASE 
        WHEN last_heartbeat IS NULL THEN 'OFFLINE'
        WHEN EXTRACT(EPOCH FROM (clock_timestamp() - last_heartbeat)) <= 15.0 THEN 'LIVE'
        WHEN EXTRACT(EPOCH FROM (clock_timestamp() - last_heartbeat)) <= 60.0 THEN 'STALE'
        ELSE 'OFFLINE'
    END AS connection_state,
    CASE WHEN interface_name IS NOT NULL THEN 'Local_Hotspot_Virtual_AP' ELSE NULL END AS interface_name,
    CASE WHEN serial_port IS NOT NULL THEN 'ESP32_Serial_UART' ELSE NULL END AS serial_port,
    status,
    -- Sanitize stop_reason: Prevents leakage of internal file paths, stack traces, or exception text
    CASE 
        WHEN stop_reason IS NULL THEN NULL
        WHEN stop_reason ILIKE '%user%' OR stop_reason ILIKE '%keyboard%' OR stop_reason ILIKE '%manual%' THEN 'Operator Requested Shutdown'
        WHEN stop_reason ILIKE '%timeout%' THEN 'Network Timeout'
        WHEN stop_reason ILIKE '%error%' OR stop_reason ILIKE '%exception%' OR stop_reason ILIKE '%fail%' THEN 'Collector Error'
        WHEN stop_reason ILIKE '%normal%' OR stop_reason ILIKE '%completed%' THEN 'Normal Shutdown'
        ELSE 'Session Terminated'
    END AS stop_reason,
    packets_parsed,
    windows_emitted,
    sensor_records
FROM collector_status;

-- ─── View 2: v_public_device_registry (Curated Station View & Allowlist) ─────
CREATE OR REPLACE VIEW v_public_device_registry WITH (security_invoker = false) AS
SELECT 
    -- Strict allowlist enforcement for public station identifier (Correction 1)
    CASE 
        WHEN node_id IN ('Node_3', 'Node_4', 'Node_5') THEN node_id
        ELSE 'Unspecified_Node'
    END AS public_station_id,
    CASE 
        WHEN node_id IN ('Node_3', 'Node_4', 'Node_5') THEN node_id
        ELSE 'Unspecified_Node'
    END AS node_id,
    CASE 
        WHEN device_type IN ('Phone_Client', 'IoT_Sensor', 'Gateway_AP') THEN device_type
        ELSE 'Client_Device'
    END AS device_type,
    CASE 
        WHEN label IN ('real_observed_traffic', 'baseline_benign', 'demo_traffic') THEN label
        ELSE 'registered_station'
    END AS label,
    last_seen,
    CASE 
        WHEN notes ILIKE '%phone 1%' THEN 'Authorized Hotspot Client 1'
        WHEN notes ILIKE '%phone 2%' THEN 'Authorized Hotspot Client 2'
        ELSE 'Registered Station'
    END AS notes
FROM device_registry;

-- ─── View 3: v_public_live_traffic_windows (Full Categorical Allowlists) ─────
CREATE OR REPLACE VIEW v_public_live_traffic_windows WITH (security_invoker = false) AS
SELECT 
    w.window_id,
    w.run_id,
    -- Strict allowlist enforcement for public pseudonym / station identifier (Correction 2)
    CASE 
        WHEN m.pseudonym_id IN ('Node_3', 'Node_4', 'Node_5') THEN m.pseudonym_id
        WHEN w.node_id IN ('Node_3', 'Node_4', 'Node_5') THEN w.node_id
        ELSE 'UNMAPPED_STATION'
    END AS public_station_id,
    -- Controlled categorical projection for node_id
    CASE 
        WHEN w.node_id IN ('Node_3', 'Node_4', 'Node_5') THEN w.node_id
        ELSE 'Unspecified_Node'
    END AS node_id,
    -- Controlled categorical projection for node_type
    CASE 
        WHEN w.node_type IN ('Phone_Client', 'IoT_Sensor', 'Gateway_AP', 'Unknown_Client') THEN w.node_type
        ELSE 'Unspecified_Device'
    END AS node_type,
    -- Controlled categorical projection for data_label
    CASE 
        WHEN w.data_label IN ('real_observed_traffic', 'baseline_benign', 'attack_simulation', 'demo_traffic') THEN w.data_label
        ELSE 'live_telemetry'
    END AS data_label,
    w.bin_start_epoch,
    w.bin_end_epoch,
    w.window_center_epoch,
    w.window_start_utc,
    w.window_end_utc,
    w.packet_count,
    w.mean_IAT,
    w.IAT_std,
    w.packet_rate,
    w.mean_packet_size,
    w.packet_size_std,
    w.score_primary,
    w.pred_primary,
    w.score_timing,
    w.pred_timing,
    w.timing_status,
    w.pred_dual,
    -- Controlled categorical projection for dual_reason
    CASE 
        WHEN w.dual_reason IN (
            'NORMAL_INLIER', 
            'ANOMALY_PRIMARY_BURST_OR_SIZE', 
            'ANOMALY_TIMING_JITTER', 
            'ANOMALY_PRIMARY_AND_TIMING', 
            'NORMAL_QUIET_TIMING_UNAVAILABLE'
        ) THEN w.dual_reason
        ELSE 'EVALUATION_PENDING'
    END AS dual_reason,
    w.created_at
FROM live_traffic_windows w
LEFT JOIN station_pseudonym_map m ON w.client_mac = m.mac_address;

-- ─── View 4: v_public_live_alerts (Categorical Allowlist Enforced) ────────────
CREATE OR REPLACE VIEW v_public_live_alerts WITH (security_invoker = false) AS
SELECT 
    a.alert_id,
    a.window_id,
    a.run_id,
    -- Strict allowlist enforcement for public pseudonym / station identifier (Correction 2)
    CASE 
        WHEN m.pseudonym_id IN ('Node_3', 'Node_4', 'Node_5') THEN m.pseudonym_id
        WHEN a.node_id IN ('Node_3', 'Node_4', 'Node_5') THEN a.node_id
        ELSE 'UNMAPPED_STATION'
    END AS public_station_id,
    -- Controlled categorical projection for node_id
    CASE 
        WHEN a.node_id IN ('Node_3', 'Node_4', 'Node_5') THEN a.node_id
        ELSE 'Unspecified_Node'
    END AS node_id,
    a.bin_start_epoch,
    a.window_start_utc,
    -- Controlled categorical projection for dual_reason
    CASE 
        WHEN a.dual_reason IN (
            'NORMAL_INLIER', 
            'ANOMALY_PRIMARY_BURST_OR_SIZE', 
            'ANOMALY_TIMING_JITTER', 
            'ANOMALY_PRIMARY_AND_TIMING', 
            'NORMAL_QUIET_TIMING_UNAVAILABLE'
        ) THEN a.dual_reason
        ELSE 'EVALUATION_PENDING'
    END AS dual_reason,
    a.score_primary,
    a.score_timing,
    a.packet_rate,
    a.mean_packet_size,
    a.packet_count,
    a.acknowledged,
    a.created_at
FROM live_alerts a
LEFT JOIN station_pseudonym_map m ON a.client_mac = m.mac_address;

-- ─── View 5: v_public_unknown_device_obs (Neutral Alias Fallback) ─────────────
CREATE OR REPLACE VIEW v_public_unknown_device_obs WITH (security_invoker = false) AS
SELECT 
    u.obs_id,
    u.run_id,
    -- Strict allowlist enforcement for public device alias (Correction 2)
    CASE 
        WHEN m.pseudonym_id IN ('Node_3', 'Node_4', 'Node_5') THEN m.pseudonym_id
        ELSE 'UNREGISTERED_STATION'
    END AS public_device_alias,
    u.first_seen_utc,
    u.last_seen_utc,
    u.observation_count,
    u.acknowledged
FROM unknown_device_obs u
LEFT JOIN station_pseudonym_map m ON u.observed_mac = m.mac_address;

-- ─── View 6: v_public_sensor_telemetry ───────────────────────────────────────
CREATE OR REPLACE VIEW v_public_sensor_telemetry WITH (security_invoker = false) AS
SELECT 
    telemetry_id,
    run_id,
    -- Strict allowlist enforcement for physical_node_id (Objective 2)
    CASE 
        WHEN physical_node_id IN ('esp32_gateway', 'esp32_sensor_node_1', 'esp32_sensor_node_2') THEN physical_node_id
        ELSE 'esp32_sanitized_node'
    END AS physical_node_id,
    -- Strict allowlist enforcement for sensor logical_node_id (Correction 2)
    CASE 
        WHEN logical_node_id IN ('Node_1', 'Node_2', 'Node_3', 'Node_4', 'Node_5') THEN logical_node_id
        ELSE 'Node_1'
    END AS logical_node_id,
    sequence_num,
    uptime_ms,
    temperature_c,
    humidity_pct,
    dht_valid,
    captured_at,
    sensor_epoch
FROM live_sensor_telemetry;

-- ─── View 7: v_public_pir_events ────────────────────────────────────────────
CREATE OR REPLACE VIEW v_public_pir_events WITH (security_invoker = false) AS
SELECT 
    pir_id,
    run_id,
    -- Strict allowlist enforcement for physical_node_id (Objective 2)
    CASE 
        WHEN physical_node_id IN ('esp32_gateway', 'esp32_sensor_node_1', 'esp32_sensor_node_2') THEN physical_node_id
        ELSE 'esp32_sanitized_node'
    END AS physical_node_id,
    -- Strict allowlist enforcement for PIR logical_node_id (Correction 2)
    CASE 
        WHEN logical_node_id IN ('Node_1', 'Node_2', 'Node_3', 'Node_4', 'Node_5') THEN logical_node_id
        ELSE 'Node_2'
    END AS logical_node_id,
    sequence_num,
    uptime_ms,
    motion_detected,
    captured_at,
    sensor_epoch
FROM live_pir_events;

-- ─── View 8: v_public_attack_events (Categorical Evidence & Crash-Proof) ─────
CREATE OR REPLACE VIEW v_public_attack_events WITH (security_invoker = false) AS
SELECT 
    e.event_id,
    e.event_uuid,
    e.run_id,
    e.window_id,
    e.timestamp_epoch,
    e.timestamp_utc,
    e.category,
    e.status,
    e.severity,
    e.confidence,
    -- Strict allowlist enforcement for source_station_id: zero raw MAC or unvetted token (Correction 2)
    CASE 
        WHEN e.source_mac IS NOT NULL AND m.pseudonym_id IN ('Node_3', 'Node_4', 'Node_5') THEN m.pseudonym_id
        WHEN e.source_mac IS NOT NULL THEN 'ATTACKER_UNMAPPED'
        ELSE NULL 
    END AS source_station_id,
    -- Semantic network classification handling IPv4 and IPv6 without leakage
    CASE 
        WHEN e.target_ip IS NULL OR TRIM(e.target_ip) = '' THEN NULL
        WHEN e.target_ip ~ '^192\.168\.' 
          OR e.target_ip ~ '^10\.' 
          OR e.target_ip ~ '^172\.(1[6-9]|2[0-9]|3[0-1])\.' 
          OR e.target_ip = '127.0.0.1' THEN 'LOCAL_NETWORK'
        WHEN e.target_ip ~ '^fe80:' 
          OR e.target_ip ~ '^fc00:' 
          OR e.target_ip ~ '^fd[0-9a-fA-F]{2}:' 
          OR e.target_ip = '::1' THEN 'LOCAL_NETWORK'
        WHEN e.target_ip ~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' 
          OR e.target_ip LIKE '%:%' THEN 'EXTERNAL_NETWORK'
        ELSE 'IP_REDACTED'
    END AS target_ip,
    
    -- Crash-Proof Categorical Evidence Projection (Correction C Enforced)
    CASE 
        WHEN e.evidence_json IS NOT NULL AND jsonb_typeof(e.evidence_json) = 'object' THEN
            jsonb_strip_nulls(jsonb_build_object(
                -- Categorical allowlist for verdict: prevents arbitrary text injection
                'verdict', CASE 
                    WHEN e.evidence_json->>'verdict' IN (
                        '802.11 Deauthentication / Disassociation flood detected',
                        '802.11 management frames present without deauthentication flood',
                        'Conflicting IP-to-MAC binding detected',
                        'Consistent identity binding',
                        'Deauth frame rate below threshold',
                        'Distributed local traffic volume',
                        'Gateway IP impersonation attempt',
                        'Legitimate IP-to-MAC binding handover confirmed',
                        'Legitimate gateway traffic',
                        'Legitimate network-wide surge',
                        'No replay violations observed',
                        'Normal traffic volume',
                        'Normal transport diversity',
                        'Ongoing conflicting IP-to-MAC observation (tracked)',
                        'Outbound application transfer (WAN)',
                        'Pending IP-to-MAC lease transition',
                        'Potential replay attack detected',
                        'Reconnaissance / scanning pattern observed',
                        'Sustained local infrastructure flood',
                        'Transient packet burst',
                        'Unassigned or non-unicast source address'
                    ) THEN e.evidence_json->>'verdict'
                    WHEN e.evidence_json->>'verdict' IS NOT NULL THEN 'Security Evaluation finding'
                    ELSE NULL
                END,
                'destination_scope', CASE 
                    WHEN e.evidence_json->>'destination_scope' ILIKE '%LAN%' THEN 'Local LAN Subnet'
                    WHEN e.evidence_json->>'destination_scope' ILIKE '%WAN%' THEN 'WAN / Internet'
                    ELSE 'Network Scope'
                END,
                -- Numeric fields bounds-checked before casting: 100% immune to integer/float overflow (Correction 3)
                'probe_counts', CASE WHEN (e.evidence_json->>'probe_counts') ~ '^[0-9]{1,9}$' THEN (e.evidence_json->>'probe_counts')::int ELSE NULL END,
                'distinct_ports_count', CASE WHEN (e.evidence_json->>'distinct_ports_count') ~ '^[0-9]{1,9}$' THEN (e.evidence_json->>'distinct_ports_count')::int ELSE NULL END,
                'distinct_hosts_count', CASE WHEN (e.evidence_json->>'distinct_hosts_count') ~ '^[0-9]{1,9}$' THEN (e.evidence_json->>'distinct_hosts_count')::int ELSE NULL END,
                'tcp_syn_count', CASE WHEN (e.evidence_json->>'tcp_syn_count') ~ '^[0-9]{1,9}$' THEN (e.evidence_json->>'tcp_syn_count')::int ELSE NULL END,
                'udp_probe_count', CASE WHEN (e.evidence_json->>'udp_probe_count') ~ '^[0-9]{1,9}$' THEN (e.evidence_json->>'udp_probe_count')::int ELSE NULL END,
                'current_rate_pps', CASE WHEN (e.evidence_json->>'current_rate_pps') ~ '^[0-9]{1,8}(\.[0-9]{1,4})?$' THEN (e.evidence_json->>'current_rate_pps')::float ELSE NULL END,
                'rate_threshold_pps', CASE WHEN (e.evidence_json->>'rate_threshold_pps') ~ '^[0-9]{1,8}(\.[0-9]{1,4})?$' THEN (e.evidence_json->>'rate_threshold_pps')::float ELSE NULL END,
                'consecutive_windows', CASE WHEN (e.evidence_json->>'consecutive_windows') ~ '^[0-9]{1,9}$' THEN (e.evidence_json->>'consecutive_windows')::int ELSE NULL END,
                'target_concentration', CASE WHEN (e.evidence_json->>'target_concentration') ~ '^[0-9]{1,3}(\.[0-9]{1,4})?$' THEN (e.evidence_json->>'target_concentration')::float ELSE NULL END,
                'is_vertical_scan', CASE WHEN (e.evidence_json->>'is_vertical_scan') IN ('true', 'false') THEN (e.evidence_json->>'is_vertical_scan')::boolean ELSE NULL END,
                'is_horizontal_sweep', CASE WHEN (e.evidence_json->>'is_horizontal_sweep') IN ('true', 'false') THEN (e.evidence_json->>'is_horizontal_sweep')::boolean ELSE NULL END,
                'total_mgmt_frames', CASE WHEN (e.evidence_json->>'total_mgmt_frames') ~ '^[0-9]{1,9}$' THEN (e.evidence_json->>'total_mgmt_frames')::int ELSE NULL END,
                'deauth_count', CASE WHEN (e.evidence_json->>'deauth_count') ~ '^[0-9]{1,9}$' THEN (e.evidence_json->>'deauth_count')::int ELSE NULL END,
                -- Categorical allowlist for reason: prevents leakage of stack traces or paths
                'reason', CASE 
                    WHEN e.evidence_json->>'reason' IN (
                        'Capture stream lacks transport layer port metadata (dst_port, src_port, tcp_flags).',
                        'Missing destination IP address in traffic observation; cannot evaluate target focus.',
                        'Missing required window rate or MAC identifiers',
                        'No packets in window',
                        'No packets provided in observation window',
                        'No packets to evaluate',
                        'Packet lacks eth_src or ip_src'
                    ) THEN e.evidence_json->>'reason'
                    WHEN e.evidence_json->>'reason' IS NOT NULL THEN 'Telemetry explanation recorded'
                    ELSE NULL
                END
            ))
        ELSE '{}'::jsonb
    END AS sanitized_evidence_json,
    
    -- Crash-Proof Missing Fields: Filters against known schema columns, safe default on malformed array
    CASE 
        WHEN e.missing_fields_json IS NULL OR jsonb_typeof(e.missing_fields_json) != 'array' THEN '[]'::jsonb
        ELSE (
            SELECT COALESCE(jsonb_agg(to_jsonb(elem)), '[]'::jsonb)
            FROM jsonb_array_elements_text(e.missing_fields_json) AS elem
            WHERE elem IN (
                'packet_rate', 'mac_address', 'ip_dst', 'dst_port', 'src_port', 
                'tcp_flags', 'gateway_mac', 'wlan_fc_type_subtype', 'wlan_reason_code', 
                'wlan_bssid', 'payload_hash', 'protocol_seq_num', 'nonce'
            )
        )
    END AS missing_fields_json,
    
    -- Templated SOC Guidance: Zero-regex mathematical impossibility of address leakage
    CASE e.category
        WHEN 'Denial_of_Service' THEN 
            'Inspect high-rate traffic flow and rate-limit source endpoint if unauthorized.'
        WHEN 'Reconnaissance_Port_Scan' THEN 
            'Inspect transport-layer probing activity and verify if scanning host is an authorized network administrator.'
        WHEN 'Spoofing_Impersonation' THEN 
            'Audit IP-to-MAC gateway binding table and inspect physical switch/AP port for conflicting ARP claims.'
        WHEN 'Deauthentication_Disassociation_Abuse' THEN 
            'Audit 802.11 management frames for 802.11w Protected Management Frames (PMF) enforcement.'
        WHEN 'Replay_Attack' THEN 
            'Inspect packet sequence counters and verify transport-layer TLS/crypto nonce validation.'
        ELSE 
            'Review security alert triage logs.'
    END AS recommended_action,
    
    e.acknowledged,
    e.created_at
FROM live_attack_events e
LEFT JOIN station_pseudonym_map m ON e.source_mac = m.mac_address;

-- ─── View 9: v_public_traffic_overview (Fast Aggregated Overview for Header) ─
CREATE OR REPLACE VIEW v_public_traffic_overview WITH (security_invoker = false) AS
SELECT 
    w.run_id,
    COUNT(*) AS total_windows,
    COALESCE(SUM(w.packet_count), 0) AS total_packets,
    COUNT(*) FILTER (WHERE w.pred_dual = -1) AS anomaly_windows,
    COUNT(*) FILTER (WHERE w.pred_primary = -1) AS primary_flags,
    COUNT(*) FILTER (WHERE w.pred_timing = -1 AND w.timing_status = 'ACTIVE') AS timing_flags,
    ROUND((COUNT(*) FILTER (WHERE w.pred_dual = -1)::numeric / NULLIF(COUNT(*), 0) * 100.0), 2) AS anomaly_pct,
    COALESCE(AVG(w.packet_rate), 0.0) AS avg_rate,
    COALESCE(MAX(w.packet_rate), 0.0) AS peak_rate,
    MAX(w.window_start_utc) AS latest_window_utc
FROM live_traffic_windows w
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
ALTER VIEW v_public_traffic_overview OWNER TO postgres;

-- -----------------------------------------------------------------------------
-- 4. ROW-LEVEL SECURITY (RLS) & LEAST-PRIVILEGE ACCESS CONTROL (PoLP)
-- -----------------------------------------------------------------------------

-- Enable RLS on all 9 base tables (Idempotent in PostgreSQL)
ALTER TABLE collector_status ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE station_pseudonym_map ENABLE ROW LEVEL SECURITY;
ALTER TABLE live_traffic_windows ENABLE ROW LEVEL SECURITY;
ALTER TABLE live_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE unknown_device_obs ENABLE ROW LEVEL SECURITY;
ALTER TABLE live_sensor_telemetry ENABLE ROW LEVEL SECURITY;
ALTER TABLE live_pir_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE live_attack_events ENABLE ROW LEVEL SECURITY;

-- ─── Atomic, Repeatable Policy Management ────────────────────────────────────
DROP POLICY IF EXISTS "collector_status_crud" ON collector_status;
CREATE POLICY "collector_status_crud" ON collector_status
    FOR ALL TO collector_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "collector_devices_crud" ON device_registry;
CREATE POLICY "collector_devices_crud" ON device_registry
    FOR ALL TO collector_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "collector_pseudonyms_crud" ON station_pseudonym_map;
CREATE POLICY "collector_pseudonyms_crud" ON station_pseudonym_map
    FOR ALL TO collector_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "collector_windows_crud" ON live_traffic_windows;
CREATE POLICY "collector_windows_crud" ON live_traffic_windows
    FOR ALL TO collector_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "collector_alerts_crud" ON live_alerts;
CREATE POLICY "collector_alerts_crud" ON live_alerts
    FOR ALL TO collector_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "collector_unknown_crud" ON unknown_device_obs;
CREATE POLICY "collector_unknown_crud" ON unknown_device_obs
    FOR ALL TO collector_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "collector_sensors_crud" ON live_sensor_telemetry;
CREATE POLICY "collector_sensors_crud" ON live_sensor_telemetry
    FOR ALL TO collector_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "collector_pir_crud" ON live_pir_events;
CREATE POLICY "collector_pir_crud" ON live_pir_events
    FOR ALL TO collector_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "collector_attacks_crud" ON live_attack_events;
CREATE POLICY "collector_attacks_crud" ON live_attack_events
    FOR ALL TO collector_role USING (true) WITH CHECK (true);

-- ─── Principle of Least Privilege: Granular Permissions by Table ─────────────
-- Category A: Mutable State Tables (SELECT, INSERT, UPDATE)
GRANT SELECT, INSERT, UPDATE ON TABLE 
    collector_status,
    device_registry,
    unknown_device_obs
TO collector_role;

-- Category B: Immutable Time-Series & Security Evidence Tables (SELECT, INSERT ONLY)
GRANT SELECT, INSERT ON TABLE 
    station_pseudonym_map,
    live_traffic_windows,
    live_alerts,
    live_sensor_telemetry,
    live_pir_events,
    live_attack_events
TO collector_role;

-- ─── Scope Sequence Privileges Strictly to Project-Owned Tables ──────────────
-- Grant USAGE and SELECT to collector_role ONLY on sequences belonging to this project's tables.
-- Unrelated sequences in the public schema belonging to extensions or other apps are untouched.
DO $$
DECLARE
    seq_name TEXT;
    project_sequences TEXT[] := ARRAY[
        pg_get_serial_sequence('collector_status', 'run_id'),
        pg_get_serial_sequence('live_traffic_windows', 'window_id'),
        pg_get_serial_sequence('live_alerts', 'alert_id'),
        pg_get_serial_sequence('unknown_device_obs', 'obs_id'),
        pg_get_serial_sequence('live_sensor_telemetry', 'telemetry_id'),
        pg_get_serial_sequence('live_pir_events', 'pir_id'),
        pg_get_serial_sequence('live_attack_events', 'event_id')
    ];
BEGIN
    FOREACH seq_name IN ARRAY project_sequences
    LOOP
        IF seq_name IS NOT NULL THEN
            EXECUTE format('GRANT USAGE, SELECT ON SEQUENCE %s TO collector_role;', seq_name);
        END IF;
    END LOOP;
END $$;

-- Explicitly Revoke UPDATE on all Immutable Tables from collector_role
REVOKE UPDATE ON TABLE 
    station_pseudonym_map,
    live_traffic_windows,
    live_alerts,
    live_sensor_telemetry,
    live_pir_events,
    live_attack_events
FROM collector_role;

-- Explicitly Revoke DELETE and TRUNCATE across ALL 9 base tables from collector_role
REVOKE DELETE, TRUNCATE ON TABLE 
    collector_status,
    device_registry,
    station_pseudonym_map,
    live_traffic_windows,
    live_alerts,
    unknown_device_obs,
    live_sensor_telemetry,
    live_pir_events,
    live_attack_events
FROM collector_role;

-- ─── Grant Read-Only Permissions for anon & authenticated (PUBLIC DASHBOARD) ────
-- Explicitly revoke direct access to all 9 base tables from anon, authenticated, and PUBLIC
REVOKE ALL ON TABLE 
    collector_status,
    device_registry,
    station_pseudonym_map,
    live_traffic_windows,
    live_alerts,
    unknown_device_obs,
    live_sensor_telemetry,
    live_pir_events,
    live_attack_events
FROM anon, authenticated, PUBLIC;

-- Explicitly revoke sequence privileges on project-owned sequences from anon, authenticated, and PUBLIC
DO $$
DECLARE
    seq_name TEXT;
    project_sequences TEXT[] := ARRAY[
        pg_get_serial_sequence('collector_status', 'run_id'),
        pg_get_serial_sequence('live_traffic_windows', 'window_id'),
        pg_get_serial_sequence('live_alerts', 'alert_id'),
        pg_get_serial_sequence('unknown_device_obs', 'obs_id'),
        pg_get_serial_sequence('live_sensor_telemetry', 'telemetry_id'),
        pg_get_serial_sequence('live_pir_events', 'pir_id'),
        pg_get_serial_sequence('live_attack_events', 'event_id')
    ];
BEGIN
    FOREACH seq_name IN ARRAY project_sequences
    LOOP
        IF seq_name IS NOT NULL THEN
            EXECUTE format('REVOKE ALL ON SEQUENCE %s FROM anon, authenticated, PUBLIC;', seq_name);
        END IF;
    END LOOP;
END $$;

-- Grant SELECT ONLY on sanitized definer views to anon and authenticated
GRANT SELECT ON TABLE 
    v_public_collector_status,
    v_public_device_registry,
    v_public_live_traffic_windows,
    v_public_live_alerts,
    v_public_unknown_device_obs,
    v_public_sensor_telemetry,
    v_public_pir_events,
    v_public_attack_events,
    v_public_traffic_overview
TO anon, authenticated;

-- Explicitly revoke all modifications on views from anon, authenticated, and PUBLIC
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON 
    v_public_collector_status,
    v_public_device_registry,
    v_public_live_traffic_windows,
    v_public_live_alerts,
    v_public_unknown_device_obs,
    v_public_sensor_telemetry,
    v_public_pir_events,
    v_public_attack_events,
    v_public_traffic_overview
FROM anon, authenticated, PUBLIC;

-- -----------------------------------------------------------------------------
-- 5. SEED CURATED LAB CLIENTS & PRIVACY MAPPINGS (CORRECTION A ENFORCED)
-- -----------------------------------------------------------------------------
-- NOTICE: The following two MAC addresses represent the operator's verified
-- physical hotspot test clients from the frozen Stage 9 demonstration baseline:
--   - Node_3 (ca:34:ea:92:d3:9e): Phone 1 (Hotspot client)
--   - Node_4 (e6:2e:db:73:1c:25): Phone 2 (Hotspot client)
-- 
-- CORRECTION A ENFORCEMENT: Uses 'ON CONFLICT (mac_address) DO NOTHING'.
-- Existing operator-edited notes, labels, or custom pseudonym tokens will NEVER
-- be overwritten when this migration is rerun.
-- 
-- To deliberately modify a device mapping in the future, the operator executes:
--   UPDATE device_registry SET notes = '...' WHERE mac_address = '...';

INSERT INTO device_registry (mac_address, node_id, device_type, label, notes)
VALUES 
    ('ca:34:ea:92:d3:9e', 'Node_3', 'Phone_Client', 'real_observed_traffic', 'Phone 1 (verified hotspot client)'),
    ('e6:2e:db:73:1c:25', 'Node_4', 'Phone_Client', 'real_observed_traffic', 'Phone 2 (verified hotspot client)')
ON CONFLICT (mac_address) DO NOTHING;

INSERT INTO station_pseudonym_map (mac_address, pseudonym_id)
VALUES 
    ('ca:34:ea:92:d3:9e', 'Node_3'),
    ('e6:2e:db:73:1c:25', 'Node_4')
ON CONFLICT (mac_address) DO NOTHING;

-- -----------------------------------------------------------------------------
-- 6. POSTGREST SCHEMA CACHE REFRESH NOTIFICATION
-- -----------------------------------------------------------------------------
NOTIFY pgrst, 'reload schema';

-- -----------------------------------------------------------------------------
-- COMMIT TRANSACTION
-- -----------------------------------------------------------------------------
COMMIT;
