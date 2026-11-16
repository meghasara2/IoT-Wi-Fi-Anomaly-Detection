-- =============================================================================
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

-- Revoke default public schema access from PUBLIC
REVOKE ALL ON SCHEMA public FROM PUBLIC;

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
    node_id AS public_station_id,
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
    COALESCE(
        m.pseudonym_id, 
        CASE 
            WHEN w.node_id IN ('Node_3', 'Node_4', 'Node_5') THEN w.node_id
            ELSE 'UNMAPPED_STATION'
        END
    ) AS public_station_id,
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
    COALESCE(
        m.pseudonym_id, 
        CASE 
            WHEN a.node_id IN ('Node_3', 'Node_4', 'Node_5') THEN a.node_id
            ELSE 'UNMAPPED_STATION'
        END
    ) AS public_station_id,
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
    COALESCE(m.pseudonym_id, 'UNREGISTERED_STATION') AS public_device_alias,
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
    'esp32_gateway' AS physical_node_id,
    logical_node_id,
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
    'esp32_gateway' AS physical_node_id,
    logical_node_id,
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
    -- Neutral alias fallback; zero MD5 or raw MAC
    CASE 
        WHEN e.source_mac IS NOT NULL THEN 
            COALESCE(m.pseudonym_id, 'ATTACKER_UNMAPPED')
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
                -- Numeric fields pre-validated with regex before casting (crash-proof)
                'probe_counts', CASE WHEN (e.evidence_json->>'probe_counts') ~ '^-?[0-9]+$' THEN (e.evidence_json->>'probe_counts')::int ELSE NULL END,
                'distinct_ports_count', CASE WHEN (e.evidence_json->>'distinct_ports_count') ~ '^-?[0-9]+$' THEN (e.evidence_json->>'distinct_ports_count')::int ELSE NULL END,
                'distinct_hosts_count', CASE WHEN (e.evidence_json->>'distinct_hosts_count') ~ '^-?[0-9]+$' THEN (e.evidence_json->>'distinct_hosts_count')::int ELSE NULL END,
                'tcp_syn_count', CASE WHEN (e.evidence_json->>'tcp_syn_count') ~ '^-?[0-9]+$' THEN (e.evidence_json->>'tcp_syn_count')::int ELSE NULL END,
                'udp_probe_count', CASE WHEN (e.evidence_json->>'udp_probe_count') ~ '^-?[0-9]+$' THEN (e.evidence_json->>'udp_probe_count')::int ELSE NULL END,
                'current_rate_pps', CASE WHEN (e.evidence_json->>'current_rate_pps') ~ '^-?[0-9]+(\.[0-9]+)?$' THEN (e.evidence_json->>'current_rate_pps')::float ELSE NULL END,
                'rate_threshold_pps', CASE WHEN (e.evidence_json->>'rate_threshold_pps') ~ '^-?[0-9]+(\.[0-9]+)?$' THEN (e.evidence_json->>'rate_threshold_pps')::float ELSE NULL END,
                'consecutive_windows', CASE WHEN (e.evidence_json->>'consecutive_windows') ~ '^-?[0-9]+$' THEN (e.evidence_json->>'consecutive_windows')::int ELSE NULL END,
                'target_concentration', CASE WHEN (e.evidence_json->>'target_concentration') ~ '^-?[0-9]+(\.[0-9]+)?$' THEN (e.evidence_json->>'target_concentration')::float ELSE NULL END,
                'is_vertical_scan', CASE WHEN (e.evidence_json->>'is_vertical_scan') IN ('true', 'false') THEN (e.evidence_json->>'is_vertical_scan')::boolean ELSE NULL END,
                'is_horizontal_sweep', CASE WHEN (e.evidence_json->>'is_horizontal_sweep') IN ('true', 'false') THEN (e.evidence_json->>'is_horizontal_sweep')::boolean ELSE NULL END,
                'total_mgmt_frames', CASE WHEN (e.evidence_json->>'total_mgmt_frames') ~ '^-?[0-9]+$' THEN (e.evidence_json->>'total_mgmt_frames')::int ELSE NULL END,
                'deauth_count', CASE WHEN (e.evidence_json->>'deauth_count') ~ '^-?[0-9]+$' THEN (e.evidence_json->>'deauth_count')::int ELSE NULL END,
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

-- Sequences required for IDENTITY autoincrement primary keys
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO collector_role;

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

-- ─── Grant Read-Only Permissions for anon (PUBLIC DASHBOARD) ────────────────
-- Revoke direct access to all base tables from anon and PUBLIC
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
FROM anon, PUBLIC;

-- Grant SELECT ONLY on sanitized views to anon
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
TO anon;

-- Revoke all modifications on views
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
FROM anon, PUBLIC;

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
