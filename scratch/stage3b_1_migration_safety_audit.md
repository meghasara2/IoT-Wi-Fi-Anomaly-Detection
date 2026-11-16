# STAGE 3B.1 — FINAL SUPABASE MIGRATION SAFETY AUDIT REPORT

**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Application:** IoT Network Guard — Dual-Detector SOC Console  
**Document Type:** Final Pre-Execution Security, Integrity & Idempotency Audit  
**Audited Artifacts:**
- `scratch/stage3b_supabase_migration.sql` (Baseline 3.0.0 DDL)
- `scratch/validate_stage3b_sql.py` (Static AST test suite)
- `scratch/stage3a_2_network_delivery_readiness.md` (Telemetry delivery specification)
- `scratch/stage2_4_final_implementation_audit.md` (Cryptographic & identity audit)
- Supabase Project: `meghasara2's Project` (`cwqumhtzeiqrfhlesksw`), Region: Mumbai (`ap-south-1`), Engine: PostgreSQL 17.6

**Audit Date:** November 15, 2026  
**Auditor:** Antigravity AI Cybersecurity & Cloud Systems Architecture Engine  
**Audit Decision:** **CONDITIONAL HOLD — TWO CRITICAL DEFECTS IDENTIFIED; REMEDIATION REQUIRED PRIOR TO MANUAL EXECUTION**

---

## 1. EXECUTIVE SUMMARY & AUDIT VERDICT

This Stage 3B.1 safety audit performs an exhaustive, independent technical evaluation of `scratch/stage3b_supabase_migration.sql` and the associated delivery architecture before any SQL is executed against the live Supabase PostgreSQL 17.6 database in Mumbai.

### Summary of Audit Findings:

| Finding ID | Severity | Category | Summary Description |
| :-: | :---: | :--- | :--- |
| **CRIT-01** | **CRITICAL** | Credential Safety | **Default/Placeholder Password Embedded in DDL:** Line 50 contains `WITH PASSWORD 'IotGuard_SecureCollector_2026!'`. Hardcoding credentials in versioned SQL violates zero-trust standards. |
| **CRIT-02** | **CRITICAL** | SQL Idempotency | **`CREATE POLICY` Fails on Re-Execution:** Lines 547–572 use `CREATE POLICY` without `DROP POLICY IF EXISTS`. PostgreSQL lacks `IF NOT EXISTS` for policies; any re-run crashes with `ERROR: policy already exists`. |
| **CRIT-03** | **CRITICAL** | Telemetry Delivery | **Drop-Oldest Queue Hazard for Discrete Alerts:** The delivery architecture co-mingled PIR events, sensor telemetry, and ML anomaly alerts into the drop-oldest circular queue (`maxsize=1000`), risking silent dropping during prolonged outages. |
| **NONCRIT-01**| **MEDIUM** | Pseudonym Privacy | **View Fallback Emits Unsalted Invertible MD5:** Views 3, 4, 5, and 8 fall back to `MD5(mac)` if unmapped in `station_pseudonym_map`. 48-bit MACs hashed with unsalted MD5 can be inverted via GPU rainbow tables in seconds. |
| **NONCRIT-02**| **LOW** | Presentation | **Target IP Masking Hardcodes Subnet:** View 8 hardcodes `'192.168.137.***'`, which inaccurately misrepresents external WAN targets (e.g. `8.8.8.8`) as local LAN traffic. |
| **NONCRIT-03**| **INFORMATIONAL**| View Security | **View-Owner RLS Bypass Semantics:** Confirmed `security_invoker = false` is intentional and required, but base table RLS does not filter view rows. View projection is the sole security boundary. |
| **NONCRIT-04**| **INFORMATIONAL**| Test Scope | **Test Limitations Transparently Declared:** Static AST parsing and dialect compilation passed 100%, but no local PostgreSQL runtime engine was used. |

**Verdict:** The existing `scratch/stage3b_supabase_migration.sql` script is **NOT SAFE for immediate manual execution** in its current form due to **CRIT-01** and **CRIT-02**. The exact corrections must be applied to produce a fully safe baseline before running in the Supabase SQL Editor.

---

## 2. SECTION 1: CREDENTIAL SAFETY AUDIT

### 2.1 Inspection of Role, User, and Authentication Statements
The relevant authentication block in `scratch/stage3b_supabase_migration.sql` (lines 36–56) was audited:

```sql
-- Ingestion Role (Non-login, for permission scoping)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'collector_role') THEN
        CREATE ROLE collector_role NOLOGIN INHERIT;
    END IF;
END $$;

-- Dedicated Collector Ingestion User (For Supavisor Connection Pooler)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'iot_collector') THEN
        CREATE USER iot_collector WITH PASSWORD 'IotGuard_SecureCollector_2026!' INHERIT;
        GRANT collector_role TO iot_collector;
    END IF;
END $$;

GRANT collector_role TO iot_collector;
```

### 2.2 Critical Finding CRIT-01: Embedded Default Password
- **The Defect:** Line 50 contains an explicit, hardcoded password literal: `'IotGuard_SecureCollector_2026!'`.
- **The Risk:** 
  1. If executed as-is, this default password becomes active on the cloud database.
  2. Because migration scripts reside in local repositories and will be committed/pushed in Stage 4, this credential would be permanently recorded in Git revision history.
  3. Anyone inspecting the repository could authenticate over public pooler port 5432 or 6543 using `iot_collector.cwqumhtzeiqrfhlesksw` and insert arbitrary records into the monitoring tables.
- **Audit Requirement:** **Zero credentials embedded in migration scripts.**

### 2.3 Required Remediation for Credential Safety
1. **Decouple User Creation from Password Provisioning:**  
   In PostgreSQL, a login user can be created with `PASSWORD NULL` (or without specifying a password). A user with a null password cannot authenticate using password authentication:
   ```sql
   DO $$
   BEGIN
       IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'iot_collector') THEN
           CREATE USER iot_collector WITH PASSWORD NULL INHERIT;
           GRANT collector_role TO iot_collector;
       END IF;
   END $$;
   ```
2. **Out-of-Band Password Configuration by Operator:**  
   The human operator must set a high-entropy, secret password directly in the Supabase SQL Editor immediately after running the schema migration:
   ```sql
   ALTER USER iot_collector WITH PASSWORD '<STRONG_RANDOMLY_GENERATED_PASSWORD>';
   ```
3. **No Administrative Postgres Credentials for Telemetry:**  
   The audit confirms that the administrative `postgres` superuser is **never used** for collector telemetry. Only the dedicated `iot_collector` role is used by the collector workstation.

---

## 3. SECTION 2: COLLECTOR PERMISSIONS & ACCESS CONTROL AUDIT

### 2.1 Privilege Verification Matrix

The privileges granted to `collector_role` (and inherited by `iot_collector`) in lines 574–600 were audited:

| Database Object / Capability | Granted Privilege | Evaluated Status | Security Assessment |
| :--- | :---: | :---: | :--- |
| **Schema `public`** | `USAGE` | ✅ Compliant | Cannot create, alter, or drop tables or views. |
| **Base Tables (9 tables)** | `SELECT`, `INSERT`, `UPDATE` | ✅ Compliant | Required for streaming telemetry, upserting idempotency, and status updates. |
| **Base Tables `DELETE`** | **REVOKED** | ✅ Compliant | Explicitly revoked via `REVOKE DELETE ON TABLE ... FROM collector_role;`. |
| **Base Tables `TRUNCATE`** | **REVOKED** | ✅ Compliant | Explicitly revoked via `REVOKE TRUNCATE ON TABLE ... FROM collector_role;`. |
| **Sequences (`identity` / `seq`)** | `USAGE`, `SELECT` | ✅ Compliant | Granted via `GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO collector_role;`. Sufficient for `IDENTITY` columns. |
| **Role / Schema Creation** | **NONE** | ✅ Compliant | Role has no `CREATEROLE`, `CREATEDB`, or `SUPERUSER` attributes. |
| **System Schemas (`auth`, `storage`, `vault`)** | **NONE** | ✅ Compliant | Zero grants on any Supabase internal schema. |
| **Role Inheritance** | `INHERIT` | ✅ Compliant | `collector_role` and `iot_collector` both have `INHERIT`, allowing clean privilege propagation across Supavisor pooler sessions. |

### 2.2 Verification of Sequences
All auto-incrementing primary keys in the 9 tables are defined using PostgreSQL standard:
`BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY`
Under PostgreSQL, identity columns use internal sequence objects. The statement:
`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO collector_role;`
guarantees that `iot_collector` can insert rows without encountering sequence permission errors.

---

## 4. SECTION 3: PUBLIC VIEW SECURITY & PRIVACY AUDIT

### 4.1 Column-by-Column Exposure Audit across All 9 Views

| View Name | Columns Exposed | Raw MACs Exposed? | Raw IPs Exposed? | Raw Evidence JSON? |
| :--- | :--- | :---: | :---: | :---: |
| `v_public_collector_status` | `run_id`, `started_at`, `last_heartbeat`, `heartbeat_age_seconds`, `connection_state`, `interface_name`, `serial_port`, `status`, `stop_reason`, `packets_parsed`, `windows_emitted`, `sensor_records` | ❌ None | ❌ None | ❌ None |
| `v_public_device_registry` | `public_station_id`, `node_id`, `device_type`, `label`, `last_seen`, `notes` | ❌ Omitted | ❌ None | ❌ None |
| `v_public_live_traffic_windows` | `window_id`, `run_id`, `public_station_id`, `node_id`, `node_type`, `data_label`, `bin_start_epoch`, `bin_end_epoch`, `window_center_epoch`, `window_start_utc`, `window_end_utc`, `packet_count`, `mean_IAT`, `IAT_std`, `packet_rate`, `mean_packet_size`, `packet_size_std`, `score_primary`, `pred_primary`, `score_timing`, `pred_timing`, `timing_status`, `pred_dual`, `dual_reason`, `created_at` | ❌ Omitted | ❌ None | ❌ None |
| `v_public_live_alerts` | `alert_id`, `window_id`, `run_id`, `public_station_id`, `node_id`, `bin_start_epoch`, `window_start_utc`, `dual_reason`, `score_primary`, `score_timing`, `packet_rate`, `mean_packet_size`, `packet_count`, `acknowledged`, `created_at` | ❌ Omitted | ❌ None | ❌ None |
| `v_public_unknown_device_obs` | `obs_id`, `run_id`, `public_device_alias`, `first_seen_utc`, `last_seen_utc`, `observation_count`, `acknowledged` | ❌ Omitted | ❌ None | ❌ None |
| `v_public_sensor_telemetry` | `telemetry_id`, `run_id`, `physical_node_id`, `logical_node_id`, `sequence_num`, `uptime_ms`, `temperature_c`, `humidity_pct`, `dht_valid`, `captured_at`, `sensor_epoch` | ❌ None | ❌ None | ❌ None |
| `v_public_pir_events` | `pir_id`, `run_id`, `physical_node_id`, `logical_node_id`, `sequence_num`, `uptime_ms`, `motion_detected`, `captured_at`, `sensor_epoch` | ❌ None | ❌ None | ❌ None |
| `v_public_attack_events` | `event_id`, `event_uuid`, `run_id`, `window_id`, `timestamp_epoch`, `timestamp_utc`, `category`, `status`, `severity`, `confidence`, `source_station_id`, `target_ip`, `sanitized_evidence_json`, `missing_fields_json`, `recommended_action`, `acknowledged`, `created_at` | ❌ Omitted | ⚠️ Host Masked (`.***`) | ❌ Vetted Allowlist Only |
| `v_public_traffic_overview` | `run_id`, `total_windows`, `total_packets`, `anomaly_windows`, `primary_flags`, `timing_flags`, `anomaly_pct`, `avg_rate`, `peak_rate`, `latest_window_utc` | ❌ None | ❌ None | ❌ None |

### 4.2 Non-Critical Finding NONCRIT-01: Invertible Unsalted MD5 Fallback in Views
- **Inspection:** In Views 3, 4, 5, and 8, the pseudonym logic uses:
  ```sql
  COALESCE(m.pseudonym_id, CONCAT('CLIENT-', UPPER(SUBSTRING(MD5(w.client_mac) FROM 1 FOR 6))))
  ```
- **The Risk:** If an observed client or attacker MAC is not yet entered in `station_pseudonym_map`, the view falls back to an unsalted MD5 hash of `client_mac`. Because a MAC address has only 48 bits, an unsalted MD5 hash can be reversed in seconds using GPU precomputed tables, unmasking the station's physical hardware address.
- **Correction:** The fallback must not hash the raw MAC. It should fall back to a non-reversible label:
  ```sql
  COALESCE(m.pseudonym_id, CONCAT('STATION-UNMAPPED-', w.window_id::text))
  ```
  Or the local collector must guarantee transactional insertion of `(mac_address, random_pseudonym)` into `station_pseudonym_map` prior to window emission.

### 4.3 View Ownership & PostgreSQL RLS Evaluation Mechanics
- **PostgreSQL 17.6 View Execution Context:**
  By default, PostgreSQL views execute with `security_invoker = false`. This means the query executes with the permissions of the **view owner** (`postgres`).
  - Because `postgres` owns the view and possesses `BYPASSRLS`, queries against `v_public_*` bypass the RLS policies on underlying base tables.
  - This behavior is **intentional and mandatory**: if `security_invoker = true` were set, `anon` would attempt to evaluate the base tables directly and crash with `ERROR: permission denied for table live_traffic_windows`.
  - **Security Guarantee:** Anonymous users (`anon`) are granted `SELECT` **exclusively on the 9 views**. Direct `SELECT`, `INSERT`, `UPDATE`, `DELETE`, and `TRUNCATE` on all 9 base tables are explicitly revoked from `anon` and `PUBLIC`.
  - **Sole Boundary:** The view query definition itself is the ultimate projection barrier. Because the view definitions omit raw MACs and project allowlisted JSON, `anon` cannot access private data.

---

## 5. SECTION 4: TELEMETRY RELIABILITY & QUEUE SAFETY AUDIT

### 5.1 Critical Finding CRIT-03: Drop-Oldest Queue Hazard for Discrete Telemetry
In the Stage 2 schema design and Stage 3A.2 delivery proposal, telemetry was dispatched via two paths:
1. `critical_queue`: Attack events and session lifecycle records.
2. `telemetry_queue`: 1-second traffic feature bins, DHT11 readings, PIR events, and unknown MAC observations, configured with:
   > *"In prolonged network blackouts, this buffer discards oldest traffic windows once 1,000 items are queued."*

#### Hazard Analysis:
- In a 3-station network, 1-second feature bins emit ~180 records per minute.
- A buffer of `maxsize=1000` fills in **5.5 minutes**.
- If a PIR physical motion event (`live_pir_events`), an unknown rogue MAC observation (`unknown_device_obs`), or a Dual Isolation Forest anomaly alert (`live_alerts`) is queued in the same FIFO queue as traffic windows, **it will be pushed out and silently discarded after 5.5 minutes of network disconnection!**
- This violates the explicit requirement: *"Sensor telemetry and anomaly alerts must be retried. Critical records must never be silently dropped."*

### 5.2 Required 3-Tier Delivery Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                      LOCAL WORKSTATION (Sovereign Core)                │
│                                                                        │
│   TShark / ML Detectors                       ESP32 Physical Gateway   │
│              │                                        │                │
│              ▼                                        ▼                │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │   SYNCHRONOUS WRITE TO LOCAL SQLITE (WAL JOURNAL)              │   │
│   │   data/live_monitoring.db — ALWAYS SUCCEEDS, ZERO NETWORK WAIT │   │
│   └───────────────────────────────┬────────────────────────────────┘   │
│                                   │                                    │
│                    Strict 3-Way Priority Dispatch                      │
│                                   │                                    │
│         ┌─────────────────────────┼─────────────────────────┐          │
│         ▼                         ▼                         ▼          │
│  ┌──────────────┐          ┌──────────────┐          ┌──────────────┐  │
│  │    TIER 1    │          │    TIER 2    │          │    TIER 3    │  │
│  │ Attack Events│          │ PIR Events,  │          │ 1-Second     │  │
│  │ & Lifecycle  │          │ Sensor DHT11,│          │ Traffic      │  │
│  │ Start/Stop   │          │ ML Alerts    │          │ Feature Bins │  │
│  └──────┬───────┘          └──────┬───────┘          └──────┬───────┘  │
│         ▼                         ▼                         ▼          │
│  ┌──────────────┐          ┌──────────────┐          ┌──────────────┐  │
│  │ Disk Journal │          │ Memory Retry │          │ Ring Buffer  │  │
│  │ (Append-Only)│          │ Queue        │          │ maxsize=1000 │  │
│  │ NEVER DROP   │          │ Exponential  │          │ DROP-OLDEST  │  │
│  │ Fsync backed │          │ Backoff      │          │ SHEDDING     │  │
│  │              │          │ NEVER DROP   │          │ PERMITTED    │  │
│  └──────┬───────┘          └──────┬───────┘          └──────┬───────┘  │
│         │                         │                         │          │
│         └─────────────────────────┼─────────────────────────┘          │
│                                   ▼                                    │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │ CloudSyncWorker Thread: Port 5432 / 6543                       │   │
│   │ Idempotent Inserts: ON CONFLICT (...) DO NOTHING               │   │
│   └───────────────────────────────┬────────────────────────────────┘   │
└───────────────────────────────────┼────────────────────────────────────┘
                                    │ Outbound TLS 1.3 (~42 ms)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   SUPABASE MANAGED POSTGRESQL (Mumbai)                 │
└────────────────────────────────────────────────────────────────────────┘
```

#### The 3 Strict Delivery Rules:
1. **Tier 1 (Critical Security Evidence):** Written to disk journal (`cloud_offline_journal.jsonl`) with `fsync`. Replayed upon restart. **Zero drop rate.**
2. **Tier 2 (Physical & Operational Alerts):** Dedicated retry queue with persistent delivery status. Retried indefinitely until acknowledged. **Zero silent dropping.**
3. **Tier 3 (High-Rate Traffic Windows):** Drop-oldest shedding permitted **exclusively** for high-volume 1-second statistical bins (`live_traffic_windows`). Local SQLite retains 100% of all windows; cloud console drops historical backlog during extended disconnects to immediately display fresh, current traffic upon reconnection.

---

## 6. SECTION 5: SQL MIGRATION SAFETY & IDEMPOTENCY AUDIT

### 6.1 Critical Finding CRIT-02: Non-Idempotent `CREATE POLICY` Statements
- **Inspection:** In `scratch/stage3b_supabase_migration.sql`, lines 547–572 define Row Level Security policies using bare `CREATE POLICY`:
  ```sql
  CREATE POLICY "collector_status_crud" ON collector_status
      FOR ALL TO collector_role USING (true) WITH CHECK (true);
  ```
- **The Defect:** In PostgreSQL 17 (and all prior versions), `CREATE POLICY` does **NOT** support an `IF NOT EXISTS` clause.
- **The Failure Mode:** If the operator runs the migration once, and then re-runs it (e.g. to apply an update or recover from a partial network drop), PostgreSQL immediately halts with:
  `ERROR: policy "collector_status_crud" for table "collector_status" already exists`.
- **The Fix:** Every `CREATE POLICY` statement must be preceded by an idempotent drop:
  ```sql
  DROP POLICY IF EXISTS "collector_status_crud" ON collector_status;
  CREATE POLICY "collector_status_crud" ON collector_status
      FOR ALL TO collector_role USING (true) WITH CHECK (true);
  ```

### 6.2 Relational Integrity & Key Constraints Audit

| Table Name | Primary Key | Foreign Key Rules | Unique Constraints | Idempotency Evaluated |
| :--- | :--- | :--- | :--- | :---: |
| `collector_status` | `run_id` (Identity) | None | None | ✅ Safe |
| `device_registry` | `mac_address` | None | None | ✅ Safe |
| `station_pseudonym_map` | `mac_address` | None | `pseudonym_id UNIQUE` | ✅ Safe |
| `live_traffic_windows` | `window_id` (Identity) | `run_id -> collector_status` (`ON DELETE RESTRICT`) | `(run_id, client_mac, bin_start_epoch)` | ✅ Safe |
| `live_alerts` | `alert_id` (Identity) | `window_id -> live_traffic_windows` (`ON DELETE RESTRICT`)<br>`run_id -> collector_status` (`ON DELETE RESTRICT`) | `(window_id)` | ✅ Safe |
| `unknown_device_obs` | `obs_id` (Identity) | `run_id -> collector_status` (`ON DELETE RESTRICT`) | `(run_id, observed_mac)` | ✅ Safe |
| `live_sensor_telemetry` | `telemetry_id` (Identity) | `run_id -> collector_status` (`ON DELETE RESTRICT`) | `(run_id, physical_node_id, sequence_num)` | ✅ Safe |
| `live_pir_events` | `pir_id` (Identity) | `run_id -> collector_status` (`ON DELETE RESTRICT`) | `(run_id, physical_node_id, sequence_num)` | ✅ Safe |
| `live_attack_events` | `event_id` (Identity) | `run_id -> collector_status` (`ON DELETE RESTRICT`)<br>`window_id -> live_traffic_windows` (`ON DELETE SET NULL`) | `event_uuid UNIQUE` | ✅ Safe |

---

## 7. SECTION 6: EXACT SQL STATEMENTS REQUIRING CORRECTION

To elevate `scratch/stage3b_supabase_migration.sql` to a production-safe baseline, the following exact SQL modifications must be made:

### Correction 1: Remove Embedded Password (Resolves CRIT-01)
**Existing SQL (Lines 47–53):**
```sql
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'iot_collector') THEN
        CREATE USER iot_collector WITH PASSWORD 'IotGuard_SecureCollector_2026!' INHERIT;
        GRANT collector_role TO iot_collector;
    END IF;
END $$;
```
**Replacement SQL:**
```sql
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'iot_collector') THEN
        CREATE USER iot_collector WITH PASSWORD NULL INHERIT;
        GRANT collector_role TO iot_collector;
    END IF;
END $$;
```

### Correction 2: Idempotent RLS Policies (Resolves CRIT-02)
**Existing SQL (Lines 546–572):**
```sql
CREATE POLICY "collector_status_crud" ON collector_status
    FOR ALL TO collector_role USING (true) WITH CHECK (true);
...
```
**Replacement SQL:**
```sql
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
```

### Correction 3: Remove Invertible MD5 Fallback (Resolves NONCRIT-01)
In Views 3, 4, 5, and 8, replace `MD5(mac)` fallback with non-hardware pseudonyms:
- **View 3 & 4:** Replace `ELSE CONCAT('CLIENT-', UPPER(SUBSTRING(MD5(...) FROM 1 FOR 6)))` with `'UNMAPPED_STATION'`.
- **View 5:** Replace `CONCAT('CLIENT-', UPPER(SUBSTRING(MD5(u.observed_mac) FROM 1 FOR 6)))` with `'UNREGISTERED_OBSERVATION'`.
- **View 8:** Replace `CONCAT('ATTACKER-', UPPER(SUBSTRING(MD5(e.source_mac) FROM 1 FOR 6)))` with `'ATTACKER_UNMAPPED'`.

### Correction 4: Dynamic IP Host Masking (Resolves NONCRIT-02)
In View 8 (lines 461–464), replace:
```sql
CASE 
    WHEN e.target_ip IS NOT NULL THEN '192.168.137.***'
    ELSE NULL 
END AS target_ip,
```
With:
```sql
CASE 
    WHEN e.target_ip IS NOT NULL THEN REGEXP_REPLACE(e.target_ip, '\.[0-9]+$', '.***')
    ELSE NULL 
END AS target_ip,
```

---

## 8. SECTION 7: VALIDATION STATUS & ENGINE SCOPE DECLARATION

In strict accordance with project guidelines:
> *"Do not claim PostgreSQL runtime verification unless an actual PostgreSQL engine was used."*

### Formal Declaration of Validation Scope:
1. **Static AST Analysis:** Passed 10/10 checks (`validate_stage3b_sql.py`). Verified table declarations, view names, column types, FK rules, and role inheritance.
2. **PostgreSQL Grammar Compilation:** Verified against SQLAlchemy 2.0.35 PostgreSQL dialect compiler.
3. **Live Catalog Execution:** **NOT EXECUTED.** The workstation possesses no local PostgreSQL service, `psql` client, or Docker container. The script has **NOT** been run against the cloud Supabase database. Live runtime verification is deferred to the authorized execution step in Stage 3B.

---

## 9. REMAINING PREREQUISITES BEFORE MANUAL EXECUTION

Before the operator pastes the migration script into the Supabase SQL Editor:
1. **Apply Corrections to Produce `scratch/stage3b_supabase_migration.sql` (Version 3.1.0):**
   - Apply Correction 1 (Password removal).
   - Apply Correction 2 (`DROP POLICY IF EXISTS`).
   - Apply Correction 3 (MD5 fallback removal).
   - Apply Correction 4 (Dynamic IP masking).
2. **Operator Out-of-Band Password Selection:**
   - Prepare a 32-character high-entropy secret string to configure for `iot_collector` via `ALTER USER`.
3. **Local Workstation `.gitignore` Hardening:**
   - Add `.env` to `.gitignore` so local connection credentials are never staged or committed to Git.

---

## 10. AFFIRMATION OF STRICT RESTRICTIONS

In strict compliance with Stage 3B.1 audit instructions:
- **No database connections were attempted.**
- **No SQL was executed against Supabase.**
- **No roles, users, or credentials were created.**
- **No application source files (`src/`), firmware, models, or SQLite databases were modified.**
- **Hardware (`COM6`), TShark, and live collectors remain idle.**
- **No Git commits, pushes, or deployments were performed.**
- **Existing migration and deliverable files remain preserved and unmodified.**

Execution is now halted. I await your review of this audit report!

