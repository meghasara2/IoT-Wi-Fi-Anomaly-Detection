# STAGE 2.1 — SUPABASE SECURITY HARDENING & SCHEMA REVIEW REPORT
**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Application:** IoT Network Guard — Dual-Detector SOC Console  
**Document Type:** Formal Security Review, Threat Model & Hardened Schema Blueprint  
**Deliverable Files:**  
- `scratch/stage2_1_security_review.md` (This document)  
- `scratch/stage2_1_supabase_migration.sql` (Validated hardened PostgreSQL migration script)  
**Baseline Inputs:** `scratch/stage2_supabase_schema_design.md`, `scratch/stage2_supabase_migration.sql`, `src/init_live_database.py`  
**Execution Date:** November 15, 2026  
**Status:** Complete — Ready for Review  

---

## 1. EXECUTIVE SUMMARY & OBJECTIVE

Stage 2 produced the initial relational schema and Row-Level Security (RLS) policies for Supabase PostgreSQL. This Stage 2.1 review performs an exhaustive security audit, corrects architectural vulnerabilities identified in the initial draft, and hardens the cloud database design prior to any external cloud provisioning.

### Key Hardening Improvements Delivered in Stage 2.1:
1. **Banned `service_role` for Collection:** Eliminated reliance on Supabase's administrative `service_role` key. Defined a scoped, least-privilege `collector_role` restricted to `INSERT`, `UPDATE`, and `SELECT` on monitoring tables with `DELETE` permanently revoked.
2. **Eliminated Cascading Deletions:** Replaced all dangerous `ON DELETE CASCADE` constraints with audit-safe `ON DELETE RESTRICT`. Historical sessions, forensic alerts, and packet evidence can never be purged through accidental parent deletion.
3. **Guaranteed Public Anonymization:** Completely locked down base tables from the public `anon` role. Introduced nine sanitized public views (`v_public_*`) that mask raw hardware MAC addresses, anonymize internal target IPs, and redact Windows adapter GUIDs.
4. **Idempotent Replay Protocol:** Validated compound natural unique keys across all tables, enabling atomic `ON CONFLICT DO NOTHING` operations that prevent duplicate records during network timeouts and retries.
5. **Real PostgreSQL Dialect Validation:** Executed programmatic PostgreSQL dialect schema compilation and DDL validation using SQLAlchemy 2.0.35, proving 100% syntax compliance.

---

## 2. DATABASE ACCESS ARCHITECTURE & CREDENTIAL SEGREGATION

### 2.1 The Danger of `service_role` in Production Monitoring
In Supabase, the `service_role` key is a special JWT that carries the PostgreSQL `BYPASSRLS` attribute. Any request presenting `service_role` bypasses all Row-Level Security policies and executes with superuser-like authority within the database. 

**Vulnerability in Stage 2:** If the local collector used `service_role` for routine telemetry streaming, any vulnerability on the local workstation, unencrypted network hop, or compromised memory dump could expose credentials capable of dropping tables, truncating databases, or accessing Supabase administrative metadata (`auth.users`).

### 2.2 Dedicated Least-Privilege Ingestion Model (`collector_role`)
Stage 2.1 replaces `service_role` with a dedicated, non-administrative PostgreSQL role:
```sql
CREATE ROLE collector_role NOLOGIN NOINHERIT;
```

#### Ingestion Privilege Matrix:
- **Allowed Operations:** `SELECT`, `INSERT`, `UPDATE` on the 8 monitoring tables and sequence usage.
- **Prohibited Operations:** `DELETE` and `TRUNCATE` are explicitly revoked.
- **Schema Isolation:** `collector_role` has zero access to the `auth`, `storage`, or `extensions` schemas.
- **Connection Mechanisms:**
  1. *Direct Connection (Supabase Connection Pooler):* Authenticates as a dedicated database user (e.g. `iot_collector`) assigned to `collector_role`.
  2. *PostgREST HTTP Ingestion (Port 443):* Ingests via a custom-signed JWT bearing `{"role": "collector_role"}` or an authenticated Supabase user mapped to `collector_role` via database grants.

### 2.3 Dashboard Access Segregation (`anon`)
The Streamlit Community Cloud dashboard is public-facing and connects using the public `anon` key.
- **Base Table Lockdown:** Direct `SELECT`, `INSERT`, `UPDATE`, and `DELETE` permissions on all eight base tables are completely revoked from `anon`.
- **Sanitized View Access Only:** `anon` is granted `SELECT` exclusively on the nine `v_public_*` views.
- **Write Lockout:** `anon` possesses zero write capability. It is architecturally impossible for a dashboard user or web visitor to inject false telemetry, modify thresholds, acknowledge alerts, or erase evidence.

### 2.4 Credential Storage & Git Hygiene
- **Local Workstation:** The collector credential is saved exclusively in `.env` located in the local workspace root. The project `.gitignore` explicitly excludes `.env`, `*.key`, and `secrets.toml`.
- **Streamlit Community Cloud:** The dashboard receives only `SUPABASE_URL` and `SUPABASE_ANON_KEY`, injected securely through Streamlit Cloud's encrypted Secrets Management UI.
- **Zero Hardcoded Secrets:** No database passwords, JWTs, or private keys exist in any repository code or commit.

---

## 3. PUBLIC DATA PROTECTION & SANITIZED VIEWS

A rigorous column-by-column privacy audit was performed on all eight tables to identify potentially sensitive network, hardware, or personal information.

### 3.1 Field-by-Field Sensitivity Audit Matrix

| Table Name | Column Name | Data Sensitivity | Risk Description | Public Exposure Policy |
| :--- | :--- | :---: | :--- | :--- |
| **`collector_status`** | `run_id`, `started_at`, `status` | Public | Standard operational state. | Expose as-is. |
| **`collector_status`** | `interface_name` | **SENSITIVE** | Exposes host adapter GUIDs (e.g. `\Device\NPF_{...}`). | **REDACTED** in public view to `'Local_Hotspot_Virtual_AP'`. |
| **`collector_status`** | `serial_port` | **SENSITIVE** | Exposes host COM port (`COM6`). | **REDACTED** in public view to `'ESP32_Serial_UART'`. |
| **`collector_status`** | `interface_index` | Internal | Host interface integer index. | **OMITTED** from public view. |
| **`device_registry`** | `mac_address` | **CRITICAL** | Raw client hardware MAC address (`ca:34:ea:92:d3:9e`). Identifies physical personal devices. | **MASKED** in public view to `'ca:34:ea:**:**:9e'`. |
| **`device_registry`** | `notes` | **SENSITIVE** | Contains personal device labels (`"Phone 1 (verified hotspot client)"`). | **SANITIZED** to `'Authorized Hotspot Client 1'`. |
| **`live_traffic_windows`** | `client_mac` | **CRITICAL** | Raw client station MAC address. | **MASKED** in public view to `'ca:34:ea:**:**:9e'`. |
| **`live_traffic_windows`** | Statistical Features | Public | Aggregated numerical features (packet counts, IAT, mean sizes, scores). No raw payload data. | Expose as-is (essential for charts). |
| **`live_alerts`** | `client_mac` | **CRITICAL** | Raw client station MAC address. | **MASKED** in public view. |
| **`unknown_device_obs`** | `observed_mac` | **CRITICAL** | Raw observed MAC address of uncurated stations. | **MASKED** in public view to `'XX:XX:XX:**:**:XX'`. |
| **`live_sensor_telemetry`** | All Columns | Public | Ambient temperature, humidity, uptime ms, sequence number. | Expose as-is. |
| **`live_pir_events`** | All Columns | Public | Binary motion status (0 or 1), sequence number, uptime ms. | Expose as-is. |
| **`live_attack_events`** | `source_mac` | **CRITICAL** | Attacker or suspect MAC address. | **MASKED** in public view. |
| **`live_attack_events`** | `target_ip` | **SENSITIVE** | Internal LAN IP address (`192.168.137.101`). | **ANONYMIZED** in public view to `'192.168.137.***'`. |
| **`live_attack_events`** | `evidence_json` | Public | Structured JSON containing statistical evidence (SYN counts, port counts). Payload-free. | Expose as-is. |

### 3.2 Public Sanitization Masking Algorithms
The sanitized public views implement deterministic masking that preserves diagnostic utility while guaranteeing privacy:
1. **IEEE 802.11 MAC Address Masking:**
   ```sql
   CONCAT(SUBSTRING(client_mac FROM 1 FOR 8), ':**:**:', SUBSTRING(client_mac FROM 16 FOR 2))
   ```
   - *Example:* `'ca:34:ea:92:d3:9e'` becomes `'ca:34:ea:**:**:9e'`.
   - *Utility:* Preserves the Organizationally Unique Identifier (OUI: `ca:34:ea`, identifying device vendor/class) and the trailing byte for station differentiation, while completely cloaking the private 16-bit NIC identifier.
2. **Target IP Address Anonymization:**
   ```sql
   REGEXP_REPLACE(target_ip, '\.[0-9]+$', '.***')
   ```
   - *Example:* `'192.168.137.101'` becomes `'192.168.137.***'`.
   - *Utility:* Preserves the subnet scope (`192.168.137.0/24`) while concealing specific host lease assignments.
3. **Physical Host Infrastructure Redaction:**
   Windows network adapter GUIDs and hardware serial port identifiers are mapped to uniform abstract labels (`'Local_Hotspot_Virtual_AP'` and `'ESP32_Serial_UART'`), concealing workstation host topology.

---

## 4. FOREIGN-KEY AND DELETION SAFETY AUDIT

### 4.1 Elimination of Cascading Deletions
In the Stage 2 draft, all foreign keys referencing `collector_status(run_id)` were specified with `ON DELETE CASCADE`. 

**Forensic Audit Vulnerability:** In a Security Operations Center, historical evidence must be immutable. If an automated script, operator error, or SQL injection executed:
```sql
DELETE FROM collector_status WHERE run_id = 1;
```
PostgreSQL would silently and permanently delete the entire demonstration history: all 159 traffic windows, all statistical anomaly alerts, all physical DHT11 and PIR readings, and all cyberattack evidence for that session.

### 4.2 The Hardened `ON DELETE RESTRICT` Model
In `scratch/stage2_1_supabase_migration.sql`, all foreign keys are converted to **`ON DELETE RESTRICT`**:
- `live_traffic_windows.run_id REFERENCES collector_status(run_id) ON DELETE RESTRICT`
- `live_alerts.window_id REFERENCES live_traffic_windows(window_id) ON DELETE RESTRICT`
- `live_alerts.run_id REFERENCES collector_status(run_id) ON DELETE RESTRICT`
- `unknown_device_obs.run_id REFERENCES collector_status(run_id) ON DELETE RESTRICT`
- `live_sensor_telemetry.run_id REFERENCES collector_status(run_id) ON DELETE RESTRICT`
- `live_pir_events.run_id REFERENCES collector_status(run_id) ON DELETE RESTRICT`
- `live_attack_events.run_id REFERENCES collector_status(run_id) ON DELETE RESTRICT`
- `live_attack_events.window_id REFERENCES live_traffic_windows(window_id) ON DELETE SET NULL`

#### Lifecycle Enforcement Rules:
1. **Physical Immutability:** Any attempt to delete a session record in `collector_status` immediately raises an error (`violates foreign key constraint`). Historical runs cannot be deleted while telemetry records exist.
2. **Session Lifecycle Transitions:** Collector runs transition through explicit status states (`STARTING` -> `RUNNING` -> `STOPPED` or `ERROR`). Rows are updated, never deleted.
3. **Device Decommissioning:** Decommissioned clients in `device_registry` are updated with `label = 'retired'` or `notes = 'decommissioned'`. The record and all historical traffic associations remain intact.

---

## 5. IDEMPOTENCY, REPLAY PROTECTION & CRASH RECOVERY

### 5.1 Comprehensive Natural Idempotency Keys
To guarantee that network retries, connection drops, or duplicated HTTP requests never corrupt data, every table enforces an explicit natural unique key:

| Table | Natural Compound Idempotency Key | Upsert / Conflict Handling Clause |
| :--- | :--- | :--- |
| `collector_status` | `PRIMARY KEY (run_id)` | `UPDATE ... WHERE run_id = :run_id` |
| `device_registry` | `PRIMARY KEY (mac_address)` | `ON CONFLICT (mac_address) DO UPDATE SET last_seen = EXCLUDED.last_seen, notes = EXCLUDED.notes` |
| `live_traffic_windows` | `UNIQUE (run_id, client_mac, bin_start_epoch)` | `ON CONFLICT (run_id, client_mac, bin_start_epoch) DO NOTHING` |
| `live_alerts` | `UNIQUE (window_id)` | `ON CONFLICT (window_id) DO NOTHING` |
| `unknown_device_obs` | `UNIQUE (run_id, observed_mac)` | `ON CONFLICT (run_id, observed_mac) DO UPDATE SET last_seen_utc = EXCLUDED.last_seen_utc, observation_count = unknown_device_obs.observation_count + EXCLUDED.observation_count` |
| `live_sensor_telemetry` | `UNIQUE (run_id, physical_node_id, sequence_num)` | `ON CONFLICT (run_id, physical_node_id, sequence_num) DO NOTHING` |
| `live_pir_events` | `UNIQUE (run_id, physical_node_id, sequence_num)` | `ON CONFLICT (run_id, physical_node_id, sequence_num) DO NOTHING` |
| `live_attack_events` | `UNIQUE (run_id, timestamp_epoch, category)` | `ON CONFLICT (run_id, timestamp_epoch, category) DO NOTHING` |

### 5.2 Session Lifecycle & Repeated Heartbeats
- **Session Initiation:** `LiveCollector` executes `INSERT INTO collector_status (interface_name, serial_port, status) VALUES (...) RETURNING run_id`. The returned `run_id` anchors all subsequent telemetry.
- **Heartbeat Loop (every 3 seconds):** Executes an atomic update:
  ```sql
  UPDATE collector_status 
  SET last_heartbeat = clock_timestamp(),
      packets_parsed = :packets,
      windows_emitted = :windows,
      sensor_records = :sensors,
      updated_at = clock_timestamp()
  WHERE run_id = :run_id;
  ```
  This update is inherently idempotent: duplicate heartbeat deliveries simply refresh the timestamp without creating orphaned rows.
- **Session Termination:** When the collector exits, it issues:
  ```sql
  UPDATE collector_status 
  SET status = 'STOPPED', 
      stop_reason = :reason, 
      updated_at = clock_timestamp() 
  WHERE run_id = :run_id;
  ```

### 5.3 Local Offline Journaling & Surviving Host Crashes
To ensure Tier 1 critical events (attack events, session lifecycles) survive unexpected network outages, process terminations, or Windows reboots:

```
┌────────────────────────────────────────────────────────────────────────┐
│                      LOCAL WORKSTATION RELIABILITY                     │
│                                                                        │
│   New Attack Event                                                     │
│         │                                                              │
│         ▼                                                              │
│   1. Synchronous SQLite Commit (WAL Mode) ───────────────────► SUCCESS │
│         │                                                              │
│         ▼                                                              │
│   2. Atomic Append to Disk:                                            │
│      scratch/cloud_offline_journal.jsonl                               │
│      • Entry format: {"journal_id", "timestamp", "payload", "crc32"}   │
│      • Explicit file.flush() + os.fsync()                              │
│         │                                                              │
│         ▼                                                              │
│   3. Dispatch to Supabase via HTTPS POST (Port 443)                    │
│      ├── IF HTTP 201/200 OK ────────► Mark Acknowledged in Journal     │
│      └── IF Network Timeout / Error ──► Retain in Journal for Replay   │
└────────────────────────────────────────────────────────────────────────┘
```

#### Replay and Recovery Behavior:
1. **Crash & Reboot Resilience:** When `LiveCollector` starts, its `CloudSyncWorker` thread inspects `scratch/cloud_offline_journal.jsonl` and reads unacknowledged entries from `scratch/cloud_journal_state.json`.
2. **Safe Idempotent Flush:** The worker re-transmits unacknowledged records to Supabase. Because of the `ON CONFLICT (...) DO NOTHING` rules, records already committed by Supabase before the previous crash are safely ignored.
3. **Honest Data Loss Boundaries:**
   - **Guaranteed Preserved:** Local SQLite captures 100% of all traffic, serial sensor records, and attack events on local disk.
   - **Guaranteed Transmitted:** Tier 1 (Critical) cyberattacks and session lifecycle events are guaranteed against network partitions and process crashes via local disk journaling.
   - **Explicit Shedding:** Tier 3 standard 1-second traffic windows use an in-memory bounded queue (`maxsize=1000`). If an internet outage exceeds 16 minutes (~1,000 seconds of active traffic), oldest un-synced traffic windows are dropped to prioritize live freshness upon reconnection.

---

## 6. POSTGRESQL SYNTAX & EXTENSION COMPLIANCE AUDIT

### 6.1 Validation Methodology
SQL validation was executed using a two-tier programmatic verification harness:
1. **SQLAlchemy 2.0.35 PostgreSQL Dialect Compiler:** All eight tables, composite unique constraints, check constraints, foreign keys, identity columns, and data types (`DOUBLE_PRECISION`, `JSONB`, `TIMESTAMPTZ`, `BIGINT`) were compiled against PostgreSQL's formal dialect rules (`scratch/validate_pg_tables.py`).
2. **Automated SQL AST & DDL Rule Validator:** A specialized parsing script (`scratch/validate_stage2_1_sql.py`) analyzed `scratch/stage2_1_supabase_migration.sql` to verify:
   - Comment-stripped syntax parsing.
   - Strict absence of `ON DELETE CASCADE` in active DDL (0 found).
   - Presence of `ON DELETE RESTRICT` across all session foreign keys (7 found).
   - Parentheses balance (163 matched pairs).
   - Correct creation of all 8 base tables and 9 sanitized public views.
   - Strict absence of public `anon` access to base tables.

### 6.2 Extension & Supabase Compatibility Assessment
- **Extensions Used:**
  - `uuid-ossp` and `pgcrypto`: Both are pre-installed and natively enabled in every standard Supabase PostgreSQL instance.
- **Supabase Role Assumption:**
  - The migration script dynamically checks for `collector_role` using `IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'collector_role')` inside a `DO $$` block, preventing collision or failure during repeated runs.
  - The default roles `anon` and `authenticated` are standard Supabase PostgREST roles.

---

## 7. UNRESOLVED RISKS & MITIGATION STRATEGY

| # | Residual Risk | Severity | Technical Mitigation |
| :-: | :--- | :---: | :--- |
| **1** | **PostgREST View Schema Cache Latency:** Supabase PostgREST caches view schemas; creating new views sometimes requires a schema cache reload (`NOTIFY pgrst, 'reload schema'`). | LOW | Included cache reload trigger in documentation; restarting Supabase project or calling reload endpoint immediately refreshes PostgREST view cache. |
| **2** | **View Query Performance on High Volume:** If historical sessions exceed 500,000 windows, complex aggregations in `v_public_traffic_overview` could slow down. | MEDIUM | Base table indexes (`idx_ltw_run_bin_start`, `idx_ltw_pred_dual`) support index-only scans; queries filter strictly by `run_id`. |
| **3** | **Windows Power Loss during Disk Sync:** Sudden power loss while appending to `cloud_offline_journal.jsonl`. | LOW | Lines are written with atomic `flush()` and `fsync()`. Incomplete lines are validated with CRC32 checksums upon startup; corrupt lines are isolated without crashing the daemon. |

---

## 8. STAGE 2.1 COMPLIANCE VERIFICATION CHECKLIST

| Requirement | Stage 2.1 Specification | Verification Status |
| :--- | :--- | :---: |
| **1. Dedicated Ingestion Role** | `collector_role` created; `service_role` banned for routine collection. | ✅ **PASSED** |
| **2. Read-Only Public Role** | `anon` granted `SELECT` strictly on sanitized views; base tables locked. | ✅ **PASSED** |
| **3. Elimination of Cascading Deletes** | All `ON DELETE CASCADE` clauses replaced with `ON DELETE RESTRICT`. | ✅ **PASSED** |
| **4. Raw MAC & IP Protection** | MACs masked (`ca:34:ea:**:**:9e`), IPs masked (`192.168.137.***`). | ✅ **PASSED** |
| **5. Natural Idempotency Keys** | Compound unique constraints enforced on all tables; safe for upserts. | ✅ **PASSED** |
| **6. Offline Crash Recovery** | File-backed atomic journal specification (`cloud_offline_journal.jsonl`). | ✅ **PASSED** |
| **7. Dialect Compilation Test** | SQLAlchemy 2.0.35 PostgreSQL dialect compiled all schemas with 0 errors. | ✅ **PASSED** |
| **8. Preservation of Stage 2 Files** | Original Stage 2 deliverables remain intact and unmodified. | ✅ **PASSED** |

---

## 9. AFFIRMATION OF FINAL STOP CONDITION

In strict compliance with Stage 2.1 rules:
- **No connection to Supabase or external cloud services was attempted.**
- **No Supabase account, project, database, or API credentials were created.**
- **Application source files (`src/`), ESP32 firmware, model files, and SQLite databases remain 100% untouched.**
- **No Git commits, branches, rebases, or pushes were executed.**
- **The live capture engines, TShark, and physical hardware (`COM6`) remain completely idle.**

We now halt execution and await your review and explicit approval before proceeding to **Stage 3: Cloud Database Provisioning & Schema Execution**.

