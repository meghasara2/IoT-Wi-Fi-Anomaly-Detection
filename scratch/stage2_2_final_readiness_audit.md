# STAGE 2.2 — FINAL CLOUD READINESS AUDIT REPORT
**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Application:** IoT Network Guard — Dual-Detector SOC Console  
**Document Type:** Final Independent Technical Audit & Cloud Readiness Verification  
**Reviewed Artifacts:**  
- `scratch/stage2_supabase_migration.sql`  
- `scratch/stage2_supabase_schema_design.md`  
- `scratch/stage2_1_supabase_migration.sql`  
- `scratch/stage2_1_security_review.md`  
**Execution Date:** November 15, 2026  
**Auditor:** Antigravity AI Cybersecurity & Cloud Architecture Audit Engine  

---

## 1. EXECUTIVE SUMMARY & AUDIT VERDICT

### Overall Audit Verdict: **CONDITIONAL READINESS — 2 CRITICAL ARCHITECTURAL FINDINGS IDENTIFIED**

The Stage 2 and Stage 2.1 deliverables successfully established the foundational 8-table schema, eliminated destructive cascading deletions, and demonstrated that deploying the IoT Network Guard to Supabase is viable. 

However, this final independent technical audit has uncovered **two critical vulnerabilities** and **two operational ambiguities** that must be resolved prior to live execution in Stage 3:

1. **CRITICAL FINDING 1 (Silent Event Loss via Idempotency Collision):**  
   The compound unique key on `live_attack_events` (`UNIQUE (run_id, timestamp_epoch, category)`) causes legitimate, distinct cyberattack findings within the same 1-second capture window to collide. In reconnaissance port-scans targeting multiple local destinations, subsequent findings in the same window will be **silently discarded** by `ON CONFLICT DO NOTHING`.
2. **CRITICAL FINDING 2 (Data Leak in Public Attack Evidence):**  
   While `v_public_attack_events` masks top-level `source_mac` and `target_ip` columns, it exposes `evidence_json` raw. Code analysis of `src/attack_detector.py` proves that `evidence_json` embeds unmasked raw MACs and internal IPs (e.g., `offending_mac`, `previous_mac`, `claimed_ip`, `target_ip`), enabling anonymous dashboard visitors to bypass column masking.
3. **OPERATIONAL AMBIGUITY 3 (PostgREST Role Authentication Mechanism):**  
   The proposed `collector_role` cannot be assumed over Supabase PostgREST simply by passing a custom header. A precise authentication transport (either direct connection pooling with a dedicated database user, or Supabase Auth email/password JWT exchange) must be formally specified.
4. **EXECUTION STATUS DISCLOSURE 4 (Local PostgreSQL Engine Unavailable):**  
   Local inspection confirms that neither `psql`/PostgreSQL nor Docker/Podman are installed on this workstation. While DDL was verified via SQLAlchemy's PostgreSQL dialect compiler, **actual runtime migration execution remains unverified against a live PostgreSQL server**.

---

## 2. AREA 1: MAC AND IP PRIVACY AUDIT

### 2.1 Assessment of Partial Masking (`ca:34:ea:**:**:9e`)
In Stage 2.1, MAC masking was implemented as:
```sql
CONCAT(SUBSTRING(mac FROM 1 FOR 8), ':**:**:', SUBSTRING(mac FROM 16 FOR 2))
```
While this masks the middle octets, our technical audit reveals two major privacy weaknesses:
1. **Vendor & Device Fingerprinting:** The first three octets (`ca:34:ea`) constitute the IEEE Organizationally Unique Identifier (OUI). For physical hardware, this publicly reveals the hardware manufacturer (e.g., Espressif, Apple, Samsung, Intel). For mobile devices using randomized MACs, it reveals that the locally administered bit is active.
2. **Narrowed Entropy (16-Bit Brute-Force Vector):** Preserving the OUI (24 bits) and the trailing byte (8 bits) leaves only 16 bits (65,536 possibilities) unknown. In a small home or lab environment where the local network is known, an observer can correlate packet timestamps and packet sizes with a standard ARP scan to de-anonymize the device with near certainty.

### 2.2 Critical Vulnerability: Privacy Leak in `evidence_json`
Inspection of `src/attack_detector.py` revealed that explainable evidence dictionaries embedded in `live_attack_events` contain raw unmasked network identifiers:
- *Spoofing Evidence:* Contains `"claimed_ip"`, `"offending_mac"`, `"authorized_gateway_mac"`, and `"previous_mac"`.
- *DoS Evidence:* Contains `"target_ip"`, `"destination_scope"`, and formatted strings such as `f"Source {mac} directed..."`.
- *Reconnaissance Evidence:* Contains `"target_ip"` and host-level port mapping.

In `scratch/stage2_1_supabase_migration.sql`, line 425 of `v_public_attack_events` returns `evidence_json` without redaction. Any anonymous user visiting the Streamlit Cloud dashboard can open browser DevTools, inspect the returned JSON payload, and recover the operator's real smartphone MAC address and local LAN IP addresses.

### 2.3 Required Privacy Corrections for Stage 3
1. **Fully Pseudonymous Station Identifiers:**  
   Replace partial MAC masking with non-reversible pseudonyms derived from logical node IDs or cryptographic hashes:
   - For curated devices: Display `node_id` directly (e.g. `Node_3 (Mobile Client 1)`, `Node_4 (Mobile Client 2)`).
   - For unknown devices: Display `CONCAT('CLIENT-', UPPER(SUBSTRING(MD5(observed_mac || 'salt') FROM 1 FOR 6)))` (e.g. `CLIENT-E4B2`).
2. **Public Evidence Sanitization:**  
   In `v_public_attack_events`, either sanitize the JSON keys using PostgreSQL JSONB transformations (e.g., `evidence_json - 'offending_mac' - 'claimed_ip'`) or generate a sanitized summary string (`evidence_summary`) that excludes raw hardware identifiers.

---

## 3. AREA 2: COLLECTOR AUTHENTICATION & PRIVILEGE ENFORCEMENT

### 3.1 The Ingestion Authentication Dilemma
Stage 2.1 correctly prohibited using Supabase's `service_role` key (which bypasses RLS and grants full database control). However, it did not specify *how* the local Python collector actually presents the `collector_role` identity over the wire.

In Supabase, PostgREST does not accept arbitrary HTTP headers like `X-Role: collector_role`. PostgREST inspects the `role` claim inside an authenticated JSON Web Token (JWT). The table below evaluates the three available ingestion authentication mechanisms:

| Ingestion Mechanism | Security & Isolation | Complexity | Performance | Feasibility on Supabase Free Tier |
| :--- | :--- | :--- | :--- | :--- |
| **Option A: Direct Connection Pooler (Port 6543)** | **Highest.** Native PostgreSQL user (`iot_collector`) assigned to `collector_role`. Governed directly by PostgreSQL kernel. | Low. Standard `psycopg2` / `SQLAlchemy` connection string in local `.env`. | Highest. Direct TCP connection pooling; zero HTTP overhead. | **FEASIBLE.** Supabase natively provides a connection pooler on port 6543. |
| **Option B: Supabase Auth User (Port 443 HTTPS)** | **High.** Collector signs in via `supabase.auth.sign_in_with_password('collector@iot-guard.internal', ...)`. PostgREST receives an authenticated JWT. | Medium. Requires managing a local refresh token loop. | High. Outbound HTTPS over standard web port 443. | **FEASIBLE.** Fully supported out-of-the-box. |
| **Option C: Supabase Edge Function Ingestion API** | **Highest.** Ingestion logic encapsulated in a serverless TypeScript endpoint (`/ingest`). Collector sends standard API secret header. | High. Requires developing, testing, deploying, and maintaining an Edge Function. | Moderate. Extra serverless invocation hop and cold-start latency. | **FEASIBLE but Overengineered.** Adds unnecessary moving parts. |

### 3.2 Selected Recommendation: Option A (Direct Connection Pooler) with Option B Fallback
- **Primary Mechanism (Option A):**  
  The migration script creates a dedicated PostgreSQL user:
  ```sql
  CREATE USER iot_collector WITH PASSWORD '<SECURE_LOCAL_PASSWORD>';
  GRANT collector_role TO iot_collector;
  ```
  The local collector connects via:
  `postgresql://iot_collector:<PASSWORD>@aws-0-<region>.pooler.supabase.com:6543/postgres?sslmode=require`
  This guarantees that the PostgreSQL engine itself enforces least privilege: `iot_collector` cannot delete rows, cannot truncate tables, cannot alter schemas, and cannot access the `auth` schema.
- **Firewall Fallback (Option B):**  
  If the operator's mobile hotspot or local Wi-Fi blocks outbound TCP port 6543, the collector falls back to PostgREST over HTTPS (Port 443) by authenticating as an unprivileged Supabase Auth user (`collector@iot-guard.internal`).

---

## 4. AREA 3: EVENT IDEMPOTENCY & COLLISION INVESTIGATION

### 4.1 Critical Finding: Silent Event Drops in `live_attack_events`
In `scratch/stage2_1_supabase_migration.sql`, the idempotency constraint is defined as:
```sql
CONSTRAINT uq_attack_event UNIQUE (run_id, timestamp_epoch, category)
```

#### The Collision Scenario:
Inspection of `src/live_collector.py` (lines 1555–1570) reveals how reconnaissance port scans are processed:
```python
for finding in findings:
    finding_res = att_res
    _insert_attack_event(
        conn=db,
        run_id=self._run_id,
        window_id=window_id,
        result=finding_res,
        source_mac=finding_src_mac,
        target_ip=finding_target_ip,
        commit=commit,
    )
```
When a scan targets multiple local hosts (e.g., probing both `192.168.137.1` and `192.168.137.101` in the same 1-second window):
1. `_insert_attack_event` is called for finding #1 (`target_ip = 192.168.137.1`). It has `timestamp_epoch = 1731682800.0` and `category = 'Reconnaissance_Port_Scan'`. It inserts successfully.
2. `_insert_attack_event` is called for finding #2 (`target_ip = 192.168.137.101`). It shares the **identical `timestamp_epoch` (1731682800.0)** and **identical `category`**.
3. Under `UNIQUE (run_id, timestamp_epoch, category)`, PostgreSQL detects a constraint violation.
4. The cloud ingestion query (`ON CONFLICT (run_id, timestamp_epoch, category) DO NOTHING`) triggers.
5. **Finding #2 is silently discarded.** The SOC console completely misses the multi-host sweep evidence.

### 4.2 The Solution: Granular Composite Idempotency Key
To eliminate collisions while preserving replay protection, the unique constraint must account for the distinct attack vector targets:
```sql
CONSTRAINT uq_attack_event UNIQUE (
    run_id, 
    timestamp_epoch, 
    category, 
    COALESCE(source_mac, ''), 
    COALESCE(target_ip, '')
)
```
Or, even more reliably, assign each evaluation a deterministic client-side signature hash:
```sql
CONSTRAINT uq_attack_event UNIQUE (run_id, event_signature)
```
Where `event_signature = MD5(run_id || timestamp_epoch || category || source_mac || target_ip || status)`.

### 4.3 Collector Restarts and Lifecycle State Handling
- **Repeated START Events:** When `LiveCollector` starts, it issues an `INSERT INTO collector_status ... RETURNING run_id`. Each physical execution receives a monotonically increasing `run_id`.
- **Repeated Heartbeats:** Executed as `UPDATE collector_status SET last_heartbeat = clock_timestamp(), ... WHERE run_id = :run_id`. This operation is 100% idempotent; repeated delivery cannot duplicate rows.
- **Repeated STOP Events:** Executed as `UPDATE collector_status SET status = 'STOPPED', stop_reason = :reason WHERE run_id = :run_id`. Repeated delivery leaves the database in the identical clean terminal state.

---

## 5. AREA 4: MIGRATION EXECUTION READINESS & ENGINE VERIFICATION

### 5.1 Local Host Inspection Results
An exhaustive check of the local workstation was conducted:
- `where.exe psql postgres pg_ctl`: **Exited with code 1** (No local PostgreSQL binaries installed).
- `docker --version`: **Not recognized** (Docker Desktop is not installed).
- `podman --version`: **Not recognized** (Podman is not installed).
- Local Windows PostgreSQL Service: **None running**.

### 5.2 Explicit Disclosure of Unverified Execution
In strict compliance with prompt instructions:
> *"If PostgreSQL is unavailable, clearly state that actual migration execution remains unverified. Do not claim full SQL execution validation."*

**Formal Audit Statement:**  
Because no local PostgreSQL installation, container, or disposable environment exists on this workstation, **actual execution of the migration script against a live PostgreSQL server remains UNVERIFIED**. 

We have verified that the schema compiles against SQLAlchemy 2.0.35's formal PostgreSQL dialect compiler and that all DDL statements obey PostgreSQL grammar rules. However, live catalog verification (e.g., verifying pg_catalog creation, live RLS evaluation, and actual query plan performance) can only occur once a disposable PostgreSQL database is provisioned.

---

## 6. COMPREHENSIVE FINDINGS MATRIX

| Finding ID | Severity | Category | Specific Issue | Recommended Pre-Stage 3 Action |
| :-: | :---: | :--- | :--- | :--- |
| **F-01** | **CRITICAL** | Idempotency / Data Loss | `UNIQUE (run_id, timestamp_epoch, category)` causes multi-target attack findings in the same window to be silently discarded. | Update constraint in `stage2_1_supabase_migration.sql` to include `source_mac` and `target_ip`. |
| **F-02** | **CRITICAL** | Privacy Leak | `v_public_attack_events` leaks raw MACs and IPs embedded inside `evidence_json`. | Redact or sanitize `evidence_json` keys in the public view. |
| **F-03** | **MEDIUM** | Privacy Exposure | Preserving the MAC OUI (`ca:34:ea:**:**:9e`) exposes vendor classification and leaves a 16-bit search space. | Transition public views to fully pseudonymous device identifiers (`Node_3`, `CLIENT-A92D`). |
| **F-04** | **MEDIUM** | Auth Ambiguity | Ingestion role `collector_role` lacks a concrete transport implementation (PostgREST header vs DB user). | Document and script the creation of `iot_collector` database user for connection pooling. |
| **F-05** | **LOW** | Operational | PostgREST view cache requires manual or automated reload (`NOTIFY pgrst, 'reload schema'`). | Include schema cache notification at the conclusion of the migration script. |

---

## 7. TESTS ACTUALLY EXECUTED AND RESULTS

| # | Test Executed | Execution Harness / Command | Result | Audit Assessment |
| :-: | :--- | :--- | :-: | :--- |
| **T-1** | Local PostgreSQL Binary Discovery | `where.exe psql postgres pg_ctl` | **NOT FOUND** | Local database engine is unavailable. |
| **T-2** | Container Runtime Discovery | `docker --version`, `podman --version` | **NOT FOUND** | Disposable containerization is unavailable. |
| **T-3** | Real SQLite Database Inspection | `scratch/inspect_sqlite_schema.py` on `data/stage9_demo_live_monitoring.db` | **PASSED** | Confirmed all 8 tables, indexes, and FK relationships. |
| **T-4** | Dual Live DB Parity Check | `scratch/check_dbs.py` on both SQLite files | **PASSED** | `live_monitoring.db` and `stage9_demo` share identical schema. |
| **T-5** | PostgreSQL Dialect DDL Compilation | `scratch/validate_pg_tables.py` via SQLAlchemy 2.0.35 | **PASSED** | All 8 tables and types compiled cleanly to PostgreSQL DDL. |
| **T-6** | Automated AST & Security Rule Audit | `scratch/validate_stage2_1_sql.py` | **PASSED** | Verified: 0 CASCADE deletes, 7 RESTRICT deletes, RLS enabled, anon locked out. |
| **T-7** | Attack Detector Evidence Trace | `scratch/find_evidence_structure.py` on `src/attack_detector.py` | **PASSED (FLAGGED)** | Discovered raw MACs and IPs embedded in `evidence_json`. |
| **T-8** | Collector Attack Ingestion Trace | `scratch/find_attack_calls.py` on `src/live_collector.py` | **PASSED (FLAGGED)** | Discovered multi-call loop in port scan causing idempotency collision. |
| **T-9** | Live Database Execution | *None (Prohibited by safety rules & lack of local PG)* | **SKIPPED** | Honestly declared unverified against live engine. |

---

## 8. STAGE 3 GO / NO-GO RECOMMENDATION & EXACT PREREQUISITES

### Formal Decision: **GO WITH PREREQUISITE PATCHES APPLIED**

Stage 3 (Cloud Database Provisioning) can safely proceed **provided that the two critical findings (F-01 and F-02) are patched in the migration SQL beforehand**.

### Exact Remaining Prerequisites Before Executing Stage 3:
1. **Patch `live_attack_events` Unique Constraint:** Update the unique constraint in `scratch/stage2_1_supabase_migration.sql` to include `source_mac` and `target_ip` so concurrent findings within the same window are preserved.
2. **Patch `v_public_attack_events` Evidence Sanitization:** Strip or sanitize embedded raw IP/MAC fields from `evidence_json` in the public view.
3. **Provisioning Credentials Preparation:**
   - Create Supabase project (via Web UI).
   - Record `SUPABASE_URL`, `SUPABASE_ANON_KEY`, and connection pooler URI (`port 6543`).
   - Run the patched migration SQL directly in the Supabase SQL Editor.
4. **Local Workstation Configuration:**
   - Populate `.env` with the pooled connection string (`iot_collector` user).
   - Ensure `SUPABASE_SERVICE_ROLE_KEY` is **never** used.

---

## 9. AFFIRMATION OF FINAL STOP CONDITION

In strict compliance with Stage 2.2 audit rules:
- **No changes were made to existing Stage 2 or Stage 2.1 deliverables.**
- **No application code (`src/`), firmware, models, detector algorithms, or SQLite databases were modified.**
- **No connection to Supabase or external cloud services was attempted.**
- **No cloud accounts, projects, databases, or API keys were provisioned.**
- **Hardware serial communication (`COM6`), TShark capture, and live collectors remain idle.**
- **No Git commits, branches, or pushes were performed.**

This completes the Stage 2.2 Final Cloud Readiness Audit. Execution is halted awaiting your review and authorization.

