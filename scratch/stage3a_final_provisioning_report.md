# STAGE 3A.1 — FINAL SUPABASE PROJECT CONFIGURATION & CONNECTION AUDIT REPORT
**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Application:** IoT Network Guard — Dual-Detector SOC Console  
**Document Type:** Verified Cloud Project Baseline & Ingestion Connection Architecture Audit  
**Deliverable File:** `scratch/stage3a_final_provisioning_report.md`  
**Execution Date:** November 15, 2026  
**Auditor:** Antigravity AI Cybersecurity & Cloud Systems Architecture Engine  

---

## 1. EXECUTIVE OVERVIEW & OBJECTIVE

Following the Stage 3A review, the cloud database environment for **IoT Network Guard** has been provisioned on Supabase. The project configuration parameters, hostnames, ports, and PostgreSQL versions were retrieved directly from the live Supabase project console.

This Stage 3A.1 audit establishes the **verified technical baseline** for the cloud project, audits the connection pooling topology (Session Pooler vs. Transaction Pooler vs. Direct Connection), evaluates IPv4/IPv6 networking constraints for the Windows Mobile Hotspot, and documents the exact least-privilege security boundaries prior to any schema migration.

### Formal Status: **PROJECT CONFIGURATION VERIFIED — READY FOR CONTROLLED MIGRATION PREPARATION**

---

## 2. CONFIRMED PROJECT DETAILS (DASHBOARD-VERIFIED FACTS)

The following parameters have been verified through the official Supabase project dashboard:

| Parameter | Verified Dashboard Value | Technical Notes |
| :--- | :--- | :--- |
| **Project Name** | `meghasara2's Project` | Active project display name. |
| **Project Reference ID** | `cwqumhtzeiqrfhlesksw` | Canonical 20-character tenant identifier. |
| **Project URL** | `https://cwqumhtzeiqrfhlesksw.supabase.co` | Base HTTPS REST endpoint (Port 443). |
| **Project Region** | **South Asia (Mumbai)** | Closest physical AWS availability zone to Chennai. |
| **Region Identifier** | `ap-south-1` | AWS Mumbai region code. |
| **Compute Tier** | Nano (Free Tier) | 500 MB relational storage, Supavisor connection pooler. |
| **PostgreSQL Version** | **`17.6`** | Modern PostgreSQL 17 release with enhanced indexing, JSONB performance, and RLS optimizations. |
| **Database Name** | `postgres` | Default administrative database catalog. |

---

## 3. VERIFIED CONNECTION POOLING CONFIGURATION

Supabase provides two distinct connection pooling endpoints powered by **Supavisor** (Supabase's high-throughput connection pooler) in addition to the direct unpooled database host:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        SUPABASE CONNECTION TOPOLOGY (ap-south-1)                       │
├─────────────────────┬───────────────────────────────────────────┬──────┬───────────────┤
│ Endpoint Mode       │ Hostname                                  │ Port │ Auth Username │
├─────────────────────┼───────────────────────────────────────────┼──────┼───────────────┤
│ **Session Pooler**  │ `aws-1-ap-south-1.pooler.supabase.com`    │ 5432 │ `[user].[ref]`│
├─────────────────────┼───────────────────────────────────────────┼──────┼───────────────┤
│ **Transaction Pool**│ `aws-1-ap-south-1.pooler.supabase.com`    │ 6543 │ `[user].[ref]`│
├─────────────────────┼───────────────────────────────────────────┼──────┼───────────────┤
│ **Direct Database** │ `db.cwqumhtzeiqrfhlesksw.supabase.co`     │ 5432 │ `postgres`    │
├─────────────────────┼───────────────────────────────────────────┼──────┼───────────────┤
│ **PostgREST API**   │ `https://cwqumhtzeiqrfhlesksw.supabase.co`│ 443  │ API Key (JWT) │
└─────────────────────┴───────────────────────────────────────────┴──────┴───────────────┘
```

### 3.1 Session Pooler (Port 5432)
- **Host:** `aws-1-ap-south-1.pooler.supabase.com`
- **Port:** `5432`
- **Username Format:** `postgres.cwqumhtzeiqrfhlesksw` (for admin) / `[custom_user].cwqumhtzeiqrfhlesksw`
- **Operational Mode:** Allocates a dedicated PostgreSQL backend connection to the client for the entire lifespan of the client session.
- **Protocol Features:** Supports full PostgreSQL session features: named server-side prepared statements, session-level variables, temporary tables, advisory locks, and transaction-spanning states.

### 3.2 Transaction Pooler (Port 6543)
- **Host:** `aws-1-ap-south-1.pooler.supabase.com`
- **Port:** `6543`
- **Username Format:** `postgres.cwqumhtzeiqrfhlesksw` (for admin) / `[custom_user].cwqumhtzeiqrfhlesksw`
- **Operational Mode:** Allocates a PostgreSQL backend connection only while an active transaction block (`BEGIN` -> `COMMIT` / `ROLLBACK`) is executing. Once committed, the connection is instantly returned to the shared pool.
- **Protocol Features:** Multiplexes thousands of client connections over a compact server connection pool. Disallows session-level state, named server-side prepared statements across transactions, and persistent `SET` commands.

### 3.3 Direct Database Host (Port 5432 — Unpooled)
- **Host:** `db.cwqumhtzeiqrfhlesksw.supabase.co`
- **Port:** `5432`
- **Networking Constraint:** **IPv6 Only** on Supabase Free Tier projects. Clients connecting from IPv4-only networks cannot resolve or route to this address without the paid IPv4 add-on.

---

## 4. CONNECTION ARCHITECTURE RECOMMENDATION FOR PYTHON COLLECTOR

### 4.1 Evaluation: Session Pooler vs. Transaction Pooler vs. PostgREST

| Technical Evaluation Criteria | Option 1: Session Pooler (Port 5432) [RECOMMENDED INITIAL] | Option 2: Transaction Pooler (Port 6543) [RECOMMENDED PROD] | Option 3: PostgREST REST API (Port 443) [FAILSAFE] |
| :--- | :--- | :--- | :--- |
| **Workstation Workload Fit** | The collector's background worker opens a single persistent connection pool (1–2 connections) and periodically commits batched inserts. | Highly efficient for stateless transactions. However, some Python drivers (e.g. SQLAlchemy default) attempt to prepare statements, which can trigger Supavisor transaction pool errors if not explicitly configured. | Outbound HTTPS over standard web port 443. Ideal if mobile hotspot firewalls block outbound ports 5432 and 6543. |
| **IPv4 / IPv6 Networking** | **Dual-Stack Supported.** Pooler hostname resolves via dual-stack routing. Works on IPv4-only networks. | **Dual-Stack Supported.** Works on IPv4-only networks. | **100% Dual-Stack IPv4/IPv6.** Bypasses all ISP port blocks. |
| **Driver Configuration** | Standard `psycopg2` / `SQLAlchemy` connection string. Zero special pooling flags required. | Requires disabling named prepared statements (`prepare_threshold=None`) in client driver. | Requires HTTP client (`requests` or `supabase-py`). |
| **Recommended Staging** | **Phase 1 Validation:** Use Session Pooler (Port 5432) for initial baseline connectivity test. | **Phase 2 Production:** Transition to Transaction Pooler (Port 6543) for sustained telemetry streaming. | **Fallback:** Available as instant fallback if ports 5432/6543 are blocked by carrier. |

### 4.2 IPv4 Compatibility & Cost Evaluation
- **Dashboard Observation:** The Supabase dashboard offers a "Dedicated IPv4 add-on" ($4/month).
- **Technical Analysis:** The IPv4 add-on is strictly required **only** if connecting directly to `db.cwqumhtzeiqrfhlesksw.supabase.co:5432`.
- **Verdict:** **The IPv4 add-on is NOT required.** Both the Supavisor pooler (`aws-1-ap-south-1.pooler.supabase.com` on ports 5432 and 6543) and the PostgREST API (port 443) support IPv4 client connectivity natively. The project remains **100% Free Tier ($0.00/month)**.

### 4.3 Python Driver Compatibility Matrix
The local workstation runs Python 3.11 with `SQLAlchemy 2.0.35` installed:
- **`psycopg2-binary` (or `psycopg3`):** Fully compatible with PostgreSQL 17.6 and Supavisor.
- **TLS Configuration:** Mandates `sslmode=require` (TLS 1.3). Supabase terminates SSL at the Supavisor boundary using valid DigiCert / Let's Encrypt certificates.

---

## 5. REQUIRED SECURITY ARCHITECTURE RE-AFFIRMATION

All security invariants established across Stages 2.1, 2.2, 2.3, and 2.4 remain strictly preserved:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   LOCAL MONITORING WORKSTATION (Windows)               │
│                                                                        │
│   • Primary Local Persistence: Local SQLite (data/live_monitoring.db)  │
│   • Local Collector Sovereignty: Runs 100% independently of cloud link │
│   • Background Cloud Sync: Bounded Queue (maxsize=1000, Drop-Oldest)   │
│   • Dedicated Database Identity: iot_collector.cwqumhtzeiqrfhlesksw    │
│   • Least-Privilege DML: SELECT, INSERT, UPDATE ONLY                   │
│   • Strictly Prohibited: DELETE, TRUNCATE, ALTER, DROP, auth schema    │
│   • Secret Management: Database password stored in local .env ONLY     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Outbound TLS 1.3 (Port 5432 / 6543)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│              SUPABASE MANAGED CLOUD DATABASE (ap-south-1)              │
│                                                                        │
│   • PostgreSQL Version: 17.6                                           │
│   • Base Tables: 8 Relational Tables (Row-Level Security Active)       │
│   • Private Security Table: station_pseudonym_map (anon REVOKED)       │
│   • Public Views: 9 Sanitized Views (v_public_*)                       │
│   • Zero Administrative Leakage: postgres user NEVER used for streaming│
│   • Zero Service Role: service_role key BANNED from collector usage    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Read-Only SQL / PostgREST (Port 443)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   STREAMLIT COMMUNITY CLOUD (Public)                   │
│                                                                        │
│   • Role: anon (Public Unauthenticated Web Role)                       │
│   • Privileges: SELECT ONLY on v_public_* Views                        │
│   • Base Tables: Direct SELECT, INSERT, UPDATE, DELETE STRICTLY BLOCKED│
│   • Public Privacy: Logical Node Names (Node_3) & Random Pseudonyms    │
│   • Zero Address Leaks: Raw MACs, IPs, and Adapter GUIDs Redacted      │
│   • Templated Guidance: SOC Remediation Advice via Fixed Allowlist     │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 6. PROJECT-SPECIFIC VERIFICATION MATRIX

| Item # | Verification Subject | Dashboard-Verified Fact | Architectural Recommendation | Untested Assumption (Requires Stage 3B Test) |
| :-: | :--- | :--- | :--- | :--- |
| **1** | **PostgreSQL Version** | **PostgreSQL 17.6** | Use modern PG17 features (JSONB, identity). | Dialect compatibility with local SQLAlchemy client. |
| **2** | **Project Region** | **`ap-south-1` (Mumbai)** | Primary region for Chennai workstation (~20ms). | Workstation round-trip ping time to pooler IP. |
| **3** | **Transaction Pooler** | `aws-1-ap-south-1.pooler.supabase.com:6543` | Target for production 1s telemetry streaming. | Outbound port 6543 pass-through on hotspot carrier. |
| **4** | **Session Pooler** | `aws-1-ap-south-1.pooler.supabase.com:5432` | Target for initial baseline connection test. | Outbound port 5432 pass-through on hotspot carrier. |
| **5** | **Username Format** | `postgres.cwqumhtzeiqrfhlesksw` | Custom user format: `iot_collector.cwqumhtzeiqrfhlesksw` | Supavisor authentication of non-postgres custom users. |
| **6** | **Connection Options** | Session, Transaction, Direct, REST | Session pooler (dev) -> Transaction (prod). | Driver stability across connection drops. |
| **7** | **IPv4 Add-on Status** | Offered as $4/mo add-on | **DO NOT PURCHASE.** Use pooler hostnames. | DNS resolution of pooler hostname to IPv4 address. |
| **8** | **Database Name** | `postgres` | Standard Supabase default catalog. | Confirmed. |

---

## 7. EXACT PREREQUISITES BEFORE STAGE 3B (SCHEMA MIGRATION)

Stage 3B (Controlled Cloud Schema Migration) can be initiated once the following prerequisites are acknowledged:

1. **Migration SQL Finalization:**  
   Prepare the final, hardened PostgreSQL 17.6 DDL script incorporating the Stage 2.4 resolutions:
   - `station_pseudonym_map` private mapping table.
   - `collector_role` with `INHERIT` enabled (eliminating the `NOINHERIT` inheritance bug).
   - `v_public_attack_events` with allowlist JSON projection and templated remediation guidance.
   - `event_uuid` constraint for collision-free attack event tracking.
2. **Execution Method:**  
   The migration will be executed **directly via the Supabase SQL Editor web console** by the operator (or guided step-by-step), running under the administrative `postgres` role to provision tables, views, and the `iot_collector` user.
3. **Credential Storage:**  
   The operator will record the `iot_collector` user password securely in local `.env` (gitignored).

---

## 8. AFFIRMATION OF STRICT STOP CONDITIONS

In strict compliance with Stage 3A.1 guidelines:
- **Zero SQL migration scripts have been executed.**
- **No database users (`iot_collector`) or custom roles have been created.**
- **No database passwords have been entered or recorded in any file.**
- **No Python or Streamlit connection to Supabase has been initiated.**
- **The IPv4 add-on has NOT been purchased.**
- **COM6, TShark, ESP32 hardware, and live collectors remain idle.**
- **Local SQLite databases, application source files (`src/`), firmware, and models remain 100% frozen.**
- **All previous Stage 2, 2.1, 2.2, 2.3, 2.4, and Stage 3A deliverables remain intact and unmodified.**

Execution is now halted. I await your review and explicit approval before proceeding to **Stage 3B — Controlled Cloud Schema Migration**!

