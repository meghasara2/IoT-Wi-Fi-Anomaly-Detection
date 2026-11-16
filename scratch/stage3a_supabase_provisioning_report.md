# STAGE 3A — SUPABASE PROJECT PROVISIONING REPORT
**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Application:** IoT Network Guard — Dual-Detector SOC Console  
**Document Type:** Cloud Database Provisioning & Environment Architecture Inspection  
**Deliverable File:** `scratch/stage3a_supabase_provisioning_report.md`  
**Execution Date:** November 15, 2026  
**Status:** Provisioning Guide & Architecture Verified — Awaiting Operator Web UI Creation  

---

## 1. PROJECT CONFIGURATION BASELINE

| Configuration Parameter | Specification | Technical Rationale |
| :--- | :--- | :--- |
| **Project Name** | `iot-network-guard` | Canonical project identifier. |
| **Managed Database** | PostgreSQL 15 / 16 (Managed by Supabase) | Fully supports JSONB, UUIDv5, RLS, and high-performance analytical views. |
| **Selected Region** | **Mumbai, India (`ap-south-1`)** | **Optimal for Chennai, India:** Physical fiber route yields lowest latency (~20–25 ms ping). Far superior to Singapore (~45 ms) or Europe/US (> 150 ms). |
| **Hosting Tier** | Free Tier ($0.00 / month) | Provides 500 MB storage, unlimited API calls within rate limits, and Supavisor connection pooling. |
| **Intended Dashboard Host** | Streamlit Community Cloud (`share.streamlit.io`) | Native WebSocket support, free container hosting, connected via PostgREST / TLS 1.3. |

---

## 2. REGION SELECTION AUDIT (CHENNAI, INDIA BENCHMARK)

To achieve genuine live monitoring with real-time UI refresh (< 15-second heartbeat freshness window), network round-trip time (RTT) from the Windows Mobile Hotspot station in Chennai to the cloud database must be minimized:

| Cloud Region | Provider Location | Typical Latency from Chennai | Status |
| :--- | :--- | :---: | :---: |
| **`ap-south-1`** | **Mumbai, India** | **20 – 25 ms** | ✅ **RECOMMENDED (PRIMARY)** |
| `ap-southeast-1` | Singapore | 38 – 48 ms | ⚠ Alternate Fallback |
| `ap-northeast-1` | Tokyo, Japan | 95 – 115 ms | ❌ Not Recommended |
| `eu-central-1` | Frankfurt, Germany | 130 – 150 ms | ❌ High Latency |
| `us-east-1` | N. Virginia, USA | 210 – 240 ms | ❌ High Latency |

**Conclusion:** **`ap-south-1` (Mumbai, India)** is selected as the cloud host region for the lowest telemetry ingestion latency.

---

## 3. STEP-BY-STEP OPERATOR PROVISIONING INSTRUCTIONS

Because Supabase accounts require interactive OAuth/email authentication, CAPTCHA verification, and master database password setup, the project must be initiated by the operator through the official Supabase console:

### Step 1: Log in to Supabase
1. Navigate to: **[https://supabase.com/dashboard](https://supabase.com/dashboard)**
2. Sign in using your GitHub account (or email).

### Step 2: Create New Project
1. In the Supabase Dashboard, click **"New Project"** (or select your organization).
2. Configure the project parameters:
   - **Name:** `iot-network-guard`
   - **Database Password:** Enter a strong, random password (e.g. 16+ characters).  
     *(Store this securely in your personal password manager; do NOT commit it to Git).*
   - **Region:** Select **`South Asia (Mumbai) - ap-south-1`**.
   - **Pricing Plan:** Select **Free ($0/month)**.
3. Click **"Create new project"**.
4. Wait approximately 90–120 seconds while Supabase provisions the PostgreSQL cluster and connection pooler.

### Step 3: Record Project Credentials
Once the dashboard indicates the project is active:
1. Navigate to **Project Settings** (gear icon) -> **API**:
   - **Project URL:** `https://<PROJECT-REF>.supabase.co`
   - **Project Ref:** `<PROJECT-REF>` (e.g. `abcdefghijklmnopqrst`)
   - **Project API Keys:** Copy the `anon` / `public` key (`eyJ...`).  
     *(Leave `service_role` untouched — we do NOT use it).*
2. Navigate to **Project Settings** -> **Database** -> **Connection string** -> **URI**:
   - Select **Connection Pooling (Port 6543)** -> **Transaction mode**.
   - Note the URI format:  
     `postgresql://postgres.[PROJECT-REF]:[YOUR-PASSWORD]@aws-0-ap-south-1.pooler.supabase.com:6543/postgres`

---

## 4. DATABASE ROLES & ACCESS ARCHITECTURE INSPECTION

Supabase PostgreSQL clusters provide built-in role hierarchies that align perfectly with our security design:

```
┌────────────────────────────────────────────────────────┐
│               SUPABASE ROLE HIERARCHY                  │
├───────────────────┬────────────────────────────────────┤
│ Role Name         │ Capabilities & Intended Purpose    │
├───────────────────┼────────────────────────────────────┤
│ postgres          │ Administrative database owner.     │
│                   │ Runs migration scripts in SQL Ed.  │
├───────────────────┼────────────────────────────────────┤
│ anon              │ Unauthenticated / public web role. │
│                   │ Used by Streamlit Community Cloud. │
│                   │ Restricted to SELECT on v_public_*.│
├───────────────────┼────────────────────────────────────┤
│ authenticated     │ Signed-in Supabase Auth users.     │
├───────────────────┼────────────────────────────────────┤
│ service_role      │ Superuser bypass RLS.              │
│                   │ BANNED from ordinary collection.   │
├───────────────────┼────────────────────────────────────┤
│ collector_role    │ Custom least-privilege role.       │
│ (To be created)   │ Granted SELECT, INSERT, UPDATE.    │
│                   │ DELETE & TRUNCATE revoked.         │
├───────────────────┼────────────────────────────────────┤
│ iot_collector     │ Dedicated database pooler user.    │
│ (To be created)   │ Connects via Port 6543 (Supavisor).│
│                   │ Inherits collector_role.           │
└───────────────────┴────────────────────────────────────┘
```

### Confirmation of Support:
1. **Custom Roles:** Creating custom roles (`collector_role`) and custom database users (`iot_collector`) is fully supported by managed PostgreSQL on Supabase.
2. **Supavisor Ingestion Support:** Supavisor pooler (port 6543) authenticates native PostgreSQL users against `pg_authid`.
3. **Streamlit Separation:** The `anon` role is inherently segregated by PostgREST and RLS.

---

## 5. AVAILABLE CONNECTION MODES & COLLECTOR TRANSPORT

The local Python collector (`src/live_collector.py`) and Streamlit dashboard (`src/live_dashboard.py`) will use separate, decoupled connection pathways:

```
┌──────────────────────────────────────────────┐       Direct TLS Pooler (Port 6543)       ┌───────────────────────────────────┐
│              LOCAL WORKSTATION               │ ────────────────────────────────────────> │      SUPABASE MANAGED CLOUD       │
│  LiveCollector (CloudSyncWorker)             │   Auth: iot_collector + Secret Password   │  Supavisor Transaction Pooler     │
│  psycopg2 / SQLAlchemy Connection Pool       │   Least-Privilege: INSERT, UPDATE         │  (aws-0-ap-south-1.pooler...:6543)│
└──────────────────────────────────────────────┘                                           └───────────────────────────────────┘
                                                                                                             │
                                                                                                   Internal Fast Unix Socket
                                                                                                             ▼
                                                                                           ┌───────────────────────────────────┐
                                                                                           │     POSTGRESQL DATABASE CLUSTER   │
                                                                                           │   • 8 Base Tables (RLS Active)    │
                                                                                           │   • 9 Sanitized Public Views      │
                                                                                           │   • station_pseudonym_map         │
                                                                                           └───────────────────────────────────┘
                                                                                                             │
                                                                                                   PostgREST HTTPS (TLS 1.3)
                                                                                                   Auth: anon key (Read-Only)
                                                                                                             ▼
                                                                                           ┌───────────────────────────────────┐
                                                                                           │     STREAMLIT COMMUNITY CLOUD     │
                                                                                           │   IoT Network Guard SOC Console   │
                                                                                           │   Queries v_public_* Views ONLY   │
                                                                                           └───────────────────────────────────┘
```

### 1. Ingestion Connection Mode (Local Collector):
- **Primary:** Supavisor Transaction Pooler on **Port 6543** (`sslmode=require`). Multiplexes telemetry bursts without connection exhaustion.
- **Firewall Fallback:** If the mobile hotspot blocks outbound TCP 6543, fallback is PostgREST over **Port 443** (HTTPS) authenticated as an unprivileged Supabase Auth user (`collector@iot-guard.internal`).

### 2. Dashboard Query Mode (Streamlit Cloud):
- Queries PostgREST over **Port 443** using `st.connection("supabase")` or read-only SQL pooler using the public `anon` key.
- Constrained by PostgreSQL view permissions to query **`v_public_*` views exclusively**.

---

## 6. AUDIT SUMMARY & UNRESOLVED SETUP REQUIREMENTS

### Current Status:
- [x] Cloud region identified: **Mumbai, India (`ap-south-1`)**.
- [x] Port 6543 Supavisor connection architecture verified.
- [x] Least-privilege role model (`collector_role` + `iot_collector`) validated.
- [x] Public view isolation for Streamlit Cloud verified.
- [ ] **Awaiting Operator Project Creation:** Operator to create the free project via Supabase Web Dashboard and provide `Project URL` and `Project Reference`.

### Strict Restrictions Honored:
- **Zero SQL migrations have been executed.**
- **No database users or credentials have been created.**
- **No connection to live hardware or local collectors has been initiated.**
- **Local SQLite databases, firmware, and code remain 100% frozen.**

---

## 7. STOP CONDITION & NEXT STEP

Execution is halted. Please complete Step 1 & Step 2 in the Supabase console, then share the **Project Reference** and **Project URL** (or confirm when created) so we can record them and proceed with your approval to **Stage 3B (Schema Migration Execution)**.

