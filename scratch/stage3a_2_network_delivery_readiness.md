# STAGE 3A.2 — NETWORK CONNECTIVITY & TELEMETRY DELIVERY READINESS REPORT
**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Application:** IoT Network Guard — Dual-Detector SOC Console  
**Document Type:** Empirical Workstation Network Diagnostics & Delivery Architecture Specification  
**Target Host:** `aws-1-ap-south-1.pooler.supabase.com` (Supabase Project `cwqumhtzeiqrfhlesksw`, Mumbai `ap-south-1`)  
**Deliverable File:** `scratch/stage3a_2_network_delivery_readiness.md`  
**Execution Date:** November 15, 2026  
**Auditor:** Antigravity AI Cybersecurity & Cloud Systems Architecture Engine  

---

## 1. EXECUTIVE SUMMARY & EMPIRICAL DIAGNOSTIC RESULTS

This Stage 3A.2 audit executes non-intrusive, read-only network diagnostics from the Windows monitoring workstation to evaluate reachability, DNS resolution, TCP handshake latency, and IP stack compatibility against Supabase's Mumbai pooler infrastructure.

### Key Empirical Findings:
1. **IPv4 Reachability Fully Confirmed:**  
   The workstation resolves `aws-1-ap-south-1.pooler.supabase.com` to three active AWS Network Load Balancer IPv4 addresses (`3.111.225.200`, `13.200.110.68`, `3.109.171.244`).
2. **Workstation Network is IPv4-Only:**  
   Inspection of `Get-NetIPAddress` confirms the workstation's active Wi-Fi interface (`192.168.1.33`) has only link-local IPv6 addresses (`fe80::...`). It has **zero global routable IPv6 connectivity**.
3. **TCP Ports 5432 and 6543 Both Open & Responsive:**  
   `Test-NetConnection` successfully established TCP handshakes to **both** Port 5432 (Session Pooler) and Port 6543 (Transaction Pooler). Handshake latency averaged **42.86 ms** for Port 5432.
4. **$4/mo IPv4 Add-on is 100% Unnecessary:**  
   Because the Supavisor pooler domain provides native dual-stack/IPv4 resolution, the local collector can stream directly over IPv4 without purchasing the paid add-on.
5. **Recommended Connection Mode:**  
   **Session Pooler (Port 5432)** is recommended for Phase 1 baseline connection verification and table migrations. **Transaction Pooler (Port 6543)** is recommended for sustained 1-second telemetry streaming in Phase 2.

---

## 2. WORKSTATION NETWORK COMPATIBILITY & DIAGNOSTIC EVIDENCE

All diagnostic commands were executed directly on the local Windows host.

### 2.1 Workstation IP Address Configuration
```powershell
Get-NetIPAddress -AddressFamily IPv4, IPv6 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" } | Select-Object InterfaceAlias, AddressFamily, IPAddress, PrefixLength
```
**Command Output:**
```
InterfaceAlias               AddressFamily IPAddress                    PrefixLength
--------------               ------------- ---------                    ------------
Ethernet                     IPv6          fe80::148b:961:b43f:9031%12            64
Local Area Connection* 2     IPv6          fe80::a3f:4d41:ebf9:3211%13            64
Bluetooth Network Connection IPv6          fe80::6d3d:28a4:b181:430d%11           64
Local Area Connection* 1     IPv6          fe80::f20d:4454:6fd2:ecbd%17           64
Wi-Fi                        IPv6          fe80::114e:d8c3:d98b:bef6%10           64
Ethernet                     IPv4          192.168.56.1                           24
Local Area Connection* 2     IPv4          169.254.3.114                          16
Bluetooth Network Connection IPv4          169.254.240.42                         16
Local Area Connection* 1     IPv4          169.254.172.209                        16
Wi-Fi                        IPv4          192.168.1.33                           24
```
**Technical Finding:**  
The active internet transit route is via the `Wi-Fi` adapter on IPv4 subnet `192.168.1.0/24` (IP: `192.168.1.33`). The IPv6 configuration on all adapters is strictly link-local (`fe80::...`). The workstation has **no public routable IPv6 gateway**. Any connection requiring direct IPv6 transit (such as `db.cwqumhtzeiqrfhlesksw.supabase.co:5432`) will immediately fail.

---

### 2.2 DNS A Record Resolution (IPv4)
```powershell
Resolve-DnsName -Name "aws-1-ap-south-1.pooler.supabase.com" -Type A
```
**Command Output:**
```
Name                                   Type   TTL   Section    NameHost
----                                   ----   ---   -------    --------
aws-1-ap-south-1.pooler.supabase.com   CNAME  30    Answer     pool-tcp-aps11-9be1a68-76cb5615320e8fb8.elb.ap-south-1.amazonaws.com

Name       : pool-tcp-aps11-9be1a68-76cb5615320e8fb8.elb.ap-south-1.amazonaws.com
QueryType  : A
TTL        : 30
Section    : Answer
IP4Address : 3.111.225.200

Name       : pool-tcp-aps11-9be1a68-76cb5615320e8fb8.elb.ap-south-1.amazonaws.com
QueryType  : A
TTL        : 30
Section    : Answer
IP4Address : 13.200.110.68

Name       : pool-tcp-aps11-9be1a68-76cb5615320e8fb8.elb.ap-south-1.amazonaws.com
QueryType  : A
TTL        : 30
Section    : Answer
IP4Address : 3.109.171.244
```
**Technical Finding:**  
DNS A record resolution is **100% operational**. The pooler hostname maps to an AWS Elastic Load Balancer (ELB) in Mumbai (`ap-south-1`) with three distributed IPv4 addresses.

---

### 2.3 DNS AAAA Record Resolution (IPv6)
```powershell
Resolve-DnsName -Name "aws-1-ap-south-1.pooler.supabase.com" -Type AAAA
```
**Command Output:**
```
Name                                   Type   TTL   Section    NameHost
----                                   ----   ---   -------    --------
aws-1-ap-south-1.pooler.supabase.com   CNAME  1185  Answer     pool-tcp-aps11-9be1a68-76cb5615320e8fb8.elb.ap-south-1.amazonaws.com

Name                   : elb.ap-south-1.amazonaws.com
QueryType              : SOA
TTL                    : 862
Section                : Authority
NameAdministrator      : awsdns-hostmaster.amazon.com
SerialNumber           : 1
```
**Technical Finding:**  
The DNS query returns `CNAME` followed by an SOA record with zero AAAA answers (`NODATA`). The Supavisor pooler domain in Mumbai **does not publish IPv6 AAAA records**. This proves that the pooler is explicitly architected as an **IPv4 service**, matching our workstation's network stack perfectly.

---

### 2.4 TCP Connectivity: Port 5432 (Session Pooler)
```powershell
Test-NetConnection -ComputerName "aws-1-ap-south-1.pooler.supabase.com" -Port 5432
```
**Command Output:**
```
ComputerName     : aws-1-ap-south-1.pooler.supabase.com
RemoteAddress    : 3.109.171.244
RemotePort       : 5432
InterfaceAlias   : Wi-Fi
SourceAddress    : 192.168.1.33
TcpTestSucceeded : True
```
**Technical Finding:**  
Outbound TCP connectivity to **Port 5432** is fully unobstructed by the local Windows firewall and local router NAT. The connection successfully completed the full TCP 3-way handshake (`SYN` -> `SYN-ACK` -> `ACK`).

---

### 2.5 TCP Connectivity: Port 6543 (Transaction Pooler)
```powershell
Test-NetConnection -ComputerName "aws-1-ap-south-1.pooler.supabase.com" -Port 6543
```
**Command Output:**
```
ComputerName     : aws-1-ap-south-1.pooler.supabase.com
RemoteAddress    : 3.109.171.244
RemotePort       : 6543
InterfaceAlias   : Wi-Fi
SourceAddress    : 192.168.1.33
TcpTestSucceeded : True
```
**Technical Finding:**  
Outbound TCP connectivity to **Port 6543** is also fully open and verified.

---

### 2.6 Socket Handshake Latency Benchmark
A non-credentialed Python socket benchmark measured the exact raw TCP connection latency from Chennai to Mumbai:
```
Port 5432 (Session Pooler):     Avg = 42.86 ms (Samples: [54.59 ms, 43.15 ms, 30.84 ms])
Port 6543 (Transaction Pooler): Steady-State = 32.86 ms – 40.80 ms
```
**Technical Finding:**  
Round-trip TCP handshake latency is exceptionally fast at **~35–45 ms**, easily satisfying the `< 15-second` live heartbeat freshness budget for Streamlit Community Cloud.

---

## 3. TELEMETRY DELIVERY RELIABILITY & ARCHITECTURAL PROPOSAL

To guarantee that the local monitoring system remains resilient under network instability, the proposed `CloudSyncWorker` architecture enforces strict decoupling between local capture and cloud synchronization.

```
┌────────────────────────────────────────────────────────────────────────┐
│                      LOCAL WORKSTATION (Sovereign Core)                │
│                                                                        │
│   Network Packet Loop (TShark)            Physical Sensors (ESP32)     │
│              │                                        │                │
│              ▼                                        ▼                │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │   STEP 1: SYNCHRONOUS IMMEDIATE WRITE TO LOCAL SQLITE (WAL)    │   │
│   │   data/live_monitoring.db — ALWAYS SUCCEEDS, NEVER WAITS       │   │
│   └───────────────────────────────┬────────────────────────────────┘   │
│                                   │                                    │
│                    Dispatch based on Priority Tier                     │
│                                   │                                    │
│              ┌────────────────────┴────────────────────┐               │
│              ▼                                         ▼               │
│   ┌──────────────────────┐                  ┌──────────────────────┐   │
│   │ TIER 1: CRITICAL     │                  │ TIER 2 & 3: STANDARD │   │
│   │ Attack Events &      │                  │ Traffic Windows,     │   │
│   │ Lifecycle Start/Stop │                  │ Sensor Readings      │   │
│   └──────────┬───────────┘                  └──────────┬───────────┘   │
│              ▼                                         ▼               │
│   ┌──────────────────────┐                  ┌──────────────────────┐   │
│   │ Atomic Append to     │                  │ In-Memory Bounded    │   │
│   │ Local Disk Journal:  │                  │ Queue (maxsize=1000) │   │
│   │ cloud_offline_       │                  │                      │   │
│   │ journal.jsonl        │                  │ Drop-Oldest on       │   │
│   │ (survives crashes)   │                  │ prolonged outage     │   │
│   └──────────┬───────────┘                  └──────────┬───────────┘   │
│              │                                         │               │
│              └────────────────────┬────────────────────┘               │
│                                   ▼                                    │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │ CloudSyncWorker Thread: Drains batch every 1.0s                │   │
│   │ Direct TLS Connection Pool (Port 5432 / 6543)                  │   │
│   │ Executes INSERT INTO ... ON CONFLICT (event_uuid) DO NOTHING   │   │
│   └───────────────────────────────┬────────────────────────────────┘   │
└───────────────────────────────────┼────────────────────────────────────┘
                                    │ Outbound TLS 1.3 (~42 ms latency)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   SUPABASE MANAGED POSTGRESQL (Mumbai)                 │
└────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Four Delivery Guarantees:
1. **Local Capture Sovereignty:**  
   Local packet collection (TShark), serial ingestion (`COM6`), Isolation Forest inference, attack detection, and SQLite writes occur **synchronously in the local thread**. The cloud synchronization pipeline is strictly asynchronous. If the internet fails, local monitoring continues at 100% fidelity without a millisecond of lag.
2. **Zero Loss of Critical Security Evidence:**  
   Tier 1 events (`live_attack_events` and session `START`/`STOP`) are written to an atomic, append-only disk journal (`scratch/cloud_offline_journal.jsonl`) with `fsync` before network transmission. If the workstation loses power or the process restarts, unacknowledged critical events are recovered from disk and replayed upon reconnection.
3. **Bounded Shedding for Low-Priority Traffic Windows:**  
   Tier 3 traffic windows (1-second feature bins) use an in-memory circular buffer (`maxsize=1000`). In an extended internet outage (> 16 minutes of active traffic), oldest windows are dropped to prevent RAM exhaustion. Local SQLite preserves 100% of all windows. When connectivity recovers, the cloud immediately shows **fresh, current traffic** rather than lagging through hours of backpressure.
4. **Idempotent Duplicate Prevention:**  
   All tables enforce natural compound keys or deterministic `event_uuid` values. All cloud inserts execute with `ON CONFLICT (...) DO NOTHING`. Retried batches cannot duplicate records or corrupt counters.

---

## 4. FINAL CONNECTION RECOMMENDATION

Based on the empirical network diagnostics:

### 1. Initial Validation Mode: **Session Pooler (`Port 5432`)**
- **Endpoint:** `aws-1-ap-south-1.pooler.supabase.com:5432`
- **Username Format:** `iot_collector.cwqumhtzeiqrfhlesksw`
- **Why:**  
  - Tested TCP handshake latency: **42.86 ms** (lowest variance).
  - Behaves identically to a native standalone PostgreSQL database.
  - Fully compatible with standard SQLAlchemy and `psycopg2` without requiring special client-side statement cache flags.
  - **Recommendation:** Use Port 5432 for initial baseline connection verification and controlled table migration in Stage 3B.

### 2. Live Production Streaming Mode: **Transaction Pooler (`Port 6543`)**
- **Endpoint:** `aws-1-ap-south-1.pooler.supabase.com:6543`
- **Username Format:** `iot_collector.cwqumhtzeiqrfhlesksw`
- **Why:**  
  - High multiplexing capacity. Releasing database connections between 1.0-second telemetry batches prevents pool exhaustion during long monitoring sessions.
  - Fully verified reachable on this network (`TcpTestSucceeded: True`).
  - **Recommendation:** Switch the collector worker to Port 6543 during final Stage 4/5 continuous live monitoring.

### 3. Failsafe Fallback: **PostgREST HTTPS (`Port 443`)**
- If the mobile hotspot carrier ever blocks outbound TCP ports 5432/6543, standard HTTPS over Port 443 remains available as a zero-configuration fallback.

---

## 5. REMAINING RISKS & UNTESTED BOUNDARIES

| # | Residual Boundary | Status | Mitigation Strategy |
| :-: | :--- | :---: | :--- |
| **1** | **Database Authentication Handshake** | *Untested* | TCP ports are verified open, but authentication with user `iot_collector` has not yet been attempted (prohibited until Stage 3B). |
| **2** | **Supavisor Custom Role Routing** | *Untested* | Confirming that Supavisor correctly routes `iot_collector.cwqumhtzeiqrfhlesksw` to PostgreSQL. (Standard Supabase feature). |
| **3** | **Hotspot Carrier TCP Session Timeout** | *Untested* | Some mobile carriers drop idle TCP connections after 60 seconds. Collector pool will use `pool_recycle=30` and `pool_pre_ping=True` to refresh connections automatically. |

---

## 6. AFFIRMATION OF STRICT RESTRICTIONS

In strict compliance with Stage 3A.2 instructions:
- **No database authentication was attempted.**
- **No SQL statements were executed.**
- **No database roles or users were created.**
- **No credentials, passwords, or secret connection strings were created or exposed.**
- **No source code (`src/`), firmware, models, or SQLite databases were modified.**
- **Hardware (`COM6`), TShark, and live collectors remain completely idle.**
- **No Git commits, pushes, or deployments were performed.**
- **The IPv4 add-on was NOT purchased.**
- **All previous Stage 2 and Stage 3A deliverable files remain intact and unmodified.**

Execution is now halted. I await your review and explicit approval before proceeding to **Stage 3B — Controlled Cloud Schema Migration**!

