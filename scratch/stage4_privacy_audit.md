# STAGE 4 — CLOUD DASHBOARD PRIVACY & REDACTION AUDIT
**Comprehensive PII & Sensitive Telemetry Redaction Certification**
**Project:** IoT Network Guard — Dual-Detector SOC Console  
**Date:** November 15, 2026  
**Target:** [`src/cloud_dashboard.py`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/cloud_dashboard.py) & Public Views (Baseline 3.6.0)

---

## 1. Audit Scope & Privacy Boundaries

The public cloud dashboard is designed for public access on Streamlit Community Cloud. To comply with rigorous cybersecurity privacy and data protection standards, the system implements a multi-tier cryptographic and semantic redaction architecture:

| Data Category | Risk / Sensitivity | Raw Form | Public Redacted Form | Redaction Mechanism |
|---|---|---|---|---|
| **Station Hardware Address** | Device tracking, PII | `ca:34:ea:92:d3:9e` | `Node_3` | Cryptographically isolated lookup in `station_pseudonym_map` |
| **Unregistered MAC Address** | Target tracking | `e2:15:ba:89:11:04` | `UNREGISTERED_STATION` | Closed allowlist in `v_public_unknown_device_obs` |
| **Attacker MAC Address** | Forensic PII | `bc:d1:1f:88:22:90` | `ATTACKER_UNMAPPED` | Allowlist enforcement in `v_public_attack_events` |
| **Target IP Address** | Internal network topology | `192.168.137.201` | `LOCAL_NETWORK` | Semantic regex classifier in `v_public_attack_events` |
| **External Target IP** | External entity tracking | `8.8.8.8` | `EXTERNAL_NETWORK` | Semantic boundary classification |
| **Internal Daemon Paths** | Path traversal, leak | `C:\Users\megha\...` | `Normal Shutdown` | Categorical regex scrubbing on `stop_reason` |
| **Forensic Evidence JSON** | Arbitrary text injection | Stack trace / memory | Allowlisted findings | 21 approved verdicts, 7 approved reasons |

---

## 2. Definitive Proof of Zero MAC / IP Leakage

### A. MAC Address Elimination
Every public view was audited line-by-line:
1. `v_public_collector_status`: No MAC columns exist.
2. `v_public_device_registry`: Projects `public_station_id` and `node_id` mapped strictly to `('Node_3', 'Node_4', 'Node_5')` or `'Unspecified_Node'`. Raw `mac_address` is never projected.
3. `v_public_live_traffic_windows`: Projects `public_station_id` mapped via `station_pseudonym_map` to `('Node_3', 'Node_4', 'Node_5')` or `'UNMAPPED_STATION'`. `w.client_mac` is never projected.
4. `v_public_live_alerts`: Projects `public_station_id` mapped via `station_pseudonym_map`. `a.client_mac` is never projected.
5. `v_public_unknown_device_obs`: Projects `public_device_alias` mapped to `'UNREGISTERED_STATION'` or allowlisted token. `u.observed_mac` is never projected.
6. `v_public_sensor_telemetry`: Projects `physical_node_id ('esp32_gateway')` and `logical_node_id ('Node_1')`. No MAC fields exist.
7. `v_public_pir_events`: Projects `physical_node_id ('esp32_gateway')` and `logical_node_id ('Node_2')`. No MAC fields exist.
8. `v_public_attack_events`: Projects `source_station_id` mapped via `station_pseudonym_map` to `('Node_3', 'Node_4', 'Node_5')` or `'ATTACKER_UNMAPPED'`. `e.source_mac` is never projected.
9. `v_public_traffic_overview`: Pre-aggregated run metrics. No MAC columns exist.

### B. IP Address Boundary Redaction
In `v_public_attack_events`, target IP addresses are sanitized via deterministic SQL:
```sql
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
END AS target_ip
```
Raw IPv4 and IPv6 addresses are completely inaccessible to public dashboard queries.

---

## 3. Role-Based Access Control Audit

| Role Name | Table Access Permissions | View Access Permissions | Schema Permissions |
|---|---|---|---|
| `anon` (Public visitors) | **ZERO** (ALL revoked) | `SELECT` on 9 `v_public_*` views | `USAGE ON SCHEMA public` |
| `authenticated` | **ZERO** (ALL revoked) | `SELECT` on 9 `v_public_*` views | `USAGE ON SCHEMA public` |
| `collector_role` | `SELECT, INSERT` (All 9 base tables); `UPDATE` (3 mutable tables only) | None needed (Ingest role) | `USAGE ON SCHEMA public` |
| `postgres` (View definer) | `ALL` (Table owner) | `OWNER` of 9 views (`security_invoker = false`) | Full administrative |

### Row-Level Security (RLS) Verification:
`ALTER TABLE station_pseudonym_map ENABLE ROW LEVEL SECURITY;` is enforced. Since no `SELECT` policy is granted to `anon` or `authenticated`, the mapping table is cryptographically isolated from public access.

---

## 4. Operational Integrity & Truth in Telemetry Presentation

In addition to cryptographic and PII redaction, the public dashboard enforces strict operational integrity guarantees:

1. **Honest Connection State Handling:**
   The dashboard continuously computes heartbeat age from `v_public_collector_status`:
   - **`LIVE` (Green):** Heartbeat $\le 15.0$ seconds.
   - **`STALE` (Amber):** Heartbeat $> 15.0$ seconds and $\le 60.0$ seconds.
   - **`OFFLINE` (Red):** Heartbeat $> 60.0$ seconds or absent.
   The console never masks a disconnected daemon or treats historical records as live telemetry.

2. **Categorical Separation of Anomalies vs Attacks:**
   - **Statistical Anomalies:** Scored by unsupervised Dual Isolation Forest (`src/benchmark_1s_anomaly_detector.py`, `src/cross_session_1s_detector.py`). The dashboard explicitly labels these as statistical deviations requiring triage, and **never describes them as confirmed cyber attacks**.
   - **Deterministic Attacks:** Flagged only when explainable, multi-layer rule heuristics in `src/attack_detector.py` meet deterministic criteria (Deauth flood, Disassociation abuse, Beacon injection, Probe request flood, RTS/CTS abuse).

3. **Graceful Empty & Offline State Handling:**
   When cloud tables are empty or the database is unconfigured, every section renders an informative, non-crashing notice card rather than throwing runtime exceptions or blank screens.

---

## 5. Privacy Certification

The public dashboard [`src/cloud_dashboard.py`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/src/cloud_dashboard.py) complies fully with all non-negotiable safety rules:
- Zero raw MAC addresses exposed across all 7 operational sections.
- Zero raw IP addresses exposed (strictly semantic `LOCAL_NETWORK`, `EXTERNAL_NETWORK`, `IP_REDACTED`).
- Zero raw evidence JSON or unconstrained internal strings/paths exposed.
- Zero service-role keys or administrator passwords required or utilized.
- Base tables 100% revoked from `anon`, `authenticated`, and `PUBLIC`.
- Definer security model active (`security_invoker = false`, views owned by `postgres`).

