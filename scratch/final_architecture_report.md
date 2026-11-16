# FINAL SYSTEM ARCHITECTURE REPORT
**Comprehensive End-to-End Architectural Blueprint**
**Project:** IoT Network Guard — Dual-Detector SOC Console  
**Date:** November 15, 2026  
**Document Reference:** `scratch/final_architecture_report.md`

---

## 1. System Architecture Overview

**IoT Network Guard** is structured across three decoupled architectural tiers:
1. **Edge Ingestion & Intelligence Tier (Local Sovereign Edge):** Workstation sniffer, dual-engine ML isolation forest, deterministic attack detectors, ESP32 serial ingestion, and authoritative SQLite database (`data/live_monitoring.db`).
2. **Asynchronous Staging & Cloud Delivery Tier:** Persistent SQLite outbox queue (`cloud_sync_outbox`), exponential backoff dispatcher, and idempotent PostgREST synchronizer.
3. **Cloud Persistence & Public Visualization Tier:** Managed PostgreSQL 17.6 on Supabase (`cwqumhtzeiqrfhlesksw`), 9 RLS-protected base tables, 9 definer views (`v_public_*`), and Streamlit Community Cloud SOC console (`src/cloud_dashboard.py`).

```mermaid
graph TD
    subgraph Edge["Edge Layer (Workstation Windows 11)"]
        WiFi["Wi-Fi Hotspot Clients (Node_3, Node_4)"] -->|802.11 Uplink| TShark["TShark Sniffer Daemon"]
        ESP32["ESP32 Gateway (Node_1, Node_2)"] -->|Serial JSON / COM6| SerialWorker["Serial Ingestion Thread"]
        TShark --> Extractor["1-Second Time-Window Extractor"]
        Extractor --> IFPrimary["Primary Isolation Forest (Packet Rate & Size)"]
        Extractor --> IFTiming["Timing Isolation Forest (Inter-Arrival Time)"]
        IFPrimary & IFTiming --> DualConsensus["Dual-Detector Consensus Engine"]
        Extractor --> AttackDetectors["Deterministic Network Attack Engine"]
        AttackDetectors --> AttackEvents["5 Attack Categories"]
        DualConsensus & AttackEvents & SerialWorker --> LocalSQLite["Local Sovereign SQLite WAL (live_monitoring.db)"]
        LocalSQLite --> LocalSOC["Local SOC Console (src/live_dashboard.py :8502)"]
    end

    subgraph Sync["Synchronization Pipeline"]
        LocalSQLite --> Outbox["Durable Staging Outbox (cloud_sync_outbox)"]
        Outbox --> SyncWorker["CloudSyncWorker (Background Thread)"]
    end

    subgraph Cloud["Cloud Infrastructure (Supabase Mumbai ap-south-1)"]
        SyncWorker -->|PostgREST Ingest (merge-duplicates)| PostgREST["Supabase PostgREST API"]
        PostgREST --> CloudBase["9 Base Tables (PostgreSQL 17.6)"]
        CloudBase --> DefinerViews["9 Public Definer Views (security_invoker = false)"]
        DefinerViews -->|Read-Only 'anon' Role| StreamlitCloud["Streamlit Community Cloud (src/cloud_dashboard.py)"]
    end
```

---

## 2. Ingestion & Detection Subsystems

### A. Dual Isolation Forest Anomaly Detection
- **Primary Detector:** Evaluates `packet_rate` (pps) and `mean_packet_size` (bytes). Trained on clean Session 1 baseline data to detect volumetric packet floods, data exfiltration bursts, and abnormal frame sizes.
- **Timing Gate Detector:** Evaluates `mean_IAT` (mean inter-arrival time) and `IAT_std` (jitter). Activated only when window packet count $N \ge 3$ to prevent false positives during idle quiet intervals.
- **Consensus Prediction:** Combines primary and timing predictions into a unified consensus state (`NORMAL_INLIER`, `ANOMALY_PRIMARY_BURST_OR_SIZE`, `ANOMALY_TIMING_JITTER`, `ANOMALY_PRIMARY_AND_TIMING`).
- **Prediction Convention:** Strictly adheres to Isolation Forest standard: $-1$ (outlier/anomaly), $+1$ (inlier/normal).

### B. Deterministic Network Attack Detection (5 Categories)
Decoupled from statistical ML outliers, this engine evaluates explainable evidence against rule-based criteria:
1. **Denial of Service (DoS):** Volumetric flood thresholding ($\ge 60$ pps sustained across consecutive windows).
2. **Reconnaissance & Port Scanning:** Evaluates vertical port sweeps ($\ge 5$ distinct ports on a single host) and horizontal host sweeps ($\ge 3$ distinct target hosts).
3. **Spoofing & Impersonation:** Detects conflicting IP-to-MAC bindings and gateway MAC impersonation attempts.
4. **Deauthentication & Disassociation Abuse:** Evaluates 802.11 management frame rates and disassociation burst thresholds.
5. **Replay Attacks:** Evaluates packet sequence number regressions and cryptographic nonce re-use.

### C. ESP32 Physical Environment Telemetry
- Microcontroller connects via UART serial port (`COM6`, 115200 baud).
- JSON framing: `{"seq": 105, "uptime_ms": 345000, "dht11": {"temp_c": 26.5, "humidity": 62.0, "valid": 1}, "pir": {"motion": 1}}`.
- Decoupled into `Node_1` (ambient physical context) and `Node_2` (physical motion state).

---

## 3. Data Synchronization Architecture

### 4-Tier Outbox Scheduling:
- **Tier 1 (Priority 1):** `live_attack_events`, `collector_status`. **Zero Data Loss Guarantee.** Never dropped.
- **Tier 2 (Priority 2):** `live_alerts`, `live_sensor_telemetry`, `live_pir_events`. **Zero Data Loss Guarantee.**
- **Tier 3 (Priority 3):** `live_traffic_windows`. High-rate 1s bins. Ring-buffered; oldest entries may be shed only after prolonged offline queue saturation ($> 5,000$ items).
- **Tier 4 (Priority 4):** `unknown_device_obs`, `device_registry`. Asynchronous upserts.

### Idempotency & Conflict Resolution:
- Every queued record receives a deterministic `event_uuid` (UUID v5).
- Cloud deliveries pass HTTP header `Prefer: resolution=merge-duplicates`.
- Duplicate delivery on network retry is mathematically prevented.

---

## 4. Cloud Database Schema Design

The cloud schema consists of:
- **9 Base Tables:** `collector_status`, `device_registry`, `station_pseudonym_map`, `live_traffic_windows`, `live_alerts`, `unknown_device_obs`, `live_sensor_telemetry`, `live_pir_events`, `live_attack_events`.
- **9 Public Definer Views:** `v_public_collector_status`, `v_public_device_registry`, `v_public_live_traffic_windows`, `v_public_live_alerts`, `v_public_unknown_device_obs`, `v_public_sensor_telemetry`, `v_public_pir_events`, `v_public_attack_events`, `v_public_traffic_overview`.
- **Security Definer Model:** Views declare `WITH (security_invoker = false)` and are owned by `postgres`.
- **Public Lockout:** Base tables are 100% revoked from public `anon` access. Views serve as the sole, immutable security boundary.

