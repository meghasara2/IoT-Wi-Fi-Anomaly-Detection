# STAGE 6.4 — INITIAL DASHBOARD INSPECTION REPORT

**Project:** AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection  
**Workspace:** `C:\Users\megha\OneDrive\Desktop\IoT_WiFi_Anomaly_Detection`  
**Execution Date:** 2026-11-10  
**Phase:** 1 (Read-Only Source & Schema Inspection)

---

## 1. Overview & Scope

This inspection audits the live monitoring Streamlit dashboard in `src/live_dashboard.py` and its relationship with the backend SQLite database (`data/live_monitoring.db`) and collector daemon (`src/live_collector.py`).

The primary objectives of Stage 6.4 are:
1. Replace hardcoded status cards in the "Five Attack Categories Operational Status" ribbon with dynamic, database-driven statuses:
   - `DETECTED`
   - `NO ALERT OBSERVED`
   - `INSUFFICIENT TELEMETRY`
   - `MONITORING UNAVAILABLE`
2. Implement an ESP32 Wi-Fi sniffer diagnostics panel that reports telemetry health honestly without fabricating values.
3. Ensure absolute stability, graceful error handling, and complete separation between statistical anomalies (Isolation Forest) and deterministic attack events.

---

## 2. Existing Attack Status Ribbon Audit

### 2.1 Hardcoded Status Cards
In `src/live_dashboard.py` lines 1450–1508 (`render_attack_intelligence`):
- **Card 1 (Denial of Service):** Hardcoded `<div class="metric-val" style="font-size:1.1rem; color:{DARK_PALETTE['safe_emerald']};">OPERATIONAL</div>`
- **Card 2 (Reconnaissance):** Hardcoded `<div class="metric-val" style="font-size:1.1rem; color:{DARK_PALETTE['safe_emerald']};">OPERATIONAL</div>`
- **Card 3 (Spoofing / Impersonation):** Hardcoded `<div class="metric-val" style="font-size:1.1rem; color:{DARK_PALETTE['safe_emerald']};">OPERATIONAL</div>`
- **Card 4 (Wi-Fi Deauth Flood):** Hardcoded `<div class="metric-val" style="font-size:1.0rem; color:#9CA3AF;">INSUFFICIENT</div>`
- **Card 5 (Replay Attack):** Hardcoded `<div class="metric-val" style="font-size:1.0rem; color:#9CA3AF;">INSUFFICIENT</div>`

### 2.2 Flaws in Existing Design
1. **False Safety & Misleading Claims:** Cards 1–3 permanently display green `OPERATIONAL` even if an active attack is detected or if monitoring is completely offline.
2. **Permanent Invalidation:** Cards 4 and 5 permanently display gray `INSUFFICIENT` even when valid deauthentication flood or replay attacks are detected and persisted in `live_attack_events`.
3. **Decoupling from SQLite Evidence:** The ribbon never queries `live_attack_events` or `collector_status` to determine category health.

---

## 3. Database Schema & Query Audit

### 3.1 Tables Present in `data/live_monitoring.db`
Verified via `sqlite_master` in `src/init_live_database.py`:
1. `collector_status`: Run lifecycle and daemon heartbeats.
2. `device_registry`: Known IoT devices and assigned logical nodes.
3. `live_traffic_windows`: 1-second extracted traffic feature windows with Isolation Forest predictions.
4. `live_alerts`: Statistical anomaly alerts flagged by Isolation Forest.
5. `unknown_device_obs`: Unregistered MAC observations.
6. `live_sensor_telemetry`: Physical DHT11 readings (Node 1).
7. `live_pir_events`: Physical PIR motion detections (Node 2).
8. `live_attack_events`: Deterministic attack detection results from `NetworkAttackDetector`.

### 3.2 Structure of `live_attack_events`
Columns:
- `event_id`: INTEGER PRIMARY KEY AUTOINCREMENT
- `run_id`: INTEGER
- `window_id`: INTEGER (NULL for stream-level evaluations)
- `timestamp_epoch`: REAL
- `timestamp_utc`: DATETIME
- `category`: TEXT (`'Denial_of_Service'`, `'Reconnaissance_Port_Scan'`, `'Spoofing_Impersonation'`, `'Deauthentication_Disassociation_Abuse'`, `'Replay_Attack'`)
- `status`: TEXT (`'CONFIRMED_THREAT'`, `'SUSPICIOUS'`, `'INSUFFICIENT_TELEMETRY'`, `'NO_EVIDENCE'`)
- `severity`: TEXT (`'NONE'`, `'LOW'`, `'MEDIUM'`, `'HIGH'`, `'CRITICAL'`)
- `confidence`: REAL (0.0 to 1.0)
- `source_mac`: TEXT (nullable)
- `target_ip`: TEXT (nullable)
- `evidence_json`: TEXT (structured JSON object containing detection findings)
- `missing_fields_json`: TEXT (structured JSON list of missing telemetry fields)
- `recommended_action`: TEXT
- `acknowledged`: INTEGER DEFAULT 0
- `created_at`: DATETIME

### 3.3 Startup Capability Records vs. Actual Threat Events
At collector daemon startup (`src/live_collector.py` lines 868–904), baseline capability records are inserted for each category:
- `status` is set to `NO_EVIDENCE` or `INSUFFICIENT_TELEMETRY`.
- `severity` is set to `'NONE'`.
- `confidence` is `0.0`.
- `window_id` is `NULL`.
- `evidence_json` contains `{"initial_capability": ...}`.

**Critical Rule:** Startup capability records are NOT attacks. Only events with `status IN ('CONFIRMED_THREAT', 'SUSPICIOUS')` and `severity != 'NONE'` indicate a `DETECTED` attack.

---

## 4. ESP32 Telemetry & Sniffer Diagnostics Audit

### 4.1 Ingestion in `src/live_collector.py`
The serial listener handles three ESP32 message types:
1. `ESP32_TELEMETRY_INITIALIZED` (Boot announcement)
2. `WIFI_SNIFFER_INITIALIZED` (Probe response handshake: boot_id, nonce, channel)
3. `wifi_mgmt` (Individual 802.11 deauth/disassociation frames)
4. `wifi_mgmt_summary` (Periodic 1.0s accounting summary report)

### 4.2 Handling of `wifi_mgmt_summary`
`_handle_wifi_mgmt_summary()` in `src/live_collector.py`:
- Validates the payload (`boot_id`, `summary_seq`, `uptime_ms`, `window_ms`, `cumulative`).
- Computes `window_delta` for cumulative counters: `rx_total`, `tb_suppressed`, `queue_dropped`, `enqueued`, `uart_accepted`, `uart_failed`.
- Stores snapshot in memory: `self._last_summary_snapshot`.

### 4.3 Key Architectural Finding: Summaries Are Not Persisted
- `_last_summary_snapshot` is **ONLY held in collector daemon memory**.
- **No SQLite table exists** for `wifi_mgmt_summary`.
- The dashboard is a standalone Streamlit process connecting via read-only SQLite URI (`file:data/live_monitoring.db?mode=ro`).
- Therefore, the dashboard **cannot access in-memory collector snapshots directly**.
- **Honesty Rule:** As explicitly directed in Phase 3, the dashboard must not fabricate summary counters. It will display the diagnostics that *are* persisted in SQLite (`collector_status.serial_port`, `collector_status.sensor_records`, sensor telemetry activity, and deauth attack findings) and explicitly state that periodic sniffer summaries are currently held in collector memory only.

---

## 5. Requirements for Phase 2–4 Implementation

1. **Status Evaluation Function (`compute_attack_category_status`):**
   A robust, database-driven helper function evaluating:
   - Daemon state (`collector_status`).
   - Attack events (`live_attack_events`).
   - Telemetry availability (traffic windows, sensor records, missing fields).
2. **Accurate Visual Cards:**
   - `DETECTED`: Coral/Red alert border with event count and latest timestamp.
   - `NO ALERT OBSERVED`: Emerald/Green border with "No Threat Flagged • Telemetry Active".
   - `INSUFFICIENT TELEMETRY`: Amber/Yellow or Neutral border with explanation of missing headers.
   - `MONITORING UNAVAILABLE`: Gray border with "Daemon Inactive / No Session Data".
3. **ESP32 Wi-Fi Sniffer Diagnostics Panel:**
   Dedicated diagnostic section reporting hardware/port status, last-seen timestamps, sniffer capability status, and clear explanation of in-memory summary limitations.
4. **Safety & Zero Disruption:**
   - Maintain read-only database access.
   - Never write to production databases.
   - Preserve all existing charts, metrics, and navigation tabs.

