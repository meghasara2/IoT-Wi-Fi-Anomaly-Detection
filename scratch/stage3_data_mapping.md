# STAGE 3 — TELEMETRY DATA MAPPING SPECIFICATION
**Local SQLite to Supabase Cloud PostgreSQL Schema Mapping**
**Project:** IoT Network Guard — Dual-Detector SOC Console  
**Date:** November 15, 2026  
**Source Engine:** SQLite 3 (WAL Mode, `data/live_monitoring.db`)  
**Target Engine:** PostgreSQL 17.6 (Supabase Cloud, Mumbai `ap-south-1`)

---

## 1. Overview & Architectural Principles

The local monitoring system uses SQLite as the sovereign, authoritative data store. Telemetry is asynchronously queued into the durable `cloud_sync_outbox` table and delivered to Supabase PostgreSQL using idempotent keys.

### Core Translation Rules:
1. **Primary Key Namespacing:** SQLite auto-increment IDs (`1`, `2`, `3`) are combined with `run_id` into globally unique strings (e.g., `win_1_45`, `alert_1_12`, `sensor_1_254`) for PostgreSQL `TEXT PRIMARY KEY` columns, preventing collisions across multiple runs or collector processes.
2. **Deterministic Event UUIDs (F-01):** Attack events use UUID v5 (`iot.guard.live_attack_events.<run_id>.<composite>`) or the detector's native event UUID, mapping directly to PostgreSQL `event_uuid UUID NOT NULL UNIQUE`.
3. **Type Conversions:**
   - SQLite `INTEGER` (0/1) → PostgreSQL `BOOLEAN` (true/false)
   - SQLite `REAL` (Unix epoch) → PostgreSQL `DOUBLE PRECISION` or `TIMESTAMPTZ`
   - SQLite `TEXT` (JSON string) → PostgreSQL `JSONB`
   - Python `NaN` / `math.nan` → PostgreSQL `NULL`
4. **Idempotent Ingestion:** All cloud deliveries use PostgREST `Prefer: resolution=merge-duplicates`, preventing duplicates upon network retry.

---

## 2. Table-by-Table Data Mapping

### Table 1: `collector_status` (Tier 1 Priority - Lifecycle & Heartbeat)
| SQLite Source Field | Outbox Payload Field | PostgreSQL Target Column | Target Type | Conversion / Transformation Logic |
|---|---|---|---|---|
| `run_id` | `run_id` | `run_id` | `TEXT PRIMARY KEY` | Converted to string: `str(run_id)` |
| `started_at` | `started_at` | `started_at` | `TIMESTAMPTZ` | ISO 8601 UTC timestamp string |
| `last_heartbeat` | `last_heartbeat` | `last_heartbeat` | `TIMESTAMPTZ` | ISO 8601 UTC timestamp string |
| `interface_name` | `interface_name` | `interface_name` | `TEXT` | Raw interface string (sanitized in view) |
| `serial_port` | `serial_port` | `serial_port` | `TEXT` | Raw serial port name (sanitized in view) |
| `status` | `status` | `status` | `TEXT` | 'STARTING', 'RUNNING', 'STOPPED', 'ERROR' |
| `stop_reason` | `stop_reason` | `stop_reason` | `TEXT` | Raw exception or shutdown reason |
| `packets_parsed` | `packets_parsed` | `packets_parsed` | `BIGINT` | Integer packet count |
| `windows_emitted` | `windows_emitted` | `windows_emitted` | `BIGINT` | Integer window count |
| `sensor_records` | `sensor_records` | `sensor_records` | `BIGINT` | Integer sensor payload count |

---

### Table 2: `device_registry` (Tier 4 Priority - Known Stations)
| SQLite Source Field | Outbox Payload Field | PostgreSQL Target Column | Target Type | Conversion / Transformation Logic |
|---|---|---|---|---|
| `mac_address` | `mac_address` | `mac_address` | `TEXT PRIMARY KEY` | Normalized lower-case MAC address |
| `node_id` | `node_id` | `node_id` | `TEXT NOT NULL` | 'Node_3', 'Node_4', 'Node_5' |
| `device_type` | `device_type` | `device_type` | `TEXT NOT NULL` | 'Phone_Client', 'IoT_Sensor', 'Gateway_AP' |
| `label` | `label` | `label` | `TEXT NOT NULL` | 'real_observed_traffic', 'baseline_benign' |
| `last_seen` | `last_seen` | `last_seen` | `TIMESTAMPTZ` | ISO 8601 UTC timestamp string |
| `notes` | `notes` | `notes` | `TEXT` | Friendly operator description |

---

### Table 3: `live_traffic_windows` (Tier 3 Priority - 1s Feature Slices)
| SQLite Source Field | Outbox Payload Field | PostgreSQL Target Column | Target Type | Conversion / Transformation Logic |
|---|---|---|---|---|
| `window_id` | `window_id` | `window_id` | `TEXT PRIMARY KEY` | Formatted: `f"win_{run_id}_{window_id}"` |
| `run_id` | `run_id` | `run_id` | `TEXT NOT NULL` | Foreign key to `collector_status(run_id)` |
| `client_mac` | `client_mac` | `client_mac` | `TEXT NOT NULL` | Private MAC address (sanitized in views) |
| `node_id` | `node_id` | `node_id` | `TEXT NOT NULL` | 'Node_3', 'Node_4', 'Node_5' |
| `node_type` | `node_type` | `node_type` | `TEXT` | Station class string |
| `data_label` | `data_label` | `data_label` | `TEXT` | Evaluation category string |
| `bin_start_epoch` | `bin_start_epoch` | `bin_start_epoch` | `DOUBLE PRECISION` | Unix epoch float |
| `bin_end_epoch` | `bin_end_epoch` | `bin_end_epoch` | `DOUBLE PRECISION` | Unix epoch float |
| `window_center_epoch` | `window_center_epoch`| `window_center_epoch`| `DOUBLE PRECISION` | Window midpoint float |
| `window_start_utc` | `window_start_utc` | `window_start_utc` | `TIMESTAMPTZ` | Timestamp string |
| `window_end_utc` | `window_end_utc` | `window_end_utc` | `TIMESTAMPTZ` | Timestamp string |
| `packet_count` | `packet_count` | `packet_count` | `BIGINT NOT NULL` | Integer packet count in window |
| `mean_IAT` | `mean_IAT` | `mean_IAT` | `DOUBLE PRECISION` | `NaN` mapped to `None` / `NULL` |
| `IAT_std` | `IAT_std` | `IAT_std` | `DOUBLE PRECISION` | `NaN` mapped to `None` / `NULL` |
| `packet_rate` | `packet_rate` | `packet_rate` | `DOUBLE PRECISION` | Float packets per second |
| `mean_packet_size` | `mean_packet_size` | `mean_packet_size` | `DOUBLE PRECISION` | `NaN` mapped to `None` / `NULL` |
| `packet_size_std` | `packet_size_std` | `packet_size_std` | `DOUBLE PRECISION` | `NaN` mapped to `None` / `NULL` |
| `score_primary` | `score_primary` | `score_primary` | `DOUBLE PRECISION` | Primary Isolation Forest score |
| `pred_primary` | `pred_primary` | `pred_primary` | `INTEGER` | -1 (anomaly) / +1 (inlier) |
| `score_timing` | `score_timing` | `score_timing` | `DOUBLE PRECISION` | Timing Isolation Forest score |
| `pred_timing` | `pred_timing` | `pred_timing` | `INTEGER` | -1 / +1 / NULL |
| `timing_status` | `timing_status` | `timing_status` | `TEXT` | 'ACTIVE' / 'UNAVAILABLE_N_LT_3' |
| `pred_dual` | `pred_dual` | `pred_dual` | `INTEGER` | Dual-detector consensus (-1 / +1) |
| `dual_reason` | `dual_reason` | `dual_reason` | `TEXT` | Categorical anomaly explanation |

---

### Table 4: `live_alerts` (Tier 2 Priority - Statistical Anomalies)
| SQLite Source Field | Outbox Payload Field | PostgreSQL Target Column | Target Type | Conversion / Transformation Logic |
|---|---|---|---|---|
| `alert_id` | `alert_id` | `alert_id` | `TEXT PRIMARY KEY` | Formatted: `f"alert_{run_id}_{alert_id}"` |
| `window_id` | `window_id` | `window_id` | `TEXT NOT NULL` | Formatted: `f"win_{run_id}_{window_id}"` |
| `run_id` | `run_id` | `run_id` | `TEXT NOT NULL` | Foreign key to `collector_status(run_id)` |
| `client_mac` | `client_mac` | `client_mac` | `TEXT NOT NULL` | Private MAC address |
| `node_id` | `node_id` | `node_id` | `TEXT NOT NULL` | Station identifier |
| `bin_start_epoch` | `bin_start_epoch` | `bin_start_epoch` | `DOUBLE PRECISION` | Epoch float |
| `window_start_utc` | `window_start_utc` | `window_start_utc` | `TIMESTAMPTZ` | Timestamp string |
| `dual_reason` | `dual_reason` | `dual_reason` | `TEXT NOT NULL` | Categorical consensus reason |
| `score_primary` | `score_primary` | `score_primary` | `DOUBLE PRECISION` | Float score |
| `score_timing` | `score_timing` | `score_timing` | `DOUBLE PRECISION` | Float score |
| `packet_rate` | `packet_rate` | `packet_rate` | `DOUBLE PRECISION` | Float packets/sec |
| `mean_packet_size` | `mean_packet_size` | `mean_packet_size` | `DOUBLE PRECISION` | Float bytes |
| `packet_count` | `packet_count` | `packet_count` | `BIGINT` | Integer packet count |
| `acknowledged` | `acknowledged` | `acknowledged` | `BOOLEAN` | Integer 0/1 mapped to boolean |

---

### Table 5: `live_attack_events` (Tier 1 Priority - Forensic Security Evidence)
| SQLite Source Field | Outbox Payload Field | PostgreSQL Target Column | Target Type | Conversion / Transformation Logic |
|---|---|---|---|---|
| N/A | `event_uuid` | `event_uuid` | `UUID NOT NULL UNIQUE` | Deterministic UUID v5 or native event UUID |
| `run_id` | `run_id` | `run_id` | `TEXT NOT NULL` | Foreign key to `collector_status(run_id)` |
| `window_id` | `window_id` | `window_id` | `TEXT` | Nullable: `f"win_{run_id}_{window_id}"` |
| `timestamp_epoch` | `timestamp_epoch` | `timestamp_epoch` | `DOUBLE PRECISION` | Unix epoch float |
| `timestamp_utc` | `timestamp_utc` | `timestamp_utc` | `TIMESTAMPTZ` | Timestamp string |
| `category` | `category` | `category` | `TEXT NOT NULL` | Denial_of_Service, Reconnaissance, etc. |
| `status` | `status` | `status` | `TEXT NOT NULL` | NO_EVIDENCE, SUSPICIOUS, CONFIRMED |
| `severity` | `severity` | `severity` | `TEXT NOT NULL` | NONE, LOW, MEDIUM, HIGH, CRITICAL |
| `confidence` | `confidence` | `confidence` | `DOUBLE PRECISION` | Confidence float between 0.0 and 1.0 |
| `source_mac` | `source_mac` | `source_mac` | `TEXT` | Private MAC (sanitized in view) |
| `target_ip` | `target_ip` | `target_ip` | `TEXT` | Private IP (scoped to LOCAL/EXTERNAL in view) |
| `evidence_json` | `evidence_json` | `evidence_json` | `JSONB NOT NULL` | Dictionary converted to PostgreSQL JSONB |
| `missing_fields_json`| `missing_fields_json`| `missing_fields_json`| `JSONB` | List converted to PostgreSQL JSONB |
| `recommended_action`| `mitigation_recommendation`| `mitigation_recommendation`| `TEXT` | Standard guidance text |
| `acknowledged` | `acknowledged` | `acknowledged` | `BOOLEAN` | Integer 0/1 mapped to boolean |

---

### Table 6: `live_sensor_telemetry` (Tier 2 Priority - Physical Node_1 DHT11)
| SQLite Source Field | Outbox Payload Field | PostgreSQL Target Column | Target Type | Conversion / Transformation Logic |
|---|---|---|---|---|
| `telemetry_id` | `telemetry_id` | `telemetry_id` | `TEXT PRIMARY KEY` | Formatted: `f"sensor_{run_id}_{seq}"` |
| `run_id` | `run_id` | `run_id` | `TEXT NOT NULL` | Foreign key to `collector_status(run_id)` |
| `logical_node_id` | `logical_node_id` | `logical_node_id` | `TEXT NOT NULL` | Strictly 'Node_1' |
| `sequence_num` | `sequence_num` | `sequence_num` | `BIGINT NOT NULL` | Firmware counter integer |
| `uptime_ms` | `uptime_ms` | `uptime_ms` | `BIGINT NOT NULL` | Millisecond uptime integer |
| `temperature_c` | `temperature_c` | `temperature_c` | `DOUBLE PRECISION` | Float degrees Celsius |
| `humidity_pct` | `humidity_pct` | `humidity_pct` | `DOUBLE PRECISION` | Float percentage |
| `dht_valid` | `dht_valid` | `dht_valid` | `BOOLEAN NOT NULL` | Integer 0/1 mapped to boolean |
| `captured_at` | `captured_at` | `captured_at` | `TIMESTAMPTZ` | Timestamp string |
| `sensor_epoch` | `sensor_epoch` | `sensor_epoch` | `DOUBLE PRECISION` | Epoch float |

---

### Table 7: `live_pir_events` (Tier 2 Priority - Physical Node_2 PIR)
| SQLite Source Field | Outbox Payload Field | PostgreSQL Target Column | Target Type | Conversion / Transformation Logic |
|---|---|---|---|---|
| `pir_id` | `pir_id` | `pir_id` | `TEXT PRIMARY KEY` | Formatted: `f"pir_{run_id}_{seq}"` |
| `run_id` | `run_id` | `run_id` | `TEXT NOT NULL` | Foreign key to `collector_status(run_id)` |
| `logical_node_id` | `logical_node_id` | `logical_node_id` | `TEXT NOT NULL` | Strictly 'Node_2' |
| `sequence_num` | `sequence_num` | `sequence_num` | `BIGINT NOT NULL` | Firmware counter integer |
| `uptime_ms` | `uptime_ms` | `uptime_ms` | `BIGINT NOT NULL` | Millisecond uptime integer |
| `motion_detected` | `motion_detected` | `motion_detected` | `BOOLEAN NOT NULL` | Integer 0/1 mapped to boolean |
| `captured_at` | `captured_at` | `captured_at` | `TIMESTAMPTZ` | Timestamp string |
| `sensor_epoch` | `sensor_epoch` | `sensor_epoch` | `DOUBLE PRECISION` | Epoch float |

---

### Table 8: `unknown_device_obs` (Tier 4 Priority - Unregistered MACs)
| SQLite Source Field | Outbox Payload Field | PostgreSQL Target Column | Target Type | Conversion / Transformation Logic |
|---|---|---|---|---|
| `obs_id` | `obs_id` | `obs_id` | `TEXT PRIMARY KEY` | Formatted: `f"obs_{run_id}_{mac}"` |
| `run_id` | `run_id` | `run_id` | `TEXT NOT NULL` | Foreign key to `collector_status(run_id)` |
| `observed_mac` | `observed_mac` | `observed_mac` | `TEXT NOT NULL` | Private MAC (sanitized in view) |
| `first_seen_utc` | `first_seen_utc` | `first_seen_utc` | `TIMESTAMPTZ` | Timestamp string |
| `last_seen_utc` | `last_seen_utc` | `last_seen_utc` | `TIMESTAMPTZ` | Timestamp string |
| `observation_count` | `observation_count` | `observation_count` | `BIGINT` | Integer observation counter |
| `acknowledged` | `acknowledged` | `acknowledged` | `BOOLEAN` | Integer 0/1 mapped to boolean |

---

## 3. Privacy & Public View Redaction Boundary

The public cloud dashboard NEVER queries the base tables above directly. All cloud dashboard queries read exclusively from the 9 definer security views (`v_public_*`):
- `v_public_collector_status`: Sanitizes `stop_reason` to safe categorical status.
- `v_public_device_registry`: Projects allowlisted station identifiers (`Node_3`, `Node_4`, `Node_5`), zero raw MACs.
- `v_public_live_traffic_windows`: Joins `station_pseudonym_map` to project safe tokens.
- `v_public_live_alerts`: Joins `station_pseudonym_map` to project safe tokens.
- `v_public_unknown_device_obs`: Neutral alias `'UNREGISTERED_STATION'`.
- `v_public_sensor_telemetry`: Whitelisted `logical_node_id` (`Node_1`).
- `v_public_pir_events`: Whitelisted `logical_node_id` (`Node_2`).
- `v_public_attack_events`: Bounds-checked numeric casts, semantic IP classification (`LOCAL_NETWORK`, `EXTERNAL_NETWORK`, `IP_REDACTED`), categorical verdicts and reasons.
- `v_public_traffic_overview`: Pre-aggregated run statistics.

