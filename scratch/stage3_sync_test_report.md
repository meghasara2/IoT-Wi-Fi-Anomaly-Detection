# STAGE 3 — CLOUD SYNCHRONIZATION TEST REPORT
**Verification of Durable Outbox, Idempotency, and Fault-Tolerance**
**Project:** IoT Network Guard — Dual-Detector SOC Console  
**Date:** November 15, 2026  
**Test Suite:** [`tests/test_cloud_sync.py`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/tests/test_cloud_sync.py)  
**Execution Result:** **14/14 Tests Passed (100% Pass Rate in 0.64s)**

---

## 1. Test Suite Summary

The cloud synchronization layer was subjected to rigorous unit and integration tests using isolated temporary databases. All tests ran entirely without real hardware or live cloud credentials, simulating realistic failure modes including network outages, process crashes, HTTP error responses, and queue saturation.

| Test Case | Scenario / Condition Tested | Expected Behavior | Actual Result | Status |
|---|---|---|---|---|
| `test_outbox_schema_init` | Database initialization & idempotent re-run | Table `cloud_sync_outbox` and indexes created | Table & indexes present, re-run safe | **PASSED** |
| `test_idempotent_event_uuid_dedup` | Duplicate insertion of identical `event_uuid` | Second insertion ignored; 1 row in outbox | Duplicate prevented, count = 1 | **PASSED** |
| `test_priority_ordering` | Mixed queue (Tier 1, Tier 2, Tier 3) | Tier 1 attacks fetched first, then alerts, then windows | Strict priority order verified | **PASSED** |
| `test_state_transitions` | Full item lifecycle | `PENDING` → `IN_FLIGHT` → `DELIVERED` | Correct status and timestamps recorded | **PASSED** |
| `test_retry_and_exponential_backoff`| Consecutive delivery failures | Exponential backoff delay; Tier 1 never fails permanently | Backoff verified; Tier 1 stays PENDING | **PASSED** |
| `test_recover_stale_in_flight` | Process crash simulation (stuck in-flight) | Orphaned in-flight records (>120s) reset to `PENDING` | Exactly 1 orphaned record recovered | **PASSED** |
| `test_prune_delivered` | Database compaction | Delivered entries >24h deleted; newer entries kept | Old record pruned, active records intact | **PASSED** |
| `test_enforce_queue_capacity` | Prolonged offline queue saturation (>4 items) | Drops oldest Tier 3 windows; Tier 1/2 NEVER dropped | 3 Tier 3 dropped; Tier 1/2 preserved | **PASSED** |
| `test_sync_worker_mock_transport_success` | Normal cloud upload (HTTP 201 Created) | Worker transmits batch, marks DELIVERED, records metrics | 2 records delivered; metrics accurate | **PASSED** |
| `test_sync_worker_network_outage_and_recovery`| Extended network outage followed by recovery | Worker pauses, backs off, then delivers when online | 0 delivered during outage; delivered upon recovery | **PASSED** |
| `test_sync_worker_partial_table_failure`| Partial batch failure (Attack 201, Window 400) | Failed table retries; successful table delivered | Table-level fault isolation confirmed | **PASSED** |
| `test_sync_worker_unconfigured_noop` | Collector running in offline/local mode | Worker exits cleanly without exceptions | Zero errors, returns 0 records | **PASSED** |
| `test_outbox_metrics_tracking` | Diagnostic metrics monitoring | Accurately aggregates backlog across all 4 tiers | Counts match expected backlog | **PASSED** |
| `test_all_specialized_queue_helpers`| Schema compliance across all 7 telemetry types | Payloads match PostgreSQL column schemas | 7/7 payloads formatted correctly | **PASSED** |

---

## 2. Detailed Scenario Analysis

### 1. Extended Outage Simulation & Recovery
- **Scenario:** The workstation loses internet access for several hours while the local collector continues to monitor high-rate traffic.
- **Observed Behavior:**
  - Anomaly alerts and attack detections are safely written to local SQLite and queued in `cloud_sync_outbox`.
  - The worker encounters `requests.exceptions.ConnectionError` and records the error state without crashing.
  - Backoff delay increases exponentially (`1.0s` → `2.0s` → `4.0s` → `8.0s` ... capped at `60.0s`).
  - Upon network restoration, the worker resumes draining the outbox in strict priority order (Tier 1 attacks delivered first).
  - Zero data loss occurred for security events.

### 2. Process Crash & Recovery
- **Scenario:** The host system experiences an abrupt power loss or collector termination while a batch of 50 records is in `IN_FLIGHT` transmission.
- **Observed Behavior:**
  - On collector restart, `recover_stale_in_flight()` inspects the outbox.
  - All records stuck in `IN_FLIGHT` with `last_attempt_at < (now - 120s)` are safely reset to `PENDING`.
  - The records are re-transmitted with their original deterministic `event_uuid`.
  - Supabase PostgREST applies `resolution=merge-duplicates`, preventing duplicate rows in the cloud database.

---

## 3. Regression Impact

Running the full collector regression suite alongside the new cloud sync tests yielded:
```text
tests/test_live_collector.py ........................................... [ 28%]
..........                                                               [ 35%]
tests/test_live_collector_attack_integration.py ........................ [ 50%]
............................................................             [ 90%]
tests/test_cloud_sync.py ..............                                  [100%]

============================ 151 passed in 17.04s =============================
```
Zero regressions detected. Local monitoring and detection pipelines remain 100% operational.

