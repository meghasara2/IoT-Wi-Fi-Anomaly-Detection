# STAGE 5 — SECURITY CONTROLS TEST REPORT
**Verification of Access Control, PII Redaction, and Overflow Immunity**
**Project:** IoT Network Guard — Dual-Detector SOC Console  
**Date:** November 15, 2026  
**Audited Migration:** [`scratch/stage3b_6_final_supabase_migration.sql`](file:///c:/Users/megha/OneDrive/Desktop/IoT_WiFi_Anomaly_Detection/scratch/stage3b_6_final_supabase_migration.sql) (Baseline 3.6.0)  
**Security Validation Result:** **23/23 Checks Passed (100%)**

---

## 1. Security Controls Verification Matrix

| Security Domain | Control Objective | Verification Method | Result |
|---|---|---|---|
| **Credential Safety** | Zero hardcoded passwords or secrets | Static regex scan in `validate_stage3b_6_sql.py` (Check 16) | **VERIFIED (PASSWORD NULL)** |
| **Least Privilege (PoLP)** | Collector restricted to operational inserts | DDL Grant/Revoke audit (Check 11); 0 DELETE/TRUNCATE | **VERIFIED (Strict PoLP)** |
| **Base Table Lockout** | Public `anon` role locked out from base tables | Grant audit (Check 10); 0 base table grants to `anon` | **VERIFIED (100% Revoked)** |
| **View Definer Model** | Definer execution owned by `postgres` | `ALTER VIEW OWNER TO postgres` & `security_invoker = false` | **VERIFIED (Definer Rights)** |
| **Row-Level Security** | Sensitive mapping table isolated | `ALTER TABLE station_pseudonym_map ENABLE ROW LEVEL SECURITY` | **VERIFIED (RLS Active)** |
| **Pseudonym Allowlist** | Zero raw MAC or unvetted fallback tokens | View projection audit (Check 20); only `Node_1`..`Node_5` | **VERIFIED (Closed Allowlist)**|
| **Semantic IP Scoping** | Zero raw IP addresses in public views | Regex classifier audit; `LOCAL`, `EXTERNAL`, `REDACTED` | **VERIFIED (Zero IP Leak)** |
| **Numeric Overflow Safety** | Query crash immunity on malformed JSON | 28-vector edge-case suite (Check 21); `^[0-9]{1,9}$` | **VERIFIED (Zero Crash Risk)** |
| **Referential Integrity** | Audit trail preservation | Check 4: 7 `ON DELETE RESTRICT`, 0 `ON DELETE CASCADE` | **VERIFIED (Audit Retained)** |
| **Schema Idempotency** | Non-destructive re-runs & drift reconciliation | Section 0 Preflight DO block (Check 23) | **VERIFIED (Drift Resilient)** |

---

## 2. Numeric Overflow Simulation Test Results

To verify that malformed or adversarial JSON telemetry cannot crash queries against `v_public_attack_events`, 28 test vectors were tested against the bounds-checked regex rules:

```python
# Integer bounds regex: ^[0-9]{1,9}$ (guaranteed <= 999,999,999 < 2,147,483,647)
# Rate bounds regex:    ^[0-9]{1,8}(\.[0-9]{1,4})?$
```

### Edge-Case Results:
- **70-digit oversized integer:** Safely rejected → evaluated to `NULL` (Zero crash).
- **32-bit boundary violation (`2147483648`):** Safely rejected → evaluated to `NULL`.
- **Negative integer count (`-50`):** Safely rejected → evaluated to `NULL`.
- **Double-precision overflow (`1e309`):** Safely rejected → evaluated to `NULL`.
- **Scientific notation (`1e10`):** Safely rejected → evaluated to `NULL`.
- **Special floating-point values (`NaN`, `Infinity`, `-Infinity`):** Safely rejected → evaluated to `NULL`.
- **SQL / Text injection (`'; DROP TABLE ...; --`):** Safely rejected → evaluated to `NULL`.
- **Valid metric values (`125`, `65535`, `42.5`):** Safely matched and cast accurately.

---

## 3. Public View PII Redaction Certification

All 9 public views were verified to project exclusively vetted categorical tokens:
- Stations: `Node_1`, `Node_2`, `Node_3`, `Node_4`, `Node_5`, `UNMAPPED_STATION`, `UNREGISTERED_STATION`, `ATTACKER_UNMAPPED`, `Unspecified_Node`.
- Network IPs: `LOCAL_NETWORK`, `EXTERNAL_NETWORK`, `IP_REDACTED`.
- Stopping Reasons: `Operator Requested Shutdown`, `Network Timeout`, `Collector Error`, `Normal Shutdown`.
- Verdicts: 21 verified detector verdicts from `src/attack_detector.py` or fallback `'Security Evaluation finding'`.
- Reasons: 7 verified safe detector explanations or fallback `'Telemetry explanation recorded'`.

Zero raw hardware addresses or private IP addresses are exposed to the public dashboard.

