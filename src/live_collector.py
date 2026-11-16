"""
Live Collector — Background Ingestion Daemon
File: src/live_collector.py

Purpose:
  Orchestrates concurrent live packet capture (via TShark) and ESP32 serial
  telemetry ingestion, applies the frozen dual-detector to each completed
  1-second window, and persists all results to data/live_monitoring.db.

Architecture (two threads):
  Thread 1 — Network Thread:
    Runs LiveStreamExtractor to receive packets, compute 1-second features,
    score them with the frozen DualDetectorBundle (trained on Session 1),
    insert scored windows into live_traffic_windows, write alerts for
    anomalous windows, and log unregistered MACs as unknown_device_obs.

  Thread 2 — Serial Thread:
    Opens the ESP32 COM port, reads validated JSON telemetry records, splits
    each combined record into two logical nodes (Node_1 = DHT11, Node_2 = PIR),
    and inserts into live_sensor_telemetry and live_pir_events.

Both threads write to the same data/live_monitoring.db using WAL mode, which
allows concurrent writes without blocking dashboard reads.

Frozen Model Loading:
  The DualDetectorBundle is re-created on each collector start by calling
  train_dual_detector() with the unchanged Session 1 CSV. This is identical
  to how validate_long_baseline_workflow.py re-creates the bundle each run.
  No serialised model file exists (design decision: re-fit from training data
  ensures reproducibility without requiring joblib/pickle artefacts).

Prediction Convention:
  IsolationForest.predict() returns -1 for outliers (anomalies) and +1 for
  inliers (normal windows). This is the sklearn default and is preserved
  verbatim from evaluate_dual_detector() in dual_detector_1s.py.

Safety:
  - Never writes to data/iot_anomaly.db or any production file.
  - Never retrains or alters the frozen detector thresholds.
  - Never automatically disconnects or blocks any device.
  - All anomaly flags are labelled as statistical deviations, NOT attacks.
  - Firmware is not modified.
"""

import argparse
import ipaddress
import json
import math
import queue
import re
import secrets
import sqlite3
import sys
import threading
import time
import datetime
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np
import pandas as pd

# ─────────────────────────────────────────────────────────────────────────────
# Project root sys.path setup — supports both 'python src/live_collector.py'
# and 'python -m src.live_collector' invocation patterns.
# ─────────────────────────────────────────────────────────────────────────────
_HERE = Path(__file__).resolve().parent
_PROJECT_ROOT = _HERE.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

try:
    from dotenv import load_dotenv
    _env_path = _PROJECT_ROOT / ".env"
    if _env_path.exists():
        load_dotenv(dotenv_path=_env_path)
    else:
        load_dotenv()
except ImportError:
    pass

# ─────────────────────────────────────────────────────────────────────────────
# Internal imports — use try/except for src. prefix compatibility
# ─────────────────────────────────────────────────────────────────────────────
try:
    from src.live_interface_resolver import (
        resolve_hotspot_interface,
        list_all_interfaces,
        format_interface_table,
        TSharkNotFoundError,
        NoHotspotInterfaceError,
        AmbiguousHotspotInterfaceError,
        TSHARK_DEFAULT_PATH,
        check_hotspot_channel_alignment,
        query_windows_hotspot_channel,
        ChannelAlignmentStatus,
        ChannelDiagnosticResult,
    )
    from src.live_stream_extractor import (
        LiveStreamExtractor,
        DEFAULT_DEVICE_REGISTRY,
        MIN_PACKETS_FOR_TIMING,
        FEATURE_COLS_PRIMARY,
        FEATURE_COLS_TIMING,
    )
    from src.init_live_database import (
        init_live_database,
        migrate_live_database,
        get_live_db_connection,
        DEFAULT_LIVE_DB_PATH,
        PRODUCTION_DB_PATH,
    )
    from src.dual_detector_1s import (
        train_dual_detector,
        evaluate_dual_detector,
        DualDetectorBundle,
    )
    from src.ingest_serial_sensors import validate_payload
    from src.attack_detector import (
        NetworkAttackDetector,
        WindowTrafficObservation,
        PacketObservation,
        AttackDetectionResult,
        AttackCategory,
        DetectionStatus,
        Severity,
        resolve_gateway_mac,
    )
except ModuleNotFoundError:
    from live_interface_resolver import (
        resolve_hotspot_interface,
        list_all_interfaces,
        format_interface_table,
        TSharkNotFoundError,
        NoHotspotInterfaceError,
        AmbiguousHotspotInterfaceError,
        TSHARK_DEFAULT_PATH,
        check_hotspot_channel_alignment,
        query_windows_hotspot_channel,
        ChannelAlignmentStatus,
        ChannelDiagnosticResult,
    )
    from live_stream_extractor import (
        LiveStreamExtractor,
        DEFAULT_DEVICE_REGISTRY,
        MIN_PACKETS_FOR_TIMING,
        FEATURE_COLS_PRIMARY,
        FEATURE_COLS_TIMING,
    )
    from init_live_database import (
        init_live_database,
        migrate_live_database,
        get_live_db_connection,
        DEFAULT_LIVE_DB_PATH,
        PRODUCTION_DB_PATH,
    )
    from dual_detector_1s import (
        train_dual_detector,
        evaluate_dual_detector,
        DualDetectorBundle,
    )
    from ingest_serial_sensors import validate_payload
    from attack_detector import (
        NetworkAttackDetector,
        WindowTrafficObservation,
        PacketObservation,
        AttackDetectionResult,
        AttackCategory,
        DetectionStatus,
        Severity,
        resolve_gateway_mac,
    )

# ─────────────────────────────────────────────────────────────────────────────
# Default Session 1 training data path (frozen baseline)
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_SESSION1_PATH = (
    _PROJECT_ROOT
    / "data"
    / "processed"
    / "experimental_time_windows"
    / "time_1s_session1_pcap_features_uplink.csv"
)

# Serial defaults
DEFAULT_SERIAL_PORT = "COM6"
DEFAULT_BAUD_RATE = 115200
SERIAL_TIMEOUT = 3.0         # seconds — max wait per readline()
SERIAL_RECONNECT_DELAY = 5.0  # seconds before retrying after disconnect

# Heartbeat interval
HEARTBEAT_INTERVAL_SEC = 10.0

# Maximum consecutive serial errors before giving up
MAX_SERIAL_ERRORS = 20

# ─────────────────────────────────────────────────────────────────────────────
# Wi-Fi sniffer telemetry validation functions (Stage 4.3.1)
# ─────────────────────────────────────────────────────────────────────────────
_MAC_REGEX = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$")


def _is_valid_mac(mac: Any) -> bool:
    """Validates whether mac is a 6-octet colon or hyphen delimited MAC address."""
    if not isinstance(mac, str):
        return False
    return bool(_MAC_REGEX.match(mac.strip()))


def _is_valid_ip(ip: Any) -> bool:
    """Validates whether ip is a valid IPv4 or IPv6 address string."""
    if not isinstance(ip, str) or not ip.strip():
        return False
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except (ValueError, AttributeError):
        return False


def validate_wifi_mgmt_event(payload: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Validates structural integrity, required fields, and ranges of incoming
    'wifi_mgmt' individual deauthentication/disassociation telemetry.
    Note: 'bssid' is optional; when absent, None, or empty string, fallback
    attribution to transmitter MAC (ta) operates downstream.
    """
    if not isinstance(payload, dict):
        return False, "Payload must be a dictionary"

    if payload.get("type") != "wifi_mgmt":
        return False, f"Expected type 'wifi_mgmt', got '{payload.get('type')}'"

    required_keys = ["type", "boot_id", "seq", "uptime_ms", "subtype", "reason", "ta", "da", "rssi"]
    for k in required_keys:
        if k not in payload:
            return False, f"Missing required key: '{k}'"

    # Numeric fields validation (ensure not bool)
    for int_key in ["boot_id", "seq", "uptime_ms", "subtype"]:
        v = payload.get(int_key)
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            return False, f"Field '{int_key}' must be a non-negative integer, got {v}"

    # Subtype: 10 (Disassoc) or 12 (Deauth)
    subtype = payload["subtype"]
    if subtype not in (10, 12):
        return False, f"Invalid management subtype: {subtype} (expected 10 or 12)"

    # Reason code: nullable or integer 1-65535
    reason = payload["reason"]
    if reason is not None:
        if not isinstance(reason, int) or isinstance(reason, bool) or not (1 <= reason <= 65535):
            return False, f"Field 'reason' must be an integer (1-65535) or null, got {reason}"

    # MAC addresses
    ta = payload["ta"]
    if not _is_valid_mac(ta):
        return False, f"Invalid transmitter MAC (ta): '{ta}'"

    da = payload["da"]
    if not _is_valid_mac(da):
        return False, f"Invalid destination MAC (da): '{da}'"

    bssid = payload.get("bssid")
    if bssid is not None and bssid != "" and not _is_valid_mac(bssid):
        return False, f"Invalid BSSID MAC: '{bssid}'"

    # RSSI: integer or float, plausible physical range (-128 to 0 dBm) or None
    rssi = payload["rssi"]
    if rssi is not None:
        if isinstance(rssi, bool) or not isinstance(rssi, (int, float)):
            return False, f"Field 'rssi' must be numeric or null, got {rssi}"
        if not (-128 <= rssi <= 0):
            return False, f"Field 'rssi' out of plausible range (-128 to 0 dBm): {rssi}"

    return True, "OK"


def validate_wifi_mgmt_summary(payload: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Validates structural integrity, required fields, and ranges of incoming
    'wifi_mgmt_summary' periodic telemetry reports.
    """
    if not isinstance(payload, dict):
        return False, "Payload must be a dictionary"

    if payload.get("type") != "wifi_mgmt_summary":
        return False, f"Expected type 'wifi_mgmt_summary', got '{payload.get('type')}'"

    required_keys = ["type", "boot_id", "summary_seq", "uptime_ms", "window_ms", "cumulative"]
    for k in required_keys:
        if k not in payload:
            return False, f"Missing required key: '{k}'"

    for int_key in ["boot_id", "summary_seq", "uptime_ms"]:
        v = payload.get(int_key)
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            return False, f"Field '{int_key}' must be a non-negative integer, got {v}"

    window_ms = payload.get("window_ms")
    if not isinstance(window_ms, (int, float)) or isinstance(window_ms, bool) or window_ms <= 0:
        return False, f"Field 'window_ms' must be a positive number, got {window_ms}"

    cum = payload.get("cumulative")
    if not isinstance(cum, dict):
        return False, f"Field 'cumulative' must be a dictionary, got {type(cum)}"

    required_cum_keys = ["rx_total", "tb_suppressed", "queue_dropped", "enqueued", "uart_accepted", "uart_failed"]
    for ck in required_cum_keys:
        if ck not in cum:
            return False, f"Missing required cumulative counter: '{ck}'"
        val = cum[ck]
        if not isinstance(val, int) or isinstance(val, bool) or val < 0:
            return False, f"Cumulative counter '{ck}' must be a non-negative integer, got {val}"

    return True, "OK"


def validate_sniffer_status(payload: Dict[str, Any], expected_nonce: Optional[int] = None) -> Tuple[bool, str]:
    """
    Validates sniffer probe response handshake status payloads.
    """
    if not isinstance(payload, dict):
        return False, "Payload must be a dictionary"

    if payload.get("status") != "WIFI_SNIFFER_INITIALIZED":
        return False, f"Expected status 'WIFI_SNIFFER_INITIALIZED', got '{payload.get('status')}'"

    for req_key in ["status", "boot_id", "nonce"]:
        if req_key not in payload:
            return False, f"Missing required key: '{req_key}'"

    boot_id = payload.get("boot_id")
    if not isinstance(boot_id, int) or isinstance(boot_id, bool) or boot_id < 0:
        return False, f"Field 'boot_id' must be a non-negative integer, got {boot_id}"

    nonce = payload.get("nonce")
    if not isinstance(nonce, int) or isinstance(nonce, bool) or nonce < 0:
        return False, f"Field 'nonce' must be a non-negative integer, got {nonce}"

    if expected_nonce is not None and nonce != expected_nonce:
        return False, f"Nonce mismatch: expected {expected_nonce}, got {nonce}"

    channel = payload.get("channel")
    if channel is not None:
        if not isinstance(channel, int) or isinstance(channel, bool) or not (1 <= channel <= 14):
            return False, f"Channel out of valid 2.4 GHz range (1-14): {channel}"

    return True, "OK"


def _now_utc_str() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


# ─────────────────────────────────────────────────────────────────────────────
# Frozen model loader
# ─────────────────────────────────────────────────────────────────────────────
def load_frozen_dual_detector(
    session1_csv: Path = DEFAULT_SESSION1_PATH,
    contamination: float = 0.05,
    random_state: int = 42,
) -> DualDetectorBundle:
    """
    Loads the frozen dual-detector by re-fitting on Session 1 data.

    No parameters are changed from those used in all previous sessions.
    This is identical to validate_long_baseline_workflow.py line 305.

    Returns
    -------
    DualDetectorBundle with .clf_primary, .clf_timing, .imputer_timing set.
    """
    if not session1_csv.exists():
        raise FileNotFoundError(
            f"Session 1 training CSV not found: {session1_csv}\n"
            "This file is required to re-create the frozen dual detector."
        )
    df_s1 = pd.read_csv(session1_csv)
    bundle = train_dual_detector(
        df_train_s1=df_s1,
        contamination=contamination,
        random_state=random_state,
    )
    print(
        f"[DETECTOR] Frozen dual detector loaded from: {session1_csv.name}\n"
        f"           Primary offset: {bundle.meta_primary['fitted_offset']:.6f}\n"
        f"           Timing offset:  {bundle.meta_timing['fitted_offset']:.6f}\n"
        f"           Training samples: {bundle.meta_primary['n_train_samples']}"
    )
    return bundle


# ─────────────────────────────────────────────────────────────────────────────
# Single-window scoring (inline — avoids DataFrame overhead for one row)
# ─────────────────────────────────────────────────────────────────────────────
def score_window(
    bundle: DualDetectorBundle,
    window: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Applies the frozen dual detector to a single feature window dict.

    Returns the window dict augmented with:
      score_primary, pred_primary, score_timing, pred_timing,
      timing_status, pred_dual, dual_reason.

    Prediction Convention (sklearn IsolationForest):
      -1 = outlier / anomaly
      +1 = inlier  / normal

    This mirrors evaluate_dual_detector() in dual_detector_1s.py but
    operates on a single dict to avoid creating a DataFrame per packet.
    """
    # Primary detector (always evaluated)
    X_prim = np.array([[
        window["packet_rate"],
        window["mean_packet_size"] if not (isinstance(window["mean_packet_size"], float) and math.isnan(window["mean_packet_size"])) else 0.0,
        window["packet_size_std"] if not (isinstance(window["packet_size_std"], float) and math.isnan(window["packet_size_std"])) else 0.0,
    ]], dtype=float)

    score_primary = float(bundle.clf_primary.decision_function(X_prim)[0])
    pred_primary = int(bundle.clf_primary.predict(X_prim)[0])  # -1 or +1

    # Timing detector (gated: only when packet_count >= MIN_PACKETS_FOR_TIMING)
    n_pkts = window.get("packet_count", 0)
    timing_active = (n_pkts >= bundle.min_packets_timing)

    if timing_active:
        mean_iat = window.get("mean_IAT")
        iat_std = window.get("IAT_std")
        mean_iat_val = mean_iat if (mean_iat is not None and not (isinstance(mean_iat, float) and math.isnan(mean_iat))) else 0.0
        iat_std_val = iat_std if (iat_std is not None and not (isinstance(iat_std, float) and math.isnan(iat_std))) else 0.0

        X_timing_raw = np.array([[mean_iat_val, iat_std_val]], dtype=float)
        X_timing_imp = bundle.imputer_timing.transform(X_timing_raw)
        score_timing = float(bundle.clf_timing.decision_function(X_timing_imp)[0])
        pred_timing = int(bundle.clf_timing.predict(X_timing_imp)[0])
        timing_status = "ACTIVE"
    else:
        score_timing = float("nan")
        pred_timing = 1  # default inlier (no false alarm for quiet windows)
        timing_status = "UNAVAILABLE_N_LT_3"

    # Combined decision rule (mirrors evaluate_dual_detector exactly)
    prim_flag = (pred_primary == -1)
    timing_flag = timing_active and (pred_timing == -1)

    if prim_flag and timing_flag:
        pred_dual = -1
        dual_reason = "ANOMALY_PRIMARY_AND_TIMING"
    elif prim_flag:
        pred_dual = -1
        dual_reason = "ANOMALY_PRIMARY_BURST_OR_SIZE"
    elif timing_flag:
        pred_dual = -1
        dual_reason = "ANOMALY_TIMING_JITTER"
    else:
        pred_dual = 1
        dual_reason = "NORMAL_QUIET_TIMING_UNAVAILABLE" if not timing_active else "NORMAL_INLIER"

    return {
        **window,
        "score_primary": score_primary,
        "pred_primary": pred_primary,
        "score_timing": None if math.isnan(score_timing) else score_timing,
        "pred_timing": pred_timing,
        "timing_status": timing_status,
        "pred_dual": pred_dual,
        "dual_reason": dual_reason,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Database write helpers
# ─────────────────────────────────────────────────────────────────────────────
def is_transient_db_lock_error(exc: BaseException) -> bool:
    """
    Returns True only if exc is a transient sqlite3.OperationalError indicating
    a database locked or busy condition. Never matches schema, constraint, or syntax errors.
    """
    if isinstance(exc, sqlite3.OperationalError):
        msg = str(exc).lower()
        return ("locked" in msg) or ("busy" in msg)
    return False


def _insert_traffic_window(
    conn: sqlite3.Connection,
    run_id: int,
    scored: Dict[str, Any],
    commit: bool = True,
) -> int:
    """Inserts a scored window into live_traffic_windows. Returns rowid."""
    cur = conn.execute(
        """
        INSERT INTO live_traffic_windows (
            run_id, client_mac, node_id, node_type, data_label,
            bin_start_epoch, bin_end_epoch, window_center_epoch,
            window_start_utc, window_end_utc,
            packet_count, mean_IAT, IAT_std, packet_rate,
            mean_packet_size, packet_size_std,
            score_primary, pred_primary,
            score_timing, pred_timing, timing_status,
            pred_dual, dual_reason
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            run_id,
            scored.get("client_mac", ""),
            scored.get("node_id", ""),
            scored.get("Node_Type", ""),
            scored.get("Data_Label", ""),
            scored.get("bin_start_timestamp"),
            scored.get("bin_end_timestamp"),
            scored.get("window_center_epoch"),
            scored.get("Window_Start_UTC"),
            scored.get("Window_End_UTC"),
            scored.get("packet_count", 0),
            _nan_to_none(scored.get("mean_IAT")),
            _nan_to_none(scored.get("IAT_std")),
            scored.get("packet_rate", 0.0),
            _nan_to_none(scored.get("mean_packet_size")),
            _nan_to_none(scored.get("packet_size_std")),
            _nan_to_none(scored.get("score_primary")),
            scored.get("pred_primary"),
            _nan_to_none(scored.get("score_timing")),
            scored.get("pred_timing"),
            scored.get("timing_status"),
            scored.get("pred_dual"),
            scored.get("dual_reason"),
        ),
    )
    window_rowid = cur.lastrowid
    try:
        from src.cloud_sync_outbox import queue_traffic_window
        queue_traffic_window(conn, run_id, window_rowid, scored, commit=False)
    except Exception:
        pass
    if commit:
        conn.commit()
    return window_rowid


def _insert_alert(
    conn: sqlite3.Connection,
    run_id: int,
    window_id: int,
    scored: Dict[str, Any],
    commit: bool = True,
) -> None:
    """Inserts an anomaly alert row for a flagged window."""
    cur = conn.execute(
        """
        INSERT INTO live_alerts (
            window_id, run_id, client_mac, node_id,
            bin_start_epoch, window_start_utc,
            dual_reason, score_primary, score_timing,
            packet_rate, mean_packet_size, packet_count
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            window_id,
            run_id,
            scored.get("client_mac", ""),
            scored.get("node_id", ""),
            scored.get("bin_start_timestamp"),
            scored.get("Window_Start_UTC"),
            scored.get("dual_reason"),
            _nan_to_none(scored.get("score_primary")),
            _nan_to_none(scored.get("score_timing")),
            scored.get("packet_rate"),
            _nan_to_none(scored.get("mean_packet_size")),
            scored.get("packet_count"),
        ),
    )
    alert_rowid = cur.lastrowid
    try:
        from src.cloud_sync_outbox import queue_live_alert
        queue_live_alert(conn, run_id, alert_rowid, scored, commit=False)
    except Exception:
        pass
    if commit:
        conn.commit()


def _insert_attack_event(
    conn: sqlite3.Connection,
    run_id: int,
    window_id: Optional[int],
    result: AttackDetectionResult,
    source_mac: Optional[str] = None,
    target_ip: Optional[str] = None,
    commit: bool = True,
) -> int:
    """Inserts a structured attack detection evaluation row into live_attack_events."""
    evidence_json = json.dumps(result.evidence)
    missing_json = json.dumps(result.missing_fields) if result.missing_fields else None
    dt_utc = datetime.datetime.fromtimestamp(
        result.timestamp, tz=datetime.timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S")

    cur = conn.execute(
        """
        INSERT INTO live_attack_events (
            run_id, window_id, timestamp_epoch, timestamp_utc,
            category, status, severity, confidence,
            source_mac, target_ip, evidence_json, missing_fields_json,
            recommended_action
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            window_id,
            result.timestamp,
            dt_utc,
            result.category.value if hasattr(result.category, "value") else str(result.category),
            result.status.value if hasattr(result.status, "value") else str(result.status),
            result.severity.value if hasattr(result.severity, "value") else str(result.severity),
            float(result.confidence),
            source_mac,
            target_ip,
            evidence_json,
            missing_json,
            result.recommended_action,
        ),
    )
    attack_rowid = cur.lastrowid
    try:
        from src.cloud_sync_outbox import generate_event_uuid, queue_attack_event
        event_uuid = getattr(result, "event_uuid", None) or generate_event_uuid(
            "live_attack_events", f"{run_id}_{attack_rowid}_{result.timestamp}_{result.category}"
        )
        data = {
            "window_id": window_id,
            "timestamp_epoch": result.timestamp,
            "timestamp_utc": dt_utc,
            "category": result.category.value if hasattr(result.category, "value") else str(result.category),
            "status": result.status.value if hasattr(result.status, "value") else str(result.status),
            "severity": result.severity.value if hasattr(result.severity, "value") else str(result.severity),
            "confidence": float(result.confidence),
            "source_mac": source_mac,
            "target_ip": target_ip,
            "evidence_json": result.evidence,
            "missing_fields_json": result.missing_fields,
            "recommended_action": result.recommended_action,
            "acknowledged": 0,
        }
        queue_attack_event(conn, run_id, event_uuid, data, commit=False)
    except Exception:
        pass
    if commit:
        conn.commit()
    return attack_rowid


def _upsert_unknown_device(
    conn: sqlite3.Connection,
    run_id: int,
    mac: str,
    commit: bool = True,
) -> None:
    """Inserts or increments the unknown-device observation counter."""
    conn.execute(
        """
        INSERT INTO unknown_device_obs (run_id, observed_mac)
        VALUES (?, ?)
        ON CONFLICT(run_id, observed_mac) DO UPDATE
            SET observation_count = observation_count + 1,
                last_seen_utc = CURRENT_TIMESTAMP
        """,
        (run_id, mac),
    )
    try:
        from src.cloud_sync_outbox import queue_unknown_device
        queue_unknown_device(conn, run_id, {"observed_mac": mac}, commit=False)
    except Exception:
        pass
    if commit:
        conn.commit()


def _insert_sensor_telemetry(
    conn: sqlite3.Connection,
    run_id: int,
    payload: Dict[str, Any],
    sensor_epoch: float,
    commit: bool = True,
) -> None:
    """Splits ESP32 JSON payload into Node_1 (DHT11) and Node_2 (PIR) rows."""
    seq = int(payload["seq"])
    uptime_ms = int(payload["uptime_ms"])
    physical_id = str(payload.get("node", "esp32_gateway"))

    dht = payload.get("dht11", {})
    dht_valid = int(dht.get("valid", 0))
    temp_c = float(dht["temp_c"]) if dht_valid == 1 and dht.get("temp_c") is not None else None
    hum_pct = float(dht["humidity"]) if dht_valid == 1 and dht.get("humidity") is not None else None

    pir = payload.get("pir", {})
    motion_detected = int(pir.get("motion", 0))

    # Derive captured_at: use provided captured_at, or convert sensor_epoch to UTC ISO, or current UTC
    captured_at = payload.get("captured_at")
    if not captured_at:
        if sensor_epoch is not None and isinstance(sensor_epoch, (int, float)) and sensor_epoch > 0:
            captured_at = datetime.datetime.fromtimestamp(sensor_epoch, tz=datetime.timezone.utc).isoformat()
        else:
            captured_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Node_1 → DHT11
    try:
        conn.execute(
            """
            INSERT OR IGNORE INTO live_sensor_telemetry
                (run_id, physical_node_id, logical_node_id,
                 sequence_num, uptime_ms,
                 temperature_c, humidity_pct, dht_valid, captured_at, sensor_epoch)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            (run_id, physical_id, "Node_1", seq, uptime_ms,
             temp_c, hum_pct, dht_valid, captured_at, sensor_epoch),
        )
    except sqlite3.IntegrityError:
        pass  # Duplicate sequence — safely ignored

    # Node_2 → PIR
    try:
        conn.execute(
            """
            INSERT OR IGNORE INTO live_pir_events
                (run_id, physical_node_id, logical_node_id,
                 sequence_num, uptime_ms, motion_detected, captured_at, sensor_epoch)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (run_id, physical_id, "Node_2", seq, uptime_ms,
             motion_detected, captured_at, sensor_epoch),
        )
    except sqlite3.IntegrityError:
        pass  # Duplicate sequence — safely ignored

    try:
        from src.cloud_sync_outbox import queue_sensor_telemetry, queue_pir_event
        queue_sensor_telemetry(conn, run_id, seq, {
            "physical_node_id": physical_id,
            "logical_node_id": "Node_1",
            "uptime_ms": uptime_ms,
            "temperature_c": temp_c,
            "humidity_pct": hum_pct,
            "dht_valid": dht_valid,
            "captured_at": captured_at,
            "sensor_epoch": sensor_epoch,
        }, commit=False)
        queue_pir_event(conn, run_id, seq, {
            "physical_node_id": physical_id,
            "logical_node_id": "Node_2",
            "uptime_ms": uptime_ms,
            "motion_detected": motion_detected,
            "captured_at": captured_at,
            "sensor_epoch": sensor_epoch,
        }, commit=False)
    except Exception:
        pass

    if commit:
        conn.commit()


def _nan_to_none(v: Any) -> Any:
    """Converts float NaN to None for SQLite NULL storage."""
    if isinstance(v, float) and math.isnan(v):
        return None
    return v


# ─────────────────────────────────────────────────────────────────────────────
# LiveCollector
# ─────────────────────────────────────────────────────────────────────────────
class LiveCollector:
    """
    Orchestrates the live dual-thread ingestion pipeline.

    Usage
    -----
    collector = LiveCollector(
        interface_index=1,
        serial_port="COM6",
        db_path=Path("data/live_monitoring.db"),
        session1_csv=Path("data/processed/.../time_1s_session1_pcap_features_uplink.csv"),
    )
    collector.start()
    # ... runs until collector.stop() is called or KeyboardInterrupt

    Attributes (read-only status)
    ----------------------------
    stats : dict — running totals for packets, windows, sensor records.
    """

    def __init__(
        self,
        interface_index: int,
        serial_port: str = DEFAULT_SERIAL_PORT,
        db_path: Path = DEFAULT_LIVE_DB_PATH,
        session1_csv: Path = DEFAULT_SESSION1_PATH,
        device_registry: Optional[Dict[str, Dict[str, str]]] = None,
        no_sensors: bool = False,
        tshark_path: str = TSHARK_DEFAULT_PATH,
        tshark_extra_args: Optional[list] = None,
        gateway_mac: Optional[str] = None,
        port_scan_cooldown_seconds: float = 10.0,
        dos_cooldown_seconds: float = 60.0,
        dos_rate_threshold: float = 60.0,
        spoofing_cooldown_seconds: float = 60.0,
        deauth_cooldown_seconds: float = 60.0,
        enable_cloud_sync: bool = False,
        sync_worker: Optional[Any] = None,
    ) -> None:
        self.interface_index = interface_index
        self.serial_port = serial_port
        self.db_path = Path(db_path)
        self.session1_csv = Path(session1_csv)
        self.device_registry = device_registry or dict(DEFAULT_DEVICE_REGISTRY)
        self.no_sensors = no_sensors
        self.tshark_path = tshark_path
        self.tshark_extra_args = tshark_extra_args or []
        raw_gw = gateway_mac if gateway_mac else resolve_gateway_mac("192.168.137.1")
        self.gateway_mac = raw_gw.strip().lower().replace("-", ":") if raw_gw else None
        self.port_scan_cooldown_seconds = float(port_scan_cooldown_seconds)
        self.dos_cooldown_seconds = float(dos_cooldown_seconds)
        self.dos_rate_threshold = float(dos_rate_threshold)
        self.spoofing_cooldown_seconds = float(spoofing_cooldown_seconds)
        self.deauth_cooldown_seconds = float(deauth_cooldown_seconds)
        self.enable_cloud_sync = bool(enable_cloud_sync)
        self._sync_worker = sync_worker
        if self.enable_cloud_sync and self._sync_worker is None:
            try:
                from src.cloud_sync_worker import CloudSyncWorker
                self._sync_worker = CloudSyncWorker(db_path=self.db_path)
            except Exception as e:
                logger.warning(f"Could not initialize CloudSyncWorker: {e}")
                self._sync_worker = None

        self._stop_event = threading.Event()
        self._net_thread: Optional[threading.Thread] = None
        self._serial_thread: Optional[threading.Thread] = None
        self._run_id: Optional[int] = None
        self._attack_table_present: bool = False

        # Worker supervision and status tracking (Stage 6.5.1)
        self._status: str = "STARTING"
        self._stop_reason: Optional[str] = None
        self._status_lock = threading.Lock()
        self._net_worker_failed: bool = False
        self._serial_worker_failed: bool = False
        self._net_failure_reason: Optional[str] = None
        self._serial_failure_reason: Optional[str] = None

        # Dynamic device registry refresh (Stage 6.5.2)
        self._registry_lock = threading.Lock()
        self.registry_refresh_interval_seconds: float = 30.0
        self._last_registry_refresh_mono: float = 0.0
        self._extractor: Optional[Any] = None
        self._has_loaded_from_db_rows: bool = False

        # Serial reconnection and backoff configuration (Stage 6.5.3)
        self.serial_backoff_initial_sec: float = 2.0
        self.serial_backoff_factor: float = 2.0
        self.serial_backoff_max_sec: float = 30.0
        self._serial_connected: bool = False
        self._serial_reconnecting: bool = False
        self._current_serial_backoff: float = 2.0

        # Database bounded retry configuration (Stage 6.5.4)
        self.db_max_retries: int = 2
        self.db_retry_initial_delay_sec: float = 0.05
        self.db_retry_backoff_factor: float = 2.0
        self.db_busy_timeout_ms: int = 250

        # In-memory deduplication caches: fingerprint -> last_emitted_monotonic_time
        self._port_scan_dedup_cache: Dict[Tuple[Any, ...], float] = {}
        self._dos_dedup_cache: Dict[Tuple[Any, ...], float] = {}
        self._spoofing_dedup_cache: Dict[Tuple[Any, ...], float] = {}
        self._deauth_dedup_cache: Dict[Tuple[Any, ...], float] = {}
        self._dedup_lock = threading.Lock()

        # In-memory fleet-window aggregation cache for live fleet surge evaluation
        self._recent_fleet_windows: Dict[str, WindowTrafficObservation] = {}

        # Stage 4.3.1: Wi-Fi management frame inter-thread queue and session tracking
        self._wifi_mgmt_queue: queue.Queue = queue.Queue(maxsize=256)
        self.active_boot_id: Optional[int] = None
        self._expected_probe_nonce: Optional[int] = None
        self._session_established: bool = False
        self._session_lock = threading.Lock()
        self._seen_mgmt_sequences: Set[int] = set()

        # Wi-Fi management summary tracking
        self._last_summary_snapshot: Optional[Dict[str, Any]] = None
        self._summary_lock = threading.Lock()

        self.attack_detector = NetworkAttackDetector(
            dos_rate_threshold=self.dos_rate_threshold,
            gateway_ip="192.168.137.1",
            gateway_mac=self.gateway_mac,
        )

        self.stats: Dict[str, int] = {
            "packets_parsed": 0,
            "windows_emitted": 0,
            "alerts_generated": 0,
            "sensor_records": 0,
            "unknown_devices_seen": 0,
            "attack_evaluations": 0,
            "attack_events_flagged": 0,
            "attack_events_cooldown_suppressed": 0,
            # Extended Wi-Fi sniffer and serial routing stats (Stage 4.3.1)
            "wifi_mgmt_events_parsed": 0,
            "wifi_mgmt_events_pushed": 0,
            "wifi_mgmt_queue_dropped": 0,
            "wifi_mgmt_malformed": 0,
            "wifi_mgmt_summaries_parsed": 0,
            "wifi_mgmt_duplicate_events": 0,
            "wifi_mgmt_stale_events": 0,
            "sniffer_probe_requests_sent": 0,
            "sniffer_status_responses_received": 0,
            "sniffer_stale_probe_responses_dropped": 0,
            "sniffer_nonce_mismatches": 0,
            "serial_raw_lines": 0,
            "sensor_payloads_invalid": 0,
            # Wi-Fi management frame queue drain and mapping stats (Stage 4.3.2)
            "wifi_mgmt_events_drained": 0,
            "wifi_mgmt_deauth_events_mapped": 0,
            "wifi_mgmt_disassoc_events_mapped": 0,
            "wifi_mgmt_dropped_unsupported_subtype": 0,
            "wifi_mgmt_exceptions": 0,
            # Database reliability and write recovery stats (Stage 6.5.4)
            "db_transient_write_retries": 0,
            "db_window_write_failures": 0,
            "db_sensor_write_failures": 0,
        }
        self._bundle: Optional[DualDetectorBundle] = None
        self._db_conn: Optional[sqlite3.Connection] = None
        # ESP32 hardware channel and Windows hotspot channel alignment diagnostic (Stage 8.4)
        self._esp32_hardware_channel: Optional[int] = None
        self._cached_hotspot_channel: Optional[int] = None
        self._cached_hotspot_interface_name: Optional[str] = None
        self._channel_diagnostic: Optional[ChannelDiagnosticResult] = None

    # ─── Public API ───────────────────────────────────────────────────────────

    def start(self, interface_name: str = "") -> None:
        """
        Loads the frozen detector, opens the database, and starts both threads.
        Blocks until both threads have started.
        """
        # 1. Load frozen detector
        self._bundle = load_frozen_dual_detector(self.session1_csv)

        # 2. Check database existence (strictly explicit migration via --migrate-db)
        if not self.db_path.exists():
            init_live_database(self.db_path)

        # Verify whether migration has been applied (live_attack_events exists)
        self._attack_table_present = False
        if self.db_path.exists():
            db_chk = get_live_db_connection(self.db_path)
            try:
                cur = db_chk.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='live_attack_events'"
                )
                self._attack_table_present = cur.fetchone() is not None
            finally:
                db_chk.close()

        if not self._attack_table_present:
            print(
                "[COLLECTOR][WARN] Database exists but 'live_attack_events' table is absent.\n"
                "                   Automatic migration is disabled for safety.\n"
                "                   To enable attack event recording, run explicitly:\n"
                "                     python src/live_collector.py --migrate-db"
            )

        # 2b. Sync persisted device_registry from SQLite into collector registry (Stage 6.5.2)
        self.refresh_device_registry(force=True)

        # 3. Create a collector run record
        db = get_live_db_connection(self.db_path)
        try:
            cur = db.execute(
                """
                INSERT INTO collector_status
                    (interface_index, interface_name, serial_port, status)
                VALUES (?, ?, ?, 'STARTING')
                """,
                (self.interface_index, interface_name, self.serial_port),
            )
            db.commit()
            self._run_id = cur.lastrowid
            try:
                from src.cloud_sync_outbox import queue_collector_status
                queue_collector_status(db, self._run_id, {
                    "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "interface_name": interface_name,
                    "serial_port": self.serial_port,
                    "status": "STARTING",
                }, operation="INSERT")
            except Exception:
                pass
            with self._status_lock:
                self._status = "STARTING"
                self._stop_reason = None
                self._net_worker_failed = False
                self._serial_worker_failed = False
                self._net_failure_reason = None
                self._serial_failure_reason = None
                self._serial_connected = False
                self._serial_reconnecting = False
                self._current_serial_backoff = self.serial_backoff_initial_sec
            with self._dedup_lock:
                self._port_scan_dedup_cache.clear()
                self._dos_dedup_cache.clear()
                self._spoofing_dedup_cache.clear()
                self._deauth_dedup_cache.clear()
                self._recent_fleet_windows.clear()
        finally:
            db.close()

        # 3b. Seed baseline telemetry status for this run into live_attack_events (if table exists)
        if self._attack_table_present:
            try:
                db_caps = get_live_db_connection(self.db_path)
                try:
                    now_epoch = time.time()
                    for cat_key, cap_info in NetworkAttackDetector.get_capabilities().items():
                        if cat_key == "RSSI_MONITORING":
                            continue
                        cat_val = cap_info.get("category", cat_key)
                        stat_val = cap_info.get("status_on_current_stream", "INSUFFICIENT_TELEMETRY")
                        det_status = (
                            DetectionStatus.NO_EVIDENCE if stat_val == "OPERATIONAL"
                            else DetectionStatus.INSUFFICIENT_TELEMETRY
                        )
                        evidence = {
                            "initial_capability": stat_val,
                            "required_telemetry": cap_info.get("required_telemetry", []),
                            "limitations_or_remedy": cap_info.get("limitations") or cap_info.get("remedy", ""),
                        }
                        missing = cap_info.get("required_telemetry") if stat_val != "OPERATIONAL" else []
                        res_baseline = AttackDetectionResult(
                            category=AttackCategory(cat_val),
                            status=det_status,
                            severity=Severity.NONE,
                            evidence=evidence,
                            missing_fields=missing,
                            confidence=0.0,
                            timestamp=now_epoch,
                            recommended_action="Normal monitoring." if stat_val == "OPERATIONAL" else "Telemetry enhancement required for full detection.",
                        )
                        _insert_attack_event(db_caps, self._run_id, None, res_baseline)
                finally:
                    db_caps.close()
            except Exception as e:
                print(f"[COLLECTOR][WARN] Could not seed baseline attack status: {e}")

        print(
            f"[COLLECTOR] Starting run_id={self._run_id} | "
            f"Interface={self.interface_index} | "
            f"Serial={'disabled' if self.no_sensors else self.serial_port}"
        )
        if self.gateway_mac:
            print(f"[COLLECTOR] Hotspot Gateway MAC verified: {self.gateway_mac}")
        else:
            print("[COLLECTOR][WARN] Hotspot Gateway MAC unverified; gateway traffic will report INSUFFICIENT_TELEMETRY.")

        # 3c. Execute Windows Mobile Hotspot / ESP32 Channel Alignment Diagnostic (Stage 8.4)
        self._run_channel_diagnostic(interface_name=interface_name)

        # 4. Launch threads
        self._stop_event.clear()

        self._net_thread = threading.Thread(
            target=self._network_loop,
            name="LiveCollector-Network",
            daemon=True,
        )
        self._net_thread.start()

        if not self.no_sensors:
            self._serial_thread = threading.Thread(
                target=self._serial_loop,
                name="LiveCollector-Serial",
                daemon=True,
            )
            self._serial_thread.start()

        # Start optional cloud sync background worker
        if self._sync_worker:
            try:
                self._sync_worker.start()
                print("[COLLECTOR] CloudSyncWorker background daemon started.")
            except Exception as e:
                print(f"[COLLECTOR][WARN] Failed to start CloudSyncWorker: {e}")

        # Mark as RUNNING
        self._update_status("RUNNING")
        print("[COLLECTOR] Both threads started. Press Ctrl+C to stop.")

    def stop(self, reason: str = "User requested stop") -> None:
        """Signals both threads to stop and waits for clean shutdown."""
        print(f"\n[COLLECTOR] Stopping: {reason}")
        self._stop_event.set()
        with self._status_lock:
            self._status = "STOPPED"
            self._stop_reason = reason
            self._serial_connected = False
            self._serial_reconnecting = False

        if self._net_thread and self._net_thread.is_alive():
            self._net_thread.join(timeout=10)

        if self._serial_thread and self._serial_thread.is_alive():
            self._serial_thread.join(timeout=5)

        if self._sync_worker:
            try:
                self._sync_worker.stop(timeout_sec=5.0)
                print("[COLLECTOR] CloudSyncWorker stopped.")
            except Exception as e:
                print(f"[COLLECTOR][WARN] Error stopping CloudSyncWorker: {e}")

        self._update_status("STOPPED", stop_reason=reason)
        self._print_final_stats()

    def run_until_stopped(self) -> None:
        """
        Blocks the calling thread until stop() is called or KeyboardInterrupt.
        Use this in the main thread to keep the process alive.
        """
        try:
            while not self._stop_event.is_set():
                self._heartbeat()
                time.sleep(HEARTBEAT_INTERVAL_SEC)
        except KeyboardInterrupt:
            self.stop("Keyboard interrupt (Ctrl+C)")

    # ─── Internal: Status helpers ─────────────────────────────────────────────

    def _persist_status_locked(self, status: str, stop_reason: Optional[str] = None) -> None:
        """Writes current status and statistics to collector_status in SQLite. Must be called with _status_lock held."""
        if self._run_id is None:
            return
        try:
            db = get_live_db_connection(self.db_path)
            try:
                db.execute(
                    """
                    UPDATE collector_status
                    SET status=?, stop_reason=?,
                        packets_parsed=?, windows_emitted=?, sensor_records=?,
                        last_heartbeat=CURRENT_TIMESTAMP
                    WHERE run_id=?
                    """,
                    (
                        status,
                        stop_reason,
                        self.stats["packets_parsed"],
                        self.stats["windows_emitted"],
                        self.stats["sensor_records"],
                        self._run_id,
                    ),
                )
                db.commit()
            finally:
                db.close()
        except Exception:
            pass  # Never let DB errors crash the collector

    def _update_status(self, status: str, stop_reason: Optional[str] = None) -> None:
        """
        Thread-safely updates collector status, protecting against invalid transitions
        (e.g., overwriting established ERROR or STOPPED state with RUNNING).
        """
        with self._status_lock:
            if self._status == "ERROR" and status == "RUNNING":
                return
            if self._status == "STOPPED" and status == "RUNNING":
                return

            self._status = status
            self._stop_reason = stop_reason
            self._persist_status_locked(status, stop_reason)

    def _heartbeat(self) -> None:
        """
        Inspects worker health and updates collector_status.
        Enforces:
          - Never overwrites an established ERROR or STOPPED state with RUNNING.
          - Detects silent network worker failure (e.g. TShark EOF / crash) and transitions to ERROR.
          - Detects serial worker failure and accurately reflects it in stop_reason.
          - Only reports RUNNING when required worker health conditions are satisfied.
        """
        with self._status_lock:
            # 1. Protection: If shutdown was requested or already STOPPED, preserve STOPPED
            if self._stop_event.is_set() or self._status == "STOPPED":
                if self._status != "STOPPED":
                    self._status = "STOPPED"
                    self._persist_status_locked("STOPPED", self._stop_reason or "Shutdown requested")
                return

            # 2. Protection: If already in ERROR state, preserve ERROR and refresh timestamp/stats
            if self._status == "ERROR" or self._net_worker_failed:
                self._status = "ERROR"
                err_reason = self._net_failure_reason or self._stop_reason or "Critical worker failure"
                self._stop_reason = err_reason
                self._persist_status_locked("ERROR", err_reason)
                return

            # 3. Supervise Network Worker Liveness
            # Network worker is critical: if it was started and is now dead, transition to ERROR
            if self._net_thread is not None and not self._net_thread.is_alive():
                err_reason = self._net_failure_reason or "Network worker thread terminated unexpectedly"
                self._net_worker_failed = True
                self._net_failure_reason = err_reason
                self._status = "ERROR"
                self._stop_reason = err_reason
                self._persist_status_locked("ERROR", err_reason)
                return

            # 4. Supervise Serial Worker Liveness (when sensors are enabled)
            if not self.no_sensors:
                if self._serial_thread is not None and not self._serial_thread.is_alive():
                    self._serial_worker_failed = True
                    self._serial_reconnecting = False
                    if not self._serial_failure_reason:
                        self._serial_failure_reason = "Serial worker thread terminated unexpectedly"

            # 5. Both required health checks passed -> Report RUNNING
            # Accurately reflect serial worker status in stop_reason if it failed or is reconnecting
            effective_stop_reason = (
                self._serial_failure_reason
                if (self._serial_worker_failed or getattr(self, "_serial_reconnecting", False))
                else None
            )
            self._status = "RUNNING"
            self._stop_reason = effective_stop_reason
            self._persist_status_locked("RUNNING", effective_stop_reason)

        # 6. Periodic device registry refresh (Stage 6.5.2)
        # Executed outside _status_lock to prevent lock nesting with DB I/O
        self.refresh_device_registry(force=False)

    def refresh_device_registry(self, force: bool = False) -> bool:
        """
        Reloads registered devices from SQLite device_registry table periodically (approx every 30s)
        or when forced. Atomically synchronizes LiveStreamExtractor and AttackDetector.
        Thread-safe; keeps previous registry on DB failure.

        Returns
        -------
        bool
            True if registry was successfully updated or changed, False if skipped or unchanged.
        """
        now = time.monotonic()
        if not force and (now - self._last_registry_refresh_mono < self.registry_refresh_interval_seconds):
            return False

        with self._registry_lock:
            # Re-check interval under lock in case another thread already refreshed
            if not force and (time.monotonic() - self._last_registry_refresh_mono < self.registry_refresh_interval_seconds):
                return False

            try:
                db = get_live_db_connection(self.db_path)
                try:
                    rows = db.execute(
                        "SELECT mac_address, node_id, device_type, label FROM device_registry ORDER BY mac_address"
                    ).fetchall()
                finally:
                    db.close()
            except Exception as e:
                print(f"[COLLECTOR][WARN] Failed to read device_registry from database: {e}")
                self._last_registry_refresh_mono = time.monotonic()
                return False

            # If the database table has never had devices registered, and collector was initialized
            # with custom/default in-memory devices, don't wipe them on startup unseeded DBs
            if len(rows) == 0 and not getattr(self, "_has_loaded_from_db_rows", False) and self.device_registry:
                self._last_registry_refresh_mono = time.monotonic()
                return False

            self._has_loaded_from_db_rows = True

            new_registry: Dict[str, Dict[str, str]] = {}
            for row in rows:
                raw_mac = row["mac_address"]
                if not raw_mac:
                    continue
                mac = raw_mac.replace("-", ":").lower().strip()
                node_id = row["node_id"]
                if not node_id:
                    continue
                new_registry[mac] = {
                    "node_id": str(node_id).strip(),
                    "device_type": str(row["device_type"] or "Phone_Client").strip(),
                    "label": str(row["label"] or "real_observed_traffic").strip(),
                }

            # Check if contents changed
            if not force and new_registry == self.device_registry:
                self._last_registry_refresh_mono = time.monotonic()
                return False

            old_count = len(self.device_registry)
            self.device_registry = new_registry
            self._last_registry_refresh_mono = time.monotonic()

            # Synchronize extractor if running
            if self._extractor is not None:
                self._extractor.update_device_registry(new_registry)

            # Synchronize attack detector
            self.attack_detector.set_known_devices(set(new_registry.keys()))

            print(
                f"[COLLECTOR] Device registry refreshed: {len(new_registry)} devices "
                f"(was {old_count})"
            )
            return True

    def get_worker_health(self) -> Dict[str, Any]:
        """
        Returns a snapshot of worker thread health and collector status.
        Thread-safe.
        """
        with self._status_lock:
            net_alive = self._net_thread is not None and self._net_thread.is_alive()
            serial_alive = (
                self._serial_thread is not None and self._serial_thread.is_alive()
                if not self.no_sensors else True
            )
            return {
                "status": self._status,
                "stop_reason": self._stop_reason,
                "net_worker_alive": net_alive,
                "serial_worker_alive": serial_alive,
                "serial_connected": getattr(self, "_serial_connected", False),
                "serial_reconnecting": getattr(self, "_serial_reconnecting", False),
                "current_serial_backoff": getattr(self, "_current_serial_backoff", 0.0),
                "net_worker_failed": self._net_worker_failed,
                "serial_worker_failed": self._serial_worker_failed,
                "net_failure_reason": self._net_failure_reason,
                "serial_failure_reason": self._serial_failure_reason,
                "is_shutdown_requested": self._stop_event.is_set(),
                "channel_diagnostic": (
                    self._channel_diagnostic.to_dict()
                    if getattr(self, "_channel_diagnostic", None) is not None
                    else None
                ),
            }

    def _save_diagnostic_to_disk(self) -> None:
        """Persists the latest channel alignment diagnostic to a sidecar JSON file."""
        if self._channel_diagnostic is None:
            return
        try:
            diag_path = self.db_path.parent / f"{self.db_path.stem}_diagnostic.json"
            with open(diag_path, "w", encoding="utf-8") as f:
                json.dump(self._channel_diagnostic.to_dict(), f, indent=2)
        except Exception as exc:
            print(f"[COLLECTOR][WARN] Failed to cache channel diagnostic to disk: {exc}")

    def _run_channel_diagnostic(self, interface_name: str = "") -> None:
        """
        Executes the Windows Mobile Hotspot channel query once at startup.
        Never blocks startup or raises unhandled exceptions.
        At startup before handshake, ESP32 channel is strictly unavailable.
        """
        try:
            # Query Windows Mobile Hotspot adapter once at startup
            h_chan, actual_name, err_status, reason = query_windows_hotspot_channel(
                target_interface_name=interface_name or None,
                timeout_sec=2.0,
            )
            self._cached_hotspot_channel = h_chan
            self._cached_hotspot_interface_name = actual_name

            if err_status is not None:
                self._channel_diagnostic = ChannelDiagnosticResult(
                    status=err_status,
                    esp32_channel=None,
                    hotspot_channel=None,
                    interface_name=actual_name,
                    esp32_source="UNAVAILABLE",
                    run_id=self._run_id,
                    timestamp=time.time(),
                    explanation=reason,
                )
            else:
                # Hotspot detected, but ESP32 channel is not yet received from handshake.
                # Strictly return CHANNEL_UNAVAILABLE. Never assume Channel 6!
                self._channel_diagnostic = ChannelDiagnosticResult(
                    status=ChannelAlignmentStatus.CHANNEL_UNAVAILABLE,
                    esp32_channel=None,
                    hotspot_channel=h_chan,
                    interface_name=actual_name,
                    esp32_source="UNAVAILABLE",
                    run_id=self._run_id,
                    timestamp=time.time(),
                    explanation=(
                        f"Windows hotspot '{actual_name}' operates on Channel {h_chan}. "
                        "ESP32 sniffer channel is unverified (awaiting valid WIFI_SNIFFER_INITIALIZED handshake). "
                        "Channel 6 is not assumed."
                    ),
                )
            self._save_diagnostic_to_disk()
            print(f"[COLLECTOR][INFO] Hotspot channel diagnostic: {self._channel_diagnostic.status.value} - {self._channel_diagnostic.explanation}")
        except Exception as exc:
            print(f"[COLLECTOR][WARN] Non-fatal error during channel alignment check: {exc}")
            self._channel_diagnostic = ChannelDiagnosticResult(
                status=ChannelAlignmentStatus.DIAGNOSTIC_ERROR,
                esp32_channel=None,
                hotspot_channel=None,
                interface_name=interface_name or None,
                esp32_source="UNAVAILABLE",
                run_id=self._run_id,
                timestamp=time.time(),
                explanation=f"Channel diagnostic failed at startup: {exc}",
            )
            self._save_diagnostic_to_disk()

    def _update_channel_alignment_with_hardware_channel(self, hw_channel: Optional[int]) -> None:
        """
        Updates the channel diagnostic when an authoritative channel is received from
        the ESP32 hardware handshake. Re-evaluates alignment against the cached hotspot channel
        without executing a new subprocess or blocking serial ingestion.
        """
        now_ts = time.time()
        is_valid = (
            isinstance(hw_channel, int)
            and not isinstance(hw_channel, bool)
            and 1 <= hw_channel <= 14
        )
        if not is_valid:
            self._esp32_hardware_channel = None
            self._channel_diagnostic = ChannelDiagnosticResult(
                status=ChannelAlignmentStatus.CHANNEL_UNAVAILABLE,
                esp32_channel=None,
                hotspot_channel=self._cached_hotspot_channel,
                interface_name=self._cached_hotspot_interface_name,
                esp32_source="UNAVAILABLE",
                run_id=self._run_id,
                timestamp=now_ts,
                explanation=f"ESP32 sniffer handshake missing or invalid channel: {hw_channel}. Alignment unverified.",
            )
            self._save_diagnostic_to_disk()
            print(f"[SERIAL][WARN] ESP32 handshake channel invalid ({hw_channel}); channel alignment unverified.")
            return

        self._esp32_hardware_channel = hw_channel
        h_chan = self._cached_hotspot_channel
        iface_name = self._cached_hotspot_interface_name or "Mobile Hotspot"

        if h_chan is not None:
            if h_chan == hw_channel:
                status = ChannelAlignmentStatus.CHANNEL_ALIGNED
                explanation = (
                    f"Windows hotspot '{iface_name}' is confirmed aligned with "
                    f"ESP32 sniffer hardware on Channel {hw_channel}."
                )
                print(f"[SERIAL][INFO] Channel alignment verified by hardware handshake: Hotspot and ESP32 both on Channel {hw_channel}")
            else:
                status = ChannelAlignmentStatus.CHANNEL_MISMATCH
                explanation = (
                    f"CHANNEL MISMATCH: Windows hotspot '{iface_name}' is on Channel {h_chan}, "
                    f"but ESP32 sniffer hardware is configured for Channel {hw_channel}."
                )
                print(f"[SERIAL][WARN] !!! CHANNEL MISMATCH CONFIRMED BY HARDWARE HANDSHAKE !!! Hotspot Ch {h_chan} != ESP32 Ch {hw_channel}")
        else:
            status = ChannelAlignmentStatus.CHANNEL_UNAVAILABLE
            explanation = (
                f"ESP32 sniffer hardware reported Channel {hw_channel}, but Windows hotspot channel "
                "was unavailable."
            )

        self._channel_diagnostic = ChannelDiagnosticResult(
            status=status,
            esp32_channel=hw_channel,
            hotspot_channel=h_chan,
            interface_name=iface_name,
            esp32_source="FIRMWARE_HANDSHAKE",
            run_id=self._run_id,
            timestamp=now_ts,
            explanation=explanation,
        )
        self._save_diagnostic_to_disk()

    def _print_final_stats(self) -> None:
        print("\n[COLLECTOR] Final statistics:")
        for k, v in self.stats.items():
            print(f"  {k}: {v}")

    @staticmethod
    def _compute_port_scan_fingerprint(
        run_id: Optional[int],
        finding: Dict[str, Any],
        source_mac: Optional[str] = None,
    ) -> Tuple[Any, ...]:
        """
        Computes a normalized, hashable fingerprint tuple for a Port Scan finding.

        Distinguishes:
          - collector run_id (int or None)
          - scanner source IP (normalized string)
          - source MAC when available (normalized lowercase colon-separated hex, or None)
          - scan type & destination scope: (is_vertical, is_horizontal, normalized scope)
          - relevant destination port or ports: sorted tuple of distinct ints
          - target host set: sorted tuple of distinct normalized IP strings
        """
        norm_run = run_id

        # Normalized source IP
        raw_ip = finding.get("src_ip")
        norm_ip = raw_ip.strip().lower() if raw_ip else None

        # Normalized source MAC (from finding or fallback argument)
        raw_mac = finding.get("source_mac") or source_mac
        norm_mac = raw_mac.strip().lower().replace("-", ":") if raw_mac else None

        # Scan type & destination scope
        is_vertical = bool(finding.get("is_vertical_scan", False))
        is_horizontal = bool(finding.get("is_horizontal_sweep", False))
        scope = (finding.get("destination_scope") or "").strip().lower()
        scan_type = (is_vertical, is_horizontal, scope)

        # Relevant destination ports (sorted unique integers)
        raw_ports = finding.get("sample_ports", [])
        try:
            norm_ports = tuple(sorted(set(int(p) for p in raw_ports if p is not None)))
        except (ValueError, TypeError):
            norm_ports = tuple(sorted(set(raw_ports)))

        # Target host set (sorted unique normalized IP strings)
        raw_hosts = finding.get("sample_hosts", [])
        norm_hosts = tuple(sorted(set(str(h).strip().lower() for h in raw_hosts if h)))

        return (norm_run, norm_ip, norm_mac, scan_type, norm_ports, norm_hosts)

    def _cleanup_port_scan_cache(self, now_mono: float) -> None:
        """Prunes expired entries from the in-memory port scan deduplication cache."""
        if len(self._port_scan_dedup_cache) > 100:
            cutoff = now_mono - max(self.port_scan_cooldown_seconds * 2, 60.0)
            expired = [k for k, t in self._port_scan_dedup_cache.items() if t < cutoff]
            for k in expired:
                del self._port_scan_dedup_cache[k]

    def _persist_attack_results(
        self,
        db: sqlite3.Connection,
        window_id: Optional[int],
        dos_results: List[AttackDetectionResult],
        stream_results: List[AttackDetectionResult],
        client_mac: str,
        scored: Dict[str, Any],
        commit: bool = True,
        pending_dedup_actions: Optional[List[Any]] = None,
    ) -> int:
        """
        Safely persists attack evaluation results into live_attack_events with
        strict entity attribution separation and deduplication:
          - DoS events are attributed to the specific feature window's client_mac
            and deduplicated within the configured dos_cooldown_seconds window.
          - Stream-level events (Port Scan, Spoofing, Deauth, Replay) are attributed
            strictly to the offending packet/finding evidence, NEVER falling back
            to an unrelated client_mac or scored['ip_dst'].
          - Multiple independent scanner findings are persisted as separate rows.
          - Port Scan findings are deduplicated during the configured cooldown window
            using a strict normalized fingerprint.
          - Spoofing findings are deduplicated during the configured cooldown window
            using a strict normalized key (run_id, mac, ip, category).
        """
        inserted_count = 0

        # 1. Window-level evaluations (DoS)
        for att_res in dos_results:
            self.stats["attack_evaluations"] += 1
            if att_res.status in (DetectionStatus.SUSPICIOUS, DetectionStatus.CONFIRMED_THREAT):
                dos_target_ip = scored.get("ip_dst")
                # Stage 2: DoS alert cooldown deduplication
                dos_key = (
                    self._run_id,
                    client_mac.lower().strip() if client_mac else "unknown",
                    dos_target_ip.strip().lower() if dos_target_ip else None,
                    AttackCategory.DOS.value,
                )
                now_mono = time.monotonic()
                with self._dedup_lock:
                    last_dos_time = self._dos_dedup_cache.get(dos_key)
                    if self.dos_cooldown_seconds > 0.0 and last_dos_time is not None:
                        if 0.0 <= (now_mono - last_dos_time) < self.dos_cooldown_seconds:
                            self.stats["attack_events_cooldown_suppressed"] += 1
                            continue

                _insert_attack_event(
                    conn=db,
                    run_id=self._run_id,
                    window_id=window_id,
                    result=att_res,
                    source_mac=client_mac,
                    target_ip=dos_target_ip,
                    commit=commit,
                )
                inserted_count += 1

                def apply_dos_dedup(key=dos_key, mono=now_mono):
                    self.stats["attack_events_flagged"] += 1
                    with self._dedup_lock:
                        self._dos_dedup_cache[key] = mono
                        if len(self._dos_dedup_cache) > 100:
                            cutoff_mono = mono - max(self.dos_cooldown_seconds * 2, 120.0)
                            expired_dos = [k for k, t in self._dos_dedup_cache.items() if t < cutoff_mono]
                            for k in expired_dos:
                                del self._dos_dedup_cache[k]

                if pending_dedup_actions is not None:
                    pending_dedup_actions.append(apply_dos_dedup)
                else:
                    apply_dos_dedup()

        # 2. Stream-level evaluations (Port Scan, Spoofing, Deauth, Replay)
        for att_res in stream_results:
            self.stats["attack_evaluations"] += 1
            if att_res.status in (DetectionStatus.SUSPICIOUS, DetectionStatus.CONFIRMED_THREAT):
                if att_res.category == AttackCategory.PORT_SCAN and att_res.evidence.get("details"):
                    for finding in att_res.evidence["details"]:
                        finding_src_mac = finding.get("source_mac") or None
                        sample_hosts = finding.get("sample_hosts", [])
                        finding_target_ip = sample_hosts[0] if sample_hosts else None

                        # Stage 1.2: Port scan finding fingerprint & cooldown deduplication
                        fp = self._compute_port_scan_fingerprint(
                            run_id=self._run_id,
                            finding=finding,
                            source_mac=finding_src_mac,
                        )
                        now_mono = time.monotonic()
                        with self._dedup_lock:
                            last_time = self._port_scan_dedup_cache.get(fp)
                            if self.port_scan_cooldown_seconds > 0.0 and last_time is not None:
                                if 0.0 <= (now_mono - last_time) < self.port_scan_cooldown_seconds:
                                    self.stats["attack_events_cooldown_suppressed"] += 1
                                    continue

                        if len(att_res.evidence["details"]) > 1:
                            finding_res = AttackDetectionResult(
                                category=AttackCategory.PORT_SCAN,
                                status=att_res.status,
                                severity=att_res.severity,
                                evidence={
                                    "verdict": "Reconnaissance / scanning pattern observed",
                                    "details": [finding],
                                    "destination_scope": finding.get("destination_scope"),
                                    "finding_source_ip": finding.get("src_ip"),
                                 },
                                missing_fields=att_res.missing_fields,
                                confidence=att_res.confidence,
                                timestamp=att_res.timestamp,
                                recommended_action=(
                                    f"Investigate host {finding.get('src_ip', 'unknown')} "
                                    f"(MAC: {finding_src_mac or 'unknown'}) for scanning tools. "
                                    f"Verify if endpoint is an authorized administrator. "
                                    f"Do NOT automatically disconnect client."
                                ),
                            )
                        else:
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
                        inserted_count += 1

                        def apply_ps_dedup(fingerprint=fp, mono=now_mono):
                            self.stats["attack_events_flagged"] += 1
                            with self._dedup_lock:
                                self._port_scan_dedup_cache[fingerprint] = mono
                                self._cleanup_port_scan_cache(mono)

                        if pending_dedup_actions is not None:
                            pending_dedup_actions.append(apply_ps_dedup)
                        else:
                            apply_ps_dedup()

                elif att_res.category == AttackCategory.SPOOFING:
                    spoof_src_mac = (
                        att_res.evidence.get("offending_mac")
                        or att_res.evidence.get("current_mac")
                        or None
                    )
                    spoof_target_ip = (
                        att_res.evidence.get("claimed_ip")
                        or att_res.evidence.get("ip_address")
                        or None
                    )
                    norm_mac = spoof_src_mac.strip().lower().replace("-", ":") if spoof_src_mac else None
                    norm_ip = spoof_target_ip.strip().lower() if spoof_target_ip else None
                    spoof_key = (self._run_id, norm_mac, norm_ip, AttackCategory.SPOOFING.value)

                    now_mono = time.monotonic()
                    with self._dedup_lock:
                        last_spoof_time = self._spoofing_dedup_cache.get(spoof_key)
                        if self.spoofing_cooldown_seconds > 0.0 and last_spoof_time is not None:
                            if 0.0 <= (now_mono - last_spoof_time) < self.spoofing_cooldown_seconds:
                                self.stats["attack_events_cooldown_suppressed"] += 1
                                continue

                    _insert_attack_event(
                        conn=db,
                        run_id=self._run_id,
                        window_id=window_id,
                        result=att_res,
                        source_mac=spoof_src_mac,
                        target_ip=spoof_target_ip,
                        commit=commit,
                    )
                    inserted_count += 1

                    def apply_spoof_dedup(key=spoof_key, mono=now_mono):
                        self.stats["attack_events_flagged"] += 1
                        with self._dedup_lock:
                            self._spoofing_dedup_cache[key] = mono
                            if len(self._spoofing_dedup_cache) > 100:
                                cutoff_mono = mono - max(self.spoofing_cooldown_seconds * 2, 120.0)
                                expired_spoof = [k for k, t in self._spoofing_dedup_cache.items() if t < cutoff_mono]
                                for k in expired_spoof:
                                    del self._spoofing_dedup_cache[k]

                    if pending_dedup_actions is not None:
                        pending_dedup_actions.append(apply_spoof_dedup)
                    else:
                        apply_spoof_dedup()

                elif att_res.category == AttackCategory.DEAUTH_FLOOD:
                    deauth_src_mac = None
                    if att_res.evidence.get("details"):
                        primary = att_res.evidence["details"][0]
                        bssid = primary.get("bssid")
                        deauth_src_mac = bssid if bssid and bssid != "unknown_bssid" else None

                    norm_bssid = deauth_src_mac.strip().lower().replace("-", ":") if deauth_src_mac else "unknown"
                    deauth_key = (self._run_id, norm_bssid, AttackCategory.DEAUTH_FLOOD.value)

                    now_mono = time.monotonic()
                    with self._dedup_lock:
                        last_deauth_time = self._deauth_dedup_cache.get(deauth_key)
                        if self.deauth_cooldown_seconds > 0.0 and last_deauth_time is not None:
                            if 0.0 <= (now_mono - last_deauth_time) < self.deauth_cooldown_seconds:
                                self.stats["attack_events_cooldown_suppressed"] += 1
                                continue

                    _insert_attack_event(
                        conn=db,
                        run_id=self._run_id,
                        window_id=window_id,
                        result=att_res,
                        source_mac=deauth_src_mac,
                        target_ip=None,
                        commit=commit,
                    )
                    inserted_count += 1

                    def apply_deauth_dedup(key=deauth_key, mono=now_mono):
                        self.stats["attack_events_flagged"] += 1
                        with self._dedup_lock:
                            self._deauth_dedup_cache[key] = mono
                            if len(self._deauth_dedup_cache) > 100:
                                cutoff_mono = mono - max(self.deauth_cooldown_seconds * 2, 120.0)
                                expired_deauth = [k for k, t in self._deauth_dedup_cache.items() if t < cutoff_mono]
                                for k in expired_deauth:
                                    del self._deauth_dedup_cache[k]

                    if pending_dedup_actions is not None:
                        pending_dedup_actions.append(apply_deauth_dedup)
                    else:
                        apply_deauth_dedup()

                elif att_res.category == AttackCategory.REPLAY:
                    # Stage 6.2: Replay alert address attribution correction
                    # Explicitly extract source MAC, source IP, and target (destination) IP
                    # without confusing IP addresses with MAC addresses.
                    replay_source_mac: Optional[str] = None
                    replay_source_ip: Optional[str] = None
                    replay_target_ip: Optional[str] = None

                    v0: Dict[str, Any] = {}
                    if att_res.evidence.get("violations") and isinstance(att_res.evidence["violations"], list):
                        raw_v0 = att_res.evidence["violations"][0]
                        if isinstance(raw_v0, dict):
                            v0 = raw_v0

                    # 1. Source MAC: Check explicit MAC fields, then fallback to v0['src'] if it is a valid MAC
                    mac_candidate = (
                        v0.get("source_mac")
                        or v0.get("eth_src")
                        or v0.get("src_mac")
                        or att_res.evidence.get("source_mac")
                        or att_res.evidence.get("eth_src")
                        or att_res.evidence.get("src_mac")
                        or v0.get("src")
                    )
                    if mac_candidate and _is_valid_mac(str(mac_candidate)):
                        replay_source_mac = str(mac_candidate).strip().lower().replace("-", ":")

                    # 2. Source IP: Check explicit IP fields, fallback to v0['src'] if it is a valid IP
                    src_ip_candidate = (
                        v0.get("source_ip")
                        or v0.get("src_ip")
                        or v0.get("ip_src")
                        or att_res.evidence.get("source_ip")
                        or att_res.evidence.get("src_ip")
                        or v0.get("src")
                    )
                    if src_ip_candidate and _is_valid_ip(str(src_ip_candidate)):
                        replay_source_ip = str(src_ip_candidate).strip()
                        if "source_ip" not in att_res.evidence:
                            att_res.evidence["source_ip"] = replay_source_ip

                    # 3. Target / Destination IP: Check destination IP fields, fallback to v0['dst'] if it is a valid IP
                    dst_ip_candidate = (
                        v0.get("target_ip")
                        or v0.get("dst_ip")
                        or v0.get("destination_ip")
                        or v0.get("ip_dst")
                        or att_res.evidence.get("target_ip")
                        or att_res.evidence.get("dst_ip")
                        or att_res.evidence.get("destination_ip")
                        or v0.get("dst")
                    )
                    if dst_ip_candidate and _is_valid_ip(str(dst_ip_candidate)):
                        replay_target_ip = str(dst_ip_candidate).strip()

                    _insert_attack_event(
                        conn=db,
                        run_id=self._run_id,
                        window_id=window_id,
                        result=att_res,
                        source_mac=replay_source_mac,
                        target_ip=replay_target_ip,
                        commit=commit,
                    )
                    inserted_count += 1

                    def apply_replay_flag():
                        self.stats["attack_events_flagged"] += 1

                    if pending_dedup_actions is not None:
                        pending_dedup_actions.append(apply_replay_flag)
                    else:
                        apply_replay_flag()

                else:
                    _insert_attack_event(
                        conn=db,
                        run_id=self._run_id,
                        window_id=window_id,
                        result=att_res,
                        source_mac=None,
                        target_ip=None,
                        commit=commit,
                    )
                    inserted_count += 1

                    def apply_other_flag():
                        self.stats["attack_events_flagged"] += 1

                    if pending_dedup_actions is not None:
                        pending_dedup_actions.append(apply_other_flag)
                    else:
                        apply_other_flag()

        return inserted_count

    def _map_wifi_mgmt_to_observation(
        self,
        payload: Dict[str, Any],
        anchor_epoch: Optional[float] = None,
    ) -> Optional[PacketObservation]:
        """
        Maps an ESP32 Wi-Fi management event dictionary to a structured PacketObservation.

        Requirements:
          - Reconstructs timestamp from payload['timestamp'], payload['_recv_epoch'], or anchor_epoch.
          - Maps transmitter address (ta) to eth_src (lowercase).
          - Maps destination address (da) to eth_dst (lowercase).
          - Subtype: 10 (Disassoc) or 12 (Deauth) -> wlan_fc_type_subtype.
          - Reason code: preserved as int, or None if missing or protected. Never invented.
          - Protected frames: treated as opaque, reason code forced to None.
          - BSSID: preserved as lowercase MAC or None.
          - Sequence number: preserved as protocol_seq_num if supported.
          - RSSI: preserved as rssi_dbm (float) or None.
          - Nonce, payload_hash, ports, IPs, TCP flags: set to None.
        """
        if not isinstance(payload, dict):
            return None

        # Validate basic MAC fields
        ta = payload.get("ta")
        da = payload.get("da")
        if not ta or not _is_valid_mac(str(ta)):
            self.stats["wifi_mgmt_malformed"] += 1
            return None
        if not da or not _is_valid_mac(str(da)):
            self.stats["wifi_mgmt_malformed"] += 1
            return None

        # Validate subtype (10: Disassoc, 12: Deauth)
        subtype = payload.get("subtype")
        if subtype not in (10, 12):
            self.stats["wifi_mgmt_dropped_unsupported_subtype"] += 1
            return None

        # Timestamp reconstruction
        if "timestamp" in payload and payload["timestamp"] is not None:
            try:
                ts = float(payload["timestamp"])
            except (ValueError, TypeError):
                ts = anchor_epoch if anchor_epoch is not None else time.time()
        elif "_recv_epoch" in payload and payload["_recv_epoch"] is not None:
            ts = float(payload["_recv_epoch"])
        else:
            ts = anchor_epoch if anchor_epoch is not None else time.time()

        # Reason code handling (Protected frames: CCMP PN at bytes 24-25, reason code opaque/None)
        is_protected = bool(payload.get("is_protected", False) or payload.get("protected", False))
        if is_protected:
            wlan_reason = None
        else:
            raw_reason = payload.get("reason")
            if raw_reason is not None and not isinstance(raw_reason, bool):
                try:
                    wlan_reason = int(raw_reason)
                except (ValueError, TypeError):
                    wlan_reason = None
            else:
                wlan_reason = None

        # BSSID handling
        bssid_raw = payload.get("bssid")
        if bssid_raw and _is_valid_mac(str(bssid_raw)):
            wlan_bssid = str(bssid_raw).strip().lower()
        else:
            wlan_bssid = None

        # Protocol sequence number:
        # The ESP32 event 'seq' field is an internal firmware admission / dispatch counter,
        # NOT the over-the-air IEEE 802.11 MAC Sequence Control number.
        # protocol_seq_num MUST remain None unless the actual 802.11 MAC sequence number is explicitly
        # captured and supplied (e.g. via 'wlan_seq' or 'mac_seq').
        # The ESP32 'seq' counter is preserved separately in payload for deduplication and telemetry.
        wlan_seq_raw = (
            payload.get("wlan_seq")
            if "wlan_seq" in payload and payload.get("wlan_seq") is not None
            else payload.get("mac_seq")
            if "mac_seq" in payload and payload.get("mac_seq") is not None
            else None
        )
        if wlan_seq_raw is not None and not isinstance(wlan_seq_raw, bool):
            try:
                protocol_seq_num = int(wlan_seq_raw)
            except (ValueError, TypeError):
                protocol_seq_num = None
        else:
            protocol_seq_num = None

        # RSSI
        raw_rssi = payload.get("rssi")
        if raw_rssi is not None and not isinstance(raw_rssi, bool):
            try:
                rssi_val = float(raw_rssi)
            except (ValueError, TypeError):
                rssi_val = None
        else:
            rssi_val = None

        # Packet size:
        # Do not represent nominal 26-byte or 42-byte estimates as measured frame lengths.
        # If the actual captured frame length is not explicitly captured/supplied,
        # use sentinel 0 (PACKET_SIZE_UNKNOWN) to comply with the existing PacketObservation.packet_size: int type
        # without inventing unmeasured frame lengths.
        # (Note: Strictly using None would require updating the PacketObservation schema in src/attack_detector.py,
        # which is frozen and prohibited from modification).
        raw_len = (
            payload.get("len")
            if "len" in payload and payload.get("len") is not None
            else payload.get("frame_len")
            if "frame_len" in payload and payload.get("frame_len") is not None
            else payload.get("packet_size")
            if "packet_size" in payload and payload.get("packet_size") is not None
            else None
        )
        if raw_len is not None and not isinstance(raw_len, bool):
            try:
                packet_size = int(raw_len)
            except (ValueError, TypeError):
                packet_size = 0
        else:
            packet_size = 0  # Sentinel for unmeasured / unavailable captured frame length

        if subtype == 12:
            self.stats["wifi_mgmt_deauth_events_mapped"] += 1
        elif subtype == 10:
            self.stats["wifi_mgmt_disassoc_events_mapped"] += 1

        return PacketObservation(
            timestamp=ts,
            packet_size=packet_size,
            eth_src=str(ta).strip().lower(),
            eth_dst=str(da).strip().lower(),
            ip_src=None,
            ip_dst=None,
            protocol="802.11",
            src_port=None,
            dst_port=None,
            tcp_flags=None,
            wlan_fc_type_subtype=subtype,
            wlan_reason_code=wlan_reason,
            wlan_bssid=wlan_bssid,
            protocol_seq_num=protocol_seq_num,
            payload_hash=None,
            nonce=None,
            rssi_dbm=rssi_val,
        )

    def _drain_wifi_mgmt_queue(
        self,
        window_epoch: Optional[float] = None,
    ) -> List[PacketObservation]:
        """
        Drains all available validated 802.11 management frames from self._wifi_mgmt_queue non-blockingly.
        Maps each event payload into a structured PacketObservation object.
        Rejects stale events whose boot_id no longer matches active_boot_id.
        """
        observations: List[PacketObservation] = []
        target_epoch = window_epoch if window_epoch is not None else time.time()

        while not self._wifi_mgmt_queue.empty():
            try:
                item = self._wifi_mgmt_queue.get_nowait()
            except queue.Empty:
                break
            except Exception as e:
                self.stats["wifi_mgmt_exceptions"] += 1
                print(f"[NET][WARN] Error dequeuing Wi-Fi mgmt event: {e}")
                break

            self.stats["wifi_mgmt_events_drained"] += 1

            # Direct PacketObservation support
            if isinstance(item, PacketObservation):
                observations.append(item)
                continue

            if not isinstance(item, dict):
                self.stats["wifi_mgmt_malformed"] += 1
                continue

            # Boot ID session consistency check
            item_boot_id = item.get("boot_id")
            with self._session_lock:
                if self.active_boot_id is not None and item_boot_id is not None and item_boot_id != self.active_boot_id:
                    self.stats["wifi_mgmt_stale_events"] += 1
                    continue

            try:
                obs = self._map_wifi_mgmt_to_observation(item, anchor_epoch=target_epoch)
                if obs is not None:
                    observations.append(obs)
            except Exception as e:
                self.stats["wifi_mgmt_exceptions"] += 1
                print(f"[NET][WARN] Error mapping Wi-Fi mgmt payload: {e}")

        return observations

    # ─── Internal: Database persistence and retry helpers (Stage 6.5.4) ───────

    def _persist_window_transaction(
        self,
        conn: sqlite3.Connection,
        scored: Dict[str, Any],
        new_unknown: List[str],
        dos_results: List[AttackDetectionResult],
        stream_results: List[AttackDetectionResult],
        client_mac: str,
    ) -> Tuple[int, List[Any], int, int]:
        """
        Executes all database operations for a completed 1-second feature window
        within the caller's transaction without committing.

        Returns:
            Tuple of (window_id, pending_dedup_actions, alerts_count, unknown_count)
        """
        window_id = _insert_traffic_window(conn, self._run_id, scored, commit=False)

        # Update last_seen in device_registry for observed client
        if client_mac:
            try:
                conn.execute(
                    "UPDATE device_registry SET last_seen = CURRENT_TIMESTAMP WHERE mac_address = ?",
                    (client_mac.lower(),),
                )
            except Exception:
                pass

        alerts_count = 0
        if scored.get("pred_dual") == -1:
            _insert_alert(conn, self._run_id, window_id, scored, commit=False)
            alerts_count = 1

        unknown_count = 0
        for mac in new_unknown:
            _upsert_unknown_device(conn, self._run_id, mac, commit=False)
            unknown_count += 1

        pending_actions: List[Any] = []
        if self._attack_table_present:
            self._persist_attack_results(
                db=conn,
                window_id=window_id,
                dos_results=dos_results,
                stream_results=stream_results,
                client_mac=client_mac,
                scored=scored,
                commit=False,
                pending_dedup_actions=pending_actions,
            )

        return window_id, pending_actions, alerts_count, unknown_count

    def _persist_window_with_retry(
        self,
        scored: Dict[str, Any],
        new_unknown: List[str],
        dos_results: List[AttackDetectionResult],
        stream_results: List[AttackDetectionResult],
        client_mac: str,
    ) -> bool:
        """
        Atomically persists the 1-second window and all associated alerts,
        unknown devices, and attack events with bounded retry for transient SQLite lock/busy errors.
        """
        if self._run_id is None or not self.db_path.exists():
            return False

        attempts = 0
        current_delay = self.db_retry_initial_delay_sec
        max_attempts = 1 + self.db_max_retries

        while attempts < max_attempts:
            attempts += 1
            db = None
            try:
                db = get_live_db_connection(self.db_path)
                try:
                    db.execute(f"PRAGMA busy_timeout = {int(self.db_busy_timeout_ms)};")
                    window_id, pending_actions, alerts_count, unknown_count = (
                        self._persist_window_transaction(
                            conn=db,
                            scored=scored,
                            new_unknown=new_unknown,
                            dos_results=dos_results,
                            stream_results=stream_results,
                            client_mac=client_mac,
                        )
                    )
                    db.commit()

                    # Commit succeeded — apply in-memory dedup updates and counters
                    for action in pending_actions:
                        try:
                            action()
                        except Exception as act_err:
                            print(f"[NET][WARN] Error applying attack dedup action: {act_err}")

                    self.stats["windows_emitted"] += 1
                    self.stats["alerts_generated"] += alerts_count
                    self.stats["unknown_devices_seen"] += unknown_count

                    if attempts > 1:
                        self.stats["db_transient_write_retries"] += 1
                        print(
                            f"[NET][INFO] Window persistence recovered on attempt {attempts}/{max_attempts}"
                        )
                    return True

                except Exception as inner_e:
                    if db is not None:
                        try:
                            db.rollback()
                        except Exception:
                            pass
                    raise inner_e
                finally:
                    if db is not None:
                        try:
                            db.close()
                        except Exception:
                            pass
                    db = None

            except Exception as e:
                if is_transient_db_lock_error(e) and attempts < max_attempts:
                    print(
                        f"[NET][WARN] Database locked/busy during window write (attempt {attempts}/{max_attempts}); "
                        f"retrying in {current_delay:.2f}s..."
                    )
                    if self._stop_event.wait(timeout=current_delay):
                        break
                    current_delay *= self.db_retry_backoff_factor
                    continue
                else:
                    self.stats["db_window_write_failures"] += 1
                    print(
                        f"[NET][ERROR] Window persistence failed (attempt {attempts}/{max_attempts}): {e}"
                    )
                    return False

        return False

    def _persist_sensor_with_retry(
        self,
        payload: Dict[str, Any],
        sensor_epoch: float,
    ) -> bool:
        """
        Attempts to persist ESP32 sensor telemetry (Node_1 DHT11 and Node_2 PIR)
        with bounded retry for transient SQLite lock/busy errors.
        """
        if not self.db_path.exists() or self._run_id is None:
            return False

        attempts = 0
        current_delay = self.db_retry_initial_delay_sec
        max_attempts = 1 + self.db_max_retries

        while attempts < max_attempts:
            attempts += 1
            db = None
            try:
                db = get_live_db_connection(self.db_path)
                try:
                    db.execute(f"PRAGMA busy_timeout = {int(self.db_busy_timeout_ms)};")
                    _insert_sensor_telemetry(db, self._run_id, payload, sensor_epoch, commit=False)
                    db.commit()
                    self.stats["sensor_records"] += 1
                    if attempts > 1:
                        self.stats["db_transient_write_retries"] += 1
                        print(
                            f"[SERIAL][INFO] Sensor persistence recovered on attempt {attempts}/{max_attempts}"
                        )
                    return True
                except Exception as inner_e:
                    if db is not None:
                        try:
                            db.rollback()
                        except Exception:
                            pass
                    raise inner_e
                finally:
                    if db is not None:
                        try:
                            db.close()
                        except Exception:
                            pass
                    db = None

            except Exception as e:
                if is_transient_db_lock_error(e) and attempts < max_attempts:
                    print(
                        f"[SERIAL][WARN] Database locked/busy during sensor write (attempt {attempts}/{max_attempts}); "
                        f"retrying in {current_delay:.2f}s..."
                    )
                    if self._stop_event.wait(timeout=current_delay):
                        break
                    current_delay *= self.db_retry_backoff_factor
                    continue
                else:
                    self.stats["db_sensor_write_failures"] += 1
                    print(
                        f"[SERIAL][ERROR] Sensor persistence failed (attempt {attempts}/{max_attempts}): {e}"
                    )
                    return False

        return False

    # ─── Internal: Network thread ─────────────────────────────────────────────

    def _network_loop(self) -> None:
        """
        Runs in Thread 1. Starts LiveStreamExtractor, iterates windows,
        scores them, writes to DB, and generates alerts.
        """
        extractor = LiveStreamExtractor(
            interface_index=self.interface_index,
            device_registry=self.device_registry,
            tshark_path=self.tshark_path,
            direction="uplink",
            tshark_extra_args=self.tshark_extra_args,
        )
        self._extractor = extractor
        try:
            extractor.start()
            print("[NET] TShark packet stream started.")

            for window in extractor.iter_windows():
                if self._stop_event.is_set():
                    break

                # Periodic device registry refresh (Stage 6.5.2)
                self.refresh_device_registry(force=False)

                # Score window with frozen dual detector
                scored = score_window(self._bundle, window)
                client_mac = scored.get("client_mac", "")

                # Flush unregistered MACs
                new_unknown = list(extractor.drain_unregistered_macs())

                # Attack Engine Evaluation:
                # 1. Drain raw packet observations captured since last drain
                recent_pkts = extractor.drain_recent_packets()
                buf_status = extractor.get_buffer_telemetry_status()
                if not buf_status["is_lossless"]:
                    self.stats["packets_dropped_overflow"] = buf_status["dropped_packets"]

                # 1b. Drain Wi-Fi management queue non-blockingly (Stage 4.3.2)
                wifi_mgmt_pkts: List[PacketObservation] = []
                try:
                    wifi_mgmt_pkts = self._drain_wifi_mgmt_queue(
                        window_epoch=scored.get("bin_start_timestamp", time.time())
                    )
                except Exception as e:
                    self.stats["wifi_mgmt_exceptions"] += 1
                    print(f"[NET][WARN] Exception draining Wi-Fi mgmt queue: {e}")

                # 2. Evaluate DoS on 1-second window
                target_obs = WindowTrafficObservation(
                    bin_start_epoch=scored.get("bin_start_timestamp", time.time()),
                    node_id=scored.get("node_id", ""),
                    mac_address=client_mac,
                    packet_count=scored.get("packet_count", 0),
                    packet_rate=scored.get("packet_rate", 0.0),
                    total_bytes=scored.get("total_bytes", 0),
                    mean_packet_size=scored.get("mean_packet_size"),
                    ip_src=scored.get("ip_src"),
                    ip_dst=scored.get("ip_dst"),
                )

                # Maintain fleet observations: prune entries older than 2.0s
                cutoff_epoch = target_obs.bin_start_epoch - 2.0
                self._recent_fleet_windows = {
                    k: w for k, w in self._recent_fleet_windows.items()
                    if w.bin_start_epoch >= cutoff_epoch
                }
                self._recent_fleet_windows[client_mac.lower()] = target_obs
                fleet_obs = [
                    w for w in self._recent_fleet_windows.values()
                    if abs(w.bin_start_epoch - target_obs.bin_start_epoch) <= 1.0
                ]

                dos_results = self.attack_detector.evaluate_traffic_window(
                    target_obs, fleet_windows=fleet_obs
                )

                # 3. Evaluate packet stream (Port Scan, Spoofing, Deauth, Replay)
                # Evaluated only when fresh packets are drained; each packet evaluated exactly once.
                stream_results = []
                combined_pkts = list(recent_pkts) + list(wifi_mgmt_pkts)
                if combined_pkts:
                    try:
                        stream_results = self.attack_detector.evaluate_packet_stream(combined_pkts)
                    except Exception as e:
                        self.stats["wifi_mgmt_exceptions"] += 1
                        print(f"[NET][WARN] Exception in evaluate_packet_stream: {e}")
                        stream_results = []

                # 4. Atomic window & attack events persistence with bounded retry (Stage 6.5.4)
                self._persist_window_with_retry(
                    scored=scored,
                    new_unknown=new_unknown,
                    dos_results=dos_results,
                    stream_results=stream_results,
                    client_mac=client_mac,
                )

                # Update packets parsed local stats
                self.stats["packets_parsed"] = extractor.stats["packets_parsed"]

            # Check if iter_windows exited unexpectedly while shutdown was NOT requested (e.g. TShark EOF)
            if not self._stop_event.is_set():
                err_msg = "Network worker terminated unexpectedly (TShark stream closed)"
                print(f"[NET][ERROR] {err_msg}")
                with self._status_lock:
                    self._net_worker_failed = True
                    self._net_failure_reason = err_msg
                    self._status = "ERROR"
                    self._stop_reason = err_msg
                    self._persist_status_locked("ERROR", err_msg)

        except Exception as e:
            err_msg = f"Network worker crashed: {e}"
            print(f"[NET][ERROR] {err_msg}")
            traceback.print_exc()
            with self._status_lock:
                self._net_worker_failed = True
                self._net_failure_reason = err_msg
                self._status = "ERROR"
                self._stop_reason = err_msg
                self._persist_status_locked("ERROR", err_msg)
        finally:
            self._extractor = None
            extractor.stop()
            print("[NET] TShark stream stopped.")

    # ─── Internal: Serial routing and handlers (Stage 4.3.1) ──────────────────

    def send_sniffer_probe(self, ser: Any = None, nonce: Optional[int] = None) -> int:
        """
        Emits a correlated request probe to the ESP32 firmware over serial.
        Generates an unpredictable 32-bit random request nonce if not provided.
        Updates self._expected_probe_nonce to correlate incoming status response.
        """
        if nonce is None:
            nonce = secrets.randbits(32)
        with self._session_lock:
            self._expected_probe_nonce = nonce
        self.stats["sniffer_probe_requests_sent"] += 1
        if ser is not None and getattr(ser, "is_open", False):
            try:
                probe_cmd = json.dumps({"cmd": "probe", "nonce": nonce}) + "\n"
                ser.write(probe_cmd.encode("utf-8"))
            except Exception as e:
                print(f"[SERIAL][WARN] Failed to transmit sniffer probe: {e}")
        return nonce

    def _handle_sniffer_status(self, payload: Dict[str, Any]) -> str:
        """
        Processes 'WIFI_SNIFFER_INITIALIZED' handshake status response.
        Verifies request nonce correlation to reject stale serial buffers.
        """
        self.stats["sniffer_status_responses_received"] += 1
        is_valid, msg = validate_sniffer_status(payload)
        if not is_valid:
            print(f"[SERIAL][INVALID] Sniffer status malformed: {msg}")
            self.stats["wifi_mgmt_malformed"] += 1
            return "MALFORMED_SNIFFER_STATUS"

        resp_nonce = payload.get("nonce")
        with self._session_lock:
            if self._expected_probe_nonce is not None and resp_nonce != self._expected_probe_nonce:
                print(
                    f"[SERIAL][WARN] Discarding stale sniffer status (nonce {resp_nonce} != {self._expected_probe_nonce})"
                )
                self.stats["sniffer_stale_probe_responses_dropped"] += 1
                self.stats["sniffer_nonce_mismatches"] += 1
                return "STALE_SNIFFER_STATUS"

            new_boot_id = payload.get("boot_id")
            if self.active_boot_id is not None and new_boot_id != self.active_boot_id:
                # Invalidate and purge stale queued events from prior boot session
                purged_count = 0
                while not self._wifi_mgmt_queue.empty():
                    try:
                        self._wifi_mgmt_queue.get_nowait()
                        purged_count += 1
                        self.stats["wifi_mgmt_stale_events"] += 1
                    except Exception:
                        break
                if purged_count > 0:
                    print(
                        f"[SERIAL][INFO] New ESP32 boot session ({self.active_boot_id} -> {new_boot_id}): "
                        f"purged {purged_count} stale Wi-Fi mgmt events."
                    )

            self.active_boot_id = new_boot_id
            self._session_established = True
            self._seen_mgmt_sequences.clear()
            print(f"[SERIAL][INFO] Sniffer session active: boot_id={new_boot_id}, nonce={resp_nonce}")

            # Authoritative channel from hardware sniffer handshake (Stage 8.4)
            hw_chan = payload.get("channel")
            self._update_channel_alignment_with_hardware_channel(hw_chan)
        return "SNIFFER_STATUS"

    def _handle_wifi_mgmt_event(self, payload: Dict[str, Any]) -> str:
        """
        Validates and enqueues individual 802.11 deauth/disassociation events.
        Rejects stale pre-reboot events and duplicate sequence numbers.
        Enforces host queue capacity (maxsize=256) without blocking serial loop.
        """
        self.stats["wifi_mgmt_events_parsed"] += 1
        is_valid, msg = validate_wifi_mgmt_event(payload)
        if not is_valid:
            print(f"[SERIAL][INVALID] Wi-Fi mgmt event malformed: {msg}")
            self.stats["wifi_mgmt_malformed"] += 1
            return "MALFORMED_WIFI_MGMT"

        evt_boot_id = payload.get("boot_id")
        with self._session_lock:
            if self.active_boot_id is not None and evt_boot_id != self.active_boot_id:
                self.stats["wifi_mgmt_stale_events"] += 1
                return "STALE_WIFI_MGMT"

            evt_seq = payload.get("seq")
            if evt_seq in self._seen_mgmt_sequences:
                self.stats["wifi_mgmt_duplicate_events"] += 1
                return "DUPLICATE_WIFI_MGMT"
            self._seen_mgmt_sequences.add(evt_seq)
            if len(self._seen_mgmt_sequences) > 10000:
                self._seen_mgmt_sequences.clear()

        try:
            payload["_recv_epoch"] = time.time()
            self._wifi_mgmt_queue.put_nowait(payload)
            self.stats["wifi_mgmt_events_pushed"] += 1
            return "WIFI_MGMT_ENQUEUED"
        except queue.Full:
            self.stats["wifi_mgmt_queue_dropped"] += 1
            print("[SERIAL][WARN] Wi-Fi mgmt queue full (256 items); event dropped.")
            return "WIFI_MGMT_QUEUE_FULL"

    def _handle_wifi_mgmt_summary(self, payload: Dict[str, Any]) -> str:
        """
        Validates periodic 1.0-second Wi-Fi sniffer summary reports.
        Preserves cumulative session totals and tracks per-window delta metrics.
        """
        self.stats["wifi_mgmt_summaries_parsed"] += 1
        is_valid, msg = validate_wifi_mgmt_summary(payload)
        if not is_valid:
            print(f"[SERIAL][INVALID] Wi-Fi mgmt summary malformed: {msg}")
            self.stats["wifi_mgmt_malformed"] += 1
            return "MALFORMED_SUMMARY"

        summ_boot_id = payload.get("boot_id")
        with self._session_lock:
            if self.active_boot_id is not None and summ_boot_id != self.active_boot_id:
                self.stats["wifi_mgmt_stale_events"] += 1
                return "STALE_SUMMARY"

        with self._summary_lock:
            cum = payload.get("cumulative", {})
            if (
                self._last_summary_snapshot is not None
                and self._last_summary_snapshot.get("boot_id") == summ_boot_id
            ):
                prev_cum = self._last_summary_snapshot.get("cumulative", {})
                delta = {
                    k: max(0, cum.get(k, 0) - prev_cum.get(k, 0))
                    for k in cum
                }
            else:
                delta = dict(cum)

            self._last_summary_snapshot = {
                "boot_id": summ_boot_id,
                "summary_seq": payload.get("summary_seq"),
                "uptime_ms": payload.get("uptime_ms"),
                "window_ms": payload.get("window_ms"),
                "cumulative": dict(cum),
                "window_delta": delta,
            }
        return "WIFI_SUMMARY"

    def process_serial_line(self, line_str: str) -> Optional[str]:
        """
        Parses and routes a single line of decoded serial telemetry.
        Distinguishes message types BEFORE passing to the sensor validator:
          1. Firmware boot announcements ('ESP32_TELEMETRY_INITIALIZED')
          2. Sniffer probe status responses ('WIFI_SNIFFER_INITIALIZED')
          3. Wi-Fi individual management events (type == 'wifi_mgmt')
          4. Wi-Fi periodic summary reports (type == 'wifi_mgmt_summary')
          5. Environmental sensor telemetry ('node' in payload)
          6. Non-JSON raw debug lines / malformed JSON
        """
        if not line_str or not line_str.strip():
            return None

        line_str = line_str.strip()

        # 1. Skip / log firmware boot announcements
        if "ESP32_TELEMETRY_INITIALIZED" in line_str:
            print(f"[SERIAL][INFO] {line_str}")
            return "BOOT_ANNOUNCEMENT"

        # 2. JSON Decoding
        try:
            payload = json.loads(line_str)
        except json.JSONDecodeError:
            print(f"[SERIAL][RAW] {line_str}")
            self.stats["serial_raw_lines"] += 1
            return "RAW_LOG"

        if not isinstance(payload, dict):
            print(f"[SERIAL][INVALID] Non-dict JSON payload: {type(payload)}")
            return "INVALID_JSON"

        # 3. Message Type Routing (BEFORE reaching sensor validator)
        # A. Sniffer Probe / Status Handshake Messages
        if payload.get("status") == "WIFI_SNIFFER_INITIALIZED":
            return self._handle_sniffer_status(payload)

        # B. Wi-Fi Management Events
        msg_type = payload.get("type")
        if msg_type == "wifi_mgmt":
            return self._handle_wifi_mgmt_event(payload)

        # C. Wi-Fi Management Summaries
        if msg_type == "wifi_mgmt_summary":
            return self._handle_wifi_mgmt_summary(payload)

        # D. Existing Sensor Telemetry (must contain "node")
        if "node" in payload:
            is_valid, msg = validate_payload(payload)
            if not is_valid:
                print(f"[SERIAL][INVALID] {msg}")
                self.stats["sensor_payloads_invalid"] += 1
                return "INVALID_SENSOR"

            sensor_epoch = time.time()
            self._persist_sensor_with_retry(payload, sensor_epoch)
            return "SENSOR_TELEMETRY"

        # E. Unrecognized JSON payload
        print(f"[SERIAL][WARN] Unrecognized JSON payload: {payload}")
        return "UNRECOGNIZED_JSON"

    # ─── Internal: Serial thread ──────────────────────────────────────────────

    def _serial_loop(self) -> None:
        """
        Runs in Thread 2. Opens the ESP32 serial port, executes initial sniffer probe
        handshake, reads JSON telemetry, routes payloads via process_serial_line(),
        and inserts Node_1 (DHT11) + Node_2 (PIR) rows.

        Handles:
          - SerialException / disconnect -> controlled reconnection with capped exponential backoff.
          - Reconnection rediscovery across port unplugs / reconnects without terminating worker thread.
          - Initial probe handshake (send_sniffer_probe) on successful connection.
          - Rejection of stale events across new boot_id sessions.
          - Timeout readline() -> continues waiting.
          - Clean interruption upon _stop_event.
        """
        try:
            import serial
            import serial.tools.list_ports
        except ImportError:
            err_msg = "pyserial not installed. Serial thread disabled."
            print(f"[SERIAL][ERROR] {err_msg}")
            with self._status_lock:
                self._serial_worker_failed = True
                self._serial_failure_reason = err_msg
                if self._status != "ERROR":
                    self._stop_reason = err_msg
                    self._persist_status_locked(self._status, err_msg)
            return

        current_backoff = self.serial_backoff_initial_sec
        consecutive_errors = 0
        reconnect_attempts = 0

        while not self._stop_event.is_set():
            # 1. Check port availability
            try:
                available = [p.device for p in serial.tools.list_ports.comports()]
            except Exception as e:
                available = []
                print(f"[SERIAL][WARN] Port enumeration failed: {e}")

            if self.serial_port not in available:
                reconnect_attempts += 1
                consecutive_errors += 1
                err_msg = (
                    f"Serial port {self.serial_port} not found (attempt {reconnect_attempts}); "
                    f"reconnecting in {current_backoff:.1f}s"
                )
                print(f"[SERIAL] {err_msg}")
                with self._status_lock:
                    self._serial_connected = False
                    self._serial_reconnecting = True
                    self._serial_failure_reason = err_msg
                    self._current_serial_backoff = current_backoff
                    if self._status != "ERROR":
                        self._stop_reason = err_msg
                        self._persist_status_locked(self._status, err_msg)

                if self._stop_event.wait(timeout=current_backoff):
                    break
                current_backoff = min(current_backoff * self.serial_backoff_factor, self.serial_backoff_max_sec)
                continue

            # 2. Port is present — attempt connection
            ser = None
            try:
                ser = serial.Serial(
                    port=self.serial_port,
                    baudrate=DEFAULT_BAUD_RATE,
                    timeout=SERIAL_TIMEOUT,
                )
                # Connection established — reset backoff and error tracking
                current_backoff = self.serial_backoff_initial_sec
                consecutive_errors = 0
                reconnect_attempts = 0
                with self._status_lock:
                    self._serial_connected = True
                    self._serial_reconnecting = False
                    self._serial_worker_failed = False
                    self._serial_failure_reason = None
                    self._current_serial_backoff = current_backoff
                    if self._status != "ERROR":
                        self._stop_reason = None
                        self._persist_status_locked(self._status, None)

                if hasattr(ser, "reset_input_buffer"):
                    ser.reset_input_buffer()

                print(f"[SERIAL] Connected to {self.serial_port}.")

                # 3. Probe Handshake (Stage 6.5.3)
                try:
                    self.send_sniffer_probe(ser)
                except Exception as probe_err:
                    print(f"[SERIAL][WARN] Initial sniffer probe transmission failed: {probe_err}")

                # 4. Continuous read loop
                while not self._stop_event.is_set():
                    try:
                        raw = ser.readline()
                    except (serial.SerialException, OSError) as read_err:
                        print(f"[SERIAL][WARN] Serial read error on {self.serial_port}: {read_err}")
                        raise

                    if not raw:
                        # Timeout with no data; normal for quiescent periods
                        continue

                    try:
                        line_str = raw.decode("utf-8", errors="replace").strip()
                    except Exception:
                        continue

                    if not line_str:
                        continue

                    self.process_serial_line(line_str)

            except (serial.SerialException, OSError) as e:
                consecutive_errors += 1
                reconnect_attempts += 1
                err_msg = (
                    f"Serial connection error on {self.serial_port} ({consecutive_errors} errors): {e}; "
                    f"reconnecting in {current_backoff:.1f}s"
                )
                print(f"[SERIAL][ERROR] {err_msg}")
                with self._status_lock:
                    self._serial_connected = False
                    self._serial_reconnecting = True
                    self._serial_failure_reason = err_msg
                    self._current_serial_backoff = current_backoff
                    if self._status != "ERROR":
                        self._stop_reason = err_msg
                        self._persist_status_locked(self._status, err_msg)

                if self._stop_event.wait(timeout=current_backoff):
                    break
                current_backoff = min(current_backoff * self.serial_backoff_factor, self.serial_backoff_max_sec)

            except Exception as e:
                err_msg = f"Serial worker unexpected exception: {e}"
                print(f"[SERIAL][ERROR] {err_msg}")
                traceback.print_exc()
                with self._status_lock:
                    self._serial_connected = False
                    self._serial_reconnecting = True
                    self._serial_failure_reason = err_msg
                    self._current_serial_backoff = current_backoff
                    if self._status != "ERROR":
                        self._stop_reason = err_msg
                        self._persist_status_locked(self._status, err_msg)

                if self._stop_event.wait(timeout=current_backoff):
                    break
                current_backoff = min(current_backoff * self.serial_backoff_factor, self.serial_backoff_max_sec)

            finally:
                if ser is not None and getattr(ser, "is_open", False):
                    try:
                        ser.close()
                    except Exception:
                        pass
                ser = None

        # Post-loop shutdown check
        with self._status_lock:
            self._serial_connected = False
            self._serial_reconnecting = False
            if not self._stop_event.is_set():
                self._serial_worker_failed = True
                if not self._serial_failure_reason:
                    self._serial_failure_reason = "Serial worker thread terminated unexpectedly"
                if self._status != "ERROR":
                    self._stop_reason = self._serial_failure_reason
                    self._persist_status_locked(self._status, self._stop_reason)

        print("[SERIAL] Serial thread stopped.")


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Live IoT Wi-Fi Anomaly Detection Collector\n"
            "Requires: Windows Mobile Hotspot active, TShark installed,\n"
            "          ESP32 connected via USB (optional with --no-sensors)."
        )
    )
    parser.add_argument(
        "--interface",
        type=int,
        default=None,
        help="TShark interface index (from 'tshark -D'). "
             "Auto-detected if omitted.",
    )
    parser.add_argument(
        "--port",
        type=str,
        default=DEFAULT_SERIAL_PORT,
        help=f"ESP32 COM port (default: {DEFAULT_SERIAL_PORT}).",
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=str(DEFAULT_LIVE_DB_PATH),
        help=f"Live monitoring database path (default: {DEFAULT_LIVE_DB_PATH}).",
    )
    parser.add_argument(
        "--session1-csv",
        type=str,
        default=str(DEFAULT_SESSION1_PATH),
        help="Session 1 training CSV for frozen detector.",
    )
    parser.add_argument(
        "--no-sensors",
        action="store_true",
        help="Disable ESP32 serial ingestion (network-only mode).",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="Print available TShark interfaces and exit.",
    )
    parser.add_argument(
        "--init-db",
        action="store_true",
        help="Initialise (or reinitialise) the live database and exit.",
    )
    parser.add_argument(
        "--overwrite-db",
        action="store_true",
        help="When combined with --init-db, deletes and recreates the database.",
    )
    parser.add_argument(
        "--migrate-db",
        action="store_true",
        help="Apply non-destructive schema migrations (such as adding live_attack_events) to the database and exit.",
    )
    parser.add_argument(
        "--gateway-mac",
        default=None,
        help="Explicit physical/virtual MAC address of the Hotspot Gateway (e.g. '36:6f:24:d2:34:3d'). If omitted, automatically attempts local adapter resolution.",
    )
    parser.add_argument(
        "--port-scan-cooldown",
        type=float,
        default=10.0,
        help="Cooldown in seconds to suppress duplicate Port Scan alert events for identical findings (default: 10.0s).",
    )
    parser.add_argument(
        "--dos-cooldown",
        type=float,
        default=60.0,
        help="Cooldown in seconds to suppress duplicate DoS alert events for identical source/target findings (default: 60.0s).",
    )
    parser.add_argument(
        "--dos-rate-threshold",
        type=float,
        default=60.0,
        help="Packet rate threshold in PPS to trigger DoS evaluation (default: 60.0 PPS).",
    )
    parser.add_argument(
        "--spoofing-cooldown",
        type=float,
        default=60.0,
        help="Cooldown in seconds to suppress duplicate Spoofing alert events for identical offending MAC/IP findings (default: 60.0s).",
    )
    parser.add_argument(
        "--deauth-cooldown",
        type=float,
        default=60.0,
        help="Cooldown in seconds to suppress duplicate Deauth alert events for identical BSSID findings (default: 60.0s).",
    )
    parser.add_argument(
        "--cloud-sync",
        action="store_true",
        default=False,
        help="Enable background cloud sync outbox worker to Supabase PostgreSQL pooler",
    )

    args = parser.parse_args()
    db_path = Path(args.db_path)

    # ── --list-interfaces ─────────────────────────────────────────────────────
    if args.list_interfaces:
        try:
            ifaces = list_all_interfaces()
            print(format_interface_table(ifaces))
        except TSharkNotFoundError as e:
            print(f"[ERROR] {e}", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

    # ── --migrate-db ──────────────────────────────────────────────────────────
    if args.migrate_db:
        try:
            migrate_live_database(db_path)
            print(f"[MIGRATE] Database migrated safely at: {db_path.resolve()}")
        except RuntimeError as e:
            print(f"[SAFETY ERROR] {e}", file=sys.stderr)
            sys.exit(2)
        sys.exit(0)

    # ── --init-db ─────────────────────────────────────────────────────────────
    if args.init_db:
        try:
            init_live_database(db_path, overwrite=args.overwrite_db)
        except (FileExistsError, RuntimeError) as e:
            print(f"[ERROR] {e}", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

    # ── Resolve interface ─────────────────────────────────────────────────────
    iface_name = ""
    try:
        iface_idx, _dev, iface_name = resolve_hotspot_interface(
            override_index=args.interface
        )
    except TSharkNotFoundError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)
    except NoHotspotInterfaceError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)
    except AmbiguousHotspotInterfaceError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        print("Re-run with: --interface <index>", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[COLLECTOR] Using interface [{iface_idx}] {iface_name}")

    # ── Ensure database exists ────────────────────────────────────────────────
    if not db_path.exists():
        print("[COLLECTOR] Database not found; initialising...")
        try:
            init_live_database(db_path)
        except RuntimeError as e:
            print(f"[SAFETY ERROR] {e}", file=sys.stderr)
            sys.exit(2)

    # ── Start collector ───────────────────────────────────────────────────────
    collector = LiveCollector(
        interface_index=iface_idx,
        serial_port=args.port,
        db_path=db_path,
        session1_csv=Path(args.session1_csv),
        no_sensors=args.no_sensors,
        gateway_mac=args.gateway_mac,
        port_scan_cooldown_seconds=args.port_scan_cooldown,
        dos_cooldown_seconds=args.dos_cooldown,
        dos_rate_threshold=args.dos_rate_threshold,
        spoofing_cooldown_seconds=args.spoofing_cooldown,
        deauth_cooldown_seconds=args.deauth_cooldown,
        enable_cloud_sync=args.cloud_sync,
    )
    collector.start(interface_name=iface_name)
    collector.run_until_stopped()


if __name__ == "__main__":
    main()
