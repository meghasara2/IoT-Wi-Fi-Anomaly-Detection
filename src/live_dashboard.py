"""
AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection
Live Interactive Monitoring Dashboard — Premium SOC Console
File: src/live_dashboard.py

Purpose:
  Provides a production-grade, real-time cybersecurity console for monitoring:
    1. Dynamic TShark packet stream & completed 1-second feature windows.
    2. Frozen Dual-Detector Isolation Forest anomaly classifications (Primary & Timing).
    3. Logical Sensor Node telemetry (Node 1 DHT11 & Node 2 PIR from shared ESP32).
    4. Wi-Fi Client Device Registry, traffic attribution, and unknown MAC surveillance.
    5. Deterministic Network Attack Intelligence across five threat categories.
    6. Live Collector daemon health, heartbeats, and interface diagnostics.

Architecture & Safety Principles:
  - STRICTLY READ-ONLY: Connects to the selected database in read-only URI mode.
    Never executes INSERT, UPDATE, DELETE, or DDL statements.
  - NO FABRICATED DATA: All statistics, alerts, charts, and device counts are derived
    directly from real database rows.
  - FROZEN PREDICTION CONVENTION: Respects Isolation Forest convention:
    -1 = outlier / anomaly, +1 = inlier / normal.
  - NON-BLOCKING OPERATOR ASSISTANCE: Anomaly alerts are classified as statistical
    deviations from the Session 1 baseline, NOT confirmed cyberattacks.
    Unknown devices prompt operator review and must NEVER be automatically blocked.
  - SENSOR & NETWORK INDEPENDENCE: Environmental telemetry (DHT11/PIR) is presented
    as ambient physical context, without false causal claims linking motion to network anomalies.

Launch Command:
  streamlit run src/live_dashboard.py --server.port 8502
"""

import datetime
import html as html_lib
import json
import math
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import streamlit as st

# ─────────────────────────────────────────────────────────────────────────────
# PAGE CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="IoT Network Guard | SOC Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────────────
# PATH DEFINITIONS & CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LIVE_DB_PATH = _PROJECT_ROOT / "data" / "live_monitoring.db"

# Static Collector Attribution Configuration (reference mapping in live_stream_extractor.py)
CONFIGURED_DEVICE_PROFILES: Dict[str, Dict[str, str]] = {
    "ca:34:ea:92:d3:9e": {
        "node_id": "Node_3",
        "name": "Phone 1 (Primary Client)",
        "device_type": "Phone_Client",
        "expected_ip": "192.168.137.201",
        "role": "Authorized Test Client",
    },
    "e6:2e:db:73:1c:25": {
        "node_id": "Node_4",
        "name": "Phone 2 (Secondary Client)",
        "device_type": "Phone_Client",
        "expected_ip": "192.168.137.6",
        "role": "Authorized Test Client",
    },
    "00:00:00:00:00:05": {
        "node_id": "Node_5",
        "name": "Phone 3 (Demonstration Reserve)",
        "device_type": "Phone_Client",
        "expected_ip": "192.168.137.x",
        "role": "Reserved for Live Demo",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# DESIGN SYSTEM: CYBERSECURITY SOC OBSIDIAN PALETTE & CUSTOM STYLING
# ─────────────────────────────────────────────────────────────────────────────
DARK_PALETTE = {
    "bg": "#080D18",
    "sidebar": "#070B14",
    "surface": "#111827",
    "surface_elevated": "#172235",
    "border": "#1E293B",
    "border_highlight": "#334155",
    "text": "#F1F5F9",
    "text_muted": "#94A3B8",
    "text_dim": "#64748B",
    "accent_cyan": "#22D3EE",
    "accent_blue": "#3B82F6",
    "accent_indigo": "#6366F1",
    "accent_teal": "#14B8A6",
    "alert_coral": "#F43F5E",
    "alert_crimson": "#E11D48",
    "alert_amber": "#F59E0B",
    "safe_emerald": "#10B981",
    "pink": "#FB7185",
    "purple": "#A855F7",
}

CUSTOM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    color: #F1F5F9;
}

code, pre, .mono {
    font-family: 'JetBrains Mono', monospace !important;
}

/* ──────── App Background & Atmosphere ──────── */
.stApp {
    background-color: #080D18;
    background-image:
        radial-gradient(ellipse at 15% 0%, rgba(34, 211, 238, 0.05) 0%, transparent 45%),
        radial-gradient(ellipse at 85% 5%, rgba(59, 130, 246, 0.04) 0%, transparent 45%),
        radial-gradient(circle at 50% 100%, rgba(16, 185, 129, 0.02) 0%, transparent 40%);
}

/* ──────── Sidebar SOC Styling ──────── */
section[data-testid="stSidebar"] {
    background-color: #070B14;
    border-right: 1px solid rgba(30, 41, 59, 0.8);
}

section[data-testid="stSidebar"] .stRadio > div {
    gap: 3px;
}

section[data-testid="stSidebar"] .stRadio > div > label {
    padding: 8px 12px !important;
    border-radius: 8px !important;
    font-size: 0.83rem !important;
    font-weight: 500 !important;
    transition: all 0.15s ease-in-out;
    border: 1px solid transparent;
}

section[data-testid="stSidebar"] .stRadio > div > label:hover {
    background: rgba(34, 211, 238, 0.06) !important;
    border-color: rgba(34, 211, 238, 0.2) !important;
}

/* ──────── SOC Surface Cards ──────── */
.cyber-card {
    background: rgba(17, 24, 39, 0.85);
    backdrop-filter: blur(14px);
    -webkit-backdrop-filter: blur(14px);
    border: 1px solid #1E293B;
    border-radius: 12px;
    padding: 16px 20px;
    margin-bottom: 14px;
    box-shadow: 0 4px 20px -3px rgba(0, 0, 0, 0.55);
    transition: border-color 0.2s ease, transform 0.2s ease;
}

.cyber-card:hover {
    border-color: #334155;
}

/* ──────── Metric Boxes & KPI Cards ──────── */
.metric-box {
    background: linear-gradient(135deg, rgba(23, 34, 53, 0.85) 0%, rgba(17, 24, 39, 0.95) 100%);
    border: 1px solid #1E293B;
    border-radius: 10px;
    padding: 14px 16px;
    position: relative;
    overflow: hidden;
    height: 100%;
    box-shadow: 0 2px 10px -2px rgba(0, 0, 0, 0.4);
}

.metric-box::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 3.5px;
    height: 100%;
    background: #22D3EE;
    border-radius: 3px 0 0 3px;
}

.metric-box.alert-border::before {
    background: #F43F5E;
}

.metric-box.warning-border::before {
    background: #F59E0B;
}

.metric-box.success-border::before {
    background: #10B981;
}

.metric-box.neutral-border::before {
    background: #64748B;
}

.metric-box.blue-border::before {
    background: #3B82F6;
}

.metric-label {
    font-size: 0.72rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #94A3B8;
    margin-bottom: 4px;
    display: flex;
    align-items: center;
    gap: 6px;
}

.metric-val {
    font-size: 1.5rem;
    font-weight: 700;
    font-variant-numeric: tabular-nums;
    font-family: 'JetBrains Mono', monospace;
    color: #FFFFFF;
    line-height: 1.2;
}

.metric-sub {
    font-size: 0.72rem;
    color: #64748B;
    margin-top: 5px;
    line-height: 1.35;
}

/* ──────── Refined Banners ──────── */
.archived-banner {
    background: rgba(245, 158, 11, 0.07);
    border: 1px solid rgba(245, 158, 11, 0.25);
    border-left: 4px solid #F59E0B;
    border-radius: 8px;
    padding: 12px 16px;
    margin: 6px 0 14px 0;
    color: #FEF3C7;
    font-size: 0.84rem;
    line-height: 1.45;
}

.security-banner {
    background: rgba(244, 63, 94, 0.07);
    border: 1px solid rgba(244, 63, 94, 0.25);
    border-left: 4px solid #F43F5E;
    border-radius: 8px;
    padding: 12px 16px;
    margin: 8px 0 14px 0;
    color: #FECDD3;
    font-size: 0.84rem;
    line-height: 1.45;
}

.info-banner {
    background: rgba(34, 211, 238, 0.06);
    border: 1px solid rgba(34, 211, 238, 0.22);
    border-left: 4px solid #22D3EE;
    border-radius: 8px;
    padding: 12px 16px;
    margin: 8px 0 14px 0;
    color: #CFFAFE;
    font-size: 0.84rem;
    line-height: 1.45;
}

.advisory-banner {
    background: rgba(99, 102, 241, 0.06);
    border: 1px solid rgba(99, 102, 241, 0.25);
    border-left: 4px solid #6366F1;
    border-radius: 8px;
    padding: 12px 16px;
    margin: 8px 0 14px 0;
    color: #E0E7FF;
    font-size: 0.84rem;
    line-height: 1.45;
}

/* ──────── Section Headers & Badges ──────── */
.section-header {
    font-size: 1.05rem;
    font-weight: 700;
    color: #F8FAFC;
    margin: 18px 0 12px 0;
    display: flex;
    align-items: center;
    gap: 8px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    padding-bottom: 6px;
}

.soc-badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: 0.70rem;
    font-weight: 600;
    padding: 3px 10px;
    border-radius: 20px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
}

.soc-badge-live {
    background: rgba(16, 185, 129, 0.14);
    color: #10B981;
    border: 1px solid rgba(16, 185, 129, 0.35);
}

.soc-badge-archived {
    background: rgba(245, 158, 11, 0.12);
    color: #F59E0B;
    border: 1px solid rgba(245, 158, 11, 0.35);
}

.soc-badge-neutral {
    background: rgba(100, 116, 139, 0.12);
    color: #94A3B8;
    border: 1px solid rgba(100, 116, 139, 0.35);
}

/* ──────── Data Tables ──────── */
th {
    background-color: #111827 !important;
    color: #94A3B8 !important;
    font-weight: 600 !important;
    font-size: 0.75rem !important;
    text-transform: uppercase !important;
    letter-spacing: 0.05em !important;
}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# DATABASE ACCESS LAYER (STRICTLY READ-ONLY)
# ─────────────────────────────────────────────────────────────────────────────
def get_db_connection(db_path: Path) -> Optional[sqlite3.Connection]:
    """
    Opens a read-only SQLite connection to the live monitoring database.
    Returns None if the file does not exist or cannot be accessed.
    """
    if not db_path.exists():
        return None
    try:
        uri = f"file:{db_path.resolve().as_posix()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as exc:
        st.error(f"Database read-only connection error: {exc}")
        return None


def fetch_collector_status(conn: sqlite3.Connection, run_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """Fetches the collector status record for a specific or latest run."""
    try:
        cur = conn.cursor()
        if run_id is not None:
            row = cur.execute(
                """
                SELECT run_id, started_at, last_heartbeat, interface_index,
                       interface_name, serial_port, status, stop_reason,
                       packets_parsed, windows_emitted, sensor_records
                FROM collector_status
                WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
        else:
            row = cur.execute(
                """
                SELECT run_id, started_at, last_heartbeat, interface_index,
                       interface_name, serial_port, status, stop_reason,
                       packets_parsed, windows_emitted, sensor_records
                FROM collector_status
                ORDER BY run_id DESC
                LIMIT 1
                """
            ).fetchone()
        return dict(row) if row else None
    except Exception:
        return None


def fetch_traffic_overview(conn: sqlite3.Connection, run_id: Optional[int] = None) -> Dict[str, Any]:
    """
    Computes rigorous summary statistics across live traffic windows.
    Reconciles primary, timing, and dual decision counts accurately.
    """
    try:
        cur = conn.cursor()
        filter_clause = "WHERE run_id = ?" if run_id else ""
        params: tuple = (run_id,) if run_id else ()
        and_or = "AND" if run_id else "WHERE"

        total_windows = cur.execute(f"SELECT COUNT(*) FROM live_traffic_windows {filter_clause}", params).fetchone()[0]
        total_packets = cur.execute(f"SELECT SUM(packet_count) FROM live_traffic_windows {filter_clause}", params).fetchone()[0] or 0

        # Rigorous prediction counts based on frozen Isolation Forest convention (-1 = anomaly, +1 = normal)
        prim_flags = cur.execute(
            f"SELECT COUNT(*) FROM live_traffic_windows {filter_clause} {and_or} pred_primary = -1",
            params
        ).fetchone()[0]

        timing_flags = cur.execute(
            f"SELECT COUNT(*) FROM live_traffic_windows {filter_clause} {and_or} pred_timing = -1 AND timing_status = 'ACTIVE'",
            params
        ).fetchone()[0]

        dual_flags = cur.execute(
            f"SELECT COUNT(*) FROM live_traffic_windows {filter_clause} {and_or} pred_dual = -1",
            params
        ).fetchone()[0]

        # Mutually exclusive dual_reason partition counts
        reasons_raw = cur.execute(
            f"SELECT dual_reason, COUNT(*) FROM live_traffic_windows {filter_clause} GROUP BY dual_reason",
            params
        ).fetchall()
        breakdown = {r[0]: r[1] for r in reasons_raw}

        # Observed clients in actual traffic
        client_rows = cur.execute(
            f"""
            SELECT client_mac, node_id, COUNT(*) AS window_count,
                   MIN(window_start_utc) AS first_seen, MAX(window_start_utc) AS last_seen,
                   SUM(packet_count) AS packet_count, AVG(packet_rate) AS avg_packet_rate
            FROM live_traffic_windows
            {filter_clause}
            GROUP BY client_mac, node_id
            ORDER BY node_id
            """,
            params
        ).fetchall()
        observed_clients = [dict(r) for r in client_rows]

        latest_ts = cur.execute(
            f"SELECT MAX(window_start_utc) FROM live_traffic_windows {filter_clause}",
            params
        ).fetchone()[0]

        rate_stats = cur.execute(
            f"SELECT AVG(packet_rate), MAX(packet_rate) FROM live_traffic_windows {filter_clause}",
            params
        ).fetchone()
        avg_rate = rate_stats[0] or 0.0
        peak_rate = rate_stats[1] or 0.0

        anomaly_pct = (dual_flags / total_windows * 100.0) if total_windows > 0 else 0.0

        return {
            "total_windows": total_windows,
            "total_packets": total_packets,
            "anomaly_windows": dual_flags,
            "primary_flags": prim_flags,
            "timing_flags": timing_flags,
            "anomaly_pct": anomaly_pct,
            "observed_clients": observed_clients,
            "latest_window_utc": latest_ts or "None",
            "breakdown": breakdown,
            "avg_rate": avg_rate,
            "peak_rate": peak_rate,
        }
    except Exception:
        return {
            "total_windows": 0, "total_packets": 0, "anomaly_windows": 0,
            "primary_flags": 0, "timing_flags": 0, "anomaly_pct": 0.0,
            "observed_clients": [], "latest_window_utc": "None", "breakdown": {},
            "avg_rate": 0.0, "peak_rate": 0.0,
        }


def fetch_recent_windows(
    conn: sqlite3.Connection,
    limit: int = 300,
    node_id: Optional[str] = None,
    run_id: Optional[int] = None,
) -> pd.DataFrame:
    """Fetches completed 1-second feature windows as a Pandas DataFrame."""
    try:
        clauses = []
        params = []
        if run_id:
            clauses.append("run_id = ?")
            params.append(run_id)
        if node_id and node_id != "All Nodes":
            clauses.append("node_id = ?")
            params.append(node_id)

        where_str = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        query = f"""
            SELECT window_id, run_id, client_mac, node_id, bin_start_epoch,
                   window_start_utc, packet_count, packet_rate,
                   mean_packet_size, packet_size_std, mean_IAT, IAT_std,
                   score_primary, pred_primary, score_timing, pred_timing,
                   timing_status, pred_dual, dual_reason, created_at
            FROM live_traffic_windows
            {where_str}
            ORDER BY bin_start_epoch ASC
            LIMIT ?
        """
        params.append(limit)
        df = pd.read_sql_query(query, conn, params=params)
        return df
    except Exception as exc:
        st.warning(f"Error fetching traffic windows: {exc}")
        return pd.DataFrame()


def fetch_alerts(
    conn: sqlite3.Connection,
    limit: int = 100,
    run_id: Optional[int] = None,
) -> pd.DataFrame:
    """Fetches statistical anomaly alert records."""
    try:
        if run_id:
            query = """
                SELECT alert_id, window_id, run_id, client_mac, node_id,
                       bin_start_epoch, window_start_utc, dual_reason,
                       score_primary, score_timing, packet_rate,
                       mean_packet_size, packet_count, acknowledged, created_at
                FROM live_alerts
                WHERE run_id = ?
                ORDER BY alert_id DESC
                LIMIT ?
            """
            df = pd.read_sql_query(query, conn, params=(run_id, limit))
        else:
            query = """
                SELECT alert_id, window_id, run_id, client_mac, node_id,
                       bin_start_epoch, window_start_utc, dual_reason,
                       score_primary, score_timing, packet_rate,
                       mean_packet_size, packet_count, acknowledged, created_at
                FROM live_alerts
                ORDER BY alert_id DESC
                LIMIT ?
            """
            df = pd.read_sql_query(query, conn, params=(limit,))
        return df
    except Exception:
        return pd.DataFrame()


def fetch_sensor_telemetry(
    conn: sqlite3.Connection,
    limit: int = 200,
    run_id: Optional[int] = None,
) -> pd.DataFrame:
    """Fetches Node 1 (DHT11) temperature and humidity readings."""
    try:
        if run_id:
            query = """
                SELECT telemetry_id, run_id, physical_node_id, logical_node_id,
                       sequence_num, uptime_ms, temperature_c, humidity_pct,
                       dht_valid, captured_at, sensor_epoch
                FROM live_sensor_telemetry
                WHERE run_id = ?
                ORDER BY telemetry_id ASC
                LIMIT ?
            """
            df = pd.read_sql_query(query, conn, params=(run_id, limit))
        else:
            query = """
                SELECT telemetry_id, run_id, physical_node_id, logical_node_id,
                       sequence_num, uptime_ms, temperature_c, humidity_pct,
                       dht_valid, captured_at, sensor_epoch
                FROM live_sensor_telemetry
                ORDER BY telemetry_id ASC
                LIMIT ?
            """
            df = pd.read_sql_query(query, conn, params=(limit,))
        return df
    except Exception:
        return pd.DataFrame()


def fetch_pir_events(
    conn: sqlite3.Connection,
    limit: int = 200,
    run_id: Optional[int] = None,
) -> pd.DataFrame:
    """Fetches Node 2 (PIR) motion event telemetry."""
    try:
        if run_id:
            query = """
                SELECT pir_id, run_id, physical_node_id, logical_node_id,
                       sequence_num, uptime_ms, motion_detected, captured_at, sensor_epoch
                FROM live_pir_events
                WHERE run_id = ?
                ORDER BY pir_id ASC
                LIMIT ?
            """
            df = pd.read_sql_query(query, conn, params=(run_id, limit))
        else:
            query = """
                SELECT pir_id, run_id, physical_node_id, logical_node_id,
                       sequence_num, uptime_ms, motion_detected, captured_at, sensor_epoch
                FROM live_pir_events
                ORDER BY pir_id ASC
                LIMIT ?
            """
            df = pd.read_sql_query(query, conn, params=(limit,))
        return df
    except Exception:
        return pd.DataFrame()


def fetch_unknown_devices(conn: sqlite3.Connection, run_id: Optional[int] = None) -> pd.DataFrame:
    """Fetches observations of unregistered MAC addresses."""
    try:
        if run_id:
            query = """
                SELECT obs_id, run_id, observed_mac, first_seen_utc,
                       last_seen_utc, observation_count, acknowledged
                FROM unknown_device_obs
                WHERE run_id = ?
                ORDER BY observation_count DESC, last_seen_utc DESC
            """
            df = pd.read_sql_query(query, conn, params=(run_id,))
        else:
            query = """
                SELECT obs_id, run_id, observed_mac, first_seen_utc,
                       last_seen_utc, observation_count, acknowledged
                FROM unknown_device_obs
                ORDER BY observation_count DESC, last_seen_utc DESC
            """
            df = pd.read_sql_query(query, conn)
        return df
    except Exception:
        return pd.DataFrame()


def fetch_attack_events(
    conn: sqlite3.Connection,
    limit: int = 200,
    run_id: Optional[int] = None,
) -> pd.DataFrame:
    """Fetches explainable network attack detection events from live_attack_events."""
    try:
        if run_id:
            query = """
                SELECT event_id, run_id, window_id, timestamp_epoch, timestamp_utc,
                       category, status, severity, confidence, source_mac, target_ip,
                       evidence_json, missing_fields_json, recommended_action,
                       acknowledged, created_at
                FROM live_attack_events
                WHERE run_id = ?
                ORDER BY event_id DESC
                LIMIT ?
            """
            df = pd.read_sql_query(query, conn, params=(run_id, limit))
        else:
            query = """
                SELECT event_id, run_id, window_id, timestamp_epoch, timestamp_utc,
                       category, status, severity, confidence, source_mac, target_ip,
                       evidence_json, missing_fields_json, recommended_action,
                       acknowledged, created_at
                FROM live_attack_events
                ORDER BY event_id DESC
                LIMIT ?
            """
            df = pd.read_sql_query(query, conn, params=(limit,))
        return df
    except Exception:
        return pd.DataFrame()


CATEGORY_CONFIG = {
    "dos": {
        "title": "1. Denial of Service",
        "icon": "🔥",
        "aliases": ["Denial_of_Service", "DOS", "dos", "denial_of_service"],
        "default_sub": "Multi-window (≥3s) • Target conc. ≥75%",
    },
    "port_scan": {
        "title": "2. Reconnaissance",
        "icon": "🔍",
        "aliases": ["Reconnaissance_Port_Scan", "PORT_SCAN", "port_scan", "reconnaissance_port_scan"],
        "default_sub": "Transport ports & SYN flags • Horizontal/vertical sweeps",
    },
    "spoofing": {
        "title": "3. Spoofing / Impersonation",
        "icon": "🎭",
        "aliases": ["Spoofing_Impersonation", "SPOOFING", "spoofing", "spoofing_impersonation"],
        "default_sub": "Conflicting IP-to-MAC • Gateway IP theft",
    },
    "deauth": {
        "title": "4. Wi-Fi Deauth Flood",
        "icon": "📡",
        "aliases": ["Deauthentication_Disassociation_Abuse", "DEAUTH_FLOOD", "deauth_flood", "deauth", "deauthentication_disassociation_abuse"],
        "default_sub": "ESP32 802.11 mgmt sniffer • ≥5 frames/s",
    },
    "replay": {
        "title": "5. Replay Attack",
        "icon": "🔄",
        "aliases": ["Replay_Attack", "REPLAY", "replay", "replay_attack"],
        "default_sub": "Cryptographic nonces & TCP flow sequence tracking",
    },
}


def _is_heartbeat_stale(
    last_heartbeat_raw: Any,
    timeout_seconds: float = 60.0,
) -> Tuple[bool, Optional[float]]:
    """
    Checks if a collector heartbeat timestamp is older than timeout_seconds.
    Returns (is_stale, age_seconds).
    Conservative safety: returns (True, None) if heartbeat is None, empty, or unparseable.
    """
    if not last_heartbeat_raw:
        return True, None
    try:
        clean_str = str(last_heartbeat_raw).strip().replace("T", " ")[:19]
        hb_dt = datetime.datetime.strptime(clean_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=datetime.timezone.utc)
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        age = (now_utc - hb_dt).total_seconds()
        if age < 0:
            return False, 0.0
        return age > timeout_seconds, age
    except Exception:
        return True, None


def compute_attack_category_status(
    conn: Optional[sqlite3.Connection],
    run_id: Optional[int] = None,
) -> Dict[str, Dict[str, Any]]:
    """
    Computes rigorous, database-driven operational statuses across all five attack categories.

    Distinguishes strictly:
      - DETECTED: Persisted attack event (SUSPICIOUS or CONFIRMED_THREAT, severity != NONE).
      - NO ALERT OBSERVED: Required telemetry is active and verified, but no attack flagged.
      - INSUFFICIENT TELEMETRY: Required telemetry headers or hardware source unavailable.
      - MONITORING UNAVAILABLE: Collector daemon offline/error/stale, or database empty.

    Safety: Does not claim false certainty, never confuses statistical anomalies with
    attacks, scopes all evaluations to effective_run_id, and strictly excludes startup
    capability seed records.
    """
    results: Dict[str, Dict[str, Any]] = {}
    default_unavailable = {
        "status": "MONITORING UNAVAILABLE",
        "color": DARK_PALETTE["text_dim"],
        "border_cls": "neutral-border",
        "sub": "Collector inactive • No session records",
        "detected_count": 0,
        "latest_utc": None,
        "effective_run_id": None,
        "is_live": False,
    }

    if conn is None:
        for cat_k, cfg in CATEGORY_CONFIG.items():
            results[cat_k] = dict(default_unavailable, title=cfg["title"], icon=cfg.get("icon", "🛡️"))
        return results

    try:
        cur = conn.cursor()

        # 1. Inspect collector status & resolve effective_run_id
        status_row = None
        try:
            if run_id is not None:
                cur.execute(
                    "SELECT run_id, status, serial_port, packets_parsed, last_heartbeat FROM collector_status WHERE run_id = ?",
                    (run_id,),
                )
            else:
                cur.execute(
                    "SELECT run_id, status, serial_port, packets_parsed, last_heartbeat FROM collector_status ORDER BY run_id DESC LIMIT 1"
                )
            status_row = cur.fetchone()
        except Exception:
            status_row = None

        effective_run_id = run_id if run_id is not None else (status_row[0] if status_row else None)
        filter_clause = f"WHERE run_id = {effective_run_id}" if effective_run_id is not None else ""

        total_windows = 0
        total_packets = 0
        try:
            w_row = cur.execute(f"SELECT COUNT(*), SUM(packet_count) FROM live_traffic_windows {filter_clause}").fetchone()
            if w_row:
                total_windows = w_row[0] or 0
                total_packets = w_row[1] or 0
        except Exception:
            pass

        if not status_row and total_windows == 0:
            for cat_k, cfg in CATEGORY_CONFIG.items():
                results[cat_k] = dict(default_unavailable, title=cfg["title"], icon=cfg.get("icon", "🛡️"), effective_run_id=effective_run_id)
            return results

        daemon_status = status_row[1] if status_row else "OFFLINE"
        serial_port = status_row[2] if status_row else None
        last_heartbeat = status_row[4] if status_row and len(status_row) > 4 else None

        # Staleness check: If collector is marked RUNNING, verify heartbeat freshness
        if daemon_status == "RUNNING":
            is_stale_hb, hb_age = _is_heartbeat_stale(last_heartbeat, timeout_seconds=60.0)
            if is_stale_hb:
                sub_msg = f"Collector heartbeat stale ({int(hb_age)}s ago > 60s timeout)" if hb_age is not None else "Collector heartbeat missing or unparseable"
                for cat_k, cfg in CATEGORY_CONFIG.items():
                    results[cat_k] = dict(
                        default_unavailable,
                        title=cfg["title"],
                        icon=cfg.get("icon", "🛡️"),
                        status="MONITORING UNAVAILABLE",
                        border_cls="neutral-border",
                        sub=f"Monitoring unavailable • {sub_msg}",
                        effective_run_id=effective_run_id,
                        is_live=False,
                    )
                return results

        if daemon_status in ("ERROR", "OFFLINE") and total_windows == 0:
            for cat_k, cfg in CATEGORY_CONFIG.items():
                results[cat_k] = dict(
                    default_unavailable,
                    title=cfg["title"],
                    icon=cfg.get("icon", "🛡️"),
                    sub=f"Collector {daemon_status} • No traffic windows",
                    effective_run_id=effective_run_id,
                    is_live=False,
                )
            return results

        is_live = (daemon_status == "RUNNING")
        session_tag = "[Live Session]" if is_live else (f"[Archived Session #{effective_run_id}]" if effective_run_id is not None else "[Archived Session]")

        # 2. Check registered IPs in device_registry and IP traffic observations for Spoofing
        reg_ip_count = 0
        try:
            cols = [col[1] for col in cur.execute("PRAGMA table_info(device_registry)").fetchall()]
            if "ip_address" in cols:
                reg_row = cur.execute(
                    "SELECT COUNT(*) FROM device_registry WHERE ip_address IS NOT NULL AND TRIM(ip_address) != ''"
                ).fetchone()
                reg_ip_count = reg_row[0] if reg_row else 0
        except Exception:
            reg_ip_count = 0

        has_ip_traffic_obs = False
        try:
            and_or_ip = "AND" if effective_run_id is not None else "WHERE"
            ip_obs_row = cur.execute(
                f"""
                SELECT COUNT(*) FROM live_attack_events
                {filter_clause} {and_or_ip}
                (target_ip IS NOT NULL AND TRIM(target_ip) != '')
                """
            ).fetchone()
            if ip_obs_row and ip_obs_row[0] > 0:
                has_ip_traffic_obs = True
        except Exception:
            pass

        # 3. Query live_attack_events scoped to effective_run_id
        attack_rows = []
        try:
            cur.execute(
                f"""
                SELECT event_id, category, status, severity, confidence, timestamp_utc,
                       evidence_json, missing_fields_json, source_mac, target_ip
                FROM live_attack_events
                {filter_clause}
                ORDER BY event_id DESC
                """
            )
            attack_rows = cur.fetchall()
        except Exception:
            attack_rows = []

        for cat_k, cfg in CATEGORY_CONFIG.items():
            aliases = [a.lower() for a in cfg["aliases"]]
            cat_events = [r for r in attack_rows if str(r[1]).lower() in aliases]

            # Separate true detected threats from startup/baseline capability records
            detected_threats = [
                r for r in cat_events
                if str(r[2]).upper() in ("CONFIRMED_THREAT", "SUSPICIOUS")
                and (r[3] and str(r[3]).upper() != "NONE")
                and (r[4] is not None and float(r[4]) > 0.0)
            ]

            insufficient_records = [
                r for r in cat_events
                if str(r[2]).upper() == "INSUFFICIENT_TELEMETRY"
            ]

            if detected_threats:
                cnt = len(detected_threats)
                latest_utc = detected_threats[0][5] or "Recent"
                results[cat_k] = {
                    "title": cfg["title"],
                    "icon": cfg.get("icon", "🛡️"),
                    "status": "DETECTED",
                    "color": DARK_PALETTE["alert_coral"],
                    "border_cls": "alert-border",
                    "sub": f"🚨 {cnt} Threat(s) Flagged {session_tag} • Latest: {latest_utc}",
                    "detected_count": cnt,
                    "latest_utc": latest_utc,
                    "effective_run_id": effective_run_id,
                    "is_live": is_live,
                }
                continue

            # No detected attack -> determine telemetry availability
            if cat_k == "dos":
                if total_windows >= 3:
                    results[cat_k] = {
                        "title": cfg["title"],
                        "icon": cfg.get("icon", "🛡️"),
                        "status": "NO ALERT OBSERVED",
                        "color": DARK_PALETTE["safe_emerald"],
                        "border_cls": "success-border",
                        "sub": f"Multi-window evaluation active ({total_windows} windows) • No DoS alert",
                        "detected_count": 0,
                        "latest_utc": None,
                        "effective_run_id": effective_run_id,
                        "is_live": is_live,
                    }
                else:
                    results[cat_k] = {
                        "title": cfg["title"],
                        "icon": cfg.get("icon", "🛡️"),
                        "status": "INSUFFICIENT TELEMETRY",
                        "color": DARK_PALETTE["alert_amber"],
                        "border_cls": "warning-border",
                        "sub": f"Requires ≥3 consecutive windows (accumulated: {total_windows})",
                        "detected_count": 0,
                        "latest_utc": None,
                        "effective_run_id": effective_run_id,
                        "is_live": is_live,
                    }

            elif cat_k == "port_scan":
                if total_packets > 0 and not insufficient_records:
                    results[cat_k] = {
                        "title": cfg["title"],
                        "icon": cfg.get("icon", "🛡️"),
                        "status": "NO ALERT OBSERVED",
                        "color": DARK_PALETTE["safe_emerald"],
                        "border_cls": "success-border",
                        "sub": "Transport port & flag inspection active • No scan alert",
                        "detected_count": 0,
                        "latest_utc": None,
                        "effective_run_id": effective_run_id,
                        "is_live": is_live,
                    }
                else:
                    results[cat_k] = {
                        "title": cfg["title"],
                        "icon": cfg.get("icon", "🛡️"),
                        "status": "INSUFFICIENT TELEMETRY",
                        "color": DARK_PALETTE["alert_amber"],
                        "border_cls": "warning-border",
                        "sub": "Transport port headers (tcp.dstport, flags) unavailable",
                        "detected_count": 0,
                        "latest_utc": None,
                        "effective_run_id": effective_run_id,
                        "is_live": is_live,
                    }

            elif cat_k == "spoofing":
                has_spoofing_telemetry = (reg_ip_count > 0) or has_ip_traffic_obs
                if not has_spoofing_telemetry:
                    for r in cat_events:
                        target_ip = r[9] if len(r) > 9 else None
                        if target_ip and str(target_ip).strip() != "":
                            has_spoofing_telemetry = True
                            break
                        ev_raw = r[6]
                        if ev_raw:
                            try:
                                ev = json.loads(ev_raw) if isinstance(ev_raw, str) else ev_raw
                                if isinstance(ev, dict) and (ev.get("ip") or ev.get("claimed_ip") or ev.get("conflicting_mac")):
                                    has_spoofing_telemetry = True
                                    break
                            except Exception:
                                pass

                if has_spoofing_telemetry and total_packets > 0:
                    sub_text = f"IP-to-MAC mapping active ({reg_ip_count} registered IPs) • No spoofing alert" if reg_ip_count > 0 else "IP-to-MAC traffic correlation active • No spoofing alert"
                    results[cat_k] = {
                        "title": cfg["title"],
                        "icon": cfg.get("icon", "🛡️"),
                        "status": "NO ALERT OBSERVED",
                        "color": DARK_PALETTE["safe_emerald"],
                        "border_cls": "success-border",
                        "sub": sub_text,
                        "detected_count": 0,
                        "latest_utc": None,
                        "effective_run_id": effective_run_id,
                        "is_live": is_live,
                    }
                else:
                    results[cat_k] = {
                        "title": cfg["title"],
                        "icon": cfg.get("icon", "🛡️"),
                        "status": "INSUFFICIENT TELEMETRY",
                        "color": DARK_PALETTE["alert_amber"],
                        "border_cls": "warning-border",
                        "sub": "Requires registered IP-to-MAC baseline mapping or observed IP traffic",
                        "detected_count": 0,
                        "latest_utc": None,
                        "effective_run_id": effective_run_id,
                        "is_live": is_live,
                    }

            elif cat_k == "deauth":
                deauth_operational_rows = [
                    r for r in cat_events
                    if str(r[2]).upper() not in ("INSUFFICIENT_TELEMETRY",)
                ]
                if deauth_operational_rows:
                    results[cat_k] = {
                        "title": cfg["title"],
                        "icon": cfg.get("icon", "🛡️"),
                        "status": "NO ALERT OBSERVED",
                        "color": DARK_PALETTE["safe_emerald"],
                        "border_cls": "success-border",
                        "sub": "ESP32 802.11 mgmt sniffer telemetry verified • No deauth flood flagged",
                        "detected_count": 0,
                        "latest_utc": None,
                        "effective_run_id": effective_run_id,
                        "is_live": is_live,
                    }
                else:
                    results[cat_k] = {
                        "title": cfg["title"],
                        "icon": cfg.get("icon", "🛡️"),
                        "status": "INSUFFICIENT TELEMETRY",
                        "color": DARK_PALETTE["text_muted"],
                        "border_cls": "neutral-border",
                        "sub": "ESP32 802.11 sniffer telemetry unavailable • NDIS filters mgmt frames",
                        "detected_count": 0,
                        "latest_utc": None,
                        "effective_run_id": effective_run_id,
                        "is_live": is_live,
                    }

            elif cat_k == "replay":
                has_crypto_telemetry = False
                for r in cat_events:
                    ev_raw = r[6]
                    if ev_raw:
                        try:
                            ev = json.loads(ev_raw) if isinstance(ev_raw, str) else ev_raw
                            if isinstance(ev, dict):
                                if ev.get("payload_hash") or ev.get("nonce") or ev.get("has_payload_hash") or ev.get("has_nonce") or ev.get("crypto_telemetry"):
                                    has_crypto_telemetry = True
                                    break
                        except Exception:
                            pass

                if has_crypto_telemetry and not insufficient_records:
                    results[cat_k] = {
                        "title": cfg["title"],
                        "icon": cfg.get("icon", "🛡️"),
                        "status": "NO ALERT OBSERVED",
                        "color": DARK_PALETTE["safe_emerald"],
                        "border_cls": "success-border",
                        "sub": "Flow cryptographic nonce & payload hash tracking active • No replay flagged",
                        "detected_count": 0,
                        "latest_utc": None,
                        "effective_run_id": effective_run_id,
                        "is_live": is_live,
                    }
                else:
                    results[cat_k] = {
                        "title": cfg["title"],
                        "icon": cfg.get("icon", "🛡️"),
                        "status": "INSUFFICIENT TELEMETRY",
                        "color": DARK_PALETTE["text_muted"],
                        "border_cls": "neutral-border",
                        "sub": "Cryptographic nonces/payload hashes required • Not in default stream",
                        "detected_count": 0,
                        "latest_utc": None,
                        "effective_run_id": effective_run_id,
                        "is_live": is_live,
                    }

    except Exception as e:
        for cat_k, cfg in CATEGORY_CONFIG.items():
            results[cat_k] = dict(
                default_unavailable,
                title=cfg["title"],
                icon=cfg.get("icon", "🛡️"),
                sub=f"Query error: {str(e)[:40]}",
                effective_run_id=effective_run_id if 'effective_run_id' in locals() else run_id,
            )

    return results


def fetch_esp32_sniffer_diagnostics(
    conn: Optional[sqlite3.Connection],
    run_id: Optional[int] = None,
    in_memory_summary: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Gathers diagnostic information about the ESP32 Wi-Fi sniffer and hardware telemetry.
    Adheres strictly to telemetry honesty: does not invent zero values for unpersisted
    in-memory periodic summary counters.
    """
    diag: Dict[str, Any] = {
        "serial_port": "Unavailable",
        "connection_status": "Disconnected",
        "physical_device": "Unknown Device",
        "node_id": "None",
        "last_seen_utc": "Never",
        "is_stale": False,
        "total_sensor_records": 0,
        "wifi_channel": "Unavailable",
        "boot_id": "Unavailable",
        "raw_callbacks": "Unavailable (in-memory only)",
        "valid_frames": "Unavailable (in-memory only)",
        "unsupported_mgmt": "Unavailable (in-memory only)",
        "malformed_frames": "Unavailable (in-memory only)",
        "tb_suppressed": "Unavailable (in-memory only)",
        "queue_dropped": "Unavailable (in-memory only)",
        "enqueued_events": "Unavailable (in-memory only)",
        "last_summary_utc": "Never",
        "deauth_events_persisted": 0,
        "effective_run_id": run_id,
    }

    if in_memory_summary:
        diag["boot_id"] = str(in_memory_summary.get("boot_id", "Unavailable"))
        diag["wifi_channel"] = str(in_memory_summary.get("channel", in_memory_summary.get("wifi_channel", "Unavailable")))
        diag["last_summary_utc"] = str(in_memory_summary.get("timestamp_utc", "Recent (in-memory)"))
        cum = in_memory_summary.get("cumulative", {})
        if isinstance(cum, dict):
            diag["raw_callbacks"] = str(cum.get("rx_total", cum.get("raw_callbacks", "Not reported")))
            diag["valid_frames"] = str(cum.get("enqueued", cum.get("valid_frames", "Not reported")))
            diag["unsupported_mgmt"] = str(cum.get("unsupported_mgmt", "Not reported"))
            diag["malformed_frames"] = str(cum.get("malformed_rx", cum.get("malformed_mgmt", "Not reported")))
            diag["tb_suppressed"] = str(cum.get("tb_suppressed", "Not reported"))
            diag["queue_dropped"] = str(cum.get("queue_dropped", "Not reported"))
            diag["enqueued_events"] = str(cum.get("enqueued", "Not reported"))

    if conn is None:
        return diag

    try:
        cur = conn.cursor()

        # Resolve effective_run_id consistently:
        effective_run_id = run_id
        if effective_run_id is None:
            try:
                st_r = cur.execute("SELECT run_id FROM collector_status ORDER BY run_id DESC LIMIT 1").fetchone()
                if st_r:
                    effective_run_id = st_r[0]
            except Exception:
                effective_run_id = None

        diag["effective_run_id"] = effective_run_id
        filter_clause = f"WHERE run_id = {effective_run_id}" if effective_run_id is not None else ""

        # 1. Collector status record
        c_row = None
        try:
            if effective_run_id is not None:
                c_row = cur.execute("SELECT serial_port, status, last_heartbeat FROM collector_status WHERE run_id = ?", (effective_run_id,)).fetchone()
            else:
                c_row = cur.execute("SELECT serial_port, status, last_heartbeat FROM collector_status ORDER BY run_id DESC LIMIT 1").fetchone()
        except Exception:
            c_row = None

        daemon_running = False
        if c_row:
            port = c_row[0]
            diag["serial_port"] = port if (port and str(port).lower() != "none") else "Disabled (--no-sensors)"
            daemon_status = c_row[1]
            daemon_running = (daemon_status == "RUNNING")
            last_hb = c_row[2] if len(c_row) > 2 else None
            is_stale_hb, _ = _is_heartbeat_stale(last_hb, timeout_seconds=60.0)

            if port and str(port).lower() not in ("none", "disabled", ""):
                if daemon_running:
                    diag["connection_status"] = "Heartbeat Stale / Inactive" if is_stale_hb else "Active"
                else:
                    diag["connection_status"] = "Archived / Inactive"

        # 2. Latest physical sensor telemetry
        try:
            s_row = cur.execute(
                f"""
                SELECT physical_node_id, logical_node_id, captured_at, sensor_epoch
                FROM live_sensor_telemetry
                {filter_clause}
                ORDER BY telemetry_id DESC
                LIMIT 1
                """
            ).fetchone()
            if s_row:
                diag["physical_device"] = s_row[0] or "ESP32 Sensor Node"
                diag["node_id"] = s_row[1] or "Node_1"
                diag["last_seen_utc"] = s_row[2] or "N/A"
                if s_row[3]:
                    now_epoch = time.time()
                    diag["is_stale"] = (now_epoch - float(s_row[3]) > 30.0) if daemon_running else False
                else:
                    diag["is_stale"] = False
        except Exception:
            pass

        try:
            cnt_row = cur.execute(f"SELECT COUNT(*) FROM live_sensor_telemetry {filter_clause}").fetchone()
            diag["total_sensor_records"] = cnt_row[0] if cnt_row else 0
        except Exception:
            pass

        # 3. Deauth attack events persisted
        try:
            aliases_deauth = ("'deauthentication_disassociation_abuse'", "'deauth_flood'", "'deauth'")
            and_or = "AND" if effective_run_id is not None else "WHERE"
            d_row = cur.execute(
                f"""
                SELECT COUNT(*), evidence_json
                FROM live_attack_events
                {filter_clause} {and_or} LOWER(category) IN ({','.join(aliases_deauth)})
                """
            ).fetchone()
            if d_row:
                diag["deauth_events_persisted"] = d_row[0] or 0
        except Exception:
            pass

    except Exception:
        pass

    return diag


def plotly_cyber_layout(
    title: str = "",
    height: int = 320,
    xaxis_title: str = "",
    yaxis_title: str = "",
    show_legend: bool = True,
) -> go.Layout:
    """Returns a unified, clean dark layout configuration for Plotly charts."""
    return go.Layout(
        title=dict(
            text=f"<b>{title}</b>" if title else "",
            font=dict(family="Inter, sans-serif", size=13, color=DARK_PALETTE["text"]),
            x=0.01,
            y=0.97,
        ),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(17, 24, 39, 0.4)",
        font=dict(family="Inter, sans-serif", size=11, color=DARK_PALETTE["text_muted"]),
        height=height,
        margin=dict(l=48, r=20, t=38, b=42),
        xaxis=dict(
            title=dict(text=xaxis_title, font=dict(size=11, color=DARK_PALETTE["text_dim"])),
            gridcolor="rgba(255, 255, 255, 0.05)",
            linecolor="rgba(255, 255, 255, 0.08)",
            zerolinecolor="rgba(255, 255, 255, 0.08)",
            tickfont=dict(family="JetBrains Mono", size=10, color=DARK_PALETTE["text_dim"]),
        ),
        yaxis=dict(
            title=dict(text=yaxis_title, font=dict(size=11, color=DARK_PALETTE["text_dim"])),
            gridcolor="rgba(255, 255, 255, 0.05)",
            linecolor="rgba(255, 255, 255, 0.08)",
            zerolinecolor="rgba(255, 255, 255, 0.08)",
            tickfont=dict(family="JetBrains Mono", size=10, color=DARK_PALETTE["text_dim"]),
        ),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1.0,
            font=dict(size=10, color=DARK_PALETTE["text_muted"]),
            bgcolor="rgba(0,0,0,0)",
        ) if show_legend else dict(visible=False),
        hovermode="x unified",
        hoverlabel=dict(
            bgcolor=DARK_PALETTE["surface_elevated"],
            bordercolor=DARK_PALETTE["accent_cyan"],
            font=dict(family="Inter", size=11, color="#FFFFFF"),
        ),
    )


# ─────────────────────────────────────────────────────────────────────────────
# VIEW 1: SYSTEM OVERVIEW & LIVE FEED
# ─────────────────────────────────────────────────────────────────────────────
def render_system_overview(conn: sqlite3.Connection, run_id: Optional[int]):
    """Renders the executive summary KPI cards, live traffic stream, and alert breakdown."""
    overview = fetch_traffic_overview(conn, run_id)
    status = fetch_collector_status(conn, run_id=run_id)
    alerts_df = fetch_alerts(conn, limit=8, run_id=run_id)
    sensor_df = fetch_sensor_telemetry(conn, limit=1, run_id=run_id)
    pir_df = fetch_pir_events(conn, limit=1, run_id=run_id)
    unknown_df = fetch_unknown_devices(conn, run_id=run_id)

    st_raw = status["status"] if status else "OFFLINE"
    is_stopped = (st_raw == "STOPPED")
    is_running = (st_raw == "RUNNING")
    cur_run_id = status["run_id"] if status else None

    # Header Ribbon
    header_col1, header_col2 = st.columns([3, 1])
    with header_col1:
        st.markdown(
            f"""
            <div style="margin-bottom: 4px;">
                <div style="font-size: 1.35rem; font-weight: 800; color: #FFFFFF; letter-spacing: -0.02em;">
                    🛡️ System Overview & Live Telemetry Feed
                </div>
                <div style="font-size: 0.78rem; color: #94A3B8; margin-top: 2px;">
                    IoT Network Guard • Dual-Detector Security Operations Center Console
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with header_col2:
        if is_running:
            badge_html = '<span class="soc-badge soc-badge-live">● Live Stream Active</span>'
        elif is_stopped:
            badge_html = f'<span class="soc-badge soc-badge-archived">◼ Run #{cur_run_id} • Archived</span>'
        else:
            badge_html = '<span class="soc-badge soc-badge-neutral">○ Daemon Offline</span>'
        ts_now = datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S UTC")
        st.markdown(
            f"""
            <div style="text-align: right; padding-top: 4px;">
                {badge_html}<br>
                <span style="font-size: 0.70rem; color: #64748B;">Console Clock: {ts_now}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Inactive / Archived Collector Banner
    if is_stopped and status:
        st.markdown(
            f"""
            <div class="archived-banner">
                <b>⏸️ Collector Daemon Inactive (Archived Session):</b>
                Gracefully stopped via <code>{status.get('stop_reason', 'SIGINT')}</code> at <b>{status.get('last_heartbeat', 'N/A')} UTC</b>.
                All <b>{overview['total_windows']:,}</b> traffic feature windows and <b>{overview['anomaly_windows']}</b> statistical alerts
                below represent completed, persisted data from <b>Run #{cur_run_id}</b> on adapter <code>{status.get('interface_name', 'Unknown')}</code>.
            </div>
            """,
            unsafe_allow_html=True,
        )

    # 1. Top KPI Metric Ribbon (6 Cards)
    k1, k2, k3, k4, k5, k6 = st.columns(6)

    with k1:
        if is_running:
            s_title = "STREAMING"
            b_cls = "success-border"
            s_sub = f"Run #{cur_run_id} • Heartbeat Active"
        elif is_stopped:
            s_title = "STOPPED"
            b_cls = "warning-border"
            s_sub = f"Run #{cur_run_id} • Persisted Archive"
        else:
            s_title = "OFFLINE"
            b_cls = "neutral-border"
            s_sub = "Daemon Not Initialized"

        st.markdown(
            f"""
            <div class="metric-box {b_cls}">
                <div class="metric-label">⚡ Collector State</div>
                <div class="metric-val">{s_title}</div>
                <div class="metric-sub">{s_sub}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with k2:
        st.markdown(
            f"""
            <div class="metric-box blue-border">
                <div class="metric-label">📦 Total Packets</div>
                <div class="metric-val">{overview['total_packets']:,}</div>
                <div class="metric-sub">{overview['total_windows']:,} Windows Processed</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with k3:
        st.markdown(
            f"""
            <div class="metric-box">
                <div class="metric-label">📊 1s Traffic Windows</div>
                <div class="metric-val">{overview['total_windows']:,}</div>
                <div class="metric-sub">{len(overview['observed_clients'])} Active Phone Client(s)</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with k4:
        anom_border = "alert-border" if overview["anomaly_windows"] > 0 else "success-border"
        st.markdown(
            f"""
            <div class="metric-box {anom_border}">
                <div class="metric-label">⚠️ Statistical Alerts</div>
                <div class="metric-val">{overview['anomaly_windows']:,}</div>
                <div class="metric-sub">{overview['anomaly_pct']:.2f}% Anomaly Ratio (Dual IF)</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with k5:
        reg_count = len(CONFIGURED_DEVICE_PROFILES)
        st.markdown(
            f"""
            <div class="metric-box blue-border">
                <div class="metric-label">📱 Registered Devices</div>
                <div class="metric-val">{reg_count}</div>
                <div class="metric-sub">{len(overview['observed_clients'])} Observed in Traffic</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with k6:
        temp_val = f"{sensor_df['temperature_c'].iloc[-1]:.1f}°C" if not sensor_df.empty and pd.notnull(sensor_df['temperature_c'].iloc[-1]) else "—"
        hum_val = f"{sensor_df['humidity_pct'].iloc[-1]:.0f}%" if not sensor_df.empty and pd.notnull(sensor_df['humidity_pct'].iloc[-1]) else "—"
        motion_state = "MOTION" if (not pir_df.empty and pir_df['motion_detected'].iloc[-1] == 1) else "CLEAR"
        motion_color = DARK_PALETTE["alert_coral"] if motion_state == "MOTION" else DARK_PALETTE["safe_emerald"]
        st.markdown(
            f"""
            <div class="metric-box success-border">
                <div class="metric-label">🌡️ Logical Sensors</div>
                <div class="metric-val">{temp_val} <span style="font-size:0.90rem; font-weight:normal; color:#94A3B8;">{hum_val}</span></div>
                <div class="metric-sub">Node 1 (DHT) • PIR: <span style="color:{motion_color}; font-weight:bold;">{motion_state}</span></div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # 2. Main Visual Panel (Two-Column Layout)
    col_left, col_right = st.columns([1.75, 1.25])

    with col_left:
        st.markdown("<div class='section-header'><span>📶</span> 1-Second Packet Rate Stream & Anomaly Markers</div>", unsafe_allow_html=True)
        windows_df = fetch_recent_windows(conn, limit=150, run_id=run_id)

        if not windows_df.empty:
            fig = go.Figure()

            # Plot packet rate per client
            for node in sorted(windows_df["node_id"].unique()):
                sub = windows_df[windows_df["node_id"] == node]
                line_color = DARK_PALETTE["accent_cyan"] if node == "Node_3" else DARK_PALETTE["accent_blue"]
                fig.add_trace(
                    go.Scatter(
                        x=sub["window_start_utc"],
                        y=sub["packet_rate"],
                        name=f"{node} Uplink",
                        mode="lines",
                        line=dict(color=line_color, width=2.0),
                    )
                )

            # Overlay statistical anomalies
            anoms = windows_df[windows_df["pred_dual"] == -1]
            if not anoms.empty:
                # Burst / Size anomalies (Coral)
                burst = anoms[anoms["dual_reason"] == "ANOMALY_PRIMARY_BURST_OR_SIZE"]
                if not burst.empty:
                    fig.add_trace(
                        go.Scatter(
                            x=burst["window_start_utc"],
                            y=burst["packet_rate"],
                            name="Burst/Size Anomaly",
                            mode="markers",
                            marker=dict(symbol="circle", size=9, color=DARK_PALETTE["alert_coral"], line=dict(color="#FFFFFF", width=1.5)),
                        )
                    )
                # Timing Jitter anomalies (Amber)
                timing = anoms[anoms["dual_reason"] == "ANOMALY_TIMING_JITTER"]
                if not timing.empty:
                    fig.add_trace(
                        go.Scatter(
                            x=timing["window_start_utc"],
                            y=timing["packet_rate"],
                            name="Timing Jitter Anomaly",
                            mode="markers",
                            marker=dict(symbol="diamond", size=8, color=DARK_PALETTE["alert_amber"], line=dict(color="#FFFFFF", width=1.2)),
                        )
                    )
                # Simultaneous Both (Crimson)
                both = anoms[anoms["dual_reason"] == "ANOMALY_PRIMARY_AND_TIMING"]
                if not both.empty:
                    fig.add_trace(
                        go.Scatter(
                            x=both["window_start_utc"],
                            y=both["packet_rate"],
                            name="Primary + Timing Anomaly",
                            mode="markers",
                            marker=dict(symbol="star", size=10, color=DARK_PALETTE["alert_crimson"], line=dict(color="#FFFFFF", width=1.5)),
                        )
                    )

            layout = plotly_cyber_layout(height=290, xaxis_title="Window Start UTC", yaxis_title="Packet Rate (pkts/s)")
            fig.update_layout(layout)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No traffic windows recorded yet. Awaiting live packet stream from TShark.")

    with col_right:
        st.markdown("<div class='section-header'><span>🎯</span> Dual-Detector Decision Partition</div>", unsafe_allow_html=True)
        breakdown = overview.get("breakdown", {})
        if breakdown:
            labels = list(breakdown.keys())
            values = list(breakdown.values())

            color_map = {
                "NORMAL_INLIER": DARK_PALETTE["safe_emerald"],
                "NORMAL_QUIET_TIMING_UNAVAILABLE": DARK_PALETTE["accent_blue"],
                "ANOMALY_TIMING_JITTER": DARK_PALETTE["alert_amber"],
                "ANOMALY_PRIMARY_BURST_OR_SIZE": DARK_PALETTE["alert_coral"],
                "ANOMALY_PRIMARY_AND_TIMING": DARK_PALETTE["alert_crimson"],
            }
            colors = [color_map.get(k, DARK_PALETTE["accent_cyan"]) for k in labels]
            clean_labels = [k.replace("_", " ").title() for k in labels]

            fig_donut = go.Figure(
                data=[
                    go.Pie(
                        labels=clean_labels,
                        values=values,
                        hole=0.62,
                        textinfo="percent",
                        hoverinfo="label+value+percent",
                        marker=dict(colors=colors, line=dict(color=DARK_PALETTE["bg"], width=2)),
                        textfont=dict(size=10, color="#FFFFFF"),
                    )
                ]
            )
            layout_donut = plotly_cyber_layout(height=290)
            layout_donut.update(
                showlegend=True,
                legend=dict(
                    orientation="h",
                    y=-0.25,
                    x=0.5,
                    xanchor="center",
                    font=dict(size=9, color=DARK_PALETTE["text_muted"]),
                ),
                margin=dict(l=10, r=10, t=10, b=50),
            )
            fig_donut.update_layout(layout_donut)
            st.plotly_chart(fig_donut, use_container_width=True)
        else:
            st.info("No decision records available.")

    # 3. Lower Stage: Recent Alerts & Threat Intelligence Summary
    bottom_col1, bottom_col2 = st.columns(2)

    with bottom_col1:
        st.markdown("<div class='section-header'><span>🚨</span> Latest Statistical Anomaly Alerts (live_alerts)</div>", unsafe_allow_html=True)
        if not alerts_df.empty:
            display_alerts = alerts_df[[
                "alert_id", "window_start_utc", "node_id", "client_mac",
                "dual_reason", "score_primary", "score_timing", "packet_rate"
            ]].copy()
            display_alerts.columns = [
                "ID", "Timestamp (UTC)", "Node", "Client MAC",
                "Reason", "Primary Score", "Timing Score", "Rate (pkt/s)"
            ]
            st.dataframe(
                display_alerts,
                use_container_width=True,
                hide_index=True,
                height=240,
                column_config={
                    "Primary Score": st.column_config.NumberColumn(format="%.4f"),
                    "Timing Score": st.column_config.NumberColumn(format="%.4f"),
                    "Rate (pkt/s)": st.column_config.NumberColumn(format="%.1f"),
                },
            )
        else:
            st.markdown(
                '<div class="info-banner" style="border-left-color:#10B981; color:#A7F3D0;">'
                '✓ <b>Clean Anomaly Baseline:</b> Zero statistical anomaly alerts recorded in this session. '
                'All 1s traffic windows conform to the Session 1 baseline.'
                '</div>',
                unsafe_allow_html=True,
            )

    with bottom_col2:
        st.markdown("<div class='section-header'><span>🛡️</span> Attack Intelligence Operational Summary</div>", unsafe_allow_html=True)
        cat_statuses = compute_attack_category_status(conn, run_id)
        total_threats = sum(v.get("detected_count", 0) for v in cat_statuses.values())

        if total_threats == 0:
            st.markdown(
                f"""
                <div class="info-banner" style="border-left-color:#10B981; color:#A7F3D0; font-size:0.83rem; margin-bottom:12px;">
                    ✓ <b>Zero Cyberattack False Alarms:</b> All 5 threat categories report <code>NO ALERT OBSERVED</code> or <code>INSUFFICIENT TELEMETRY</code>.
                    Statistical anomaly deviations are rigorously decoupled from deterministic attack detections.
                </div>
                """,
                unsafe_allow_html=True,
            )

        summary_rows = []
        for cat_k, info in cat_statuses.items():
            summary_rows.append({
                "Threat Category": f"{info.get('icon', '🛡️')} {info['title']}",
                "Operational Status": info["status"],
                "Threats Flagged": info.get("detected_count", 0),
            })
        st.dataframe(pd.DataFrame(summary_rows), use_container_width=True, hide_index=True, height=185)


# ─────────────────────────────────────────────────────────────────────────────
# VIEW 2: LIVE NETWORK TRAFFIC ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────
def render_network_monitoring(conn: sqlite3.Connection, run_id: Optional[int]):
    """Detailed deep-dive into 1-second packet features, rates, sizes, and inter-arrival timing."""
    overview = fetch_traffic_overview(conn, run_id)

    st.markdown(
        """
        <div style="margin-bottom: 8px;">
            <div style="font-size: 1.35rem; font-weight: 800; color: #FFFFFF; letter-spacing: -0.02em;">
                📈 Live Network Traffic Analytics
            </div>
            <div style="font-size: 0.78rem; color: #94A3B8; margin-top: 2px;">
                High-resolution 1-second feature dynamics, packet sizing distributions, and inter-arrival timing jitter
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 1. KPI Ribbon
    k1, k2, k3, k4, k5 = st.columns(5)
    with k1:
        st.markdown(
            f"""
            <div class="metric-box blue-border">
                <div class="metric-label">📦 Total Packets</div>
                <div class="metric-val">{overview['total_packets']:,}</div>
                <div class="metric-sub">Captured Frame Count</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with k2:
        st.markdown(
            f"""
            <div class="metric-box">
                <div class="metric-label">📊 Traffic Windows</div>
                <div class="metric-val">{overview['total_windows']:,}</div>
                <div class="metric-sub">1-Second Slices Emitted</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with k3:
        st.markdown(
            f"""
            <div class="metric-box">
                <div class="metric-label">👤 Active Clients</div>
                <div class="metric-val">{len(overview['observed_clients'])}</div>
                <div class="metric-sub">Transmitting Phone Nodes</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with k4:
        st.markdown(
            f"""
            <div class="metric-box">
                <div class="metric-label">📈 Avg Packet Rate</div>
                <div class="metric-val">{overview['avg_rate']:.1f}<span style="font-size:0.9rem; color:#94A3B8;">/s</span></div>
                <div class="metric-sub">Mean Throughput Density</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with k5:
        st.markdown(
            f"""
            <div class="metric-box warning-border">
                <div class="metric-label">🔺 Peak Packet Rate</div>
                <div class="metric-val">{overview['peak_rate']:.0f}<span style="font-size:0.9rem; color:#94A3B8;">/s</span></div>
                <div class="metric-sub">Maximum Burst Observed</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # 2. Interactive Filter Controls
    c_filter, c_limit = st.columns([2, 1])
    with c_filter:
        node_filter = st.selectbox(
            "Filter Client Node",
            options=["All Nodes", "Node_3", "Node_4", "Node_5"],
            index=0,
            key="traffic_node_filter"
        )
    with c_limit:
        window_limit = st.slider("Window History Depth", min_value=50, max_value=1000, value=300, step=50)

    df_windows = fetch_recent_windows(conn, limit=window_limit, node_id=node_filter, run_id=run_id)

    if df_windows.empty:
        st.info("No traffic windows available matching the selected filter.")
        return

    # 3. Sub-Tab Visualizations
    t1, t2 = st.tabs(["📊 Packet Rate & Burst Size Dynamics", "⏱️ Inter-Arrival Timing & Jitter"])

    with t1:
        fig_rate = make_subplots(
            rows=2, cols=1,
            shared_xaxes=True,
            vertical_spacing=0.09,
            subplot_titles=("1-Second Packet Rate (packets/sec)", "Mean Packet Size ± Std Dev (Bytes)")
        )

        for node in sorted(df_windows["node_id"].unique()):
            sub = df_windows[df_windows["node_id"] == node]
            color = DARK_PALETTE["accent_cyan"] if node == "Node_3" else DARK_PALETTE["accent_blue"]

            fig_rate.add_trace(
                go.Scatter(
                    x=sub["window_start_utc"],
                    y=sub["packet_rate"],
                    name=f"{node} Rate",
                    mode="lines",
                    line=dict(color=color, width=1.8),
                ),
                row=1, col=1
            )

            fig_rate.add_trace(
                go.Scatter(
                    x=sub["window_start_utc"],
                    y=sub["mean_packet_size"],
                    name=f"{node} Mean Size",
                    mode="lines+markers",
                    marker=dict(size=3),
                    line=dict(color=color, width=1.5),
                ),
                row=2, col=1
            )

        layout_rate = plotly_cyber_layout(height=420)
        fig_rate.update_layout(layout_rate)
        st.plotly_chart(fig_rate, use_container_width=True)

    with t2:
        timing_sub = df_windows[df_windows["timing_status"] == "ACTIVE"]

        if not timing_sub.empty:
            fig_timing = make_subplots(
                rows=2, cols=1,
                shared_xaxes=True,
                vertical_spacing=0.09,
                subplot_titles=("Mean Inter-Arrival Time (IAT in seconds)", "IAT Standard Deviation / Timing Jitter")
            )

            for node in sorted(timing_sub["node_id"].unique()):
                sub = timing_sub[timing_sub["node_id"] == node]
                color = DARK_PALETTE["accent_teal"] if node == "Node_3" else DARK_PALETTE["purple"]

                fig_timing.add_trace(
                    go.Scatter(
                        x=sub["window_start_utc"],
                        y=sub["mean_IAT"],
                        name=f"{node} Mean IAT",
                        mode="lines+markers",
                        marker=dict(size=4),
                        line=dict(color=color, width=1.8),
                    ),
                    row=1, col=1
                )

                fig_timing.add_trace(
                    go.Scatter(
                        x=sub["window_start_utc"],
                        y=sub["IAT_std"],
                        name=f"{node} Jitter (Std)",
                        mode="lines",
                        line=dict(color=DARK_PALETTE["alert_amber"], width=1.5, dash="dot"),
                    ),
                    row=2, col=1
                )

            layout_timing = plotly_cyber_layout(height=420)
            fig_timing.update_layout(layout_timing)
            st.plotly_chart(fig_timing, use_container_width=True)
        else:
            st.info("Timing features are inactive. All current windows have packet_count < 3 (UNAVAILABLE_N_LT_3).")

    # 4. Raw Feature Windows Explorer
    with st.expander("🔍 View Raw 1-Second Traffic Windows (Features & Decision Scores)"):
        st.dataframe(
            df_windows[[
                "window_id", "window_start_utc", "node_id", "client_mac",
                "packet_count", "packet_rate", "mean_packet_size", "packet_size_std",
                "mean_IAT", "IAT_std", "score_primary", "score_timing", "pred_dual", "dual_reason"
            ]],
            use_container_width=True,
            hide_index=True,
            column_config={
                "window_start_utc": st.column_config.TextColumn("Timestamp (UTC)"),
                "packet_rate": st.column_config.NumberColumn("Rate (pkt/s)", format="%.1f"),
                "mean_packet_size": st.column_config.NumberColumn("Mean Size (B)", format="%.1f"),
                "mean_IAT": st.column_config.NumberColumn("Mean IAT (s)", format="%.4f"),
                "IAT_std": st.column_config.NumberColumn("IAT Std (s)", format="%.4f"),
                "score_primary": st.column_config.NumberColumn("P.Score", format="%.4f"),
                "score_timing": st.column_config.NumberColumn("T.Score", format="%.4f"),
            },
        )


# ─────────────────────────────────────────────────────────────────────────────
# VIEW 3: STATISTICAL ANOMALY ALERTS CONSOLE
# ─────────────────────────────────────────────────────────────────────────────
def render_anomaly_alerts(conn: sqlite3.Connection, run_id: Optional[int]):
    """Detailed anomaly investigation console with exact reconciled detector accounting."""
    st.markdown(
        """
        <div style="margin-bottom: 8px;">
            <div style="font-size: 1.35rem; font-weight: 800; color: #FFFFFF; letter-spacing: -0.02em;">
                🛡️ Dual-Detector Anomaly Investigation Console
            </div>
            <div style="font-size: 0.78rem; color: #94A3B8; margin-top: 2px;">
                Unsupervised machine learning anomaly scoring based on frozen Isolation Forest baseline models
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="advisory-banner">
            <b>Methodological & Legal Framing:</b> Flagged anomaly windows represent statistical departures
            from the Session 1 baseline model (Isolation Forest). They identify unusual packet bursts,
            atypical frame sizes, or inter-arrival timing jitter. <b>They are NOT confirmed cyberattacks.</b>
            All decisions follow the scikit-learn Isolation Forest convention: <code>-1 = Anomaly</code>, <code>+1 = Normal Inlier</code>.
        </div>
        """,
        unsafe_allow_html=True,
    )

    overview = fetch_traffic_overview(conn, run_id)
    df_alerts = fetch_alerts(conn, limit=200, run_id=run_id)
    df_all_windows = fetch_recent_windows(conn, limit=500, run_id=run_id)

    # 1. Rigorous Alert Accounting Breakdown Cards (5 Cards)
    total_dual_alerts = overview["anomaly_windows"]
    burst_only = overview["breakdown"].get("ANOMALY_PRIMARY_BURST_OR_SIZE", 0)
    timing_only = overview["breakdown"].get("ANOMALY_TIMING_JITTER", 0)
    combined_both = overview["breakdown"].get("ANOMALY_PRIMARY_AND_TIMING", 0)
    normal_windows = overview["total_windows"] - total_dual_alerts

    c_tot, c_prim, c_tim, c_comb, c_norm = st.columns(5)

    with c_tot:
        st.markdown(
            f"""
            <div class="metric-box alert-border">
                <div class="metric-label">⚠️ Total Dual Alerts</div>
                <div class="metric-val">{total_dual_alerts}</div>
                <div class="metric-sub">Mutually Exclusive Sum</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c_prim:
        st.markdown(
            f"""
            <div class="metric-box alert-border">
                <div class="metric-label">1. Primary Anomaly Only</div>
                <div class="metric-val">{burst_only}</div>
                <div class="metric-sub">Burst Rate / Size Outliers</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c_tim:
        st.markdown(
            f"""
            <div class="metric-box warning-border">
                <div class="metric-label">2. Timing Anomaly Only</div>
                <div class="metric-val">{timing_only}</div>
                <div class="metric-sub">Inter-Arrival Jitter (N ≥ 3)</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c_comb:
        comb_border = "alert-border" if combined_both > 0 else "neutral-border"
        st.markdown(
            f"""
            <div class="metric-box {comb_border}">
                <div class="metric-label">3. Simultaneous Both</div>
                <div class="metric-val">{combined_both}</div>
                <div class="metric-sub">Primary + Timing Flagged</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c_norm:
        st.markdown(
            f"""
            <div class="metric-box success-border">
                <div class="metric-label">✓ Normal Inliers</div>
                <div class="metric-val">{normal_windows}</div>
                <div class="metric-sub">{overview['total_windows']} Total Windows</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Reconciled Accounting Explanation Box
    st.markdown(
        f"""
        <div class="cyber-card" style="margin-top:14px; font-size:0.83rem; line-height:1.5;">
            <b>Reconciliation Equation:</b> The 3 subcategories above form a <b>mutually exclusive</b> partition
            of the total dual anomaly alerts:<br>
            <code>Total Dual Alerts ({total_dual_alerts}) = Primary Only ({burst_only}) + Timing Only ({timing_only}) + Simultaneous Both ({combined_both})</code>.<br>
            Individually, the Primary Detector flagged <b>{overview['primary_flags']}</b> windows and the Timing Detector flagged <b>{overview['timing_flags']}</b> active windows.
            Combined, the dual detector triggered on exactly <b>{total_dual_alerts}</b> distinct 1-second windows ({overview['anomaly_pct']:.2f}% of session).
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 2. 2D Decision Space Scatter (Primary Score vs Timing Score)
    if not df_all_windows.empty:
        st.markdown("<div class='section-header'><span>🎯</span> Dual Detector Decision Space (Thresholds at 0.0)</div>", unsafe_allow_html=True)
        valid_scores = df_all_windows.dropna(subset=["score_primary"]).copy()

        fig_scatter = go.Figure()

        # Inliers
        inliers = valid_scores[valid_scores["pred_dual"] == 1]
        fig_scatter.add_trace(
            go.Scatter(
                x=inliers["score_primary"],
                y=inliers["score_timing"].fillna(-0.25),
                name="Normal Windows (+1)",
                mode="markers",
                marker=dict(color=DARK_PALETTE["safe_emerald"], size=6, opacity=0.6),
            )
        )

        # Anomalies
        anomalies = valid_scores[valid_scores["pred_dual"] == -1]
        if not anomalies.empty:
            fig_scatter.add_trace(
                go.Scatter(
                    x=anomalies["score_primary"],
                    y=anomalies["score_timing"].fillna(-0.25),
                    name="Anomaly Alerts (-1)",
                    mode="markers",
                    marker=dict(color=DARK_PALETTE["alert_coral"], size=9, symbol="x"),
                )
            )

        # Decision threshold lines at 0.0
        fig_scatter.add_vline(x=0.0, line_dash="dash", line_color="rgba(255,255,255,0.3)", annotation_text="Primary Offset (0.0)")
        fig_scatter.add_hline(y=0.0, line_dash="dash", line_color="rgba(255,255,255,0.3)", annotation_text="Timing Offset (0.0)")

        layout_scatter = plotly_cyber_layout(
            height=330,
            xaxis_title="Primary Decision Score (Negative = Outlier)",
            yaxis_title="Timing Decision Score (Negative = Outlier)",
        )
        fig_scatter.update_layout(layout_scatter)
        st.plotly_chart(fig_scatter, use_container_width=True)

    # 3. Full Alerts Table with Details & Filters
    st.markdown("<div class='section-header'><span>📋</span> Complete Statistical Alerts Log (live_alerts)</div>", unsafe_allow_html=True)
    if not df_alerts.empty:
        f1, f2 = st.columns(2)
        with f1:
            reason_opts = ["All Reasons"] + sorted(df_alerts["dual_reason"].dropna().unique().tolist())
            sel_reason = st.selectbox("Filter by Dual Reason", reason_opts, key="console_alert_reason")
        with f2:
            node_opts = ["All Nodes"] + sorted(df_alerts["node_id"].dropna().unique().tolist())
            sel_node = st.selectbox("Filter by Client Node", node_opts, key="console_alert_node")

        filtered_alerts = df_alerts.copy()
        if sel_reason != "All Reasons":
            filtered_alerts = filtered_alerts[filtered_alerts["dual_reason"] == sel_reason]
        if sel_node != "All Nodes":
            filtered_alerts = filtered_alerts[filtered_alerts["node_id"] == sel_node]

        display_tbl = filtered_alerts[[
            "alert_id", "window_start_utc", "node_id", "client_mac",
            "dual_reason", "score_primary", "score_timing", "packet_rate", "mean_packet_size", "packet_count"
        ]].copy()
        display_tbl.columns = [
            "Alert ID", "Timestamp (UTC)", "Node ID", "Hardware MAC",
            "Dual Reason", "Primary Score", "Timing Score", "Packet Rate (pkt/s)", "Mean Size (B)", "Packet Count"
        ]
        st.dataframe(
            display_tbl,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Primary Score": st.column_config.NumberColumn(format="%.4f"),
                "Timing Score": st.column_config.NumberColumn(format="%.4f"),
                "Packet Rate (pkt/s)": st.column_config.NumberColumn(format="%.1f"),
                "Mean Size (B)": st.column_config.NumberColumn(format="%.1f"),
            },
        )
    else:
        st.info("No anomaly alerts found for the current session and filter criteria.")


# ─────────────────────────────────────────────────────────────────────────────
# VIEW 4: PHYSICAL SENSORS (ESP32: NODE 1 & NODE 2)
# ─────────────────────────────────────────────────────────────────────────────
def render_sensor_monitoring(conn: sqlite3.Connection, run_id: Optional[int]):
    """Monitors logical Node 1 (DHT11) and Node 2 (PIR) from the shared ESP32 serial hub."""
    st.markdown(
        """
        <div style="margin-bottom: 8px;">
            <div style="font-size: 1.35rem; font-weight: 800; color: #FFFFFF; letter-spacing: -0.02em;">
                🌡️ Physical IoT Sensors (ESP32 Gateway)
            </div>
            <div style="font-size: 0.78rem; color: #94A3B8; margin-top: 2px;">
                Node 1 (DHT11 Environmental Sensor) and Node 2 (AM312 PIR Motion Sensor) concurrent ingestion
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="info-banner">
            <b>Physical Node Architecture & Separation of Concerns:</b>
            Both <b>Node 1 (DHT11 Temperature/Humidity)</b> and <b>Node 2 (PIR Motion)</b> share ONE physical ESP32
            microcontroller communicating over USB serial (e.g. <code>COM6</code>). They are partitioned logically by the ingestion daemon.<br>
            <b>CRITICAL DISCLAIMER:</b> Physical sensor events (e.g. motion detection or ambient room temperature shifts)
            <b>do NOT cause or explain Wi-Fi network anomalies</b>. They are recorded concurrently to monitor the physical testbed environment
            without causal conflation.
        </div>
        """,
        unsafe_allow_html=True,
    )

    df_dht = fetch_sensor_telemetry(conn, limit=300, run_id=run_id)
    df_pir = fetch_pir_events(conn, limit=300, run_id=run_id)

    # 1. Node 1 (DHT11) Metrics & Trends
    st.markdown("<div class='section-header'><span>🧪</span> Node 1: DHT11 Environmental Readings</div>", unsafe_allow_html=True)
    if not df_dht.empty:
        latest_temp = df_dht["temperature_c"].iloc[-1]
        latest_hum = df_dht["humidity_pct"].iloc[-1]
        valid_cnt = int(df_dht["dht_valid"].sum())
        valid_pct = (valid_cnt / len(df_dht) * 100.0) if len(df_dht) > 0 else 0.0

        c_dht1, c_dht2, c_dht3 = st.columns(3)
        with c_dht1:
            st.metric("Latest Temperature", f"{latest_temp:.1f} °C" if pd.notnull(latest_temp) else "—", delta=None)
        with c_dht2:
            st.metric("Latest Relative Humidity", f"{latest_hum:.1f} %" if pd.notnull(latest_hum) else "—", delta=None)
        with c_dht3:
            st.metric("DHT11 Read Reliability", f"{valid_pct:.1f}%", f"{valid_cnt}/{len(df_dht)} Valid Reads")

        # DHT11 Dual-Axis Plotly Chart
        fig_dht = make_subplots(specs=[[{"secondary_y": True}]])
        fig_dht.add_trace(
            go.Scatter(
                x=df_dht["captured_at"],
                y=df_dht["temperature_c"],
                name="Temperature (°C)",
                mode="lines+markers",
                marker=dict(size=4),
                line=dict(color=DARK_PALETTE["pink"], width=2.0),
            ),
            secondary_y=False,
        )
        fig_dht.add_trace(
            go.Scatter(
                x=df_dht["captured_at"],
                y=df_dht["humidity_pct"],
                name="Humidity (%)",
                mode="lines",
                line=dict(color=DARK_PALETTE["accent_cyan"], width=1.8),
            ),
            secondary_y=True,
        )

        layout_dht = plotly_cyber_layout(height=280, xaxis_title="Capture Timestamp UTC", yaxis_title="Temperature (°C)")
        fig_dht.update_layout(layout_dht)
        fig_dht.update_yaxes(title_text="Relative Humidity (%)", secondary_y=True, gridcolor="rgba(255,255,255,0.03)")
        st.plotly_chart(fig_dht, use_container_width=True)
    else:
        st.info("No DHT11 sensor readings recorded in live_sensor_telemetry.")

    # 2. Node 2 (PIR) Motion Detection
    st.markdown("<div class='section-header'><span>🚶</span> Node 2: PIR Motion Detection Activity</div>", unsafe_allow_html=True)
    if not df_pir.empty:
        motion_events = df_pir[df_pir["motion_detected"] == 1]
        motion_rate = (len(motion_events) / len(df_pir) * 100.0) if len(df_pir) > 0 else 0.0

        c_pir1, c_pir2 = st.columns(2)
        with c_pir1:
            st.metric("Total Motion Detections", f"{len(motion_events):,} Events", f"{motion_rate:.1f}% Active Intervals")
        with c_pir2:
            st.metric("Latest Motion State", "MOTION DETECTED" if df_pir["motion_detected"].iloc[-1] == 1 else "CLEAR")

        fig_pir = go.Figure()
        fig_pir.add_trace(
            go.Bar(
                x=df_pir["captured_at"],
                y=df_pir["motion_detected"],
                name="Motion State",
                marker_color=[DARK_PALETTE["alert_coral"] if m == 1 else DARK_PALETTE["surface_elevated"] for m in df_pir["motion_detected"]],
            )
        )
        layout_pir = plotly_cyber_layout(height=190, xaxis_title="Capture Timestamp UTC", yaxis_title="State (1=Motion)", show_legend=False)
        layout_pir.yaxis.update(dtick=1, range=[-0.1, 1.3])
        fig_pir.update_layout(layout_pir)
        st.plotly_chart(fig_pir, use_container_width=True)
    else:
        st.info("No PIR motion events recorded in live_pir_events.")

    # 3. Hardware Status Summary
    st.markdown("<div class='section-header'><span>🖥️</span> ESP32 Gateway Hardware Identity</div>", unsafe_allow_html=True)
    esp_diag = fetch_esp32_sniffer_diagnostics(conn, run_id)
    hw_rows = [
        {"Property": "Hardware Device", "Observed Value": esp_diag["physical_device"]},
        {"Property": "Logical Nodes Hosted", "Observed Value": "Node_1 (DHT11) & Node_2 (PIR)"},
        {"Property": "Serial Connection Link", "Observed Value": f"{esp_diag['connection_status']} ({esp_diag['serial_port']})"},
        {"Property": "Last Telemetry Timestamp", "Observed Value": esp_diag["last_seen_utc"]},
        {"Property": "Total Sensor Records Logged", "Observed Value": f"{esp_diag['total_sensor_records']:,}"},
    ]
    st.dataframe(pd.DataFrame(hw_rows), use_container_width=True, hide_index=True)


# ─────────────────────────────────────────────────────────────────────────────
# VIEW 5: DEVICE REGISTRY & WI-FI CLIENT SECURITY
# ─────────────────────────────────────────────────────────────────────────────
def render_device_registry(conn: sqlite3.Connection):
    """Displays registered phone clients and unregistered MAC address observations."""
    st.markdown(
        """
        <div style="margin-bottom: 8px;">
            <div style="font-size: 1.35rem; font-weight: 800; color: #FFFFFF; letter-spacing: -0.02em;">
                📱 Device Registry & Network Asset Surveillance
            </div>
            <div style="font-size: 0.78rem; color: #94A3B8; margin-top: 2px;">
                5-Node logical topology inventory and unknown MAC surveillance
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="security-banner">
            <b>OPERATOR MANDATE ON UNKNOWN DEVICES:</b>
            Observed unregistered MAC addresses require manual administrative verification.
            <b>Under no circumstances should any device be automatically blocked, dropped, or deauthenticated.</b><br>
            <i>Modern mobile devices (iOS, Android, Windows) dynamically randomize MAC addresses for privacy, which can generate benign unrecognized identifiers.</i>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 1. Inspect actual SQLite table: device_registry
    try:
        db_reg_rows = conn.execute(
            "SELECT mac_address, node_id, device_type, label, notes, last_seen FROM device_registry ORDER BY node_id"
        ).fetchall()
        db_reg_count = len(db_reg_rows)
    except Exception:
        db_reg_rows = []
        db_reg_count = 0

    st.markdown(
        f"""
        <div class="cyber-card" style="font-size:0.84rem;">
            <b>Persisted SQLite Registry Status (<code>device_registry</code> table):</b>
            Currently contains <b>{db_reg_count} persisted records</b>.
            Device attribution is active for all registered MAC addresses.
            <br><i>ℹ️ <b>Signal Monitoring Note:</b> RSSI is <b>not available</b> in this capture mode. Windows Mobile Hotspot captures NDIS Ethernet frames without 802.11 radiotap headers. No RSSI values are fabricated.</i>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 2. Unified 5 Logical Nodes Architecture Matrix
    st.markdown("<div class='section-header'><span>🌐</span> Five Logical Nodes Topology & Hardware Architecture</div>", unsafe_allow_html=True)

    overview = fetch_traffic_overview(conn)
    observed_map = {item["client_mac"]: item for item in overview["observed_clients"]}
    sensor_df = fetch_sensor_telemetry(conn, limit=1)
    pir_df = fetch_pir_events(conn, limit=1)

    try:
        dht_total = conn.execute("SELECT COUNT(*) FROM live_sensor_telemetry").fetchone()[0]
        pir_total = conn.execute("SELECT COUNT(*) FROM live_pir_events").fetchone()[0]
        pir_motions = conn.execute("SELECT COUNT(*) FROM live_pir_events WHERE motion_detected = 1").fetchone()[0]
    except Exception:
        dht_total = pir_total = pir_motions = 0

    # Sensor status
    temp_val = f"{sensor_df['temperature_c'].iloc[-1]:.1f}°C" if not sensor_df.empty and pd.notnull(sensor_df['temperature_c'].iloc[-1]) else "N/A"
    hum_val = f"{sensor_df['humidity_pct'].iloc[-1]:.0f}%" if not sensor_df.empty and pd.notnull(sensor_df['humidity_pct'].iloc[-1]) else "N/A"
    node1_desc = f"ONLINE ({dht_total} records, latest: {temp_val} / {hum_val})" if dht_total > 0 else "OFFLINE"
    node2_desc = f"ONLINE ({pir_total} records, {pir_motions} motion events)" if pir_total > 0 else "OFFLINE"

    five_nodes_matrix = [
        {
            "Logical Node": "Node_1",
            "Functional Role": "DHT11 Environmental Sensor",
            "Physical Hardware": "ESP32 Sensor Hub (USB Serial)",
            "Network / Hardware ID": "esp32_gateway (Serial COM)",
            "Enrollment State": "Logical Sensor Partition",
            "Current Operational State": node1_desc,
        },
        {
            "Logical Node": "Node_2",
            "Functional Role": "PIR Motion Activity Sensor",
            "Physical Hardware": "ESP32 Sensor Hub (USB Serial)",
            "Network / Hardware ID": "esp32_gateway (Serial COM)",
            "Enrollment State": "Logical Sensor Partition",
            "Current Operational State": node2_desc,
        },
    ]

    # Wi-Fi Phone Clients from DB registry or config
    reg_dict = {r["mac_address"]: dict(r) for r in db_reg_rows}
    combined_macs = list(CONFIGURED_DEVICE_PROFILES.keys())
    for mac in reg_dict:
        if mac not in combined_macs:
            combined_macs.append(mac)

    for mac in combined_macs:
        reg_item = reg_dict.get(mac, {})
        cfg_item = CONFIGURED_DEVICE_PROFILES.get(mac, {})
        node_id = reg_item.get("node_id") or cfg_item.get("node_id", "Unknown")
        name = cfg_item.get("name", reg_item.get("notes", f"Client {node_id}"))
        label = reg_item.get("label", cfg_item.get("label", ""))

        obs = observed_map.get(mac)
        if obs:
            state_str = f"ACTIVE IN TRAFFIC ({obs['window_count']} windows, {obs['packet_count']} pkts)"
        elif node_id == "Node_5" or "reserved" in label.lower():
            state_str = "RESERVED DEMO DEVICE (Unobserved — Awaiting Demonstration)"
        else:
            state_str = "CONFIGURED (No Packets in Current Session)"

        five_nodes_matrix.append({
            "Logical Node": node_id,
            "Functional Role": name,
            "Physical Hardware": "Smartphone Wi-Fi Client",
            "Network / Hardware ID": mac,
            "Enrollment State": "Persisted in SQLite" if mac in reg_dict else "Attribution Profile",
            "Current Operational State": state_str,
        })

    df_5nodes = pd.DataFrame(five_nodes_matrix)
    st.dataframe(
        df_5nodes,
        use_container_width=True,
        hide_index=True,
    )

    # 3. Unknown MAC address observations table & ALERT
    st.markdown("<div class='section-header'><span>⚠️</span> Unregistered MAC Address Surveillance (unknown_device_obs)</div>", unsafe_allow_html=True)
    df_unknown = fetch_unknown_devices(conn)

    if not df_unknown.empty:
        st.markdown(
            f"""
            <div class="security-banner">
                <b>🚨 UNKNOWN DEVICE DETECTED ({len(df_unknown)} unverified MAC addresses observed):</b><br>
                One or more unregistered client devices have transmitted frames on the Mobile Hotspot adapter.<br>
                <b>Operator Action:</b> Review the hardware MAC addresses below. If this is Phone 3 for the demonstration,
                enroll it using: <code>python src/init_live_database.py --register-mac &lt;MAC&gt; --node-id Node_5</code>.
                <b>DO NOT automatically disconnect or block the device.</b>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.dataframe(
            df_unknown[[
                "obs_id", "observed_mac", "first_seen_utc", "last_seen_utc", "observation_count"
            ]],
            use_container_width=True,
            hide_index=True,
            column_config={
                "observed_mac": st.column_config.TextColumn("Observed MAC"),
                "first_seen_utc": st.column_config.TextColumn("First Seen (UTC)"),
                "last_seen_utc": st.column_config.TextColumn("Last Seen (UTC)"),
                "observation_count": st.column_config.NumberColumn("Seen Count"),
            },
        )
    else:
        st.markdown(
            """
            <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 8px; padding: 14px 18px; color: #A7F3D0; font-size: 0.86rem;">
                ✓ <b>Clean Device Surveillance Status:</b> Zero unregistered MAC addresses recorded in <code>unknown_device_obs</code>.
                All captured uplink packets belong to verified test clients (Phone 1 and Phone 2).
            </div>
            """,
            unsafe_allow_html=True,
        )


# ─────────────────────────────────────────────────────────────────────────────
# VIEW 6: DAEMON DIAGNOSTICS & SYSTEM INTEGRITY
# ─────────────────────────────────────────────────────────────────────────────
def fetch_stored_channel_diagnostic(
    db_path: Optional[Path],
    current_run_id: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """
    Reads the stored channel diagnostic result from disk without spawning any subprocess.
    Validates session freshness against current_run_id to ensure a stale result from a
    prior run or session is never presented as current or aligned.
    """
    if db_path is None:
        return None
    try:
        diag_path = db_path.parent / f"{db_path.stem}_diagnostic.json"
        if not diag_path.exists():
            return None
        with open(diag_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, dict) or "status" not in data:
                return None

        # Session Freshness Validation (Stage 8.4)
        if current_run_id is not None:
            cached_run_id = data.get("run_id")
            is_valid_run_type = isinstance(cached_run_id, int) and not isinstance(cached_run_id, bool)
            if not is_valid_run_type or cached_run_id != current_run_id:
                if not is_valid_run_type:
                    explanation = (
                        f"Stored channel diagnostic run ID ({cached_run_id!r}) is missing, null, or invalid type "
                        f"(active session is Run #{current_run_id}). Channel alignment must be verified live "
                        f"for the current session. Channel 6 is not assumed."
                    )
                else:
                    explanation = (
                        f"Stored channel diagnostic is from previous Run #{cached_run_id} "
                        f"(active session is Run #{current_run_id}). Channel alignment "
                        f"must be verified live for the current session. Channel 6 is not assumed."
                    )
                return {
                    "status": "CHANNEL_UNAVAILABLE",
                    "esp32_channel": None,
                    "hotspot_channel": data.get("hotspot_channel"),
                    "interface_name": data.get("interface_name"),
                    "esp32_source": "STALE_CACHE",
                    "run_id": cached_run_id if is_valid_run_type else None,
                    "timestamp": data.get("timestamp"),
                    "is_stale": True,
                    "explanation": explanation,
                }
        return data
    except Exception:
        return None


def render_diagnostics(conn: sqlite3.Connection, db_path: Optional[Path] = None, run_id: Optional[int] = None):
    """Provides operational metrics on collector heartbeats, database sizes, and pipeline health."""
    st.markdown(
        """
        <div style="margin-bottom: 8px;">
            <div style="font-size: 1.35rem; font-weight: 800; color: #FFFFFF; letter-spacing: -0.02em;">
                ⚙️ Live Collector Daemon & Storage Diagnostics
            </div>
            <div style="font-size: 0.78rem; color: #94A3B8; margin-top: 2px;">
                Collector daemon lifecycle, Wi-Fi channel alignment verification, and SQLite WAL database metrics
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    status = fetch_collector_status(conn, run_id=run_id)
    current_run_id = status['run_id'] if status else run_id

    if status:
        c_diag1, c_diag2 = st.columns(2)
        with c_diag1:
            st.markdown(
                f"""
                <div class="cyber-card">
                    <b style="color:#22D3EE;">Persisted Daemon Execution Record</b><br>
                    • <b>Run ID:</b> #{status['run_id']}<br>
                    • <b>Status:</b> <span style="font-weight:700; color:#FFFFFF;">{status['status']}</span><br>
                    • <b>Started At:</b> {status['started_at']} UTC<br>
                    • <b>Last Heartbeat:</b> {status['last_heartbeat']} UTC<br>
                    • <b>Termination Reason:</b> {status.get('stop_reason') or 'N/A'}<br>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with c_diag2:
            st.markdown(
                f"""
                <div class="cyber-card">
                    <b style="color:#22D3EE;">Hardware & Ingestion Settings</b><br>
                    • <b>TShark Interface Index:</b> {status['interface_index']}<br>
                    • <b>Interface Name:</b> {status['interface_name']}<br>
                    • <b>Serial Port:</b> {status['serial_port']}<br>
                    • <b>Packets Parsed:</b> {status['packets_parsed']:,}<br>
                    • <b>1s Windows Emitted:</b> {status['windows_emitted']:,}<br>
                    • <b>Sensor Records Emitted:</b> {status['sensor_records']:,}<br>
                </div>
                """,
                unsafe_allow_html=True,
            )

    # ── Channel Alignment Diagnostic (Stage 8.4) ───────────────────────────
    st.markdown("<div class='section-header'><span>📡</span> Wi-Fi Physical Layer & Channel Alignment Diagnostic</div>", unsafe_allow_html=True)
    diag = fetch_stored_channel_diagnostic(db_path, current_run_id=current_run_id)

    is_aligned = (
        diag is not None
        and diag.get("status") == "CHANNEL_ALIGNED"
        and not diag.get("is_stale", False)
        and diag.get("esp32_channel") is not None
        and diag.get("hotspot_channel") is not None
        and diag.get("esp32_channel") == diag.get("hotspot_channel")
    )
    is_mismatch = (
        diag is not None
        and diag.get("status") == "CHANNEL_MISMATCH"
        and not diag.get("is_stale", False)
    )

    if is_aligned:
        badge_color = DARK_PALETTE["safe_emerald"]
        border_cls = "success-border"
        status_label = f"ALIGNED (Channel {diag['esp32_channel']})"
        detail_msg = diag.get("explanation") or f"Windows hotspot and ESP32 sniffer are confirmed aligned on Channel {diag['esp32_channel']}."
    elif is_mismatch:
        badge_color = DARK_PALETTE["alert_coral"]
        border_cls = "alert-border"
        status_label = f"MISMATCH (Hotspot: Ch {diag.get('hotspot_channel', '?')} vs ESP32: Ch {diag.get('esp32_channel', '?')})"
        detail_msg = diag.get("explanation") or "Channel mismatch detected! 802.11 management packet capture will be degraded."
    else:
        badge_color = DARK_PALETTE["text_muted"]
        border_cls = "neutral-border"
        status_val = diag.get("status") if diag else "UNAVAILABLE"
        if diag and diag.get("is_stale"):
            status_label = "UNAVAILABLE (Stale Session Cache)"
        else:
            status_label = f"{status_val} (Neutral Status)"
        if diag and diag.get("explanation"):
            detail_msg = diag["explanation"]
        else:
            detail_msg = (
                "No verified channel alignment diagnostic record found for this session. "
                "The dashboard maintains strict integrity and refuses to assume Channel 6 "
                "without collector hardware verification."
            )

    c_chan1, c_chan2 = st.columns(2)
    with c_chan1:
        st.markdown(
            f"""
            <div class="cyber-card {border_cls}">
                <b style="color:#22D3EE;">Wi-Fi Channel Alignment Status</b><br>
                • <b>Diagnostic Status:</b> <span style="color:{badge_color}; font-weight:700;">{status_label}</span><br>
                • <b>ESP32 Sniffer Channel:</b> {diag.get('esp32_channel') if diag and diag.get('esp32_channel') is not None else 'Unverified / Unknown'} ({diag.get('esp32_source', 'No Telemetry') if diag else 'N/A'})<br>
                • <b>Hotspot Interface Name:</b> {diag.get('interface_name') if diag and diag.get('interface_name') else (status.get('interface_name', 'Unknown') if status else 'Unknown')}<br>
                • <b>Hotspot Operating Channel:</b> {diag.get('hotspot_channel') if diag and diag.get('hotspot_channel') is not None else 'Unverified / Unknown'}<br>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c_chan2:
        st.markdown(
            f"""
            <div class="cyber-card">
                <b style="color:#22D3EE;">Diagnostic Evidence & Limitations</b><br>
                • <b>Diagnostic Timestamp:</b> {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(diag['timestamp'])) if diag and diag.get('timestamp') else 'N/A'}<br>
                • <b>Detail:</b> {detail_msg}<br>
                • <b>Assumptions Policy:</b> Hardcoded assumptions forbidden. Live verification required for green status.
            </div>
            """,
            unsafe_allow_html=True,
        )

    # SQLite Storage Information
    st.markdown("<div class='section-header'><span>💾</span> SQLite Database Statistics (WAL Mode)</div>", unsafe_allow_html=True)
    try:
        tables = [
            "collector_status", "device_registry", "live_traffic_windows",
            "live_alerts", "unknown_device_obs", "live_sensor_telemetry", "live_pir_events",
            "live_attack_events"
        ]
        table_counts = []
        for t in tables:
            cnt = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            table_counts.append({"Database Table": t, "Row Count": cnt})
        st.dataframe(pd.DataFrame(table_counts), use_container_width=True, hide_index=True)
    except Exception as exc:
        st.warning(f"Error reading database statistics: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# VIEW 7: NETWORK ATTACK INTELLIGENCE & EXPLAINABLE THREAT ENGINE
# ─────────────────────────────────────────────────────────────────────────────
def render_attack_intelligence(conn: sqlite3.Connection, run_id: Optional[int]):
    """Provides explainable, evidence-backed security threat intelligence across five attack categories."""
    st.markdown(
        """
        <div style="margin-bottom: 8px;">
            <div style="font-size: 1.35rem; font-weight: 800; color: #FFFFFF; letter-spacing: -0.02em;">
                🛡️ Network Attack Intelligence & Threat Engine
            </div>
            <div style="font-size: 0.78rem; color: #94A3B8; margin-top: 2px;">
                Explainable, protocol-level threat evaluations across five distinct cyberattack categories
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="info-banner">
            <b>Explainable Attack Detection Principles & Safety Boundaries:</b><br>
            • <b>Decoupled Detection Pipelines:</b> Statistical anomalies flagged by the frozen Isolation Forest (traffic spikes, size outliers) are <i>not</i> assumed to be cyberattacks. Confirmed or suspicious attack detections require deterministic protocol evidence.<br>
            • <b>Telemetry Honesty:</b> If required headers (such as raw 802.11 management frames or cryptographic nonces) are absent from the capture stream, the engine strictly reports <code>INSUFFICIENT_TELEMETRY</code> rather than fabricating findings.<br>
            • <b>Non-Disruptive Operator Assistance:</b> All alerts provide operator guidance for manual investigation. <b>No device is ever automatically disconnected, blocked, or deauthenticated.</b>
        </div>
        """,
        unsafe_allow_html=True,
    )

    cat_statuses = compute_attack_category_status(conn, run_id)
    effective_run_id = cat_statuses.get("dos", {}).get("effective_run_id", run_id)
    is_live = cat_statuses.get("dos", {}).get("is_live", False)
    session_tag = "[Live Session]" if is_live else (f"[Archived Session #{effective_run_id}]" if effective_run_id is not None else "[Archived Session]")

    df_events = fetch_attack_events(conn, limit=300, run_id=effective_run_id)

    # 1. Five Attack Categories Capability & Operational Ribbon
    st.markdown("<div class='section-header'><span>📡</span> Five Attack Categories Operational Status</div>", unsafe_allow_html=True)
    c1, c2, c3, c4, c5 = st.columns(5)
    for col, cat_k in zip([c1, c2, c3, c4, c5], ["dos", "port_scan", "spoofing", "deauth", "replay"]):
        st_info = cat_statuses[cat_k]
        with col:
            st.markdown(
                f"""
                <div class="metric-box {st_info['border_cls']}">
                    <div class="metric-label">{st_info.get('icon', '🛡️')} {st_info['title']}</div>
                    <div class="metric-val" style="font-size:1.0rem; color:{st_info['color']};">{st_info['status']}</div>
                    <div class="metric-sub">{st_info['sub']}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.caption(f"Status evaluated at {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} • Context: {session_tag} • Source: live_attack_events & collector_status")

    # 2. ESP32 Wi-Fi Sniffer Diagnostics Panel
    st.markdown("<div class='section-header'><span>📡</span> ESP32 Wi-Fi Sniffer Health & Telemetry Diagnostics</div>", unsafe_allow_html=True)
    esp_diag = fetch_esp32_sniffer_diagnostics(conn, effective_run_id)

    d1, d2, d3, d4 = st.columns(4)
    with d1:
        st_color = DARK_PALETTE["safe_emerald"] if esp_diag["connection_status"] == "Active" else DARK_PALETTE["alert_amber"] if esp_diag["connection_status"] == "Archived / Inactive" else DARK_PALETTE["text_dim"]
        st.markdown(
            f"""
            <div class="metric-box">
                <div class="metric-label">🔌 Serial Sniffer Link</div>
                <div class="metric-val" style="font-size:1.1rem; color:{st_color};">{esp_diag['connection_status']}</div>
                <div class="metric-sub">Port: <code>{esp_diag['serial_port']}</code></div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with d2:
        stale_txt = " (STALE)" if esp_diag["is_stale"] else ""
        st.markdown(
            f"""
            <div class="metric-box">
                <div class="metric-label">🖥️ Device Identity</div>
                <div class="metric-val" style="font-size:1.0rem;">{esp_diag['physical_device']}</div>
                <div class="metric-sub">Last Seen: {esp_diag['last_seen_utc']}{stale_txt}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with d3:
        st.markdown(
            f"""
            <div class="metric-box">
                <div class="metric-label">📡 Telemetry Ingested</div>
                <div class="metric-val" style="font-size:1.2rem;">{esp_diag['total_sensor_records']:,}</div>
                <div class="metric-sub">DHT11 (Node 1) & PIR (Node 2)</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with d4:
        deauth_border = "alert-border" if esp_diag["deauth_events_persisted"] > 0 else "success-border"
        deauth_color = DARK_PALETTE["alert_coral"] if esp_diag["deauth_events_persisted"] > 0 else DARK_PALETTE["safe_emerald"]
        st.markdown(
            f"""
            <div class="metric-box {deauth_border}">
                <div class="metric-label">🚨 Deauth Events Persisted</div>
                <div class="metric-val" style="font-size:1.2rem; color:{deauth_color};">{esp_diag['deauth_events_persisted']}</div>
                <div class="metric-sub">802.11 Deauth/Disassoc abuse</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Expandable Sniffer Accounting & Architecture Inspector
    with st.expander("📊 ESP32 802.11 Sniffer Detailed Telemetry Breakdown & Memory Accounting"):
        sniffer_tbl = pd.DataFrame([
            {"Sniffer Metric / Diagnostic Counter": "Wi-Fi Operating Channel", "Observed Value": esp_diag["wifi_channel"], "Telemetry Source / Status": "Firmware sniffer probe response"},
            {"Sniffer Metric / Diagnostic Counter": "Firmware Session Boot ID", "Observed Value": esp_diag["boot_id"], "Telemetry Source / Status": "ESP32 serial handshake / events"},
            {"Sniffer Metric / Diagnostic Counter": "Raw 802.11 Management Callbacks", "Observed Value": esp_diag["raw_callbacks"], "Telemetry Source / Status": "Periodic accounting summary (cumulative)"},
            {"Sniffer Metric / Diagnostic Counter": "Valid Deauth/Disassoc Frames Parsed", "Observed Value": esp_diag["valid_frames"], "Telemetry Source / Status": "Firmware accounting filter (subtype 10/12)"},
            {"Sniffer Metric / Diagnostic Counter": "Unsupported Management Frames", "Observed Value": esp_diag["unsupported_mgmt"], "Telemetry Source / Status": "Beacons/probes dropped by firmware"},
            {"Sniffer Metric / Diagnostic Counter": "Malformed Management Frames", "Observed Value": esp_diag["malformed_frames"], "Telemetry Source / Status": "Corrupted OTA frames rejected"},
            {"Sniffer Metric / Diagnostic Counter": "Token-Bucket Rate Suppressed", "Observed Value": esp_diag["tb_suppressed"], "Telemetry Source / Status": "UART burst protector (max 20/sec)"},
            {"Sniffer Metric / Diagnostic Counter": "Host Queue Dropped", "Observed Value": esp_diag["queue_dropped"], "Telemetry Source / Status": "Host UART ring-buffer overflow"},
            {"Sniffer Metric / Diagnostic Counter": "Host Enqueued Events", "Observed Value": esp_diag["enqueued_events"], "Telemetry Source / Status": "Transmitted over UART to Python"},
            {"Sniffer Metric / Diagnostic Counter": "Last 1.0s Summary Timestamp", "Observed Value": esp_diag["last_summary_utc"], "Telemetry Source / Status": "Periodic 1.0s summary snapshot"},
        ])
        st.dataframe(sniffer_tbl, use_container_width=True, hide_index=True)

        st.markdown(
            """
            <div class="info-banner" style="font-size:0.83rem; margin-top:8px;">
                <b>Telemetry Ingestion Architecture Notice:</b>
                ESP32 periodic accounting summaries (<code>wifi_mgmt_summary</code>) containing raw callback, token-bucket suppression, and UART queue counters are currently processed and maintained in the live collector daemon's in-memory state (<code>_last_summary_snapshot</code>) and are not persisted to a SQLite table. The dashboard accesses the database via read-only URI and cannot inspect cross-process memory. To avoid fabricating data, in-memory counters are displayed as <code>Unavailable (in-memory only)</code>. Individual deauthentication threat events, when detected, are persisted to <code>live_attack_events</code> and reflected above.
            </div>
            """,
            unsafe_allow_html=True,
        )

    # 3. Attack Events Metrics & Filters
    st.markdown("<div class='section-header'><span>🚨</span> Live Threat Detections & Evidence Feed (live_attack_events)</div>", unsafe_allow_html=True)

    if not df_events.empty:
        col_cat, col_status = st.columns([1.5, 1.5])
        with col_cat:
            cat_options = ["All Categories"] + sorted(list(df_events["category"].unique()))
            selected_cat = st.selectbox("Filter Category", cat_options, index=0, key="att_filter_cat")
        with col_status:
            status_options = ["All Statuses"] + sorted(list(df_events["status"].unique()))
            selected_status = st.selectbox("Filter Status", status_options, index=0, key="att_filter_status")

        filtered_df = df_events.copy()
        if selected_cat != "All Categories":
            filtered_df = filtered_df[filtered_df["category"] == selected_cat]
        if selected_status != "All Statuses":
            filtered_df = filtered_df[filtered_df["status"] == selected_status]

        suspicious_threats = len(filtered_df[filtered_df["status"].isin(["SUSPICIOUS", "CONFIRMED_THREAT"])])

        if suspicious_threats > 0:
            st.markdown(
                f"""
                <div class="security-banner">
                    <b>🚨 Active Threat Indicators Observed ({suspicious_threats} suspicious event(s)):</b><br>
                    Review the evidence details and recommended actions below. Verify target endpoints and network logs before taking any administrative action.
                </div>
                """,
                unsafe_allow_html=True,
            )

        # Display table
        display_tbl = filtered_df[[
            "event_id", "timestamp_utc", "category", "status", "severity",
            "confidence", "source_mac", "target_ip", "recommended_action"
        ]].copy()
        display_tbl.columns = [
            "Event ID", "Timestamp (UTC)", "Attack Category", "Detection Status",
            "Severity", "Confidence", "Source MAC", "Target IP", "Recommended Operator Action"
        ]

        st.dataframe(
            display_tbl,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Confidence": st.column_config.NumberColumn(format="%.2f"),
            },
        )

        # Expandable Structured Evidence Inspector
        with st.expander("🔍 Deep-Dive Explainable Evidence Inspector (Structured JSON & Reasoning)"):
            for idx, row in filtered_df.head(10).iterrows():
                st.markdown(f"**Event #{row['event_id']} — {row['category']} [{row['status']}] ({row['timestamp_utc']} UTC)**")
                try:
                    evidence_parsed = json.loads(row["evidence_json"])
                    st.json(evidence_parsed)
                except Exception:
                    st.code(row["evidence_json"])
                if row.get("missing_fields_json"):
                    st.caption(f"Missing Telemetry Fields: `{row['missing_fields_json']}`")
                st.info(f"**Operator Action:** {row['recommended_action']}")
                st.divider()

    else:
        st.markdown(
            """
            <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 8px; padding: 14px 18px; color: #A7F3D0; font-size: 0.86rem;">
                ✓ <b>No Active Threats Detected:</b> Zero attack events recorded in <code>live_attack_events</code>. All client observations adhere to normal protocol behavior.
            </div>
            """,
            unsafe_allow_html=True,
        )


# ─────────────────────────────────────────────────────────────────────────────
# LIVE AUTO-REFRESH FRAGMENT CONTAINER
# ─────────────────────────────────────────────────────────────────────────────
@st.fragment
def render_live_dashboard_fragment(db_path: Path, active_tab: str, selected_run_id: Optional[int]):
    """
    Renders the selected dashboard view with live read-only database access.
    Gracefully handles missing or uninitialized database files.
    """
    conn = get_db_connection(db_path)
    if conn is None:
        st.markdown(
            f"""
            <div class="advisory-banner" style="font-size:0.92rem;">
                <b>⚠️ Database Not Found:</b> Unable to connect to <code>{db_path}</code>.<br><br>
                To launch the backend collection pipeline, run:
                <pre style="background:rgba(0,0,0,0.4); padding:10px; border-radius:6px; margin-top:8px;">
python src/init_live_database.py --db-path data/live_monitoring.db
python src/live_collector.py --db-path data/live_monitoring.db --serial-port COM6
                </pre>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    try:
        if active_tab == "Overview & Live Feed":
            render_system_overview(conn, selected_run_id)
        elif active_tab == "Live Network Traffic":
            render_network_monitoring(conn, selected_run_id)
        elif active_tab == "Anomaly Alerts Console":
            render_anomaly_alerts(conn, selected_run_id)
        elif active_tab == "Attack Intelligence":
            render_attack_intelligence(conn, selected_run_id)
        elif active_tab == "Physical Sensors (ESP32)":
            render_sensor_monitoring(conn, selected_run_id)
        elif active_tab == "Device Registry":
            render_device_registry(conn)
        elif active_tab == "Daemon Diagnostics":
            render_diagnostics(conn, db_path, run_id=selected_run_id)
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# MAIN STREAMLIT APPLICATION ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
def main():
    with st.sidebar:
        # Branding
        st.markdown(
            f"""
            <div style="padding: 12px 0 16px 0;">
                <div style="display:flex; align-items:center; gap:12px;">
                    <div style="width:40px; height:40px; background: linear-gradient(135deg, {DARK_PALETTE['accent_cyan']}, {DARK_PALETTE['accent_blue']});
                                border-radius:10px; display:flex; align-items:center; justify-content:center;
                                font-size:1.35rem; box-shadow: 0 2px 10px rgba(34,211,238,0.25);">
                        🛡️
                    </div>
                    <div>
                        <div style="font-size: 1.05rem; font-weight: 800; color: #FFFFFF; letter-spacing: -0.02em;">
                            IoT NETWORK GUARD
                        </div>
                        <div style="font-size: 0.70rem; color: {DARK_PALETTE['accent_cyan']}; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;">
                            Dual-Detector SOC Console
                        </div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("---")

        active_tab = st.radio(
            "Navigation Menu",
            options=[
                "Overview & Live Feed",
                "Live Network Traffic",
                "Anomaly Alerts Console",
                "Attack Intelligence",
                "Physical Sensors (ESP32)",
                "Device Registry",
                "Daemon Diagnostics",
            ],
            index=0,
            label_visibility="collapsed",
        )

        st.markdown("---")

        st.markdown(
            f"""
            <div style="font-size:0.72rem; font-weight:700; color:{DARK_PALETTE['text_muted']}; text-transform:uppercase; letter-spacing:0.06em; margin-bottom:8px;">
                System Controls
            </div>
            """,
            unsafe_allow_html=True,
        )
        db_path_input = st.text_input("Live DB Path", value=str(DEFAULT_LIVE_DB_PATH))
        db_path = Path(db_path_input)

        # Run ID filter
        conn = get_db_connection(db_path)
        selected_run_id = None
        if conn:
            try:
                run_rows = conn.execute("SELECT run_id, status FROM collector_status ORDER BY run_id DESC").fetchall()
                run_options = ["Latest Session"] + [f"Run #{r[0]} ({r[1]})" for r in run_rows]
                selected_run_str = st.selectbox("Collector Run Filter", options=run_options, index=0)
                if selected_run_str != "Latest Session":
                    selected_run_id = int(selected_run_str.split()[1].replace("#", ""))
            except Exception:
                pass
            finally:
                conn.close()

        # Manual Refresh Trigger
        st.markdown("<div style='height: 4px;'></div>", unsafe_allow_html=True)
        if st.button("🔄 Refresh Data Now", use_container_width=True):
            st.rerun()

        st.markdown(
            f"""
            <div style="font-size:0.68rem; color:#64748B; margin-top:20px; line-height:1.45;">
                <b style="color:#94A3B8;">Console Diagnostics:</b><br>
                • Streamlit: <code>v{st.__version__}</code><br>
                • Model: <code>Dual IF (Session 1 Frozen)</code><br>
                • Storage: <code>SQLite WAL (Read-Only)</code><br>
                • Console Clock: <code>{datetime.datetime.now(datetime.timezone.utc).strftime('%H:%M:%S')} UTC</code>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Render Active Tab inside Live Fragment
    render_live_dashboard_fragment(db_path, active_tab, selected_run_id)


if __name__ == "__main__":
    main()
