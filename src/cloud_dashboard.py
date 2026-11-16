"""
AI-Assisted IoT Wi-Fi Network Security and Anomaly Detection
Cloud Interactive Monitoring Dashboard — Public SOC Console
File: src/cloud_dashboard.py

Purpose:
  Streamlit Community Cloud-compatible public cybersecurity console.
  Connects exclusively to Supabase Managed PostgreSQL via sanitized public views
  (v_public_*) over PostgREST.

Key Architectural & Security Invariants:
  1. ZERO ACCESS TO BASE TABLES: Connects with the unprivileged 'anon' public role.
     Direct base table access is 100% revoked; only definer views are queryable.
  2. PRIVACY & PSEUDONYMIZATION: Zero raw MAC addresses, private IP addresses, or
     unvetted private tokens. Station tokens are mapped to allowlisted pseudonyms.
  3. READ-ONLY ARCHITECTURE: Never issues INSERT, UPDATE, DELETE, or DDL commands.
  4. NO HARDWARE OR LOCAL DB DEPENDENCIES: Zero COM6, TShark, or local SQLite requirements.
  5. RESILIENT ZERO-CRASH DESIGN: Handles offline states, empty datasets, and API errors
     gracefully with professional SOC fallback indicators.
  6. XSS & INJECTION PROTECTION: Every dynamic database value rendered in HTML is escaped
     exactly once using html.escape().
  7. NON-BLOCKING STREAMLIT REFRESH: Uses native st.fragment(run_every=...) for periodic
     refresh without blocking the server or freezing UI threads.

Launch Command:
  streamlit run src/cloud_dashboard.py --server.port 8503
"""

import datetime
import html as html_lib
import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import requests
import streamlit as st

logger = logging.getLogger("CloudDashboard")

# ─────────────────────────────────────────────────────────────────────────────
# PAGE CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="IoT Network Guard | Cloud SOC Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────────────
# DESIGN SYSTEM: SOC OBSIDIAN PALETTE
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
    "accent_blue": "#38BDF8",
    "accent_green": "#10B981",
    "accent_yellow": "#F59E0B",
    "accent_red": "#EF4444",
    "accent_purple": "#A855F7",
}

CUSTOM_CSS = f"""
<style>
    .stApp {{
        background-color: {DARK_PALETTE['bg']};
        color: {DARK_PALETTE['text']};
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }}
    [data-testid="stSidebar"] {{
        background-color: {DARK_PALETTE['sidebar']};
        border-right: 1px solid {DARK_PALETTE['border']};
    }}
    .soc-card {{
        background-color: {DARK_PALETTE['surface']};
        border: 1px solid {DARK_PALETTE['border']};
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
    }}
    .soc-badge {{
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
        letter-spacing: 0.05em;
        text-transform: uppercase;
    }}
    .badge-live {{ background: rgba(16, 185, 129, 0.2); color: #34D399; border: 1px solid #10B981; }}
    .badge-stale {{ background: rgba(245, 158, 11, 0.2); color: #FBBF24; border: 1px solid #F59E0B; }}
    .badge-offline {{ background: rgba(239, 68, 68, 0.2); color: #F87171; border: 1px solid #EF4444; }}
    .badge-critical {{ background: rgba(239, 68, 68, 0.25); color: #FCA5A5; border: 1px solid #EF4444; }}
    .badge-high {{ background: rgba(249, 115, 22, 0.25); color: #FDBA74; border: 1px solid #F97316; }}
    .badge-medium {{ background: rgba(245, 158, 11, 0.25); color: #FDE68A; border: 1px solid #F59E0B; }}
    .badge-low {{ background: rgba(59, 130, 246, 0.25); color: #93C5FD; border: 1px solid #3B82F6; }}
    .badge-info {{ background: rgba(148, 163, 184, 0.25); color: #CBD5E1; border: 1px solid #94A3B8; }}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# SAFE ESCAPING & NUMERIC VALIDATION HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def safe_html(val: Any) -> str:
    """Escapes dynamic database values before HTML insertion to prevent XSS and injection."""
    if val is None:
        return ""
    return html_lib.escape(str(val))


def safe_float(val: Any, default: float = 0.0) -> float:
    """Converts value to float safely, handling None, NaN, inf, malformed strings without crashing."""
    if val is None:
        return default
    try:
        if pd.isna(val):
            return default
        f = float(val)
        return default if (f != f) else f
    except (ValueError, TypeError, OverflowError):
        return default


def safe_int(val: Any, default: int = 0) -> int:
    """Converts value to int safely, handling None, NaN, floats, malformed strings without crashing."""
    if val is None:
        return default
    try:
        if pd.isna(val):
            return default
        return int(float(val))
    except (ValueError, TypeError, OverflowError):
        return default


# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION & POSTGREST CLIENT
# ─────────────────────────────────────────────────────────────────────────────

def get_supabase_config() -> Tuple[str, str]:
    """
    Retrieves Supabase URL and Anon Key from Streamlit Secrets or Environment.
    Supports both nested [supabase] format and flat top-level variables.
    Strictly rejects service-role keys or collector database passwords in public dashboard.
    """
    url = ""
    anon_key = ""

    # 1. Streamlit Secrets (handles local secrets.toml or cloud settings)
    try:
        if hasattr(st, "secrets"):
            # Nested [supabase] format (recommended)
            if "supabase" in st.secrets:
                sub = st.secrets["supabase"]
                url = str(sub.get("url", "") or sub.get("SUPABASE_URL", ""))
                anon_key = str(sub.get("key", "") or sub.get("anon_key", "") or sub.get("SUPABASE_ANON_KEY", ""))

            # Flat top-level format fallback
            if not url:
                url = str(st.secrets.get("SUPABASE_URL", "") or st.secrets.get("url", ""))
            if not anon_key:
                anon_key = str(st.secrets.get("SUPABASE_ANON_KEY", "") or st.secrets.get("SUPABASE_KEY", "") or st.secrets.get("key", ""))
    except Exception:
        url = ""
        anon_key = ""

    # 2. Environment Variables fallback
    if not url:
        url = os.getenv("SUPABASE_URL", "https://cwqumhtzeiqrfhlesksw.supabase.co")
    if not anon_key:
        anon_key = os.getenv("SUPABASE_ANON_KEY", "") or os.getenv("SUPABASE_KEY", "")

    # 3. Security Sanity Check: Never allow service_role key or collector DB credentials
    if anon_key:
        if "service_role" in anon_key.lower():
            logger.warning("PROHIBITED: service_role key detected in dashboard secrets! Discarding for security.")
            anon_key = ""
        elif os.getenv("SUPABASE_SERVICE_KEY") and anon_key == os.getenv("SUPABASE_SERVICE_KEY"):
            logger.warning("PROHIBITED: service_role key match detected! Discarding.")
            anon_key = ""

    return url.rstrip("/"), anon_key


@st.cache_data(ttl=5.0)
def fetch_cloud_view(
    view_name: str,
    limit: int = 100,
    order_column: Optional[str] = None,
    order_desc: bool = True,
    filters: Optional[Dict[str, str]] = None,
) -> Tuple[pd.DataFrame, Optional[str]]:
    """
    Queries a sanitized public PostgREST view with caching (5s TTL).
    Returns (DataFrame, error_message).
    """
    supabase_url, anon_key = get_supabase_config()
    if not supabase_url or not anon_key:
        return pd.DataFrame(), "Awaiting Supabase cloud credentials in Streamlit Secrets or environment variables."

    endpoint = f"{supabase_url}/rest/v1/{view_name}"
    headers = {
        "apikey": anon_key,
        "Authorization": f"Bearer {anon_key}",
        "Accept": "application/json",
    }
    params: Dict[str, Any] = {"select": "*", "limit": limit}
    if order_column:
        direction = "desc" if order_desc else "asc"
        params["order"] = f"{order_column}.{direction}"

    if filters:
        for k, v in filters.items():
            params[k] = v

    try:
        resp = requests.get(endpoint, headers=headers, params=params, timeout=8.0)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                return pd.DataFrame(data), None
            return pd.DataFrame([data]), None
        elif resp.status_code in (401, 403):
            return pd.DataFrame(), f"Access Denied (HTTP {resp.status_code}): Invalid or expired Supabase Anon Key."
        elif resp.status_code == 404:
            return pd.DataFrame(), f"View '{view_name}' not found. Verify Stage 3B migration has been executed."
        else:
            return pd.DataFrame(), f"Cloud API Error (HTTP {resp.status_code}): {resp.text[:200]}"
    except requests.exceptions.RequestException as e:
        return pd.DataFrame(), f"Network connection error: {str(e)[:200]}"
    except Exception as e:
        return pd.DataFrame(), f"Unexpected error: {str(e)[:200]}"


# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR NAVIGATION & HEALTH STATUS
# ─────────────────────────────────────────────────────────────────────────────

supabase_url, anon_key = get_supabase_config()

with st.sidebar:
    st.markdown("### 🛡️ IoT Network Guard")
    st.markdown("**Cloud SOC Console (v3.6.0)**")
    st.markdown("---")

    # Cloud Link Status (Single Host Display)
    if supabase_url and anon_key:
        host_display = safe_html(supabase_url.split("//")[-1])
        st.markdown(
            f"""<div style="font-size:0.8rem; margin-bottom:12px;">
                <span class="soc-badge badge-live">Cloud Link Active</span><br>
                <span style="color:{DARK_PALETTE['text_dim']}; font-family:monospace;">Host: {host_display}</span>
            </div>""",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """<div style="font-size:0.8rem; margin-bottom:12px;">
                <span class="soc-badge badge-stale">Demo / Standby Mode</span><br>
                <span style="color:#F59E0B;">Credentials unconfigured</span>
            </div>""",
            unsafe_allow_html=True,
        )

    nav_selection = st.radio(
        "SOC Console Sections",
        [
            "1. Overview & Live Feed",
            "2. Live Network Traffic",
            "3. Anomaly Alerts Console",
            "4. Attack Intelligence",
            "5. Physical Sensors (ESP32)",
            "6. Device Registry",
            "7. Daemon Diagnostics",
        ],
        index=0,
        key="cloud_soc_nav_radio",
    )

    st.markdown("---")
    # Single auto-refresh checkbox with unique key
    auto_refresh = st.checkbox("Auto-refresh data (10s)", value=False, key="cloud_dash_auto_refresh")

    if st.button("🔄 Refresh Now", use_container_width=True, key="cloud_dash_refresh_btn"):
        st.cache_data.clear()
        st.rerun()

    st.markdown("---")
    st.markdown(
        f"""<div style="font-size:0.75rem; color:{DARK_PALETTE['text_dim']}; line-height:1.4;">
            <b>Privacy Invariant:</b><br>
            • Definer views active (PoLP)<br>
            • Station tokens allowlisted<br>
            • Semantic IP boundaries<br>
            • Zero raw MAC exposure
        </div>""",
        unsafe_allow_html=True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# NON-BLOCKING DASHBOARD RENDER FRAGMENT
# ─────────────────────────────────────────────────────────────────────────────

@st.fragment(run_every=10 if auto_refresh else None)
def render_soc_dashboard(section: str) -> None:
    """Renders the selected dashboard section with non-blocking auto-refresh."""

    # ─────────────────────────────────────────────────────────────────────────
    # SECTION 1: OVERVIEW & LIVE FEED
    # ─────────────────────────────────────────────────────────────────────────
    if section == "1. Overview & Live Feed":
        st.title("🛡️ SOC Overview & Telemetry Feed")
        st.markdown("Real-time telemetry and consensus anomaly summary from cloud persistence layer.")

        # Fetch views
        status_df, status_err = fetch_cloud_view("v_public_collector_status", limit=1, order_column="started_at", order_desc=True)
        overview_df, overview_err = fetch_cloud_view("v_public_traffic_overview", limit=1)
        attacks_df, attacks_err = fetch_cloud_view("v_public_attack_events", limit=5, order_column="timestamp_epoch", order_desc=True)

        # 1. Daemon Connection Banner (Single element)
        if not status_df.empty:
            status_row = status_df.iloc[0]
            age_sec = safe_float(status_row.get("heartbeat_age_seconds"), default=999.0)

            if age_sec <= 15.0:
                state = "LIVE"
                badge_class = "badge-live"
            elif age_sec <= 60.0:
                state = "STALE"
                badge_class = "badge-stale"
            else:
                state = "OFFLINE"
                badge_class = "badge-offline"

            run_id_display = safe_html(status_row.get("run_id", "N/A"))
            age_display = safe_html(f"{age_sec:.1f}") if age_sec < 900.0 else "N/A"
            if_display = safe_html(status_row.get("interface_name", "Virtual AP"))
            serial_display = safe_html(status_row.get("serial_port", "ESP32"))

            st.markdown(
                f"""<div class="soc-card" style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="soc-badge {badge_class}">{state}</span>
                        <span style="font-size:1.1rem; font-weight:600; margin-left:12px;">Collector Daemon Run {run_id_display}</span>
                        <span style="color:{DARK_PALETTE['text_muted']}; margin-left:12px; font-size:0.85rem;">Heartbeat: {age_display}s ago</span>
                    </div>
                    <div style="font-size:0.85rem; color:{DARK_PALETTE['text_dim']};">
                        Interface: {if_display} | Serial: {serial_display}
                    </div>
                </div>""",
                unsafe_allow_html=True,
            )
        elif status_err:
            st.warning(f"Cloud Status Notice: {status_err}")
        else:
            st.info("No collector status records currently present in cloud persistence.")

        # 2. Key Metrics Row
        m1, m2, m3, m4, m5 = st.columns(5)
        with m1:
            total_pkts = safe_int(overview_df.iloc[0].get("total_packets")) if not overview_df.empty else 0
            st.metric("Total Packets Captured", f"{total_pkts:,}")
        with m2:
            total_wins = safe_int(overview_df.iloc[0].get("total_windows")) if not overview_df.empty else 0
            st.metric("1s Feature Windows", f"{total_wins:,}")
        with m3:
            anom_wins = safe_int(overview_df.iloc[0].get("anomaly_windows")) if not overview_df.empty else 0
            st.metric("Consensus Anomalies", f"{anom_wins:,}")
        with m4:
            peak_rate = safe_float(overview_df.iloc[0].get("peak_rate")) if not overview_df.empty else 0.0
            st.metric("Peak Packet Rate", f"{peak_rate:.1f} pps")
        with m5:
            anom_pct = safe_float(overview_df.iloc[0].get("anomaly_pct")) if not overview_df.empty else 0.0
            st.metric("Anomaly Ratio", f"{anom_pct:.2f}%")

        # 3. Recent Forensic Attack Intelligence
        st.markdown("### 🚨 Recent Forensic Attack Intelligence")
        if not attacks_df.empty:
            for _, att in attacks_df.iterrows():
                raw_sev = str(att.get("severity", "INFO")).upper()
                sev = safe_html(raw_sev)
                sev_class = "badge-critical" if raw_sev == "CRITICAL" else ("badge-high" if raw_sev == "HIGH" else "badge-medium")
                conf = safe_float(att.get("confidence", 0.0)) * 100.0

                cat_display = safe_html(att.get("category", "Threat Detected"))
                src_display = safe_html(att.get("source_station_id", "Unmapped"))
                tgt_display = safe_html(att.get("target_ip", "LOCAL_NETWORK"))
                rec_display = safe_html(att.get("recommended_action", "Triage event"))
                ts_display = safe_html(att.get("timestamp_utc", "N/A"))
                uuid_display = safe_html(att.get("event_uuid", "N/A"))

                border_color = DARK_PALETTE["accent_red"] if raw_sev in ("CRITICAL", "HIGH") else DARK_PALETTE["accent_yellow"]

                st.markdown(
                    f"""<div class="soc-card" style="border-left: 4px solid {border_color};">
                        <div style="display:flex; justify-content:space-between; margin-bottom:8px;">
                            <div>
                                <span class="soc-badge {sev_class}">{sev}</span>
                                <span style="font-weight:600; margin-left:8px; font-size:1.05rem;">{cat_display}</span>
                                <span style="color:{DARK_PALETTE['text_dim']}; font-size:0.85rem; margin-left:8px;">Source: {src_display}</span>
                            </div>
                            <div style="font-size:0.85rem; color:{DARK_PALETTE['text_dim']};">
                                Scope: {tgt_display} | Confidence: {conf:.0f}%
                            </div>
                        </div>
                        <div style="font-size:0.9rem; color:{DARK_PALETTE['text']}; margin-bottom:4px;">
                            <b>Recommended SOC Mitigation:</b> {rec_display}
                        </div>
                        <div style="font-size:0.8rem; color:{DARK_PALETTE['text_dim']};">
                            Timestamp: {ts_display} | UUID: {uuid_display}
                        </div>
                    </div>""",
                    unsafe_allow_html=True,
                )
        elif attacks_err:
            st.warning(f"Attack Feed Notice: {attacks_err}")
        else:
            st.info("No attack events detected in the cloud database. Fleet status is benign.")

    # ─────────────────────────────────────────────────────────────────────────
    # SECTION 2: LIVE NETWORK TRAFFIC
    # ─────────────────────────────────────────────────────────────────────────
    elif section == "2. Live Network Traffic":
        st.title("📊 Live Network Traffic Telemetry")
        st.markdown("1-second window feature time-series and dual-detector isolation forest scoring.")

        windows_df, win_err = fetch_cloud_view("v_public_live_traffic_windows", limit=120, order_column="bin_start_epoch", order_desc=False)

        if not windows_df.empty:
            # Numeric safety conversion before charting
            windows_df["bin_start_epoch"] = pd.to_numeric(windows_df["bin_start_epoch"], errors="coerce").fillna(0.0)
            windows_df["packet_rate"] = pd.to_numeric(windows_df["packet_rate"], errors="coerce").fillna(0.0)
            windows_df["score_primary"] = pd.to_numeric(windows_df["score_primary"], errors="coerce").fillna(0.0)

            fig = make_subplots(
                rows=2, cols=1,
                shared_xaxes=True,
                vertical_spacing=0.08,
                subplot_titles=("Packet Rate (pps) by Station Token", "Dual-Detector Consensus Score"),
            )

            node_colors = {
                "Node_3": DARK_PALETTE["accent_cyan"],
                "Node_4": DARK_PALETTE["accent_purple"],
                "Node_5": DARK_PALETTE["accent_blue"],
            }

            for node_id, group in windows_df.groupby("public_station_id"):
                color = node_colors.get(str(node_id), "#94A3B8")
                fig.add_trace(
                    go.Scatter(
                        x=pd.to_datetime(group["bin_start_epoch"], unit="s", errors="coerce"),
                        y=group["packet_rate"],
                        mode="lines+markers",
                        name=f"{safe_html(node_id)} Rate",
                        line=dict(color=color, width=2),
                        marker=dict(size=4),
                    ),
                    row=1, col=1,
                )

                anom_points = group[group["pred_dual"] == -1]
                if not anom_points.empty:
                    fig.add_trace(
                        go.Scatter(
                            x=pd.to_datetime(anom_points["bin_start_epoch"], unit="s", errors="coerce"),
                            y=anom_points["packet_rate"],
                            mode="markers",
                            name=f"{safe_html(node_id)} Anomaly",
                            marker=dict(color=DARK_PALETTE["accent_red"], size=8, symbol="triangle-up"),
                        ),
                        row=1, col=1,
                    )

            fig.add_trace(
                go.Scatter(
                    x=pd.to_datetime(windows_df["bin_start_epoch"], unit="s", errors="coerce"),
                    y=windows_df["score_primary"],
                    mode="lines",
                    name="Primary Score (IF)",
                    line=dict(color=DARK_PALETTE["accent_blue"], width=1.5),
                ),
                row=2, col=1,
            )

            fig.update_layout(
                paper_bgcolor=DARK_PALETTE["surface"],
                plot_bgcolor=DARK_PALETTE["bg"],
                font=dict(color=DARK_PALETTE["text"]),
                height=500,
                margin=dict(l=40, r=40, t=40, b=30),
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            )
            fig.update_xaxes(gridcolor=DARK_PALETTE["border"])
            fig.update_yaxes(gridcolor=DARK_PALETTE["border"])
            st.plotly_chart(fig, use_container_width=True)

            st.markdown("### 📋 Completed Traffic Feature Slices (Most Recent 25)")
            cols_to_show = [c for c in ["window_id", "public_station_id", "packet_count", "packet_rate", "mean_packet_size", "pred_dual", "dual_reason", "window_start_utc"] if c in windows_df.columns]
            st.dataframe(windows_df[cols_to_show].tail(25).iloc[::-1], use_container_width=True)
        elif win_err:
            st.warning(f"Telemetry Notice: {win_err}")
        else:
            st.info("No traffic window records found in cloud database.")

    # ─────────────────────────────────────────────────────────────────────────
    # SECTION 3: ANOMALY ALERTS CONSOLE
    # ─────────────────────────────────────────────────────────────────────────
    elif section == "3. Anomaly Alerts Console":
        st.title("🚨 Anomaly Alerts Console")
        st.markdown("Statistical Isolation Forest anomaly detections requiring operator review. (Non-blocking, non-destructive).")

        alerts_df, alert_err = fetch_cloud_view("v_public_live_alerts", limit=50, order_column="bin_start_epoch", order_desc=True)

        if not alerts_df.empty:
            cols_to_show = [c for c in ["alert_id", "public_station_id", "dual_reason", "packet_rate", "mean_packet_size", "packet_count", "score_primary", "window_start_utc"] if c in alerts_df.columns]
            st.dataframe(alerts_df[cols_to_show], use_container_width=True)
        elif alert_err:
            st.warning(f"Alerts Notice: {alert_err}")
        else:
            st.info("No anomaly alerts present in the cloud database.")

    # ─────────────────────────────────────────────────────────────────────────
    # SECTION 4: ATTACK INTELLIGENCE
    # ─────────────────────────────────────────────────────────────────────────
    elif section == "4. Attack Intelligence":
        st.title("🎯 Forensic Attack Intelligence")
        st.markdown("Deterministic multi-layer cyberattack classifications with explainable evidence telemetry.")

        attacks_df, att_err = fetch_cloud_view("v_public_attack_events", limit=50, order_column="timestamp_epoch", order_desc=True)

        if not attacks_df.empty:
            for _, att in attacks_df.iterrows():
                raw_sev = str(att.get("severity", "INFO")).upper()
                sev = safe_html(raw_sev)
                sev_class = "badge-critical" if raw_sev == "CRITICAL" else ("badge-high" if raw_sev == "HIGH" else "badge-medium")
                conf = safe_float(att.get("confidence", 0.0)) * 100.0

                evidence = att.get("sanitized_evidence_json", {})
                if isinstance(evidence, str):
                    try:
                        evidence = json.loads(evidence)
                    except Exception:
                        evidence = {}

                cat_display = safe_html(att.get("category", "Threat Detected"))
                src_display = safe_html(att.get("source_station_id", "Unmapped"))
                tgt_display = safe_html(att.get("target_ip", "LOCAL_NETWORK"))
                status_display = safe_html(att.get("status", "EVALUATED"))
                rec_display = safe_html(att.get("recommended_action", "Triage finding"))
                evidence_display = safe_html(json.dumps(evidence))

                border_color = DARK_PALETTE["accent_red"] if raw_sev in ("CRITICAL", "HIGH") else DARK_PALETTE["accent_yellow"]

                st.markdown(
                    f"""<div class="soc-card" style="border-left: 4px solid {border_color};">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <div>
                                <span class="soc-badge {sev_class}">{sev}</span>
                                <span style="font-weight:600; font-size:1.1rem; margin-left:8px;">{cat_display}</span>
                                <span style="color:{DARK_PALETTE['text_dim']}; font-size:0.85rem; margin-left:12px;">Source: {src_display}</span>
                                <span style="color:{DARK_PALETTE['text_dim']}; font-size:0.85rem; margin-left:12px;">Target Scope: {tgt_display}</span>
                            </div>
                            <div style="font-size:0.85rem; color:{DARK_PALETTE['text_dim']};">
                                Confidence: <b>{conf:.0f}%</b> | Status: <b>{status_display}</b>
                            </div>
                        </div>
                        <div style="margin-top:10px; font-size:0.9rem; line-height:1.5;">
                            <b>Security Recommendation:</b> {rec_display}<br>
                            <b>Forensic Findings:</b> <span style="font-family:monospace; font-size:0.85rem; color:{DARK_PALETTE['accent_cyan']};">{evidence_display}</span>
                        </div>
                    </div>""",
                    unsafe_allow_html=True,
                )
        elif att_err:
            st.warning(f"Attack Intelligence Notice: {att_err}")
        else:
            st.info("No cyberattack events flagged by the deterministic detection engine.")

    # ─────────────────────────────────────────────────────────────────────────
    # SECTION 5: PHYSICAL SENSORS (ESP32)
    # ─────────────────────────────────────────────────────────────────────────
    elif section == "5. Physical Sensors (ESP32)":
        st.title("🌡️ Physical Environment & Sensor Telemetry")
        st.markdown("Ambient temperature, humidity, and PIR motion telemetry from ESP32 gateway.")

        sensors_df, sens_err = fetch_cloud_view("v_public_sensor_telemetry", limit=100, order_column="sequence_num", order_desc=False)
        pir_df, pir_err = fetch_cloud_view("v_public_pir_events", limit=100, order_column="sequence_num", order_desc=False)

        if not sensors_df.empty:
            c1, c2, c3 = st.columns(3)
            latest_sensor = sensors_df.iloc[-1]
            temp_val = safe_float(latest_sensor.get("temperature_c"))
            hum_val = safe_float(latest_sensor.get("humidity_pct"))
            phys_node = safe_html(str(latest_sensor.get("physical_node_id") or "esp32_gateway"))
            log_node = safe_html(str(latest_sensor.get("logical_node_id") or "Node_1"))

            with c1:
                st.metric("Temperature", f"{temp_val:.1f} °C")
            with c2:
                st.metric("Relative Humidity", f"{hum_val:.1f} %")
            with c3:
                motion_detected = bool(not pir_df.empty and pir_df.iloc[-1].get("motion_detected"))
                motion_state = "MOTION DETECTED" if motion_detected else "CLEAR"
                st.metric("PIR Motion Sensor", motion_state)

            st.caption(f"Active Sensor Node: `{phys_node}` (Logical Channel: `{log_node}`)")

            # Safe numeric typing for plotly charts
            sensors_df["sequence_num"] = pd.to_numeric(sensors_df["sequence_num"], errors="coerce").fillna(0)
            sensors_df["temperature_c"] = pd.to_numeric(sensors_df["temperature_c"], errors="coerce").fillna(0.0)
            sensors_df["humidity_pct"] = pd.to_numeric(sensors_df["humidity_pct"], errors="coerce").fillna(0.0)

            fig = go.Figure()
            fig.add_trace(go.Scatter(x=sensors_df["sequence_num"], y=sensors_df["temperature_c"], name="Temperature (°C)", line=dict(color=DARK_PALETTE["accent_yellow"])))
            fig.add_trace(go.Scatter(x=sensors_df["sequence_num"], y=sensors_df["humidity_pct"], name="Humidity (%)", line=dict(color=DARK_PALETTE["accent_blue"])))
            fig.update_layout(
                paper_bgcolor=DARK_PALETTE["surface"],
                plot_bgcolor=DARK_PALETTE["bg"],
                font=dict(color=DARK_PALETTE["text"]),
                height=380,
                margin=dict(l=40, r=40, t=30, b=30),
            )
            st.plotly_chart(fig, use_container_width=True)
        elif sens_err:
            st.warning(f"Sensor Telemetry Notice: {sens_err}")
        else:
            st.info("No physical sensor records currently found in cloud persistence.")

    # ─────────────────────────────────────────────────────────────────────────
    # SECTION 6: DEVICE REGISTRY
    # ─────────────────────────────────────────────────────────────────────────
    elif section == "6. Device Registry":
        st.title("📱 Authorized Device Registry & Surveillance")
        st.markdown("Curated station profiles and unknown device surveillance. (Zero raw MACs exposed).")

        reg_df, reg_err = fetch_cloud_view("v_public_device_registry", limit=20)
        unk_df, unk_err = fetch_cloud_view("v_public_unknown_device_obs", limit=20)

        st.markdown("### Known Authorized Stations")
        if not reg_df.empty:
            st.dataframe(reg_df, use_container_width=True)
        elif reg_err:
            st.warning(f"Registry Notice: {reg_err}")
        else:
            st.info("No registered devices present in cloud view.")

        st.markdown("### Unknown Wireless Node Observations")
        if not unk_df.empty:
            st.dataframe(unk_df, use_container_width=True)
        elif unk_err:
            st.warning(f"Surveillance Notice: {unk_err}")
        else:
            st.info("Zero unknown device observations recorded.")

    # ─────────────────────────────────────────────────────────────────────────
    # SECTION 7: DAEMON DIAGNOSTICS
    # ─────────────────────────────────────────────────────────────────────────
    elif section == "7. Daemon Diagnostics":
        st.title("⚙️ Collector Daemon Diagnostics")
        st.markdown("Real-time cloud health, heartbeat age, and PostgREST schema verification.")

        status_df, status_err = fetch_cloud_view("v_public_collector_status", limit=10, order_column="started_at", order_desc=True)

        if not status_df.empty:
            st.dataframe(status_df, use_container_width=True)
        elif status_err:
            st.warning(f"Diagnostics Notice: {status_err}")
        else:
            st.info("No collector diagnostic history available in cloud database.")

        st.markdown("---")
        st.markdown("### 🔒 Cloud Architecture & Privacy Audit Status")
        st.markdown(
            f"""<div class="soc-card">
                <b>Target PostgreSQL Project:</b> cwqumhtzeiqrfhlesksw (Mumbai / ap-south-1)<br>
                <b>Engine Version:</b> PostgreSQL 17.6<br>
                <b>Security Model:</b> View Definer (security_invoker = false) owned by postgres<br>
                <b>Public Role Grants:</b> SELECT on 9 v_public_* views ONLY (Base tables 100% revoked)<br>
                <b>Public Station Pseudonyms:</b> Closed allowlist ('Node_1'..'Node_5')<br>
                <b>Network IP Scope:</b> Semantic boundary redaction (LOCAL_NETWORK, EXTERNAL_NETWORK, IP_REDACTED)
            </div>""",
            unsafe_allow_html=True,
        )


# Render dashboard section inside non-blocking fragment
render_soc_dashboard(nav_selection)
