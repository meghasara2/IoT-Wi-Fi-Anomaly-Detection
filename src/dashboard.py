"""
AI-Assisted IoT Wi-Fi Anomaly Detection
Streamlit Academic Research Dashboard (Stage 21D - Final UI / Design-System Pass)
Software-Only Network Behaviour Analysis

This dashboard provides read-only monitoring and evaluation of the
SQLite research database (data/iot_anomaly.db).

All values are read directly from SQLite in read-only URI mode. The
presentation layer in this file never writes to the database and does
not alter any model, dataset or evaluation result. It displays the
results of completed experimental runs; it is not a live monitor.

Design-system layout of this file
---------------------------------
THEME_TOKENS       colour tokens for the two presentation themes (Dark / Light)
TYPOGRAPHY_TOKENS  type scale shared by CSS and Plotly
build_css()        emits CSS custom properties from the tokens + one static sheet
plotly_theme()     Plotly layout derived from the same tokens
The theme selector is a presentation-only setting held in session state.
"""

import html as html_lib
import math
import sqlite3
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# -----------------------------------------------------------------------------
# PAGE CONFIGURATION
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="AI-Assisted IoT Wi-Fi Anomaly Detection | Research Console",
    page_icon=":material/hub:",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------------------------------------------------------
# DESIGN TOKENS
# -----------------------------------------------------------------------------
THEME_TOKENS = {
    "Dark": {
        "scheme": "dark",
        "bg": "#0A0F1A",
        "bg_glow": "rgba(86,200,236,0.055)",
        "surface": "#0E1522",
        "elevated": "#131C2D",
        "track": "#1B2639",
        "border": "#1F2B3D",
        "border_strong": "#2E405A",
        "text": "#E6EBF3",
        "text_2": "#B4BFD0",
        "text_muted": "#8995AA",
        "accent": "#56C8EC",
        "success": "#46D398",
        "warning": "#F0B44C",
        "danger": "#F47A6C",
        "series_normal": "#56C8EC",
        "series_anomaly": "#F47A6C",
        "input_bg": "#121B2B",
        "input_text": "#E6EBF3",
        "table_bg": "#0E1522",
        "table_head": "#131C2D",
        "table_text": "#E6EBF3",
        "hover": "rgba(86,200,236,0.06)",
        "chart_plot": "#0C1320",
        "chart_grid": "#1C2737",
        "chart_axis": "#34465F",
        "chart_text": "#B4BFD0",
        "tooltip_bg": "#131C2D",
        "grid_motif": "rgba(86,200,236,0.05)",
        "hero_from": "rgba(19,28,45,0.96)",
        "hero_to": "rgba(14,21,34,0.96)",
        "notice_bg": "rgba(10,15,26,0.55)",
        "shadow": "none",
        "fill_alpha": 0.40,
    },
    "Light": {
        "scheme": "light",
        "bg": "#EDF1F5",
        "bg_glow": "rgba(10,110,147,0.06)",
        "surface": "#FFFFFF",
        "elevated": "#F5F7FA",
        "track": "#E2E7EE",
        "border": "#D5DCE5",
        "border_strong": "#B3BFCE",
        "text": "#0D1726",
        "text_2": "#2F3D50",
        "text_muted": "#526073",
        "accent": "#0A6E93",
        "success": "#11784A",
        "warning": "#965800",
        "danger": "#BE3326",
        "series_normal": "#0E7AA3",
        "series_anomaly": "#C53A2D",
        "input_bg": "#FFFFFF",
        "input_text": "#0D1726",
        "table_bg": "#FFFFFF",
        "table_head": "#F2F5F8",
        "table_text": "#0D1726",
        "hover": "rgba(10,110,147,0.055)",
        "chart_plot": "#FFFFFF",
        "chart_grid": "#E7ECF2",
        "chart_axis": "#B3BFCE",
        "chart_text": "#2F3D50",
        "tooltip_bg": "#FFFFFF",
        "grid_motif": "rgba(10,110,147,0.075)",
        "hero_from": "#FFFFFF",
        "hero_to": "#F7F9FC",
        "notice_bg": "#F3F6F9",
        "shadow": "0 1px 2px rgba(13,23,38,0.05), 0 2px 10px rgba(13,23,38,0.04)",
        "fill_alpha": 0.28,
    },
}

TYPOGRAPHY_TOKENS = {
    "sans": "Inter, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif",
    "mono": "'JetBrains Mono', ui-monospace, 'Cascadia Code', Consolas, monospace",
    "fs_title": "34px",
    "fs_section": "26px",
    "fs_subsection": "19px",
    "fs_panel": "16.5px",
    "fs_metric_xl": "46px",
    "fs_metric_l": "30px",
    "fs_metric_m": "23px",
    "fs_body": "15.5px",
    "fs_table": "14.5px",
    "fs_sidebar": "14px",
    "fs_meta": "12.5px",
    "fs_eyebrow": "11.5px",
    "fs_tab": "15px",
    "lh_body": "1.55",
    # Plotly (pixel numbers)
    "chart_axis_title": 14,
    "chart_tick": 13,
    "chart_legend": 13.5,
    "chart_hover": 13,
}

FEATURES = {
    "mean_iat": ("mean_IAT", "mean inter-arrival time"),
    "iat_std": ("IAT_std", "inter-arrival time standard deviation"),
    "packet_rate": ("packet_rate", "packet rate"),
    "mean_packet_size": ("mean_packet_size", "mean packet size"),
    "packet_size_std": ("packet_size_std", "packet size standard deviation"),
}

LABEL_NORMAL_DS = "Normal baseline"
LABEL_ANOM_DS = "Controlled synthetic anomaly"
LABEL_ANOM_CLS = "Anomalous Behaviour"
LABEL_NORM_CLS = "Normal Behaviour"


# -----------------------------------------------------------------------------
# PRESENTATION STATE (theme + sticky segmented controls)
# -----------------------------------------------------------------------------
def _sticky(key: str) -> None:
    """Prevent a segmented control from being de-selected (keeps last value)."""
    last = f"_{key}_last"
    if st.session_state.get(key) is None:
        st.session_state[key] = st.session_state.get(last)
    else:
        st.session_state[last] = st.session_state[key]


def _init_state(key: str, default) -> None:
    if key not in st.session_state:
        st.session_state[key] = default
    st.session_state.setdefault(f"_{key}_last", default)


_init_state("ui_theme", "Dark")
ACTIVE_THEME = st.session_state.get("ui_theme") or "Dark"
T = THEME_TOKENS[ACTIVE_THEME]
TY = TYPOGRAPHY_TOKENS


def alpha(hex_color: str, a: float) -> str:
    """Hex colour -> rgba() string with the given alpha."""
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"rgba({r},{g},{b},{a})"


# -----------------------------------------------------------------------------
# STYLESHEET (tokens -> CSS custom properties; one static sheet uses var())
# -----------------------------------------------------------------------------
BASE_CSS = """
/* ---------- App shell ---------- */
html, body { color-scheme: var(--scheme); }
[data-testid="stApp"] {
  font-family: var(--sans);
  background: radial-gradient(1200px 460px at 82% -10%, var(--bg-glow), transparent 62%), var(--bg);
  color: var(--text);
}
[data-testid="stApp"] :where(p, li, label, input, textarea, button, h1, h2, h3, h4, h5, h6, [data-baseweb="select"] div) {
  font-family: var(--sans);
}
[data-testid="stHeader"] { background: transparent !important; }
[data-testid="stDecoration"], [data-testid="stAppDeployButton"], [data-testid="stHeaderActionElements"] { display: none !important; }
[data-testid="stToolbar"] button, [data-testid="stToolbar"] a, [data-testid="stMainMenu"] button,
[data-testid="stExpandSidebarButton"], [data-testid="stSidebarCollapseButton"] button,
[data-testid="stStatusWidget"] { color: var(--text-2) !important; }
[data-testid="stExpandSidebarButton"]:hover, [data-testid="stSidebarCollapseButton"] button:hover { background: var(--hover) !important; }
[data-testid="stMainBlockContainer"] { padding-top: 2.6rem; padding-bottom: 4rem; max-width: 1480px; }
[data-testid="stMarkdownContainer"] { color: var(--text); }
[data-testid="stMarkdownContainer"] p { color: var(--text); font-size: var(--fs-body); line-height: var(--lh-body); }
[data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] p { color: var(--text-muted) !important; font-size: 13px !important; }
::selection { background: var(--accent-soft-2); }
* { scrollbar-color: var(--border-strong) transparent; scrollbar-width: thin; }
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border-strong); border-radius: 6px; border: 2px solid transparent; background-clip: padding-box; }
:focus-visible { outline: 2px solid var(--accent) !important; outline-offset: 2px; }
.mono { font-family: var(--mono); }

/* ---------- Sidebar control panel ---------- */
[data-testid="stSidebar"] { background: var(--surface) !important; border-right: 1px solid var(--border); }
[data-testid="stSidebar"] > div { background: var(--surface) !important; }
[data-testid="stSidebar"] [data-testid="stSidebarUserContent"] { padding-top: 0.25rem; }
.sb-brand { display:flex; align-items:center; gap:12px; padding: 2px 0 16px; border-bottom:1px solid var(--border); margin-bottom: 16px; }
.sb-brand .t1 { font: 600 15.5px/1.25 var(--sans); color: var(--text); }
.sb-brand .t2 { font: 500 var(--fs-eyebrow)/1.3 var(--mono); color: var(--text-muted); letter-spacing: 0.08em; text-transform: uppercase; margin-top: 2px; }
.sb-group { margin-bottom: 20px; }
.sb-title {
  font: 600 var(--fs-eyebrow)/1 var(--mono); letter-spacing: 0.13em; text-transform: uppercase;
  color: var(--text-muted); margin: 0 0 10px; display:flex; align-items:center; gap:8px;
}
.sb-title::after { content:""; flex:1; height:1px; background: var(--border); }
.sb-hint { font-size: 12.5px; color: var(--text-muted); line-height: 1.45; margin: 6px 0 20px; }
.sb-row { display:flex; justify-content:space-between; align-items:baseline; gap:12px; padding: 7px 0; border-bottom: 1px dashed var(--border); }
.sb-row:last-child { border-bottom: none; }
.sb-row .k { font-size: var(--fs-sidebar); color: var(--text-2); white-space: nowrap; }
.sb-row .v { font-size: var(--fs-sidebar); font-weight: 500; color: var(--text); text-align:right; }
.sb-row .v.mono { font-size: 13.5px; }
.sb-lock { border: 1px solid var(--border-strong); border-left: 3px solid var(--success); background: var(--elevated); border-radius: 6px; padding: 12px 14px 6px; }
.sb-lock-head { display:flex; align-items:center; justify-content: space-between; gap:8px; margin-bottom: 6px; }
.badge {
  font: 600 var(--fs-eyebrow)/1 var(--mono); letter-spacing: 0.11em; color: var(--success);
  border: 1px solid var(--success-line); background: var(--success-soft);
  padding: 5px 8px; border-radius: 4px; display:inline-flex; align-items:center; gap:7px;
}
.sb-note { font-size: 12.5px; color: var(--text-muted); line-height: 1.5; margin-top: 10px; }

/* ---------- Native widgets ---------- */
[data-testid="stWidgetLabel"] p {
  font-size: 13.5px !important; font-weight: 600 !important; color: var(--text-2) !important; letter-spacing: 0.01em;
}
[data-baseweb="select"] > div {
  background: var(--input-bg) !important; border: 1px solid var(--border-strong) !important;
  border-radius: 6px !important; min-height: 42px; transition: border-color .15s;
}
[data-baseweb="select"] > div:hover, [data-baseweb="select"] > div:focus-within { border-color: var(--accent) !important; }
[data-baseweb="select"] div, [data-baseweb="select"] input, [data-baseweb="select"] span { color: var(--input-text) !important; font-size: 15px; }
[data-baseweb="select"] svg { color: var(--text-muted) !important; fill: var(--text-muted) !important; }
[data-baseweb="popover"] > div, [data-baseweb="popover"] [role="listbox"], [data-baseweb="popover"] ul, [data-baseweb="menu"] {
  background: var(--surface) !important; border-color: var(--border-strong) !important;
}
[data-baseweb="popover"] [role="listbox"] { border: 1px solid var(--border-strong) !important; box-shadow: 0 8px 24px rgba(0,0,0,0.18); }
[data-baseweb="popover"] li, [data-baseweb="popover"] [role="option"] { color: var(--text) !important; background: transparent !important; font-size: 15px; }
[data-baseweb="popover"] [role="option"] * { color: var(--text) !important; }
[data-baseweb="popover"] [role="option"]:hover, [data-baseweb="popover"] [role="option"][aria-selected="true"] { background: var(--accent-soft) !important; }

[data-testid="stButtonGroup"] button {
  background: var(--input-bg) !important; border-color: var(--border-strong) !important; color: var(--text-2) !important;
  min-height: 40px; transition: background .15s, border-color .15s, color .15s;
}
[data-testid="stButtonGroup"] button p { font-size: 14px !important; font-weight: 500 !important; color: inherit !important; }
[data-testid="stButtonGroup"] button span { color: inherit !important; }
[data-testid="stButtonGroup"] button:hover { color: var(--text) !important; background: var(--hover) !important; }
[data-testid="stBaseButton-segmented_controlActive"] {
  background: var(--accent-soft) !important; border-color: var(--accent) !important; color: var(--text) !important;
  box-shadow: inset 0 -2px 0 var(--accent) !important; z-index: 1;
}
[data-testid="stBaseButton-segmented_controlActive"] p { font-weight: 650 !important; }
.st-key-feat_feature button p { font-family: var(--mono) !important; font-size: 13.5px !important; }

[data-testid="stBaseButton-secondary"] {
  background: var(--input-bg) !important; border: 1px solid var(--border-strong) !important; color: var(--text) !important;
  border-radius: 6px !important; transition: border-color .15s, background .15s;
}
[data-testid="stBaseButton-secondary"] p { font-size: 14.5px !important; font-weight: 500; color: var(--text) !important; }
[data-testid="stBaseButton-secondary"]:hover { border-color: var(--accent) !important; background: var(--accent-soft) !important; }

[data-testid="stMetric"] { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; }
[data-testid="stMetricLabel"] p { color: var(--text-2) !important; font-size: 13.5px !important; }
[data-testid="stMetricValue"] { color: var(--text) !important; font-family: var(--mono); }
[data-testid="stExpander"] details { background: var(--surface) !important; border: 1px solid var(--border) !important; border-radius: 8px; }
[data-testid="stExpander"] summary, [data-testid="stExpander"] summary p { color: var(--text) !important; }
[data-testid="stAlert"], [data-testid="stAlertContainer"] { background: var(--elevated) !important; color: var(--text) !important; border: 1px solid var(--border); }
[data-testid="stAlert"] p { color: var(--text) !important; }
[data-testid="stPlotlyChart"] { animation: fadeIn .5s ease-out both; }

/* ---------- Tabs ---------- */
.stTabs [data-baseweb="tab-list"] { gap: 6px; border-bottom: 1px solid var(--border); background: transparent; }
.stTabs [data-baseweb="tab"] {
  height: 52px; padding: 0 18px; background: transparent !important; border-radius: 6px 6px 0 0; color: var(--text-muted);
  transition: color .15s, background .15s;
}
.stTabs [data-baseweb="tab"] p { font-size: var(--fs-tab) !important; font-weight: 600 !important; color: inherit !important; letter-spacing: 0.005em; }
.stTabs [data-baseweb="tab"]:hover { color: var(--text); background: var(--hover) !important; }
.stTabs [aria-selected="true"] { color: var(--text) !important; }
.stTabs [data-baseweb="tab-highlight"] { background-color: var(--accent) !important; height: 3px; border-radius: 2px; }
.stTabs [data-baseweb="tab-border"] { display: none; }
.stTabs [data-baseweb="tab-panel"] { padding-top: 1.75rem; animation: fadeUp .3s ease-out both; }

/* ---------- Hero ---------- */
.hero {
  position: relative; overflow: hidden; border: 1px solid var(--border); border-radius: 10px;
  background: linear-gradient(180deg, var(--hero-from), var(--hero-to)); box-shadow: var(--shadow);
  padding: 26px 30px 0; margin-bottom: 10px; animation: fadeUp .45s ease-out both;
}
.hero-grid {
  position:absolute; inset:0; pointer-events:none;
  background-image: linear-gradient(var(--grid-motif) 1px, transparent 1px), linear-gradient(90deg, var(--grid-motif) 1px, transparent 1px);
  background-size: 28px 28px;
  -webkit-mask-image: linear-gradient(100deg, transparent 38%, #000 88%); mask-image: linear-gradient(100deg, transparent 38%, #000 88%);
}
.hero-row { position:relative; display:flex; justify-content:space-between; align-items:flex-start; gap: 24px; flex-wrap: wrap; }
.hero-id { display:flex; gap: 18px; align-items:flex-start; min-width: 0; flex: 1 1 520px; }
.hero-mark { flex: 0 0 auto; width: 54px; height: 54px; border:1px solid var(--border-strong); border-radius: 10px; display:grid; place-items:center; background: var(--surface); }
.eyebrow { font: 600 var(--fs-eyebrow)/1.2 var(--mono); letter-spacing: 0.15em; text-transform: uppercase; color: var(--accent); }
.hero .eyebrow { margin-bottom: 10px; }
.hero h1.hero-title, .hero-title {
  font: 700 var(--fs-title)/1.15 var(--sans) !important; letter-spacing: -0.02em; color: var(--text) !important; margin: 0 !important; padding: 0 !important;
}
.hero-sub { font-size: 17px; color: var(--text-2); margin-top: 8px; }
.hero-status { display:flex; flex-direction:column; align-items:flex-end; gap: 12px; }
.status-pill {
  display:inline-flex; align-items:center; gap: 9px; font: 600 12px/1 var(--mono); letter-spacing: 0.13em; color: var(--success);
  border: 1px solid var(--success-line); background: var(--success-soft); padding: 8px 12px; border-radius: 5px;
}
.verify-dot { position: relative; width: 16px; height: 16px; display:inline-grid; place-items:center; }
.verify-dot::after {
  content:""; position:absolute; inset:0; border-radius:50%; border:1px solid var(--success);
  animation: ping 2.4s cubic-bezier(.2,.6,.3,1) 2 both;
}
.scope { font: 500 12px/1 var(--mono); letter-spacing: 0.11em; color: var(--text-2); }
.scope i { font-style: normal; color: var(--text-muted); padding: 0 7px; }
.notice {
  position:relative; display:flex; gap: 16px; align-items: baseline; margin: 22px -30px 0; padding: 13px 30px;
  border-top: 1px solid var(--border); background: var(--notice-bg);
}
.notice-tag {
  flex: 0 0 auto; font: 600 var(--fs-eyebrow)/1 var(--mono); letter-spacing: 0.13em; text-transform: uppercase;
  color: var(--warning); border: 1px solid var(--warning-line); padding: 5px 8px; border-radius: 4px;
}
.notice p { margin: 0 !important; font-size: 14.5px !important; color: var(--text-2) !important; line-height: 1.55 !important; }

/* ---------- Section / sub-section headers ---------- */
.sec { display:flex; align-items:flex-end; justify-content:space-between; gap: 24px; flex-wrap: wrap; margin: 0 0 20px; }
.sec .eyebrow { margin-bottom: 10px; }
.sec-title { font: 700 var(--fs-section)/1.2 var(--sans); color: var(--text); letter-spacing: -0.015em; }
.sec-desc { font-size: var(--fs-body); color: var(--text-2); max-width: 600px; line-height: var(--lh-body); }
.sub-h { display:flex; align-items:center; gap: 12px; margin: 34px 0 14px; }
.sub-h .t { font: 650 var(--fs-subsection)/1.25 var(--sans); color: var(--text); white-space: nowrap; }
.sub-h::after { content:""; flex:1; height:1px; background: var(--border); min-width: 20px; }
.sub-h.tight { margin-top: 8px; }

/* ---------- Panels & tags ---------- */
.panel {
  border: 1px solid var(--border); border-radius: 8px; background: var(--surface); box-shadow: var(--shadow);
  padding: 22px 24px; animation: fadeUp .45s ease-out both;
}
.panel-h { display:flex; justify-content:space-between; align-items:center; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }
.panel-t { font: 650 var(--fs-panel)/1.3 var(--sans); color: var(--text); }
.tag {
  font: 600 var(--fs-eyebrow)/1 var(--mono); letter-spacing: 0.07em; color: var(--text-2); text-transform: uppercase;
  border: 1px solid var(--border-strong); padding: 5px 8px; border-radius: 4px; white-space: nowrap; display:inline-flex; align-items:center; gap:6px;
}
.tag.ok { color: var(--success); border-color: var(--success-line); background: var(--success-soft); }
.tag.warn { color: var(--warning); border-color: var(--warning-line); background: var(--warning-soft); }
.tag.accent { color: var(--accent); border-color: var(--accent-line); background: var(--accent-soft); }
.tag.bad { color: var(--danger); border-color: var(--danger-line); background: var(--danger-soft); }

/* ---------- Detection hero metric ---------- */
.det { display:flex; align-items:center; gap: 30px; flex-wrap: wrap; min-height: 236px; }
.det-ring { position: relative; width: 176px; height: 176px; flex: 0 0 auto; }
.det-ring .center { position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center; }
.det-ring .center .v { font: 600 var(--fs-metric-l)/1 var(--mono); color: var(--text); letter-spacing: -0.02em; }
.det-ring .center .l { font: 600 var(--fs-eyebrow)/1 var(--mono); color: var(--text-muted); letter-spacing: 0.12em; margin-top: 8px; text-transform: uppercase; }
.ring-main { animation: ringMain 1.2s cubic-bezier(.3,.7,.2,1) .1s both; }
.det-body { flex: 1 1 240px; min-width: 0; }
.det-big { font: 600 var(--fs-metric-xl)/1 var(--mono); color: var(--text); letter-spacing: -0.03em; }
.det-big span { font-size: 24px; color: var(--text-2); margin-left: 3px; }
.det-label { font: 600 var(--fs-eyebrow)/1 var(--mono); color: var(--text-muted); letter-spacing: 0.12em; text-transform: uppercase; margin-bottom: 10px; }
.det-cap { font-size: var(--fs-body); color: var(--text-2); margin: 10px 0 20px; line-height: 1.5; }
.det-cap b { color: var(--text); font-family: var(--mono); font-weight: 600; }
.det-split { display:grid; grid-template-columns: repeat(3, minmax(0,1fr)); border-top: 1px solid var(--border); }
.det-split > div { padding: 14px 0 0; }
.det-split > div + div { padding-left: 16px; border-left: 1px solid var(--border); }
.det-split .k { font-size: 13.5px; font-weight: 600; color: var(--text-2); }
.det-split .v { font: 600 var(--fs-metric-m)/1 var(--mono); margin-top: 9px; color: var(--text); }

/* ---------- Inventory list ---------- */
.inv { display:flex; flex-direction:column; min-height: 236px; }
.inv-row { display:grid; grid-template-columns: 1fr auto; align-items: center; gap: 12px; padding: 10px 0; border-bottom: 1px solid var(--border); }
.inv-row:last-child { border-bottom: none; padding-bottom: 0; }
.inv-row .k { font-size: 15px; color: var(--text); font-weight: 500; }
.inv-row .k small { display:block; font-size: 13px; color: var(--text-muted); margin-top: 3px; font-weight: 400; }
.inv-row .v { font: 600 22px/1 var(--mono); color: var(--text); }

/* ---------- Pipeline strip ---------- */
.pipe { display:flex; align-items: stretch; flex-wrap: wrap; border: 1px solid var(--border); border-radius: 8px; background: var(--surface); box-shadow: var(--shadow); overflow: hidden; }
.pipe-step { flex: 1 1 200px; padding: 16px 20px; position: relative; }
.pipe-step + .pipe-step { border-left: 1px solid var(--border); }
.pipe-step .n { font: 600 var(--fs-eyebrow)/1 var(--mono); color: var(--accent); letter-spacing: 0.13em; }
.pipe-step .t { font-size: 15.5px; color: var(--text); margin-top: 9px; font-weight: 600; }
.pipe-step .d { font-size: 13.5px; color: var(--text-2); margin-top: 5px; line-height: 1.45; }
.pipe-step .d b { font-family: var(--mono); font-weight: 600; color: var(--text); font-size: 13px; }

/* ---------- Key/value grid ---------- */
.kv { display:grid; grid-template-columns: repeat(auto-fit, minmax(310px, 1fr)); column-gap: 32px; }
.kv-row { display:flex; justify-content: space-between; gap: 16px; padding: 10px 0; border-bottom: 1px dashed var(--border); align-items: baseline; }
.kv-row .k { font-size: 14.5px; color: var(--text-2); white-space: nowrap; }
.kv-row .v { font-size: 14.5px; font-weight: 500; color: var(--text); text-align: right; }
.kv-row .v.mono { font-size: 13.5px; }
.kv-wide { grid-column: 1 / -1; }

/* ---------- Run ledger ---------- */
.run { padding: 14px 0; border-bottom: 1px solid var(--border); }
.run:last-child { border-bottom: none; padding-bottom: 0; }
.run:first-child { padding-top: 0; }
.run-h { display:flex; justify-content:space-between; gap: 10px; align-items: center; }
.run-h .id { font: 600 12.5px/1 var(--mono); color: var(--accent); letter-spacing: 0.08em; text-transform: uppercase; }
.run-name { font-size: 15.5px; color: var(--text); margin: 8px 0 4px; font-weight: 600; }
.run-ds { font-size: 13.5px; color: var(--text-muted); margin-bottom: 8px; }
.run-m { display:flex; gap: 22px; flex-wrap: wrap; font-size: 14px; color: var(--text-2); }
.run-m b { font-family: var(--mono); font-weight: 600; color: var(--text); font-size: 13.5px; }

/* ---------- Node map ---------- */
.map-svg { width: 100%; height: auto; display: block; }
.map-link { stroke-dasharray: 600; animation: draw .9s ease-out both; }
.map-node { animation: fadeIn .45s ease-out both; }
.ring-node { animation: ringNode 1s cubic-bezier(.3,.7,.2,1) both; }
.map-halo { animation: halo .4s ease-out both; transform-box: fill-box; transform-origin: center; }
.map-caption { display:flex; gap: 20px; flex-wrap: wrap; margin-top: 10px; font-size: 13px; color: var(--text-2); }
.map-caption span { display:inline-flex; align-items:center; gap: 7px; }
.map-caption i { width: 9px; height: 9px; border-radius: 50%; display:inline-block; }
.map-caption code { font-family: var(--mono); font-size: 12.5px; color: var(--text); background: none; padding: 0; }

/* ---------- Node detail ---------- */
.nd-head { display:flex; justify-content:space-between; align-items:flex-start; gap: 12px; }
.nd-id { font: 600 12.5px/1 var(--mono); color: var(--accent); letter-spacing: 0.12em; text-transform: uppercase; }
.nd-type { font: 650 21px/1.25 var(--sans); color: var(--text); margin-top: 8px; }
.nd-kind { font-size: 13.5px; color: var(--text-muted); margin-top: 3px; }
.nd-rate { font: 600 40px/1 var(--mono); margin: 20px 0 6px; letter-spacing: -0.03em; }
.nd-rate-l { font-size: 13.5px; font-weight: 600; color: var(--text-2); }
.bar { height: 7px; border-radius: 4px; background: var(--danger-soft-2); overflow: hidden; margin: 16px 0 7px; display:flex; }
.bar > i { display:block; height: 100%; background: var(--success); animation: grow .8s cubic-bezier(.3,.7,.2,1) both; transform-origin: left; }
.bar-l { display:flex; justify-content: space-between; font-size: 13px; color: var(--text-2); margin-bottom: 12px; }
.bar-l b { font-family: var(--mono); color: var(--text); }
.nd-rows .sb-row .k, .nd-rows .sb-row .v { font-size: 14.5px; }

/* ---------- HTML data tables ---------- */
.tbl-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: 8px; background: var(--table-bg); box-shadow: var(--shadow); }
.tbl-scroll { max-height: 560px; overflow: auto; }
table.tbl { width: 100%; border-collapse: separate; border-spacing: 0; min-width: 820px; margin: 0; background: transparent; color: var(--table-text); }
.tbl th, .tbl td { border: none !important; border-bottom: 1px solid var(--border) !important; background: transparent; }
.tbl th {
  text-align: left; font: 600 13px/1.3 var(--sans); color: var(--text-2); padding: 13px 16px;
  background: var(--table-head) !important; border-bottom: 1px solid var(--border-strong) !important; white-space: nowrap;
}
.tbl-scroll .tbl th { position: sticky; top: 0; z-index: 2; }
.tbl td { padding: 13px 16px; font-size: var(--fs-table); color: var(--table-text); white-space: nowrap; }
.tbl tbody tr:last-child td { border-bottom: none !important; }
.tbl tbody tr { background: transparent !important; transition: background .12s; }
.tbl tbody tr:hover td { background: var(--hover); }
.tbl td.num, .tbl th.num { text-align: right; }
.tbl td.num { font-family: var(--mono); font-size: 14px; }
.tbl td.dim { color: var(--text-2); }
.tbl td.id { font-family: var(--mono); font-size: 14px; font-weight: 500; }
.tbl tfoot td { background: var(--table-head) !important; border-top: 1px solid var(--border-strong) !important; border-bottom: none !important; font-weight: 600; }
.tbl tr.flag td:first-child { box-shadow: inset 3px 0 0 var(--warning); }
.tbl.compact td { padding: 11px 16px; }
.rate-cell { display:flex; align-items:center; gap: 12px; min-width: 220px; }
.rate-track { flex: 1; height: 6px; border-radius: 3px; background: var(--track); overflow:hidden; }
.rate-track i { display:block; height:100%; border-radius: 3px; animation: grow .8s cubic-bezier(.3,.7,.2,1) both; transform-origin: left; }
.rate-v { font: 600 15px/1 var(--mono); width: 72px; text-align: right; }
.dot { width: 8px; height: 8px; border-radius: 50%; display:inline-block; margin-right: 9px; vertical-align: middle; }
.miss-nz { color: var(--danger) !important; font-weight: 600; }

/* Classification pills: text + shape, never colour alone */
.pill { display:inline-flex; align-items:center; gap: 8px; font-size: 13.5px; font-weight: 600; padding: 4px 10px 4px 9px; border-radius: 4px; border: 1px solid; }
.pill i { width: 8px; height: 8px; display:inline-block; }
.pill.anom { color: var(--danger); border-color: var(--danger-line); background: var(--danger-soft); }
.pill.anom i { background: var(--danger); transform: rotate(45deg); }
.pill.norm { color: var(--accent); border-color: var(--accent-line); background: var(--accent-soft); }
.pill.norm i { background: var(--accent); border-radius: 50%; }

/* ---------- Insight / note ---------- */
.insight {
  border: 1px solid var(--border); border-left: 3px solid var(--accent); border-radius: 0 8px 8px 0;
  background: var(--surface); box-shadow: var(--shadow); padding: 16px 20px; animation: fadeUp .4s ease-out both;
}
.insight.warn { border-left-color: var(--warning); }
.insight .h { font: 600 var(--fs-eyebrow)/1 var(--mono); letter-spacing: 0.13em; text-transform: uppercase; color: var(--text-muted); margin-bottom: 10px; }
.insight p { margin: 0 0 10px !important; font-size: var(--fs-body) !important; line-height: 1.6 !important; color: var(--text) !important; }
.insight p:last-child { margin-bottom: 0 !important; }
.insight p.fine { font-size: 13.5px !important; color: var(--text-muted) !important; }
.insight b { font-family: var(--mono); font-weight: 600; font-size: 14.5px; }
.footnote { font-size: 13.5px; color: var(--text-muted); margin: 2px 0 0; line-height: 1.55; }
.footnote code { font-family: var(--mono); font-size: 12.5px; color: var(--text-2); background: var(--elevated); border: 1px solid var(--border); padding: 1px 5px; border-radius: 3px; }

/* ---------- Context strip (feature tab) ---------- */
.ctx { display:flex; flex-wrap: wrap; gap: 0; border: 1px solid var(--border); border-radius: 6px; background: var(--surface); min-height: 42px; }
.ctx > div { padding: 10px 16px; display:flex; align-items: baseline; gap: 8px; font-size: 14px; color: var(--text-2); }
.ctx > div + div { border-left: 1px solid var(--border); }
.ctx b { font-family: var(--mono); font-weight: 600; color: var(--text); font-size: 14px; }

/* ---------- Evidence summary strip ---------- */
.sum { display:grid; grid-template-columns: repeat(4, minmax(0,1fr)); border: 1px solid var(--border); border-radius: 8px; background: var(--surface); box-shadow: var(--shadow); overflow:hidden; }
.sum > div { padding: 16px 20px; }
.sum > div + div { border-left: 1px solid var(--border); }
.sum .k { font-size: 14px; font-weight: 600; color: var(--text-2); display:flex; align-items:center; gap: 8px; }
.sum .v { font: 600 var(--fs-metric-l)/1 var(--mono); margin-top: 10px; color: var(--text); }
.sum .s { font-size: 13px; color: var(--text-muted); margin-top: 8px; }
.sum-bar { grid-column: 1 / -1; padding: 0 !important; border-left: none !important; display:flex; height: 4px; }
.sum-bar i { display:block; height:100%; }

/* ---------- Motion ---------- */
@keyframes fadeUp { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
@keyframes ping { 0% { transform: scale(.8); opacity: .8; } 80%, 100% { transform: scale(1.9); opacity: 0; } }
@keyframes ringMain { from { stroke-dashoffset: 452.39; } }
@keyframes ringNode { from { stroke-dashoffset: 175.93; } }
@keyframes draw { from { stroke-dashoffset: 600; } to { stroke-dashoffset: 0; } }
@keyframes halo { from { opacity: 0; transform: scale(.85); } to { opacity: 1; transform: scale(1); } }
@keyframes grow { from { transform: scaleX(0); } to { transform: scaleX(1); } }
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation: none !important; transition: none !important; scroll-behavior: auto !important; }
  .verify-dot::after { display: none; }
}

/* ---------- Responsive ---------- */
@media (max-width: 1280px) {
  .sum { grid-template-columns: repeat(2, minmax(0,1fr)); }
  .sum > div:nth-child(3) { border-left: none; }
  .sum > div:nth-child(n+3) { border-top: 1px solid var(--border); }
  .hero-status { align-items: flex-start; }
}
@media (max-width: 900px) {
  :root { --fs-title: 27px; --fs-section: 22px; --fs-metric-xl: 38px; }
  .det-split .v { font-size: 19px; }
}
"""

FONT_IMPORT = (
    "@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;650;700"
    "&family=JetBrains+Mono:wght@400;500;600&display=swap');"
)


def build_css(t: dict, ty: dict) -> str:
    """Emit the stylesheet: token custom properties followed by the static sheet."""
    derived = {
        "accent_soft": alpha(t["accent"], 0.10),
        "accent_soft_2": alpha(t["accent"], 0.24),
        "accent_line": alpha(t["accent"], 0.42),
        "success_soft": alpha(t["success"], 0.09),
        "success_line": alpha(t["success"], 0.42),
        "warning_soft": alpha(t["warning"], 0.09),
        "warning_line": alpha(t["warning"], 0.45),
        "danger_soft": alpha(t["danger"], 0.09),
        "danger_soft_2": alpha(t["danger"], 0.45),
        "danger_line": alpha(t["danger"], 0.42),
    }
    css_vars = {k: v for k, v in t.items() if isinstance(v, str)}
    css_vars.update(derived)
    css_vars.update({k: v for k, v in ty.items() if isinstance(v, str)})
    root = ":root{" + "".join(f"--{k.replace('_', '-')}:{v};" for k, v in css_vars.items()) + "}"
    return f"<style>{FONT_IMPORT}{root}{BASE_CSS}</style>"


st.markdown(build_css(T, TY), unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# DATABASE UTILITIES (READ-ONLY URI MODE & CACHING)
# -----------------------------------------------------------------------------
@st.cache_resource
def get_db_uri():
    """Resolve absolute path to SQLite database and format as read-only URI."""
    db_path = (Path(__file__).parent.parent / "data" / "iot_anomaly.db").resolve()
    if not db_path.exists():
        st.error(f"Database not found at expected path: {db_path}")
        st.stop()
    return f"file:{db_path.as_posix()}?mode=ro"

def get_connection():
    """Return a read-only SQLite connection."""
    return sqlite3.connect(get_db_uri(), uri=True)

@st.cache_data(ttl=600)
def load_system_kpis():
    """Load high-level verification metrics from the database."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        nodes_count = cur.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
        obs_count = cur.execute("SELECT COUNT(*) FROM traffic_observations").fetchone()[0]
        total_windows = cur.execute("SELECT COUNT(*) FROM feature_windows").fetchone()[0]
        normal_windows = cur.execute("SELECT COUNT(*) FROM feature_windows WHERE dataset_id = 1").fetchone()[0]
        anomaly_windows = cur.execute("SELECT COUNT(*) FROM feature_windows WHERE dataset_id = 2").fetchone()[0]
        
        datasets_count = cur.execute("SELECT COUNT(*) FROM datasets").fetchone()[0]
        runs_count = cur.execute("SELECT COUNT(*) FROM prediction_runs").fetchone()[0]
        predictions_count = cur.execute("SELECT COUNT(*) FROM anomaly_predictions").fetchone()[0]
        
        # Detection metrics for run_id=2 (Final Controlled Anomaly Evaluation)
        cur.execute("""
            SELECT 
                COUNT(*),
                SUM(CASE WHEN prediction = -1 THEN 1 ELSE 0 END),
                SUM(CASE WHEN prediction = 1 THEN 1 ELSE 0 END)
            FROM anomaly_predictions
            WHERE run_id = 2
        """)
        anom_eval_total, detected, missed = cur.fetchone()
        
        detection_rate = (detected / anom_eval_total * 100.0) if anom_eval_total > 0 else 0.0
        
        return {
            "nodes_count": nodes_count,
            "obs_count": obs_count,
            "total_windows": total_windows,
            "normal_windows": normal_windows,
            "anomaly_windows": anomaly_windows,
            "anom_eval_total": anom_eval_total,
            "detected_anomalies": detected,
            "missed_anomalies": missed,
            "detection_rate": detection_rate,
            "datasets_count": datasets_count,
            "runs_count": runs_count,
            "predictions_count": predictions_count,
        }
    finally:
        conn.close()

@st.cache_data(ttl=600)
def load_node_summary():
    """Load node-wise breakdown of feature windows and detection performance."""
    conn = get_connection()
    try:
        query = """
        WITH NormalCounts AS (
            SELECT node_id, COUNT(window_id) AS normal_windows
            FROM feature_windows
            WHERE dataset_id = 1
            GROUP BY node_id
        ),
        AnomalyCounts AS (
            SELECT node_id, COUNT(window_id) AS anomaly_windows
            FROM feature_windows
            WHERE dataset_id = 2
            GROUP BY node_id
        ),
        DetectedCounts AS (
            SELECT node_id, COUNT(window_id) AS detected_anomalies
            FROM anomaly_predictions
            WHERE run_id = 2 AND prediction = -1
            GROUP BY node_id
        ),
        MissedCounts AS (
            SELECT node_id, COUNT(window_id) AS missed_anomalies
            FROM anomaly_predictions
            WHERE run_id = 2 AND prediction = 1
            GROUP BY node_id
        )
        SELECT 
            n.node_id AS "Node ID",
            n.node_type AS "Node Type",
            COALESCE(nc.normal_windows, 0) AS "Normal Windows",
            COALESCE(ac.anomaly_windows, 0) AS "Controlled Anomaly Windows",
            COALESCE(dc.detected_anomalies, 0) AS "Detected Anomalies",
            COALESCE(mc.missed_anomalies, 0) AS "Missed Anomalies"
        FROM nodes n
        LEFT JOIN NormalCounts nc ON n.node_id = nc.node_id
        LEFT JOIN AnomalyCounts ac ON n.node_id = ac.node_id
        LEFT JOIN DetectedCounts dc ON n.node_id = dc.node_id
        LEFT JOIN MissedCounts mc ON n.node_id = mc.node_id
        ORDER BY n.node_id;
        """
        df = pd.read_sql_query(query, conn)
        df["Detection Rate (%)"] = (
            df["Detected Anomalies"] / df["Controlled Anomaly Windows"] * 100.0
        ).round(2)
        return df
    finally:
        conn.close()

@st.cache_data(ttl=600)
def load_feature_windows_all():
    """Load feature windows for both normal and controlled anomaly datasets."""
    conn = get_connection()
    try:
        query = """
        SELECT 
            fw.node_id,
            n.node_type,
            d.dataset_id,
            d.dataset_name,
            d.dataset_type,
            fw.window_id,
            fw.mean_iat,
            fw.iat_std,
            fw.packet_rate,
            fw.mean_packet_size,
            fw.packet_size_std
        FROM feature_windows fw
        JOIN datasets d ON fw.dataset_id = d.dataset_id
        JOIN nodes n ON fw.node_id = n.node_id
        ORDER BY fw.node_id, fw.dataset_id, fw.window_id;
        """
        return pd.read_sql_query(query, conn)
    finally:
        conn.close()

@st.cache_data(ttl=600)
def load_predictions_with_features(run_id: int):
    """
    Load prediction ledger joined with feature_windows using the mandatory join rule:
        fw.dataset_id = pr.dataset_id
        AND fw.node_id = ap.node_id
        AND fw.window_id = ap.window_id
    """
    conn = get_connection()
    try:
        query = """
        SELECT 
            ap.prediction_id,
            ap.run_id,
            pr.run_name,
            ap.node_id,
            n.node_type,
            ap.window_id,
            fw.mean_iat,
            fw.iat_std,
            fw.packet_rate,
            fw.mean_packet_size,
            fw.packet_size_std,
            ap.prediction,
            ap.anomaly_score,
            ap.actual_class
        FROM anomaly_predictions ap
        JOIN prediction_runs pr ON ap.run_id = pr.run_id
        JOIN feature_windows fw ON fw.dataset_id = pr.dataset_id 
                                AND fw.node_id = ap.node_id 
                                AND fw.window_id = ap.window_id
        JOIN nodes n ON n.node_id = ap.node_id
        WHERE ap.run_id = ?
        ORDER BY ap.node_id, ap.window_id;
        """
        return pd.read_sql_query(query, conn, params=(run_id,))
    finally:
        conn.close()

@st.cache_data(ttl=600)
def load_run_ledger():
    """Read-only summary of each prediction run (metadata + per-run prediction counts)."""
    conn = get_connection()
    try:
        query = """
        SELECT
            pr.run_id,
            pr.run_name,
            pr.created_at,
            d.dataset_name,
            d.dataset_type,
            COUNT(ap.prediction_id) AS evaluated,
            SUM(CASE WHEN ap.prediction = -1 THEN 1 ELSE 0 END) AS classified_anomalous,
            SUM(CASE WHEN ap.prediction = 1 THEN 1 ELSE 0 END) AS classified_normal
        FROM prediction_runs pr
        JOIN datasets d ON d.dataset_id = pr.dataset_id
        LEFT JOIN anomaly_predictions ap ON ap.run_id = pr.run_id
        GROUP BY pr.run_id, pr.run_name, pr.created_at, d.dataset_name, d.dataset_type
        ORDER BY pr.run_id;
        """
        return pd.read_sql_query(query, conn)
    finally:
        conn.close()

@st.cache_data(ttl=600)
def load_fk_violation_count():
    """Count foreign-key violations via PRAGMA foreign_key_check (read-only check)."""
    conn = get_connection()
    try:
        return len(conn.execute("PRAGMA foreign_key_check").fetchall())
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# PRESENTATION HELPERS
# -----------------------------------------------------------------------------
def esc(value) -> str:
    """HTML-escape any value for safe inline rendering."""
    return html_lib.escape(str(value))


def render(markup: str) -> None:
    """
    Render an HTML fragment. Lines are stripped and blank lines removed so the
    Markdown parser treats the whole fragment as a single raw HTML block.
    """
    compact = "\n".join(ln.strip() for ln in markup.splitlines() if ln.strip())
    st.markdown(compact, unsafe_allow_html=True)


def fmt_int(n) -> str:
    return f"{int(n):,}"


def fmt_rate(rate: float) -> str:
    return "100%" if round(rate, 2) >= 100 else f"{rate:.2f}%"


def fmt_num(v: float) -> str:
    """Adaptive precision for technical feature values."""
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "—"
    a = abs(v)
    if a >= 1000:
        return f"{v:,.1f}"
    if a >= 100:
        return f"{v:,.2f}"
    if a >= 1:
        return f"{v:.3f}"
    return f"{v:.4f}"


def rate_tone(rate: float, is_lowest: bool = False) -> str:
    """Restrained semantic tone for a detection rate."""
    if round(rate, 2) >= 100:
        return "ok"
    if is_lowest:
        return "warn"
    return "accent"


def tone_color(tone: str) -> str:
    return {"ok": T["success"], "warn": T["warning"], "accent": T["accent"], "bad": T["danger"]}.get(tone, T["text_2"])


TONE_LABEL = {"ok": "Full detection", "accent": "Partial detection", "warn": "Lowest detection rate"}


def section_header(index: str, title: str, desc: str = "") -> None:
    desc_html = f'<div class="sec-desc">{esc(desc)}</div>' if desc else ""
    render(f"""
    <div class="sec">
      <div><div class="eyebrow">{esc(index)}</div><div class="sec-title">{esc(title)}</div></div>
      {desc_html}
    </div>
    """)


def sub_header(label: str, tag: str = "", tight: bool = False) -> None:
    tag_html = f'<span class="tag">{esc(tag)}</span>' if tag else ""
    render(f'<div class="sub-h{" tight" if tight else ""}"><span class="t">{esc(label)}</span>{tag_html}</div>')


def sb_row(k: str, v: str, mono: bool = False, color: str = "") -> str:
    style = f' style="color:{color}"' if color else ""
    return (f'<div class="sb-row"><span class="k">{esc(k)}</span>'
            f'<span class="v{" mono" if mono else ""}"{style}>{esc(v)}</span></div>')


def mark_svg(size: int = 26) -> str:
    """Small product mark: a central engine with five node links."""
    return f"""
    <svg width="{size}" height="{size}" viewBox="0 0 32 32" fill="none" aria-hidden="true">
      <g stroke="{T['border_strong']}" stroke-width="1.2">
        <line x1="16" y1="16" x2="16" y2="4"/><line x1="16" y1="16" x2="5" y2="11"/>
        <line x1="16" y1="16" x2="27" y2="11"/><line x1="16" y1="16" x2="8" y2="27"/>
        <line x1="16" y1="16" x2="24" y2="27"/>
      </g>
      <g fill="{T['surface']}" stroke="{T['accent']}" stroke-width="1.3">
        <circle cx="16" cy="4" r="2.4"/><circle cx="5" cy="11" r="2.4"/><circle cx="27" cy="11" r="2.4"/>
        <circle cx="8" cy="27" r="2.4"/><circle cx="24" cy="27" r="2.4"/>
      </g>
      <rect x="11.5" y="11.5" width="9" height="9" rx="2" fill="{alpha(T['accent'], 0.16)}" stroke="{T['accent']}" stroke-width="1.3"/>
    </svg>
    """


def lock_svg(color: str) -> str:
    return f"""<svg width="11" height="12" viewBox="0 0 10 11" fill="none" aria-hidden="true">
    <rect x="1" y="5" width="8" height="5.5" rx="1" stroke="{color}" stroke-width="1.1"/>
    <path d="M3 5V3.4a2 2 0 0 1 4 0V5" stroke="{color}" stroke-width="1.1"/></svg>"""


def check_svg(color: str) -> str:
    return f"""<svg width="12" height="12" viewBox="0 0 12 12" fill="none" aria-hidden="true">
    <circle cx="6" cy="6" r="5.3" stroke="{color}" stroke-width="1.1"/>
    <path d="M3.6 6.1l1.6 1.6 3.2-3.3" stroke="{color}" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>"""


def ring_svg(pct: float) -> str:
    """Overview detection ring (r=72 -> circumference 452.39, matched in CSS keyframes)."""
    r = 72
    circ = 2 * math.pi * r
    offset = circ * (1 - max(0.0, min(pct, 100.0)) / 100.0)
    ticks = []
    for i in range(60):
        ang = math.radians(i * 6 - 90)
        r1, r2 = (82, 86) if i % 5 == 0 else (83.5, 85.5)
        ticks.append(
            f'<line x1="{88 + r1 * math.cos(ang):.2f}" y1="{88 + r1 * math.sin(ang):.2f}" '
            f'x2="{88 + r2 * math.cos(ang):.2f}" y2="{88 + r2 * math.sin(ang):.2f}"/>'
        )
    return f"""
    <svg width="176" height="176" viewBox="0 0 176 176" aria-label="Detection rate {pct:.2f} percent" role="img">
      <g stroke="{T['border_strong']}" stroke-width="1">{''.join(ticks)}</g>
      <circle cx="88" cy="88" r="{r}" fill="none" stroke="{alpha(T['danger'], 0.5)}" stroke-width="10"/>
      <circle class="ring-main" cx="88" cy="88" r="{r}" fill="none" stroke="{T['success']}" stroke-width="10"
        stroke-dasharray="{circ:.2f}" stroke-dashoffset="{offset:.2f}" transform="rotate(-90 88 88)"/>
    </svg>
    """


# Node map geometry (viewBox 0 0 820 430)
NODE_POS = {
    "Node_1": (120, 128),
    "Node_2": (120, 318),
    "Node_3": (700, 128),
    "Node_4": (700, 318),
    "Node_5": (410, 66),
}
ENGINE_BOX = (300, 184, 220, 100)  # x, y, w, h


def node_map_svg(df: pd.DataFrame, selected: str, lowest: str) -> str:
    """Conceptual map: one central analysis engine, five node-specific models."""
    sans, mono = TY["sans"].replace("'", ""), TY["mono"].replace("'", "")
    ex, ey, ew, eh = ENGINE_BOX
    ecx, ecy = ex + ew / 2, ey + eh / 2
    r_ring = 28
    circ = 2 * math.pi * r_ring  # 175.93, matched in CSS keyframes

    links, tags, nodes = [], [], []
    for i, row in enumerate(df.itertuples(index=False)):
        nid, ntype = row[0], row[1]
        rate = float(row[6])
        if nid not in NODE_POS:
            continue
        x, y = NODE_POS[nid]
        is_sel = nid == selected
        col = tone_color(rate_tone(rate, nid == lowest))
        num = nid.split("_")[-1]

        link_col = T["accent"] if is_sel else T["border_strong"]
        links.append(
            f'<line class="map-link" x1="{x}" y1="{y}" x2="{ecx}" y2="{ecy}" stroke="{link_col}" '
            f'stroke-width="{1.8 if is_sel else 1.2}" style="animation-delay:{100 + i * 80}ms"/>'
        )
        mx, my = (x + ecx) / 2, (y + ecy) / 2
        if nid == "Node_5":
            my = (y + r_ring + ey) / 2
        tag_stroke = T["accent"] if is_sel else T["border_strong"]
        tag_text = T["accent"] if is_sel else T["text_2"]
        tags.append(
            f'<g class="map-node" style="animation-delay:{380 + i * 60}ms">'
            f'<rect x="{mx - 28}" y="{my - 11}" width="56" height="22" rx="4" fill="{T["surface"]}" stroke="{tag_stroke}" stroke-width="1"/>'
            f'<text x="{mx}" y="{my + 4.3}" text-anchor="middle" font-family="{mono}" font-size="12" font-weight="600" '
            f'fill="{tag_text}" letter-spacing="0.5">IF·M{num}</text></g>'
        )

        offset = circ * (1 - rate / 100.0)
        halo = ""
        if is_sel:
            halo = (f'<circle class="map-halo" cx="{x}" cy="{y}" r="{r_ring + 10}" fill="{alpha(T["accent"], 0.08)}" '
                    f'stroke="{T["accent"]}" stroke-opacity="0.65" stroke-width="1.2"/>')
        if nid == "Node_5":
            lx, anchor, ly1, ly2, ly3 = x + r_ring + 16, "start", y - 12, y + 9, y + 28
        else:
            lx, anchor, ly1, ly2, ly3 = x, "middle", y + r_ring + 22, y + r_ring + 44, y + r_ring + 63
        id_col = T["accent"] if is_sel else T["text_2"]
        nodes.append(f"""
        <g class="map-node" style="animation-delay:{50 + i * 80}ms">
          {halo}
          <circle cx="{x}" cy="{y}" r="{r_ring}" fill="{T['surface']}" stroke="{T['track']}" stroke-width="5"/>
          <circle class="ring-node" cx="{x}" cy="{y}" r="{r_ring}" fill="none" stroke="{col}" stroke-width="5"
            stroke-dasharray="{circ:.2f}" stroke-dashoffset="{offset:.2f}" transform="rotate(-90 {x} {y})"
            style="animation-delay:{180 + i * 80}ms"/>
          <text x="{x}" y="{y + 4.5}" text-anchor="middle" font-family="{mono}" font-size="12.5" font-weight="600" fill="{T['text']}">{esc(fmt_rate(rate))}</text>
          <text x="{lx}" y="{ly1}" text-anchor="{anchor}" font-family="{mono}" font-size="12.5" font-weight="600" letter-spacing="1.2" fill="{id_col}">NODE {num}</text>
          <text x="{lx}" y="{ly2}" text-anchor="{anchor}" font-family="{sans}" font-size="17" font-weight="600" fill="{T['text']}">{esc(ntype)}</text>
          <text x="{lx}" y="{ly3}" text-anchor="{anchor}" font-family="{sans}" font-size="13.5" fill="{T['text_2']}">{int(row[4])} / {int(row[3])} detected</text>
        </g>
        """)

    engine = f"""
    <g class="map-node">
      <rect x="{ex}" y="{ey}" width="{ew}" height="{eh}" rx="9" fill="{T['elevated']}" stroke="{T['accent']}" stroke-opacity="0.7" stroke-width="1.3"/>
      <rect x="{ex + 6}" y="{ey + 6}" width="{ew - 12}" height="{eh - 12}" rx="6" fill="none" stroke="{T['border_strong']}" stroke-dasharray="2 4" stroke-width="1"/>
      <text x="{ecx}" y="{ecy - 16}" text-anchor="middle" font-family="{mono}" font-size="11.5" font-weight="600" letter-spacing="1.6" fill="{T['accent']}">ISOLATION FOREST</text>
      <text x="{ecx}" y="{ecy + 6}" text-anchor="middle" font-family="{sans}" font-size="18" font-weight="650" fill="{T['text']}">Analysis Engine</text>
      <text x="{ecx}" y="{ecy + 27}" text-anchor="middle" font-family="{sans}" font-size="13" fill="{T['text_2']}">5 independent node models</text>
    </g>
    """
    return f"""
    <svg class="map-svg" viewBox="0 0 820 430" role="img" aria-label="Software-defined node profiles connected to the Isolation Forest analysis engine">
      <defs>
        <pattern id="mapgrid" width="24" height="24" patternUnits="userSpaceOnUse">
          <path d="M24 0H0V24" fill="none" stroke="{T['border']}" stroke-width="0.7"/>
        </pattern>
      </defs>
      <rect x="0" y="0" width="820" height="430" fill="url(#mapgrid)" opacity="0.6"/>
      {''.join(links)}
      {engine}
      {''.join(tags)}
      {''.join(nodes)}
    </svg>
    """


# -----------------------------------------------------------------------------
# PLOTLY THEME (derived from the same tokens)
# -----------------------------------------------------------------------------
def plotly_theme() -> dict:
    sans, mono = TY["sans"].replace("'", ""), TY["mono"].replace("'", "")
    axis = dict(
        gridcolor=T["chart_grid"],
        zerolinecolor=T["chart_axis"],
        linecolor=T["chart_axis"],
        showline=True,
        ticks="outside",
        tickcolor=T["chart_axis"],
        ticklen=4,
        tickfont=dict(family=mono, size=TY["chart_tick"], color=T["chart_text"]),
        title_font=dict(family=sans, size=TY["chart_axis_title"], color=T["chart_text"]),
        automargin=True,
    )
    layout = dict(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor=T["chart_plot"],
        font=dict(family=sans, size=13, color=T["chart_text"]),
        legend=dict(
            orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0,
            bgcolor="rgba(0,0,0,0)", font=dict(family=sans, size=TY["chart_legend"], color=T["text"]),
            itemclick="toggleothers",
        ),
        hoverlabel=dict(
            bgcolor=T["tooltip_bg"], bordercolor=T["border_strong"],
            font=dict(family=mono, size=TY["chart_hover"], color=T["text"]),
        ),
        modebar=dict(bgcolor="rgba(0,0,0,0)", color=T["text_muted"], activecolor=T["accent"]),
    )
    return {"layout": layout, "axis": axis}


PLOTLY_THEME = plotly_theme()
PLOT_CONFIG = {
    "displaylogo": False,
    "responsive": True,
    "modeBarButtonsToRemove": ["select2d", "lasso2d", "autoScale2d", "toggleSpikelines"],
}


def style_fig(fig: go.Figure, height: int = 360, legend: bool = True) -> go.Figure:
    """Apply the active Plotly theme."""
    fig.update_layout(**PLOTLY_THEME["layout"])
    fig.update_layout(height=height, showlegend=legend, margin=dict(l=8, r=12, t=46 if legend else 16, b=8))
    fig.update_xaxes(**PLOTLY_THEME["axis"])
    fig.update_yaxes(**PLOTLY_THEME["axis"])
    return fig


def show_fig(fig: go.Figure, key: str) -> None:
    # Key includes the theme so the chart re-mounts cleanly with new colours.
    st.plotly_chart(fig, width="stretch", theme=None, config=PLOT_CONFIG, key=f"{key}_{ACTIVE_THEME}")


# -----------------------------------------------------------------------------
# LOAD DATA (read-only, cached)
# -----------------------------------------------------------------------------
kpis = load_system_kpis()
df_nodes = load_node_summary()
df_runs = load_run_ledger()
fk_violations = load_fk_violation_count()

NODE_IDS = df_nodes["Node ID"].tolist()
NODE_TYPES = dict(zip(df_nodes["Node ID"], df_nodes["Node Type"]))
LOWEST_NODE = df_nodes.loc[df_nodes["Detection Rate (%)"].idxmin(), "Node ID"]


# -----------------------------------------------------------------------------
# SIDEBAR — EXPERIMENTAL CONFIGURATION PANEL
# -----------------------------------------------------------------------------
with st.sidebar:
    render(f"""
    <div class="sb-brand">
      {mark_svg(30)}
      <div><div class="t1">Research Console</div><div class="t2">IoT Wi-Fi · Anomaly Lab</div></div>
    </div>
    <div class="sb-title">Display</div>
    """)
    st.segmented_control(
        "Theme",
        options=["Dark", "Light"],
        format_func=lambda t: f":material/{'dark_mode' if t == 'Dark' else 'light_mode'}: {t}",
        key="ui_theme",
        on_change=_sticky,
        args=("ui_theme",),
        width="stretch",
    )
    render(f"""
    <div class="sb-hint">Presentation setting only. Data, model and predictions are unaffected.</div>

    <div class="sb-group">
      <div class="sb-title">Research Platform</div>
      {sb_row("Testbed", "100% Software-Only")}
      {sb_row("Traffic", "Simulated")}
      {sb_row("Storage", "SQLite")}
      {sb_row("Database", "iot_anomaly.db", mono=True)}
      {sb_row("Access", "Read-Only Mode", color=T["accent"])}
    </div>

    <div class="sb-group">
      <div class="sb-title">Model Lock Status</div>
      <div class="sb-lock">
        <div class="sb-lock-head"><span class="badge">{lock_svg(T['success'])}MODEL LOCKED</span></div>
        {sb_row("Algorithm", "Isolation Forest")}
        {sb_row("contamination", "0.05", mono=True)}
        {sb_row("random_state", "42", mono=True)}
        {sb_row("Models", "5 node-specific")}
        {sb_row("Training split", "80% normal")}
      </div>
    </div>

    <div class="sb-title">Data Cache</div>
    """)
    if st.button("Refresh cached data", width="stretch", icon=":material/refresh:"):
        st.cache_data.clear()
        st.rerun()
    render("""
    <div class="sb-note">Re-reads the SQLite database in read-only URI mode
    (<span class="mono">mode=ro</span>). No records are written or modified.
    Results shown are from completed experimental runs.</div>
    """)


# -----------------------------------------------------------------------------
# HEADER — RESEARCH PLATFORM BANNER
# -----------------------------------------------------------------------------
render(f"""
<div class="hero">
  <div class="hero-grid"></div>
  <div class="hero-row">
    <div class="hero-id">
      <div class="hero-mark">{mark_svg(32)}</div>
      <div>
        <div class="eyebrow">Network Security Research Testbed</div>
        <h1 class="hero-title">AI-Assisted IoT Wi-Fi Anomaly Detection</h1>
        <div class="hero-sub">Software-Only Network Behaviour Analysis</div>
      </div>
    </div>
    <div class="hero-status">
      <div class="status-pill"><span class="verify-dot">{check_svg(T['success'])}</span>EVALUATION VERIFIED</div>
      <div class="scope">SOFTWARE TESTBED<i>/</i>SQLITE<i>/</i>ISOLATION FOREST</div>
    </div>
  </div>
  <div class="notice">
    <span class="notice-tag">Research scope</span>
    <p>This dashboard evaluates controlled synthetic anomalous behaviour generated from
    software-defined IoT traffic profiles. An anomaly indicates statistical deviation from
    learned normal behaviour and is not proof of a specific cyberattack.</p>
  </div>
</div>
""")

tab1, tab2, tab3, tab4 = st.tabs([
    "01 · System Overview",
    "02 · Node-Wise Monitoring",
    "03 · Behavioural Features",
    "04 · Prediction & Evidence",
])


# -----------------------------------------------------------------------------
# TAB 1: SYSTEM OVERVIEW
# -----------------------------------------------------------------------------
with tab1:
    section_header(
        "01 / System overview",
        "Experimental system health",
        "Completed evaluation of controlled synthetic anomalous behaviour against "
        "per-node Isolation Forest models trained on the normal baseline.",
    )

    det_rate = kpis["detection_rate"]
    detected = int(kpis["detected_anomalies"])
    missed = int(kpis["missed_anomalies"])
    evaluated = int(kpis["anom_eval_total"])

    col_det, col_inv = st.columns([7, 5], gap="medium")
    with col_det:
        render(f"""
        <div class="panel">
          <div class="panel-h">
            <span class="panel-t">Controlled anomaly detection</span>
            <span class="tag ok">{check_svg(T['success'])}RUN 02 · VERIFIED</span>
          </div>
          <div class="det">
            <div class="det-ring">
              {ring_svg(det_rate)}
              <div class="center"><div class="v">{detected}</div><div class="l">of {evaluated}</div></div>
            </div>
            <div class="det-body">
              <div class="det-label">Detection rate</div>
              <div class="det-big">{det_rate:.2f}<span>%</span></div>
              <div class="det-cap"><b>{detected} / {evaluated}</b> controlled anomaly windows identified as statistical deviation</div>
              <div class="det-split">
                <div><div class="k">Detected</div><div class="v" style="color:{T['success']}">{fmt_int(detected)}</div></div>
                <div><div class="k">Missed</div><div class="v" style="color:{T['danger']}">{fmt_int(missed)}</div></div>
                <div><div class="k">Evaluated</div><div class="v">{fmt_int(evaluated)}</div></div>
              </div>
            </div>
          </div>
        </div>
        """)

    with col_inv:
        inv_rows = [
            ("Software-defined IoT nodes", "Independent behaviour profiles", kpis["nodes_count"]),
            ("Traffic observations", "Simulated traffic records", kpis["obs_count"]),
            ("Feature windows",
             f"{fmt_int(kpis['normal_windows'])} normal · {fmt_int(kpis['anomaly_windows'])} controlled anomaly",
             kpis["total_windows"]),
            ("Datasets", "Normal baseline · controlled anomaly", kpis["datasets_count"]),
            ("Prediction runs", f"{fmt_int(kpis['predictions_count'])} anomaly predictions stored", kpis["runs_count"]),
        ]
        rows_html = "".join(
            f'<div class="inv-row"><div class="k">{esc(k)}<small>{esc(s)}</small></div>'
            f'<div class="v">{fmt_int(v)}</div></div>'
            for k, s, v in inv_rows
        )
        fk_tag = (f'<span class="tag ok">FK violations · {fk_violations}</span>' if fk_violations == 0
                  else f'<span class="tag bad">FK violations · {fk_violations}</span>')
        render(f"""
        <div class="panel">
          <div class="panel-h"><span class="panel-t">System inventory</span>{fk_tag}</div>
          <div class="inv">{rows_html}</div>
        </div>
        """)

    sub_header("Analysis pipeline")
    render(f"""
    <div class="pipe">
      <div class="pipe-step"><div class="n">STAGE 01</div><div class="t">Simulated traffic</div>
        <div class="d"><b>{fmt_int(kpis['obs_count'])}</b> observations from <b>{kpis['nodes_count']}</b> software-defined nodes</div></div>
      <div class="pipe-step"><div class="n">STAGE 02</div><div class="t">Windowed feature extraction</div>
        <div class="d"><b>{fmt_int(kpis['total_windows'])}</b> windows · 5 behavioural features</div></div>
      <div class="pipe-step"><div class="n">STAGE 03</div><div class="t">Node-specific Isolation Forest</div>
        <div class="d"><b>{kpis['nodes_count']}</b> models trained on the normal baseline</div></div>
      <div class="pipe-step"><div class="n">STAGE 04</div><div class="t">Evaluation &amp; evidence</div>
        <div class="d"><b>{fmt_int(kpis['predictions_count'])}</b> predictions across <b>{kpis['runs_count']}</b> runs</div></div>
    </div>
    """)

    col_cfg, col_runs = st.columns([7, 5], gap="medium")
    with col_cfg:
        sub_header("Locked model configuration", "LOCKED")
        cfg = [
            ("Algorithm", "Isolation Forest", False),
            ("Modelling scope", "5 node-specific models", False),
            ("contamination", "0.05", True),
            ("random_state", "42", True),
            ("Training data", "80% normal · dataset_id=1", True),
            ("Normal test split", "20% normal · dataset_id=1", True),
            ("Anomaly evaluation", "dataset_id=2 · unseen", True),
            ("Training labels", "None (unsupervised)", False),
        ]
        kv_html = "".join(
            f'<div class="kv-row"><span class="k">{esc(k)}</span>'
            f'<span class="v{" mono" if m else ""}">{esc(v)}</span></div>'
            for k, v, m in cfg
        )
        render(f"""
        <div class="panel">
          <div class="kv">
            {kv_html}
            <div class="kv-row kv-wide"><span class="k">Model features</span><span class="v mono">mean_IAT · IAT_std · packet_rate · mean_packet_size · packet_size_std</span></div>
            <div class="kv-row kv-wide" style="border-bottom:none"><span class="k">Excluded metadata</span><span class="v mono" style="color:{T['text_2']}">Node_ID · Node_Type · Window_ID · dataset_id · run_id</span></div>
          </div>
        </div>
        """)

    with col_runs:
        sub_header("Evaluation runs")
        run_html = []
        for r in df_runs.itertuples(index=False):
            ds_label = "Normal baseline · 20% test split" if r.dataset_type == "normal" else "Controlled synthetic anomalous behaviour"
            run_html.append(f"""
            <div class="run">
              <div class="run-h"><span class="id">RUN {int(r.run_id):02d}</span><span class="tag ok">VERIFIED</span></div>
              <div class="run-name">{esc(r.run_name)}</div>
              <div class="run-ds">{esc(ds_label)}</div>
              <div class="run-m">
                <span>Evaluated <b>{fmt_int(r.evaluated)}</b></span>
                <span>Anomalous <b style="color:{T['danger']}">{fmt_int(r.classified_anomalous)}</b></span>
                <span>Normal <b style="color:{T['accent']}">{fmt_int(r.classified_normal)}</b></span>
              </div>
            </div>
            """)
        render(f'<div class="panel">{"".join(run_html)}</div>')


# -----------------------------------------------------------------------------
# TAB 2: NODE-WISE MONITORING
# -----------------------------------------------------------------------------
with tab2:
    section_header(
        "02 / Node-wise monitoring",
        "Node behaviour map",
        "Each software-defined IoT node is modelled independently. Ring progress "
        "shows the share of that node's controlled anomaly windows detected.",
    )

    _init_state("node_map_select", NODE_IDS[0])
    selected_node = st.segmented_control(
        "Inspect software-defined node profile",
        options=NODE_IDS,
        format_func=lambda n: n.replace("_", " "),
        key="node_map_select",
        on_change=_sticky,
        args=("node_map_select",),
        width="stretch",
    ) or NODE_IDS[0]

    col_map, col_detail = st.columns([8, 4], gap="medium")
    with col_map:
        render(f"""
        <div class="panel" style="padding:18px 20px 16px">
          <div class="panel-h" style="margin-bottom:6px">
            <span class="panel-t">Software-defined node profiles</span>
            <span class="tag">Conceptual model map · not a physical topology</span>
          </div>
          {node_map_svg(df_nodes, selected_node, LOWEST_NODE)}
          <div class="map-caption">
            <span><i style="background:{T['success']}"></i>Full detection</span>
            <span><i style="background:{T['accent']}"></i>Partial detection</span>
            <span><i style="background:{T['warning']}"></i>Lowest detection rate</span>
            <span><code>IF·Mn</code> = node-specific Isolation Forest model</span>
          </div>
        </div>
        """)

    with col_detail:
        row = df_nodes[df_nodes["Node ID"] == selected_node].iloc[0]
        n_norm = int(row["Normal Windows"])
        n_anom = int(row["Controlled Anomaly Windows"])
        n_det = int(row["Detected Anomalies"])
        n_miss = int(row["Missed Anomalies"])
        n_rate = float(row["Detection Rate (%)"])
        tone = rate_tone(n_rate, selected_node == LOWEST_NODE)
        det_share = (n_det / n_anom * 100.0) if n_anom else 0.0
        render(f"""
        <div class="panel">
          <div class="nd-head">
            <div>
              <div class="nd-id">{esc(selected_node.replace('_', ' '))}</div>
              <div class="nd-type">{esc(row['Node Type'])}</div>
              <div class="nd-kind">Software-defined IoT node · simulated traffic</div>
            </div>
          </div>
          <div class="nd-rate" style="color:{tone_color(tone)}">{n_rate:.2f}%</div>
          <div class="nd-rate-l">Detection rate · controlled anomaly&nbsp;&nbsp;<span class="tag {tone}">{TONE_LABEL[tone]}</span></div>
          <div class="bar"><i style="width:{det_share:.2f}%"></i></div>
          <div class="bar-l"><span>Detected <b>{n_det}</b></span><span>Missed <b>{n_miss}</b></span></div>
          <div class="nd-rows">
            {sb_row("Node type", row['Node Type'])}
            {sb_row("Normal windows", fmt_int(n_norm), mono=True)}
            {sb_row("Controlled anomaly windows", fmt_int(n_anom), mono=True)}
            {sb_row("Detected", fmt_int(n_det), mono=True, color=T['success'])}
            {sb_row("Missed", fmt_int(n_miss), mono=True, color=T['danger'] if n_miss else '')}
            {sb_row("Model", "IF·M" + selected_node.split('_')[-1] + " (independent)", mono=True)}
          </div>
        </div>
        """)

    # Node-wise performance table
    sub_header("Node-wise detection performance", "RUN 02")
    body = []
    for i, r in enumerate(df_nodes.itertuples(index=False)):
        nid, ntype, nn, na, nd, nm, rate = r
        is_low = nid == LOWEST_NODE and rate < 100
        tone = rate_tone(rate, is_low)
        col = tone_color(tone)
        status = {"ok": "Full detection", "accent": "Partial", "warn": "Lowest rate"}[tone]
        body.append(f"""
        <tr class="{'flag' if is_low else ''}">
          <td class="id"><span class="dot" style="background:{col}"></span>{esc(nid)}</td>
          <td class="dim">{esc(ntype)}</td>
          <td class="num">{fmt_int(nn)}</td>
          <td class="num">{fmt_int(na)}</td>
          <td class="num">{fmt_int(nd)}</td>
          <td class="num {'miss-nz' if nm else 'dim'}">{fmt_int(nm)}</td>
          <td><div class="rate-cell"><div class="rate-track"><i style="width:{rate:.2f}%;background:{col};animation-delay:{i * 60}ms"></i></div>
              <span class="rate-v" style="color:{col}">{rate:.2f}%</span></div></td>
          <td><span class="tag {tone}">{status}</span></td>
        </tr>
        """)
    tot_n = int(df_nodes["Normal Windows"].sum())
    tot_a = int(df_nodes["Controlled Anomaly Windows"].sum())
    tot_d = int(df_nodes["Detected Anomalies"].sum())
    tot_m = int(df_nodes["Missed Anomalies"].sum())
    tot_rate = (tot_d / tot_a * 100.0) if tot_a else 0.0
    render(f"""
    <div class="tbl-wrap">
      <table class="tbl">
        <thead><tr>
          <th>Node ID</th><th>Node type</th><th class="num">Normal windows</th>
          <th class="num">Controlled anomaly windows</th><th class="num">Detected</th>
          <th class="num">Missed</th><th>Detection rate</th><th>Status</th>
        </tr></thead>
        <tbody>{''.join(body)}</tbody>
        <tfoot><tr>
          <td class="id">All nodes</td><td class="dim">5 software-defined profiles</td>
          <td class="num">{fmt_int(tot_n)}</td><td class="num">{fmt_int(tot_a)}</td>
          <td class="num">{fmt_int(tot_d)}</td><td class="num miss-nz">{fmt_int(tot_m)}</td>
          <td><div class="rate-cell"><div class="rate-track"><i style="width:{tot_rate:.2f}%;background:{T['text']}"></i></div>
              <span class="rate-v">{tot_rate:.2f}%</span></div></td>
          <td></td>
        </tr></tfoot>
      </table>
    </div>
    """)

    low = df_nodes[df_nodes["Node ID"] == LOWEST_NODE].iloc[0]
    low_miss_rate = (low["Missed Anomalies"] / low["Controlled Anomaly Windows"] * 100.0) if low["Controlled Anomaly Windows"] else 0.0
    full_nodes = int((df_nodes["Detection Rate (%)"] >= 100).sum())
    st.write("")
    render(f"""
    <div class="insight warn">
      <div class="h">Observation</div>
      <p>{esc(LOWEST_NODE.replace('_', ' '))} shows the highest residual miss rate in the controlled anomaly
      experiment (<b>{int(low['Missed Anomalies'])}</b> of <b>{int(low['Controlled Anomaly Windows'])}</b> windows,
      <b>{low_miss_rate:.2f}%</b> missed). {full_nodes} of {len(df_nodes)} nodes detected every controlled anomaly window.</p>
      <p class="fine">This is an observed experimental result only; no causal explanation is inferred.</p>
    </div>
    """)


# -----------------------------------------------------------------------------
# TAB 3: BEHAVIOURAL FEATURES
# -----------------------------------------------------------------------------
with tab3:
    section_header(
        "03 / Behavioural features",
        "Behavioural feature analysis",
        "Compare the normal baseline with controlled synthetic anomalous behaviour "
        "for a single software-defined IoT node and window-level feature.",
    )

    df_features = load_feature_windows_all()

    c_node, c_ctx = st.columns([4, 8], gap="medium", vertical_alignment="bottom")
    with c_node:
        f_node = st.selectbox(
            "Node",
            options=NODE_IDS,
            format_func=lambda x: f"{x.replace('_', ' ')} — {NODE_TYPES.get(x, '')}",
            key="feat_node",
        )
    with c_ctx:
        nrow = df_nodes[df_nodes["Node ID"] == f_node].iloc[0]
        render(f"""
        <div class="ctx">
          <div>Normal windows <b>{fmt_int(nrow['Normal Windows'])}</b></div>
          <div>Controlled anomaly windows <b>{fmt_int(nrow['Controlled Anomaly Windows'])}</b></div>
          <div>Detection rate <b>{float(nrow['Detection Rate (%)']):.2f}%</b></div>
        </div>
        """)

    _init_state("feat_feature", "mean_iat")
    f_feat = st.segmented_control(
        "Feature",
        options=list(FEATURES.keys()),
        format_func=lambda k: FEATURES[k][0],
        key="feat_feature",
        on_change=_sticky,
        args=("feat_feature",),
        width="stretch",
    ) or "mean_iat"

    feat_label, feat_phrase = FEATURES[f_feat]
    dfn = df_features[df_features["node_id"] == f_node].copy()
    s_norm = dfn.loc[dfn["dataset_type"] == "normal", f_feat].dropna()
    s_anom = dfn.loc[dfn["dataset_type"] == "controlled_anomaly", f_feat].dropna()
    fa = T["fill_alpha"]

    col_dist, col_traj = st.columns([5, 7], gap="medium")
    with col_dist:
        sub_header("A · Distribution", feat_label)
        fig_d = go.Figure()
        for name, series, color in (
            (LABEL_NORMAL_DS, s_norm, T["series_normal"]),
            ("Controlled synthetic<br>anomaly", s_anom, T["series_anomaly"]),
        ):
            hover_name = name.replace("<br>", " ")
            fig_d.add_trace(go.Violin(
                y=series, name=name, line=dict(color=color, width=1.4), fillcolor=alpha(color, fa),
                box_visible=True, box=dict(fillcolor=T["surface"], line=dict(color=color, width=1.2)),
                meanline_visible=True, points=False, spanmode="hard", width=0.8,
                hovertemplate=f"{hover_name}<br>{feat_label}: %{{y:.4f}}<extra></extra>",
            ))
        style_fig(fig_d, height=380, legend=False)
        fig_d.update_yaxes(title_text=feat_label)
        fig_d.update_xaxes(tickfont=dict(family=TY["sans"].replace("'", ""), size=13.5, color=T["text"]), showgrid=False)
        show_fig(fig_d, key="fig_dist")

    with col_traj:
        sub_header("B · Behaviour trajectory across windows", feat_label)
        fig_t = go.Figure()
        if len(s_norm) > 1:
            mu, sd = float(s_norm.mean()), float(s_norm.std())
            xmax = float(dfn["window_id"].max())
            xmin = float(dfn["window_id"].min())
            fig_t.add_trace(go.Scatter(
                x=[xmin, xmax, xmax, xmin], y=[mu - 2 * sd, mu - 2 * sd, mu + 2 * sd, mu + 2 * sd],
                fill="toself", fillcolor=alpha(T["series_normal"], 0.10), line=dict(width=0),
                name="Baseline mean ± 2 SD (descriptive)", hoverinfo="skip",
            ))
        for dtype, name, color in (("normal", LABEL_NORMAL_DS, T["series_normal"]),
                                   ("controlled_anomaly", LABEL_ANOM_DS, T["series_anomaly"])):
            d = dfn[dfn["dataset_type"] == dtype].sort_values("window_id")
            fig_t.add_trace(go.Scatter(
                x=d["window_id"], y=d[f_feat], name=name, mode="lines",
                line=dict(color=color, width=1.6),
                hovertemplate=f"{name}<br>window %{{x}}<br>{feat_label}: %{{y:.4f}}<extra></extra>",
            ))
        style_fig(fig_t, height=380)
        fig_t.update_xaxes(title_text="Window ID")
        fig_t.update_yaxes(title_text=feat_label)
        show_fig(fig_t, key="fig_traj")

    col_stats, col_ins = st.columns([7, 5], gap="medium")

    def _stats(s: pd.Series) -> dict:
        return {
            "Windows": len(s), "Mean": s.mean(), "Median": s.median(),
            "Std dev": s.std(), "Min": s.min(), "Max": s.max(),
        }

    st_n, st_a = _stats(s_norm), _stats(s_anom)
    with col_stats:
        sub_header("C · Statistical comparison", feat_label)
        rows = []
        for k in st_n:
            vn, va = st_n[k], st_a[k]
            if k == "Windows":
                rows.append(f'<tr><td class="dim">{k}</td><td class="num">{fmt_int(vn)}</td>'
                            f'<td class="num">{fmt_int(va)}</td><td class="num dim">—</td></tr>')
                continue
            if vn and not math.isnan(vn) and vn != 0:
                rel = (va - vn) / abs(vn) * 100.0
                rel_s = f"{rel:+.1f}%"
            else:
                rel_s = "—"
            rows.append(f'<tr><td class="dim">{k}</td><td class="num">{fmt_num(vn)}</td>'
                        f'<td class="num">{fmt_num(va)}</td><td class="num dim">{rel_s}</td></tr>')
        render(f"""
        <div class="tbl-wrap">
          <table class="tbl compact" style="min-width:480px">
            <thead><tr><th>Statistic</th>
              <th class="num"><span class="dot" style="background:{T['series_normal']}"></span>Normal baseline</th>
              <th class="num"><span class="dot" style="background:{T['series_anomaly']}"></span>Controlled anomaly</th>
              <th class="num">Δ vs baseline</th></tr></thead>
            <tbody>{''.join(rows)}</tbody>
          </table>
        </div>
        """)

    with col_ins:
        sub_header("Computed insight")
        node_lbl = f_node.replace("_", " ")
        if len(s_norm) and len(s_anom):
            mn, ma = float(s_norm.mean()), float(s_anom.mean())
            rel = ((ma - mn) / abs(mn) * 100.0) if mn != 0 else float("inf")
            arel = abs(rel)
            if arel < 5:
                sentence = (f"Controlled anomalous behaviour shows a {feat_phrase} comparable to the normal "
                            f"baseline for {node_lbl}")
            else:
                mag = "slightly" if arel < 20 else ("moderately" if arel < 50 else "substantially")
                direction = "higher" if ma > mn else "lower"
                sentence = (f"Controlled anomalous behaviour shows a {mag} {direction} {feat_phrase} "
                            f"than the normal baseline for {node_lbl}")
            rel_txt = f"{rel:+.1f}%" if math.isfinite(rel) else "n/a"
            lo, hi = float(s_norm.min()), float(s_norm.max())
            outside = int(((s_anom < lo) | (s_anom > hi)).sum())
            out_pct = outside / len(s_anom) * 100.0
            sd_n, sd_a = float(s_norm.std()), float(s_anom.std())
            disp = (f"Dispersion (std dev) is <b>{sd_a / sd_n:.2f}×</b> the baseline."
                    if sd_n > 0 else "Baseline dispersion is zero for this feature.")
            render(f"""
            <div class="insight">
              <div class="h">{esc(node_lbl)} · {esc(feat_label)}</div>
              <p>{esc(sentence)} (mean <b>{fmt_num(ma)}</b> vs <b>{fmt_num(mn)}</b>, <b>{rel_txt}</b>).</p>
              <p><b>{outside}</b> of <b>{len(s_anom)}</b> controlled anomaly windows (<b>{out_pct:.1f}%</b>) fall outside
              the observed normal range [{fmt_num(lo)}, {fmt_num(hi)}]. {disp}</p>
              <p class="fine">Computed from the selected node and feature only. The Isolation Forest models all five
              features jointly, so a single feature does not determine a prediction.</p>
            </div>
            """)
        else:
            render('<div class="insight"><p>No feature windows available for this selection.</p></div>')


# -----------------------------------------------------------------------------
# TAB 4: PREDICTION & EVIDENCE
# -----------------------------------------------------------------------------
def evidence_table_html(df: pd.DataFrame) -> str:
    """Complete, theme-aware evidence ledger (scrollable, sticky header)."""
    if df.empty:
        return '<div class="insight"><p>No records match the active filters.</p></div>'
    pill_a = f'<span class="pill anom"><i></i>{LABEL_ANOM_CLS}</span>'
    pill_n = f'<span class="pill norm"><i></i>{LABEL_NORM_CLS}</span>'
    rows = []
    for r in df.itertuples(index=False):
        rows.append(
            f'<tr><td class="id">{esc(r.node_id)}</td><td class="dim">{esc(r.node_type)}</td>'
            f'<td class="num">{int(r.window_id)}</td>'
            f'<td class="num">{r.mean_iat:.4f}</td><td class="num">{r.iat_std:.4f}</td>'
            f'<td class="num">{r.packet_rate:.2f}</td><td class="num">{r.mean_packet_size:.2f}</td>'
            f'<td class="num">{r.packet_size_std:.2f}</td>'
            f'<td>{pill_a if r.prediction == -1 else pill_n}</td>'
            f'<td class="num">{r.anomaly_score:.6f}</td><td class="id dim">{esc(r.actual_class)}</td></tr>'
        )
    head = (
        "<thead><tr><th>Node ID</th><th>Node Type</th><th class='num'>Window ID</th>"
        "<th class='num'>mean_iat</th><th class='num'>iat_std</th><th class='num'>packet_rate</th>"
        "<th class='num'>mean_packet_size</th><th class='num'>packet_size_std</th>"
        "<th>Classification</th><th class='num'>Anomaly Score</th><th>Actual Class</th></tr></thead>"
    )
    return (f'<div class="tbl-wrap tbl-scroll"><table class="tbl" style="min-width:1240px">'
            f'{head}<tbody>{"".join(rows)}</tbody></table></div>')


with tab4:
    section_header(
        "04 / Prediction & evidence",
        "Prediction evidence ledger",
        "Window-level Isolation Forest outputs joined to their feature vectors, "
        "read directly from SQLite.",
    )

    render("""
    <div class="insight" style="margin-bottom:8px">
      <div class="h">Interpretation</div>
      <p>Isolation Forest detects statistical deviation from the learned normal baseline.
      It does not identify or confirm a specific attack type.</p>
    </div>
    """)

    col_run, col_node_f, col_pred_f = st.columns([5, 3, 4], gap="medium")
    with col_run:
        selected_run = st.selectbox(
            "Evaluation run",
            options=[2, 1],
            format_func=lambda x: "Run 02 · Controlled anomaly evaluation" if x == 2 else "Run 01 · Normal baseline test"
        )
    with col_node_f:
        selected_pred_node = st.selectbox(
            "Node",
            options=["All Nodes"] + NODE_IDS,
        )
    with col_pred_f:
        selected_status = st.selectbox(
            "Classification",
            options=["All Predictions", "Anomalous Behaviour (-1)", "Normal Behaviour (1)"]
        )

    df_run = load_predictions_with_features(selected_run)

    # Filter by node
    df_scope = df_run if selected_pred_node == "All Nodes" else df_run[df_run["node_id"] == selected_pred_node]

    # Filter by status
    df_evidence = df_scope
    if selected_status == "Anomalous Behaviour (-1)":
        df_evidence = df_scope[df_scope["prediction"] == -1]
    elif selected_status == "Normal Behaviour (1)":
        df_evidence = df_scope[df_scope["prediction"] == 1]

    # Result summary (node scope, before classification filter)
    n_total = len(df_scope)
    n_anom = int((df_scope["prediction"] == -1).sum())
    n_norm = int((df_scope["prediction"] == 1).sum())
    is_anom_run = selected_run == 2
    share = (n_anom / n_total * 100.0) if n_total else 0.0
    norm_sub = "Missed controlled anomalies" if is_anom_run else "Normal test windows"
    anom_sub = "Controlled anomalies detected" if is_anom_run else "Normal test windows flagged"
    rate_k = "Detection rate" if is_anom_run else "Flagged share"
    rate_col = T["success"] if is_anom_run else T["warning"]
    scope_lbl = "All nodes" if selected_pred_node == "All Nodes" else selected_pred_node.replace("_", " ")
    render(f"""
    <div class="sum" style="margin-top:6px">
      <div><div class="k">Records</div><div class="v">{fmt_int(n_total)}</div><div class="s">Run {selected_run:02d} · {esc(scope_lbl)}</div></div>
      <div><div class="k"><span class="pill anom" style="padding:0;border:none;background:none"><i></i></span>{LABEL_ANOM_CLS}</div>
        <div class="v" style="color:{T['danger']}">{fmt_int(n_anom)}</div><div class="s">{anom_sub}</div></div>
      <div><div class="k"><span class="pill norm" style="padding:0;border:none;background:none"><i></i></span>{LABEL_NORM_CLS}</div>
        <div class="v" style="color:{T['accent']}">{fmt_int(n_norm)}</div><div class="s">{norm_sub}</div></div>
      <div><div class="k">{rate_k}</div><div class="v" style="color:{rate_col}">{share:.2f}%</div><div class="s">{fmt_int(n_anom)} / {fmt_int(n_total)} classified anomalous</div></div>
      <div class="sum-bar"><i style="width:{share:.2f}%;background:{T['danger']}"></i><i style="flex:1;background:{T['accent']};opacity:.75"></i></div>
    </div>
    """)

    # Anomaly score visualisation
    df_sc = df_scope.copy()
    df_sc["Classification"] = df_sc["prediction"].map({-1: LABEL_ANOM_CLS, 1: LABEL_NORM_CLS})
    col_h, col_s = st.columns([6, 6], gap="medium")
    with col_h:
        sub_header("Anomaly score distribution", f"RUN {selected_run:02d}")
        fig_h = go.Figure()
        for cls, color in ((LABEL_NORM_CLS, T["series_normal"]), (LABEL_ANOM_CLS, T["series_anomaly"])):
            vals = df_sc.loc[df_sc["Classification"] == cls, "anomaly_score"]
            if len(vals):
                fig_h.add_trace(go.Histogram(
                    x=vals, name=f"{cls} ({len(vals)})", nbinsx=40,
                    marker=dict(color=color, line=dict(color=T["surface"], width=0.6)), opacity=0.82,
                    hovertemplate="score %{x}<br>windows %{y}<extra>" + cls + "</extra>",
                ))
        style_fig(fig_h, height=350)
        fig_h.update_layout(barmode="overlay", bargap=0.04)
        fig_h.update_xaxes(title_text="anomaly_score (lower = stronger deviation)")
        fig_h.update_yaxes(title_text="Windows")
        show_fig(fig_h, key="fig_score_hist")

    with col_s:
        sub_header("Anomaly score by node")
        fig_s = go.Figure()
        for cls, color in ((LABEL_NORM_CLS, T["series_normal"]), (LABEL_ANOM_CLS, T["series_anomaly"])):
            d = df_sc[df_sc["Classification"] == cls]
            if len(d):
                fig_s.add_trace(go.Box(
                    x=d["node_id"], y=d["anomaly_score"], name=cls,
                    boxpoints="all", jitter=0.55, pointpos=0,
                    fillcolor="rgba(0,0,0,0)", line=dict(color="rgba(0,0,0,0)"),
                    marker=dict(color=color, size=5, opacity=0.7,
                                symbol="diamond" if cls == LABEL_ANOM_CLS else "circle"),
                    customdata=d[["window_id"]].values,
                    hovertemplate="%{x} · window %{customdata[0]}<br>score %{y:.4f}<extra>" + cls + "</extra>",
                ))
        style_fig(fig_s, height=350)
        fig_s.update_layout(boxmode="overlay")
        fig_s.update_yaxes(title_text="anomaly_score")
        fig_s.update_xaxes(title_text="Software-defined IoT node", categoryorder="array", categoryarray=NODE_IDS)
        show_fig(fig_s, key="fig_score_node")

    render("""
    <p class="footnote">Scores are the stored <code>decision_function</code> outputs of each trained node-specific
    Isolation Forest. Classification labels are the model's own predictions; no threshold or decision
    boundary is drawn or inferred by this dashboard.</p>
    """)

    # Evidence table
    col_eh, col_sort = st.columns([8, 4], gap="medium", vertical_alignment="bottom")
    with col_eh:
        sub_header("Evidence records", f"{len(df_evidence):,} matching active filters")
    with col_sort:
        sort_mode = st.selectbox(
            "Order records by",
            options=["window", "score_asc", "score_desc"],
            format_func=lambda m: {
                "window": "Node · window sequence",
                "score_asc": "Anomaly score · strongest deviation first",
                "score_desc": "Anomaly score · weakest deviation first",
            }[m],
            key="ev_sort",
        )
    if sort_mode == "score_asc":
        df_evidence = df_evidence.sort_values("anomaly_score", kind="stable")
    elif sort_mode == "score_desc":
        df_evidence = df_evidence.sort_values("anomaly_score", ascending=False, kind="stable")

    st.html(evidence_table_html(df_evidence))
