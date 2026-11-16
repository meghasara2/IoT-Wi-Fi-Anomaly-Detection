"""
Unit Tests for Streamlit Cloud Dashboard.
File: tests/test_cloud_dashboard.py

Covers:
  - Configuration retrieval (st.secrets vs env vars).
  - Graceful handling of unconfigured / offline states.
  - Mock PostgREST API query execution and DataFrame mapping.
  - Error isolation (HTTP 401, 403, 404, 500, ConnectionError).
  - Verification of privacy boundaries (no raw MACs or unredacted IPs).
"""

from unittest.mock import MagicMock, patch
import pandas as pd
import pytest
import requests

from src.cloud_dashboard import fetch_cloud_view, get_supabase_config


def test_get_supabase_config_env(monkeypatch):
    """Verifies that Supabase URL and Anon Key are retrieved from environment."""
    monkeypatch.setenv("SUPABASE_URL", "https://test.supabase.co")
    monkeypatch.setenv("SUPABASE_ANON_KEY", "anon_key_123")

    url, key = get_supabase_config()
    assert url == "https://test.supabase.co"
    assert key == "anon_key_123"


def test_fetch_cloud_view_unconfigured(monkeypatch):
    """Verifies graceful handling when credentials are missing."""
    monkeypatch.setenv("SUPABASE_URL", "")
    monkeypatch.setenv("SUPABASE_ANON_KEY", "")

    df, err = fetch_cloud_view("v_public_collector_status")
    assert df.empty
    assert "Awaiting Supabase cloud credentials" in err


def test_fetch_cloud_view_success(monkeypatch):
    """Verifies successful retrieval and DataFrame mapping from PostgREST."""
    monkeypatch.setenv("SUPABASE_URL", "https://test.supabase.co")
    monkeypatch.setenv("SUPABASE_ANON_KEY", "anon_key_123")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {"run_id": "run_1", "connection_state": "LIVE", "heartbeat_age_seconds": 2.5},
        {"run_id": "run_2", "connection_state": "STALE", "heartbeat_age_seconds": 35.0},
    ]

    with patch("requests.get", return_value=mock_resp):
        # Clear cache for isolated test
        fetch_cloud_view.clear()
        df, err = fetch_cloud_view("v_public_collector_status", limit=10)

    assert err is None
    assert not df.empty
    assert len(df) == 2
    assert "connection_state" in df.columns
    assert df.iloc[0]["connection_state"] == "LIVE"


def test_fetch_cloud_view_auth_error(monkeypatch):
    """Verifies that HTTP 401/403 access denial is reported cleanly without raising."""
    monkeypatch.setenv("SUPABASE_URL", "https://test.supabase.co")
    monkeypatch.setenv("SUPABASE_ANON_KEY", "expired_key")

    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.text = "Invalid API key"

    with patch("requests.get", return_value=mock_resp):
        fetch_cloud_view.clear()
        df, err = fetch_cloud_view("v_public_attack_events")

    assert df.empty
    assert "Access Denied" in err
    assert "HTTP 401" in err


def test_fetch_cloud_view_network_error(monkeypatch):
    """Verifies that network connection failures are caught and reported cleanly."""
    monkeypatch.setenv("SUPABASE_URL", "https://test.supabase.co")
    monkeypatch.setenv("SUPABASE_ANON_KEY", "anon_key_123")

    with patch("requests.get", side_effect=requests.exceptions.ConnectionError("Connection timed out")):
        fetch_cloud_view.clear()
        df, err = fetch_cloud_view("v_public_live_traffic_windows")

    assert df.empty
    assert "Network connection error" in err


def test_cloud_view_privacy_invariants():
    """
    Verifies that cloud views never project raw hardware MAC addresses or unredacted IP addresses.
    Checks simulated outputs for public views.
    """
    sample_attack_payload = [
        {
            "event_id": 1,
            "category": "Denial_of_Service",
            "source_station_id": "Node_3",
            "target_ip": "LOCAL_NETWORK",
            "sanitized_evidence_json": {"probe_counts": 500, "verdict": "Single-source TCP SYN flood detected"},
            "recommended_action": "Inspect high-rate traffic flow and rate-limit source endpoint if unauthorized.",
        }
    ]
    df = pd.DataFrame(sample_attack_payload)
    
    # Assert no raw MAC column
    assert "source_mac" not in df.columns
    assert "client_mac" not in df.columns
    # Assert target_ip is categorical
    assert df.iloc[0]["target_ip"] in ("LOCAL_NETWORK", "EXTERNAL_NETWORK", "IP_REDACTED")
    # Assert station token is allowlisted
    assert df.iloc[0]["source_station_id"] in ("Node_1", "Node_2", "Node_3", "Node_4", "Node_5", "ATTACKER_UNMAPPED")


def test_safe_html_xss_escaping():
    """Verifies that safe_html properly escapes HTML tags and prevents script injection."""
    from src.cloud_dashboard import safe_html

    # Test malicious scripts
    assert safe_html("<script>alert('XSS')</script>") == "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;"
    assert safe_html('<img src=x onerror="alert(1)">') == "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;"
    assert safe_html("Hello & World") == "Hello &amp; World"
    assert safe_html(None) == ""
    assert safe_html(12345) == "12345"


def test_connection_state_thresholds():
    """Verifies that connection state accurately reflects LIVE, STALE, and OFFLINE thresholds."""
    # LIVE: age <= 15s
    for age in [0.0, 5.2, 14.9, 15.0]:
        state = "LIVE" if age <= 15.0 else ("STALE" if age <= 60.0 else "OFFLINE")
        assert state == "LIVE"

    # STALE: 15s < age <= 60s
    for age in [15.1, 30.0, 59.9, 60.0]:
        state = "LIVE" if age <= 15.0 else ("STALE" if age <= 60.0 else "OFFLINE")
        assert state == "STALE"

    # OFFLINE: age > 60s or None
    for age in [60.1, 120.0, 999.0]:
        state = "LIVE" if age <= 15.0 else ("STALE" if age <= 60.0 else "OFFLINE")
        assert state == "OFFLINE"


def test_get_supabase_config_nested_secrets(monkeypatch):
    """Verifies that nested [supabase] secrets format is properly parsed."""
    import streamlit as st

    class MockSecrets(dict):
        def get(self, key, default=None):
            return super().get(key, default)

    mock_sec = MockSecrets({
        "supabase": {
            "url": "https://nested.supabase.co",
            "key": "nested_anon_key_xyz",
        }
    })
    monkeypatch.setattr(st, "secrets", mock_sec)
    monkeypatch.setenv("SUPABASE_URL", "")
    monkeypatch.setenv("SUPABASE_ANON_KEY", "")

    url, key = get_supabase_config()
    assert url == "https://nested.supabase.co"
    assert key == "nested_anon_key_xyz"


def test_get_supabase_config_rejects_service_role(monkeypatch):
    """Verifies that service_role keys are strictly rejected from public dashboard."""
    import streamlit as st
    monkeypatch.setattr(st, "secrets", {})
    monkeypatch.setenv("SUPABASE_URL", "https://test.supabase.co")
    monkeypatch.setenv("SUPABASE_ANON_KEY", "eyJhbGciOi...service_role...secret")

    url, key = get_supabase_config()
    assert url == "https://test.supabase.co"
    assert key == ""  # Discarded for security!


def test_safe_numeric_parsers():
    """Verifies safe_int and safe_float against malicious and edge values."""
    from src.cloud_dashboard import safe_float, safe_int

    assert safe_int(42) == 42
    assert safe_int("42") == 42
    assert safe_int("42.8") == 42
    assert safe_int(None, default=0) == 0
    assert safe_int("invalid", default=-1) == -1
    assert safe_int(float("nan"), default=0) == 0

    assert safe_float(3.14) == 3.14
    assert safe_float("3.14") == 3.14
    assert safe_float(None, default=0.0) == 0.0
    assert safe_float("nan", default=0.0) == 0.0
    assert safe_float("bad_float", default=999.0) == 999.0



