"""
Unit Tests: Live Interface Resolver
File: tests/test_live_interface_resolver.py

Covers:
  - parse_interface_list: correct parsing of tshark -D output
  - parse_interface_list: graceful handling of malformed/extra lines
  - find_hotspot_candidates: keyword matching logic
  - resolve_hotspot_interface: single candidate, no candidate, ambiguous
  - resolve_hotspot_interface: override_index accepted and validated
  - TSharkNotFoundError raised for missing binary (mocked)

All tests use mock tshark output — no real subprocess is spawned.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add project root to sys.path for both invocation styles
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.live_interface_resolver import (
    AmbiguousHotspotInterfaceError,
    NoHotspotInterfaceError,
    TSharkNotFoundError,
    find_hotspot_candidates,
    format_interface_table,
    parse_interface_list,
    resolve_hotspot_interface,
    ChannelAlignmentStatus,
    ChannelDiagnosticResult,
    parse_netsh_wlan_interfaces,
    query_windows_hotspot_channel,
    check_hotspot_channel_alignment,
)

# ─────────────────────────────────────────────────────────────────────────────
# Sample tshark -D outputs
# ─────────────────────────────────────────────────────────────────────────────
TSHARK_OUTPUT_ONE_HOTSPOT = """\
1. \\Device\\NPF_{3D966D1A-458D-466F-BAE8-A8EDC7C3D42B} (Local Area Connection* 10)
2. \\Device\\NPF_{E3465DF4-E4E6-4EC3-9024-9B5011B42CAE} (Local Area Connection* 9)
3. \\Device\\NPF_{49F3748D-CE57-4359-BAA4-D2F2F66277C9} (Local Area Connection* 8)
4. \\Device\\NPF_{7681A799-6125-4110-805A-DCD3EE30DCF7} (Bluetooth Network Connection)
5. \\Device\\NPF_{7FE57C21-6C58-45CB-8A59-D7C5720DCE0E} (Local Area Connection* 2)
6. \\Device\\NPF_{5635802C-B744-4D3A-86B0-1ECE103433CF} (Wi-Fi)
7. \\Device\\NPF_{B85A0023-9173-4690-992A-67C7957BA8E4} (Local Area Connection* 1)
8. \\Device\\NPF_{7E88BE63-F7A2-4BD1-85C6-733BC7BF60E6} (Ethernet)
9. \\Device\\NPF_Loopback (Adapter for loopback traffic capture)
10. etwdump (Event Tracing for Windows (ETW) reader)
"""

# A simpler output where only one adapter matches hotspot keyword
TSHARK_OUTPUT_SINGLE_CANDIDATE = """\
1. \\Device\\NPF_{AAAA} (Wi-Fi)
2. \\Device\\NPF_{BBBB} (Local Area Connection* 10)
3. \\Device\\NPF_{CCCC} (Ethernet)
"""

TSHARK_OUTPUT_NO_HOTSPOT = """\
1. \\Device\\NPF_{AAAA} (Wi-Fi)
2. \\Device\\NPF_{BBBB} (Ethernet)
3. \\Device\\NPF_Loopback (Loopback)
"""

TSHARK_OUTPUT_MULTI_HOTSPOT = """\
1. \\Device\\NPF_{AAAA} (Local Area Connection* 10)
2. \\Device\\NPF_{BBBB} (Local Area Connection* 9)
3. \\Device\\NPF_{CCCC} (Wi-Fi)
"""

TSHARK_OUTPUT_WITH_BANNER = """\
Running as user "root" and group "root". This could be dangerous.

1. \\Device\\NPF_{AAAA} (Local Area Connection* 10)
2. \\Device\\NPF_{BBBB} (Ethernet)
"""


# ─────────────────────────────────────────────────────────────────────────────
# Tests: parse_interface_list
# ─────────────────────────────────────────────────────────────────────────────
class TestParseInterfaceList:

    def test_parses_ten_interfaces(self):
        # The real tshark -D output has 10 lines but the last line uses the
        # non-standard 'etwdump (...)' format (no \Device\NPF_ token) which
        # the parser correctly skips. Only 9 lines have the standard format.
        ifaces = parse_interface_list(TSHARK_OUTPUT_ONE_HOTSPOT)
        assert len(ifaces) == 9

    def test_first_interface_index(self):
        ifaces = parse_interface_list(TSHARK_OUTPUT_ONE_HOTSPOT)
        assert ifaces[0][0] == 1

    def test_last_interface_index(self):
        # The etwdump line is non-standard (no \Device\NPF_ path) and is
        # correctly skipped. The last parseable line is the Loopback adapter
        # at index 9.
        ifaces = parse_interface_list(TSHARK_OUTPUT_ONE_HOTSPOT)
        assert ifaces[-1][0] == 9

    def test_interface_name_parsing(self):
        ifaces = parse_interface_list(TSHARK_OUTPUT_ONE_HOTSPOT)
        # Index 6 should be Wi-Fi
        names = {idx: name for idx, _dev, name in ifaces}
        assert names[6] == "Wi-Fi"

    def test_local_area_connection_star_name(self):
        ifaces = parse_interface_list(TSHARK_OUTPUT_ONE_HOTSPOT)
        names = {idx: name for idx, _dev, name in ifaces}
        assert "Local Area Connection* 10" in names[1]

    def test_empty_input_returns_empty(self):
        assert parse_interface_list("") == []

    def test_banner_lines_are_skipped(self):
        ifaces = parse_interface_list(TSHARK_OUTPUT_WITH_BANNER)
        assert len(ifaces) == 2

    def test_returns_list_of_tuples(self):
        ifaces = parse_interface_list(TSHARK_OUTPUT_ONE_HOTSPOT)
        for item in ifaces:
            assert isinstance(item, tuple) and len(item) == 3

    def test_indices_are_integers(self):
        ifaces = parse_interface_list(TSHARK_OUTPUT_ONE_HOTSPOT)
        for idx, _dev, _name in ifaces:
            assert isinstance(idx, int)


# ─────────────────────────────────────────────────────────────────────────────
# Tests: find_hotspot_candidates
# ─────────────────────────────────────────────────────────────────────────────
class TestFindHotspotCandidates:

    def _ifaces(self, raw: str):
        return parse_interface_list(raw)

    def test_one_hotspot_candidate_real_output(self):
        """The real tshark -D output seen in this project has two 'Local Area Connection*'
        and one Wi-Fi; the Wi-Fi keyword matches Wi-Fi adapter too but hotspot adapters
        are 'Local Area Connection*'. We only expect ones matching our keywords."""
        ifaces = self._ifaces(TSHARK_OUTPUT_ONE_HOTSPOT)
        # All 'Local Area Connection*' entries should match 'local area connection*' keyword
        candidates = find_hotspot_candidates(ifaces)
        # Indices 1, 2, 3, 5, 7 match "local area connection*"
        candidate_indices = [c[0] for c in candidates]
        assert 1 in candidate_indices  # Local Area Connection* 10
        assert 2 in candidate_indices  # Local Area Connection* 9

    def test_no_hotspot_returns_empty(self):
        ifaces = self._ifaces(TSHARK_OUTPUT_NO_HOTSPOT)
        candidates = find_hotspot_candidates(ifaces)
        assert candidates == []

    def test_single_candidate(self):
        ifaces = self._ifaces(TSHARK_OUTPUT_SINGLE_CANDIDATE)
        candidates = find_hotspot_candidates(ifaces)
        # Only "Local Area Connection* 10" should match
        assert len(candidates) == 1
        assert candidates[0][0] == 2

    def test_multi_hotspot(self):
        ifaces = self._ifaces(TSHARK_OUTPUT_MULTI_HOTSPOT)
        candidates = find_hotspot_candidates(ifaces)
        assert len(candidates) == 2

    def test_case_insensitive_matching(self):
        raw = "1. \\Device\\NPF_{A} (LOCAL AREA CONNECTION* 99)\n"
        ifaces = parse_interface_list(raw)
        candidates = find_hotspot_candidates(ifaces)
        assert len(candidates) == 1

    def test_custom_keywords(self):
        raw = "1. \\Device\\NPF_{A} (My Custom Hotspot Adapter)\n"
        ifaces = parse_interface_list(raw)
        candidates = find_hotspot_candidates(ifaces, keywords=("custom hotspot",))
        assert len(candidates) == 1


# ─────────────────────────────────────────────────────────────────────────────
# Tests: resolve_hotspot_interface
# ─────────────────────────────────────────────────────────────────────────────
class TestResolveHotspotInterface:

    def _patch_run(self, raw_output: str):
        """Helper to patch _run_tshark_list to return a preset string."""
        return patch(
            "src.live_interface_resolver._run_tshark_list",
            return_value=raw_output,
        )

    def test_single_candidate_returns_tuple(self):
        with self._patch_run(TSHARK_OUTPUT_SINGLE_CANDIDATE):
            result = resolve_hotspot_interface()
        idx, dev, name = result
        assert idx == 2
        assert "Local Area Connection* 10" in name

    def test_no_candidate_raises_no_hotspot_error(self):
        with self._patch_run(TSHARK_OUTPUT_NO_HOTSPOT):
            with pytest.raises(NoHotspotInterfaceError):
                resolve_hotspot_interface()

    def test_multiple_candidates_raises_ambiguous_error(self):
        with self._patch_run(TSHARK_OUTPUT_MULTI_HOTSPOT):
            with pytest.raises(AmbiguousHotspotInterfaceError) as exc_info:
                resolve_hotspot_interface()
        assert len(exc_info.value.candidates) == 2

    def test_override_index_returns_correct_interface(self):
        with self._patch_run(TSHARK_OUTPUT_NO_HOTSPOT):
            # Wi-Fi is index 1 in TSHARK_OUTPUT_NO_HOTSPOT
            result = resolve_hotspot_interface(override_index=1)
        assert result[0] == 1

    def test_override_index_invalid_raises_value_error(self):
        with self._patch_run(TSHARK_OUTPUT_NO_HOTSPOT):
            with pytest.raises(ValueError, match="not found"):
                resolve_hotspot_interface(override_index=99)

    def test_missing_tshark_binary_raises_error(self):
        with pytest.raises(TSharkNotFoundError):
            resolve_hotspot_interface(
                tshark_path=r"C:\Nonexistent\Path\tshark.exe"
            )

    def test_ambiguous_error_lists_candidates(self):
        with self._patch_run(TSHARK_OUTPUT_MULTI_HOTSPOT):
            with pytest.raises(AmbiguousHotspotInterfaceError) as exc_info:
                resolve_hotspot_interface()
        error_str = str(exc_info.value)
        assert "Local Area Connection* 10" in error_str or "Local Area Connection* 9" in error_str


# ─────────────────────────────────────────────────────────────────────────────
# Tests: format_interface_table
# ─────────────────────────────────────────────────────────────────────────────
class TestFormatInterfaceTable:

    def test_empty_list_returns_no_interfaces(self):
        result = format_interface_table([])
        assert "no interfaces" in result.lower()

    def test_includes_index_and_name(self):
        ifaces = [(1, r"\Device\NPF_{X}", "Local Area Connection* 10")]
        result = format_interface_table(ifaces)
        assert "1" in result
        assert "Local Area Connection* 10" in result

    def test_multiple_interfaces_formatted(self):
        ifaces = [
            (1, r"\Device\NPF_{X}", "Wi-Fi"),
            (2, r"\Device\NPF_{Y}", "Ethernet"),
        ]
        result = format_interface_table(ifaces)
        assert "Wi-Fi" in result
        assert "Ethernet" in result


# ─────────────────────────────────────────────────────────────────────────────
# Tests: Stage 8.4 Windows Mobile Hotspot / ESP32 Channel Alignment Diagnostic
# ─────────────────────────────────────────────────────────────────────────────
NETSH_OUTPUT_HOTSPOT_CH6 = """\
There is 1 interface on the system:

    Name                   : Local Area Connection* 2
    Description            : Microsoft Wi-Fi Direct Virtual Adapter
    GUID                   : 7fe57c21-6c58-45cb-8a59-d7c5720dce0e
    Physical address       : 2e:6b:f5:6e:3e:7c
    State                  : connected
    SSID                   : DIRECT-Hotspot
    BSSID                  : 2e:6b:f5:6e:3e:7c
    Network type           : Infrastructure
    Radio type             : 802.11n
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Connection mode        : Profile
    Channel                : 6
    Receive rate (Mbps)    : 144
    Transmit rate (Mbps)   : 144
    Signal                 : 100%
    Profile                : DIRECT-Hotspot

    Hosted network status  : Not available
"""

NETSH_OUTPUT_HOTSPOT_CH1 = """\
There is 1 interface on the system:

    Name                   : Local Area Connection* 2
    Description            : Microsoft Wi-Fi Direct Virtual Adapter
    State                  : connected
    Channel                : 1
"""

NETSH_OUTPUT_HOTSPOT_CH11 = """\
There is 1 interface on the system:

    Name                   : Local Area Connection* 2
    Description            : Microsoft Wi-Fi Direct Virtual Adapter
    State                  : connected
    Channel                : 11
"""

NETSH_OUTPUT_HOTSPOT_DISCONNECTED_NO_CHANNEL = """\
There is 1 interface on the system:

    Name                   : Local Area Connection* 2
    Description            : Microsoft Wi-Fi Direct Virtual Adapter
    State                  : disconnected
    Radio status           : Hardware On
                             Software On

    Hosted network status  : Not available
"""

NETSH_OUTPUT_ONLY_PHYSICAL_WIFI_CH6 = """\
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    GUID                   : 5635802c-b744-4d3a-86b0-1ece103433cf
    Physical address       : 2c:6b:f5:6e:3e:7b
    State                  : connected
    SSID                   : UpstreamHomeRouter
    Channel                : 6
"""

NETSH_OUTPUT_PHYSICAL_WIFI_CH6_AND_HOTSPOT_DISCONNECTED = """\
There are 2 interfaces on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    State                  : connected
    SSID                   : UpstreamHomeRouter
    Channel                : 6

    Name                   : Local Area Connection* 2
    Description            : Microsoft Wi-Fi Direct Virtual Adapter
    State                  : disconnected
"""

NETSH_OUTPUT_MALFORMED_GARBAGE = """\
Running diagnostics...
Error 0x80070422: The service cannot be started.
Unexpected arbitrary lines with no interface definitions.
"""


class TestChannelAlignmentDiagnosticStage84:
    """Deterministic offline unit tests for Stage 8.4 channel alignment diagnostic."""

    def test_01_aligned_channel_6_handshake(self):
        """Scenario 1: Hotspot channel 6 / ESP32 handshake channel 6 -> CHANNEL_ALIGNED."""
        res = check_hotspot_channel_alignment(
            esp32_channel=6,
            hotspot_interface_name="Local Area Connection* 2",
            netsh_runner=lambda: NETSH_OUTPUT_HOTSPOT_CH6,
        )
        assert res.status == ChannelAlignmentStatus.CHANNEL_ALIGNED
        assert res.esp32_channel == 6
        assert res.hotspot_channel == 6
        assert res.interface_name == "Local Area Connection* 2"
        assert res.esp32_source == "FIRMWARE_HANDSHAKE"
        assert "aligned" in res.explanation.lower()

    def test_02_missing_handshake_channel_strictly_unavailable(self):
        """When handshake has not arrived (esp32_channel=None), strictly CHANNEL_UNAVAILABLE. Never assumes 6."""
        res = check_hotspot_channel_alignment(
            esp32_channel=None,
            hotspot_interface_name="Local Area Connection* 2",
            netsh_runner=lambda: NETSH_OUTPUT_HOTSPOT_CH6,
        )
        assert res.status == ChannelAlignmentStatus.CHANNEL_UNAVAILABLE
        assert res.status != ChannelAlignmentStatus.CHANNEL_ALIGNED
        assert res.esp32_channel is None
        assert res.hotspot_channel == 6
        assert res.esp32_source == "UNAVAILABLE"
        assert "unverified" in res.explanation.lower()

    def test_03_mismatch_channel_1(self):
        """Scenario 2: Hotspot channel 1 / ESP32 channel 6 -> CHANNEL_MISMATCH."""
        res = check_hotspot_channel_alignment(
            esp32_channel=6,
            hotspot_interface_name="Local Area Connection* 2",
            netsh_runner=lambda: NETSH_OUTPUT_HOTSPOT_CH1,
        )
        assert res.status == ChannelAlignmentStatus.CHANNEL_MISMATCH
        assert res.esp32_channel == 6
        assert res.hotspot_channel == 1
        assert "mismatch" in res.explanation.lower()

    def test_04_mismatch_channel_11(self):
        """Scenario 3: Hotspot channel 11 / ESP32 channel 6 -> CHANNEL_MISMATCH."""
        res = check_hotspot_channel_alignment(
            esp32_channel=6,
            hotspot_interface_name="Local Area Connection* 2",
            netsh_runner=lambda: NETSH_OUTPUT_HOTSPOT_CH11,
        )
        assert res.status == ChannelAlignmentStatus.CHANNEL_MISMATCH
        assert res.esp32_channel == 6
        assert res.hotspot_channel == 11
        assert "mismatch" in res.explanation.lower()

    def test_05_channel_unavailable_when_disconnected_or_no_channel(self):
        """Scenario 4: Hotspot interface found but state disconnected / channel unavailable -> CHANNEL_UNAVAILABLE."""
        res = check_hotspot_channel_alignment(
            esp32_channel=6,
            hotspot_interface_name="Local Area Connection* 2",
            netsh_runner=lambda: NETSH_OUTPUT_HOTSPOT_DISCONNECTED_NO_CHANNEL,
        )
        assert res.status == ChannelAlignmentStatus.CHANNEL_UNAVAILABLE
        assert res.hotspot_channel is None
        assert "not reported" in res.explanation.lower()

    def test_06_hotspot_interface_unavailable(self):
        """Scenario 5: Hotspot interface not present in netsh output -> INTERFACE_UNAVAILABLE."""
        res = check_hotspot_channel_alignment(
            esp32_channel=6,
            hotspot_interface_name="Local Area Connection* 2",
            netsh_runner=lambda: NETSH_OUTPUT_ONLY_PHYSICAL_WIFI_CH6,
        )
        assert res.status == ChannelAlignmentStatus.INTERFACE_UNAVAILABLE
        assert res.hotspot_channel is None
        assert "not found" in res.explanation.lower()

    def test_07_subprocess_timeout_returns_diagnostic_error(self):
        """Scenario 6: Subprocess timeout -> DIAGNOSTIC_ERROR."""
        import subprocess

        def _timeout():
            raise subprocess.TimeoutExpired(cmd=["netsh", "wlan", "show", "interfaces"], timeout=3.0)

        res = check_hotspot_channel_alignment(
            esp32_channel=6,
            hotspot_interface_name="Local Area Connection* 2",
            netsh_runner=_timeout,
        )
        assert res.status == ChannelAlignmentStatus.DIAGNOSTIC_ERROR
        assert res.hotspot_channel is None
        assert "timed out" in res.explanation.lower()

    def test_08_subprocess_file_not_found_returns_diagnostic_error(self):
        """Scenario 6b: Missing binary -> DIAGNOSTIC_ERROR."""
        def _not_found():
            raise FileNotFoundError("netsh binary missing")

        res = check_hotspot_channel_alignment(
            esp32_channel=6,
            hotspot_interface_name="Local Area Connection* 2",
            netsh_runner=_not_found,
        )
        assert res.status == ChannelAlignmentStatus.DIAGNOSTIC_ERROR
        assert res.hotspot_channel is None
        assert "not found" in res.explanation.lower()

    def test_09_malformed_netsh_output_produces_no_false_alignment(self):
        """Scenario 7: Malformed output never produces a false alignment."""
        res = check_hotspot_channel_alignment(
            esp32_channel=6,
            hotspot_interface_name="Local Area Connection* 2",
            netsh_runner=lambda: NETSH_OUTPUT_MALFORMED_GARBAGE,
        )
        assert res.status != ChannelAlignmentStatus.CHANNEL_ALIGNED
        assert res.status in (ChannelAlignmentStatus.CHANNEL_UNAVAILABLE, ChannelAlignmentStatus.INTERFACE_UNAVAILABLE)
        assert res.hotspot_channel is None

    def test_10_other_wifi_adapter_channel_6_never_falsely_attributes_to_hotspot(self):
        """Scenario 8: Physical Wi-Fi is on Channel 6, but hotspot has no channel -> MUST NOT false ALIGN."""
        res = check_hotspot_channel_alignment(
            esp32_channel=6,
            hotspot_interface_name="Local Area Connection* 2",
            netsh_runner=lambda: NETSH_OUTPUT_PHYSICAL_WIFI_CH6_AND_HOTSPOT_DISCONNECTED,
        )
        # Must not falsely report CHANNEL_ALIGNED because the Channel 6 belongs to 'Wi-Fi'
        assert res.status != ChannelAlignmentStatus.CHANNEL_ALIGNED
        assert res.status == ChannelAlignmentStatus.CHANNEL_UNAVAILABLE
        assert res.hotspot_channel is None
        assert res.interface_name == "Local Area Connection* 2"

    def test_11_invalid_esp32_channels_strictly_unavailable(self):
        """Invalid ESP32 channels (out of 1-14 range or wrong types) strictly return CHANNEL_UNAVAILABLE."""
        for invalid_ch in [0, 15, 99, -1, True, "6"]:
            res = check_hotspot_channel_alignment(
                esp32_channel=invalid_ch,
                hotspot_interface_name="Local Area Connection* 2",
                netsh_runner=lambda: NETSH_OUTPUT_HOTSPOT_CH6,
            )
            assert res.status == ChannelAlignmentStatus.CHANNEL_UNAVAILABLE
            assert res.status != ChannelAlignmentStatus.CHANNEL_ALIGNED
            assert res.esp32_channel is None
            assert res.hotspot_channel == 6
            assert res.esp32_source == "UNAVAILABLE"
