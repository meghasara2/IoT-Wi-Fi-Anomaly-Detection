"""
Live Interface Resolver
File: src/live_interface_resolver.py

Purpose:
  Dynamically discovers TShark-visible network interfaces and identifies
  the Windows Mobile Hotspot / Wi-Fi Direct virtual adapter candidate(s)
  for live packet capture.

Design Principles:
  - Never hardcodes an interface index. Windows Mobile Hotspot adapters
    recreate with a new index each time the hotspot is toggled.
  - Parses 'tshark -D' output to find all interfaces whose display name
    contains a recognised hotspot indicator.
  - Returns the single matching interface index without user interaction
    when exactly one candidate is found; raises an error listing all
    candidates when multiple match, so the caller can ask the operator.
  - All functions are testable with mock tshark output.
  - Raises explicit, typed exceptions instead of calling sys.exit().

Interface Index Convention:
  tshark -D numbering is 1-based.  The returned index is the integer that
  can be used directly with 'tshark -i <index>'.
"""

import enum
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# Default path confirmed operational in this project
TSHARK_DEFAULT_PATH: str = r"C:\Program Files\Wireshark\tshark.exe"

# Keywords that identify a Windows Mobile Hotspot Wi-Fi Direct adapter.
# Matching is case-insensitive and any single keyword is sufficient.
HOTSPOT_KEYWORDS: Tuple[str, ...] = (
    "local area connection*",  # Windows Mobile Hotspot virtual interface pattern
    "wi-fi direct",
    "microsoft wi-fi direct",
    "virtual adapter",
)

# Regex pattern to parse a single line of 'tshark -D' output.
# Example line:
#   1. \Device\NPF_{...} (Local Area Connection* 10)
_IFACE_LINE_RE = re.compile(
    r"^\s*(?P<index>\d+)\.\s+(?P<device>\S+)\s+\((?P<name>[^)]*)\)\s*$"
)


class TSharkNotFoundError(FileNotFoundError):
    """Raised when the tshark executable cannot be located."""


class NoHotspotInterfaceError(RuntimeError):
    """Raised when no hotspot adapter candidate is found."""


class AmbiguousHotspotInterfaceError(RuntimeError):
    """Raised when multiple hotspot adapter candidates are found."""

    def __init__(self, candidates: List[Tuple[int, str, str]]) -> None:
        self.candidates = candidates
        lines = "\n".join(
            f"  [{idx}] {name}  ({dev})"
            for idx, dev, name in candidates
        )
        super().__init__(
            f"Multiple hotspot interface candidates found. "
            f"Pass --interface <index> to select one:\n{lines}"
        )


class ChannelAlignmentStatus(str, enum.Enum):
    """Diagnostic status for Windows Mobile Hotspot and ESP32 channel alignment."""
    CHANNEL_ALIGNED = "CHANNEL_ALIGNED"
    CHANNEL_MISMATCH = "CHANNEL_MISMATCH"
    CHANNEL_UNAVAILABLE = "CHANNEL_UNAVAILABLE"
    INTERFACE_UNAVAILABLE = "INTERFACE_UNAVAILABLE"
    DIAGNOSTIC_ERROR = "DIAGNOSTIC_ERROR"


@dataclass
class ChannelDiagnosticResult:
    """
    Structured outcome of the Windows Mobile Hotspot and ESP32 channel check.
    """
    status: ChannelAlignmentStatus
    esp32_channel: Optional[int] = None
    hotspot_channel: Optional[int] = None
    interface_name: Optional[str] = None
    esp32_source: str = "UNAVAILABLE"
    run_id: Optional[int] = None
    timestamp: float = field(default_factory=time.time)
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value if isinstance(self.status, enum.Enum) else str(self.status),
            "esp32_channel": self.esp32_channel,
            "hotspot_channel": self.hotspot_channel,
            "interface_name": self.interface_name,
            "esp32_source": self.esp32_source,
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "explanation": self.explanation,
        }


def _run_tshark_list(tshark_path: str = TSHARK_DEFAULT_PATH) -> str:
    """
    Executes 'tshark -D' and returns its combined stdout+stderr as a string.

    Raises TSharkNotFoundError if the binary does not exist.
    Raises subprocess.CalledProcessError if tshark exits with a non-zero code.
    """
    tshark_bin = Path(tshark_path)
    if not tshark_bin.exists():
        raise TSharkNotFoundError(
            f"tshark executable not found at: {tshark_path}\n"
            "Install Wireshark from https://www.wireshark.org/download.html"
        )
    result = subprocess.run(
        [str(tshark_bin), "-D"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    # tshark -D exits 0 even on partial failure; combine both streams
    return result.stdout + result.stderr


def parse_interface_list(raw_output: str) -> List[Tuple[int, str, str]]:
    """
    Parses the text output of 'tshark -D' into a list of
    (index, device_path, display_name) tuples.

    Lines that do not match the expected format are silently skipped.
    This makes the function robust to banner text or permission warnings.

    Parameters
    ----------
    raw_output : str
        Combined stdout + stderr from 'tshark -D'.

    Returns
    -------
    list of (int, str, str)
        Each tuple is (1-based index, device string, display name).
    """
    interfaces: List[Tuple[int, str, str]] = []
    for line in raw_output.splitlines():
        m = _IFACE_LINE_RE.match(line)
        if m:
            idx = int(m.group("index"))
            device = m.group("device").strip()
            name = m.group("name").strip()
            interfaces.append((idx, device, name))
    return interfaces


def find_hotspot_candidates(
    interfaces: List[Tuple[int, str, str]],
    keywords: Tuple[str, ...] = HOTSPOT_KEYWORDS,
) -> List[Tuple[int, str, str]]:
    """
    Filters the interface list to those whose display name matches any
    hotspot keyword (case-insensitive substring match).

    Parameters
    ----------
    interfaces : list of (index, device, name)
    keywords : tuple of strings to match against the display name.

    Returns
    -------
    list of matching (index, device, name) tuples.
    """
    candidates: List[Tuple[int, str, str]] = []
    for idx, device, name in interfaces:
        name_lower = name.lower()
        if any(kw in name_lower for kw in keywords):
            candidates.append((idx, device, name))
    return candidates


def resolve_hotspot_interface(
    tshark_path: str = TSHARK_DEFAULT_PATH,
    override_index: Optional[int] = None,
) -> Tuple[int, str, str]:
    """
    Resolves the TShark interface index for live hotspot capture.

    If ``override_index`` is given, the function verifies it exists in the
    interface list and returns it directly without keyword matching.

    Otherwise, it runs 'tshark -D', parses the output, and looks for
    hotspot adapter candidates:
      - Exactly one candidate → returned immediately.
      - Zero candidates → raises NoHotspotInterfaceError.
      - Multiple candidates → raises AmbiguousHotspotInterfaceError
        listing all options so the caller can re-invoke with an override.

    Returns
    -------
    (index, device_path, display_name) tuple of the selected interface.

    Raises
    ------
    TSharkNotFoundError
    NoHotspotInterfaceError
    AmbiguousHotspotInterfaceError
    ValueError
        If ``override_index`` is provided but not found in the interface list.
    """
    raw = _run_tshark_list(tshark_path)
    all_ifaces = parse_interface_list(raw)

    if not all_ifaces:
        raise NoHotspotInterfaceError(
            "tshark -D returned no parseable interfaces. "
            "Ensure Npcap/WinPcap is installed and you have capture privileges."
        )

    if override_index is not None:
        for idx, dev, name in all_ifaces:
            if idx == override_index:
                return (idx, dev, name)
        available = [(i, n) for i, _, n in all_ifaces]
        raise ValueError(
            f"Override interface index {override_index} not found. "
            f"Available: {available}"
        )

    candidates = find_hotspot_candidates(all_ifaces)

    if len(candidates) == 0:
        all_names = [(i, n) for i, _, n in all_ifaces]
        raise NoHotspotInterfaceError(
            f"No hotspot adapter candidate found among {len(all_ifaces)} interfaces.\n"
            f"All interfaces: {all_names}\n"
            "Enable Windows Mobile Hotspot and retry, or specify --interface <index>."
        )

    if len(candidates) > 1:
        raise AmbiguousHotspotInterfaceError(candidates)

    return candidates[0]


def list_all_interfaces(
    tshark_path: str = TSHARK_DEFAULT_PATH,
) -> List[Tuple[int, str, str]]:
    """
    Returns all interfaces visible to tshark as a list of
    (index, device_path, display_name) tuples, for diagnostic use.

    Raises TSharkNotFoundError if the binary cannot be found.
    """
    raw = _run_tshark_list(tshark_path)
    return parse_interface_list(raw)


def format_interface_table(interfaces: List[Tuple[int, str, str]]) -> str:
    """
    Formats a list of interfaces as a human-readable table string.
    """
    if not interfaces:
        return "(no interfaces)"
    lines = ["Index  Display Name"]
    lines.append("-" * 40)
    for idx, _dev, name in interfaces:
        lines.append(f"  {idx:<5} {name}")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Windows Mobile Hotspot Wi-Fi Channel Diagnostics
# ─────────────────────────────────────────────────────────────────────────────

def _run_netsh_wlan_interfaces(timeout_sec: float = 3.0) -> str:
    """
    Executes 'netsh wlan show interfaces' using explicit arguments (shell=False).
    Returns combined stdout + stderr as a string.

    Raises FileNotFoundError if netsh executable is not found.
    Raises subprocess.TimeoutExpired if the command exceeds timeout_sec.
    """
    res = subprocess.run(
        ["netsh", "wlan", "show", "interfaces"],
        capture_output=True,
        text=True,
        timeout=timeout_sec,
        check=False,
    )
    return res.stdout + ("\n" + res.stderr if res.stderr else "")


def parse_netsh_wlan_interfaces(raw_output: str) -> List[Dict[str, Any]]:
    """
    Parses the multi-interface text output of 'netsh wlan show interfaces'
    into a list of interface dictionaries containing:
      - name: str (e.g. 'Local Area Connection* 2' or 'Wi-Fi')
      - description: str (e.g. 'Microsoft Wi-Fi Direct Virtual Adapter')
      - state: str (e.g. 'connected', 'disconnected')
      - channel: Optional[int] (e.g. 6)
      - guid: Optional[str]
      - ssid: Optional[str]

    Each interface is completely isolated to prevent attribute leakage
    (e.g. a physical Wi-Fi channel is never attributed to a virtual adapter).
    """
    interfaces: List[Dict[str, Any]] = []
    current_iface: Optional[Dict[str, Any]] = None

    for line in raw_output.splitlines():
        line_stripped = line.strip()
        if not line_stripped:
            continue

        # Look for "Name : ..." which starts a new interface block
        m_name = re.match(r"^Name\s*:\s*(.+)$", line_stripped, re.IGNORECASE)
        if m_name:
            if current_iface is not None:
                interfaces.append(current_iface)
            current_iface = {"name": m_name.group(1).strip()}
            continue

        if current_iface is not None:
            m_kv = re.match(r"^([^:]+?)\s*:\s*(.*)$", line_stripped)
            if m_kv:
                key = m_kv.group(1).strip().lower()
                val = m_kv.group(2).strip()

                if key == "description":
                    current_iface["description"] = val
                elif key == "state":
                    current_iface["state"] = val
                elif key == "ssid":
                    current_iface["ssid"] = val
                elif key == "guid":
                    current_iface["guid"] = val
                elif key == "channel":
                    m_chan = re.search(r"\b(\d+)\b", val)
                    if m_chan:
                        try:
                            current_iface["channel"] = int(m_chan.group(1))
                        except ValueError:
                            pass

    if current_iface is not None:
        interfaces.append(current_iface)

    return interfaces


def query_windows_hotspot_channel(
    target_interface_name: Optional[str] = None,
    timeout_sec: float = 3.0,
    netsh_runner: Optional[Callable[[], str]] = None,
) -> Tuple[Optional[int], Optional[str], Optional[ChannelAlignmentStatus], str]:
    """
    Queries the actual operating channel of the Windows Mobile Hotspot adapter.

    Returns:
      (channel: Optional[int], interface_name: Optional[str], error_status: Optional[ChannelAlignmentStatus], reason: str)
      If successful: (channel, interface_name, None, explanation)
      If failed: (None, interface_name_or_None, error_status, explanation)

    Strict Verification:
      - Validates that the channel belongs strictly to the hotspot virtual adapter.
      - Never confuses physical Wi-Fi adapters with the Mobile Hotspot virtual adapter.
      - Never guesses Channel 6 or falls back to an unverified default.
    """
    try:
        if netsh_runner is not None:
            raw = netsh_runner()
        else:
            raw = _run_netsh_wlan_interfaces(timeout_sec=timeout_sec)
    except FileNotFoundError:
        return (
            None,
            None,
            ChannelAlignmentStatus.DIAGNOSTIC_ERROR,
            "netsh executable was not found on this system.",
        )
    except subprocess.TimeoutExpired:
        return (
            None,
            None,
            ChannelAlignmentStatus.DIAGNOSTIC_ERROR,
            f"netsh wlan command timed out after {timeout_sec}s.",
        )
    except Exception as exc:
        return (
            None,
            None,
            ChannelAlignmentStatus.DIAGNOSTIC_ERROR,
            f"Subprocess execution error querying netsh: {exc}",
        )

    # Detect missing WLAN service / unsupported command contexts
    raw_lower = raw.lower()
    if (
        "the following command was not found" in raw_lower
        or "wlansvc) is not running" in raw_lower
        or "wireless autoconfig service" in raw_lower
        or "there is no wireless interface" in raw_lower
    ):
        return (
            None,
            None,
            ChannelAlignmentStatus.CHANNEL_UNAVAILABLE,
            "Windows WLAN AutoConfig Service (wlansvc) is unavailable or returned no interfaces.",
        )

    interfaces = parse_netsh_wlan_interfaces(raw)
    if not interfaces:
        return (
            None,
            None,
            ChannelAlignmentStatus.CHANNEL_UNAVAILABLE,
            "netsh wlan show interfaces produced no parseable interface blocks.",
        )

    # Resolve the target hotspot adapter from the parsed interface blocks
    matched_iface: Optional[Dict[str, Any]] = None

    if target_interface_name:
        target_clean = target_interface_name.strip().lower()
        # 1. Exact match
        for ifc in interfaces:
            if ifc.get("name", "").strip().lower() == target_clean:
                matched_iface = ifc
                break
        # 2. Substring match
        if matched_iface is None:
            for ifc in interfaces:
                if target_clean in ifc.get("name", "").strip().lower():
                    matched_iface = ifc
                    break

    # If target not matched by name or not specified, search by hotspot keywords
    if matched_iface is None:
        for ifc in interfaces:
            name_low = ifc.get("name", "").lower()
            desc_low = ifc.get("description", "").lower()
            # Explicitly exclude physical Wi-Fi adapters when scanning generically
            if name_low == "wi-fi" and "virtual" not in desc_low and "direct" not in desc_low:
                continue
            if any(kw in name_low for kw in HOTSPOT_KEYWORDS) or any(
                kw in desc_low for kw in HOTSPOT_KEYWORDS
            ):
                matched_iface = ifc
                break

    if matched_iface is None:
        target_display = target_interface_name or "Mobile Hotspot virtual adapter"
        return (
            None,
            None,
            ChannelAlignmentStatus.INTERFACE_UNAVAILABLE,
            f"Hotspot interface '{target_display}' not found in Windows WLAN interfaces (physical Wi-Fi ignored).",
        )

    actual_name = matched_iface.get("name", "Unknown Hotspot Adapter")
    chan = matched_iface.get("channel")

    if chan is None:
        state = matched_iface.get("state", "unknown")
        return (
            None,
            actual_name,
            ChannelAlignmentStatus.CHANNEL_UNAVAILABLE,
            f"Hotspot interface '{actual_name}' detected (state: {state}), but operating channel is not reported by Windows.",
        )

    return (
        chan,
        actual_name,
        None,
        f"Hotspot interface '{actual_name}' operating on Channel {chan}.",
    )


def check_hotspot_channel_alignment(
    esp32_channel: Optional[int] = None,
    hotspot_interface_name: Optional[str] = None,
    timeout_sec: float = 3.0,
    run_id: Optional[int] = None,
    netsh_runner: Optional[Callable[[], str]] = None,
) -> ChannelDiagnosticResult:
    """
    Evaluates whether the Windows Mobile Hotspot operating channel matches the
    ESP32 Wi-Fi sniffer channel.

    STRICT SAFETY RULE:
      - Obtains the ESP32 channel exclusively from a valid WIFI_SNIFFER_INITIALIZED handshake.
      - Never uses hardcoded Channel 6, firmware defaults, or historical logs as a fallback.
      - If esp32_channel is missing or unverified, status is strictly CHANNEL_UNAVAILABLE.
      - CHANNEL_ALIGNED is possible ONLY when both the verified ESP32 handshake channel and
        the verified Windows Mobile Hotspot channel are available and equal.

    Parameters:
      - esp32_channel: Optional[int] strictly from valid firmware sniffer handshake.
      - hotspot_interface_name: Optional[str] name of the resolved hotspot interface.
      - timeout_sec: Subprocess timeout in seconds.
      - run_id: Optional collector run ID for session freshness tracking.
      - netsh_runner: Optional callable to supply mock output for deterministic offline testing.

    Returns:
      ChannelDiagnosticResult with status, verified channels, attribution source, and explanation.
    """
    # 1. Validate ESP32 handshake channel
    verified_esp_channel: Optional[int] = None
    esp_source: str = "UNAVAILABLE"

    if (
        isinstance(esp32_channel, int)
        and not isinstance(esp32_channel, bool)
        and 1 <= esp32_channel <= 14
    ):
        verified_esp_channel = esp32_channel
        esp_source = "FIRMWARE_HANDSHAKE"

    # 2. Query Windows Mobile Hotspot channel
    hotspot_chan, iface_name, err_status, reason = query_windows_hotspot_channel(
        target_interface_name=hotspot_interface_name,
        timeout_sec=timeout_sec,
        netsh_runner=netsh_runner,
    )

    # 3. Handle query errors/unavailability from Windows
    if err_status is not None:
        return ChannelDiagnosticResult(
            status=err_status,
            esp32_channel=verified_esp_channel,
            hotspot_channel=None,
            interface_name=iface_name,
            esp32_source=esp_source,
            run_id=run_id,
            explanation=reason,
        )

    # 4. Handle unavailable ESP32 sniffer channel (handshake not yet received or invalid)
    if verified_esp_channel is None:
        return ChannelDiagnosticResult(
            status=ChannelAlignmentStatus.CHANNEL_UNAVAILABLE,
            esp32_channel=None,
            hotspot_channel=hotspot_chan,
            interface_name=iface_name,
            esp32_source=esp_source,
            run_id=run_id,
            explanation=(
                f"ESP32 sniffer channel is unverified: requires valid WIFI_SNIFFER_INITIALIZED handshake. "
                f"Windows hotspot operates on Channel {hotspot_chan}. Channel 6 is not assumed."
            ),
        )

    # 5. Evaluate alignment strictly against verified channels
    if hotspot_chan == verified_esp_channel:
        return ChannelDiagnosticResult(
            status=ChannelAlignmentStatus.CHANNEL_ALIGNED,
            esp32_channel=verified_esp_channel,
            hotspot_channel=hotspot_chan,
            interface_name=iface_name,
            esp32_source=esp_source,
            run_id=run_id,
            explanation=f"Windows hotspot '{iface_name}' is confirmed aligned with ESP32 sniffer hardware on Channel {verified_esp_channel}.",
        )
    else:
        return ChannelDiagnosticResult(
            status=ChannelAlignmentStatus.CHANNEL_MISMATCH,
            esp32_channel=verified_esp_channel,
            hotspot_channel=hotspot_chan,
            interface_name=iface_name,
            esp32_source=esp_source,
            run_id=run_id,
            explanation=(
                f"CHANNEL MISMATCH: Windows hotspot '{iface_name}' is on Channel {hotspot_chan}, "
                f"but ESP32 sniffer hardware is configured for Channel {verified_esp_channel}. "
                f"Promiscuous 802.11 management packet capture will be severely degraded."
            ),
        )
