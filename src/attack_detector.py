"""
Network Attack Detection Engine
File: src/attack_detector.py

Purpose:
  Provides explainable, evidence-backed detection logic for five distinct
  network attack categories, resolving academic ambiguity between statistical
  traffic features (packet rate, packet size, timing jitter) and verified security threats:
    1. Denial-of-Service (DoS)
    2. Reconnaissance / Port Scanning
    3. Spoofing / Impersonation
    4. Wi-Fi Deauthentication / Disassociation Abuse
    5. Replay Attack

Design Philosophy & Scientific Constraints:
  - Explainable Evidence: Every detection decision produces an explicit structured
    evidence dictionary, confidence rating, and list of missing telemetry fields.
  - Telemetry Honesty: If required protocol headers (e.g., transport ports, 802.11
    management frames, protocol sequence nonces) are absent from the capture stream,
    the engine reports INSUFFICIENT_TELEMETRY rather than fabricating results or
    generating false alarms.
  - Strict Defense Separation: Suspicious indicators are strictly separated from
    confirmed threats. Passive monitors suggest operator investigation, NEVER
    automatic blocking or disruptive deauthentication.
  - RSSI Integrity: RSSI is treated as a physical signal measurement in dBm,
    never synthesized, estimated, or conflated with zero.
"""

from __future__ import annotations

import enum
import ipaddress
import math
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# =============================================================================
# Network Environment Configuration Defaults
# =============================================================================

DEFAULT_HOTSPOT_SUBNET: str = "192.168.137.0/24"
DEFAULT_GATEWAY_IP: str = "192.168.137.1"


# =============================================================================
# Core Enumerations
# =============================================================================

class AttackCategory(str, enum.Enum):
    """The five distinct attack categories addressed by this security engine."""
    DOS = "Denial_of_Service"
    PORT_SCAN = "Reconnaissance_Port_Scan"
    SPOOFING = "Spoofing_Impersonation"
    DEAUTH_FLOOD = "Deauthentication_Disassociation_Abuse"
    REPLAY = "Replay_Attack"


class DetectionStatus(str, enum.Enum):
    """
    Status of detection evaluation.

    NO_EVIDENCE:
      Sufficient telemetry was inspected; no indicators of attack found.
    INSUFFICIENT_TELEMETRY:
      Required packet/frame fields are absent from the capture pipeline;
      the attack hypothesis cannot mathematically or logically be evaluated.
    SUSPICIOUS:
      Corroborated heuristic evidence observed exceeding baseline thresholds;
      warrants operator review.
    CONFIRMED_THREAT:
      Irrefutable, cryptographically or deterministically proven attack signature
      (reserved strictly for conclusive protocol violations).
    """
    NO_EVIDENCE = "NO_EVIDENCE"
    INSUFFICIENT_TELEMETRY = "INSUFFICIENT_TELEMETRY"
    SUSPICIOUS = "SUSPICIOUS"
    CONFIRMED_THREAT = "CONFIRMED_THREAT"


class Severity(str, enum.Enum):
    """Standardized alert severity levels."""
    NONE = "NONE"
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# =============================================================================
# Telemetry Input Schemas
# =============================================================================

@dataclass
class PacketObservation:
    """
    Fine-grained per-packet observation.

    Base fields represent data currently extracted by the live TShark stream.
    Extended fields represent transport, 802.11, and cryptographic attributes
    required for comprehensive attack detection.
    """
    timestamp: float
    packet_size: int
    eth_src: str
    eth_dst: str
    ip_src: Optional[str] = None
    ip_dst: Optional[str] = None
    protocol: Optional[str] = None

    # Extended transport layer fields (required for Port Scanning / Replay)
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None

    # Extended 802.11 management fields (required for Deauth / Disassoc)
    wlan_fc_type_subtype: Optional[int] = None   # 10 = Disassoc, 12 = Deauth
    wlan_reason_code: Optional[int] = None       # IEEE 802.11 reason code
    wlan_bssid: Optional[str] = None

    # Extended replay / crypto verification fields (required for Replay)
    protocol_seq_num: Optional[int] = None       # TCP seq or CCMP PN
    payload_hash: Optional[str] = None           # SHA256 / MD5 of payload
    nonce: Optional[str] = None

    # Optional physical layer signal
    rssi_dbm: Optional[float] = None             # Physical signal in dBm; None if unavailable


@dataclass
class WindowTrafficObservation:
    """
    Aggregated 1-second time window observation per network client node.
    Directly compatible with the live streaming feature extractor schema.
    """
    bin_start_epoch: float
    node_id: str
    mac_address: str
    packet_count: int
    packet_rate: float
    total_bytes: int
    mean_packet_size: Optional[float] = None
    ip_src: Optional[str] = None
    ip_dst: Optional[str] = None
    packets: Optional[List[PacketObservation]] = None


# =============================================================================
# Detection Output Schema
# =============================================================================

@dataclass
class AttackDetectionResult:
    """
    Structured, explainable evaluation output returned by each detector.
    """
    category: AttackCategory
    status: DetectionStatus
    severity: Severity
    evidence: Dict[str, Any]
    missing_fields: List[str]
    confidence: float
    timestamp: float
    recommended_action: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.value,
            "status": self.status.value,
            "severity": self.severity.value,
            "evidence": self.evidence,
            "missing_fields": self.missing_fields,
            "confidence": round(self.confidence, 4),
            "timestamp": self.timestamp,
            "recommended_action": self.recommended_action,
        }


# =============================================================================
# RSSI Management & Validation Module
# =============================================================================

@dataclass
class RSSIMeasurement:
    """
    Explicit physical Wi-Fi signal measurement.

    Academic Principle:
      RSSI (Received Signal Strength Indicator) is measured in negative dBm
      (typically -30 dBm for near-field down to -95 dBm at sensitivity edge).
      0 dBm represents 1 milliwatt of power, which is physically impossible
      for normal ambient IoT reception and usually indicates a software bug.
      Missing RSSI MUST be represented as None, never 0.0 or synthetic approximations.
    """
    source_mac: str
    rssi_dbm: float
    timestamp: float
    capture_interface: str

    @classmethod
    def validate(cls, value: Optional[float]) -> Optional[float]:
        """
        Validates whether a raw float is a physically plausible RSSI in dBm.
        Returns None if missing, NaN, or non-physical (e.g., 0.0 or > 0.0).
        """
        if value is None:
            return None
        if not isinstance(value, (int, float)):
            return None
        if math.isnan(value) or math.isinf(value):
            return None
        # Strict physical filter: 0.0 dBm is almost always uninitialized data
        if value >= 0.0 or value < -110.0:
            return None
        return float(value)


# =============================================================================
# 1. Denial-of-Service (DoS) Detector
# =============================================================================

class DoSDetector:
    """
    Detects targeted Denial-of-Service (DoS) attacks.

    Detection Logic:
      1. Sustained Duration: Requires high traffic volume across multiple consecutive
         time windows (min_consecutive_windows >= 3). A single 1-second burst is
         classified as a transient surge, NOT a DoS attack.
      2. Target Focus: Verifies that the offending source is disproportionately
         targeting a specific destination IP / service, rather than distributing traffic.
      3. Fleet-Wide Surge Discrimination: Compares the suspect device against the fleet
         of all active network devices. If a majority of devices (e.g., >= 50%) experience
         a simultaneous surge (such as a classroom exam, video broadcast, or synchronized
         cloud sync), the event is classified as a legitimate network surge, NOT a DoS.
    """

    def __init__(
        self,
        rate_threshold_pps: float = 60.0,
        min_consecutive_windows: int = 3,
        target_concentration_ratio: float = 0.75,
        fleet_surge_threshold: float = 0.50,
        local_subnet: str = DEFAULT_HOTSPOT_SUBNET,
        gateway_ip: str = DEFAULT_GATEWAY_IP,
    ):
        self.rate_threshold_pps = rate_threshold_pps
        self.min_consecutive_windows = min_consecutive_windows
        self.target_concentration_ratio = target_concentration_ratio
        self.fleet_surge_threshold = fleet_surge_threshold
        self.local_subnet_str = local_subnet
        self.gateway_ip = gateway_ip.strip()
        self._local_network = self._parse_subnet(local_subnet)

        # Sliding window state: mac -> list of (timestamp, packet_rate, ip_dst, bytes)
        self._history: Dict[str, List[Tuple[float, float, Optional[str], int]]] = {}

    def set_local_subnet(self, subnet_str: str) -> None:
        """Configures or updates the monitored local subnet."""
        self.local_subnet_str = subnet_str
        self._local_network = self._parse_subnet(subnet_str)

    def set_gateway_ip(self, gateway_ip: str) -> None:
        """Configures or updates the verified gateway IP address."""
        self.gateway_ip = gateway_ip.strip()

    @staticmethod
    def _parse_subnet(subnet_str: str) -> ipaddress.IPv4Network:
        """Parses a CIDR string or dotted prefix into an IPv4Network."""
        cleaned = subnet_str.strip()
        try:
            return ipaddress.ip_network(cleaned, strict=False)
        except ValueError:
            prefix = cleaned.rstrip(".")
            parts = prefix.split(".")
            while len(parts) < 4:
                parts.append("0")
            return ipaddress.ip_network(f"{'.'.join(parts)}/24", strict=False)

    def is_local_target(self, ip_str: Optional[str]) -> bool:
        """
        Returns True if the destination IP address targets local infrastructure
        (the gateway IP, or a unicast host within the local LAN subnet).
        """
        if not ip_str:
            return False
        cleaned = ip_str.strip()
        if cleaned == self.gateway_ip:
            return True
        try:
            addr = ipaddress.ip_address(cleaned)
            if addr.version != 4:
                return False
            if addr in self._local_network:
                return not (
                    addr.is_multicast
                    or addr == self._local_network.broadcast_address
                    or addr == self._local_network.network_address
                )
            return False
        except ValueError:
            return False

    def reset(self) -> None:
        self._history.clear()

    def evaluate(
        self,
        target_window: WindowTrafficObservation,
        fleet_windows: Optional[List[WindowTrafficObservation]] = None,
    ) -> AttackDetectionResult:
        missing_fields: List[str] = []
        now = target_window.bin_start_epoch

        if target_window.packet_rate is None or math.isnan(target_window.packet_rate):
            missing_fields.append("packet_rate")
        if not target_window.mac_address:
            missing_fields.append("mac_address")

        if missing_fields:
            return AttackDetectionResult(
                category=AttackCategory.DOS,
                status=DetectionStatus.INSUFFICIENT_TELEMETRY,
                severity=Severity.NONE,
                evidence={"reason": "Missing required window rate or MAC identifiers"},
                missing_fields=missing_fields,
                confidence=0.0,
                timestamp=now,
                recommended_action="Ensure live extractor records complete epoch window metrics.",
            )

        mac = target_window.mac_address
        current_rate = float(target_window.packet_rate)

        # Update per-node history
        if mac not in self._history:
            self._history[mac] = []
        self._history[mac].append((
            now,
            current_rate,
            target_window.ip_dst,
            target_window.total_bytes,
        ))

        # Keep history bounded (last 10 windows)
        if len(self._history[mac]) > 10:
            self._history[mac] = self._history[mac][-10:]

        # Prune stale MAC entries older than 300 seconds to prevent unbounded memory growth
        stale_macs = [
            m for m, hist in self._history.items()
            if not hist or (now - hist[-1][0] > 300.0)
        ]
        for m in stale_macs:
            del self._history[m]

        # Check fleet-wide surge: Are other devices surging simultaneously?
        # A legitimate multi-device fleet surge requires at least 2 distinct devices surging concurrently.
        if fleet_windows and len(fleet_windows) > 1:
            surging_devices = sum(
                1 for w in fleet_windows
                if w.packet_rate is not None and w.packet_rate >= self.rate_threshold_pps
            )
            fleet_ratio = surging_devices / len(fleet_windows)
            if surging_devices >= 2 and fleet_ratio >= self.fleet_surge_threshold:
                return AttackDetectionResult(
                    category=AttackCategory.DOS,
                    status=DetectionStatus.NO_EVIDENCE,
                    severity=Severity.INFO,
                    evidence={
                        "verdict": "Legitimate network-wide surge",
                        "surging_devices": surging_devices,
                        "total_active_devices": len(fleet_windows),
                        "fleet_ratio": round(fleet_ratio, 3),
                        "explanation": "Simultaneous traffic surge observed across multiple devices (e.g. classroom/exam scenario). Not an isolated DoS.",
                    },
                    missing_fields=[],
                    confidence=0.2,
                    timestamp=now,
                    recommended_action="Monitor overall network bandwidth consumption.",
                )

        # Check single-window burst vs sustained
        recent = self._history[mac]
        consecutive_high = 0
        target_counts: Dict[str, int] = {}

        for entry in reversed(recent):
            _, rate, dst, _ = entry
            if rate >= self.rate_threshold_pps:
                consecutive_high += 1
                if dst:
                    target_counts[dst] = target_counts.get(dst, 0) + 1
            else:
                break

        if consecutive_high < self.min_consecutive_windows:
            # Below sustained threshold: transient burst
            if current_rate >= self.rate_threshold_pps:
                return AttackDetectionResult(
                    category=AttackCategory.DOS,
                    status=DetectionStatus.NO_EVIDENCE,
                    severity=Severity.INFO,
                    evidence={
                        "verdict": "Transient packet burst",
                        "current_rate": current_rate,
                        "rate_threshold": self.rate_threshold_pps,
                        "consecutive_windows": consecutive_high,
                        "min_required_windows": self.min_consecutive_windows,
                        "explanation": "Isolated traffic surge within tolerance; insufficient duration to classify as DoS.",
                    },
                    missing_fields=[],
                    confidence=0.1,
                    timestamp=now,
                    recommended_action="Observe subsequent windows for sustained pattern.",
                )
            return AttackDetectionResult(
                category=AttackCategory.DOS,
                status=DetectionStatus.NO_EVIDENCE,
                severity=Severity.NONE,
                evidence={
                    "verdict": "Normal traffic volume",
                    "current_rate": current_rate,
                    "rate_threshold": self.rate_threshold_pps,
                },
                missing_fields=[],
                confidence=0.0,
                timestamp=now,
                recommended_action="Normal monitoring.",
            )

        # Sustained high rate verified: check target concentration
        total_high_windows = consecutive_high
        most_targeted_ip = None
        concentration = 0.0
        if target_counts:
            most_targeted_ip, count = max(target_counts.items(), key=lambda x: x[1])
            concentration = count / total_high_windows

        # Check for missing destination IP telemetry
        if not most_targeted_ip:
            return AttackDetectionResult(
                category=AttackCategory.DOS,
                status=DetectionStatus.INSUFFICIENT_TELEMETRY,
                severity=Severity.NONE,
                evidence={
                    "reason": "Missing destination IP address in traffic observation; cannot evaluate target focus.",
                    "current_rate_pps": current_rate,
                    "consecutive_windows": consecutive_high,
                },
                missing_fields=["ip_dst"],
                confidence=0.0,
                timestamp=now,
                recommended_action="Ensure capture pipeline extracts IP layer destination headers.",
            )

        # Check target destination scope: Is this a local infrastructure flood or outbound WAN streaming?
        is_local = self.is_local_target(most_targeted_ip)

        if not is_local:
            # Outbound application streaming / data transfer (e.g. Meta CDN, YouTube, video conferencing)
            # Normal mobile hotspot clients streaming video or uploading media generate 100-300 PPS to external WAN servers.
            # This does not constitute a DoS attack on local hotspot or IoT infrastructure.
            return AttackDetectionResult(
                category=AttackCategory.DOS,
                status=DetectionStatus.NO_EVIDENCE,
                severity=Severity.INFO,
                evidence={
                    "verdict": "Outbound application transfer (WAN)",
                    "current_rate_pps": current_rate,
                    "consecutive_windows": consecutive_high,
                    "target_ip": most_targeted_ip,
                    "target_concentration": round(concentration, 3),
                    "destination_scope": "WAN / Internet",
                    "explanation": (
                        f"Source {mac} sustained {current_rate:.1f} pps over {consecutive_high} consecutive seconds "
                        f"destined for external WAN host {most_targeted_ip} (e.g. media streaming, CDN transfer); "
                        f"does not target local hotspot or IoT infrastructure."
                    ),
                },
                missing_fields=[],
                confidence=0.0,
                timestamp=now,
                recommended_action="Normal monitoring.",
            )

        # Target is on the local LAN: verify target concentration
        if concentration < self.target_concentration_ratio:
            # Distributed across multiple local hosts without focusing on one
            return AttackDetectionResult(
                category=AttackCategory.DOS,
                status=DetectionStatus.NO_EVIDENCE,
                severity=Severity.INFO,
                evidence={
                    "verdict": "Distributed local traffic volume",
                    "current_rate_pps": current_rate,
                    "consecutive_windows": consecutive_high,
                    "target_ip": most_targeted_ip,
                    "target_concentration": round(concentration, 3),
                    "destination_scope": f"LAN ({self.local_subnet_str})",
                    "explanation": (
                        f"Source {mac} sustained {current_rate:.1f} pps distributed across local hosts; "
                        f"target concentration ({concentration:.1%}) below threshold ({self.target_concentration_ratio:.1%})."
                    ),
                },
                missing_fields=[],
                confidence=0.1,
                timestamp=now,
                recommended_action="Observe traffic distribution across local devices.",
            )

        # Sustained local flood against local infrastructure (gateway or local IoT node)
        confidence = min(0.95, 0.60 + 0.10 * (consecutive_high - self.min_consecutive_windows) + 0.20 * concentration)

        evidence = {
            "verdict": "Sustained local infrastructure flood",
            "consecutive_windows": consecutive_high,
            "current_rate_pps": current_rate,
            "rate_threshold_pps": self.rate_threshold_pps,
            "target_ip": most_targeted_ip,
            "target_concentration": round(concentration, 3),
            "destination_scope": f"LAN ({self.local_subnet_str})",
            "explanation": (
                f"Source {mac} sustained {current_rate:.1f} pps over {consecutive_high} consecutive seconds "
                f"targeting local infrastructure host {most_targeted_ip} (concentration: {concentration:.1%})."
            ),
        }

        return AttackDetectionResult(
            category=AttackCategory.DOS,
            status=DetectionStatus.SUSPICIOUS,
            severity=Severity.HIGH if consecutive_high >= 5 else Severity.MEDIUM,
            evidence=evidence,
            missing_fields=[],
            confidence=confidence,
            timestamp=now,
            recommended_action=f"Inspect destination host {most_targeted_ip} for service degradation. Do NOT automatically disconnect client.",
        )


# =============================================================================
# 2. Reconnaissance / Port Scanning Detector
# =============================================================================

def _is_tcp_syn_no_ack(tcp_flags: Optional[str]) -> bool:
    """
    Determines whether a TCP packet has the SYN flag set without the ACK flag.
    Handles both hex strings (e.g. '0x0002', '0x02'), integer strings (e.g. '2'),
    and descriptive flag strings (e.g. 'SYN', 'SYN, ACK', 'ACK').
    """
    if not tcp_flags:
        return False
    val_str = tcp_flags.strip()
    try:
        if val_str.lower().startswith("0x"):
            val = int(val_str, 16)
        elif val_str.isdigit():
            val = int(val_str)
        else:
            val = None
        if val is not None:
            is_syn = bool(val & 0x02)
            is_ack = bool(val & 0x10)
            return is_syn and not is_ack
    except (ValueError, TypeError):
        pass
    upper = val_str.upper()
    return "SYN" in upper and "ACK" not in upper


def _is_tcp_established_or_ack(tcp_flags: Optional[str]) -> bool:
    """
    Determines whether a TCP packet has the ACK flag set (established traffic).
    """
    if not tcp_flags:
        return False
    val_str = tcp_flags.strip()
    try:
        if val_str.lower().startswith("0x"):
            val = int(val_str, 16)
        elif val_str.isdigit():
            val = int(val_str)
        else:
            val = None
        if val is not None:
            return bool(val & 0x10)
    except (ValueError, TypeError):
        pass
    upper = val_str.upper()
    return "ACK" in upper


@dataclass
class _ScanRecord:
    timestamp: float
    dst_ip: str
    dst_port: int
    protocol: str
    tcp_flags: Optional[str]
    src_mac: Optional[str] = None


class PortScanDetector:
    """
    Detects network reconnaissance and port scanning behavior.

    Detection Logic:
      - Vertical Scan: A single source probes multiple distinct non-infrastructure
        destination ports on a single local destination host within a sliding
        observation window, requiring connection-attempt evidence (e.g., TCP SYN
        without ACK, or repeated UDP probes).
      - Horizontal Sweep: A single source probes the SAME destination port across
        multiple distinct destination hosts within the configured local LAN subnet
        (e.g., 192.168.137.0/24), requiring connection-attempt evidence.
      - Strobe Scan: Multiple ports across multiple hosts simultaneously.

    False-Positive Safeguards:
      - Normal Infrastructure Exclusion: Normal infrastructure discovery/service
        ports (DNS: 53, DHCP: 67/68, SSDP: 1900, mDNS: 5353, LLMNR: 5355, NTP: 123,
        NetBIOS: 137/138, WS-Discovery: 3702) are excluded from scanning alerts.
      - Scope Isolation: Horizontal sweeps are restricted to the local LAN subnet.
        Outbound browsing contacting multiple public WAN hosts is NOT classified
        as a horizontal sweep.
      - Established TCP Protection: Normal established TCP traffic (packets with
        ACK/PSH flags) is excluded from scan counting.
      - UDP Separation: UDP scanning does not expect SYN flags, but requires
        repeated probes on the same port across multiple local hosts.
      - Telemetry Honesty: If transport ports are missing, reports INSUFFICIENT_TELEMETRY.
        If connection flags are absent, does NOT speculate or invent evidence.
    """

    DEFAULT_INFRASTRUCTURE_PORTS: Set[int] = {
        53,    # DNS
        67,    # DHCP Server
        68,    # DHCP Client
        123,   # NTP / Network Time
        137,   # NetBIOS Name Service
        138,   # NetBIOS Datagram Service
        139,   # NetBIOS Session Service
        1900,  # SSDP / UPnP
        3702,  # WS-Discovery
        5353,  # mDNS (Multicast DNS)
        5355,  # LLMNR (Link-Local Multicast Name Resolution)
    }

    def __init__(
        self,
        vertical_port_threshold: int = 8,
        horizontal_host_threshold: int = 5,
        window_duration_seconds: float = 5.0,
        local_subnet: str = DEFAULT_HOTSPOT_SUBNET,
        infrastructure_ports: Optional[Set[int]] = None,
    ):
        self.vertical_port_threshold = vertical_port_threshold
        self.horizontal_host_threshold = horizontal_host_threshold
        self.window_duration_seconds = window_duration_seconds
        self.local_subnet_str = local_subnet
        self.infrastructure_ports = (
            set(infrastructure_ports) if infrastructure_ports is not None else set(self.DEFAULT_INFRASTRUCTURE_PORTS)
        )
        self._local_network = self._parse_subnet(local_subnet)

        # State: src_ip -> list of _ScanRecord
        self._history: Dict[str, List[_ScanRecord]] = {}

    def set_local_subnet(self, subnet_str: str) -> None:
        """Configures or updates the monitored local subnet."""
        self.local_subnet_str = subnet_str
        self._local_network = self._parse_subnet(subnet_str)

    @staticmethod
    def _parse_subnet(subnet_str: str) -> ipaddress.IPv4Network:
        """Parses a CIDR string or dotted prefix into an IPv4Network."""
        cleaned = subnet_str.strip()
        try:
            return ipaddress.ip_network(cleaned, strict=False)
        except ValueError:
            prefix = cleaned.rstrip(".")
            parts = prefix.split(".")
            while len(parts) < 4:
                parts.append("0")
            return ipaddress.ip_network(f"{'.'.join(parts)}/24", strict=False)

    def is_local_unicast_ip(self, ip_str: Optional[str]) -> bool:
        """
        Returns True if the IP address belongs to the local subnet and is a
        valid unicast host address (not broadcast, multicast, or network address).
        """
        if not ip_str:
            return False
        try:
            addr = ipaddress.ip_address(ip_str.strip())
            if addr.version != 4:
                return False
            if addr in self._local_network:
                if (
                    addr.is_multicast
                    or addr == self._local_network.broadcast_address
                    or addr == self._local_network.network_address
                ):
                    return False
                return True
            return False
        except ValueError:
            return False

    def reset(self) -> None:
        self._history.clear()

    def evaluate(self, packets: List[PacketObservation]) -> AttackDetectionResult:
        if not packets:
            return AttackDetectionResult(
                category=AttackCategory.PORT_SCAN,
                status=DetectionStatus.NO_EVIDENCE,
                severity=Severity.NONE,
                evidence={"reason": "No packets provided in observation window"},
                missing_fields=[],
                confidence=0.0,
                timestamp=time.time(),
                recommended_action="Normal monitoring.",
            )

        now = max(p.timestamp for p in packets)

        # Check if transport layer fields are present in the packet batch
        packets_with_ports = [p for p in packets if p.dst_port is not None and p.ip_src is not None]

        if not packets_with_ports:
            return AttackDetectionResult(
                category=AttackCategory.PORT_SCAN,
                status=DetectionStatus.INSUFFICIENT_TELEMETRY,
                severity=Severity.NONE,
                evidence={
                    "reason": "Capture stream lacks transport layer port metadata (dst_port, src_port, tcp_flags).",
                    "packets_inspected": len(packets),
                    "protocol_column": list(set(p.protocol for p in packets if p.protocol)),
                },
                missing_fields=["dst_port", "src_port", "tcp_flags"],
                confidence=0.0,
                timestamp=now,
                recommended_action="Enable transport port extraction in TShark (-e tcp.dstport -e udp.dstport).",
            )

        # Ingest packets into state
        for p in packets_with_ports:
            src = p.ip_src.strip()
            if src not in self._history:
                self._history[src] = []
            self._history[src].append(_ScanRecord(
                timestamp=p.timestamp,
                dst_ip=p.ip_dst.strip() if p.ip_dst else "unknown",
                dst_port=int(p.dst_port),
                protocol=(p.protocol or "UNKNOWN").upper().strip(),
                tcp_flags=p.tcp_flags,
                src_mac=p.eth_src.strip().lower() if p.eth_src else None,
            ))

        # Prune inactive sources to avoid memory and iteration leaks
        for src in list(self._history.keys()):
            active_records = [r for r in self._history[src] if now - r.timestamp <= self.window_duration_seconds]
            if not active_records:
                del self._history[src]
            else:
                self._history[src] = active_records

        # Evaluate each active source in the current window
        findings = []
        for src, active_records in self._history.items():

            # Identify primary source MAC if available
            source_mac = None
            for r in reversed(active_records):
                if r.src_mac:
                    source_mac = r.src_mac
                    break

            # -------------------------------------------------------------
            # Vertical Scan Evaluation (per local destination host)
            # -------------------------------------------------------------
            vertical_targets: Dict[str, Dict[str, Any]] = {}
            local_recs_by_dst: Dict[str, List[_ScanRecord]] = {}
            for r in active_records:
                if self.is_local_unicast_ip(r.dst_ip) and r.dst_ip != src:
                    if r.dst_ip not in local_recs_by_dst:
                        local_recs_by_dst[r.dst_ip] = []
                    local_recs_by_dst[r.dst_ip].append(r)

            for dst_ip, dst_recs in local_recs_by_dst.items():
                tcp_syn_ports: Set[int] = set()
                tcp_syn_probes = 0
                udp_probed_ports: Set[int] = set()
                udp_probes = 0

                for r in dst_recs:
                    if r.dst_port in self.infrastructure_ports:
                        continue

                    is_tcp = ("TCP" in r.protocol) or (r.tcp_flags is not None)
                    if is_tcp:
                        if _is_tcp_syn_no_ack(r.tcp_flags):
                            tcp_syn_ports.add(r.dst_port)
                            tcp_syn_probes += 1
                    elif "UDP" in r.protocol or r.protocol in ("UNKNOWN", ""):
                        udp_probed_ports.add(r.dst_port)
                        udp_probes += 1

                probed_ports = tcp_syn_ports | udp_probed_ports
                if len(probed_ports) >= self.vertical_port_threshold:
                    vertical_targets[dst_ip] = {
                        "probed_ports": probed_ports,
                        "tcp_syn_ports": tcp_syn_ports,
                        "tcp_syn_probes": tcp_syn_probes,
                        "udp_ports": udp_probed_ports,
                        "udp_probes": udp_probes,
                    }

            # -------------------------------------------------------------
            # Horizontal Sweep Evaluation (per destination port across LAN)
            # -------------------------------------------------------------
            horizontal_ports: Dict[int, Dict[str, Any]] = {}
            local_recs_by_port: Dict[int, List[_ScanRecord]] = {}
            for r in active_records:
                if self.is_local_unicast_ip(r.dst_ip) and r.dst_ip != src:
                    if r.dst_port not in self.infrastructure_ports:
                        if r.dst_port not in local_recs_by_port:
                            local_recs_by_port[r.dst_port] = []
                        local_recs_by_port[r.dst_port].append(r)

            for port, port_recs in local_recs_by_port.items():
                tcp_syn_hosts: Set[str] = set()
                tcp_syn_probes = 0
                udp_hosts: Set[str] = set()
                udp_probes = 0

                for r in port_recs:
                    is_tcp = ("TCP" in r.protocol) or (r.tcp_flags is not None)
                    if is_tcp:
                        if _is_tcp_syn_no_ack(r.tcp_flags):
                            tcp_syn_hosts.add(r.dst_ip)
                            tcp_syn_probes += 1
                    elif "UDP" in r.protocol or r.protocol in ("UNKNOWN", ""):
                        udp_hosts.add(r.dst_ip)
                        udp_probes += 1

                is_tcp_sweep = (
                    len(tcp_syn_hosts) >= self.horizontal_host_threshold
                    and tcp_syn_probes >= self.horizontal_host_threshold
                )
                is_udp_sweep = (
                    len(udp_hosts) >= self.horizontal_host_threshold
                    and udp_probes >= self.horizontal_host_threshold
                )

                if is_tcp_sweep or is_udp_sweep:
                    swept_hosts = tcp_syn_hosts if is_tcp_sweep else udp_hosts
                    horizontal_ports[port] = {
                        "hosts": swept_hosts,
                        "is_tcp": is_tcp_sweep,
                        "is_udp": is_udp_sweep,
                        "tcp_syn_count": tcp_syn_probes,
                        "udp_probe_count": udp_probes,
                    }

            # -------------------------------------------------------------
            # Compile Structured Finding for This Source
            # -------------------------------------------------------------
            is_vertical = len(vertical_targets) > 0
            is_horizontal = len(horizontal_ports) > 0

            if is_vertical or is_horizontal:
                all_flagged_ports: Set[int] = set()
                all_flagged_hosts: Set[str] = set()
                total_syn_count = 0
                total_udp_count = 0
                reasons = []

                if is_vertical:
                    for v_dst, v_info in vertical_targets.items():
                        all_flagged_hosts.add(v_dst)
                        all_flagged_ports.update(v_info["probed_ports"])
                        total_syn_count += v_info["tcp_syn_probes"]
                        total_udp_count += v_info["udp_probes"]
                        reasons.append(
                            f"Vertical scan: {len(v_info['probed_ports'])} ports probed on local host {v_dst} "
                            f"({v_info['tcp_syn_probes']} TCP SYN, {v_info['udp_probes']} UDP)"
                        )

                if is_horizontal:
                    for h_port, h_info in horizontal_ports.items():
                        all_flagged_ports.add(h_port)
                        all_flagged_hosts.update(h_info["hosts"])
                        total_syn_count += h_info["tcp_syn_count"]
                        total_udp_count += h_info["udp_probe_count"]
                        proto_str = "TCP SYN" if h_info["is_tcp"] else "UDP"
                        reasons.append(
                            f"Horizontal sweep: Port {h_port} probed across {len(h_info['hosts'])} local hosts "
                            f"({h_info['tcp_syn_count'] + h_info['udp_probe_count']} {proto_str} probes)"
                        )

                total_probes = total_syn_count + total_udp_count
                detection_reason = "; ".join(reasons)

                findings.append({
                    "src_ip": src,
                    "source_mac": source_mac,
                    "destination_scope": f"LAN ({self.local_subnet_str})",
                    "distinct_ports_count": len(all_flagged_ports),
                    "sample_ports": sorted(list(all_flagged_ports))[:10],
                    "distinct_hosts_count": len(all_flagged_hosts),
                    "sample_hosts": sorted(list(all_flagged_hosts))[:5],
                    "probe_counts": total_probes,
                    "tcp_syn_count": total_syn_count,
                    "syn_flag_count": total_syn_count,  # Backwards compatibility
                    "udp_probe_count": total_udp_count,
                    "detection_reason": detection_reason,
                    "is_vertical_scan": is_vertical,
                    "is_horizontal_sweep": is_horizontal,
                })

        if not findings:
            return AttackDetectionResult(
                category=AttackCategory.PORT_SCAN,
                status=DetectionStatus.NO_EVIDENCE,
                severity=Severity.NONE,
                evidence={
                    "verdict": "Normal transport diversity",
                    "inspected_sources": len(self._history),
                    "destination_scope": f"LAN ({self.local_subnet_str})",
                },
                missing_fields=[],
                confidence=0.0,
                timestamp=now,
                recommended_action="Normal monitoring.",
            )

        # Suspicious scanning activity detected
        primary = findings[0]
        severity = Severity.HIGH if (primary["is_vertical_scan"] and primary["is_horizontal_sweep"]) else Severity.MEDIUM
        confidence = min(0.92, 0.65 + 0.05 * min(10, primary["distinct_ports_count"] if primary["is_vertical_scan"] else primary["distinct_hosts_count"]))

        return AttackDetectionResult(
            category=AttackCategory.PORT_SCAN,
            status=DetectionStatus.SUSPICIOUS,
            severity=severity,
            evidence={
                "verdict": "Reconnaissance / scanning pattern observed",
                "details": findings,
                "destination_scope": f"LAN ({self.local_subnet_str})",
            },
            missing_fields=[],
            confidence=confidence,
            timestamp=now,
            recommended_action=(
                f"Investigate host {primary['src_ip']} (MAC: {primary.get('source_mac') or 'unknown'}) "
                f"for scanning tools. Verify if endpoint is an authorized administrator. "
                f"Do NOT automatically disconnect client."
            ),
        )


# =============================================================================
# Hotspot Gateway MAC Address Resolution
# =============================================================================

def resolve_gateway_mac(gateway_ip: str = "192.168.137.1") -> Optional[str]:
    """
    Discovers the physical/virtual MAC address of the local Windows Hotspot
    gateway adapter assigned to `gateway_ip`.

    Reliability Strategy:
      1. Inspects Windows `ipconfig /all` output across all network adapter blocks.
      2. Locates the specific adapter section bound to `gateway_ip` (e.g. 192.168.137.1).
      3. Extracts the Physical Address and standardizes it as lowercase colon-separated hex.
      4. If unresolvable or running on non-Windows/offline hotspot, returns None safely.
    """
    try:
        proc = subprocess.run(
            ["ipconfig", "/all"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
        )
        if proc.returncode != 0:
            return None
        output = proc.stdout
    except Exception:
        return None

    # Parse adapter blocks separated by blank lines
    blocks = re.split(r"\r?\n\r?\n", output)
    escaped_ip = re.escape(gateway_ip)
    ip_pattern = re.compile(rf"IPv4 Address[ .]*:[ ]*{escaped_ip}", re.IGNORECASE)
    mac_pattern = re.compile(
        r"Physical Address[ .]*:[ ]*([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})",
        re.IGNORECASE,
    )

    for block in blocks:
        if ip_pattern.search(block):
            m = mac_pattern.search(block)
            if m:
                raw_mac = m.group(1).replace("-", ":").lower()
                return raw_mac

    return None


# =============================================================================
# 3. Spoofing / Impersonation Detector
# =============================================================================

@dataclass
class ConflictCandidateRecord:
    """Tracks conflicting observations from an alternate MAC attempting to use an already-bound IP."""
    candidate_mac: str
    first_seen: float
    last_seen: float
    packet_count: int
    last_alert_time: float
    last_updated_mono: float


class SpoofingDetector:
    """
    Detects IP / MAC identity spoofing and impersonation attacks.

    Academic Principle:
      - Unknown MAC addresses appear legitimately due to mobile MAC Address
        Randomization (Android, iOS, Windows private addressing).
      - An unknown MAC address alone MUST NOT trigger a spoofing alarm!
      - Genuine spoofing requires conflicting identity evidence:
        1. Conflicting IP-to-MAC mapping: The same IP address (especially the
           gateway 192.168.137.1 or an active registered device) is concurrently
           claimed by two distinct MAC addresses within an active DHCP lease.
        2. Impersonation: A rogue client attempts to send traffic claiming the
           gateway IP address.
      - Gateway Impersonation Safety:
        If the Hotspot Gateway MAC cannot be verified/configured, traffic claiming
        the gateway IP MUST report INSUFFICIENT_TELEMETRY rather than raising a false alarm.
    """

    @staticmethod
    def normalize_mac(mac: Optional[str]) -> Optional[str]:
        """Standardizes a MAC address string to lowercase colon-separated hex."""
        if not mac:
            return None
        return mac.strip().lower().replace("-", ":")

    def __init__(
        self,
        gateway_ip: str = "192.168.137.1",
        gateway_mac: Optional[str] = None,
        ip_conflict_window_seconds: float = 60.0,
        local_subnet: str = DEFAULT_HOTSPOT_SUBNET,
        binding_expiry_seconds: float = 300.0,
        conflict_alert_cooldown_seconds: float = 60.0,
        confirmation_min_packets: int = 2,
        max_tracked_ips: int = 1000,
    ):
        self.gateway_ip = gateway_ip
        self.gateway_mac = self.normalize_mac(gateway_mac)
        self.ip_conflict_window_seconds = float(ip_conflict_window_seconds)
        self.local_subnet_str = local_subnet
        self._local_network = self._parse_subnet(local_subnet)
        self.binding_expiry_seconds = float(binding_expiry_seconds)
        self.conflict_alert_cooldown_seconds = float(conflict_alert_cooldown_seconds)
        self.confirmation_min_packets = int(confirmation_min_packets)
        self.max_tracked_ips = int(max_tracked_ips)

        # Baseline binding: ip -> (baseline_mac, last_seen_epoch)
        self._ip_to_mac_binding: Dict[str, Tuple[str, float]] = {}
        # Baseline metadata: ip -> {"first_seen": float, "packet_count": int, "last_updated_mono": float}
        self._binding_metadata: Dict[str, Dict[str, Any]] = {}
        # Conflict candidates: ip -> {candidate_mac -> ConflictCandidateRecord}
        self._conflict_candidates: Dict[str, Dict[str, ConflictCandidateRecord]] = {}
        # State: mac -> known registration status
        self._registered_macs: Set[str] = set()

    def set_local_subnet(self, subnet_str: str) -> None:
        """Configures or updates the monitored local subnet."""
        self.local_subnet_str = subnet_str
        self._local_network = self._parse_subnet(subnet_str)

    def set_gateway_mac(self, gateway_mac: Optional[str]) -> None:
        """Sets or updates the verified gateway MAC address."""
        self.gateway_mac = self.normalize_mac(gateway_mac)

    def set_registered_devices(self, macs: Set[str]) -> None:
        self._registered_macs = {self.normalize_mac(m) for m in macs if m}

    def reset(self) -> None:
        self._ip_to_mac_binding.clear()
        self._binding_metadata.clear()
        self._conflict_candidates.clear()

    def _cleanup_stale_bindings(self, now_mono: Optional[float] = None) -> None:
        """Prunes stale bindings and candidate trackers when memory limits are exceeded."""
        if len(self._ip_to_mac_binding) >= self.max_tracked_ips or now_mono is not None:
            mono = now_mono if now_mono is not None else time.monotonic()
            cutoff = mono - (self.binding_expiry_seconds * 2)
            expired_ips = [
                ip for ip, meta in self._binding_metadata.items()
                if meta.get("last_updated_mono", 0.0) < cutoff
            ]
            for ip in expired_ips:
                self._ip_to_mac_binding.pop(ip, None)
                self._binding_metadata.pop(ip, None)
                self._conflict_candidates.pop(ip, None)

            # Stage 3.2.1: Also prune stale candidate trackers within active baseline IPs
            for ip, candidates in list(self._conflict_candidates.items()):
                stale_candidates = [
                    mac for mac, cand in candidates.items()
                    if cand.last_updated_mono < cutoff
                ]
                for mac in stale_candidates:
                    candidates.pop(mac, None)
                if not candidates and ip not in self._ip_to_mac_binding:
                    self._conflict_candidates.pop(ip, None)

    @staticmethod
    def _parse_subnet(subnet_str: str) -> ipaddress.IPv4Network:
        """Parses a CIDR string or dotted prefix into an IPv4Network."""
        cleaned = subnet_str.strip()
        try:
            return ipaddress.ip_network(cleaned, strict=False)
        except ValueError:
            prefix = cleaned.rstrip(".")
            parts = prefix.split(".")
            while len(parts) < 4:
                parts.append("0")
            return ipaddress.ip_network(f"{'.'.join(parts)}/24", strict=False)

    def is_invalid_or_non_unicast_source_ip(self, ip_str: str) -> bool:
        """
        Determines whether a source IP address is unassigned, broadcast, multicast,
        or non-routable, and therefore ineligible for IP-to-MAC binding.

        Handles:
          - '0.0.0.0' (unspecified source address used in DHCP Discover/Request)
          - '255.255.255.255' (limited broadcast)
          - IPv4 multicast addresses (224.0.0.0/4)
          - Local network address (e.g. 192.168.137.0)
          - Local broadcast address (e.g. 192.168.137.255)
        """
        if not ip_str:
            return True
        cleaned = ip_str.strip()
        if cleaned in ("0.0.0.0", "255.255.255.255"):
            return True
        try:
            addr = ipaddress.ip_address(cleaned)
            if addr.version != 4:
                return True
            if addr.is_unspecified or addr.is_multicast or addr.is_reserved:
                return True
            if addr == ipaddress.IPv4Address("255.255.255.255"):
                return True
            if self._local_network:
                if addr == self._local_network.network_address or addr == self._local_network.broadcast_address:
                    return True
            return False
        except ValueError:
            return True

    @staticmethod
    def is_locally_administered_mac(mac: str) -> bool:
        """
        Checks if the MAC address has the IEEE 802 Locally Administered bit set
        (second least significant bit of first octet is 1, e.g. x2:, x6:, xA:, xE:).
        This indicates mobile randomized MAC addressing for user privacy.
        """
        try:
            cleaned = mac.strip().lower().replace("-", ":")
            first_byte = int(cleaned.split(":")[0], 16)
            return bool(first_byte & 0x02)
        except Exception:
            return False

    def evaluate(self, packet: PacketObservation) -> AttackDetectionResult:
        now = packet.timestamp
        now_mono = time.monotonic()
        mac = self.normalize_mac(packet.eth_src) or ""
        ip = packet.ip_src.strip() if packet.ip_src else ""

        missing = []
        if not mac:
            missing.append("eth_src")
        if not ip:
            missing.append("ip_src")
        if missing:
            return AttackDetectionResult(
                category=AttackCategory.SPOOFING,
                status=DetectionStatus.INSUFFICIENT_TELEMETRY,
                severity=Severity.NONE,
                evidence={"reason": "Packet lacks eth_src or ip_src"},
                missing_fields=missing,
                confidence=0.0,
                timestamp=now,
                recommended_action="Ensure Ethernet and IP headers are extracted.",
            )

        # Check for unassigned / broadcast / multicast source IP (e.g. DHCP Discover 0.0.0.0)
        if self.is_invalid_or_non_unicast_source_ip(ip):
            is_random = self.is_locally_administered_mac(mac)
            return AttackDetectionResult(
                category=AttackCategory.SPOOFING,
                status=DetectionStatus.NO_EVIDENCE,
                severity=Severity.NONE,
                evidence={
                    "verdict": "Unassigned or non-unicast source address",
                    "ip": ip,
                    "mac": mac,
                    "is_randomized_mac": is_random,
                    "explanation": (
                        f"Source IP {ip} is an unassigned, broadcast, or multicast address "
                        f"(e.g. initial DHCP negotiation); excluded from IP-to-MAC binding."
                    ),
                },
                missing_fields=[],
                confidence=0.0,
                timestamp=now,
                recommended_action="Normal monitoring.",
            )

        # 1. Gateway IP Impersonation Check:
        # A packet claiming the gateway IP address (192.168.137.1)
        if ip == self.gateway_ip:
            is_random = self.is_locally_administered_mac(mac)
            if not self.gateway_mac:
                # Gateway MAC cannot be verified: report INSUFFICIENT_TELEMETRY (never false alert!)
                return AttackDetectionResult(
                    category=AttackCategory.SPOOFING,
                    status=DetectionStatus.INSUFFICIENT_TELEMETRY,
                    severity=Severity.NONE,
                    evidence={
                        "reason": (
                            "Hotspot Gateway MAC address is unverified/unconfigured. "
                            "Cannot determine if traffic claiming gateway IP 192.168.137.1 is genuine or spoofed."
                        ),
                        "claimed_ip": ip,
                        "observed_mac": mac,
                        "is_randomized_mac": is_random,
                    },
                    missing_fields=["gateway_mac"],
                    confidence=0.0,
                    timestamp=now,
                    recommended_action="Configure the verified hotspot gateway MAC address via --gateway-mac or network interface resolution.",
                )

            if mac == self.gateway_mac:
                # Genuine gateway traffic
                return AttackDetectionResult(
                    category=AttackCategory.SPOOFING,
                    status=DetectionStatus.NO_EVIDENCE,
                    severity=Severity.NONE,
                    evidence={
                        "verdict": "Legitimate gateway traffic",
                        "claimed_ip": ip,
                        "mac": mac,
                        "is_gateway": True,
                        "is_randomized_mac": is_random,
                        "explanation": "Observed MAC matches the verified Hotspot Gateway MAC.",
                    },
                    missing_fields=[],
                    confidence=0.0,
                    timestamp=now,
                    recommended_action="Normal monitoring.",
                )
            else:
                # Conflicting gateway identity observed!
                return AttackDetectionResult(
                    category=AttackCategory.SPOOFING,
                    status=DetectionStatus.SUSPICIOUS,
                    severity=Severity.HIGH,
                    evidence={
                        "verdict": "Gateway IP impersonation attempt",
                        "claimed_ip": ip,
                        "offending_mac": mac,
                        "authorized_gateway_mac": self.gateway_mac,
                        "is_randomized_mac": is_random,
                        "explanation": (
                            f"Host with MAC {mac} emitted traffic claiming the Hotspot Gateway IP "
                            f"{self.gateway_ip}, but authorized gateway MAC is {self.gateway_mac}."
                        ),
                    },
                    missing_fields=[],
                    confidence=0.90,
                    timestamp=now,
                    recommended_action=f"Investigate host claiming gateway IP {ip}. Inspect ARP cache and physical port.",
                )

        # 2. IP-to-MAC Binding & Conservative Conflict-Confirmation Check:
        if ip in self._ip_to_mac_binding:
            baseline_mac, baseline_last_seen = self._ip_to_mac_binding[ip]

            if mac == baseline_mac:
                # The authoritative baseline device communicated again.
                # Refresh last seen epoch and monotonic timestamp.
                self._ip_to_mac_binding[ip] = (baseline_mac, now)
                meta = self._binding_metadata.setdefault(
                    ip, {"first_seen": now, "packet_count": 0, "last_updated_mono": now_mono}
                )
                meta["packet_count"] += 1
                meta["last_updated_mono"] = now_mono

            else:
                # mac != baseline_mac: An alternate MAC is observed claiming this IP!
                time_since_baseline = now - baseline_last_seen
                ip_candidates = self._conflict_candidates.setdefault(ip, {})
                candidate = ip_candidates.get(mac)

                if candidate is None:
                    candidate = ConflictCandidateRecord(
                        candidate_mac=mac,
                        first_seen=now,
                        last_seen=now,
                        packet_count=1,
                        last_alert_time=now,
                        last_updated_mono=now_mono,
                    )
                    ip_candidates[mac] = candidate
                elif (now - candidate.last_seen) > self.binding_expiry_seconds:
                    # Stage 3.2.1: The existing candidate record is stale (> binding_expiry_seconds gap).
                    # Reset confirmation state as a fresh candidate so old observations cannot combine
                    # with new observations to satisfy confirmation/handover thresholds.
                    candidate.first_seen = now
                    candidate.last_seen = now
                    candidate.packet_count = 1
                    candidate.last_alert_time = now
                    candidate.last_updated_mono = now_mono
                else:
                    candidate.last_seen = now
                    candidate.packet_count += 1
                    candidate.last_updated_mono = now_mono

                # Determine whether baseline has aged out / expired:
                baseline_has_expired = time_since_baseline > self.binding_expiry_seconds

                if not baseline_has_expired:
                    # Baseline is still active or within protected expiry lease!
                    # A single conflicting packet (or repeated packets) CANNOT overwrite baseline.
                    is_within_conflict_window = time_since_baseline <= self.ip_conflict_window_seconds

                    # Condition for alert: either first packet from candidate, or cooldown has elapsed
                    should_alert = (
                        candidate.packet_count == 1
                        or (now - candidate.last_alert_time) >= self.conflict_alert_cooldown_seconds
                    )

                    if should_alert:
                        candidate.last_alert_time = now
                        severity = Severity.HIGH if is_within_conflict_window else Severity.MEDIUM
                        confidence = 0.85 if is_within_conflict_window else 0.70
                        return AttackDetectionResult(
                            category=AttackCategory.SPOOFING,
                            status=DetectionStatus.SUSPICIOUS,
                            severity=severity,
                            evidence={
                                "verdict": "Conflicting IP-to-MAC binding detected",
                                "ip_address": ip,
                                "current_mac": mac,
                                "previous_mac": baseline_mac,
                                "elapsed_seconds": round(time_since_baseline, 2),
                                "conflict_packet_count": candidate.packet_count,
                                "current_is_randomized": self.is_locally_administered_mac(mac),
                                "previous_is_randomized": self.is_locally_administered_mac(baseline_mac),
                                "explanation": (
                                    f"IP {ip} was active on baseline MAC {baseline_mac} "
                                    f"{round(time_since_baseline, 1)}s ago, now observed on {mac}. "
                                    f"Observed {candidate.packet_count} conflicting packet(s)."
                                ),
                            },
                            missing_fields=[],
                            confidence=confidence,
                            timestamp=now,
                            recommended_action="Check DHCP lease table to determine if legitimate handover or IP collision occurred.",
                        )
                    else:
                        # Ongoing conflict from same candidate MAC: alert is suppressed within cooldown window
                        return AttackDetectionResult(
                            category=AttackCategory.SPOOFING,
                            status=DetectionStatus.NO_EVIDENCE,
                            severity=Severity.NONE,
                            evidence={
                                "verdict": "Ongoing conflicting IP-to-MAC observation (tracked)",
                                "ip_address": ip,
                                "current_mac": mac,
                                "previous_mac": baseline_mac,
                                "conflict_packet_count": candidate.packet_count,
                                "elapsed_since_last_alert": round(now - candidate.last_alert_time, 2),
                                "explanation": (
                                    f"Ongoing conflict on IP {ip} from {mac}; observation tracked "
                                    f"({candidate.packet_count} packets). Repeated alerts suppressed within cooldown."
                                ),
                            },
                            missing_fields=[],
                            confidence=0.0,
                            timestamp=now,
                            recommended_action="Normal monitoring (ongoing conflict alert in cooldown).",
                        )

                else:
                    # Baseline has safely aged out (time_since_baseline > binding_expiry_seconds)!
                    # Check confirmation threshold for safe lease handover promotion:
                    if candidate.packet_count >= self.confirmation_min_packets:
                        # Confirmed sustained communication from new MAC: promote to new baseline!
                        self._ip_to_mac_binding[ip] = (mac, now)
                        self._binding_metadata[ip] = {
                            "first_seen": candidate.first_seen,
                            "packet_count": candidate.packet_count,
                            "last_updated_mono": now_mono,
                        }
                        # Remove promoted candidate from conflicts
                        ip_candidates.pop(mac, None)

                        return AttackDetectionResult(
                            category=AttackCategory.SPOOFING,
                            status=DetectionStatus.NO_EVIDENCE,
                            severity=Severity.NONE,
                            evidence={
                                "verdict": "Legitimate IP-to-MAC binding handover confirmed",
                                "ip_address": ip,
                                "current_mac": mac,
                                "previous_mac": baseline_mac,
                                "elapsed_since_previous_mac": round(time_since_baseline, 2),
                                "confirmed_packet_count": candidate.packet_count,
                                "explanation": (
                                    f"Previous baseline MAC {baseline_mac} has aged out ({round(time_since_baseline, 1)}s silence). "
                                    f"New MAC {mac} confirmed across {candidate.packet_count} packets; binding safely updated."
                                ),
                            },
                            missing_fields=[],
                            confidence=0.0,
                            timestamp=now,
                            recommended_action="Normal monitoring (lease handover confirmed).",
                        )
                    else:
                        # A single packet (or insufficient packets) from new MAC:
                        # Do NOT overwrite baseline yet (Requirement 2 & 6), and do NOT classify as attack (Requirement 7)
                        return AttackDetectionResult(
                            category=AttackCategory.SPOOFING,
                            status=DetectionStatus.NO_EVIDENCE,
                            severity=Severity.NONE,
                            evidence={
                                "verdict": "Pending IP-to-MAC lease transition",
                                "ip_address": ip,
                                "current_mac": mac,
                                "previous_mac": baseline_mac,
                                "candidate_packet_count": candidate.packet_count,
                                "required_packets": self.confirmation_min_packets,
                                "explanation": (
                                    f"Previous baseline MAC {baseline_mac} aged out ({round(time_since_baseline, 1)}s silence). "
                                    f"Candidate {mac} observed ({candidate.packet_count}/{self.confirmation_min_packets} packets); awaiting confirmation."
                                ),
                            },
                            missing_fields=[],
                            confidence=0.0,
                            timestamp=now,
                            recommended_action="Normal monitoring (lease transition pending confirmation).",
                        )

        else:
            # First time observing this IP: establish authoritative baseline
            self._ip_to_mac_binding[ip] = (mac, now)
            self._binding_metadata[ip] = {
                "first_seen": now,
                "packet_count": 1,
                "last_updated_mono": now_mono,
            }
            self._conflict_candidates.pop(ip, None)
            self._cleanup_stale_bindings(now_mono)

        # 3. Unknown MAC handling:
        # An unknown MAC without IP conflicts is NOT an attack.
        is_unknown = bool(self._registered_macs and mac not in self._registered_macs)
        is_random = self.is_locally_administered_mac(mac)

        return AttackDetectionResult(
            category=AttackCategory.SPOOFING,
            status=DetectionStatus.NO_EVIDENCE,
            severity=Severity.INFO if is_unknown else Severity.NONE,
            evidence={
                "verdict": "Consistent identity binding",
                "mac": mac,
                "ip": ip,
                "is_registered": not is_unknown,
                "is_randomized_mac": is_random,
                "explanation": "No identity clash or address conflict observed.",
            },
            missing_fields=[],
            confidence=0.0,
            timestamp=now,
            recommended_action="Normal monitoring.",
        )


# =============================================================================
# 4. Wi-Fi Deauthentication / Disassociation Abuse Detector
# =============================================================================

class DeauthDetector:
    """
    Detects 802.11 Deauthentication and Disassociation flood attacks.

    Telemetry Reality & Capture Constraints:
      - Raw 802.11 Management Frames (Type 0, Subtype 10/12) are required to detect
        deauth abuse.
      - Standard Windows Mobile Hotspot adapters run in NDIS Ethernet-emulation mode,
        which strips 802.11 management frames before WinPcap/Npcap/TShark can capture them.
      - If raw 802.11 fields (`wlan_fc_type_subtype`, `wlan_reason_code`) are missing,
        this detector MUST report INSUFFICIENT_TELEMETRY rather than falsely claiming safety
        or fabricating detections.
    """

    def __init__(
        self,
        flood_rate_threshold: int = 5,
        window_seconds: float = 1.0,
    ):
        self.flood_rate_threshold = flood_rate_threshold
        self.window_seconds = window_seconds
        # State: bssid -> list of (timestamp, subtype, reason_code, dst_mac)
        self._history: Dict[str, List[Tuple[float, int, Optional[int], str]]] = {}

    def reset(self) -> None:
        self._history.clear()

    def evaluate(self, packets: List[PacketObservation]) -> AttackDetectionResult:
        if not packets:
            return AttackDetectionResult(
                category=AttackCategory.DEAUTH_FLOOD,
                status=DetectionStatus.NO_EVIDENCE,
                severity=Severity.NONE,
                evidence={"reason": "No packets in window"},
                missing_fields=[],
                confidence=0.0,
                timestamp=time.time(),
                recommended_action="Normal monitoring.",
            )

        now = max(p.timestamp for p in packets)

        # Check for 802.11 management telemetry
        mgmt_packets = [p for p in packets if p.wlan_fc_type_subtype is not None]

        if not mgmt_packets:
            return AttackDetectionResult(
                category=AttackCategory.DEAUTH_FLOOD,
                status=DetectionStatus.INSUFFICIENT_TELEMETRY,
                severity=Severity.NONE,
                evidence={
                    "reason": (
                        "802.11 management frame telemetry (wlan_fc_type_subtype, wlan_reason_code) "
                        "is missing from the capture stream. Windows Hotspot NDIS miniport captures "
                        "emulate 802.3 Ethernet and do not deliver raw 802.11 management frames."
                    ),
                    "packets_inspected": len(packets),
                },
                missing_fields=["wlan_fc_type_subtype", "wlan_reason_code", "wlan_bssid"],
                confidence=0.0,
                timestamp=now,
                recommended_action="Deploy an external monitor-mode Wi-Fi adapter or ESP32 promiscuous sniffer.",
            )

        # Ingest management frames (Subtype 10 = Disassoc, Subtype 12 = Deauth)
        deauth_frames = [
            p for p in mgmt_packets
            if p.wlan_fc_type_subtype in (10, 12)
        ]

        if not deauth_frames:
            return AttackDetectionResult(
                category=AttackCategory.DEAUTH_FLOOD,
                status=DetectionStatus.NO_EVIDENCE,
                severity=Severity.NONE,
                evidence={
                    "verdict": "802.11 management frames present without deauthentication flood",
                    "total_mgmt_frames": len(mgmt_packets),
                },
                missing_fields=[],
                confidence=0.0,
                timestamp=now,
                recommended_action="Normal monitoring.",
            )

        # Group by BSSID / source
        for p in deauth_frames:
            bssid = p.wlan_bssid or p.eth_src or "unknown_bssid"
            if bssid not in self._history:
                self._history[bssid] = []
            self._history[bssid].append((
                p.timestamp,
                p.wlan_fc_type_subtype,
                p.wlan_reason_code,
                p.eth_dst or "broadcast",
            ))

        findings = []
        for bssid in list(self._history.keys()):
            recent = [f for f in self._history[bssid] if now - f[0] <= self.window_seconds]
            if not recent:
                del self._history[bssid]
                continue
            self._history[bssid] = recent
            if len(recent) >= self.flood_rate_threshold:
                reason_codes = [f[2] for f in recent if f[2] is not None]
                broadcast_count = sum(1 for f in recent if "ff:ff:ff:ff:ff:ff" in f[3].lower())
                findings.append({
                    "bssid": bssid,
                    "frame_count_in_window": len(recent),
                    "subtypes": [f[1] for f in recent],
                    "reason_codes": reason_codes,
                    "broadcast_targets": broadcast_count,
                })

        if not findings:
            return AttackDetectionResult(
                category=AttackCategory.DEAUTH_FLOOD,
                status=DetectionStatus.NO_EVIDENCE,
                severity=Severity.NONE,
                evidence={
                    "verdict": "Deauth frame rate below threshold",
                    "deauth_count": len(deauth_frames),
                },
                missing_fields=[],
                confidence=0.0,
                timestamp=now,
                recommended_action="Normal monitoring.",
            )

        primary = findings[0]
        confidence = min(0.95, 0.70 + 0.05 * min(5, primary["frame_count_in_window"]))

        return AttackDetectionResult(
            category=AttackCategory.DEAUTH_FLOOD,
            status=DetectionStatus.SUSPICIOUS,
            severity=Severity.HIGH,
            evidence={
                "verdict": "802.11 Deauthentication / Disassociation flood detected",
                "details": findings,
            },
            missing_fields=[],
            confidence=confidence,
            timestamp=now,
            recommended_action="Inspect physical environment for rogue deauthentication transmitter.",
        )


# =============================================================================
# 5. Replay Attack Detector
# =============================================================================

class ReplayDetector:
    """
    Detects protocol-aware message and packet replay attacks.

    Academic Principle:
      - Identical packet sizes or repetitive transmission timings DO NOT constitute
        evidence of a replay attack. IoT sensors (e.g., our DHT11) legitimately
        transmit messages of identical size at strict periodic intervals.
      - Legitimate TCP retransmissions: A dropped packet is routinely retransmitted
        by TCP within a short retransmission timeout (RTO).
      - Genuine replay evidence requires:
        1. Identical message payload hash or message identifier.
        2. Sequence number regression or nonce re-use violating protocol state.
      - If sequence numbers, payload hashes, or cryptographic nonces are absent,
        the detector MUST report INSUFFICIENT_TELEMETRY.
    """

    def __init__(
        self,
        tcp_retransmit_window_seconds: float = 3.0,
        replay_history_window_seconds: float = 60.0,
    ):
        self.tcp_retransmit_window_seconds = tcp_retransmit_window_seconds
        self.replay_history_window_seconds = replay_history_window_seconds

        # State: payload_hash / seq_key -> list of (timestamp, seq_num, nonce, src, dst, flow_key)
        self._seen_payloads: Dict[str, List[Tuple[float, Optional[int], Optional[str], str, str, Tuple[Any, ...]]]] = {}

    def reset(self) -> None:
        self._seen_payloads.clear()

    @staticmethod
    def _extract_flow_key(p: PacketObservation) -> Tuple[Any, ...]:
        """
        Extracts a flow identity 5-tuple from available network and transport fields.

        Flow fields:
          - Source IP (falls back to eth_src if IP is absent, to distinguish L2 frames)
          - Destination IP (falls back to eth_dst if IP is absent)
          - Source port (int or None; missing fields remain None without inventing synthetic values)
          - Destination port (int or None; missing fields remain None)
          - Transport protocol (uppercase string or None)
        """
        src = p.ip_src if (p.ip_src is not None and p.ip_src != "") else p.eth_src
        dst = p.ip_dst if (p.ip_dst is not None and p.ip_dst != "") else p.eth_dst
        proto = p.protocol.upper() if isinstance(p.protocol, str) else None
        return (src, dst, p.src_port, p.dst_port, proto)

    def evaluate(self, packets: List[PacketObservation]) -> AttackDetectionResult:
        if not packets:
            return AttackDetectionResult(
                category=AttackCategory.REPLAY,
                status=DetectionStatus.NO_EVIDENCE,
                severity=Severity.NONE,
                evidence={"reason": "No packets in window"},
                missing_fields=[],
                confidence=0.0,
                timestamp=time.time(),
                recommended_action="Normal monitoring.",
            )

        now = max(p.timestamp for p in packets)

        # Check if protocol-level sequence numbers or payload hashes are available
        evaluable_packets = [
            p for p in packets
            if p.payload_hash is not None or p.nonce is not None or p.protocol_seq_num is not None
        ]

        if not evaluable_packets:
            return AttackDetectionResult(
                category=AttackCategory.REPLAY,
                status=DetectionStatus.INSUFFICIENT_TELEMETRY,
                severity=Severity.NONE,
                evidence={
                    "reason": (
                        "Protocol sequence numbers, payload hashes, or cryptographic nonces are "
                        "absent from the capture stream. Identical packet sizes or periodic timings "
                        "alone are scientifically insufficient to establish replay."
                    ),
                    "packets_inspected": len(packets),
                },
                missing_fields=["payload_hash", "protocol_seq_num", "nonce"],
                confidence=0.0,
                timestamp=now,
                recommended_action="Configure payload hashing or capture transport sequence numbers.",
            )

        replay_anomalies = []

        for p in evaluable_packets:
            flow_key = self._extract_flow_key(p)
            src = p.ip_src or p.eth_src
            dst = p.ip_dst or p.eth_dst

            if p.payload_hash is not None:
                key = p.payload_hash
            elif p.nonce is not None:
                key = p.nonce
            elif p.protocol_seq_num is not None:
                key = f"seq_{flow_key}_{p.protocol_seq_num}"
            else:
                continue

            entry_record = (p.timestamp, p.protocol_seq_num, p.nonce, src, dst, flow_key)

            if key not in self._seen_payloads:
                self._seen_payloads[key] = []
                self._seen_payloads[key].append(entry_record)
                continue

            previous_entries = self._seen_payloads[key]

            for prev_time, prev_seq, prev_nonce, prev_src, prev_dst, prev_flow in previous_entries:
                time_delta = p.timestamp - prev_time

                # Case A: Standard TCP retransmission (same sequence number within RTO window on same flow)
                if (
                    p.protocol_seq_num is not None
                    and prev_seq is not None
                    and p.protocol_seq_num == prev_seq
                    and time_delta <= self.tcp_retransmit_window_seconds
                    and flow_key == prev_flow
                ):
                    # Legitimate network retransmission
                    continue

                # Case B: Nonce reuse (cryptographic violation)
                if p.nonce is not None and prev_nonce is not None and p.nonce == prev_nonce:
                    replay_anomalies.append({
                        "anomaly_type": "Cryptographic Nonce Reuse",
                        "nonce": p.nonce,
                        "time_delta_seconds": round(time_delta, 3),
                        "src": src,
                        "dst": dst,
                    })

                # Case C: Duplicate payload observed outside legitimate retransmission window
                elif p.payload_hash is not None and time_delta > self.tcp_retransmit_window_seconds:
                    replay_anomalies.append({
                        "anomaly_type": "Stale Payload Re-injection",
                        "payload_hash": p.payload_hash,
                        "time_delta_seconds": round(time_delta, 3),
                        "src": src,
                        "dst": dst,
                    })

            self._seen_payloads[key].append(entry_record)

        # Cleanup old entries
        for k in list(self._seen_payloads.keys()):
            self._seen_payloads[k] = [
                entry for entry in self._seen_payloads[k]
                if now - entry[0] <= self.replay_history_window_seconds
            ]
            if not self._seen_payloads[k]:
                del self._seen_payloads[k]

        if not replay_anomalies:
            return AttackDetectionResult(
                category=AttackCategory.REPLAY,
                status=DetectionStatus.NO_EVIDENCE,
                severity=Severity.NONE,
                evidence={
                    "verdict": "No replay violations observed",
                    "evaluable_packets": len(evaluable_packets),
                },
                missing_fields=[],
                confidence=0.0,
                timestamp=now,
                recommended_action="Normal monitoring.",
            )

        confidence = 0.85 if any("Nonce" in a["anomaly_type"] for a in replay_anomalies) else 0.70

        return AttackDetectionResult(
            category=AttackCategory.REPLAY,
            status=DetectionStatus.SUSPICIOUS,
            severity=Severity.HIGH,
            evidence={
                "verdict": "Potential replay attack detected",
                "violations": replay_anomalies,
            },
            missing_fields=[],
            confidence=confidence,
            timestamp=now,
            recommended_action="Verify application-layer session tokens and TLS / secure MQTT handshake state.",
        )


# =============================================================================
# Composite Network Attack Detector Engine
# =============================================================================

class NetworkAttackDetector:
    """
    Unified manager orchestrating all five attack detectors.
    Ensures safe evaluation, state tracking, and clear telemetry reporting.
    """

    def __init__(
        self,
        dos_rate_threshold: float = 60.0,
        dos_min_consecutive_windows: int = 3,
        port_scan_vertical_threshold: int = 8,
        port_scan_horizontal_threshold: int = 5,
        gateway_ip: str = "192.168.137.1",
        gateway_mac: Optional[str] = None,
        local_subnet: str = DEFAULT_HOTSPOT_SUBNET,
    ):
        self.dos_detector = DoSDetector(
            rate_threshold_pps=dos_rate_threshold,
            min_consecutive_windows=dos_min_consecutive_windows,
            local_subnet=local_subnet,
            gateway_ip=gateway_ip,
        )
        self.port_scan_detector = PortScanDetector(
            vertical_port_threshold=port_scan_vertical_threshold,
            horizontal_host_threshold=port_scan_horizontal_threshold,
            local_subnet=local_subnet,
        )
        self.spoofing_detector = SpoofingDetector(
            gateway_ip=gateway_ip,
            gateway_mac=gateway_mac,
            local_subnet=local_subnet,
        )
        self.deauth_detector = DeauthDetector()
        self.replay_detector = ReplayDetector()

    def set_local_subnet(self, subnet_str: str) -> None:
        """Configures or updates the monitored local subnet."""
        self.port_scan_detector.set_local_subnet(subnet_str)
        self.dos_detector.set_local_subnet(subnet_str)
        self.spoofing_detector.set_local_subnet(subnet_str)

    def set_gateway_mac(self, gateway_mac: Optional[str]) -> None:
        """Configures or updates the verified gateway MAC address."""
        self.spoofing_detector.set_gateway_mac(gateway_mac)

    def set_known_devices(self, mac_addresses: Set[str]) -> None:
        """Configures registered client MAC addresses for identity verification."""
        self.spoofing_detector.set_registered_devices(mac_addresses)

    def reset_all_states(self) -> None:
        """Resets all internal temporal states across all detectors."""
        self.dos_detector.reset()
        self.port_scan_detector.reset()
        self.spoofing_detector.reset()
        self.deauth_detector.reset()
        self.replay_detector.reset()

    def evaluate_traffic_window(
        self,
        window: WindowTrafficObservation,
        fleet_windows: Optional[List[WindowTrafficObservation]] = None,
    ) -> List[AttackDetectionResult]:
        """
        Evaluates an aggregated 1-second feature window.
        Primary target for DoS detection.
        """
        results: List[AttackDetectionResult] = []
        dos_res = self.dos_detector.evaluate(window, fleet_windows)
        results.append(dos_res)
        return results

    def evaluate_packet_stream(
        self,
        packets: List[PacketObservation],
    ) -> List[AttackDetectionResult]:
        """
        Evaluates a batch of packet observations across all packet-level detectors:
        Port Scanning, Spoofing, Deauthentication, and Replay.
        """
        results: List[AttackDetectionResult] = []

        # 1. Port scan check
        results.append(self.port_scan_detector.evaluate(packets))

        # 2. Spoofing check across packets
        spoof_results: List[AttackDetectionResult] = []
        for p in packets:
            res = self.spoofing_detector.evaluate(p)
            if res.status == DetectionStatus.SUSPICIOUS:
                spoof_results.append(res)
                break  # Stop at first suspicious finding in this batch

        if spoof_results:
            results.append(spoof_results[0])
        elif packets:
            # Report status of first packet
            results.append(self.spoofing_detector.evaluate(packets[0]))
        else:
            results.append(AttackDetectionResult(
                category=AttackCategory.SPOOFING,
                status=DetectionStatus.NO_EVIDENCE,
                severity=Severity.NONE,
                evidence={"reason": "No packets to evaluate"},
                missing_fields=[],
                confidence=0.0,
                timestamp=time.time(),
                recommended_action="Normal monitoring.",
            ))

        # 3. Deauth check
        results.append(self.deauth_detector.evaluate(packets))

        # 4. Replay check
        results.append(self.replay_detector.evaluate(packets))

        return results

    @staticmethod
    def get_capabilities() -> Dict[str, Any]:
        """
        Returns an academic capability matrix detailing which attack categories
        can operate on current live telemetry vs those requiring enhanced capture.
        """
        return {
            "DOS": {
                "category": AttackCategory.DOS.value,
                "status_on_current_stream": "OPERATIONAL",
                "required_telemetry": ["packet_rate", "mac_address", "ip_dst"],
                "limitations": "Requires multi-window sliding state to avoid false positives on transient bursts.",
            },
            "PORT_SCAN": {
                "category": AttackCategory.PORT_SCAN.value,
                "status_on_current_stream": "INSUFFICIENT_TELEMETRY",
                "required_telemetry": ["dst_port", "src_port", "tcp_flags"],
                "remedy": "Add -e tcp.dstport -e udp.dstport -e tcp.flags to live TShark command.",
            },
            "SPOOFING": {
                "category": AttackCategory.SPOOFING.value,
                "status_on_current_stream": "OPERATIONAL",
                "required_telemetry": ["eth_src", "ip_src"],
                "limitations": "Cannot detect RF-level MAC cloning without physical layer RSSI or radio fingerprinting.",
            },
            "DEAUTH_FLOOD": {
                "category": AttackCategory.DEAUTH_FLOOD.value,
                "status_on_current_stream": "INSUFFICIENT_TELEMETRY",
                "required_telemetry": ["wlan_fc_type_subtype", "wlan_reason_code", "wlan_bssid"],
                "remedy": "Windows Hotspot NDIS interface strips 802.11 management frames. Requires external monitor-mode adapter or ESP32 sniffer.",
            },
            "REPLAY": {
                "category": AttackCategory.REPLAY.value,
                "status_on_current_stream": "INSUFFICIENT_TELEMETRY",
                "required_telemetry": ["payload_hash", "protocol_seq_num", "nonce"],
                "remedy": "Add payload extraction (-e data or application layer decoder) to TShark pipeline.",
            },
            "RSSI_MONITORING": {
                "status_on_current_stream": "UNAVAILABLE",
                "required_hardware": "Monitor-mode adapter with radiotap headers or ESP32 promiscuous RX callback.",
                "note": "ESP32 currently dedicated to DHT11 (GPIO4) and PIR (GPIO27) serial streaming.",
            },
        }
