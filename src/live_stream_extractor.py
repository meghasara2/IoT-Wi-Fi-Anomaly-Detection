"""
Live Streaming Packet Feature Extractor
File: src/live_stream_extractor.py

Purpose:
  Reads a live TShark packet stream from a subprocess, accumulates packets
  into completed one-second epoch bins, and yields finished 1-second feature
  windows consistent with the offline extractor (src/extract_pcap_time_windows.py).

Feature Computation Convention (MUST stay identical to offline pipeline):
  - packet_rate  = packet_count / 1.0  (packets captured per 1-second bin)
  - N = 0: all other features = NaN
  - N = 1: mean_IAT = NaN, IAT_std = NaN, mean_packet_size = size, packet_size_std = 0.0
  - N = 2: mean_IAT = single interval, IAT_std = 0.0, packet_size_std = sample std (ddof=1)
  - N >= 3: mean_IAT = mean(IATs), IAT_std = std(IATs, ddof=1), packet_size_std = std(ddof=1)
  This matches compute_1s_features_for_client() in extract_pcap_time_windows.py exactly.

Live Device Registry:
  A configurable dict mapping observed MAC addresses to node metadata.
  Any MAC not in the registry is flagged as UNKNOWN_DEVICE and stored in
  unregistered_macs for the caller to forward as unknown-device alerts.
  Hotspot gateway / AP packets are filtered by broadcast/multicast addresses.

Node Configuration:
  - Node_3, Node_4, Node_5: Wi-Fi client phones (registered by MAC).
  - Node_1, Node_2: Logical sensor nodes (DHT11 / PIR) — handled by the
    serial ingestion path, NOT by TShark. They do not appear here.

TShark Integration:
  Opens a subprocess running:
    tshark -i <iface> -l -T fields -e frame.number -e frame.time_epoch
           -e frame.len -e eth.src -e eth.dst -e ip.src -e ip.dst
           -e _ws.col.Protocol -E separator=<TAB> -E occurrence=f
  Each line is parsed immediately. Completed bins (wall-clock second elapsed)
  are yielded as feature dicts. Partial bins at stream close are also yielded.

Thread Safety:
  This module is designed to run in a single background thread. The caller
  is responsible for thread lifecycle management.
"""

import atexit
import datetime
import math
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Iterator, Set

import numpy as np

try:
    from src.live_interface_resolver import TSHARK_DEFAULT_PATH
    from src.attack_detector import PacketObservation
except ModuleNotFoundError:
    from live_interface_resolver import TSHARK_DEFAULT_PATH
    from attack_detector import PacketObservation

# ─────────────────────────────────────────────────────────────────────────────
# Feature column names — MUST match the offline extractor column names.
# ─────────────────────────────────────────────────────────────────────────────
FEATURE_COLS_PRIMARY = ["packet_rate", "mean_packet_size", "packet_size_std"]
FEATURE_COLS_TIMING = ["mean_IAT", "IAT_std"]
MIN_PACKETS_FOR_TIMING = 3  # Must match dual_detector_1s.py


# ─────────────────────────────────────────────────────────────────────────────
# Default device registry — configurable, not hardcoded as permanent truth.
# MACs are treated as observed identifiers; randomised MACs will appear as
# UNKNOWN_DEVICE and should prompt operator review, not automatic blocking.
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_DEVICE_REGISTRY: Dict[str, Dict[str, str]] = {
    # Populate with observed MAC → node metadata as devices connect.
    # Format: "xx:xx:xx:xx:xx:xx": {"node_id": "Node_3", "device_type": "...", "label": "..."}
    "ca:34:ea:92:d3:9e": {
        "node_id": "Node_3",
        "device_type": "Phone_Client",
        "label": "real_observed_traffic",
        "ip": "192.168.137.201",
    },
    "e6:2e:db:73:1c:25": {
        "node_id": "Node_4",
        "device_type": "Phone_Client",
        "label": "real_observed_traffic",
        "ip": "192.168.137.6",
    },
    # Node_5 (Phone 3) is intentionally absent until connected in the demo.
}

# Hotspot gateway/AP subnet prefix
HOTSPOT_SUBNET_PREFIX = "192.168.137."


# ─────────────────────────────────────────────────────────────────────────────
# Internal packet record type (lightweight dict)
# ─────────────────────────────────────────────────────────────────────────────
class _RawPacket:
    """Lightweight container for a single parsed TShark frame field set."""
    __slots__ = (
        "timestamp", "packet_size", "eth_src", "eth_dst",
        "ip_src", "ip_dst", "protocol",
        "src_port", "dst_port", "tcp_flags", "tcp_seq",
    )

    def __init__(
        self,
        timestamp: float,
        packet_size: int,
        eth_src: str,
        eth_dst: str,
        ip_src: str,
        ip_dst: str,
        protocol: str,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        tcp_flags: Optional[str] = None,
        tcp_seq: Optional[int] = None,
    ) -> None:
        self.timestamp = timestamp
        self.packet_size = packet_size
        self.eth_src = eth_src
        self.eth_dst = eth_dst
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.protocol = protocol
        self.src_port = src_port
        self.dst_port = dst_port
        self.tcp_flags = tcp_flags
        self.tcp_seq = tcp_seq

    def to_observation(self) -> PacketObservation:
        """Converts raw packet into structured PacketObservation for attack detection."""
        return PacketObservation(
            timestamp=self.timestamp,
            packet_size=self.packet_size,
            eth_src=self.eth_src,
            eth_dst=self.eth_dst,
            ip_src=self.ip_src if self.ip_src else None,
            ip_dst=self.ip_dst if self.ip_dst else None,
            protocol=self.protocol if self.protocol else None,
            src_port=self.src_port,
            dst_port=self.dst_port,
            tcp_flags=self.tcp_flags,
            protocol_seq_num=self.tcp_seq,
        )


def _is_broadcast_or_multicast(eth_dst: str) -> bool:
    """Returns True for broadcast/multicast Ethernet destinations."""
    d = eth_dst.lower()
    return (
        d.startswith("ff:ff:ff")
        or d.startswith("01:00:5e")   # IPv4 multicast
        or d.startswith("33:33:")      # IPv6 multicast
        or d.startswith("01:80:c2:")   # IEEE 802.1D spanning tree etc.
    )


def _attribute_packet(
    pkt: _RawPacket,
    registry: Dict[str, Dict[str, str]],
) -> Tuple[Optional[str], Optional[Dict[str, str]], str]:
    """
    Determines the node identity (if any) for a single parsed packet.

    Returns
    -------
    (node_id, node_info, direction)
        node_id    : str or None if unknown / unregisterable
        node_info  : registry entry or None
        direction  : 'uplink', 'downlink', or 'unknown'
    """
    if _is_broadcast_or_multicast(pkt.eth_dst):
        return None, None, "infrastructure"

    src = pkt.eth_src.lower()
    dst = pkt.eth_dst.lower()

    # MAC-based match (uplink: device → hotspot AP)
    if src in registry:
        return registry[src]["node_id"], registry[src], "uplink"
    # MAC-based match (downlink: hotspot AP → device)
    if dst in registry:
        return registry[dst]["node_id"], registry[dst], "downlink"

    # IP-based fallback (for packets where Ethernet header uses hotspot MAC)
    ip_to_reg = {
        info.get("ip", ""): (mac, info)
        for mac, info in registry.items()
        if info.get("ip")
    }
    if pkt.ip_src in ip_to_reg:
        _, info = ip_to_reg[pkt.ip_src]
        return info["node_id"], info, "uplink"
    if pkt.ip_dst in ip_to_reg:
        _, info = ip_to_reg[pkt.ip_dst]
        return info["node_id"], info, "downlink"

    return None, None, "unregistered"


def _compute_1s_window_features(
    node_id: str,
    node_info: Dict[str, str],
    client_mac: str,
    bin_start: float,
    packets: List[_RawPacket],
) -> Dict[str, Any]:
    """
    Computes 1-second window features from a list of _RawPacket objects
    that fall within [bin_start, bin_start+1.0).

    This follows EXACTLY the same arithmetic as
    compute_1s_features_for_client() in extract_pcap_time_windows.py.

    Parameters
    ----------
    node_id   : Registered node identifier (e.g. 'Node_3').
    node_info : Registry entry for this node.
    client_mac: Observed source MAC address.
    bin_start : Unix epoch of the 1-second window start.
    packets   : All packets in this bin, already sorted by timestamp.

    Returns
    -------
    dict with all standard feature columns plus metadata.
    """
    bin_end = bin_start + 1.0
    n_pkts = len(packets)

    packet_rate = float(n_pkts)  # / 1.0 s

    if n_pkts == 0:
        mean_iat = np.nan
        iat_std = np.nan
        mean_packet_size = np.nan
        packet_size_std = np.nan
    elif n_pkts == 1:
        mean_iat = np.nan
        iat_std = np.nan
        mean_packet_size = float(packets[0].packet_size)
        packet_size_std = 0.0
    elif n_pkts == 2:
        dt = packets[1].timestamp - packets[0].timestamp
        mean_iat = float(dt) if dt >= 0.0 else 0.0
        iat_std = 0.0
        sizes = [p.packet_size for p in packets]
        mean_packet_size = float(np.mean(sizes))
        std_val = float(np.std(sizes, ddof=1))
        packet_size_std = 0.0 if np.isnan(std_val) else std_val
    else:  # n_pkts >= 3
        timestamps = np.array([p.timestamp for p in packets], dtype=float)
        iats = np.diff(timestamps)
        mean_iat = float(np.mean(iats))
        iat_std_val = float(np.std(iats, ddof=1))
        iat_std = 0.0 if np.isnan(iat_std_val) else iat_std_val
        sizes = np.array([p.packet_size for p in packets], dtype=float)
        mean_packet_size = float(np.mean(sizes))
        ps_std_val = float(np.std(sizes, ddof=1))
        packet_size_std = 0.0 if np.isnan(ps_std_val) else ps_std_val

    dt_start_utc = datetime.datetime.fromtimestamp(
        bin_start, tz=datetime.timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    dt_end_utc = datetime.datetime.fromtimestamp(
        bin_end, tz=datetime.timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    total_bytes = sum(p.packet_size for p in packets) if packets else 0
    dst_counts: Dict[str, int] = {}
    for p in packets:
        if p.ip_dst:
            dst_counts[p.ip_dst] = dst_counts.get(p.ip_dst, 0) + 1
    dom_dst = max(dst_counts.items(), key=lambda x: x[1])[0] if dst_counts else None
    dom_src = packets[0].ip_src if (packets and packets[0].ip_src) else None

    return {
        "client_mac": client_mac,
        "node_id": node_id,
        "Node_Type": node_info.get("device_type", "Unknown"),
        "Data_Label": node_info.get("label", "real_observed_traffic"),
        "bin_start_timestamp": bin_start,
        "bin_end_timestamp": bin_end,
        "window_center_epoch": bin_start + 0.5,
        "Window_Start_UTC": dt_start_utc,
        "Window_End_UTC": dt_end_utc,
        "packet_count": n_pkts,
        "mean_IAT": mean_iat,
        "IAT_std": iat_std,
        "packet_rate": packet_rate,
        "mean_packet_size": mean_packet_size,
        "packet_size_std": packet_size_std,
        "total_bytes": total_bytes,
        "ip_src": dom_src,
        "ip_dst": dom_dst,
    }


# ─────────────────────────────────────────────────────────────────────────────
# TShark command builder
# ─────────────────────────────────────────────────────────────────────────────
def build_tshark_command(
    interface_index: int,
    tshark_path: str = TSHARK_DEFAULT_PATH,
    extra_args: Optional[List[str]] = None,
    include_extended_attack_fields: bool = True,
) -> List[str]:
    """
    Builds the tshark subprocess command list for live streaming capture.

    Parameters
    ----------
    interface_index : 1-based integer from 'tshark -D'.
    tshark_path     : Path to tshark.exe.
    extra_args      : Additional arguments inserted before the field list
                      (e.g. ["-a", "duration:600"] for time-limited tests).
    include_extended_attack_fields : If True, appends transport port, flag, and seq fields
                                     required for reconnaissance and attack detection.
    """
    cmd = [
        str(Path(tshark_path)),
        "-i", str(interface_index),
        "-l",           # Line-buffered output — essential for streaming
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "eth.src",
        "-e", "eth.dst",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "_ws.col.Protocol",
    ]
    if include_extended_attack_fields:
        cmd.extend([
            "-e", "tcp.srcport",
            "-e", "udp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.dstport",
            "-e", "tcp.flags",
            "-e", "tcp.seq",
        ])
    cmd.extend([
        "-E", "separator=\t",
        "-E", "occurrence=f",
    ])
    if extra_args:
        # Insert extra args after the interface flag but before field specs
        # Find the position of '-T' and insert before it
        t_idx = cmd.index("-T")
        for a in reversed(extra_args):
            cmd.insert(t_idx, a)
    return cmd


def _safe_int(val: Optional[str]) -> Optional[int]:
    if not val:
        return None
    try:
        cleaned = val.split(",")[0].strip()
        return int(cleaned) if cleaned else None
    except (ValueError, TypeError):
        return None


def _parse_tshark_line(line: str) -> Optional[_RawPacket]:
    """
    Parses a single tab-separated tshark field output line into a _RawPacket.
    Returns None for malformed or incomplete lines.
    Supports both legacy 8-field format and extended transport format.
    """
    parts = line.rstrip("\r\n").split("\t")
    if len(parts) < 8:
        return None
    _frame_num, time_epoch, frame_len, eth_src, eth_dst, ip_src, ip_dst, protocol = (
        parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6], parts[7]
    )
    try:
        timestamp = float(time_epoch)
        pkt_len = int(frame_len)
    except (ValueError, TypeError):
        return None
    if pkt_len <= 0:
        return None

    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None
    tcp_seq: Optional[int] = None

    if len(parts) > 8:
        tcp_sp = parts[8].strip() if len(parts) > 8 else ""
        udp_sp = parts[9].strip() if len(parts) > 9 else ""
        tcp_dp = parts[10].strip() if len(parts) > 10 else ""
        udp_dp = parts[11].strip() if len(parts) > 11 else ""
        flags_val = parts[12].strip() if len(parts) > 12 else ""
        seq_val = parts[13].strip() if len(parts) > 13 else ""

        src_port = _safe_int(tcp_sp) if tcp_sp else _safe_int(udp_sp)
        dst_port = _safe_int(tcp_dp) if tcp_dp else _safe_int(udp_dp)
        tcp_flags = flags_val if flags_val else None
        tcp_seq = _safe_int(seq_val) if seq_val else None

    return _RawPacket(
        timestamp=timestamp,
        packet_size=pkt_len,
        eth_src=eth_src.lower().strip() if eth_src else "",
        eth_dst=eth_dst.lower().strip() if eth_dst else "",
        ip_src=ip_src.strip() if ip_src else "",
        ip_dst=ip_dst.strip() if ip_dst else "",
        protocol=protocol.strip() if protocol else "UNKNOWN",
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        tcp_seq=tcp_seq,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main streaming extractor class
# ─────────────────────────────────────────────────────────────────────────────
class LiveStreamExtractor:
    """
    Reads a live TShark packet stream, accumulates packets into 1-second
    epoch bins per registered node, and emits completed feature windows.

    Usage (in a background thread)
    --------------------------------
    extractor = LiveStreamExtractor(interface_index=1)
    extractor.start()
    for window in extractor.iter_windows():
        # window is a dict with all feature columns + metadata
        process(window)
    extractor.stop()

    Alternatively, run extractor.stream_forever(callback) which calls
    callback(window_dict) for each completed window.
    """

    def __init__(
        self,
        interface_index: int,
        device_registry: Optional[Dict[str, Dict[str, str]]] = None,
        tshark_path: str = TSHARK_DEFAULT_PATH,
        direction: str = "uplink",
        tshark_extra_args: Optional[List[str]] = None,
        max_packet_buffer: int = 5000,
    ) -> None:
        """
        Parameters
        ----------
        interface_index  : 1-based TShark interface index.
        device_registry  : MAC → node metadata dict. Defaults to
                           DEFAULT_DEVICE_REGISTRY if None.
        tshark_path      : Path to tshark.exe.
        direction        : 'uplink', 'downlink', or 'both'. Only packets
                           matching this direction are included in features.
        tshark_extra_args: Extra tshark flags, e.g. ["-a", "duration:60"].
        max_packet_buffer: Maximum capacity of the un-drained packet observation buffer.
        """
        self.interface_index = interface_index
        self._registry_lock = threading.Lock()
        self.registry: Dict[str, Dict[str, str]] = self._normalize_registry(
            device_registry if device_registry is not None
            else dict(DEFAULT_DEVICE_REGISTRY)
        )
        self.tshark_path = tshark_path
        self.direction = direction
        self.tshark_extra_args = tshark_extra_args or []
        self.max_packet_buffer = max_packet_buffer

        # State
        self._proc: Optional[subprocess.Popen] = None
        self._stderr_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Accumulation buffers: mac → list of packets in current bin
        # Each entry: {"bin_start": float, "node_id": str, "node_info": dict, "packets": list}
        self._bins: Dict[str, Dict[str, Any]] = {}

        # Statistics counters
        self.stats: Dict[str, int] = {
            "packets_parsed": 0,
            "packets_attributed": 0,
            "packets_unregistered": 0,
            "packets_infrastructure": 0,
            "windows_emitted": 0,
            "packets_dropped_buffer_overflow": 0,
        }

        # Set of unregistered MACs encountered (for unknown-device alert generation)
        self.unregistered_macs: Set[str] = set()
        # Lock for thread-safe access to unregistered_macs
        self._unreg_lock = threading.Lock()

        # Bounded buffer of individual packet observations for attack detection
        self._recent_packet_observations: List[PacketObservation] = []
        self._pkt_lock = threading.Lock()
        self._dropped_packet_count: int = 0
        self._telemetry_degraded: bool = False

    def start(self) -> None:
        """Launches the tshark subprocess. Call before iter_windows()."""
        if self._proc is not None:
            raise RuntimeError("LiveStreamExtractor already started.")
        cmd = build_tshark_command(
            self.interface_index,
            tshark_path=self.tshark_path,
            extra_args=self.tshark_extra_args,
        )
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,  # line-buffered
        )
        self._stop_event.clear()

        # Dedicated daemon thread to drain stderr continuously to prevent pipe buffer deadlock
        def _drain_stderr(proc: subprocess.Popen) -> None:
            try:
                if proc.stderr is not None:
                    for line in iter(proc.stderr.readline, ""):
                        if not line:
                            break
            except Exception:
                pass
            finally:
                if proc.stderr is not None:
                    try:
                        proc.stderr.close()
                    except Exception:
                        pass

        self._stderr_thread = threading.Thread(
            target=_drain_stderr,
            args=(self._proc,),
            daemon=True,
            name="TSharkStderrDrainer",
        )
        self._stderr_thread.start()

        # Register exit hook to prevent orphan / zombie processes on unexpected interpreter exit
        try:
            atexit.register(self.stop)
        except Exception:
            pass

    def stop(self) -> None:
        """Signals the extractor to stop and terminates tshark and child processes (dumpcap)."""
        self._stop_event.set()
        if self._proc is not None:
            proc = self._proc
            self._proc = None
            try:
                # On Windows, kill entire process tree (/T) to ensure child dumpcap.exe is terminated
                if sys.platform == "win32" and hasattr(proc, "pid") and proc.pid:
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                        capture_output=True,
                        timeout=5,
                    )
                else:
                    proc.terminate()
                    proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        try:
            atexit.unregister(self.stop)
        except Exception:
            pass

        self._stderr_thread = None

    @property
    def is_running(self) -> bool:
        """True while the tshark subprocess is alive and stop not requested."""
        if self._stop_event.is_set():
            return False
        if self._proc is None:
            return False
        return self._proc.poll() is None

    @staticmethod
    def _normalize_mac_addr(mac: Optional[str]) -> Optional[str]:
        """Standardizes a MAC address string to lowercase colon-separated hex."""
        if not mac:
            return None
        return str(mac).strip().lower().replace("-", ":")

    @classmethod
    def _normalize_registry(cls, raw_registry: Optional[Dict[str, Dict[str, Any]]]) -> Dict[str, Dict[str, str]]:
        """
        Validates and standardizes a raw registry mapping.
        Guarantees:
          - MAC keys are normalized (lowercase, colons, stripped).
          - Duplicate MAC representations map to the same key safely.
          - Missing or invalid node_id entries are excluded.
          - Partially specified metadata dictionaries receive defaults.
        """
        if not raw_registry:
            return {}
        clean: Dict[str, Dict[str, str]] = {}
        for raw_mac, info in raw_registry.items():
            norm_mac = cls._normalize_mac_addr(raw_mac)
            if not norm_mac or not isinstance(info, dict):
                continue
            node_id = info.get("node_id")
            if not node_id:
                continue
            clean_info: Dict[str, str] = {
                "node_id": str(node_id).strip(),
                "device_type": str(info.get("device_type", "Phone_Client")).strip(),
                "label": str(info.get("label", "real_observed_traffic")).strip(),
            }
            if "ip" in info and info["ip"]:
                clean_info["ip"] = str(info["ip"]).strip()
            clean[norm_mac] = clean_info
        return clean

    def update_device_registry(self, new_registry: Dict[str, Dict[str, Any]]) -> None:
        """
        Atomically updates the active device registry for the packet processing loop.
        Constructs and validates the normalized registry entirely before taking the lock,
        ensuring packet processing never observes a partially updated state.
        """
        clean = self._normalize_registry(new_registry)
        with self._registry_lock:
            self.registry = clean

    def update_registry(self, new_registry: Dict[str, Dict[str, Any]]) -> None:
        """Alias for update_device_registry."""
        self.update_device_registry(new_registry)

    def get_device_registry(self) -> Dict[str, Dict[str, str]]:
        """Returns a thread-safe copy of the active device registry."""
        with self._registry_lock:
            return {k: dict(v) for k, v in self.registry.items()}

    def _flush_bin(self, mac: str) -> Optional[Dict[str, Any]]:
        """
        Finalises the current 1-second bin for ``mac`` and computes features.
        Returns a feature dict, or None if the bin is empty and should be skipped.
        """
        entry = self._bins.pop(mac, None)
        if entry is None:
            return None
        pkts = entry["packets"]
        if not pkts:
            return None  # sparse — omit empty windows (matches offline extractor default)

        pkts.sort(key=lambda p: p.timestamp)
        window = _compute_1s_window_features(
            node_id=entry["node_id"],
            node_info=entry["node_info"],
            client_mac=mac,
            bin_start=entry["bin_start"],
            packets=pkts,
        )
        self.stats["windows_emitted"] += 1
        return window

    def _get_or_create_bin(
        self, mac: str, node_id: str, node_info: Dict[str, str], bin_start: float
    ) -> None:
        """Ensures a bin exists for (mac, bin_start); creates if absent."""
        if mac not in self._bins:
            self._bins[mac] = {
                "bin_start": bin_start,
                "node_id": node_id,
                "node_info": node_info,
                "packets": [],
            }

    def _record_unknown_mac(self, mac: str) -> None:
        """Thread-safely records an unregistered MAC for alerting."""
        with self._unreg_lock:
            self.unregistered_macs.add(mac)

    def iter_windows(self) -> Iterator[Dict[str, Any]]:
        """
        Iterates over completed 1-second feature windows from the live stream.

        Yields one dict per completed window. Raises StopIteration when the
        tshark process exits or stop() is called.

        The caller must have called start() beforehand.
        """
        if self._proc is None:
            raise RuntimeError("Call start() before iter_windows().")

        stdout = self._proc.stdout
        assert stdout is not None

        for raw_line in stdout:
            if self._stop_event.is_set():
                break

            pkt = _parse_tshark_line(raw_line)
            if pkt is None:
                continue

            self.stats["packets_parsed"] += 1

            # Accumulate PacketObservation for attack detection engine
            obs = pkt.to_observation()
            with self._pkt_lock:
                if len(self._recent_packet_observations) >= self.max_packet_buffer:
                    # Explicitly account for dropped packets due to buffer overflow
                    excess = (len(self._recent_packet_observations) - self.max_packet_buffer) + 1
                    del self._recent_packet_observations[:excess]
                    self._dropped_packet_count += excess
                    self.stats["packets_dropped_buffer_overflow"] += excess
                    self._telemetry_degraded = True
                self._recent_packet_observations.append(obs)

            # Attribute to a registered node
            with self._registry_lock:
                current_registry = self.registry
            node_id, node_info, direction = _attribute_packet(pkt, current_registry)

            if direction == "infrastructure":
                self.stats["packets_infrastructure"] += 1
                continue

            if node_id is None:
                self.stats["packets_unregistered"] += 1
                # Record unregistered MAC for unknown-device alert generation
                # In uplink mode, the transmitting client is eth_src
                if pkt.eth_src and not _is_broadcast_or_multicast(pkt.eth_src) and pkt.ip_src != "192.168.137.1":
                    self._record_unknown_mac(pkt.eth_src)
                elif pkt.eth_dst and not _is_broadcast_or_multicast(pkt.eth_dst) and pkt.ip_dst != "192.168.137.1" and self.direction == "downlink":
                    self._record_unknown_mac(pkt.eth_dst)
                continue

            # Apply direction filter
            if self.direction != "both" and direction != self.direction:
                continue

            assert node_info is not None
            self.stats["packets_attributed"] += 1

            # Determine 1-second bin
            bin_start = float(math.floor(pkt.timestamp))
            mac = pkt.eth_src if direction == "uplink" else pkt.eth_dst

            existing = self._bins.get(mac)
            if existing is not None and existing["bin_start"] != bin_start:
                # Current packet belongs to a NEW bin; flush the old one
                window = self._flush_bin(mac)
                if window is not None:
                    yield window

            self._get_or_create_bin(mac, node_id, node_info, bin_start)
            self._bins[mac]["packets"].append(pkt)

        # Flush all open bins when the stream ends
        for mac in list(self._bins.keys()):
            window = self._flush_bin(mac)
            if window is not None:
                yield window

    def drain_unregistered_macs(self) -> Set[str]:
        """
        Returns and clears the set of unregistered MACs seen so far.
        Thread-safe.
        """
        with self._unreg_lock:
            seen = set(self.unregistered_macs)
            self.unregistered_macs.clear()
        return seen

    def get_buffer_telemetry_status(self) -> Dict[str, Any]:
        """
        Returns telemetry integrity status of the packet observation stream buffer.
        Guarantees honest reporting: indicates if buffer overflow occurred and drops were incurred.
        """
        with self._pkt_lock:
            buffered = len(self._recent_packet_observations)
            dropped = self._dropped_packet_count
            degraded = self._telemetry_degraded
        return {
            "buffered_packets": buffered,
            "dropped_packets": dropped,
            "is_lossless": (dropped == 0),
            "telemetry_degraded": degraded,
            "max_buffer_size": self.max_packet_buffer,
        }

    def drain_recent_packets(self) -> List[PacketObservation]:
        """
        Atomically returns and clears all packet observations accumulated since the last drain.
        Guarantees that each packet observation is returned at most once (lossless under normal capacity).
        Thread-safe.
        """
        with self._pkt_lock:
            if not self._recent_packet_observations:
                return []
            pkts = list(self._recent_packet_observations)
            self._recent_packet_observations.clear()
            return pkts
