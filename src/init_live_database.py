"""
Live Database Initialiser
File: src/init_live_database.py

Purpose:
  Creates and initialises the isolated live monitoring SQLite database
  (data/live_monitoring.db).  This file is separate from the production
  database (data/iot_anomaly.db) and is never used by src/dashboard.py.

Database Design:
  - WAL journal mode for safe concurrent reads (Streamlit) and writes
    (collector threads) without exclusive locking.
  - Seven tables covering the full live pipeline:
    1. collector_status   — heartbeat / health record for each collector run.
    2. device_registry    — known Wi-Fi node metadata (operator-curated).
    3. live_traffic_windows — 1-second feature windows per node.
    4. live_alerts        — dual-detector anomaly flags requiring investigation.
    5. unknown_device_obs — unregistered MACs flagged for operator review.
    6. live_sensor_telemetry — DHT11 temperature/humidity readings (Node_1).
    7. live_pir_events    — PIR motion state snapshots (Node_2).

  Logical Sensor Node Convention:
    The physical ESP32 board emits a single combined JSON record containing
    both DHT11 and PIR fields.  The ingestion layer maps them to two logical
    nodes in the database:
      Node_1  → live_sensor_telemetry (temperature_c, humidity_pct, dht_valid)
      Node_2  → live_pir_events       (motion_detected)
    Both rows share the same physical_node_id ('esp32_gateway') and
    sequence_num from the firmware, enabling later correlation.

Safety:
  - Raises FileExistsError (with guidance) if the database already exists
    and --overwrite is not passed.
  - Never touches data/iot_anomaly.db or any production file.
  - Safe to call multiple times: all CREATE statements use IF NOT EXISTS.
"""

import argparse
import sqlite3
import sys
from pathlib import Path
from typing import Any, Union

# ─────────────────────────────────────────────────────────────────────────────
# Default path — isolated from production DB
# ─────────────────────────────────────────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LIVE_DB_PATH = _PROJECT_ROOT / "data" / "live_monitoring.db"

PRODUCTION_DB_PATH = _PROJECT_ROOT / "data" / "iot_anomaly.db"


# ─────────────────────────────────────────────────────────────────────────────
# Schema SQL — all tables with IF NOT EXISTS guards
# ─────────────────────────────────────────────────────────────────────────────
_SCHEMA_PRAGMAS = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;
PRAGMA foreign_keys = ON;
"""

_SCHEMA_TABLES = """
-- ─── 1. Collector heartbeat / status ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS collector_status (
    run_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_heartbeat  DATETIME,
    interface_index INTEGER,
    interface_name  TEXT,
    serial_port     TEXT,
    status          TEXT NOT NULL DEFAULT 'STARTING',
        -- Values: STARTING, RUNNING, STOPPED, ERROR
    stop_reason     TEXT,
    packets_parsed  INTEGER DEFAULT 0,
    windows_emitted INTEGER DEFAULT 0,
    sensor_records  INTEGER DEFAULT 0
);

-- ─── 2. Registered device registry ──────────────────────────────────────────
-- Each row represents a known Wi-Fi node (Node_3, Node_4, Node_5).
-- Sensor logical nodes (Node_1, Node_2) are NOT tracked here;
-- they share the physical ESP32 and never appear on the Wi-Fi interface.
CREATE TABLE IF NOT EXISTS device_registry (
    mac_address TEXT PRIMARY KEY,
    node_id     TEXT NOT NULL,
    device_type TEXT NOT NULL DEFAULT 'Phone_Client',
    label       TEXT NOT NULL DEFAULT 'real_observed_traffic',
    last_seen   DATETIME,
    notes       TEXT
);

-- ─── 3. Live 1-second traffic feature windows ───────────────────────────────
CREATE TABLE IF NOT EXISTS live_traffic_windows (
    window_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id              INTEGER,
    client_mac          TEXT NOT NULL,
    node_id             TEXT NOT NULL,
    node_type           TEXT,
    data_label          TEXT,
    bin_start_epoch     REAL NOT NULL,
    bin_end_epoch       REAL NOT NULL,
    window_center_epoch REAL,
    window_start_utc    TEXT,
    window_end_utc      TEXT,
    packet_count        INTEGER NOT NULL,
    mean_IAT            REAL,
    IAT_std             REAL,
    packet_rate         REAL NOT NULL,
    mean_packet_size    REAL,
    packet_size_std     REAL,
    score_primary       REAL,
    pred_primary        INTEGER,    -- -1 anomaly / +1 normal (IF convention)
    score_timing        REAL,
    pred_timing         INTEGER,    -- -1 / +1 or NULL when timing unavailable
    timing_status       TEXT,       -- 'ACTIVE' | 'UNAVAILABLE_N_LT_3'
    pred_dual           INTEGER,    -- -1 anomaly / +1 normal
    dual_reason         TEXT,
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (run_id) REFERENCES collector_status(run_id)
);
CREATE INDEX IF NOT EXISTS idx_ltw_run_node
    ON live_traffic_windows(run_id, node_id);
CREATE INDEX IF NOT EXISTS idx_ltw_bin_start
    ON live_traffic_windows(bin_start_epoch);

-- ─── 4. Anomaly alerts ───────────────────────────────────────────────────────
-- One row per dual-detector anomaly flag. Flagged windows are statistical
-- deviations from Session 1; they are NOT confirmed cyberattacks.
CREATE TABLE IF NOT EXISTS live_alerts (
    alert_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    window_id       INTEGER NOT NULL,
    run_id          INTEGER,
    client_mac      TEXT NOT NULL,
    node_id         TEXT NOT NULL,
    bin_start_epoch REAL NOT NULL,
    window_start_utc TEXT,
    dual_reason     TEXT NOT NULL,
    score_primary   REAL,
    score_timing    REAL,
    packet_rate     REAL,
    mean_packet_size REAL,
    packet_count    INTEGER,
    acknowledged    INTEGER DEFAULT 0,  -- 0=pending, 1=acknowledged by operator
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (window_id) REFERENCES live_traffic_windows(window_id),
    FOREIGN KEY (run_id)    REFERENCES collector_status(run_id)
);
CREATE INDEX IF NOT EXISTS idx_alerts_run
    ON live_alerts(run_id, created_at);

-- ─── 5. Unknown / unregistered device observations ──────────────────────────
-- Any MAC not found in device_registry triggers one row here.
-- IMPORTANT: Do NOT assume these are malicious. Randomised MACs from modern
-- mobile OS privacy features will also appear here.
CREATE TABLE IF NOT EXISTS unknown_device_obs (
    obs_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER,
    observed_mac    TEXT NOT NULL,
    first_seen_utc  DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen_utc   DATETIME DEFAULT CURRENT_TIMESTAMP,
    observation_count INTEGER DEFAULT 1,
    acknowledged    INTEGER DEFAULT 0,
    UNIQUE(run_id, observed_mac),
    FOREIGN KEY (run_id) REFERENCES collector_status(run_id)
);

-- ─── 6. Live DHT11 sensor telemetry (logical Node_1) ────────────────────────
CREATE TABLE IF NOT EXISTS live_sensor_telemetry (
    telemetry_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER,
    physical_node_id TEXT NOT NULL DEFAULT 'esp32_gateway',
    logical_node_id  TEXT NOT NULL DEFAULT 'Node_1',
    sequence_num    INTEGER NOT NULL,
    uptime_ms       INTEGER NOT NULL,
    temperature_c   REAL,       -- NULL if DHT11 read failed
    humidity_pct    REAL,       -- NULL if DHT11 read failed
    dht_valid       INTEGER NOT NULL DEFAULT 0,  -- 1 = valid reading
    captured_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    sensor_epoch    REAL,
    UNIQUE(run_id, physical_node_id, sequence_num),
    FOREIGN KEY (run_id) REFERENCES collector_status(run_id)
);
CREATE INDEX IF NOT EXISTS idx_sensor_run
    ON live_sensor_telemetry(run_id, captured_at);

-- ─── 7. Live PIR motion events (logical Node_2) ──────────────────────────────
CREATE TABLE IF NOT EXISTS live_pir_events (
    pir_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER,
    physical_node_id TEXT NOT NULL DEFAULT 'esp32_gateway',
    logical_node_id  TEXT NOT NULL DEFAULT 'Node_2',
    sequence_num    INTEGER NOT NULL,
    uptime_ms       INTEGER NOT NULL,
    motion_detected INTEGER NOT NULL,   -- 0 = clear, 1 = motion
    captured_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    sensor_epoch    REAL,
    UNIQUE(run_id, physical_node_id, sequence_num),
    FOREIGN KEY (run_id) REFERENCES collector_status(run_id)
);
CREATE INDEX IF NOT EXISTS idx_pir_run
    ON live_pir_events(run_id, captured_at);

-- ─── 8. Live attack detection events ─────────────────────────────────────────
-- Holds explainable evaluations from the NetworkAttackDetector engine.
-- Strictly decoupled from live_alerts (which holds statistical IF anomalies).
CREATE TABLE IF NOT EXISTS live_attack_events (
    event_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id              INTEGER,
    window_id           INTEGER,             -- References live_traffic_windows(window_id), nullable
    timestamp_epoch     REAL NOT NULL,
    timestamp_utc       TEXT NOT NULL,
    category            TEXT NOT NULL,       -- Denial_of_Service, Reconnaissance_Port_Scan, Spoofing_Impersonation, Deauthentication_Disassociation_Abuse, Replay_Attack
    status              TEXT NOT NULL,       -- NO_EVIDENCE, INSUFFICIENT_TELEMETRY, SUSPICIOUS, CONFIRMED_THREAT
    severity            TEXT NOT NULL,       -- NONE, INFO, LOW, MEDIUM, HIGH, CRITICAL
    confidence          REAL NOT NULL,       -- Float 0.0 to 1.0
    source_mac          TEXT,
    target_ip           TEXT,
    evidence_json       TEXT NOT NULL,       -- Structured JSON evidence dictionary
    missing_fields_json TEXT,                -- JSON list of missing fields when INSUFFICIENT_TELEMETRY
    recommended_action  TEXT,
    acknowledged        INTEGER DEFAULT 0,  -- Operator review flag (0 = pending, 1 = verified)
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (run_id) REFERENCES collector_status(run_id),
    FOREIGN KEY (window_id) REFERENCES live_traffic_windows(window_id)
);
CREATE INDEX IF NOT EXISTS idx_attack_run_cat
    ON live_attack_events(run_id, category, status);
CREATE INDEX IF NOT EXISTS idx_attack_timestamp
    ON live_attack_events(timestamp_epoch);

-- ─── 9. Durable local cloud sync outbox ─────────────────────────────────────
-- Holds asynchronous staged payloads destined for Supabase Cloud.
-- Local SQLite remains authoritative. Failures never block local monitoring.
CREATE TABLE IF NOT EXISTS cloud_sync_outbox (
    outbox_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    event_uuid          TEXT UNIQUE NOT NULL,
    table_name          TEXT NOT NULL,
    operation           TEXT NOT NULL DEFAULT 'INSERT',
    priority_tier       INTEGER NOT NULL DEFAULT 3,
    payload_json        TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'PENDING',
    retry_count         INTEGER NOT NULL DEFAULT 0,
    max_retries         INTEGER NOT NULL DEFAULT 10,
    next_retry_at       REAL NOT NULL,
    last_attempt_at     REAL,
    last_error          TEXT,
    delivered_at        REAL,
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_outbox_queue 
    ON cloud_sync_outbox(status, priority_tier, next_retry_at);
CREATE INDEX IF NOT EXISTS idx_outbox_uuid 
    ON cloud_sync_outbox(event_uuid);
"""


def _safety_check(db_path: Any) -> None:
    """
    Refuses to operate on the production database.
    Raises RuntimeError if the resolved path matches iot_anomaly.db.
    """
    resolved = Path(db_path).resolve()
    prod_resolved = PRODUCTION_DB_PATH.resolve()
    if resolved == prod_resolved:
        raise RuntimeError(
            "SAFETY GUARD: Attempted to initialise the PRODUCTION database "
            f"({prod_resolved}) as a live monitoring database. "
            "Use a separate path such as data/live_monitoring.db."
        )


# ─────────────────────────────────────────────────────────────────────────────
# Default Known Device Profiles (Reference for Hotspot Clients)
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_KNOWN_DEVICES = [
    {
        "mac_address": "ca:34:ea:92:d3:9e",
        "node_id": "Node_3",
        "device_type": "Phone_Client",
        "label": "real_observed_traffic",
        "notes": "Phone 1 (verified hotspot client)",
    },
    {
        "mac_address": "e6:2e:db:73:1c:25",
        "node_id": "Node_4",
        "device_type": "Phone_Client",
        "label": "real_observed_traffic",
        "notes": "Phone 2 (verified hotspot client)",
    },
    {
        "mac_address": "00:00:00:00:00:05",
        "node_id": "Node_5",
        "device_type": "Phone_Client",
        "label": "reserved_demo",
        "notes": "Phone 3 (reserved for live demonstration — unobserved until connection)",
    },
]


def register_device(
    conn: sqlite3.Connection,
    mac_address: str,
    node_id: str,
    device_type: str = "Phone_Client",
    label: str = "real_observed_traffic",
    notes: str = "",
) -> None:
    """
    Safely registers or updates a device in device_registry.
    Does not touch production databases.
    """
    mac = mac_address.lower().strip()
    conn.execute(
        """
        INSERT INTO device_registry (mac_address, node_id, device_type, label, notes)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(mac_address) DO UPDATE SET
            node_id = excluded.node_id,
            device_type = excluded.device_type,
            label = excluded.label,
            notes = excluded.notes
        """,
        (mac, node_id, device_type, label, notes),
    )
    conn.commit()


def seed_default_devices(conn: sqlite3.Connection) -> int:
    """
    Seeds default known devices (Node_3, Node_4, Node_5 reserved) into device_registry
    if they are not already present. Returns count of devices registered.
    """
    count = 0
    for dev in DEFAULT_KNOWN_DEVICES:
        cur = conn.execute(
            """
            INSERT OR IGNORE INTO device_registry (mac_address, node_id, device_type, label, notes)
            VALUES (?, ?, ?, ?, ?)
            """,
            (dev["mac_address"], dev["node_id"], dev["device_type"], dev["label"], dev["notes"]),
        )
        if cur.rowcount > 0:
            count += 1
    conn.commit()
    return count


def init_live_database(
    db_path: Path = DEFAULT_LIVE_DB_PATH,
    overwrite: bool = False,
    seed_defaults: bool = False,
) -> Path:
    """
    Creates (or re-initialises) the live monitoring SQLite database.

    Parameters
    ----------
    db_path       : Target database path. Must not point to iot_anomaly.db.
    overwrite     : If True, deletes the existing database before creating.
                    If False and the file exists, raises FileExistsError.
    seed_defaults : If True, seeds DEFAULT_KNOWN_DEVICES into device_registry.

    Returns
    -------
    The resolved path to the created database.

    Raises
    ------
    RuntimeError   : If db_path resolves to the production database.
    FileExistsError: If the database already exists and overwrite=False.
    """
    db_path = Path(db_path)
    _safety_check(db_path)

    if db_path.exists():
        if overwrite:
            db_path.unlink()
            print(f"[INIT] Existing database removed (overwrite=True): {db_path}")
        else:
            raise FileExistsError(
                f"Live monitoring database already exists: {db_path}\n"
                "Pass overwrite=True (or --overwrite on the CLI) to reinitialise."
            )

    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path))
    try:
        # Apply pragmas (WAL, sync, FK) — must be run as individual statements
        for pragma in _SCHEMA_PRAGMAS.strip().split(";"):
            pragma = pragma.strip()
            if pragma:
                conn.execute(pragma)

        # Create all tables atomically
        conn.executescript(_SCHEMA_TABLES)

        if seed_defaults:
            seeded = seed_default_devices(conn)
            print(f"[INIT] Seeded {seeded} default devices into device_registry.")

        conn.commit()

        print(f"[INIT] Live monitoring database initialised: {db_path}")
        print("[INIT] Tables created:")
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        for row in cur.fetchall():
            print(f"       - {row[0]}")

    finally:
        conn.close()

    return db_path.resolve()


def get_live_db_connection(
    db_path: Path = DEFAULT_LIVE_DB_PATH,
    read_only: bool = False,
) -> sqlite3.Connection:
    """
    Opens a connection to the live monitoring database.

    Parameters
    ----------
    db_path   : Path to live_monitoring.db.
    read_only : If True, opens in URI read-only mode (safe for dashboard reads).

    Returns
    -------
    sqlite3.Connection with WAL pragma and 10-second busy timeout.
    """
    db_path = Path(db_path)
    _safety_check(db_path)

    if read_only:
        uri = f"file:{db_path.as_posix()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=10.0)
    else:
        conn = sqlite3.connect(str(db_path), timeout=10.0)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous  = NORMAL;")
        conn.execute("PRAGMA foreign_keys = ON;")

    conn.row_factory = sqlite3.Row
    return conn


def migrate_live_database(db_path: Path = DEFAULT_LIVE_DB_PATH) -> bool:
    """
    Safely applies missing schema objects (such as live_attack_events table and indexes)
    to an existing database without modifying or deleting any existing rows.
    Returns True upon successful non-destructive migration.
    """
    db_path = Path(db_path)
    _safety_check(db_path)
    if not db_path.exists():
        init_live_database(db_path)
        return True

    conn = get_live_db_connection(db_path)
    try:
        conn.executescript(_SCHEMA_TABLES)
        conn.commit()
    finally:
        conn.close()
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Initialise the isolated live monitoring SQLite database and manage device registry."
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=str(DEFAULT_LIVE_DB_PATH),
        help=f"Path to the live monitoring database (default: {DEFAULT_LIVE_DB_PATH})",
    )
    parser.add_argument(
        "--migrate",
        action="store_true",
        help="Safely apply missing tables/indexes (such as live_attack_events) to an existing database without modifying existing data.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Delete and recreate the database if it already exists.",
    )
    parser.add_argument(
        "--seed-defaults",
        action="store_true",
        help="Seed default known devices (Node_3, Node_4, Node_5) on database creation.",
    )
    parser.add_argument(
        "--register-defaults",
        action="store_true",
        help="Safely register default known devices into an existing database without modifying other tables.",
    )
    parser.add_argument(
        "--register-mac",
        type=str,
        help="Register or update a specific client MAC address.",
    )
    parser.add_argument(
        "--node-id",
        type=str,
        help="Logical node ID for the registered MAC (e.g. Node_5).",
    )
    parser.add_argument(
        "--device-type",
        type=str,
        default="Phone_Client",
        help="Device type (default: Phone_Client).",
    )
    parser.add_argument(
        "--notes",
        type=str,
        default="",
        help="Optional notes describing the registered device.",
    )
    args = parser.parse_args()

    db_path = Path(args.db_path)

    # 0. Action: Non-destructive schema migration
    if args.migrate:
        _safety_check(db_path)
        migrate_live_database(db_path)
        print(f"[MIGRATE] Safe schema migration completed at: {db_path.resolve()}")
        return

    # 1. Action: Register defaults into existing database
    if args.register_defaults:
        _safety_check(db_path)
        if not db_path.exists():
            init_live_database(db_path=db_path, seed_defaults=True)
            print(f"[READY] Created database and registered defaults at: {db_path.resolve()}")
            return
        conn = get_live_db_connection(db_path)
        try:
            seeded = seed_default_devices(conn)
            print(f"[REGISTRY] Registered {seeded} default devices into: {db_path.resolve()}")
        finally:
            conn.close()
        return

    # 2. Action: Register single device
    if args.register_mac:
        if not args.node_id:
            print("[ERROR] --node-id is required when --register-mac is specified.", file=sys.stderr)
            sys.exit(1)
        _safety_check(db_path)
        if not db_path.exists():
            init_live_database(db_path=db_path)
        conn = get_live_db_connection(db_path)
        try:
            register_device(
                conn=conn,
                mac_address=args.register_mac,
                node_id=args.node_id,
                device_type=args.device_type,
                notes=args.notes,
            )
            print(f"[REGISTRY] Registered {args.register_mac} as {args.node_id} in: {db_path.resolve()}")
        finally:
            conn.close()
        return

    # 3. Action: Standard init_live_database
    try:
        resolved = init_live_database(
            db_path=db_path,
            overwrite=args.overwrite,
            seed_defaults=args.seed_defaults,
        )
        print(f"\n[READY] Live monitoring database is ready at: {resolved}")
    except FileExistsError as e:
        print(f"\n[ERROR] {e}", file=sys.stderr)
        sys.exit(1)
    except RuntimeError as e:
        print(f"\n[SAFETY ERROR] {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()

