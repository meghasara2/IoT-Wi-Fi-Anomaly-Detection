import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable, CreateIndex

metadata = sa.MetaData()

# 1. collector_status
collector_status = sa.Table(
    'collector_status', metadata,
    sa.Column('run_id', sa.BigInteger, sa.Identity(start=1, cycle=False), primary_key=True),
    sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.text('clock_timestamp()'), nullable=False),
    sa.Column('last_heartbeat', sa.DateTime(timezone=True), nullable=True),
    sa.Column('interface_index', sa.Integer, nullable=True),
    sa.Column('interface_name', sa.Text, nullable=True),
    sa.Column('serial_port', sa.Text, nullable=True),
    sa.Column('status', sa.Text, server_default='STARTING', nullable=False),
    sa.Column('stop_reason', sa.Text, nullable=True),
    sa.Column('packets_parsed', sa.BigInteger, server_default=sa.text('0'), nullable=False),
    sa.Column('windows_emitted', sa.BigInteger, server_default=sa.text('0'), nullable=False),
    sa.Column('sensor_records', sa.BigInteger, server_default=sa.text('0'), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('clock_timestamp()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('clock_timestamp()'), nullable=False),
    sa.CheckConstraint("status IN ('STARTING', 'RUNNING', 'STOPPED', 'ERROR')", name='chk_collector_status')
)

# 2. device_registry
device_registry = sa.Table(
    'device_registry', metadata,
    sa.Column('mac_address', sa.Text, primary_key=True),
    sa.Column('node_id', sa.Text, nullable=False),
    sa.Column('device_type', sa.Text, server_default='Phone_Client', nullable=False),
    sa.Column('label', sa.Text, server_default='real_observed_traffic', nullable=False),
    sa.Column('last_seen', sa.DateTime(timezone=True), nullable=True),
    sa.Column('notes', sa.Text, nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('clock_timestamp()'), nullable=False),
    sa.CheckConstraint("mac_address ~* '^([0-9a-f]{2}[:-]){5}([0-9a-f]{2})$'", name='chk_mac_format')
)

# 3. live_traffic_windows
live_traffic_windows = sa.Table(
    'live_traffic_windows', metadata,
    sa.Column('window_id', sa.BigInteger, sa.Identity(start=1, cycle=False), primary_key=True),
    sa.Column('run_id', sa.BigInteger, sa.ForeignKey('collector_status.run_id', ondelete='RESTRICT'), nullable=False),
    sa.Column('client_mac', sa.Text, nullable=False),
    sa.Column('node_id', sa.Text, nullable=False),
    sa.Column('node_type', sa.Text, nullable=True),
    sa.Column('data_label', sa.Text, nullable=True),
    sa.Column('bin_start_epoch', postgresql.DOUBLE_PRECISION, nullable=False),
    sa.Column('bin_end_epoch', postgresql.DOUBLE_PRECISION, nullable=False),
    sa.Column('window_center_epoch', postgresql.DOUBLE_PRECISION, nullable=True),
    sa.Column('window_start_utc', sa.DateTime(timezone=True), nullable=True),
    sa.Column('window_end_utc', sa.DateTime(timezone=True), nullable=True),
    sa.Column('packet_count', sa.Integer, server_default=sa.text('0'), nullable=False),
    sa.Column('mean_IAT', postgresql.DOUBLE_PRECISION, nullable=True),
    sa.Column('IAT_std', postgresql.DOUBLE_PRECISION, nullable=True),
    sa.Column('packet_rate', postgresql.DOUBLE_PRECISION, server_default=sa.text('0.0'), nullable=False),
    sa.Column('mean_packet_size', postgresql.DOUBLE_PRECISION, nullable=True),
    sa.Column('packet_size_std', postgresql.DOUBLE_PRECISION, nullable=True),
    sa.Column('score_primary', postgresql.DOUBLE_PRECISION, nullable=True),
    sa.Column('pred_primary', sa.Integer, nullable=True),
    sa.Column('score_timing', postgresql.DOUBLE_PRECISION, nullable=True),
    sa.Column('pred_timing', sa.Integer, nullable=True),
    sa.Column('timing_status', sa.Text, nullable=True),
    sa.Column('pred_dual', sa.Integer, nullable=True),
    sa.Column('dual_reason', sa.Text, nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('clock_timestamp()'), nullable=False),
    sa.UniqueConstraint('run_id', 'client_mac', 'bin_start_epoch', name='uq_traffic_window_run_mac_epoch'),
    sa.CheckConstraint('pred_primary IN (-1, 1) OR pred_primary IS NULL', name='chk_pred_primary'),
    sa.CheckConstraint('pred_timing IN (-1, 1) OR pred_timing IS NULL', name='chk_pred_timing'),
    sa.CheckConstraint("timing_status IN ('ACTIVE', 'UNAVAILABLE_N_LT_3') OR timing_status IS NULL", name='chk_timing_status'),
    sa.CheckConstraint('pred_dual IN (-1, 1) OR pred_dual IS NULL', name='chk_pred_dual')
)

# 4. live_alerts
live_alerts = sa.Table(
    'live_alerts', metadata,
    sa.Column('alert_id', sa.BigInteger, sa.Identity(start=1, cycle=False), primary_key=True),
    sa.Column('window_id', sa.BigInteger, sa.ForeignKey('live_traffic_windows.window_id', ondelete='RESTRICT'), nullable=False),
    sa.Column('run_id', sa.BigInteger, sa.ForeignKey('collector_status.run_id', ondelete='RESTRICT'), nullable=False),
    sa.Column('client_mac', sa.Text, nullable=False),
    sa.Column('node_id', sa.Text, nullable=False),
    sa.Column('bin_start_epoch', postgresql.DOUBLE_PRECISION, nullable=False),
    sa.Column('window_start_utc', sa.DateTime(timezone=True), nullable=True),
    sa.Column('dual_reason', sa.Text, nullable=False),
    sa.Column('score_primary', postgresql.DOUBLE_PRECISION, nullable=True),
    sa.Column('score_timing', postgresql.DOUBLE_PRECISION, nullable=True),
    sa.Column('packet_rate', postgresql.DOUBLE_PRECISION, nullable=True),
    sa.Column('mean_packet_size', postgresql.DOUBLE_PRECISION, nullable=True),
    sa.Column('packet_count', sa.Integer, nullable=True),
    sa.Column('acknowledged', sa.Integer, server_default=sa.text('0'), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('clock_timestamp()'), nullable=False),
    sa.UniqueConstraint('window_id', name='uq_live_alerts_window'),
    sa.CheckConstraint('acknowledged IN (0, 1)', name='chk_alert_ack')
)

# 5. unknown_device_obs
unknown_device_obs = sa.Table(
    'unknown_device_obs', metadata,
    sa.Column('obs_id', sa.BigInteger, sa.Identity(start=1, cycle=False), primary_key=True),
    sa.Column('run_id', sa.BigInteger, sa.ForeignKey('collector_status.run_id', ondelete='RESTRICT'), nullable=False),
    sa.Column('observed_mac', sa.Text, nullable=False),
    sa.Column('first_seen_utc', sa.DateTime(timezone=True), server_default=sa.text('clock_timestamp()'), nullable=False),
    sa.Column('last_seen_utc', sa.DateTime(timezone=True), server_default=sa.text('clock_timestamp()'), nullable=False),
    sa.Column('observation_count', sa.Integer, server_default=sa.text('1'), nullable=False),
    sa.Column('acknowledged', sa.Integer, server_default=sa.text('0'), nullable=False),
    sa.UniqueConstraint('run_id', 'observed_mac', name='uq_unknown_mac_run'),
    sa.CheckConstraint('acknowledged IN (0, 1)', name='chk_unknown_ack')
)

# 6. live_sensor_telemetry
live_sensor_telemetry = sa.Table(
    'live_sensor_telemetry', metadata,
    sa.Column('telemetry_id', sa.BigInteger, sa.Identity(start=1, cycle=False), primary_key=True),
    sa.Column('run_id', sa.BigInteger, sa.ForeignKey('collector_status.run_id', ondelete='RESTRICT'), nullable=False),
    sa.Column('physical_node_id', sa.Text, server_default='esp32_gateway', nullable=False),
    sa.Column('logical_node_id', sa.Text, server_default='Node_1', nullable=False),
    sa.Column('sequence_num', sa.Integer, nullable=False),
    sa.Column('uptime_ms', sa.BigInteger, nullable=False),
    sa.Column('temperature_c', postgresql.DOUBLE_PRECISION, nullable=True),
    sa.Column('humidity_pct', postgresql.DOUBLE_PRECISION, nullable=True),
    sa.Column('dht_valid', sa.Integer, server_default=sa.text('0'), nullable=False),
    sa.Column('captured_at', sa.DateTime(timezone=True), server_default=sa.text('clock_timestamp()'), nullable=False),
    sa.Column('sensor_epoch', postgresql.DOUBLE_PRECISION, nullable=True),
    sa.UniqueConstraint('run_id', 'physical_node_id', 'sequence_num', name='uq_sensor_telemetry'),
    sa.CheckConstraint('dht_valid IN (0, 1)', name='chk_dht_valid')
)

# 7. live_pir_events
live_pir_events = sa.Table(
    'live_pir_events', metadata,
    sa.Column('pir_id', sa.BigInteger, sa.Identity(start=1, cycle=False), primary_key=True),
    sa.Column('run_id', sa.BigInteger, sa.ForeignKey('collector_status.run_id', ondelete='RESTRICT'), nullable=False),
    sa.Column('physical_node_id', sa.Text, server_default='esp32_gateway', nullable=False),
    sa.Column('logical_node_id', sa.Text, server_default='Node_2', nullable=False),
    sa.Column('sequence_num', sa.Integer, nullable=False),
    sa.Column('uptime_ms', sa.BigInteger, nullable=False),
    sa.Column('motion_detected', sa.Integer, nullable=False),
    sa.Column('captured_at', sa.DateTime(timezone=True), server_default=sa.text('clock_timestamp()'), nullable=False),
    sa.Column('sensor_epoch', postgresql.DOUBLE_PRECISION, nullable=True),
    sa.UniqueConstraint('run_id', 'physical_node_id', 'sequence_num', name='uq_pir_events'),
    sa.CheckConstraint('motion_detected IN (0, 1)', name='chk_pir_motion')
)

# 8. live_attack_events
live_attack_events = sa.Table(
    'live_attack_events', metadata,
    sa.Column('event_id', sa.BigInteger, sa.Identity(start=1, cycle=False), primary_key=True),
    sa.Column('run_id', sa.BigInteger, sa.ForeignKey('collector_status.run_id', ondelete='RESTRICT'), nullable=False),
    sa.Column('window_id', sa.BigInteger, sa.ForeignKey('live_traffic_windows.window_id', ondelete='SET NULL'), nullable=True),
    sa.Column('timestamp_epoch', postgresql.DOUBLE_PRECISION, nullable=False),
    sa.Column('timestamp_utc', sa.DateTime(timezone=True), nullable=False),
    sa.Column('category', sa.Text, nullable=False),
    sa.Column('status', sa.Text, nullable=False),
    sa.Column('severity', sa.Text, nullable=False),
    sa.Column('confidence', postgresql.DOUBLE_PRECISION, nullable=False),
    sa.Column('source_mac', sa.Text, nullable=True),
    sa.Column('target_ip', sa.Text, nullable=True),
    sa.Column('evidence_json', postgresql.JSONB, server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('missing_fields_json', postgresql.JSONB, server_default=sa.text("'[]'::jsonb"), nullable=True),
    sa.Column('recommended_action', sa.Text, nullable=True),
    sa.Column('acknowledged', sa.Integer, server_default=sa.text('0'), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('clock_timestamp()'), nullable=False),
    sa.UniqueConstraint('run_id', 'timestamp_epoch', 'category', name='uq_attack_event'),
    sa.CheckConstraint(
        "category IN ('Denial_of_Service', 'Reconnaissance_Port_Scan', 'Spoofing_Impersonation', 'Deauthentication_Disassociation_Abuse', 'Replay_Attack')",
        name='chk_attack_category'
    ),
    sa.CheckConstraint("status IN ('NO_EVIDENCE', 'INSUFFICIENT_TELEMETRY', 'SUSPICIOUS', 'CONFIRMED_THREAT')", name='chk_attack_status'),
    sa.CheckConstraint("severity IN ('NONE', 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')", name='chk_attack_severity'),
    sa.CheckConstraint('confidence >= 0.0 AND confidence <= 1.0', name='chk_confidence_range'),
    sa.CheckConstraint('acknowledged IN (0, 1)', name='chk_attack_ack')
)

pg_dialect = postgresql.dialect()

print("Compiling all 8 tables with PostgreSQL Dialect:")
for name, table in metadata.tables.items():
    ddl = str(CreateTable(table).compile(dialect=pg_dialect))
    print(f"Table '{name}': SUCCESS ({len(ddl.splitlines())} DDL lines)")

print("\nSUCCESS: All 8 PostgreSQL table DDL schemas compiled without dialect or type errors!")

