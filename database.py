"""
Database models for Homelab Manager using SQLAlchemy ORM
Supports SQLite3 (default) and PostgreSQL (via connection string)
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()


class AppSetting(db.Model):
    '''Key/value application settings stored in the database.'''
    __tablename__ = 'app_settings'

    key = db.Column(db.String(255), primary_key=True)
    value_json = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        try:
            value = json.loads(self.value_json) if self.value_json else None
        except Exception:
            value = self.value_json
        return {'key': self.key, 'value': value, 'updated_at': self.updated_at.isoformat() if self.updated_at else None}

# Association tables for many-to-many relationships
host_groups = db.Table(
    'host_groups',
    db.Column('host_id', db.Integer, db.ForeignKey('hosts.id'), primary_key=True),
    db.Column('group_id', db.Integer, db.ForeignKey('groups.id'), primary_key=True)
)

host_tags = db.Table(
    'host_tags',
    db.Column('host_id', db.Integer, db.ForeignKey('hosts.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tags.id'), primary_key=True)
)


class Host(db.Model):
    """Represents a managed host/device"""
    __tablename__ = 'hosts'
    
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), nullable=False)
    friendly_name = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(255), nullable=False, unique=True)
    ssh_user = db.Column(db.String(255), nullable=False)
    ssh_key_id = db.Column(db.Integer, db.ForeignKey('ssh_keys.id'), nullable=True)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), default='unknown')  # unknown, online, offline, auth_error
    # Set from the Remediation page: the planner and runner both refuse it.
    do_not_remediate = db.Column(db.Boolean, default=False, nullable=False)
    last_seen = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    ssh_key = db.relationship('SSHKey', backref='hosts_using_key')
    system_info = db.relationship('SystemInfo', uselist=False, backref='host', cascade='all, delete-orphan')
    services = db.relationship('Service', backref='host', cascade='all, delete-orphan')
    host_logs = db.relationship('HostLog', backref='host', cascade='all, delete-orphan')
    groups = db.relationship('Group', secondary=host_groups, backref='hosts')
    tags = db.relationship('Tag', secondary=host_tags, backref='hosts')
    
    def to_dict(self):
        return {
            'id': self.id,
            'hostname': self.hostname,
            'friendly_name': self.friendly_name,
            'ip_address': self.ip_address,
            'ssh_user': self.ssh_user,
            'description': self.description,
            'status': self.status,
            'do_not_remediate': bool(self.do_not_remediate),
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'groups': [g.to_dict() for g in self.groups],
            'tags': [t.to_dict() for t in self.tags],
            'system_info': self.system_info.to_dict() if self.system_info else None,
        }


class SystemInfo(db.Model):
    """System information collected from a host"""
    __tablename__ = 'system_info'
    
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    
    os_version = db.Column(db.String(255), nullable=True)
    hostname = db.Column(db.String(255), nullable=True)
    last_update = db.Column(db.DateTime, nullable=True)
    ram_total = db.Column(db.BigInteger, nullable=True)  # bytes
    ram_used = db.Column(db.BigInteger, nullable=True)   # bytes
    disk_total = db.Column(db.BigInteger, nullable=True) # bytes
    disk_used = db.Column(db.BigInteger, nullable=True)  # bytes
    cpu_type = db.Column(db.String(255), nullable=True)
    cpu_cores = db.Column(db.Integer, nullable=True)
    netbird_ip = db.Column(db.String(255), nullable=True)
    main_ip = db.Column(db.String(255), nullable=True)
    
    captured_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'os_version': self.os_version,
            'hostname': self.hostname,
            'last_update': self.last_update.isoformat() if self.last_update else None,
            'ram_total': self.ram_total,
            'ram_used': self.ram_used,
            'disk_total': self.disk_total,
            'disk_used': self.disk_used,
            'cpu_type': self.cpu_type,
            'cpu_cores': self.cpu_cores,
            'netbird_ip': self.netbird_ip,
            'main_ip': self.main_ip,
            'captured_at': self.captured_at.isoformat() if self.captured_at else None,
        }


class Service(db.Model):
    """Systemd service status on a host"""
    __tablename__ = 'services'
    
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    service_name = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), nullable=True)  # active, inactive, failed, etc.
    is_running = db.Column(db.Boolean, default=False)
    last_checked = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'service_name': self.service_name,
            'status': self.status,
            'is_running': self.is_running,
            'last_checked': self.last_checked.isoformat() if self.last_checked else None,
        }


class HostLog(db.Model):
    """Logs for host operations (setup logs, etc)"""
    __tablename__ = 'host_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    log_content = db.Column(db.Text, nullable=False)
    log_type = db.Column(db.String(50), default='setup')  # setup, update, discovery, etc.
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'log_content': self.log_content,
            'log_type': self.log_type,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class SSHKey(db.Model):
    """Stored SSH keys for host connections"""
    __tablename__ = 'ssh_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    key_name = db.Column(db.String(255), nullable=False, unique=True)
    key_type = db.Column(db.String(50), nullable=False)  # 'file' or 'pasted'
    key_content = db.Column(db.Text, nullable=False)
    key_checksum = db.Column(db.String(64), nullable=True)  # SHA256 hex checksum
    is_encrypted = db.Column(db.Boolean, default=True)  # Whether key_content is encrypted
    enc_version = db.Column(db.String(50), nullable=True)  # Encryption version identifier
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'key_name': self.key_name,
            'key_type': self.key_type,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class Group(db.Model):
    """Host groups for organization"""
    __tablename__ = 'groups'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class Tag(db.Model):
    """Tags for categorizing hosts"""
    __tablename__ = 'tags'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, unique=True)
    color = db.Column(db.String(7), default='#3b82f6')  # hex color code
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'color': self.color,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class Schedule(db.Model):
    """A named recurring analysis schedule."""
    __tablename__ = 'schedules'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, default='Schedule')
    enabled = db.Column(db.Boolean, default=False)
    interval_hours = db.Column(db.Integer, nullable=False, default=6)
    # 'log'   - the original per-source AI analysis
    # 'report' - the server-wide correlated report pipeline (one report per host)
    kind = db.Column(db.String(16), nullable=False, default='log')
    report_window_minutes = db.Column(db.Integer)
    report_depth = db.Column(db.Integer)
    report_model = db.Column(db.String(128))
    report_scope_json = db.Column(db.Text)
    last_run_at = db.Column(db.DateTime)
    last_status = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    hosts = db.relationship('ScheduleHost', backref='schedule', cascade='all, delete-orphan')
    sources = db.relationship('ScheduleSource', backref='schedule', cascade='all, delete-orphan')

    def report_scope(self):
        try:
            return json.loads(self.report_scope_json) if self.report_scope_json else {}
        except Exception:
            return {}

    def to_dict(self, include_children=False):
        d = {
            'id': self.id,
            'name': self.name,
            'enabled': bool(self.enabled),
            'interval_hours': self.interval_hours,
            'kind': self.kind or 'log',
            'report_window_minutes': self.report_window_minutes,
            'report_depth': self.report_depth,
            'report_model': self.report_model,
            'report_scope': self.report_scope(),
            'last_run_at': self.last_run_at.isoformat() if self.last_run_at else None,
            'last_status': self.last_status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_children:
            d['hosts'] = [h.to_dict() for h in self.hosts]
            d['sources'] = [s.to_dict() for s in self.sources]
        return d


class ScheduleHost(db.Model):
    """Hosts included in a schedule (host-first selection)."""
    __tablename__ = 'schedule_hosts'

    id = db.Column(db.Integer, primary_key=True)
    schedule_id = db.Column(db.Integer, db.ForeignKey('schedules.id'), nullable=False, index=True)
    host_id = db.Column(db.String(64), nullable=False)  # 'local' or 'db-<id>'

    def to_dict(self):
        return {'id': self.id, 'schedule_id': self.schedule_id, 'host_id': self.host_id}


class ScheduleSource(db.Model):
    """A log source (file/journal) for a given schedule and host."""
    __tablename__ = 'schedule_sources'

    id = db.Column(db.Integer, primary_key=True)
    schedule_id = db.Column(db.Integer, db.ForeignKey('schedules.id'), nullable=False, index=True)
    host_id = db.Column(db.String(64), nullable=False)
    source_type = db.Column(db.String(16), nullable=False)  # file/journal
    source_name = db.Column(db.String(512), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'schedule_id': self.schedule_id,
            'host_id': self.host_id,
            'type': self.source_type,
            'name': self.source_name,
        }


# -----------------------------
# Suricata (remote sensor) data
# -----------------------------

class SuricataSensor(db.Model):
    __tablename__ = 'suricata_sensors'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    host = db.Column(db.String(256), nullable=False)
    user = db.Column(db.String(64), nullable=False)
    ssh_key_id = db.Column(db.Integer, db.ForeignKey('ssh_keys.id'), nullable=True)
    log_dir = db.Column(db.String(512), nullable=False, default='/var/log/suricata')
    enabled = db.Column(db.Boolean, default=True)
    ingest_interval_seconds = db.Column(db.Integer, default=30)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    ssh_key = db.relationship('SSHKey')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'host': self.host,
            'user': self.user,
            'ssh_key_id': self.ssh_key_id,
            'log_dir': self.log_dir,
            'enabled': bool(self.enabled),
            'ingest_interval_seconds': self.ingest_interval_seconds,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class SuricataIngestState(db.Model):
    __tablename__ = 'suricata_ingest_state'

    id = db.Column(db.Integer, primary_key=True)
    sensor_id = db.Column(db.Integer, db.ForeignKey('suricata_sensors.id'), nullable=False, index=True)
    filename = db.Column(db.String(64), nullable=False)  # eve.json, fast.log, stats.log, suricata.log

    last_inode = db.Column(db.String(64), nullable=True)
    last_size = db.Column(db.Integer, nullable=True)
    last_offset = db.Column(db.Integer, nullable=False, default=0)
    last_mtime = db.Column(db.Integer, nullable=True)

    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    sensor = db.relationship('SuricataSensor')

    __table_args__ = (
        db.UniqueConstraint('sensor_id', 'filename', name='uq_suricata_ingest_state_sensor_filename'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'sensor_id': self.sensor_id,
            'filename': self.filename,
            'last_inode': self.last_inode,
            'last_size': self.last_size,
            'last_offset': self.last_offset,
            'last_mtime': self.last_mtime,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class SuricataStatsCounterBucket(db.Model):
    __tablename__ = 'suricata_stats_counter_buckets'

    id = db.Column(db.Integer, primary_key=True)
    sensor_id = db.Column(db.Integer, db.ForeignKey('suricata_sensors.id'), nullable=False, index=True)
    bucket_ts = db.Column(db.Integer, nullable=False, index=True)  # epoch seconds bucket start
    counter = db.Column(db.String(256), nullable=False, index=True)
    tm_name = db.Column(db.String(128), nullable=True)
    value = db.Column(db.BigInteger, nullable=False)

    sensor = db.relationship('SuricataSensor')

    __table_args__ = (
        db.Index('idx_suricata_stats_sensor_bucket_counter', 'sensor_id', 'bucket_ts', 'counter'),
    )


class SuricataFastAlertBucket(db.Model):
    __tablename__ = 'suricata_fast_alert_buckets'

    id = db.Column(db.Integer, primary_key=True)
    sensor_id = db.Column(db.Integer, db.ForeignKey('suricata_sensors.id'), nullable=False, index=True)
    bucket_ts = db.Column(db.Integer, nullable=False, index=True)
    sid = db.Column(db.Integer, nullable=True, index=True)
    msg = db.Column(db.String(512), nullable=True)
    classification = db.Column(db.String(256), nullable=True)
    priority = db.Column(db.Integer, nullable=True)
    proto = db.Column(db.String(16), nullable=True)
    src_ip = db.Column(db.String(64), nullable=True, index=True)
    dst_ip = db.Column(db.String(64), nullable=True, index=True)
    src_port = db.Column(db.Integer, nullable=True, index=True)
    dst_port = db.Column(db.Integer, nullable=True, index=True)
    count = db.Column(db.Integer, nullable=False, default=1)

    sensor = db.relationship('SuricataSensor')

    __table_args__ = (
        db.Index('idx_suricata_fast_sensor_bucket', 'sensor_id', 'bucket_ts'),
    )


class SuricataAlertBucket(db.Model):
    __tablename__ = 'suricata_alert_buckets'

    id = db.Column(db.Integer, primary_key=True)
    sensor_id = db.Column(db.Integer, db.ForeignKey('suricata_sensors.id'), nullable=False, index=True)
    bucket_ts = db.Column(db.Integer, nullable=False, index=True)
    signature_id = db.Column(db.Integer, nullable=True, index=True)
    signature = db.Column(db.String(512), nullable=True)
    category = db.Column(db.String(256), nullable=True)
    severity = db.Column(db.Integer, nullable=True)
    src_ip = db.Column(db.String(64), nullable=True, index=True)
    dst_ip = db.Column(db.String(64), nullable=True, index=True)
    src_port = db.Column(db.Integer, nullable=True, index=True)
    dst_port = db.Column(db.Integer, nullable=True, index=True)
    proto = db.Column(db.String(16), nullable=True)
    app_proto = db.Column(db.String(32), nullable=True)
    count = db.Column(db.Integer, nullable=False, default=1)

    sensor = db.relationship('SuricataSensor')

    __table_args__ = (
        db.Index('idx_suricata_alert_sensor_bucket', 'sensor_id', 'bucket_ts'),
    )


# --- Monitoring subsystem models ---


class Monitor(db.Model):
    __tablename__ = 'monitors'

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False, index=True)

    name = db.Column(db.String(256), nullable=False)
    type = db.Column(db.String(32), nullable=False)  # http|tcp|ping (ping optional)
    enabled = db.Column(db.Boolean, default=True, nullable=False)

    interval_seconds = db.Column(db.Integer, default=60, nullable=False)
    timeout_seconds = db.Column(db.Integer, default=10, nullable=False)

    config_json = db.Column(db.Text, nullable=False)  # JSON string
    tags_json = db.Column(db.Text, nullable=True)

    last_status = db.Column(db.String(16), nullable=True)  # up|down|error
    last_checked_at = db.Column(db.DateTime, nullable=True)
    last_response_time_ms = db.Column(db.Integer, nullable=True)
    last_status_code = db.Column(db.Integer, nullable=True)
    last_error_message = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    host = db.relationship('Host', backref=db.backref('monitors', lazy=True, cascade='all, delete-orphan'))

    def config(self):
        try:
            return json.loads(self.config_json or '{}')
        except Exception:
            return {}

    def tags(self):
        if not self.tags_json:
            return []
        try:
            return json.loads(self.tags_json)
        except Exception:
            return []

    def to_dict(self, include_checks: bool = False, checks_limit: int = 20):
        d = {
            'id': self.id,
            'host_id': self.host_id,
            'name': self.name,
            'type': self.type,
            'enabled': self.enabled,
            'interval_seconds': self.interval_seconds,
            'timeout_seconds': self.timeout_seconds,
            'config': self.config(),
            'tags': self.tags(),
            'last_status': self.last_status,
            'last_checked_at': self.last_checked_at.isoformat() if self.last_checked_at else None,
            'last_response_time_ms': self.last_response_time_ms,
            'last_status_code': self.last_status_code,
            'last_error_message': self.last_error_message,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_checks:
            checks = (
                MonitorCheck.query.filter_by(monitor_id=self.id)
                .order_by(MonitorCheck.checked_at.desc())
                .limit(int(checks_limit))
                .all()
            )
            d['checks'] = [c.to_dict() for c in checks]
        return d


class MonitorCheck(db.Model):
    __tablename__ = 'monitor_checks'

    id = db.Column(db.Integer, primary_key=True)
    monitor_id = db.Column(db.Integer, db.ForeignKey('monitors.id'), nullable=False, index=True)

    checked_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    status = db.Column(db.String(16), nullable=False)  # up|down|error
    response_time_ms = db.Column(db.Integer, nullable=False)
    status_code = db.Column(db.Integer, nullable=True)
    error_message = db.Column(db.Text, nullable=True)

    monitor = db.relationship('Monitor', backref=db.backref('checks', lazy=True, cascade='all, delete-orphan'))

    def to_dict(self):
        return {
            'id': self.id,
            'monitor_id': self.monitor_id,
            'checked_at': self.checked_at.isoformat() if self.checked_at else None,
            'status': self.status,
            'response_time_ms': self.response_time_ms,
            'status_code': self.status_code,
            'error_message': self.error_message,
        }


class HostDockerInventory(db.Model):
    __tablename__ = 'host_docker_inventory'

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False, index=True)
    captured_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    inventory_json = db.Column(db.Text, nullable=False)

    host = db.relationship('Host', backref=db.backref('docker_inventories', lazy=True, cascade='all, delete-orphan'))

    def inventory(self):
        try:
            return json.loads(self.inventory_json or '{}')
        except Exception:
            return {}

    def to_dict(self):
        return {
            'id': self.id,
            'host_id': self.host_id,
            'captured_at': self.captured_at.isoformat() if self.captured_at else None,
            'inventory': self.inventory(),
        }


class DockerEndpoint(db.Model):
    """A discovered Docker Engine API endpoint for an ailog host.

    Additive table - created automatically by ``db.create_all()``.
    """
    __tablename__ = 'docker_endpoints'

    id = db.Column(db.Integer, primary_key=True)
    host_key = db.Column(db.String(128), nullable=False, unique=True, index=True)
    friendly_name = db.Column(db.String(255))
    ip_address = db.Column(db.String(255))
    mode = db.Column(db.String(32))  # 'socket' | 'tcp' | 'tcp+tls'
    port = db.Column(db.Integer)
    server_version = db.Column(db.String(64))
    is_reachable = db.Column(db.Boolean, default=False, nullable=False)
    discovered_by = db.Column(db.String(32))
    engine_json = db.Column(db.Text)
    last_checked_at = db.Column(db.DateTime)
    last_error = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def engine(self):
        try:
            return json.loads(self.engine_json or '{}')
        except Exception:
            return {}

    def to_dict(self):
        return {
            'id': self.id,
            'host_key': self.host_key,
            'friendly_name': self.friendly_name,
            'ip_address': self.ip_address,
            'mode': self.mode,
            'port': self.port,
            'server_version': self.server_version,
            'is_reachable': bool(self.is_reachable),
            'discovered_by': self.discovered_by,
            'engine': self.engine(),
            'last_checked_at': self.last_checked_at.isoformat() if self.last_checked_at else None,
            'last_error': self.last_error,
        }


class LogReport(db.Model):
    """A stored server-wide correlated log report.

    Additive table - created automatically by ``db.create_all()``.

    ``evidence_text`` is kept on purpose: re-running the summarise stage against
    a different model later does not need a fresh (expensive) collection pass.
    """
    __tablename__ = 'log_reports'

    id = db.Column(db.Integer, primary_key=True)
    host_key = db.Column(db.String(128), nullable=False, index=True)
    host_label = db.Column(db.String(255))
    window_minutes = db.Column(db.Integer, default=120, nullable=False)
    window_start = db.Column(db.DateTime)
    window_end = db.Column(db.DateTime)

    provider = db.Column(db.String(32))
    model = db.Column(db.String(128))
    verdict = db.Column(db.String(32))  # healthy | degraded | failing | unknown

    sources_total = db.Column(db.Integer, default=0)
    sources_ok = db.Column(db.Integer, default=0)
    sources_failed = db.Column(db.Integer, default=0)
    events_total = db.Column(db.Integer, default=0)
    clusters_total = db.Column(db.Integer, default=0)

    severity_json = db.Column(db.Text)
    timeline_json = db.Column(db.Text)
    correlations_json = db.Column(db.Text)
    containers_json = db.Column(db.Text)
    coverage_json = db.Column(db.Text)
    clusters_json = db.Column(db.Text)   # compact cluster list, used for diffing
    evidence_text = db.Column(db.Text)

    tokens_in = db.Column(db.Integer)
    tokens_out = db.Column(db.Integer)
    duration_ms = db.Column(db.Integer)

    report_markdown = db.Column(db.Text)
    error = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def _load(self, raw, default):
        try:
            return json.loads(raw) if raw else default
        except Exception:
            return default

    def severity(self):
        return self._load(self.severity_json, {})

    def timeline(self):
        return self._load(self.timeline_json, [])

    def correlations(self):
        return self._load(self.correlations_json, [])

    def containers(self):
        return self._load(self.containers_json, [])

    def coverage(self):
        return self._load(self.coverage_json, {})

    def clusters(self):
        return self._load(self.clusters_json, [])

    def to_dict(self, include_markdown=False):
        data = {
            'id': self.id,
            'host_key': self.host_key,
            'host_label': self.host_label,
            'window_minutes': self.window_minutes,
            'window_start': self.window_start.isoformat() if self.window_start else None,
            'window_end': self.window_end.isoformat() if self.window_end else None,
            'provider': self.provider,
            'model': self.model,
            'verdict': self.verdict,
            'sources_total': self.sources_total,
            'sources_ok': self.sources_ok,
            'sources_failed': self.sources_failed,
            'events_total': self.events_total,
            'clusters_total': self.clusters_total,
            'severity': self.severity(),
            'timeline': self.timeline(),
            'correlations': self.correlations(),
            'containers': self.containers(),
            'coverage': self.coverage(),
            'tokens_in': self.tokens_in,
            'tokens_out': self.tokens_out,
            'duration_ms': self.duration_ms,
            'error': self.error,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }
        if include_markdown:
            data['report_markdown'] = self.report_markdown
        return data


class AlertRule(db.Model):
    """A threshold rule evaluated against the metrics ailog collects.

    Additive table - created by ``db.create_all()``.
    """
    __tablename__ = 'alert_rules'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, default='Rule')
    metric = db.Column(db.String(64), nullable=False, default='mem_percent')
    op = db.Column(db.String(8), nullable=False, default='>=')
    threshold = db.Column(db.Float, nullable=False, default=0.0)
    for_seconds = db.Column(db.Integer, nullable=False, default=0)
    cooldown_seconds = db.Column(db.Integer, nullable=False, default=900)
    severity = db.Column(db.String(16), nullable=False, default='warning')
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'metric': self.metric,
            'op': self.op,
            'threshold': self.threshold,
            'for_seconds': self.for_seconds,
            'cooldown_seconds': self.cooldown_seconds,
            'severity': self.severity,
            'enabled': bool(self.enabled),
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class AlertEvent(db.Model):
    """One firing/resolved episode for a rule on a host.

    Additive table - created by ``db.create_all()``.
    """
    __tablename__ = 'alert_events'

    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, index=True)
    rule_name = db.Column(db.String(120))
    host_key = db.Column(db.String(64), index=True)
    metric = db.Column(db.String(64))
    op = db.Column(db.String(8))
    value = db.Column(db.Float)
    threshold = db.Column(db.Float)
    resolved_value = db.Column(db.Float)
    severity = db.Column(db.String(16), default='warning')
    state = db.Column(db.String(16), default='firing', index=True)
    message = db.Column(db.Text)
    notified = db.Column(db.Boolean, default=False)
    notify_error = db.Column(db.Text)
    started_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    resolved_at = db.Column(db.DateTime)

    def to_dict(self):
        return {
            'id': self.id,
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'host_key': self.host_key,
            'metric': self.metric,
            'op': self.op,
            'value': self.value,
            'threshold': self.threshold,
            'resolved_value': self.resolved_value,
            'severity': self.severity,
            'state': self.state,
            'message': self.message,
            'notified': bool(self.notified),
            'notify_error': self.notify_error,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
        }


# ---------------------------------------------------------------------------
# Self-healing remediation (see remediation/ and docs/remediation.md)
# ---------------------------------------------------------------------------

class Remediation(db.Model):
    """Catalog mirror: one row per YAML file in remediations/.

    The YAML is the source of truth (it is validated at startup and in CI);
    this table exists so the UI can list, disable and join against runs.
    """
    __tablename__ = 'remediations'

    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(96), nullable=False, unique=True, index=True)
    version = db.Column(db.Integer, nullable=False, default=1)
    title = db.Column(db.String(255), nullable=False)
    summary = db.Column(db.Text)
    risk = db.Column(db.String(16), nullable=False, default='low')
    est_seconds = db.Column(db.Integer, default=30)
    executable = db.Column(db.Boolean, nullable=False, default=True)
    fleet_safe = db.Column(db.Boolean, nullable=False, default=False)
    requires_json = db.Column(db.Text)
    changes_json = db.Column(db.Text)
    does_not_json = db.Column(db.Text)
    yaml_json = db.Column(db.Text)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def _load(self, raw, default):
        try:
            return json.loads(raw) if raw else default
        except Exception:
            return default

    def to_dict(self):
        return {
            'id': self.id,
            'slug': self.slug,
            'version': self.version,
            'title': self.title,
            'summary': self.summary,
            'risk': self.risk,
            'est_seconds': self.est_seconds,
            'executable': bool(self.executable),
            'fleet_safe': bool(self.fleet_safe),
            'requires': self._load(self.requires_json, []),
            'changes': self._load(self.changes_json, []),
            'does_not': self._load(self.does_not_json, []),
            'enabled': bool(self.enabled),
        }
class RemediationMatch(db.Model):
    """A remedy card attached to one report.

    The card is denormalised on purpose: a two-year-old report must render
    exactly as it did when it was written, even if the catalog has moved on.
    source=llm cards are idea-channel only and are never executable.
    """
    __tablename__ = 'remediation_matches'

    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, index=True, nullable=False)
    host_key = db.Column(db.String(128), index=True)
    slug = db.Column(db.String(96), index=True)
    source = db.Column(db.String(16), nullable=False, default='catalog')
    executable = db.Column(db.Boolean, nullable=False, default=False)
    title = db.Column(db.String(255), nullable=False)
    summary = db.Column(db.Text)
    risk = db.Column(db.String(16), default='low')
    est_seconds = db.Column(db.Integer, default=30)
    confidence = db.Column(db.Float, default=0.0)
    evidence_json = db.Column(db.Text)
    rationale = db.Column(db.Text)
    code_text = db.Column(db.Text)
    verify_text = db.Column(db.Text)
    rollback_text = db.Column(db.Text)
    changes_json = db.Column(db.Text)
    does_not_json = db.Column(db.Text)
    requires_json = db.Column(db.Text)
    state = db.Column(db.String(24), nullable=False, default='open', index=True)
    dismissed_reason = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def _load(self, raw, default):
        try:
            return json.loads(raw) if raw else default
        except Exception:
            return default

    def to_dict(self):
        return {
            'id': self.id,
            'report_id': self.report_id,
            'host_key': self.host_key,
            'slug': self.slug,
            'source': self.source,
            'executable': bool(self.executable),
            'title': self.title,
            'summary': self.summary,
            'risk': self.risk,
            'est_seconds': self.est_seconds,
            'confidence': round(float(self.confidence or 0.0), 2),
            'evidence': self._load(self.evidence_json, []),
            'rationale': self.rationale,
            'code': self.code_text,
            'verify': self.verify_text,
            'rollback': self.rollback_text,
            'changes': self._load(self.changes_json, []),
            'does_not': self._load(self.does_not_json, []),
            'requires': self._load(self.requires_json, []),
            'state': self.state,
            'dismissed_reason': self.dismissed_reason,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }
class RemediationRun(db.Model):
    __tablename__ = 'remediation_runs'

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(64), nullable=False, unique=True, index=True)
    slug = db.Column(db.String(96), index=True)
    match_id = db.Column(db.Integer, index=True)
    dry_run = db.Column(db.Boolean, nullable=False, default=True)
    scope = db.Column(db.String(16), nullable=False, default='host')
    requested_by = db.Column(db.String(128))
    confirm_fingerprint = db.Column(db.String(64))
    state = db.Column(db.String(32), nullable=False, default='queued', index=True)
    started_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    finished_at = db.Column(db.DateTime)
    summary_json = db.Column(db.Text)
    artifact_dir = db.Column(db.Text)
    error = db.Column(db.Text)

    targets = db.relationship('RemediationTarget', backref='run', lazy=True,
                              cascade='all, delete-orphan')

    def _load(self, raw, default):
        try:
            return json.loads(raw) if raw else default
        except Exception:
            return default

    def to_dict(self, include_targets=True):
        data = {
            'uuid': self.uuid,
            'slug': self.slug,
            'match_id': self.match_id,
            'dry_run': bool(self.dry_run),
            'scope': self.scope,
            'requested_by': self.requested_by,
            'state': self.state,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'finished_at': self.finished_at.isoformat() if self.finished_at else None,
            'summary': self._load(self.summary_json, {}),
            'error': self.error,
        }
        if include_targets:
            data['targets'] = [t.to_dict() for t in self.targets]
        return data


class RemediationTarget(db.Model):
    __tablename__ = 'remediation_targets'

    id = db.Column(db.Integer, primary_key=True)
    run_id = db.Column(db.Integer, db.ForeignKey('remediation_runs.id'), nullable=False, index=True)
    host_key = db.Column(db.String(128), nullable=False)
    host_label = db.Column(db.String(255))
    state = db.Column(db.String(32), nullable=False, default='pending')
    exit_code = db.Column(db.Integer)
    changed_tasks = db.Column(db.Integer)
    before_json = db.Column(db.Text)
    after_json = db.Column(db.Text)
    output = db.Column(db.Text)
    rollback_state = db.Column(db.String(32))

    def _load(self, raw, default):
        try:
            return json.loads(raw) if raw else default
        except Exception:
            return default

    def to_dict(self):
        return {
            'host_key': self.host_key,
            'host_label': self.host_label,
            'state': self.state,
            'exit_code': self.exit_code,
            'changed_tasks': self.changed_tasks,
            'before': self._load(self.before_json, {}),
            'after': self._load(self.after_json, {}),
            'output': self.output,
            'rollback_state': self.rollback_state,
        }
class RemediationWindow(db.Model):
    """In-app maintenance window.

    days is a comma separated list of ISO weekdays (1=Mon .. 7=Sun);
    start_time/end_time are local HH:MM. A window whose end is before its
    start wraps over midnight.
    """
    __tablename__ = 'remediation_windows'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False, default='Window')
    group_id = db.Column(db.Integer, index=True)
    tag_id = db.Column(db.Integer, index=True)
    days = db.Column(db.String(32), default='1,2,3,4,5,6,7')
    start_time = db.Column(db.String(5), default='22:00')
    end_time = db.Column(db.String(5), default='02:00')
    timezone = db.Column(db.String(64), default='UTC')
    mode = db.Column(db.String(16), default='block')
    enabled = db.Column(db.Boolean, default=True)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'group_id': self.group_id,
            'tag_id': self.tag_id,
            'days': self.days,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'timezone': self.timezone,
            'mode': self.mode,
            'enabled': bool(self.enabled),
        }


class AuditEvent(db.Model):
    """Generic audit trail (remediation today, other actions later)."""
    __tablename__ = 'audit_events'

    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    actor = db.Column(db.String(128))
    action = db.Column(db.String(64), index=True)
    object_type = db.Column(db.String(64))
    object_id = db.Column(db.String(128))
    detail_json = db.Column(db.Text)
    request_id = db.Column(db.String(64))

    def to_dict(self):
        try:
            detail = json.loads(self.detail_json) if self.detail_json else {}
        except Exception:
            detail = {}
        return {
            'id': self.id,
            'ts': self.ts.isoformat() if self.ts else None,
            'actor': self.actor,
            'action': self.action,
            'object_type': self.object_type,
            'object_id': self.object_id,
            'detail': detail,
        }
