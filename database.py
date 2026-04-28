"""
Database models for AI Log Viewer using SQLAlchemy ORM
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    hosts = db.relationship('ScheduleHost', backref='schedule', cascade='all, delete-orphan')
    sources = db.relationship('ScheduleSource', backref='schedule', cascade='all, delete-orphan')

    def to_dict(self, include_children=False):
        d = {
            'id': self.id,
            'name': self.name,
            'enabled': bool(self.enabled),
            'interval_hours': self.interval_hours,
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
