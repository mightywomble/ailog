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
