"""Group and tag management routes.

Extracted verbatim from app.py as part of the app.py split. Route paths and
handler behaviour are unchanged; the blueprint is registered without a URL
prefix so every URL stays exactly where it was.
"""

from __future__ import annotations

import datetime
import json
import os
import shutil
import sqlite3
import tempfile

from flask import (Blueprint, Response, current_app, jsonify, request)
from sqlalchemy import text as sql_text

from database import db, AppSetting, Group, Host, Tag

bp = Blueprint('inventory_groups', __name__)


@bp.route('/groups', methods=['GET'])
def get_groups():
    """Get all groups"""
    try:
        groups = Group.query.all()
        return jsonify([g.to_dict() for g in groups])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/groups', methods=['POST'])
def create_group():
    """Create a new group"""
    try:
        data = request.get_json()
        name = data.get('name')
        
        if not name:
            return jsonify({'error': 'Group name required'}), 400
        
        existing = Group.query.filter_by(name=name).first()
        if existing:
            return jsonify({'error': 'Group already exists'}), 400
        
        group = Group(
            name=name,
            description=data.get('description', '')
        )
        db.session.add(group)
        db.session.commit()
        
        return jsonify(group.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500



@bp.route('/groups/<int:group_id>', methods=['PUT'])
def update_group(group_id):
    """Update an existing group"""
    try:
        group = Group.query.get(group_id)
        if not group:
            return jsonify({'error': 'Group not found'}), 404

        data = request.get_json() or {}
        name = data.get('name')
        description = data.get('description')

        if name is not None:
            name = name.strip()
            if not name:
                return jsonify({'error': 'Group name required'}), 400
            existing = Group.query.filter(Group.name == name, Group.id != group_id).first()
            if existing:
                return jsonify({'error': 'Group already exists'}), 400
            group.name = name

        if description is not None:
            group.description = description

        db.session.commit()
        return jsonify(group.to_dict())
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@bp.route('/groups/<int:group_id>', methods=['DELETE'])
def delete_group(group_id):
    """Delete a group"""
    try:
        group = Group.query.get(group_id)
        if not group:
            return jsonify({'error': 'Group not found'}), 404

        # Detach from hosts first (association table)
        group.hosts = []
        db.session.delete(group)
        db.session.commit()
        return jsonify({'message': 'Group deleted'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@bp.route('/groups/<int:group_id>/hosts', methods=['GET'])
def get_group_hosts(group_id):
    """List hosts assigned to a group"""
    try:
        group = Group.query.get(group_id)
        if not group:
            return jsonify({'error': 'Group not found'}), 404

        hosts = []
        for h in (group.hosts or []):
            hosts.append({
                'id': h.id,
                'host_id': f"db-{h.id}",
                'hostname': h.hostname,
                'friendly_name': h.friendly_name,
                'ip_address': h.ip_address,
                'ssh_user': h.ssh_user,
                'description': h.description,
            })

        return jsonify({'group': group.to_dict(), 'hosts': hosts})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@bp.route('/tags', methods=['GET'])
def get_tags():
    """Get all tags"""
    try:
        tags = Tag.query.all()
        return jsonify([t.to_dict() for t in tags])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/tags', methods=['POST'])
def create_tag():
    """Create a new tag"""
    try:
        data = request.get_json()
        name = data.get('name')
        
        if not name:
            return jsonify({'error': 'Tag name required'}), 400
        
        existing = Tag.query.filter_by(name=name).first()
        if existing:
            return jsonify({'error': 'Tag already exists'}), 400
        
        tag = Tag(
            name=name,
            color=data.get('color', '#3b82f6')
        )
        db.session.add(tag)
        db.session.commit()
        
        return jsonify(tag.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@bp.route('/hosts/db/<int:host_id>/groups', methods=['POST'])
def add_host_to_group(host_id):
    """Add host to a group"""
    try:
        data = request.get_json()
        group_ids = data.get('group_ids', [])
        
        host = Host.query.get(host_id)
        if not host:
            return jsonify({'error': 'Host not found'}), 404
        
        groups = Group.query.filter(Group.id.in_(group_ids)).all()
        host.groups = groups
        db.session.commit()
        
        return jsonify(host.to_dict())
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@bp.route('/hosts/db/<int:host_id>/tags', methods=['POST'])
def add_host_to_tags(host_id):
    """Add tags to a host"""
    try:
        data = request.get_json()
        tag_ids = data.get('tag_ids', [])
        
        host = Host.query.get(host_id)
        if not host:
            return jsonify({'error': 'Host not found'}), 404
        
        tags = Tag.query.filter(Tag.id.in_(tag_ids)).all()
        host.tags = tags
        db.session.commit()
        
        return jsonify(host.to_dict())
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
