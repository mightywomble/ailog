"""Host inventory exports (Ansible inventory, SSH config).

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

bp = Blueprint('inventory_export', __name__)


@bp.route('/export/ansible-inventory', methods=['POST'])
def export_ansible_inventory():
    '''Generate Ansible inventory JSON with mainip and netbirdip groups.'''
    try:
        hosts = Host.query.all()

        inventory = {
            'mainip':    {'hosts': []},
            'netbirdip': {'hosts': []},
            '_meta':     {'hostvars': {}}
        }

        for host in hosts:
            host_name = host.friendly_name or host.hostname
            si        = getattr(host, 'system_info', None)
            main_ip   = getattr(si, 'main_ip',    None) if si else None
            netbird_ip= getattr(si, 'netbird_ip', None) if si else None
            base_ip   = main_ip or host.ip_address

            inventory['mainip']['hosts'].append(host_name)
            inventory['_meta']['hostvars'][host_name] = {
                'ansible_host': base_ip,
                'ansible_user': host.ssh_user,
            }

            if netbird_ip:
                nb_name = f'{host_name}-netbird'
                inventory['netbirdip']['hosts'].append(nb_name)
                inventory['_meta']['hostvars'][nb_name] = {
                    'ansible_host': netbird_ip,
                    'ansible_user': host.ssh_user,
                }

        json_output = json.dumps(inventory, indent=2, sort_keys=True)

        return Response(
            json_output,
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename=inventory.json'}
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/export/ssh-config', methods=['POST'])
def export_ssh_config():
    """Generate SSH config file"""
    try:
        hosts = Host.query.all()
        
        ssh_config = "# Auto-generated SSH config from Homelab Manager\n"
        ssh_config += f"# Generated: {datetime.datetime.utcnow().isoformat()}\n\n"
        
        def _host_block(name, ip, host_obj):
            nonlocal ssh_config
            ssh_config += f'Host {name}\n'
            ssh_config += f'    HostName {ip}\n'
            ssh_config += f'    User {host_obj.ssh_user}\n'
            if host_obj.ssh_key:
                ssh_config += f'    IdentityFile ~/.ssh/{host_obj.ssh_key.key_name}\n'
            ssh_config += '    StrictHostKeyChecking no\n'
            ssh_config += '    UserKnownHostsFile=/dev/null\n'
            ssh_config += '\n'

        ssh_config += '# ----------------------------------------\n'
        ssh_config += '# Group: mainip\n'
        ssh_config += '# ----------------------------------------\n'
        for host in hosts:
            host_name  = host.friendly_name or host.hostname
            si         = getattr(host, 'system_info', None)
            main_ip    = getattr(si, 'main_ip', None) if si else None
            base_ip    = main_ip or host.ip_address
            _host_block(host_name, base_ip, host)

        ssh_config += '# ----------------------------------------\n'
        ssh_config += '# Group: netbirdip\n'
        ssh_config += '# ----------------------------------------\n'
        for host in hosts:
            host_name  = host.friendly_name or host.hostname
            si         = getattr(host, 'system_info', None)
            netbird_ip = getattr(si, 'netbird_ip', None) if si else None
            if netbird_ip:
                _host_block(f'{host_name}-netbird', netbird_ip, host)
        
        return Response(
            ssh_config,
            mimetype='text/plain',
            headers={'Content-Disposition': 'attachment; filename=ssh_config'}
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500
