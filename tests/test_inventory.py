"""Tests for the inventory blueprint (groups, tags, exports, DB admin).

These routes used to live in app.py and were extracted verbatim into the
``inventory`` package; the tests pin the URLs and behaviour so the split stays
honest.
"""
import json


def _host_id(host_key):
    return int(host_key.split('-', 1)[1])


def test_groups_list_is_json(client):
    r = client.get('/groups')
    assert r.status_code == 200
    assert isinstance(r.get_json(), list)


def test_group_crud(client, ctx):
    from database import Group

    r = client.post('/groups', json={'name': 'web', 'description': 'web tier'})
    assert r.status_code == 201
    created = r.get_json()
    assert created['name'] == 'web'

    # duplicate name is rejected
    assert client.post('/groups', json={'name': 'web'}).status_code == 400

    # missing name is rejected
    assert client.post('/groups', json={}).status_code == 400

    r = client.put(f"/groups/{created['id']}", json={'name': 'web2'})
    assert r.status_code == 200
    assert r.get_json()['name'] == 'web2'

    assert client.put('/groups/999999', json={'name': 'x'}).status_code == 404

    assert client.delete(f"/groups/{created['id']}").status_code == 200
    assert Group.query.get(created['id']) is None


def test_group_rename_collision_is_rejected(client, ctx):
    a = client.post('/groups', json={'name': 'alpha'}).get_json()
    client.post('/groups', json={'name': 'beta'})
    r = client.put(f"/groups/{a['id']}", json={'name': 'beta'})
    assert r.status_code == 400


def test_group_hosts_and_assignment(client, ctx, host):
    gid = client.post('/groups', json={'name': 'assigned'}).get_json()['id']
    hid = _host_id(host)

    r = client.post(f'/hosts/db/{hid}/groups', json={'group_ids': [gid]})
    assert r.status_code == 200
    assert gid in [g['id'] for g in r.get_json()['groups']]

    r = client.get(f'/groups/{gid}/hosts')
    assert r.status_code == 200
    payload = r.get_json()
    assert payload['group']['id'] == gid
    assert [h['host_name'] if 'host_name' in h else h['hostname'] for h in payload['hosts']]

    assert client.get('/groups/999999/hosts').status_code == 404
    assert client.post('/hosts/db/999999/groups', json={'group_ids': []}).status_code == 404


def test_tags_crud_and_assignment(client, ctx, host):
    r = client.post('/tags', json={'name': 'prod', 'color': '#ff0000'})
    assert r.status_code == 201
    tag = r.get_json()
    assert tag['color'] == '#ff0000'

    assert client.post('/tags', json={'name': 'prod'}).status_code == 400
    assert client.post('/tags', json={}).status_code == 400

    r = client.get('/tags')
    assert r.status_code == 200
    assert any(t['name'] == 'prod' for t in r.get_json())

    hid = _host_id(host)
    r = client.post(f'/hosts/db/{hid}/tags', json={'tag_ids': [tag['id']]})
    assert r.status_code == 200
    assert tag['id'] in [t['id'] for t in r.get_json()['tags']]

    assert client.post('/hosts/db/999999/tags', json={'tag_ids': []}).status_code == 404


def test_default_tag_colour(client):
    tag = client.post('/tags', json={'name': 'no-colour'}).get_json()
    assert tag['color'] == '#3b82f6'


def test_ansible_inventory_export(client, ctx, host):
    from database import Host, SystemInfo, db

    hid = _host_id(host)
    row = Host.query.get(hid)
    db.session.add(SystemInfo(host_id=hid, main_ip='192.0.2.10', netbird_ip='100.64.0.10'))
    db.session.commit()

    r = client.post('/export/ansible-inventory')
    assert r.status_code == 200
    assert r.mimetype == 'application/json'
    assert 'attachment; filename=inventory.json' == r.headers['Content-Disposition']

    inv = json.loads(r.data)
    name = row.friendly_name or row.hostname
    assert name in inv['mainip']['hosts']
    assert inv['_meta']['hostvars'][name]['ansible_host'] == '192.0.2.10'
    assert inv['_meta']['hostvars'][f'{name}-netbird']['ansible_host'] == '100.64.0.10'


def test_ssh_config_export(client, ctx, host):
    r = client.post('/export/ssh-config')
    assert r.status_code == 200
    assert r.mimetype == 'text/plain'
    body = r.data.decode()
    assert body.startswith('# Auto-generated SSH config from Homelab Manager')
    assert 'Group: mainip' in body
    assert 'StrictHostKeyChecking accept-new' in body
    assert 'UserKnownHostsFile=/dev/null' not in body


def test_db_backup_returns_sqlite_bytes(client):
    r = client.get('/admin/db/backup')
    assert r.status_code == 200
    assert r.headers['Content-Disposition'].startswith('attachment; filename=homelab-manager-backup-')
    assert r.data[:15] == b'SQLite format 3'


def test_db_restore_rejects_missing_file(client):
    assert client.post('/admin/db/restore', data={}).status_code == 400


def test_selective_restore_rejects_missing_file(client):
    r = client.post('/admin/db/restore-selective', data={})
    assert r.status_code == 400


def test_sqlite_path_helper_handles_urls(ctx):
    from inventory.dbadmin_routes import _get_sqlite_db_file_path
    from flask import current_app

    original = current_app.config.get('SQLALCHEMY_DATABASE_URI')
    try:
        current_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/x.db'
        assert _get_sqlite_db_file_path() == '/tmp/x.db'
        current_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rel.db'
        assert _get_sqlite_db_file_path() == 'rel.db'
        current_app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://x'
        assert _get_sqlite_db_file_path() is None
    finally:
        current_app.config['SQLALCHEMY_DATABASE_URI'] = original


def test_extracted_routes_are_registered_on_blueprints(flask_app):
    rules = {r.rule: r.endpoint for r in flask_app.url_map.iter_rules()}
    assert rules['/groups'].startswith('inventory_groups.')
    assert rules['/tags'].startswith('inventory_groups.')
    assert rules['/export/ansible-inventory'].startswith('inventory_export.')
    assert rules['/admin/db/backup'].startswith('inventory_dbadmin.')
