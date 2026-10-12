from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List

import requests
from flask import Blueprint, jsonify, redirect, render_template, request

from database import Host, Monitor, HostDockerInventory, db

from .discovery import (
    collect_docker_inventory,
    collect_listening_ports_v4,
    collect_listening_udp_ports_v4,
    generate_monitor_candidates,
)
from .sshkeys import materialize_ssh_key_path


monitoring_bp = Blueprint('monitoring', __name__)


def _http_probe_ports(host_ip: str, ports: List[int]) -> Dict[int, Dict[str, Any]]:
    results: Dict[int, Dict[str, Any]] = {}
    for port in ports:
        # Try http then https (some services speak TLS on non-443 ports)
        for scheme in ('http', 'https'):
            url = f'{scheme}://{host_ip}:{port}/'
            try:
                r = requests.get(url, timeout=2, allow_redirects=True, verify=False)
                # If we got any HTTP status, it's HTTP.
                results[port] = {'is_http': True, 'url': f'{scheme}://{host_ip}:{port}'}
                break
            except Exception:
                continue
        if port not in results:
            results[port] = {'is_http': False}
    return results


@monitoring_bp.get('/monitoring/wizard')
def monitoring_wizard():
    hosts = Host.query.order_by(Host.friendly_name.asc()).all()
    preselect = request.args.get('host_id')
    try:
        preselect_id = int(preselect) if preselect is not None else None
    except Exception:
        preselect_id = None
    return render_template('monitoring_wizard.html', hosts=hosts, preselect_id=preselect_id)

@monitoring_bp.post('/monitoring/wizard/discover')
def monitoring_wizard_discover():
    data = request.get_json(force=True) or {}
    host_ids = data.get('host_ids') or []
    scan_profile = data.get('scan_profile') or 'common'

    if scan_profile not in ('common', '1-1024'):
        return jsonify({'error': 'Invalid scan_profile'}), 400

    if not host_ids:
        return jsonify({'error': 'No hosts selected'}), 400

    hosts = Host.query.filter(Host.id.in_([int(x) for x in host_ids])).all()
    out = []

    for h in hosts:
        user = h.ssh_user or 'root'
        ssh_key_path = materialize_ssh_key_path(h.ssh_key_id)

        host_result: Dict[str, Any] = {
            'host_id': h.id,
            'ip': h.ip_address,
            'friendly_name': h.friendly_name,
            'errors': [],
        }

        ok_ports, listeners, err_ports = collect_listening_ports_v4(user, h.ip_address, ssh_key_path)
        ok_udp, udp_listeners, err_udp = collect_listening_udp_ports_v4(user, h.ip_address, ssh_key_path)
        if not ok_udp:
            udp_listeners = []

        if not ok_ports:
            host_result['errors'].append({'stage': 'ports', 'error': err_ports})
            listeners = []

        ok_docker, docker_inv, err_docker = collect_docker_inventory(user, h.ip_address, ssh_key_path)
        if not ok_docker:
            host_result['errors'].append({'stage': 'docker', 'error': err_docker})
            docker_inv = {'docker': False, 'containers': []}

        # HTTP probe only for ports we might consider candidates.
        discovered_ports = sorted({int(x['port']) for x in listeners if 'port' in x})
        if scan_profile == 'common':
            probe_ports = [p for p in discovered_ports if p in (80, 443, 3000, 5000, 8000, 8080, 8443, 9000)]
        else:
            probe_ports = [p for p in discovered_ports if 1 <= p <= 1024]
            probe_ports = probe_ports[:40]  # cap to avoid long probes

        http_probe = _http_probe_ports(h.ip_address, probe_ports)
        candidates = generate_monitor_candidates(h.ip_address, listeners, docker_inv, scan_profile, udp_listeners, http_probe)

        host_result['listeners'] = listeners
        host_result['udp_listeners'] = udp_listeners
        host_result['docker'] = docker_inv
        # Persist docker inventory snapshot (new table)
        try:
            snap = HostDockerInventory(host_id=h.id, inventory_json=json.dumps(docker_inv))
            db.session.add(snap)
            db.session.commit()
        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass

        host_result['candidates'] = candidates
        out.append(host_result)

    return jsonify({'scan_profile': scan_profile, 'results': out})


@monitoring_bp.post('/monitoring/wizard/apply')
def monitoring_wizard_apply():
    data = request.get_json(force=True) or {}
    selections = data.get('selections') or []
    interval_seconds = int(data.get('interval_seconds') or 60)
    timeout_seconds = int(data.get('timeout_seconds') or 10)

    created = 0
    skipped = 0

    for sel in selections:
        host_id = int(sel.get('host_id'))
        candidates = sel.get('candidates') or []

        for c in candidates:
            mtype = c.get('type')
            name = c.get('name')
            cfg = c.get('config') or {}
            if mtype not in ('http', 'tcp', 'docker_container', 'udp_listen'):
                skipped += 1
                continue
            if not name:
                skipped += 1
                continue

            cfg_json = json.dumps(cfg, sort_keys=True)

            # de-dupe by host/type/config_json
            existing = Monitor.query.filter_by(host_id=host_id, type=mtype, config_json=cfg_json).first()
            if existing:
                skipped += 1
                continue

            m = Monitor(
                host_id=host_id,
                name=name,
                type=mtype,
                enabled=True,
                interval_seconds=interval_seconds,
                timeout_seconds=timeout_seconds,
                config_json=cfg_json,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            db.session.add(m)
            created += 1

    db.session.commit()
    return jsonify({'created': created, 'skipped': skipped})


@monitoring_bp.get('/hosts/<int:host_id>/monitoring')
def host_monitoring_page(host_id: int):
    host = db.session.get(Host, int(host_id))
    if not host:
        return 'Host not found', 404

    monitors = Monitor.query.filter_by(host_id=host.id).order_by(Monitor.id.asc()).all()
    if not monitors:
        return redirect(f'/monitoring/wizard?host_id={host.id}')

    docker_snapshot = (
        HostDockerInventory.query.filter_by(host_id=host.id)
        .order_by(HostDockerInventory.captured_at.desc())
        .first()
    )
    return render_template('monitoring.html', host=host, monitors=monitors, docker_snapshot=docker_snapshot)



@monitoring_bp.get('/api/hosts/<int:host_id>/monitoring')
def api_host_monitoring(host_id: int):
    host = db.session.get(Host, int(host_id))
    if not host:
        return jsonify({'error': 'Host not found'}), 404

    monitors = Monitor.query.filter_by(host_id=host.id).order_by(Monitor.id.asc()).all()
    docker_snapshot = (
        HostDockerInventory.query.filter_by(host_id=host.id)
        .order_by(HostDockerInventory.captured_at.desc())
        .first()
    )

    return jsonify({
        'host': host.to_dict() if hasattr(host, 'to_dict') else {'id': host.id, 'ip_address': host.ip_address, 'friendly_name': host.friendly_name},
        'monitors': [m.to_dict(include_checks=False) for m in monitors],
        'docker_snapshot': docker_snapshot.to_dict() if docker_snapshot else None,
    })


def _execute_monitor_now(m: Monitor):
    """Execute a monitor immediately and persist a MonitorCheck + update monitor last_* fields."""
    from datetime import datetime
    from monitoring.scheduler import db as _db
    from database import MonitorCheck

    try:
        timeout = int(m.timeout_seconds or 10)
    except Exception:
        timeout = 10

    try:
        if m.type == 'tcp':
            from monitoring.runner import execute_tcp_check
            cfg = m.config()
            result = execute_tcp_check(cfg.get('hostname') or m.host.ip_address, int(cfg.get('port')), timeout)
        elif m.type == 'http':
            from monitoring.runner import execute_http_check
            result = execute_http_check(m.config(), timeout)
        elif m.type == 'docker_container':
            from monitoring.runner import execute_docker_container_check
            from monitoring.sshkeys import materialize_ssh_key_path
            cfg = m.config()
            user = (m.host.ssh_user or 'root')
            key_path = materialize_ssh_key_path(m.host.ssh_key_id)
            result = execute_docker_container_check(user, m.host.ip_address, key_path, cfg.get('container_name') or '', timeout)
        elif m.type == 'udp_listen':
            from monitoring.runner import execute_udp_listen_check
            from monitoring.sshkeys import materialize_ssh_key_path
            cfg = m.config()
            user = (m.host.ssh_user or 'root')
            key_path = materialize_ssh_key_path(m.host.ssh_key_id)
            result = execute_udp_listen_check(user, m.host.ip_address, key_path, int(cfg.get('port') or 0), timeout)
        else:
            raise ValueError(f'Unsupported monitor type: {m.type}')

        chk = MonitorCheck(
            monitor_id=m.id,
            checked_at=datetime.utcnow(),
            status=result.status,
            response_time_ms=int(result.response_time_ms),
            status_code=getattr(result, 'status_code', None),
            error_message=getattr(result, 'error_message', None),
        )
        _db.session.add(chk)
        m.last_status = chk.status
        m.last_checked_at = chk.checked_at
        m.last_response_time_ms = chk.response_time_ms
        m.last_status_code = chk.status_code
        m.last_error_message = chk.error_message
        _db.session.commit()
        return {'ok': True, 'monitor': m.to_dict(include_checks=False), 'check': chk.to_dict()}
    except Exception as e:
        try:
            _db.session.rollback()
        except Exception:
            pass
        return {'ok': False, 'error': str(e)[:500]}


@monitoring_bp.post('/api/monitors/<int:monitor_id>/test')
def api_monitor_test(monitor_id: int):
    m = db.session.get(Monitor, int(monitor_id))
    if not m:
        return jsonify({'error': 'Monitor not found'}), 404
    res = _execute_monitor_now(m)
    if not res.get('ok'):
        return jsonify(res), 500
    return jsonify(res)


@monitoring_bp.patch('/api/monitors/<int:monitor_id>')
def api_monitor_patch(monitor_id: int):
    m = db.session.get(Monitor, int(monitor_id))
    if not m:
        return jsonify({'error': 'Monitor not found'}), 404

    data = request.get_json(force=True) or {}

    if 'name' in data:
        m.name = str(data.get('name') or '').strip() or m.name
    if 'enabled' in data:
        m.enabled = bool(data.get('enabled'))
    if 'interval_seconds' in data:
        try:
            m.interval_seconds = int(data.get('interval_seconds'))
        except Exception:
            pass
    if 'timeout_seconds' in data:
        try:
            m.timeout_seconds = int(data.get('timeout_seconds'))
        except Exception:
            pass

    if 'config' in data:
        cfg = data.get('config') or {}
        # For http monitors, normalize acceptedStatusCodes
        if m.type == 'http' and isinstance(cfg, dict) and 'acceptedStatusCodes' in cfg:
            codes = cfg.get('acceptedStatusCodes')
            if isinstance(codes, str):
                # allow "200,403"
                parts = [c.strip() for c in codes.split(',') if c.strip()]
                codes = [int(x) for x in parts if x.isdigit()]
            if isinstance(codes, list):
                norm = []
                for c in codes:
                    try:
                        norm.append(int(c))
                    except Exception:
                        pass
                cfg['acceptedStatusCodes'] = sorted(set(norm))
        m.config_json = json.dumps(cfg, sort_keys=True)

    db.session.commit()
    return jsonify({'ok': True, 'monitor': m.to_dict(include_checks=False)})


@monitoring_bp.delete('/api/monitors/<int:monitor_id>')
def api_monitor_delete(monitor_id: int):
    m = db.session.get(Monitor, int(monitor_id))
    if not m:
        return jsonify({'error': 'Monitor not found'}), 404
    db.session.delete(m)
    db.session.commit()
    return jsonify({'ok': True})


@monitoring_bp.post('/api/monitors/bulk')
def api_monitors_bulk():
    data = request.get_json(force=True) or {}
    action = (data.get('action') or '').strip()
    ids = data.get('ids') or []
    try:
        ids = [int(x) for x in ids]
    except Exception:
        return jsonify({'error': 'Invalid ids'}), 400

    if not ids:
        return jsonify({'error': 'No ids provided'}), 400

    if action == 'test':
        results = []
        for mid in ids:
            m = db.session.get(Monitor, int(mid))
            if not m:
                results.append({'id': mid, 'ok': False, 'error': 'not found'})
                continue
            results.append({'id': mid, **_execute_monitor_now(m)})
        return jsonify({'ok': True, 'results': results})

    if action == 'delete':
        deleted = 0
        for mid in ids:
            m = db.session.get(Monitor, int(mid))
            if not m:
                continue
            db.session.delete(m)
            deleted += 1
        db.session.commit()
        return jsonify({'ok': True, 'deleted': deleted})

    return jsonify({'error': 'Unsupported action'}), 400
