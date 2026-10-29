"""SQLite backup and restore routes.

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

from flask import (Blueprint, Response, current_app, g, jsonify, request)
from sqlalchemy import text as sql_text

from database import db, AppSetting

bp = Blueprint('inventory_dbadmin', __name__)


@bp.before_request
def _guard_db_admin():
    """DB backup/restore is destructive: opt-in via env AND authenticated."""
    if not current_app.config.get('AILOG_ALLOW_DB_ADMIN'):
        return jsonify({
            'error': 'Database admin endpoints are disabled. Set AILOG_ALLOW_DB_ADMIN=1 to enable them.'
        }), 403
    mode = current_app.config.get('AILOG_AUTH_MODE', 'none')
    if mode != 'none' and not getattr(g, 'auth_user', None):
        return jsonify({'error': 'Authentication required'}), 401
    return None


MIN_DB_BYTES = 4096
REQUIRED_TABLES = ('host',)


def _validate_sqlite_upload(path):
    """Reject anything that is not a plausible, structurally valid Homelab DB.

    Raises ValueError with a user-safe message.
    """
    size = os.path.getsize(path)
    if size < MIN_DB_BYTES:
        raise ValueError('Uploaded file is too small to be a database backup')
    with open(path, 'rb') as fh:
        if fh.read(16) != b'SQLite format 3\x00':
            raise ValueError('Uploaded file is not a valid sqlite database')
    conn = sqlite3.connect('file:' + path + '?mode=ro', uri=True)
    try:
        row = conn.execute('PRAGMA integrity_check').fetchone()
        if not row or str(row[0]).lower() != 'ok':
            raise ValueError('Uploaded database failed the integrity check')
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        missing = [t for t in REQUIRED_TABLES if t not in tables]
        if missing:
            raise ValueError('Uploaded database is missing required tables: ' + ', '.join(missing))
    finally:
        conn.close()


def _pre_restore_backup(db_path):
    """Copy the live database aside before it is replaced. Returns the copy path."""
    if not os.path.exists(db_path):
        return None
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    backup_path = f'{db_path}.pre-restore-{stamp}'
    shutil.copyfile(db_path, backup_path)
    return backup_path


def _put_setting(key, value):
    """Local mirror of app._setting_set: routes always run in an app context."""
    row = AppSetting.query.get(key)
    if not row:
        row = AppSetting(key=key)
        db.session.add(row)
    row.value_json = json.dumps(value)
    db.session.commit()


def _get_sqlite_db_file_path():
    '''Return sqlite file path if DATABASE_URL is sqlite:////... else None.'''
    url = current_app.config.get('SQLALCHEMY_DATABASE_URI', '') or ''
    if not url.startswith('sqlite:'):
        return None
    # sqlite:////absolute/path or sqlite:///relative/path
    if url.startswith('sqlite:////'):
        # Keep leading slash
        return '/' + url[len('sqlite:////'):]
    if url.startswith('sqlite:///'):
        return url[len('sqlite:///'):]
    if url == 'sqlite://':
        return None
    if url.startswith('sqlite:'):
        return url.split('sqlite:', 1)[1]
    return None


@bp.route('/admin/db/backup', methods=['GET'])
def backup_database():
    '''Download a copy of the current sqlite database.'''
    try:
        db_path = _get_sqlite_db_file_path()
        if not db_path:
            return jsonify({'error': 'Database backup only supported for sqlite'}), 400
        if not os.path.exists(db_path):
            return jsonify({'error': f'Database file not found: {db_path}'}), 404

        ts = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        filename = f"homelab-manager-backup-{ts}.db"

        with open(db_path, 'rb') as f:
            data = f.read()

        return Response(
            data,
            mimetype='application/octet-stream',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/admin/db/restore', methods=['POST'])
def restore_database():
    '''Restore sqlite database from uploaded file.'''
    try:
        db_path = _get_sqlite_db_file_path()
        if not db_path:
            return jsonify({'error': 'Database restore only supported for sqlite'}), 400

        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400

        upload = request.files['file']
        if not upload or not upload.filename:
            return jsonify({'error': 'No file selected'}), 400

        tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        tmp_path = tmp.name
        tmp.close()
        upload.save(tmp_path)

        try:
            try:
                _validate_sqlite_upload(tmp_path)
            except ValueError as exc:
                return jsonify({'error': str(exc)}), 400

            os.makedirs(os.path.dirname(db_path) or '.', exist_ok=True)

            # Keep a timestamped copy of the live DB so a bad restore is recoverable.
            backup_path = _pre_restore_backup(db_path)

            # Drop connections and replace DB file
            try:
                db.session.remove()
            except Exception:
                pass
            try:
                db.engine.dispose()
            except Exception:
                pass

            shutil.copyfile(tmp_path, db_path)

        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

        return jsonify({
            'message': 'Database restored successfully. Please refresh the page.',
            'backup': backup_path,
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# --- SERVER-SENT EVENTS (SSE) STREAMING ENDPOINTS ---




@bp.route('/admin/db/restore-selective', methods=['POST'])
def restore_database_selective():
    '''Selective restore from uploaded sqlite DB.

    Flags (form fields):
    - restore_ai
    - restore_discord
    - restore_hosts (replace-all)
    - restore_schedule (interval/is_running only)
    - restore_ai_search (prompt/keywords)
    - restore_suricata (suricata sensors + prompt)
    '''
    try:
        db_path = _get_sqlite_db_file_path()
        if not db_path:
            return jsonify({'error': 'Database restore only supported for sqlite'}), 400

        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400

        upload = request.files['file']
        if not upload or not upload.filename:
            return jsonify({'error': 'No file selected'}), 400

        def _flag(name: str) -> bool:
            v = (request.form.get(name) or '').lower()
            return v in ('1', 'true', 'yes', 'on')

        restore_ai = _flag('restore_ai')
        restore_discord = _flag('restore_discord')
        restore_hosts = _flag('restore_hosts')
        restore_schedule = _flag('restore_schedule')
        restore_ai_search = _flag('restore_ai_search')
        restore_suricata = _flag('restore_suricata')

        if not any([restore_ai, restore_discord, restore_hosts, restore_schedule, restore_ai_search, restore_suricata]):
            return jsonify({'error': 'No restore categories selected'}), 400

        tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        tmp_path = tmp.name
        tmp.close()
        upload.save(tmp_path)

        try:
            try:
                _validate_sqlite_upload(tmp_path)
            except ValueError as exc:
                return jsonify({'error': str(exc)}), 400

            src = sqlite3.connect(tmp_path)
            src.row_factory = sqlite3.Row

            def table_exists(conn, name: str) -> bool:
                cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,))
                return cur.fetchone() is not None

            def read_table(conn, name: str):
                cur = conn.execute(f"SELECT * FROM {name}")
                rows = [dict(r) for r in cur.fetchall()]
                return rows

            def exec_many(stmt, rows):
                if not rows:
                    return
                db.session.execute(stmt, rows)

            # Avoid using a stale connection while mutating
            try:
                db.session.remove()
            except Exception:
                pass
            try:
                db.engine.dispose()
            except Exception:
                pass

            # SETTINGS restore (app_settings)
            if restore_ai or restore_discord or restore_schedule or restore_ai_search:
                # Support both new and old backups: prefer app_settings
                if table_exists(src, 'app_settings'):
                    keys = set()
                    if restore_ai:
                        keys |= {'analysis_provider', 'openai_api_key', 'ollama_url', 'ollama_model'}
                    if restore_discord:
                        keys |= {'discord_webhook_url'}
                    if restore_schedule:
                        keys |= {'schedule.is_running', 'schedule.interval_hours'}
                    if restore_suricata:
                        keys |= {'suricata.prompt'}

                    if keys:
                        cur = src.execute(
                            f"SELECT key, value_json FROM app_settings WHERE key IN ({','.join(['?']*len(keys))})",
                            tuple(sorted(keys))
                        )
                        rows = cur.fetchall()
                        for r in rows:
                            _put_setting(r['key'], json.loads(r['value_json']) if r['value_json'] else None)
                else:
                    # Fallback: try legacy scheduler_config.json style keys in a settings-like table (none), so skip.
                    pass

            

            # SURICATA restore (replace-all for suricata_* tables)
            if restore_suricata:
                suri_tables = [
                    'suricata_sensors',
                    'suricata_ingest_state',
                    'suricata_alert_buckets',
                    'suricata_fast_alert_buckets',
                    'suricata_stats_counter_buckets',
                ]
                suri_tables = [t for t in suri_tables if table_exists(src, t)]
                if not suri_tables:
                    return jsonify({'error': 'Backup does not contain Suricata tables'}), 400

                # Delete then insert
                for t in suri_tables:
                    db.session.execute(sql_text(f"DELETE FROM {t}"))

                for t in suri_tables:
                    rows = read_table(src, t)
                    if not rows:
                        continue
                    cols = list(rows[0].keys())
                    placeholders = ','.join([f":{c}" for c in cols])
                    col_list = ','.join(cols)
                    stmt = sql_text(f"INSERT INTO {t} ({col_list}) VALUES ({placeholders})")
                    exec_many(stmt, rows)
# HOSTS restore (replace-all)
            if restore_hosts:
                required_tables = ['hosts']
                if not all(table_exists(src, t) for t in required_tables):
                    return jsonify({'error': 'Backup does not contain required host tables'}), 400

                # Determine which tables we can restore
                tables = [
                    'host_groups', 'host_tags',
                    'system_info', 'services', 'host_logs',
                    'hosts',
                    'groups', 'tags',
                    'ssh_keys',
                ]
                tables = [t for t in tables if table_exists(src, t)]

                # Delete in FK-safe-ish order (association, dependents, base)
                delete_order = [t for t in ['host_groups','host_tags','system_info','services','host_logs','hosts','groups','tags','ssh_keys'] if t in tables]
                for t in delete_order:
                    db.session.execute(sql_text(f"DELETE FROM {t}"))

                # Insert rows
                for t in tables:
                    rows = read_table(src, t)
                    if not rows:
                        continue
                    cols = list(rows[0].keys())
                    placeholders = ','.join([f":{c}" for c in cols])
                    col_list = ','.join(cols)
                    stmt = sql_text(f"INSERT INTO {t} ({col_list}) VALUES ({placeholders})")
                    exec_many(stmt, rows)

            db.session.commit()

        finally:
            try:
                src.close()
            except Exception:
                pass
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

        return jsonify({'message': 'Selective restore complete. Please refresh the page.'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
