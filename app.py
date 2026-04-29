import subprocess
from flask import Flask, render_template, jsonify, request, Response, stream_with_context, has_app_context
import shlex
import os
import datetime
import openai
import requests
import json
import re
import sqlite3
import atexit
from apscheduler.schedulers.background import BackgroundScheduler
import threading
import queue
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from functools import lru_cache
import ast
import tempfile
from sqlalchemy import text as sql_text
from sqlalchemy.exc import IntegrityError
import shutil
from database import db, Host, SystemInfo, Service, HostLog, SSHKey, Group, Tag, AppSetting, Schedule, ScheduleHost, ScheduleSource, SuricataSensor, SuricataIngestState, SuricataAlertBucket, SuricataFastAlertBucket, SuricataStatsCounterBucket, Monitor, MonitorCheck, HostDockerInventory
from wizard_helpers import test_ssh_connection, collect_system_info, collect_services, execute_remote_command
from utils.sshkey_crypto import encrypt_str, decrypt_str, is_configured as sshkey_crypto_configured, generate_master_key, SSHKeyCryptoError, compute_key_checksum, verify_key_checksum, normalize_ssh_key_text

# --- INITIALIZATION ---
app = Flask(__name__, instance_path=None)

# Monitoring subsystem (modular bolt-on)
from monitoring import monitoring_bp
app.register_blueprint(monitoring_bp)

# --- DATABASE CONFIGURATION ---
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:////home/david/code/ailog/ailog.db')
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Create database tables on startup

def _ensure_suricata_endpoint_columns():
    """Lightweight SQLite migration: add endpoint/port columns used by Endpoint Stats."""
    try:
        uri = str(app.config.get('SQLALCHEMY_DATABASE_URI') or '')
        if not uri.startswith('sqlite'):
            return
    except Exception:
        return

    def _col_exists(table: str, col: str) -> bool:
        try:
            rows = db.session.execute(sql_text(f"PRAGMA table_info({table})")).fetchall()
            return any(r[1] == col for r in rows)
        except Exception:
            return False

    def _add_col(table: str, col: str, decl: str):
        if _col_exists(table, col):
            return
        try:
            db.session.execute(sql_text(f"ALTER TABLE {table} ADD COLUMN {col} {decl}"))
            db.session.commit()
        except Exception:
            db.session.rollback()

    for c, decl in [('src_ip','TEXT'),('dst_ip','TEXT'),('src_port','INTEGER'),('dst_port','INTEGER')]:
        _add_col('suricata_fast_alert_buckets', c, decl)

    for c, decl in [('src_ip','TEXT'),('dst_ip','TEXT'),('src_port','INTEGER'),('dst_port','INTEGER'),('proto','TEXT'),('app_proto','TEXT')]:
        _add_col('suricata_alert_buckets', c, decl)





def _ensure_sshkey_encryption_columns():
    """Lightweight SQLite migration: add encryption columns to ssh_keys and optionally encrypt legacy plaintext rows."""
    try:
        uri = str(app.config.get('SQLALCHEMY_DATABASE_URI') or '')
        if not uri.startswith('sqlite'):
            return
    except Exception:
        return

    def _col_exists(table: str, col: str) -> bool:
        try:
            rows = db.session.execute(sql_text(f"PRAGMA table_info({table})")).fetchall()
            return any(r[1] == col for r in rows)
        except Exception:
            return False

    def _add_col(table: str, col: str, decl: str):
        if _col_exists(table, col):
            return
        try:
            db.session.execute(sql_text(f"ALTER TABLE {table} ADD COLUMN {col} {decl}"))
            db.session.commit()
        except Exception:
            db.session.rollback()

    _add_col('ssh_keys', 'is_encrypted', 'BOOLEAN DEFAULT 0')
    _add_col('ssh_keys', 'enc_version', 'TEXT')

    # Best-effort migration of legacy plaintext -> encrypted when master key is configured
    if not sshkey_crypto_configured():
        return

    try:
        keys = SSHKey.query.all()
        changed = False
        for k in keys:
            if getattr(k, 'is_encrypted', False):
                continue
            pt = (k.key_content or '').strip()
            if not pt:
                continue
            k.key_content = encrypt_str(pt)
            k.is_encrypted = True
            k.enc_version = 'fernet-v1'
            changed = True
        if changed:
            db.session.commit()
    except Exception:
        db.session.rollback()

with app.app_context():
    db.create_all()
    _ensure_suricata_endpoint_columns()
    _ensure_sshkey_encryption_columns()

scheduler = BackgroundScheduler(daemon=True)

# --- MULTI-SCHEDULE RUN QUEUE (serial execution) ---
# Single worker thread processes schedule runs one-at-a-time.
schedule_run_queue: queue.Queue = queue.Queue()
_schedule_worker_started = False

# Schedule run status (in-memory): schedule_id -> dict
schedule_status_map = {}


def _enqueue_schedule_run(schedule_id: int, reason: str = 'scheduled', emit=None):
    schedule_run_queue.put({'schedule_id': schedule_id, 'reason': reason, 'emit': emit, 'enqueued_at': datetime.datetime.now(datetime.timezone.utc).isoformat()})


def _ensure_schedule_worker():
    global _schedule_worker_started
    if _schedule_worker_started:
        return

    def worker_loop():
        while True:
            item = schedule_run_queue.get()
            try:
                sid = int(item.get('schedule_id'))
                reason = item.get('reason') or 'scheduled'
                emit = item.get('emit')

                # track status
                schedule_status_map[sid] = {
                    'state': 'running',
                    'reason': reason,
                    'queued_at': item.get('enqueued_at'),
                    'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    'finished_at': None,
                    'error': None,
                }

                def _emit(payload):
                    try:
                        if emit:
                            emit(payload)
                    except Exception:
                        pass

                # Load schedule and run inside app context
                with app.app_context():
                    sched = Schedule.query.get(sid)
                    if not sched or not sched.enabled:
                        schedule_status_map[sid].update({
                            'state': 'skipped',
                            'finished_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                            'error': 'Schedule not found or disabled',
                        })
                        _emit({'status': 'log', 'message': 'Skipped: schedule not found or disabled.'})
                    else:
                        _emit({'status': 'progress', 'message': f'Running schedule: {sched.name}', 'progress': 0})
                        _run_schedule(sched, emit=_emit)
                        schedule_status_map[sid].update({
                            'state': 'idle',
                            'finished_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        })
            except Exception as e:
                try:
                    sid = int(item.get('schedule_id'))
                    schedule_status_map[sid] = {
                        'state': 'error',
                        'reason': item.get('reason') or 'scheduled',
                        'queued_at': item.get('enqueued_at'),
                        'started_at': schedule_status_map.get(sid, {}).get('started_at'),
                        'finished_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        'error': str(e),
                    }
                except Exception:
                    pass
            finally:
                schedule_run_queue.task_done()

    t = threading.Thread(target=worker_loop, daemon=True)
    t.start()
    _schedule_worker_started = True


# --- CONFIGURATION ---
LOG_DIRECTORY = '/var/log'
MAX_CHAR_COUNT = 40000 
DISCORD_ALERT_KEYWORDS = ['error', 'issue', 'failed', 'warning', 'critical', 'exception', 'denied', 'unable']

# AI Search (prompt + keywords) - defaults; can be overridden per DB settings
DEFAULT_AI_SEARCH_PROMPT = (
    "Analyse this log for any errors and create a summary report,"
    " troubleshooting tips and any other advice relating to any other issues found."
)
DEFAULT_ALERT_KEYWORDS = DISCORD_ALERT_KEYWORDS


def get_ai_search_prompt():
    return (_setting_get('ai.search_prompt', DEFAULT_AI_SEARCH_PROMPT) or DEFAULT_AI_SEARCH_PROMPT).strip()

DEFAULT_SURICATA_PROMPT = "Analyse this data and provide a summary and executive summary for an engineer to understand what it is telling them."

def get_suricata_prompt():
    return _setting_get('suricata.prompt', DEFAULT_SURICATA_PROMPT)

def set_suricata_prompt(prompt: str):
    _setting_set('suricata.prompt', (prompt or DEFAULT_SURICATA_PROMPT).strip())


def get_ai_alert_keywords():
    kws = _setting_get('ai.alert_keywords', DEFAULT_ALERT_KEYWORDS)
    if not isinstance(kws, list):
        return list(DEFAULT_ALERT_KEYWORDS)
    out = []
    for k in kws:
        s = str(k).strip()
        if s:
            out.append(s)
    return out


CONFIG_FILE = 'scheduler_config.json'
HOSTS_FILE = 'hosts.json'


# --- DB-BACKED APP SETTINGS ---

def _setting_get(key, default=None):
    def _do():
        row = AppSetting.query.get(key)
        if not row or row.value_json is None:
            return default
        try:
            return json.loads(row.value_json)
        except Exception:
            return row.value_json

    if has_app_context():
        return _do()
    with app.app_context():
        return _do()


def _setting_set(key, value):
    def _do():
        row = AppSetting.query.get(key)
        if not row:
            row = AppSetting(key=key)
            db.session.add(row)
        row.value_json = json.dumps(value)
        db.session.commit()

    if has_app_context():
        return _do()
    with app.app_context():
        return _do()


def _migrate_scheduler_config_file_to_db():
    # One-time migration from scheduler_config.json into DB settings.
    if not os.path.exists(CONFIG_FILE):
        return
    try:
        with open(CONFIG_FILE, 'r') as f:
            cfg = json.load(f)
    except Exception:
        return

    mapping = {
        'analysis_provider': 'analysis_provider',
        'openai_api_key': 'openai_api_key',
        'ollama_url': 'ollama_url',
        'ollama_model': 'ollama_model',
        'webhook_url': 'discord_webhook_url',
        'discord_webhook_url': 'discord_webhook_url',
        'is_running': 'schedule.is_running',
        'interval': 'schedule.interval_hours',
        'sources': 'schedule.sources',
    }

    changed = False
    for src_key, dst_key in mapping.items():
        if src_key not in cfg:
            continue
        if AppSetting.query.get(dst_key) is not None:
            continue
        db.session.add(AppSetting(key=dst_key, value_json=json.dumps(cfg.get(src_key))))
        changed = True

    if changed:
        db.session.commit()

# --- HELPER FUNCTIONS for HOSTS ---
def load_hosts():
    if not os.path.exists(HOSTS_FILE):
        with open(HOSTS_FILE, 'w') as f: json.dump({}, f)
        return {}
    try:
        with open(HOSTS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {}

def save_hosts(hosts):
    with open(HOSTS_FILE, 'w') as f:
        json.dump(hosts, f, indent=4)

def get_ssh_prefix_args(user, ip, identity_file=None):
    """Construct the SSH command prefix as a list of args."""
    args = [
        "ssh", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes"
    ]
    if identity_file:
        args += ["-i", identity_file]
    args.append(f"{user}@{ip}")
    return args



# -----------------------------
# --- SEARCH FUNCTIONALITY ---
@app.route('/search', methods=['POST'])
def search_logs():
    """Search for keywords/phrases across logs"""
    data = request.get_json()
    query = data.get('query', '').strip()
    search_scope = data.get('scope', 'all')  # 'all' or specific log identifier
    host_filter = data.get('host_filter', [])  # list of host IDs to search in
    case_sensitive = data.get('case_sensitive', False)
    
    if not query:
        return jsonify({'error': 'Search query is required'}), 400
    
    search_results = []
    failed_hosts = []
    
    # Get list of hosts to search
    hosts = load_hosts()
    search_hosts = [('local', 'Localhost')]
    
    # Add remote hosts
    for host_id, host_data in hosts.items():
        if not host_filter or host_id in host_filter:
            search_hosts.append((host_id, host_data['friendly_name']))
    
    # Filter hosts if host_filter is specified
    if host_filter:
        search_hosts = [(h_id, h_name) for h_id, h_name in search_hosts if h_id in host_filter or h_id == 'local']
    
    # Perform search on each host
    for host_id, host_name in search_hosts:
        try:
            host_results = search_host_logs(host_id, host_name, query, search_scope, case_sensitive)
            search_results.extend(host_results)
        except Exception as e:
            error_msg = str(e)
            if 'timeout' in error_msg.lower():
                error_msg = "Connection timed out"
            elif 'connection refused' in error_msg.lower():
                error_msg = "Connection refused"
            failed_hosts.append({'host_id': host_id, 'host_name': host_name, 'error': error_msg})
    
    return jsonify({
        'results': search_results,
        'total_matches': len(search_results),
        'failed_hosts': failed_hosts,
        'query': query,
        'scope': search_scope
    })

def search_host_logs(host_id, host_name, query, search_scope, case_sensitive):
    """Search for query in logs on a specific host"""
    results = []
    
    # Get available log sources from the host
    try:
        # List log files
        cmd_ls = f"sudo ls -p {shlex.quote(LOG_DIRECTORY)}"
        res_ls = execute_command(host_id, cmd_ls, timeout=10)
        filenames = [entry for entry in res_ls.stdout.strip().split('\n') if not entry.endswith('/') and entry]
        
        # Search in log files
        for filename in filenames:
            if search_scope != 'all' and search_scope != f"file:{filename}":
                continue
                
            try:
                # Use grep to search within the file
                grep_flags = "-i" if not case_sensitive else ""
                if filename.endswith('.gz'):
                    search_cmd = f"sudo zcat {shlex.quote(os.path.join(LOG_DIRECTORY, filename))} 2>/dev/null | grep {grep_flags} -n {shlex.quote(query)} | head -20"
                else:
                    search_cmd = f"sudo grep {grep_flags} -n {shlex.quote(query)} {shlex.quote(os.path.join(LOG_DIRECTORY, filename))} | head -20"
                
                result = execute_command(host_id, search_cmd, timeout=15)
                
                if result.stdout.strip():
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if ':' in line:
                            line_num, content = line.split(':', 1)
                            results.append({
                                'host_id': host_id,
                                'host_name': host_name,
                                'log_name': filename,
                                'log_type': 'file',
                                'line_number': line_num,
                                'content': content.strip(),
                                'timestamp': None  # Could extract from log line if needed
                            })
            except Exception as e:
                # Skip files we can't read
                continue
        
        # Search in journal services if scope allows
        if search_scope == 'all' or search_scope.startswith('journal:'):
            try:
                cmd_journal = "sudo journalctl --field _SYSTEMD_UNIT | sort | uniq | head -10"
                res_journal = execute_command(host_id, cmd_journal, timeout=10)
                journal_units = [unit for unit in res_journal.stdout.strip().split('\n') if unit]
                
                for unit in journal_units:
                    if search_scope != 'all' and search_scope != f"journal:{unit}":
                        continue
                        
                    try:
                        # Search in journal for this unit
                        grep_flags = "-i" if not case_sensitive else ""
                        journal_search_cmd = f"sudo journalctl -u {shlex.quote(unit)} -n 100 --no-pager | grep {grep_flags} -n {shlex.quote(query)} | head -10"
                        result = execute_command(host_id, journal_search_cmd, timeout=15)
                        
                        if result.stdout.strip():
                            lines = result.stdout.strip().split('\n')
                            for line in lines:
                                if ':' in line:
                                    line_num, content = line.split(':', 1)
                                    results.append({
                                        'host_id': host_id,
                                        'host_name': host_name,
                                        'log_name': unit,
                                        'log_type': 'journal',
                                        'line_number': line_num,
                                        'content': content.strip(),
                                        'timestamp': None
                                    })
                    except Exception as e:
                        continue
                        
            except Exception as e:
                # Skip journal search if it fails
                pass
                
    except Exception as e:
        raise Exception(f"Failed to search logs on {host_name}: {str(e)}")
    
    return results

# --- CORE LOGIC (Refactored for Remote Execution) ---
def execute_command(hostname, command_str, timeout=10):
    """Execute a command either locally or against a remote host.

    hostname can be:
      - 'local' to run on this machine
      - a config host ID from load_hosts()
      - a database-backed host ID like 'db-<id>' created by the wizard
    """
    ssh_prefix_args = []
    if hostname != 'local':
        # First try config-based hosts
        hosts = load_hosts() or {}
        host_info = hosts.get(hostname)

        # If not found in config, try database hosts with prefix db-<id>
        if not host_info and hostname.startswith('db-'):
            try:
                from app import Host  # local import to avoid circulars at import time
            except Exception:
                Host = None
            if Host is not None:
                try:
                    host_id = int(hostname.split('-', 1)[1])
                    from flask import current_app
                    from app import db
                    # We assume we're in an app/request context when this is called via Flask routes
                    host_obj = Host.query.get(host_id)
                    if host_obj:
                        host_info = {
                            'user': host_obj.ssh_user or 'root',
                            'ip': host_obj.ip_address,
                            'ssh_key_id': host_obj.ssh_key_id,
                        }
                except Exception as e:
                    print(f"[ERROR] Failed to resolve DB host '{hostname}': {e}")

        if not host_info:
            raise ValueError(f"Host ID '{hostname}' not found in configuration or database.")

        identity_path = _materialize_ssh_key_path(host_info.get('ssh_key_id'))
        ssh_prefix_args = get_ssh_prefix_args(host_info['user'], host_info['ip'], identity_file=identity_path)

    cmd_list = ssh_prefix_args + [command_str] if ssh_prefix_args else [command_str]
    # Use shell=False for remote commands for security, shell=True for local for simplicity with sudo
    shell_mode = not bool(ssh_prefix_args)
    print(f"[DEBUG] Executing command: {cmd_list}")
    try:
        result = subprocess.run(cmd_list, shell=shell_mode, capture_output=True, text=True, check=True, timeout=timeout)
        return result
    except subprocess.CalledProcessError as e:
        # Ensure we log and propagate stderr/stdout for actionable SSH failures (e.g. Permission denied).
        stderr = (e.stderr or '').strip()
        stdout = (e.stdout or '').strip()
        print(f"[DEBUG] SSH command failed with return code {e.returncode}", flush=True)
        print(f"[DEBUG] STDERR: {stderr[:2000]}", flush=True)
        print(f"[DEBUG] STDOUT: {stdout[:2000]}", flush=True)
        # Raise an error that includes stderr so the UI can surface the real SSH reason.
        raise RuntimeError(f"SSH command failed (rc={e.returncode}): {stderr or '<no stderr>'}")

def get_log_sources_from_host_stream(hostname='local'):
    def generate_event(data):
        return f"data: {json.dumps(data)}\n\n"
    try:
        yield generate_event({'status': 'progress', 'message': 'Listing log files...', 'progress': 5})
        cmd_ls = f"sudo ls -p {shlex.quote(LOG_DIRECTORY)}"
        res_ls = execute_command(hostname, cmd_ls)
        filenames = [entry for entry in res_ls.stdout.strip().split('\n') if not entry.endswith('/') and entry]
        total_files = len(filenames)
        yield generate_event({'status': 'progress', 'message': f'Found {total_files} potential log files.', 'progress': 10})
        for i, filename in enumerate(filenames):
            progress = 10 + int((i / total_files) * 80) if total_files > 0 else 90
            yield generate_event({'status': 'progress', 'message': f'Checking: {filename}', 'progress': progress})
            try:
                cmd_stat = f"sudo stat -c '%s %Y' {shlex.quote(os.path.join(LOG_DIRECTORY, filename))}"
                res_stat = execute_command(hostname, cmd_stat)
                size_bytes, mod_time_epoch = map(int, res_stat.stdout.strip().split())
                source_data = {'type': 'file', 'name': filename, 'size_bytes': size_bytes,'size_formatted': format_bytes(size_bytes), 'modified_epoch': mod_time_epoch,'modified_formatted': format_relative_time(mod_time_epoch)}
                yield generate_event({'status': 'source', 'data': source_data})
            except Exception as e:
                print(f"Could not stat file '{filename}' on '{hostname}': {e}")
                continue
        yield generate_event({'status': 'progress', 'message': 'Fetching journald services...', 'progress': 95})
        try:
            cmd_journal = "sudo journalctl --field _SYSTEMD_UNIT | sort | uniq"
            res_journal = execute_command(hostname, cmd_journal)
            journal_units = [unit for unit in res_journal.stdout.strip().split('\n') if unit]
            for unit in journal_units:
                source_data = {'type': 'journal', 'name': unit, 'size_bytes': 0, 'size_formatted': 'N/A','modified_epoch': 0, 'modified_formatted': 'Journald Service'}
                yield generate_event({'status': 'source', 'data': source_data})
        except Exception as e:
            print(f"Could not fetch journald units from '{hostname}': {e}")
        yield generate_event({'status': 'complete', 'message': 'Done!'})
    except Exception as e:
        yield generate_event({'status': 'error', 'message': str(e)})

# --- HELPER FUNCTIONS ---
def format_bytes(size_bytes):
    if size_bytes == 0: return "0B"
    power, n = 1024, 0
    power_labels = {0: 'B', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
    while size_bytes >= power and n < len(power_labels) - 1:
        size_bytes /= power
        n += 1
    return f"{size_bytes:.1f} {power_labels[n]}" if n > 0 else f"{int(size_bytes)} {power_labels[n]}"

def format_relative_time(epoch_time):
    if epoch_time == 0: return "N/A"
    delta = datetime.datetime.now() - datetime.datetime.fromtimestamp(epoch_time)
    if delta.days > 1: return f"{delta.days} days ago"
    if delta.days == 1: return "Yesterday"
    if delta.seconds >= 3600: return f"{delta.seconds // 3600} hours ago"
    if delta.seconds >= 60: return f"{delta.seconds // 60} mins ago"
    return "Just now"


def extract_log_time_range(log_content):
    """Extract (start_iso, end_iso) from the first/last timestamped lines, or (None, None)."""
    if not log_content:
        return None, None

    lines = [ln for ln in log_content.splitlines() if ln.strip()]
    if not lines:
        return None, None

    iso_re = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)")
    syslog_re = re.compile(r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+([ 0-3]?\d)\s+(\d{2}:\d{2}:\d{2})")
    now = datetime.datetime.now(datetime.timezone.utc)

    def _parse(line):
        mt = iso_re.search(line)
        if mt:
            s = mt.group(1).replace(' ', 'T')
            try:
                if s.endswith('Z'):
                    s = s[:-1] + '+00:00'
                return datetime.datetime.fromisoformat(s).astimezone(datetime.timezone.utc)
            except Exception:
                pass
        ms = syslog_re.match(line)
        if ms:
            try:
                mon, day, hms = ms.group(1), int(ms.group(2)), ms.group(3)
                dt = datetime.datetime.strptime(f"{now.year} {mon} {day:02d} {hms}", "%Y %b %d %H:%M:%S")
                return dt.replace(tzinfo=datetime.timezone.utc)
            except Exception:
                pass
        return None

    start_dt, end_dt = None, None
    for ln in lines[:200]:
        dt = _parse(ln)
        if dt:
            start_dt = dt
            break
    for ln in reversed(lines[-200:]):
        dt = _parse(ln)
        if dt:
            end_dt = dt
            break

    if not start_dt and not end_dt:
        return None, None
    return (start_dt or end_dt).isoformat(), (end_dt or start_dt).isoformat()


def _resolve_hostname(host_id):
    """Resolve the actual hostname from a host identifier.
    
    For 'local', returns 'localhost'.
    For 'db-<id>', queries the database to get the actual hostname.
    Otherwise, checks load_hosts() config.
    """
    if host_id == 'local':
        return 'localhost'
    
    # Try to resolve database host (db-<id> format)
    if host_id.startswith('db-'):
        try:
            host_id_num = int(host_id.split('-', 1)[1])
            if has_app_context():
                host_obj = Host.query.get(host_id_num)
                if host_obj and host_obj.hostname:
                    return host_obj.hostname
        except Exception as e:
            print(f"[DEBUG] Failed to resolve hostname for '{host_id}': {e}")
    
    # Fall back to config hosts
    hosts = load_hosts() or {}
    if host_id in hosts:
        return hosts[host_id].get('friendly_name', host_id)
    
    # If nothing found, return the host_id as-is
    return host_id


def _send_discord_embed(webhook_url, title, description, color=3447003):
    if not webhook_url:
        return
    headers = {'Content-Type': 'application/json'}
    discord_payload = {
        "embeds": [
            {
                "title": title,
                "description": (description or '')[:4000],
                "color": color,
                "footer": {"text": "Log Viewer AI Analysis"},
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
        ]
    }
    try:
        requests.post(webhook_url, data=json.dumps(discord_payload), headers=headers, timeout=10)
    except requests.exceptions.RequestException as e:
        print(f"Error sending Discord notification: {e}")


def send_discord_notification(webhook_url, log_name, host_id, analysis_text, data_start=None, data_end=None):
    # Alert embed (red)
    actual_hostname = _resolve_hostname(host_id)

    range_line = f"\n\nData range: {data_start} → {data_end}" if (data_start and data_end) else ''
    title = f"🚨 AI Alert for: {log_name} on {actual_hostname}"
    desc = (analysis_text or '') + range_line
    _send_discord_embed(webhook_url, title, desc, color=15158332)


def send_discord_status(webhook_url, log_name, host_id, message, data_start=None, data_end=None):
    # Info embed (blue)
    actual_hostname = _resolve_hostname(host_id)

    range_line = f"\n\nData range: {data_start} → {data_end}" if (data_start and data_end) else ''
    title = f"ℹ️ Analysis of {log_name} on {actual_hostname}"
    desc = (message or '') + range_line
    _send_discord_embed(webhook_url, title, desc, color=3447003)


# --- FLASK ROUTES ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/favicon.ico')
def favicon():
    return '', 204  # No content response for favicon

@app.route('/sources/local')
def get_local_sources():
    return Response(stream_with_context(get_log_sources_from_host_stream('local')), mimetype='text/event-stream')

@app.route('/sources/remote/<hostname>')
def get_remote_sources(hostname):
    return Response(stream_with_context(get_log_sources_from_host_stream(hostname)), mimetype='text/event-stream')

# Cache for host sources to avoid repeated queries
_host_sources_cache = {}
_cache_timeout = 60  # Cache for 60 seconds

def fetch_sources_from_host(host_id, host_name, failed_hosts):
    """Fetch log sources from a single host with proper error handling"""
    host_sources = []
    print(f"Fetching logs from host '{host_id}' ({host_name})")
    
    try:
        # Use shorter timeout for bulk operations
        cmd_ls = f"sudo ls -p {shlex.quote(LOG_DIRECTORY)}"
        res_ls = execute_command(host_id, cmd_ls, timeout=8)
        filenames = [entry for entry in res_ls.stdout.strip().split('\n') if not entry.endswith('/') and entry]

        # Process files but limit to avoid timeout - sort by modification time and get recent ones
        if len(filenames) > 10:
            # Get file stats for sorting by modification time
            file_stats = []
            for filename in filenames[:20]:  # Check first 20 files quickly
                try:
                    cmd_stat = f"sudo stat -c '%s %Y' {shlex.quote(os.path.join(LOG_DIRECTORY, filename))}"
                    res_stat = execute_command(host_id, cmd_stat, timeout=3)  # Very short timeout
                    size_bytes, mod_time_epoch = map(int, res_stat.stdout.strip().split())
                    if size_bytes > 0:
                        file_stats.append((filename, size_bytes, mod_time_epoch))
                except Exception:
                    continue
            
            # Sort by modification time (newest first) and take top 10
            file_stats.sort(key=lambda x: x[2], reverse=True)
            for filename, size_bytes, mod_time_epoch in file_stats[:10]:
                host_sources.append({
                    'name': filename,
                    'type': 'file',
                    'host': host_id,
                    'host_name': host_name,
                    'size_bytes': size_bytes,
                    'size_formatted': format_bytes(size_bytes),
                    'modified_epoch': mod_time_epoch,
                    'modified_formatted': format_relative_time(mod_time_epoch)
                })
        else:
            # Process all files if there are few
            for filename in filenames:
                try:
                    cmd_stat = f"sudo stat -c '%s %Y' {shlex.quote(os.path.join(LOG_DIRECTORY, filename))}"
                    res_stat = execute_command(host_id, cmd_stat, timeout=5)
                    size_bytes, mod_time_epoch = map(int, res_stat.stdout.strip().split())
                    if size_bytes > 0:
                        host_sources.append({
                            'name': filename,
                            'type': 'file',
                            'host': host_id,
                            'host_name': host_name,
                            'size_bytes': size_bytes,
                            'size_formatted': format_bytes(size_bytes),
                            'modified_epoch': mod_time_epoch,
                            'modified_formatted': format_relative_time(mod_time_epoch)
                        })
                except Exception as e:
                    print(f"Could not stat file '{filename}' on '{host_id}': {e}")
                    continue

        # Get journald services with timeout
        try:
            cmd_journal = "sudo journalctl --field _SYSTEMD_UNIT | sort | uniq | head -15"  # Limit results
            res_journal = execute_command(host_id, cmd_journal, timeout=8)
            journal_units = [unit for unit in res_journal.stdout.strip().split('\n') if unit]
            for unit in journal_units:
                host_sources.append({
                    'name': unit,
                    'type': 'journal',
                    'host': host_id,
                    'host_name': host_name,
                    'size_bytes': 0,
                    'size_formatted': 'N/A',
                    'modified_epoch': 0,
                    'modified_formatted': 'Journald Service'
                })
        except Exception as e:
            print(f"Could not fetch journald units from '{host_id}': {e}")

        print(f"Successfully fetched {len(host_sources)} log sources from '{host_id}'")

    except Exception as e:
        error_msg = str(e)
        if 'timeout' in error_msg.lower():
            error_msg = "Connection timed out"
        elif 'connection refused' in error_msg.lower():
            error_msg = "Connection refused"
        elif 'no route to host' in error_msg.lower():
            error_msg = "No route to host"
        print(f"Could not connect to host '{host_id}': {error_msg}")
        failed_hosts.append({'host_id': host_id, 'host_name': host_name, 'error': error_msg})

    return host_sources

@app.route('/sources/clear-cache', methods=['POST'])
def clear_sources_cache():
    """Clear the host sources cache"""
    global _host_sources_cache
    _host_sources_cache.clear()
    return jsonify({'message': 'Cache cleared successfully'})

@app.route('/sources/all', methods=['POST'])
def get_all_host_sources():
    """Get a simplified list of log sources from all configured hosts for selection purposes"""
    current_time = time.time()
    
    # Check cache first
    cache_key = 'all_sources'
    if cache_key in _host_sources_cache:
        cached_data, timestamp = _host_sources_cache[cache_key]
        if current_time - timestamp < _cache_timeout:
            print("Returning cached host sources")
            return jsonify(cached_data)
    
    all_sources = []
    failed_hosts = []
    hosts = load_hosts()
    all_hostnames = [('local', 'Localhost')] + [(host_id, host_data['friendly_name']) for host_id, host_data in hosts.items()]
    
    # Add DB-hosted devices from wizard
    try:
        db_hosts = Host.query.all()
        for h in db_hosts:
            db_host_id = f"db-{h.id}"
            host_name = h.friendly_name or h.hostname or h.ip_address
            all_hostnames.append((db_host_id, host_name))
    except Exception as e:
        print(f"[ERROR] Failed to add DB hosts to sources list: {e}")

    # Use ThreadPoolExecutor with timeout for concurrent processing
    with ThreadPoolExecutor(max_workers=3) as executor:  # Reduced workers to avoid overwhelming
        future_to_host = {executor.submit(fetch_sources_from_host, host_id, host_name, failed_hosts): (host_id, host_name) 
                         for host_id, host_name in all_hostnames}
        
        # Wait for completion with overall timeout and proper error handling
        try:
            for future in as_completed(future_to_host, timeout=25):  # Reduced timeout
                host_id, host_name = future_to_host[future]
                try:
                    host_sources = future.result(timeout=3)  # Shorter individual timeout
                    all_sources.extend(host_sources)
                except Exception as exc:
                    print(f"Host {host_name} generated an exception: {exc}")
                    failed_hosts.append({'host_id': host_id, 'host_name': host_name, 'error': str(exc)})
        except Exception as timeout_exc:
            print(f"Overall timeout or error in all sources: {timeout_exc}")
            # Handle any remaining unfinished futures
            for future, (host_id, host_name) in future_to_host.items():
                if not future.done():
                    print(f"Marking {host_name} as failed due to timeout")
                    failed_hosts.append({'host_id': host_id, 'host_name': host_name, 'error': 'Connection timed out'})
                    future.cancel()

    print(f"Total sources collected: {len(all_sources)} from {len(all_hostnames) - len(failed_hosts)} hosts")
    if failed_hosts:
        print(f"Failed hosts: {failed_hosts}")

    response_data = {
        'sources': all_sources,
        'failed_hosts': failed_hosts,
        'total_hosts': len(all_hostnames),
        'successful_hosts': len(all_hostnames) - len(failed_hosts)
    }
    
    # Cache the result
    _host_sources_cache[cache_key] = (response_data, current_time)
    
    return jsonify(response_data)

@app.route('/sources/table', methods=['POST'])
def get_log_table_view():
    """Get logs organized in a table format: log names as rows, hosts as columns"""
    current_time = time.time()
    
    # Check cache first
    cache_key = 'table_view'
    if cache_key in _host_sources_cache:
        cached_data, timestamp = _host_sources_cache[cache_key]
        if current_time - timestamp < _cache_timeout:
            print("Returning cached table view")
            return jsonify(cached_data)
    
    all_sources = []
    failed_hosts = []
    hosts = load_hosts()
    all_hostnames = [('local', 'Localhost')] + [(host_id, host_data['friendly_name']) for host_id, host_data in hosts.items()]
    
    # Add DB-hosted devices from wizard
    try:
        db_hosts = Host.query.all()
        for h in db_hosts:
            db_host_id = f"db-{h.id}"
            host_name = h.friendly_name or h.hostname or h.ip_address
            all_hostnames.append((db_host_id, host_name))
    except Exception as e:
        print(f"[ERROR] Failed to add DB hosts to sources list: {e}")

    # Use ThreadPoolExecutor with timeout for concurrent processing
    with ThreadPoolExecutor(max_workers=3) as executor:
        future_to_host = {executor.submit(fetch_sources_from_host, host_id, host_name, failed_hosts): (host_id, host_name) 
                         for host_id, host_name in all_hostnames}
        
        # Wait for completion with overall timeout and proper error handling
        try:
            for future in as_completed(future_to_host, timeout=30):
                host_id, host_name = future_to_host[future]
                try:
                    host_sources = future.result(timeout=5)
                    all_sources.extend(host_sources)
                except Exception as exc:
                    print(f"Host {host_name} generated an exception: {exc}")
                    failed_hosts.append({'host_id': host_id, 'host_name': host_name, 'error': str(exc)})
        except Exception as timeout_exc:
            print(f"Overall timeout or error in table view: {timeout_exc}")
            # Handle any remaining unfinished futures
            for future, (host_id, host_name) in future_to_host.items():
                if not future.done():
                    print(f"Marking {host_name} as failed due to timeout")
                    failed_hosts.append({'host_id': host_id, 'host_name': host_name, 'error': 'Connection timed out'})
                    future.cancel()

    # Create log-to-hosts mapping
    log_matrix = {}
    host_list = []
    
    # Build host list
    for host_id, host_name in all_hostnames:
        if not any(f['host_id'] == host_id for f in failed_hosts):
            host_list.append({'host_id': host_id, 'host_name': host_name})
    
    # Build log matrix
    for source in all_sources:
        log_key = f"{source['name']}|{source['type']}"
        if log_key not in log_matrix:
            log_matrix[log_key] = {
                'name': source['name'],
                'type': source['type'],
                'hosts': {},
                'size_info': source.get('size_formatted', 'N/A'),
                'modified_info': source.get('modified_formatted', 'N/A')
            }
        
        # Add host information for this log
        log_matrix[log_key]['hosts'][source['host']] = {
            'host_id': source['host'],
            'host_name': source['host_name'],
            'size_bytes': source.get('size_bytes', 0),
            'size_formatted': source.get('size_formatted', 'N/A'),
            'modified_epoch': source.get('modified_epoch', 0),
            'modified_formatted': source.get('modified_formatted', 'N/A')
        }
    
    # Convert to list format for frontend
    logs_table = list(log_matrix.values())
    
    # Sort logs by name
    logs_table.sort(key=lambda x: x['name'].lower())
    
    response_data = {
        'logs': logs_table,
        'hosts': host_list,
        'failed_hosts': failed_hosts,
        'total_hosts': len(all_hostnames),
        'successful_hosts': len(host_list)
    }
    
    # Cache the result
    _host_sources_cache[cache_key] = (response_data, current_time)
    
    return jsonify(response_data)

@app.route('/sources/table/stream')
def get_log_table_view_stream():
    """Get logs organized in a table format with streaming progress updates"""
    def generate_table_events():
        def generate_event(data):
            return f"data: {json.dumps(data)}\n\n"
        
        try:
            yield generate_event({'status': 'progress', 'message': 'Initializing host scan...', 'progress': 5})
            
            all_sources = []
            failed_hosts = []
            hosts = load_hosts()
            all_hostnames = [('local', 'Localhost')] + [(host_id, host_data['friendly_name']) for host_id, host_data in hosts.items()]
            total_hosts = len(all_hostnames)
            
            yield generate_event({'status': 'progress', 'message': f'Found {total_hosts} hosts to scan', 'progress': 10})
            
            print(f"Starting streaming table scan for {total_hosts} hosts: {all_hostnames}")
            
            # Process hosts sequentially for better progress tracking
            for i, (host_id, host_name) in enumerate(all_hostnames):
                host_progress = 10 + int((i / total_hosts) * 80)
                yield generate_event({'status': 'progress', 'message': f'Connecting to {host_name}...', 'progress': host_progress})
                print(f"Processing host {i+1}/{total_hosts}: {host_name} ({host_id})")
                
                try:
                    # Fetch sources from this host with detailed logging
                    host_sources = fetch_sources_from_host_detailed(host_id, host_name, generate_event, host_progress)
                    all_sources.extend(host_sources)
                    print(f"Successfully fetched {len(host_sources)} sources from {host_name}")
                    yield generate_event({'status': 'progress', 'message': f'✅ {host_name}: Found {len(host_sources)} log sources', 'progress': host_progress + int(80/total_hosts)})
                except Exception as e:
                    error_msg = str(e)
                    print(f"Error fetching from {host_name}: {error_msg}")
                    if 'timeout' in error_msg.lower():
                        error_msg = "Connection timed out"
                    elif 'connection refused' in error_msg.lower():
                        error_msg = "Connection refused"
                    elif 'no route to host' in error_msg.lower():
                        error_msg = "No route to host"
                        
                    failed_hosts.append({'host_id': host_id, 'host_name': host_name, 'error': error_msg})
                    yield generate_event({'status': 'progress', 'message': f'❌ {host_name}: {error_msg}', 'progress': host_progress + int(80/total_hosts)})
            
            print(f"Completed host scanning. Collected {len(all_sources)} sources total, {len(failed_hosts)} hosts failed")
            yield generate_event({'status': 'progress', 'message': 'Building log matrix...', 'progress': 90})
            
            # Create log-to-hosts mapping
            log_matrix = {}
            host_list = []
            
            # Build host list
            for host_id, host_name in all_hostnames:
                if not any(f['host_id'] == host_id for f in failed_hosts):
                    host_list.append({'host_id': host_id, 'host_name': host_name})
            
            # Build log matrix
            for source in all_sources:
                log_key = f"{source['name']}|{source['type']}"
                if log_key not in log_matrix:
                    log_matrix[log_key] = {
                        'name': source['name'],
                        'type': source['type'],
                        'hosts': {},
                        'size_info': source.get('size_formatted', 'N/A'),
                        'modified_info': source.get('modified_formatted', 'N/A')
                    }
                
                # Add host information for this log
                log_matrix[log_key]['hosts'][source['host']] = {
                    'host_id': source['host'],
                    'host_name': source['host_name'],
                    'size_bytes': source.get('size_bytes', 0),
                    'size_formatted': source.get('size_formatted', 'N/A'),
                    'modified_epoch': source.get('modified_epoch', 0),
                    'modified_formatted': source.get('modified_formatted', 'N/A')
                }
            
            # Convert to list format for frontend
            logs_table = list(log_matrix.values())
            
            # Sort logs by name
            logs_table.sort(key=lambda x: x['name'].lower())
            
            response_data = {
                'logs': logs_table,
                'hosts': host_list,
                'failed_hosts': failed_hosts,
                'total_hosts': len(all_hostnames),
                'successful_hosts': len(host_list)
            }
            
            print(f"Final response data: {len(response_data['logs'])} logs, {response_data['successful_hosts']}/{response_data['total_hosts']} hosts successful")
            yield generate_event({'status': 'complete', 'data': response_data, 'progress': 100})
            
        except Exception as e:
            print(f"Critical error in streaming table view: {str(e)}")
            import traceback
            traceback.print_exc()
            yield generate_event({'status': 'error', 'message': str(e)})
    
    return Response(stream_with_context(generate_table_events()), mimetype='text/event-stream')

def fetch_sources_from_host_detailed(host_id, host_name, progress_callback, base_progress):
    """Fetch log sources from a single host with detailed progress reporting"""
    host_sources = []
    
    try:
        # Use shorter timeout for bulk operations
        progress_callback({'status': 'progress', 'message': f'📂 {host_name}: Listing log directory...', 'progress': base_progress})
        cmd_ls = f"sudo ls -p {shlex.quote(LOG_DIRECTORY)}"
        res_ls = execute_command(host_id, cmd_ls, timeout=8)
        filenames = [entry for entry in res_ls.stdout.strip().split('\n') if not entry.endswith('/') and entry]
        
        progress_callback({'status': 'progress', 'message': f'📋 {host_name}: Found {len(filenames)} potential log files', 'progress': base_progress})

        # Process files but limit to avoid timeout - sort by modification time and get recent ones
        if len(filenames) > 10:
            progress_callback({'status': 'progress', 'message': f'🔍 {host_name}: Checking file stats for recent files...', 'progress': base_progress})
            # Get file stats for sorting by modification time
            file_stats = []
            for i, filename in enumerate(filenames[:20]):  # Check first 20 files quickly
                if i % 5 == 0:  # Update progress every 5 files
                    progress_callback({'status': 'progress', 'message': f'📊 {host_name}: Checking {filename}...', 'progress': base_progress})
                try:
                    cmd_stat = f"sudo stat -c '%s %Y' {shlex.quote(os.path.join(LOG_DIRECTORY, filename))}"
                    res_stat = execute_command(host_id, cmd_stat, timeout=3)  # Very short timeout
                    size_bytes, mod_time_epoch = map(int, res_stat.stdout.strip().split())
                    if size_bytes > 0:
                        file_stats.append((filename, size_bytes, mod_time_epoch))
                except Exception:
                    continue
            
            # Sort by modification time (newest first) and take top 10
            file_stats.sort(key=lambda x: x[2], reverse=True)
            progress_callback({'status': 'progress', 'message': f'📝 {host_name}: Processing {len(file_stats[:10])} most recent log files...', 'progress': base_progress})
            
            for filename, size_bytes, mod_time_epoch in file_stats[:10]:
                host_sources.append({
                    'name': filename,
                    'type': 'file',
                    'host': host_id,
                    'host_name': host_name,
                    'size_bytes': size_bytes,
                    'size_formatted': format_bytes(size_bytes),
                    'modified_epoch': mod_time_epoch,
                    'modified_formatted': format_relative_time(mod_time_epoch)
                })
        else:
            # Process all files if there are few
            progress_callback({'status': 'progress', 'message': f'📝 {host_name}: Processing all {len(filenames)} log files...', 'progress': base_progress})
            for i, filename in enumerate(filenames):
                if i % 3 == 0:  # Update progress every 3 files
                    progress_callback({'status': 'progress', 'message': f'📄 {host_name}: Processing {filename}...', 'progress': base_progress})
                try:
                    cmd_stat = f"sudo stat -c '%s %Y' {shlex.quote(os.path.join(LOG_DIRECTORY, filename))}"
                    res_stat = execute_command(host_id, cmd_stat, timeout=5)
                    size_bytes, mod_time_epoch = map(int, res_stat.stdout.strip().split())
                    if size_bytes > 0:
                        host_sources.append({
                            'name': filename,
                            'type': 'file',
                            'host': host_id,
                            'host_name': host_name,
                            'size_bytes': size_bytes,
                            'size_formatted': format_bytes(size_bytes),
                            'modified_epoch': mod_time_epoch,
                            'modified_formatted': format_relative_time(mod_time_epoch)
                        })
                except Exception as e:
                    continue

        # Get journald services with timeout
        progress_callback({'status': 'progress', 'message': f'🔧 {host_name}: Fetching systemd journal services...', 'progress': base_progress})
        try:
            cmd_journal = "sudo journalctl --field _SYSTEMD_UNIT | sort | uniq | head -15"  # Limit results
            res_journal = execute_command(host_id, cmd_journal, timeout=8)
            journal_units = [unit for unit in res_journal.stdout.strip().split('\n') if unit]
            
            progress_callback({'status': 'progress', 'message': f'📋 {host_name}: Found {len(journal_units)} journal services', 'progress': base_progress})
            
            for unit in journal_units:
                host_sources.append({
                    'name': unit,
                    'type': 'journal',
                    'host': host_id,
                    'host_name': host_name,
                    'size_bytes': 0,
                    'size_formatted': 'N/A',
                    'modified_epoch': 0,
                    'modified_formatted': 'Journald Service'
                })
        except Exception as e:
            progress_callback({'status': 'progress', 'message': f'⚠️ {host_name}: Could not fetch journal services: {str(e)}', 'progress': base_progress})

    except Exception as e:
        progress_callback({'status': 'progress', 'message': f'❌ {host_name}: Connection failed: {str(e)}', 'progress': base_progress})
        raise e

    return host_sources

@app.route('/log/<path:filename>')
def get_log_content(filename):
    hostname = request.args.get('host', 'local')
    
    # Debug: show which SSH key is being used for DB hosts
    if hostname != 'local' and hostname.startswith('db-'):
        try:
            host_id = int(hostname.split('-', 1)[1])
            host_obj = Host.query.get(host_id)
            if host_obj:
                ssh_key_id = host_obj.ssh_key_id
                identity_path = _materialize_ssh_key_path(ssh_key_id)
                print(f"[DEBUG /log] Using SSH key_id={ssh_key_id} for DB host {hostname}")
        except Exception as e:
            print(f"[DEBUG /log] Error resolving DB host SSH key: {e}")
    else:
        print(f"[DEBUG /log] Using local/config host: {hostname}")
    
    try:
        command_str = f"sudo zcat {shlex.quote(os.path.join(LOG_DIRECTORY, filename))} 2>/dev/null | tail -n 500" if filename.endswith('.gz') else f"sudo tail -n 500 {shlex.quote(os.path.join(LOG_DIRECTORY, filename))}"
        result = execute_command(hostname, command_str)
        return jsonify({'content': result.stdout, 'will_be_truncated': len(result.stdout) > MAX_CHAR_COUNT})
    except Exception as e: 
        return jsonify({'error': f"Could not read log file '{filename}' on '{hostname}': {e}"}), 500

@app.route('/journal/<path:unit>')
def get_journal_content(unit):
    hostname = request.args.get('host', 'local')
    try:
        command_str = f"sudo journalctl -u {shlex.quote(unit)} -n 500 --no-pager"
        result = execute_command(hostname, command_str)
        return jsonify({'content': result.stdout, 'will_be_truncated': len(result.stdout) > MAX_CHAR_COUNT})
    except Exception as e: 
        return jsonify({'error': f"Could not read journal for unit '{unit}' on '{hostname}': {e}"}), 500

# --- HOST MANAGEMENT ROUTES ---
@app.route('/hosts', methods=['GET'])
def get_hosts():
    """Return combined hosts from config file and database."""
    print("[DEBUG] /hosts endpoint called")
    # Load hosts from config file (original behaviour)
    hosts_data = load_hosts() or {}

    # Merge in hosts from database so wizard-added hosts appear
    try:
        db_hosts = Host.query.all()
        for h in db_hosts:
            hid = f"db-{h.id}"
            if hid not in hosts_data:
                hosts_data[hid] = {
                    'friendly_name': h.friendly_name or h.hostname or h.ip_address,
                    'ip': h.ip_address,
                    'user': h.ssh_user or 'root',
                    'description': h.description or 'Onboarded via wizard',
                    'source': 'db',
                    'group_names': [g.name for g in (h.groups or [])]
                }
    except Exception as e:
        print(f"[ERROR] Failed to merge DB hosts into /hosts response: {e}")

    print(f"[DEBUG] Returning hosts data: {hosts_data}")
    return jsonify(hosts_data)

@app.route('/hosts/add', methods=['POST'])
def add_host():
    data = request.get_json()
    host_id = str(uuid.uuid4())
    hosts = load_hosts()
    hosts[host_id] = {'friendly_name': data.get('friendly_name'),'ip': data.get('ip'),'user': data.get('user'),'description': data.get('description')}
    save_hosts(hosts)
    return jsonify({'message': 'Host added successfully.', 'host_id': host_id})

@app.route('/hosts/update/<host_id>', methods=['PUT'])
def update_host(host_id):
    data = request.get_json()
    hosts = load_hosts()
    if host_id in hosts:
        hosts[host_id].update(data)
        save_hosts(hosts)
        return jsonify({'message': 'Host updated successfully.'})
    return jsonify({'error': 'Host not found.'}), 404

@app.route('/hosts/delete/<host_id>', methods=['DELETE'])
def delete_host(host_id):
    """Delete a host from either the config file or the database.

    host_id can be a config ID or a db-backed ID like 'db-<id>'.
    """
    # First try to delete from config-based hosts
    hosts = load_hosts() or {}
    if host_id in hosts:
        del hosts[host_id]
        save_hosts(hosts)
        return jsonify({'message': 'Host deleted from configuration.'})

    # If not found in config, try database hosts with prefix db-<id>
    if host_id.startswith('db-'):
        try:
            from app import Host, SystemInfo, Service, HostLog, db  # local import to avoid circulars at import time
        except Exception:
            Host = None
        if Host is not None:
            try:
                db_id = int(host_id.split('-', 1)[1])
                host = Host.query.get(db_id)
                if not host:
                    return jsonify({'error': 'Host not found.'}), 404

                # Delete related records if cascading is not configured
                SystemInfo.query.filter_by(host_id=db_id).delete()
                Service.query.filter_by(host_id=db_id).delete()
                HostLog.query.filter_by(host_id=db_id).delete()
                db.session.delete(host)
                db.session.commit()
                return jsonify({'message': 'Host deleted from database.'})
            except Exception as e:
                db.session.rollback()
                return jsonify({'error': f'Failed to delete DB host: {str(e)}'}), 500

    return jsonify({'error': 'Host not found.'}), 404

@app.route('/hosts/test', methods=['POST'])
def test_host_connection():
    data = request.get_json()
    user, ip = data.get('user'), data.get('ip')
    if not all([user, ip]):
        return jsonify({'success': False, 'error': 'User and IP are required.'}), 400
    try:
        ssh_prefix_args = get_ssh_prefix_args(user, ip)
        result = subprocess.run(ssh_prefix_args + ["sudo echo 'success'"], shell=False, capture_output=True, text=True, check=True, timeout=10)
        if 'success' in result.stdout:
            return jsonify({'success': True, 'message': 'Connection successful!'})
        else:
            return jsonify({'success': False, 'error': 'Sudo access might be misconfigured.'})
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'Connection timed out.'})
    except subprocess.CalledProcessError as e:
        return jsonify({'success': False, 'error': e.stderr or 'Failed to connect. Check credentials, keys, and network.'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# --- OLLAMA INTEGRATION ROUTES ---
@app.route('/ollama/test', methods=['POST'])
def test_ollama():
    """Test connection to Ollama instance"""
    data = request.get_json()
    ollama_url = data.get('ollama_url', '').strip()
    if not ollama_url:
        return jsonify({'success': False, 'error': 'Ollama URL is required.'}), 400
    
    # Ensure URL is properly formatted
    if not ollama_url.startswith('http'):
        ollama_url = f'http://{ollama_url}'
    ollama_url = ollama_url.rstrip('/')

    # Normalize: avoid trailing slash that can cause //api/generate redirects (which may flip POST to GET)
    ollama_url = ollama_url.rstrip('/')
    
    try:
        # Test connectivity by fetching models list
        response = requests.get(f'{ollama_url}/api/tags', timeout=5)
        response.raise_for_status()
        models = response.json().get('models', [])
        return jsonify({'success': True, 'message': f'Connection successful! Found {len(models)} model(s).', 'models': models})
    except requests.exceptions.ConnectionError:
        return jsonify({'success': False, 'error': 'Could not connect to Ollama instance. Check URL and ensure Ollama is running.'}), 400
    except requests.exceptions.Timeout:
        return jsonify({'success': False, 'error': 'Connection timed out. Check if Ollama is running and accessible.'}), 400
    except requests.exceptions.RequestException as e:
        return jsonify({'success': False, 'error': f'Connection error: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': f'Unexpected error: {str(e)}'}), 500

@app.route('/ollama/models', methods=['POST'])
def get_ollama_models():
    """Fetch available models from Ollama instance - backend proxy to avoid CORS"""
    data = request.get_json()
    ollama_url = data.get('ollama_url', '').strip()
    
    if not ollama_url:
        # Fall back to config if not provided
        config = load_config()
    def _emit(payload):
        try:
            if emit:
                emit(payload)
            else:
                # default: log to server
                print(payload.get('message') or payload)
        except Exception:
            pass
        ollama_url = config.get('ollama_url', '').strip()
    
    if not ollama_url:
        return jsonify({'error': 'Ollama URL not provided.'}), 400
    
    if not ollama_url.startswith('http'):
        ollama_url = f'http://{ollama_url}'
    ollama_url = ollama_url.rstrip('/')
    
    try:
        response = requests.get(f'{ollama_url}/api/tags', timeout=10)
        response.raise_for_status()
        models = response.json().get('models', [])
        model_names = [m.get('name', 'unknown') for m in models]
        return jsonify({'models': model_names})
    except Exception as e:
        return jsonify({'error': f'Failed to fetch models: {str(e)}'}), 500

@app.route('/ai/config', methods=['GET'])
def get_ai_config():
    """Get current AI provider configuration"""
    config = load_config()
    provider = config.get('analysis_provider', 'openai')
    
    result = {'provider': provider}
    
    if provider == 'openai':
        result['openai_configured'] = bool(config.get('openai_api_key'))
    elif provider == 'ollama':
        result['ollama_configured'] = bool(config.get('ollama_url') and config.get('ollama_model'))
        result['ollama_model'] = config.get('ollama_model', '')
    
    return jsonify(result)

@app.route('/openai/config', methods=['POST', 'GET'])
def openai_config():
    """Save or retrieve OpenAI configuration"""
    if request.method == 'POST':
        data = request.get_json()
        api_key = data.get('api_key', '').strip()
        
        if not api_key:
            return jsonify({'error': 'OpenAI API key is required.'}), 400
        
        config = load_config()
        config['openai_api_key'] = api_key
        config['analysis_provider'] = 'openai'  # Set as default provider
        save_config(config)
        return jsonify({'message': 'OpenAI configuration saved.'})
    else:  # GET
        config = load_config()
        return jsonify({
            'api_key': config.get('openai_api_key', ''),
            'analysis_provider': config.get('analysis_provider', 'openai')
        })



@app.route('/openai/test-saved', methods=['GET'])
def test_saved_openai_key():
    # Test the saved OpenAI API key stored in DB settings.
    try:
        cfg = load_config()
        api_key = (cfg.get('openai_api_key') or '').strip()
        if not api_key:
            return jsonify({'success': False, 'error': 'No saved OpenAI API key configured.'}), 400

        resp = requests.get(
            'https://api.openai.com/v1/models',
            headers={'Authorization': f'Bearer {api_key}'},
            timeout=10,
        )
        if resp.status_code == 200:
            return jsonify({'success': True, 'message': 'Saved OpenAI API key is valid.'})
        try:
            j = resp.json()
            err = (j.get('error') or {}).get('message')
        except Exception:
            err = None
        return jsonify({'success': False, 'error': err or f'OpenAI validation failed ({resp.status_code}).'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/ai/search-config', methods=['GET', 'POST'])
def ai_search_config():
    """Get/set the AI search prompt and alert keywords (DB-backed)."""
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        prompt = (data.get('search_prompt') or '').strip()
        keywords = data.get('alert_keywords')
        if prompt:
            _setting_set('ai.search_prompt', prompt)
        if isinstance(keywords, list):
            cleaned = [str(k).strip() for k in keywords if str(k).strip()]
            _setting_set('ai.alert_keywords', cleaned)
        return jsonify({'search_prompt': get_ai_search_prompt(), 'alert_keywords': get_ai_alert_keywords(), 'message': 'AI search settings saved.'})
    return jsonify({'search_prompt': get_ai_search_prompt(), 'alert_keywords': get_ai_alert_keywords()})

@app.route('/suricata/prompt', methods=['GET', 'POST'])
def suricata_prompt_config():
    if request.method == 'GET':
        return jsonify({'prompt': get_suricata_prompt()})

    data = request.get_json(force=True, silent=True) or {}
    prompt = (data.get('prompt') or '').strip()
    if not prompt:
        prompt = DEFAULT_SURICATA_PROMPT
    set_suricata_prompt(prompt)
    return jsonify({'prompt': get_suricata_prompt()})


@app.route('/discord/config', methods=['GET', 'POST'])
def discord_config():
    # Save or retrieve Discord webhook configuration.
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        webhook_url = (data.get('webhook_url') or '').strip()
        if not webhook_url:
            return jsonify({'error': 'Discord webhook URL is required.'}), 400
        cfg = load_config()
        cfg['discord_webhook_url'] = webhook_url
        save_config(cfg)
        return jsonify({'message': 'Discord webhook saved.'})

    cfg = load_config()
    webhook_url = (cfg.get('discord_webhook_url') or '').strip()
    configured = bool(webhook_url)
    return jsonify({'configured': configured, 'webhook_url': webhook_url})


@app.route('/discord/test', methods=['POST'])
def discord_test():
    # Send a test message to Discord using provided webhook_url or saved config.
    try:
        data = request.get_json(silent=True) or {}
        webhook_url = (data.get('webhook_url') or '').strip()
        if not webhook_url:
            cfg = load_config()
            webhook_url = (cfg.get('discord_webhook_url') or '').strip()

        if not webhook_url:
            return jsonify({'success': False, 'error': 'No Discord webhook URL configured.'}), 400

        payload = {'content': '✅ AI Log Viewer test notification.'}
        r = requests.post(webhook_url, json=payload, timeout=10)
        if r.status_code in (200, 204):
            return jsonify({'success': True, 'message': 'Discord webhook test sent.'})
        return jsonify({'success': False, 'error': f'Discord returned {r.status_code}: {r.text[:200]}'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/ollama/config', methods=['POST', 'GET'])
def ollama_config():
    """Save or retrieve Ollama configuration"""
    if request.method == 'POST':
        data = request.get_json()
        ollama_url = data.get('ollama_url', '').strip()
        ollama_model = data.get('ollama_model', '').strip()
        
        if not ollama_url or not ollama_model:
            return jsonify({'error': 'Both Ollama URL and model are required.'}), 400
        
        config = load_config()
        config['ollama_url'] = ollama_url if ollama_url.startswith('http') else f'http://{ollama_url}'
        config['ollama_model'] = ollama_model
        config['analysis_provider'] = 'ollama'  # Set as default provider
        save_config(config)
        return jsonify({'message': 'Ollama configuration saved.'})
    else:  # GET
        config = load_config()
        return jsonify({
            'ollama_url': config.get('ollama_url', ''),
            'ollama_model': config.get('ollama_model', ''),
            'analysis_provider': config.get('analysis_provider', 'openai')
        })

def analyse_with_ollama(log_content, log_name, ollama_url, ollama_model):
    """Analyze log using Ollama"""
    if not ollama_url.startswith('http'):
        ollama_url = f'http://{ollama_url}'
    ollama_url = ollama_url.rstrip('/')
    
    truncated_content = log_content
    if len(log_content) > MAX_CHAR_COUNT:
        truncated_content = f"[--- Log truncated due to size limit... ---]\n" + log_content[-MAX_CHAR_COUNT:]
    
    prompt = f"Analyse this log for {log_name} for errors, create a summary report, and give troubleshooting tips.\n\n{truncated_content}"
    
    try:
        endpoint_url = f'{ollama_url}/api/generate'
        response = requests.post(
            endpoint_url,
            allow_redirects=False,
            json={'model': ollama_model, 'prompt': prompt, 'stream': False},
            timeout=60
        )

        if response.is_redirect or response.is_permanent_redirect:
            loc = response.headers.get('Location')
            raise Exception(f'Ollama redirected request from {endpoint_url} to {loc} (status {response.status_code}). Final URL seen: {response.url}. Check the base URL (no trailing slash) and reverse proxy settings.')

        response.raise_for_status()

        try:
            result = response.json()
        except Exception:
            snippet = (response.text or '')[:300].replace('\n', ' ')
            raise Exception(f'Unexpected response from Ollama (status {response.status_code}): {snippet}')
        return result.get('response', 'No response from Ollama')
    except Exception as e:
        raise Exception(f'Ollama analysis failed: {str(e)}')

# --- ANALYSIS & SCHEDULER ROUTES (RESTORED) ---
def save_config(config):
    """Persist relevant config keys to DB-backed AppSetting."""
    if 'analysis_provider' in config:
        _setting_set('analysis_provider', config.get('analysis_provider'))
    if 'openai_api_key' in config:
        _setting_set('openai_api_key', config.get('openai_api_key'))
    if 'api_key' in config and 'openai_api_key' not in config:
        _setting_set('openai_api_key', config.get('api_key'))
    if 'ollama_url' in config:
        _setting_set('ollama_url', config.get('ollama_url'))
    if 'ollama_model' in config:
        _setting_set('ollama_model', config.get('ollama_model'))

    if 'discord_webhook_url' in config:
        _setting_set('discord_webhook_url', config.get('discord_webhook_url'))
    if 'webhook_url' in config and 'discord_webhook_url' not in config:
        _setting_set('discord_webhook_url', config.get('webhook_url'))

    if 'is_running' in config:
        _setting_set('schedule.is_running', bool(config.get('is_running')))
    if 'interval' in config:
        _setting_set('schedule.interval_hours', config.get('interval'))
    if 'sources' in config:
        _setting_set('schedule.sources', config.get('sources') or [])
def load_config():
    """Load config from DB settings; fall back to scheduler_config.json via migration."""
    try:
        _migrate_scheduler_config_file_to_db()
    except Exception:
        pass

    cfg = {}
    cfg['analysis_provider'] = _setting_get('analysis_provider', 'openai')
    cfg['openai_api_key'] = _setting_get('openai_api_key', '')
    cfg['api_key'] = cfg['openai_api_key']  # backward-compatible alias
    cfg['ollama_url'] = _setting_get('ollama_url', '')
    cfg['ollama_model'] = _setting_get('ollama_model', '')

    cfg['discord_webhook_url'] = _setting_get('discord_webhook_url', '')
    cfg['webhook_url'] = cfg['discord_webhook_url']

    cfg['is_running'] = bool(_setting_get('schedule.is_running', False))
    cfg['interval'] = _setting_get('schedule.interval_hours', None)
    cfg['sources'] = _setting_get('schedule.sources', []) or []

    return cfg

@app.route('/analyse', methods=['POST'])
def analyse_log():
    data = request.get_json(silent=True) or {}
    log_content = data.get('log_content')
    log_name = data.get('log_name')
    webhook_url = data.get('webhook_url')
    provider = data.get('provider', 'openai')  # 'openai' or 'ollama'

    if not log_content:
        return jsonify({'error': 'Missing log_content.'}), 400

    try:
        if provider == 'ollama':
            config = load_config()
            ollama_url = config.get('ollama_url')
            ollama_model = config.get('ollama_model')
            if not ollama_url or not ollama_model:
                return jsonify({'error': 'Ollama not configured. Please set up Ollama in Settings.'}), 400
            analysis = analyse_with_ollama(log_content, log_name, ollama_url, ollama_model)
        else:
            api_key = data.get('api_key')
            if not api_key:
                return jsonify({'error': 'OpenAI API key not provided.'}), 400

            truncated_content = log_content
            if len(log_content) > MAX_CHAR_COUNT:
                truncated_content = f"[--- Log truncated due to size limit... ---]\n" + log_content[-MAX_CHAR_COUNT:]


            client = openai.OpenAI(api_key=api_key)
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a helpful assistant that analyses log files."},
                    {"role": "user", "content": f"Analyse this log for {log_name} for errors, create a summary report, and give troubleshooting tips.\n\n{truncated_content}"}
                ]
            )
            analysis = response.choices[0].message.content

        discord_sent = False
        data_start, data_end = extract_log_time_range(log_content)
        if webhook_url and analysis and any(keyword.lower() in analysis.lower() for keyword in get_ai_alert_keywords()):
            send_discord_notification(webhook_url, log_name, 'local', analysis, data_start=data_start, data_end=data_end)
            discord_sent = True

        return jsonify({'analysis': analysis, 'discord_sent': discord_sent})
    except Exception as e:
        return jsonify({'error': f'An error occurred during AI Analysis: {str(e)}'}), 500


@app.route('/suricata/analyse', methods=['POST'])
def suricata_analyse():
    data = request.get_json(silent=True) or {}
    log_content = data.get('log_content')
    log_name = data.get('log_name') or 'Suricata Raw Data'
    provider = data.get('provider', 'openai')

    if not log_content:
        return jsonify({'error': 'Missing log_content.'}), 400

    prompt = (data.get('prompt') or '').strip() or get_suricata_prompt()

    try:
        if provider == 'ollama':
            config = load_config()
            ollama_url = config.get('ollama_url')
            ollama_model = config.get('ollama_model')
            if not ollama_url or not ollama_model:
                return jsonify({'error': 'Ollama not configured. Please set it up in Settings.'}), 400
            analysis = analyse_with_ollama(f"{prompt}\n\n{log_content}", log_name, ollama_url, ollama_model)
        else:
            api_key = data.get('api_key')
            if not api_key:
                return jsonify({'error': 'OpenAI API key not provided.'}), 400

            truncated_content = log_content
            if len(log_content) > MAX_CHAR_COUNT:
                truncated_content = f"[--- Data truncated due to size limit... ---]\n" + log_content[-MAX_CHAR_COUNT:]

            client = openai.OpenAI(api_key=api_key)
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a helpful assistant that analyses Suricata data."},
                    {"role": "user", "content": f"{prompt}\n\n--- DATA for {log_name} ---\n{truncated_content}"},
                ]
            )
            analysis = response.choices[0].message.content

        return jsonify({'analysis': analysis})
    except Exception as e:
        return jsonify({'error': f'An error occurred during AI Analysis: {str(e)}'}), 500

def _exec_summary_from_analysis(analysis_text: str, max_chars: int = 600) -> str:
    if not analysis_text:
        return '(no analysis output)'
    txt = analysis_text.strip().replace('\r', '')
    parts = [p.strip() for p in txt.split('\n\n') if p.strip()]
    head = parts[0] if parts else txt
    if len(head) > max_chars:
        head = head[:max_chars].rstrip() + '…'
    return head

def _do_analysis_task(emit=None):
    """Run analysis over configured sources.

    If emit is provided, it will be called with dict payloads suitable for SSE.
    """
    config = load_config()

    def _emit(payload):
        try:
            if emit:
                emit(payload)
            else:
                print(payload.get('message') or payload)
        except Exception:
            pass

    _emit({'status': 'progress', 'message': 'Starting scheduled analysis...', 'progress': 0})

    webhook_url = (config.get('webhook_url') or '').strip()
    sources = config.get('sources', []) or []
    provider = config.get('analysis_provider', 'openai')

    if not webhook_url or not sources:
        _emit({'status': 'error', 'message': 'Scheduled analysis aborted: Missing webhook URL or selected logs.'})
        return

    if provider == 'ollama':
        if not config.get('ollama_url') or not config.get('ollama_model'):
            _emit({'status': 'error', 'message': 'Scheduled analysis aborted: Ollama not configured.'})
            return
    else:
        if not config.get('api_key'):
            _emit({'status': 'error', 'message': 'Scheduled analysis aborted: OpenAI API key not configured.'})
            return

    total = len(sources)

    for i, source in enumerate(sources, start=1):
        log_name = source.get('name')
        log_type = source.get('type')
        host = source.get('host', 'local')

        progress = int(((i - 1) / max(total, 1)) * 100)
        _emit({'status': 'progress', 'message': f'Analyzing {i}/{total}: {log_name} on {host}...', 'progress': progress})
        _emit({'status': 'log', 'message': f'Analyzing {log_type}: {log_name} on {host} using {provider}'})

        try:
            command = f"sudo zcat {shlex.quote(os.path.join(LOG_DIRECTORY, log_name))} 2>/dev/null | tail -n 500" if str(log_name).endswith('.gz') else f"sudo tail -n 500 {shlex.quote(os.path.join(LOG_DIRECTORY, log_name))}"
            if log_type != 'file':
                command = f"sudo journalctl -u {shlex.quote(log_name)} -n 500 --no-pager"

            result = execute_command(host, command)
            log_content = result.stdout
            if not log_content:
                _emit({'status': 'log', 'message': f'Skipping {log_name} on {host}: empty log.'})
                continue

            data_start, data_end = extract_log_time_range(log_content)

            # Notify Discord that analysis started (info)
            send_discord_status(webhook_url, log_name, host, 'Analysis started.', data_start=data_start, data_end=data_end)

            # Split long logs into chunks instead of truncating
            chunks = [log_content[j:j + MAX_CHAR_COUNT] for j in range(0, len(log_content), MAX_CHAR_COUNT)]
            if len(chunks) > 1:
                _emit({'status': 'log', 'message': f'Log is large; splitting into {len(chunks)} parts for analysis.'})

            analysis_parts = []

            for part_idx, chunk in enumerate(chunks, start=1):
                part_label = f'part {part_idx}/{len(chunks)}' if len(chunks) > 1 else 'single part'
                _emit({'status': 'log', 'message': f'Analyzing {part_label}...'})

                hb_stop = threading.Event()

                def _hb():
                    waited = 0
                    while not hb_stop.wait(5):
                        waited += 5
                        _emit({'status': 'log', 'message': f'Waiting for {provider} response ({waited}s)...'})

                hb_thread = threading.Thread(target=_hb)
                hb_thread.daemon = True

                try:
                    _emit({'status': 'log', 'message': f'Waiting for {provider} response...'})
                    hb_thread.start()

                    if provider == 'ollama':
                        part_analysis = analyse_with_ollama(chunk, f"{log_name} on {host}", config.get('ollama_url'), config.get('ollama_model'))
                    else:
                        prompt = get_ai_search_prompt()
                        client = openai.OpenAI(api_key=config.get('api_key'))
                        response = client.chat.completions.create(
                            model="gpt-3.5-turbo",
                            messages=[
                                {"role": "system", "content": "You are a helpful assistant that analyses log files for potential issues."},
                                {"role": "user", "content": f"{prompt}\n\n--- LOG for {log_name} on {host} ({part_label}) ---\n{chunk}"},
                            ]
                        )
                        part_analysis = response.choices[0].message.content

                    analysis_parts.append(part_analysis)

                    _emit({'status': 'log', 'message': f'✅ Completed {part_label}.'})
                finally:
                    hb_stop.set()

            analysis = "\n\n".join(analysis_parts)
            alert_needed = any(keyword.lower() in analysis.lower() for keyword in get_ai_alert_keywords())
            if alert_needed:
                _emit({'status': 'log', 'message': f'Issue found in {log_name} on {host}. Sending alert to Discord...'})
                send_discord_notification(webhook_url, log_name, host, analysis, data_start=data_start, data_end=data_end)
                _emit({'status': 'log', 'message': 'Discord alert sent.'})
            else:
                _emit({'status': 'log', 'message': f'No alert keywords found for {log_name} on {host}; sending summary to Discord.'})
                exec_sum = _exec_summary_from_analysis(analysis)
                send_discord_status(webhook_url, log_name, host, f'No alert keywords found.\n\nExecutive summary:\n{exec_sum}', data_start=data_start, data_end=data_end)

        except Exception as e:
            _emit({'status': 'log', 'message': f'Error analyzing {log_name} on {host}: {e}'})

    _emit({'status': 'complete', 'message': 'Scheduled analysis completed.', 'progress': 100})

def _run_schedule(schedule: Schedule, emit=None):
    """Run analysis for a specific Schedule by temporarily overriding legacy schedule.sources.

    This reuses the existing _do_analysis_task implementation while we complete the migration.
    """
    # Build sources list
    sources = []
    for ss in ScheduleSource.query.filter_by(schedule_id=schedule.id).all():
        sources.append({'host': ss.host_id, 'type': ss.source_type, 'name': ss.source_name})

    old_sources = _setting_get('schedule.sources', [])
    try:
        _setting_set('schedule.sources', sources)
        _do_analysis_task(emit=emit)
    finally:
        try:
            _setting_set('schedule.sources', old_sources)
        except Exception:
            pass


# --- MULTI-SCHEDULE API + MIGRATION HELPERS ---

def _get_all_host_choices():
    """Return list of (host_id, host_name) including local and remote hosts.
    
    Must match the IDs returned by /hosts (config hosts + db-<id> hosts).
    """
    hosts_data = load_hosts() or {}
    out = [('local', 'Localhost')]
    
    # config-file hosts
    for hid, h in hosts_data.items():
        try:
            out.append((hid, (h.get('friendly_name') or hid)))
        except Exception:
            out.append((hid, hid))
    
    # db-backed hosts (wizard)
    try:
        for h in Host.query.all():
            hid = f'db-{h.id}'
            name = (h.friendly_name or h.hostname or h.ip_address or hid)
            if not any(x[0] == hid for x in out):
                out.append((hid, name))
    except Exception:
        pass
    
    return out

def _schedule_to_payload(s: Schedule, include_children: bool = True):
    if not s:
        return None
    return s.to_dict(include_children=include_children)


def _ensure_default_schedule_migrated():
    """If no schedules exist, create a Default schedule from legacy schedule.* settings."""
    if Schedule.query.count() > 0:
        return

    interval = int(_setting_get('schedule.interval_hours', 6) or 6)
    enabled = bool(_setting_get('schedule.is_running', False))
    legacy_sources = _setting_get('schedule.sources', []) or []

    s = Schedule(name='Default', enabled=enabled, interval_hours=max(1, interval))
    db.session.add(s)
    db.session.flush()  # get id

    # Derive hosts from sources, falling back to local
    host_ids = []
    for src in legacy_sources:
        try:
            hid = (src or {}).get('host') or 'local'
        except Exception:
            hid = 'local'
        if hid not in host_ids:
            host_ids.append(hid)

    if not host_ids:
        host_ids = ['local']

    for hid in host_ids:
        db.session.add(ScheduleHost(schedule_id=s.id, host_id=hid))

    for src in legacy_sources:
        if not isinstance(src, dict):
            continue
        hid = src.get('host') or 'local'
        st = src.get('type')
        sn = src.get('name')
        if not st or not sn:
            continue
        db.session.add(ScheduleSource(schedule_id=s.id, host_id=hid, source_type=str(st), source_name=str(sn)))

    db.session.commit()


def _sync_scheduler_jobs_from_db():
    """Ensure APScheduler has one interval job per enabled schedule."""
    _ensure_schedule_worker()

    enabled_schedules = Schedule.query.filter_by(enabled=True).all()
    enabled_ids = {s.id for s in enabled_schedules}

    # Remove jobs for schedules that are no longer enabled
    for job in list(scheduler.get_jobs()):
        if job.id.startswith('schedule_'):
            try:
                sid = int(job.id.split('_', 1)[1])
            except Exception:
                continue
            if sid not in enabled_ids:
                try:
                    scheduler.remove_job(job.id)
                except Exception:
                    pass

    # Upsert jobs for enabled schedules
    for s in enabled_schedules:
        hours = max(1, int(s.interval_hours or 6))

        def _make_job(schedule_id: int):
            def _job():
                _enqueue_schedule_run(schedule_id, reason='scheduled')
            return _job

        scheduler.add_job(
            _make_job(s.id),
            trigger='interval',
            hours=hours,
            id=f'schedule_{s.id}',
            replace_existing=True,
        )


@app.route('/api/schedules', methods=['GET', 'POST'])
def api_schedules_collection():
    if request.method == 'GET':
        schedules = Schedule.query.order_by(Schedule.id.asc()).all()
        return jsonify([_schedule_to_payload(s, include_children=True) for s in schedules])

    data = request.get_json(force=True, silent=True) or {}
    name = (data.get('name') or 'Schedule').strip()
    enabled = bool(data.get('enabled', False))
    interval_hours = int(data.get('interval_hours') or 6)
    interval_hours = max(1, interval_hours)

    s = Schedule(name=name, enabled=enabled, interval_hours=interval_hours)
    db.session.add(s)
    db.session.flush()

    host_ids = data.get('hosts') or []
    if not isinstance(host_ids, list):
        host_ids = []
    if not host_ids:
        host_ids = ['local']

    for hid in host_ids:
        db.session.add(ScheduleHost(schedule_id=s.id, host_id=str(hid)))

    sources = data.get('sources') or []
    if isinstance(sources, list):
        for src in sources:
            if not isinstance(src, dict):
                continue
            hid = src.get('host') or src.get('host_id') or 'local'
            st = src.get('type') or src.get('source_type')
            sn = src.get('name') or src.get('source_name')
            if not st or not sn:
                continue
            db.session.add(ScheduleSource(schedule_id=s.id, host_id=str(hid), source_type=str(st), source_name=str(sn)))

    db.session.commit()

    _sync_scheduler_jobs_from_db()

    return jsonify(_schedule_to_payload(s, include_children=True)), 201


@app.route('/api/schedules/<int:schedule_id>', methods=['GET', 'PUT', 'DELETE'])
def api_schedule_item(schedule_id: int):
    s = Schedule.query.get_or_404(schedule_id)

    if request.method == 'GET':
        return jsonify(_schedule_to_payload(s, include_children=True))

    if request.method == 'DELETE':
        try:
            scheduler.remove_job(f'schedule_{s.id}')
        except Exception:
            pass
        db.session.delete(s)
        db.session.commit()
        return jsonify({'message': 'Schedule deleted.'})

    data = request.get_json(force=True, silent=True) or {}
    if 'name' in data:
        s.name = (data.get('name') or s.name).strip() or s.name
    if 'enabled' in data:
        s.enabled = bool(data.get('enabled'))
    if 'interval_hours' in data:
        s.interval_hours = max(1, int(data.get('interval_hours') or s.interval_hours or 6))

    # Replace hosts if provided
    if 'hosts' in data:
        host_ids = data.get('hosts')
        if not isinstance(host_ids, list):
            host_ids = []
        ScheduleHost.query.filter_by(schedule_id=s.id).delete()
        if not host_ids:
            host_ids = ['local']
        for hid in host_ids:
            db.session.add(ScheduleHost(schedule_id=s.id, host_id=str(hid)))

    # Replace sources if provided
    if 'sources' in data:
        sources = data.get('sources')
        ScheduleSource.query.filter_by(schedule_id=s.id).delete()
        if isinstance(sources, list):
            for src in sources:
                if not isinstance(src, dict):
                    continue
                hid = src.get('host') or src.get('host_id') or 'local'
                st = src.get('type') or src.get('source_type')
                sn = src.get('name') or src.get('source_name')
                if not st or not sn:
                    continue
                db.session.add(ScheduleSource(schedule_id=s.id, host_id=str(hid), source_type=str(st), source_name=str(sn)))

    db.session.commit()
    _sync_scheduler_jobs_from_db()
    return jsonify(_schedule_to_payload(s, include_children=True))


@app.route('/api/schedules/<int:schedule_id>/run_now/stream', methods=['GET'])
def api_schedule_run_now_stream(schedule_id: int):
    from queue import Queue, Empty

    s = Schedule.query.get_or_404(schedule_id)

    q: Queue = Queue()

    def emit(payload):
        q.put(payload)

    # Basic validation: must have at least one source
    if ScheduleSource.query.filter_by(schedule_id=s.id).count() == 0:
        def gen_err():
            yield f"data: {json.dumps({'status':'error','message':'No log sources selected for this schedule.'})}\n\n"
        headers = {'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
        return Response(stream_with_context(gen_err()), mimetype='text/event-stream', headers=headers)

    _ensure_schedule_worker()
    _enqueue_schedule_run(s.id, reason='manual', emit=emit)

    def generate():
        yield f"data: {json.dumps({'status':'progress','message':'Queued...','progress':0})}\n\n"
        while True:
            try:
                payload = q.get(timeout=10)
            except Empty:
                yield ': keepalive\n\n'
                continue
            yield f"data: {json.dumps(payload)}\n\n"
            if payload.get('status') in ('complete', 'error'):
                break

    headers = {'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    return Response(stream_with_context(generate()), mimetype='text/event-stream', headers=headers)


@app.route('/api/schedules/<int:schedule_id>/sources/table/stream', methods=['GET'])
def api_schedule_sources_table_stream(schedule_id: int):
    """Like /sources/table/stream but limited to selected hosts (host-first)."""
    Schedule.query.get_or_404(schedule_id)

    # Hosts can be passed as querystring: ?hosts=local,host1,host2
    hosts_param = (request.args.get('hosts') or '').strip()
    allowed = None
    if hosts_param:
        allowed = {h.strip() for h in hosts_param.split(',') if h.strip()}

    def generate_table_events():
        def generate_event(data):
            return f"data: {json.dumps(data)}\n\n"

        try:
            yield generate_event({'status': 'progress', 'message': 'Initializing host scan...', 'progress': 5})

            all_sources = []
            failed_hosts = []
            all_hostnames = _get_all_host_choices()
            if allowed is not None:
                all_hostnames = [(hid, hname) for hid, hname in all_hostnames if hid in allowed]

            total_hosts = len(all_hostnames)
            if total_hosts == 0:
                yield generate_event({'status': 'error', 'message': 'No hosts selected.'})
                return

            yield generate_event({'status': 'progress', 'message': f'Found {total_hosts} hosts to scan', 'progress': 10})

            for i, (host_id, host_name) in enumerate(all_hostnames):
                host_progress = 10 + int((i / total_hosts) * 80)
                yield generate_event({'status': 'progress', 'message': f'Connecting to {host_name}...', 'progress': host_progress})
                try:
                    host_sources = fetch_sources_from_host_detailed(host_id, host_name, generate_event, host_progress)
                    all_sources.extend(host_sources)
                    yield generate_event({'status': 'progress', 'message': f'✅ {host_name}: Found {len(host_sources)} log sources', 'progress': host_progress + int(80/total_hosts)})
                except Exception as e:
                    error_msg = str(e)
                    if 'timeout' in error_msg.lower():
                        error_msg = 'Connection timed out'
                    elif 'connection refused' in error_msg.lower():
                        error_msg = 'Connection refused'
                    elif 'no route to host' in error_msg.lower():
                        error_msg = 'No route to host'
                    failed_hosts.append({'host_id': host_id, 'host_name': host_name, 'error': error_msg})
                    yield generate_event({'status': 'progress', 'message': f'❌ {host_name}: {error_msg}', 'progress': host_progress + int(80/total_hosts)})

            yield generate_event({'status': 'progress', 'message': 'Building log matrix...', 'progress': 90})

            log_matrix = {}
            host_list = []
            for host_id, host_name in all_hostnames:
                if not any(f['host_id'] == host_id for f in failed_hosts):
                    host_list.append({'host_id': host_id, 'host_name': host_name})

            for source in all_sources:
                log_key = f"{source['name']}|{source['type']}"
                if log_key not in log_matrix:
                    log_matrix[log_key] = {
                        'name': source['name'],
                        'type': source['type'],
                        'hosts': {},
                        'size_info': source.get('size_formatted', 'N/A'),
                        'modified_info': source.get('modified_formatted', 'N/A')
                    }
                log_matrix[log_key]['hosts'][source['host']] = {
                    'host_id': source['host'],
                    'host_name': source['host_name'],
                    'size_bytes': source.get('size_bytes', 0),
                    'size_formatted': source.get('size_formatted', 'N/A'),
                    'modified_epoch': source.get('modified_epoch', 0),
                    'modified_formatted': source.get('modified_formatted', 'N/A')
                }

            logs_table = list(log_matrix.values())
            logs_table.sort(key=lambda x: x['name'].lower())

            response_data = {
                'logs': logs_table,
                'hosts': host_list,
                'failed_hosts': failed_hosts,
                'total_hosts': len(all_hostnames),
                'successful_hosts': len(host_list)
            }

            yield generate_event({'status': 'complete', 'data': response_data, 'progress': 100})

        except Exception as e:
            yield generate_event({'status': 'error', 'message': str(e)})

    return Response(stream_with_context(generate_table_events()), mimetype='text/event-stream')


@app.route('/schedule/start', methods=['POST'])
def start_schedule():
    config = request.get_json()
    interval = config.get('interval')
    if not interval or interval <= 0: return jsonify({'error': 'Invalid interval.'}), 400
    config['is_running'] = True
    save_config(config)
    if scheduler.get_job('scheduled_analysis'): scheduler.remove_job('scheduled_analysis')
    scheduler.add_job(perform_scheduled_analysis, 'interval', hours=interval, id='scheduled_analysis', replace_existing=True)
    return jsonify({'message': 'Scheduled analysis started.'})

@app.route('/schedule/stop', methods=['POST'])
def stop_schedule():
    if scheduler.get_job('scheduled_analysis'): scheduler.remove_job('scheduled_analysis')
    config = load_config()
    config['is_running'] = False
    save_config(config)
    return jsonify({'message': 'Scheduled analysis stopped.'})

@app.route('/schedule/run_now', methods=['POST'])
def run_now():
    config = load_config()
    if not all([config.get('api_key'), config.get('webhook_url'), config.get('sources')]):
         return jsonify({'error': 'Cannot run. Configure API key, webhook, and select logs first.'}), 400
    thread = threading.Thread(target=_do_analysis_task)
    thread.daemon = True
    thread.start()
    return jsonify({'message': 'Immediate analysis triggered. Alerts will be sent for any issues found.'})

@app.route('/schedule/run_now/stream', methods=['GET'])
def run_now_stream():
    """Run an immediate analysis and stream progress via Server-Sent Events."""
    from queue import Queue, Empty

    q: Queue = Queue()

    def emit(payload):
        q.put(payload)

    config = load_config()
    provider = config.get('analysis_provider', 'openai')
    # Validate minimal requirements
    if not config.get('webhook_url') or not config.get('sources'):
        def gen_err():
            yield f"data: {json.dumps({'status':'error','message':'Cannot run. Configure Discord webhook and select logs first.'})}\n\n"
        headers = {'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
        return Response(stream_with_context(gen_err()), mimetype='text/event-stream', headers=headers)
    if provider != 'ollama' and not config.get('api_key'):
        def gen_err():
            yield f"data: {json.dumps({'status':'error','message':'Cannot run. Configure OpenAI API key first.'})}\n\n"
        headers = {'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
        return Response(stream_with_context(gen_err()), mimetype='text/event-stream', headers=headers)

    def worker():
        try:
            _do_analysis_task(emit=emit)
        except Exception as e:
            emit({'status': 'error', 'message': f'Run failed: {e}'})
        finally:
            emit({'status': 'complete', 'message': 'Run finished.', 'progress': 100})

    thread = threading.Thread(target=worker)
    thread.daemon = True
    thread.start()

    def generate():
        # send initial ping
        yield f"data: {json.dumps({'status':'progress','message':'Run started...','progress':0})}\n\n"
        while True:
            try:
                payload = q.get(timeout=10)
            except Empty:
                # keepalive
                yield ': keepalive\n\n'
                continue
            yield f"data: {json.dumps(payload)}\n\n"
            if payload.get('status') in ('complete','error'):
                break

    headers = {'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    return Response(stream_with_context(generate()), mimetype='text/event-stream', headers=headers)

@app.route('/schedule/status', methods=['GET', 'POST'])
def schedule_status():
    config = load_config()
    job = scheduler.get_job('scheduled_analysis')
    status = {'is_running': False, 'sources': config.get('sources', []), 'interval': config.get('interval')}
    if job and config.get('is_running'):
        status.update({'is_running': True, 'next_run': job.next_run_time.isoformat() if job.next_run_time else None})
    return jsonify(status)

def perform_scheduled_analysis():
    config = load_config()
    if not config.get('is_running'):
        print("Scheduler is paused. Skipping scheduled run.")
        return
    _do_analysis_task()

# --- STARTUP & SHUTDOWN ---

def _run_monitors_in_appctx(fn, limit: int):
    """Run a callable inside a Flask app context (for APScheduler jobs)."""
    try:
        with app.app_context():
            return fn(limit=limit)
    except Exception as e:
        print(f'[WARN] Monitoring runner failed: {e}')
        return None

def startup_scheduler():
    """Start APScheduler and sync jobs from DB schedules."""
    with app.app_context():
        # Monitoring runner job (executes due monitors)
        try:
            from monitoring.scheduler import run_due_monitors
            scheduler.add_job(
                lambda: (_run_monitors_in_appctx(run_due_monitors, 100)),
                trigger='interval',
                seconds=15,
                id='monitoring_runner',
                replace_existing=True,
                max_instances=1,
                coalesce=True,
            )
        except Exception as e:
            print(f'[WARN] Monitoring scheduler job not started: {e}')

        try:
            _ensure_default_schedule_migrated()
        except Exception as e:
            print(f'[WARN] Schedule migration skipped: {e}')
        try:
            _sync_scheduler_jobs_from_db()
        except Exception as e:
            print(f'[WARN] Scheduler sync skipped: {e}')

# --- STARTUP INITIALIZATION ---
def initialize_app():
    """Initialize application components on startup"""
    print("=== AI Log Viewer Startup ===")
    # Migrate legacy scheduler_config.json into DB settings
    try:
        _migrate_scheduler_config_file_to_db()
    except Exception as e:
        print(f"[WARN] Settings migration skipped: {e}")

    
    # Load and display host configuration
    hosts = load_hosts()
    if hosts:
        print(f"Loaded {len(hosts)} configured hosts:")
        for host_id, host_data in hosts.items():
            print(f"  - {host_data.get('friendly_name', 'Unnamed')} ({host_data.get('user')}@{host_data.get('ip')})")
    else:
        print("No hosts configured - only localhost will be available")
    
    # Load scheduler configuration
    config = load_config()
    if config.get('is_running'):
        print(f"Scheduler was previously running - will restart with {config.get('interval', 1)} hour interval")
        scheduled_sources = config.get('sources', [])
        if scheduled_sources:
            print(f"Monitoring {len(scheduled_sources)} log sources for analysis")
    else:
        print("Scheduler is not configured to run")
    
    print(f"Starting web server on http://0.0.0.0:5001")
    print("============================")


# --- SURICATA SENSOR SUPPORT ---
SURICATA_ALLOWED_FILES = ['eve.json', 'fast.log', 'stats.log', 'suricata.log']

# Cache SSH key temp files (key_id -> path)
_suricata_key_cache = {}

# Cache SSH key temp files (ssh_key_id -> path) for general remote operations
_ssh_key_file_cache = {}

def _cleanup_ssh_key_file_cache():
    for p in list(_ssh_key_file_cache.values()):
        try:
            if p and os.path.exists(p):
                os.unlink(p)
        except Exception:
            pass

atexit.register(_cleanup_ssh_key_file_cache)


def _write_temp_ssh_key_file(plaintext: str) -> str:
    """Write SSH key plaintext to a temp file in a way that avoids newline/encoding issues."""
    normalized = normalize_ssh_key_text(plaintext or '')
    if normalized and not normalized.endswith("\n"):
        normalized = normalized + "\n"
    tf = tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False)
    tf.write(normalized.encode('utf-8'))
    tf.flush(); tf.close()
    os.chmod(tf.name, 0o600)
    return tf.name




def _sshkey_plaintext_from_model(key: SSHKey) -> str:
    """Return decrypted plaintext for a stored SSHKey row.

    Historical note: some rows ended up being encrypted multiple times due to earlier
    bugs/migrations. We attempt to decrypt repeatedly until the result resembles an
    SSH private key.
    """
    if not key:
        return ''

    content = key.key_content or ''
    if not getattr(key, 'is_encrypted', False):
        return content

    # Decrypt up to N layers. Stop once it looks like a private key.
    max_layers = 6
    for layer in range(1, max_layers + 1):
        try:
            content = decrypt_str(content)
        except Exception as e:
            print(f"[DEBUG] SSH key decrypt failed at layer {layer}: {e}", flush=True)
            break

        # If we got something that looks like a private key, stop.
        if 'BEGIN' in content and 'PRIVATE KEY' in content and 'END' in content:
            break

        # If it still looks like an encoded blob (single-line token), keep going.
        # (Fernet tokens / our stored format often look like long base64-url strings.)
        if '\n' not in content and len(content) > 200 and re.fullmatch(r'[A-Za-z0-9_\-]+=*', content.strip()):
            continue

        # Otherwise: stop; we don't want to accidentally mangle non-token plaintext.
        break

    return content or ''


def _materialize_ssh_key_path(ssh_key_id: int | None) -> str | None:
    """Return temp file path containing decrypted key; cached per key id."""
    if not ssh_key_id:
        return None
    ssh_key_id = int(ssh_key_id)
    if ssh_key_id in _ssh_key_file_cache and os.path.exists(_ssh_key_file_cache[ssh_key_id]):
        return _ssh_key_file_cache[ssh_key_id]
    key = SSHKey.query.get(ssh_key_id)
    if not key:
        print(f"[DEBUG] SSH key {ssh_key_id} not found in database")
        return None
    print(f"[DEBUG] SSH key {ssh_key_id} found: is_encrypted={getattr(key, 'is_encrypted', 'MISSING')}")
    content = _sshkey_plaintext_from_model(key)
    print(f"[DEBUG] Key content length after decryption: {len(content) if content else 0} bytes")
    if not content:
        print(f"[DEBUG] SSH key {ssh_key_id} decrypted to empty content")
        return None
    if not content.lstrip().startswith('BEGIN'):
        print(f"[DEBUG] WARNING: SSH key {ssh_key_id} doesn't start with a PEM BEGIN header after decryption!")
        print(f"[DEBUG] First 100 chars: {content[:100]!r}")
    if not content.strip().endswith('END'):
        print(f"[DEBUG] WARNING: SSH key {ssh_key_id} doesn't end with 'END' after decryption!")
        print(f"[DEBUG] Last 100 chars: {content[-100:]!r}")
    tf_name = _write_temp_ssh_key_file(content)
    # Verify file was written correctly
    with open(tf_name, 'r', encoding='utf-8') as f:
        written_content = f.read()
    if written_content != content:
        print(f"[DEBUG] WARNING: Written key content doesn't match original!")
        print(f"[DEBUG] Original: {len(content)} bytes, Written: {len(written_content)} bytes")
    print(f"[DEBUG] Materialized SSH key {ssh_key_id} to {tf_name} ({len(content)} bytes)")
    
    # Verify we can read it back
    try:
        with open(tf_name, 'r') as verify_f:
            verify_content = verify_f.read()
        if verify_content == content:
            print(f"[DEBUG] ✓ Key file verified: content matches")
        else:
            print(f"[DEBUG] ✗ Key file mismatch: {len(verify_content)} bytes read vs {len(content)} bytes written")
        
        # Check permissions
        stat_info = os.stat(tf_name)
        print(f"[DEBUG] Key file permissions: {oct(stat_info.st_mode)}")
    except Exception as e:
        print(f"[DEBUG] Error verifying key file: {e}")
    
    _ssh_key_file_cache[ssh_key_id] = tf_name
    return tf_name


def _suricata_cleanup_key_cache():
    for p in list(_suricata_key_cache.values()):
        try:
            if p and os.path.exists(p):
                os.unlink(p)
        except Exception:
            pass

atexit.register(_suricata_cleanup_key_cache)


def _suricata_get_ssh_key_path(ssh_key_id: int | None) -> str | None:
    """Return a local temp file path containing the SSH private key for this id."""
    if not ssh_key_id:
        return None
    if ssh_key_id in _suricata_key_cache and os.path.exists(_suricata_key_cache[ssh_key_id]):
        return _suricata_key_cache[ssh_key_id]

    key = SSHKey.query.get(int(ssh_key_id))
    if not key:
        return None

    tf = tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False)
    tf.write(_sshkey_plaintext_from_model(key) or '')
    tf.flush()
    tf.close()
    os.chmod(tf_name, 0o600)
    _suricata_key_cache[ssh_key_id] = tf_name
    return tf_name


def _suricata_bucket_ts(epoch_seconds: int, bucket_size: int) -> int:
    return int(epoch_seconds // bucket_size) * bucket_size


def _parse_suricata_ts(value: str) -> int | None:
    """Parse Suricata timestamp strings to epoch seconds."""
    if not value:
        return None
    v = value.strip()
    # eve.json timestamps are ISO-like; allow trailing Z
    try:
        if v.endswith('Z'):
            v = v[:-1] + '+00:00'
        dt = datetime.datetime.fromisoformat(v)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return int(dt.timestamp())
    except Exception:
        pass
    # fast.log timestamps are MM/DD/YYYY-HH:MM:SS.uuuuuu
    try:
        dt = datetime.datetime.strptime(v, '%m/%d/%Y-%H:%M:%S.%f')
        dt = dt.replace(tzinfo=datetime.timezone.utc)
        return int(dt.timestamp())
    except Exception:
        return None


def _suricata_remote_cmd(user: str, host: str, cmd: str, ssh_key_path: str | None, timeout: int = 20) -> tuple[bool, str]:
    return execute_remote_command(user, host, cmd, ssh_key_path=ssh_key_path, timeout=timeout)


def _suricata_remote_stat(user: str, host: str, ssh_key_path: str | None, path: str) -> dict:
    # inode size mtime
    ok, out = _suricata_remote_cmd(user, host, f"sudo stat -c '%i %s %Y' {shlex.quote(path)}", ssh_key_path, timeout=20)
    if not ok:
        return {'ok': False, 'error': out.strip()[:200]}
    try:
        inode, size, mtime = out.strip().split()[:3]
        return {'ok': True, 'inode': inode, 'size': int(size), 'mtime': int(mtime)}
    except Exception:
        return {'ok': False, 'error': f'Could not parse stat output: {out.strip()[:200]}'}


def _suricata_incremental_read(user: str, host: str, ssh_key_path: str | None, path: str, offset: int, max_bytes: int) -> tuple[bool, str]:
    # dd is widely available and allows byte offsets; cap read size.
    cmd = f"sudo dd if={shlex.quote(path)} bs=1 skip={int(offset)} count={int(max_bytes)} status=none 2>/dev/null"
    return _suricata_remote_cmd(user, host, cmd, ssh_key_path, timeout=60)


def _suricata_get_or_create_state(sensor_id: int, filename: str) -> SuricataIngestState:
    st = SuricataIngestState.query.filter_by(sensor_id=sensor_id, filename=filename).first()
    if st:
        return st
    st = SuricataIngestState(sensor_id=sensor_id, filename=filename, last_offset=0)
    db.session.add(st)
    db.session.commit()
    return st


def _suricata_ingest_fast_log(sensor: SuricataSensor, content: str, bucket_size: int) -> dict:
    # Format:
    # 03/21/2021-20:24:02.524057  [**] [1:2006380:14] MSG [**] [Classification: ...] [Priority: 1] {TCP} src:port -> dst:port
    rx = re.compile(r'^(?P<ts>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<msg>.*?)\s+\[\*\*\]\s+\[Classification:\s+(?P<class>.*?)\]\s+\[Priority:\s+(?P<prio>\d+)\]\s+\{(?P<proto>\w+)\}\s+(?P<src>[^\s]+)\s+->\s+(?P<dst>[^\s]+)')
    rows = 0
    for line in content.splitlines():
        m = rx.match(line)
        if not m:
            continue
        epoch = _parse_suricata_ts(m.group('ts'))
        if epoch is None:
            continue
        bts = _suricata_bucket_ts(epoch, bucket_size)
        sid = int(m.group('sid'))
        msg = (m.group('msg') or '')[:512]
        classification = (m.group('class') or '')[:256]
        priority = int(m.group('prio'))
        proto = (m.group('proto') or '')[:16]
        src_raw = m.group('src')
        dst_raw = m.group('dst')
        src_ip, src_port = None, None
        dst_ip, dst_port = None, None
        try:
            if src_raw and ':' in src_raw:
                src_ip, sp = src_raw.rsplit(':', 1)
                src_port = int(sp)
            else:
                src_ip = src_raw
        except Exception:
            pass
        try:
            if dst_raw and ':' in dst_raw:
                dst_ip, dp = dst_raw.rsplit(':', 1)
                dst_port = int(dp)
            else:
                dst_ip = dst_raw
        except Exception:
            pass

        db.session.add(SuricataFastAlertBucket(
            sensor_id=sensor.id,
            bucket_ts=bts,
            sid=sid,
            msg=msg,
            classification=classification,
            priority=priority,
            proto=proto,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            count=1,
        ))
        rows += 1
    return {'fast_rows': rows}


def _suricata_ingest_eve_alerts(sensor: SuricataSensor, content: str, bucket_size: int) -> dict:
    rows = 0
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if obj.get('event_type') != 'alert':
            continue
        epoch = _parse_suricata_ts(obj.get('timestamp') or '')
        if epoch is None:
            continue
        bts = _suricata_bucket_ts(epoch, bucket_size)
        alert = obj.get('alert') or {}
        sig_id = alert.get('signature_id')
        sig = (alert.get('signature') or '')[:512]
        cat = (alert.get('category') or '')[:256]
        sev = alert.get('severity')
        try:
            sig_id = int(sig_id) if sig_id is not None else None
        except Exception:
            sig_id = None
        try:
            sev = int(sev) if sev is not None else None
        except Exception:
            sev = None

        src_ip = (obj.get('src_ip') or None)
        dst_ip = (obj.get('dest_ip') or obj.get('dst_ip') or None)
        src_port = obj.get('src_port')
        dst_port = obj.get('dest_port') or obj.get('dst_port')
        proto = (obj.get('proto') or None)
        app_proto = (obj.get('app_proto') or None)
        try:
            src_port = int(src_port) if src_port is not None else None
        except Exception:
            src_port = None
        try:
            dst_port = int(dst_port) if dst_port is not None else None
        except Exception:
            dst_port = None
        db.session.add(SuricataAlertBucket(
            sensor_id=sensor.id,
            bucket_ts=bts,
            signature_id=sig_id,
            signature=sig,
            category=cat,
            severity=sev,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            proto=proto,
            app_proto=app_proto,
            count=1,
        ))
        rows += 1
    return {'eve_alert_rows': rows}


def _suricata_ingest_stats_log(sensor: SuricataSensor, content: str, bucket_size: int, allow_counters: set[str]) -> dict:
    # Parse blocks starting with: Date: 4/8/2024 -- 16:17:28 (uptime: ...)
    # Then table lines: counter | TM Name | Value
    date_rx = re.compile(r'^Date:\s+(?P<d>\d{1,2}/\d{1,2}/\d{4})\s+--\s+(?P<t>\d{2}:\d{2}:\d{2})')
    row_rx = re.compile(r'^(?P<counter>[A-Za-z0-9_\.\-]+)\s*\|\s*(?P<tm>[^|]+?)\s*\|\s*(?P<val>-?\d+)\s*$')

    current_epoch = None
    rows = 0
    for line in content.splitlines():
        line = line.rstrip('\n')
        dm = date_rx.match(line.strip())
        if dm:
            try:
                dt = datetime.datetime.strptime(dm.group('d') + ' ' + dm.group('t'), '%m/%d/%Y %H:%M:%S')
                dt = dt.replace(tzinfo=datetime.timezone.utc)
                current_epoch = int(dt.timestamp())
            except Exception:
                current_epoch = None
            continue
        rm = row_rx.match(line)
        if not rm or current_epoch is None:
            continue
        counter = rm.group('counter')
        if allow_counters and counter not in allow_counters:
            continue
        tm = (rm.group('tm') or '').strip()[:128]
        try:
            val = int(rm.group('val'))
        except Exception:
            continue
        bts = _suricata_bucket_ts(current_epoch, bucket_size)
        db.session.add(SuricataStatsCounterBucket(
            sensor_id=sensor.id,
            bucket_ts=bts,
            counter=counter,
            tm_name=tm,
            value=val,
        ))
        rows += 1
    return {'stats_rows': rows}


def suricata_ingest_sensor(sensor: SuricataSensor, bucket_size: int, max_bytes_per_file: int = 2_000_000) -> dict:
    """Incrementally ingest Suricata files for a single sensor."""
    ssh_key_path = None
    with app.app_context():
        ssh_key_path = _suricata_get_ssh_key_path(sensor.ssh_key_id)

    base = sensor.log_dir.rstrip('/')
    summary = {'sensor_id': sensor.id, 'files': {}, 'errors': []}

    # Only store a few counters that are useful for graphs/KPIs
    allow_counters = {
        'decoder.pkts',
        'decoder.bytes',
        'capture.kernel_drops',
        'capture.kernel_packets',
        'tcp.reassembly_gap',
        'detect.alert',
        'flow.memuse',
        'tcp.memuse',
    }

    for fn in SURICATA_ALLOWED_FILES:
        full = f"{base}/{fn}"
        st = _suricata_get_or_create_state(sensor.id, fn)
        stat = _suricata_remote_stat(sensor.user, sensor.host, ssh_key_path, full)
        if not stat.get('ok'):
            summary['files'][fn] = {'ok': False, 'error': stat.get('error')}
            continue

        inode = str(stat['inode'])
        size = int(stat['size'])
        mtime = int(stat['mtime'])

        # Rotation/truncation detection
        if st.last_inode and st.last_inode != inode:
            st.last_offset = 0
        if st.last_size is not None and size < int(st.last_size or 0):
            st.last_offset = 0

        offset = int(st.last_offset or 0)
        if offset > size:
            offset = 0

        to_read = min(max_bytes_per_file, max(0, size - offset))
        if to_read <= 0:
            st.last_inode = inode
            st.last_size = size
            st.last_mtime = mtime
            db.session.commit()
            summary['files'][fn] = {'ok': True, 'read_bytes': 0, 'size': size, 'mtime': mtime}
            continue

        ok, chunk = _suricata_incremental_read(sensor.user, sensor.host, ssh_key_path, full, offset, to_read)
        if not ok:
            summary['files'][fn] = {'ok': False, 'error': (chunk or '').strip()[:200]}
            continue

        # Ingest content
        try:
            if fn == 'fast.log':
                out = _suricata_ingest_fast_log(sensor, chunk, bucket_size)
            elif fn == 'eve.json':
                out = _suricata_ingest_eve_alerts(sensor, chunk, bucket_size)
            elif fn == 'stats.log':
                out = _suricata_ingest_stats_log(sensor, chunk, bucket_size, allow_counters)
            else:
                out = {'skipped': True}

            db.session.commit()
        except Exception as e:
            db.session.rollback()
            summary['errors'].append(f"{fn}: {str(e)[:200]}")
            out = {'error': str(e)[:200]}

        # Update ingest state
        st.last_inode = inode
        st.last_size = size
        st.last_mtime = mtime
        st.last_offset = offset + len(chunk.encode('utf-8', errors='ignore'))
        db.session.commit()

        summary['files'][fn] = {'ok': True, 'read_bytes': to_read, 'size': size, 'mtime': mtime, **out}

    return summary


def suricata_ingest_all_enabled() -> list[dict]:
    results = []
    with app.app_context():
        sensors = SuricataSensor.query.filter_by(enabled=True).all()
        for sensor in sensors:
            try:
                results.append(suricata_ingest_sensor(sensor, bucket_size=60))
            except Exception as e:
                results.append({'sensor_id': sensor.id, 'error': str(e)[:200]})
    return results


def startup_suricata_ingest_jobs():
    """Ensure there is one APScheduler job to ingest Suricata sensors."""
    def _job():
        try:
            suricata_ingest_all_enabled()
        except Exception as e:
            print(f"[WARN] Suricata ingest job failed: {e}")

    # Run every 30s; sensors can be individually throttled later.
    scheduler.add_job(_job, trigger='interval', seconds=30, id='suricata_ingest', replace_existing=True)


@app.route('/suricata/config', methods=['GET', 'POST'])
def suricata_config():
    if request.method == 'GET':
        sensors = SuricataSensor.query.order_by(SuricataSensor.updated_at.desc(), SuricataSensor.id.desc()).all()
        return jsonify([s.to_dict() for s in sensors])

    data = request.get_json(force=True, silent=True) or {}
    sensor_id = data.get('id')

    name = (data.get('name') or 'Suricata Sensor').strip()[:128]
    host = (data.get('host') or '').strip()[:256]
    user = (data.get('user') or '').strip()[:64]
    log_dir = (data.get('log_dir') or '/var/log/suricata').strip()[:512]
    enabled = bool(data.get('enabled', True))
    ingest_interval_seconds = int(data.get('ingest_interval_seconds') or 30)
    ingest_interval_seconds = max(5, min(3600, ingest_interval_seconds))
    ssh_key_id = data.get('ssh_key_id')
    ssh_key_id = int(ssh_key_id) if str(ssh_key_id).isdigit() else None

    if not host or not user:
        return jsonify({'error': 'host and user are required'}), 400

    if sensor_id:
        sensor = SuricataSensor.query.get(int(sensor_id))
        if not sensor:
            return jsonify({'error': 'sensor not found'}), 404
    else:
        # If the UI didn't send an id, update the most recent sensor (single-sensor UX)
        sensor = SuricataSensor.query.order_by(SuricataSensor.updated_at.desc(), SuricataSensor.id.desc()).first()
        if not sensor:
            sensor = SuricataSensor()
            db.session.add(sensor)

    sensor.name = name
    sensor.host = host
    sensor.user = user
    sensor.log_dir = log_dir
    sensor.enabled = enabled
    sensor.ingest_interval_seconds = ingest_interval_seconds
    sensor.ssh_key_id = ssh_key_id

    db.session.commit()

    return jsonify(sensor.to_dict())


@app.route('/suricata/test', methods=['POST'])
def suricata_test():
    data = request.get_json(force=True, silent=True) or {}
    host = (data.get('host') or '').strip()
    user = (data.get('user') or '').strip()
    log_dir = (data.get('log_dir') or '/var/log/suricata').strip()
    ssh_key_id = data.get('ssh_key_id')
    ssh_key_id = int(ssh_key_id) if str(ssh_key_id).isdigit() else None

    if not host or not user:
        return jsonify({'error': 'host and user are required'}), 400

    ssh_key_path = None
    with app.app_context():
        ssh_key_path = _suricata_get_ssh_key_path(ssh_key_id)

    conn = test_ssh_connection(user, host, ssh_key_path, timeout=8)
    if conn.get('status') != 'success':
        return jsonify({'ok': False, 'connection': conn}), 200

    # Check directory listing
    ok, out = _suricata_remote_cmd(user, host, f"sudo ls -1 {shlex.quote(log_dir)}", ssh_key_path, timeout=20)
    dir_ok = bool(ok)

    files = {}
    for fn in SURICATA_ALLOWED_FILES:
        full = log_dir.rstrip('/') + '/' + fn
        stat = _suricata_remote_stat(user, host, ssh_key_path, full)
        files[fn] = stat

    return jsonify({
        'ok': True,
        'connection': conn,
        'dir_ok': dir_ok,
        'dir_list': out.splitlines()[:200] if ok else out.strip()[:200],
        'files': files,
    })


@app.route('/suricata/ingest/run_once', methods=['POST'])
def suricata_ingest_run_once():
    data = request.get_json(force=True, silent=True) or {}
    sensor_id = data.get('sensor_id')
    bucket_size = int(data.get('bucket_size') or 60)
    bucket_size = max(60, min(3600, bucket_size))

    with app.app_context():
        if sensor_id:
            sensor = SuricataSensor.query.get(int(sensor_id))
            if not sensor:
                return jsonify({'error': 'sensor not found'}), 404
            res = suricata_ingest_sensor(sensor, bucket_size=bucket_size)
            return jsonify(res)
        else:
            return jsonify({'results': suricata_ingest_all_enabled()})


@app.route('/suricata/stats', methods=['GET'])
def suricata_stats():
    sensor_id = request.args.get('sensor_id', type=int)
    range_key = (request.args.get('range') or '24h').strip()
    if range_key not in ('1h', '6h', '24h', '7d'):
        range_key = '24h'

    seconds = {'1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800}[range_key]
    now = int(time.time())
    start = now - seconds

    with app.app_context():
        if sensor_id:
            sensor = SuricataSensor.query.get(int(sensor_id))
        else:
            sensor = SuricataSensor.query.order_by(SuricataSensor.id.asc()).first()
        if not sensor:
            return jsonify({'error': 'no sensor configured'}), 400

        # Alerts time series (prefer eve buckets, fallback to fast buckets)
        eve_series = db.session.query(SuricataAlertBucket.bucket_ts, sql_text('sum(count) as c'))\
            .filter(SuricataAlertBucket.sensor_id == sensor.id, SuricataAlertBucket.bucket_ts >= start)\
            .group_by(SuricataAlertBucket.bucket_ts)\
            .order_by(SuricataAlertBucket.bucket_ts.asc()).all()

        fast_series = db.session.query(SuricataFastAlertBucket.bucket_ts, sql_text('sum(count) as c'))\
            .filter(SuricataFastAlertBucket.sensor_id == sensor.id, SuricataFastAlertBucket.bucket_ts >= start)\
            .group_by(SuricataFastAlertBucket.bucket_ts)\
            .order_by(SuricataFastAlertBucket.bucket_ts.asc()).all()

        series = eve_series if eve_series else fast_series
        alerts_timeseries = [{'ts': int(ts), 'alerts': int(c)} for (ts, c) in series]

        total_alerts = sum(p['alerts'] for p in alerts_timeseries)
        alerts_per_hour = (total_alerts / (seconds / 3600)) if seconds else 0

        # Top signatures
        top = db.session.query(SuricataAlertBucket.signature, sql_text('sum(count) as c'))\
            .filter(SuricataAlertBucket.sensor_id == sensor.id, SuricataAlertBucket.bucket_ts >= start)\
            .group_by(SuricataAlertBucket.signature)\
            .order_by(sql_text('c desc')).limit(10).all()
        top_signatures = [{'signature': (sig or 'unknown'), 'count': int(c)} for (sig, c) in top]

        # Pie by category
        cat = db.session.query(SuricataAlertBucket.category, sql_text('sum(count) as c'))\
            .filter(SuricataAlertBucket.sensor_id == sensor.id, SuricataAlertBucket.bucket_ts >= start)\
            .group_by(SuricataAlertBucket.category)\
            .order_by(sql_text('c desc')).limit(8).all()
        pie_categories = [{'category': (categ or 'unknown'), 'count': int(c)} for (categ, c) in cat]

        # Selected stats counters timeseries
        counters = ['decoder.pkts', 'decoder.bytes', 'capture.kernel_drops', 'tcp.reassembly_gap', 'detect.alert']
        counter_series = {}
        for cn in counters:
            rows = db.session.query(SuricataStatsCounterBucket.bucket_ts, SuricataStatsCounterBucket.value)\
                .filter(SuricataStatsCounterBucket.sensor_id == sensor.id, SuricataStatsCounterBucket.bucket_ts >= start, SuricataStatsCounterBucket.counter == cn)\
                .order_by(SuricataStatsCounterBucket.bucket_ts.asc()).all()
            counter_series[cn] = [{'ts': int(ts), 'value': int(v)} for (ts, v) in rows]

        # KPIs (simple v1)
        kpis = {
            'total_alerts': int(total_alerts),
            'alerts_per_hour': float(alerts_per_hour),
        }

        return jsonify({
            'sensor': sensor.to_dict(),
            'range': range_key,
            'kpis': kpis,
            'alerts_timeseries': alerts_timeseries,
            'top_signatures': top_signatures,
            'pie_categories': pie_categories,
            'counter_series': counter_series,
            # Back-compat keys used by older frontend code
            'alerts_series': alerts_timeseries,
            'fast_alerts_series': [],
            'stats_series': counter_series,
        })


# --- NEW WIZARD & SSH KEY MANAGEMENT ENDPOINTS ---

@app.route('/suricata/endpoints', methods=['GET'])
def suricata_endpoints():
    """Return a simple endpoint summary by parsing recent fast.log + eve.json (alerts only)."""
    sensor_id = request.args.get('sensor_id', type=int)
    range_key = (request.args.get('range') or '24h').strip()
    if range_key not in ('1h', '6h', '24h', '7d'):
        range_key = '24h'

    with app.app_context():
        if sensor_id:
            sensor = SuricataSensor.query.get(int(sensor_id))
        else:
            sensor = SuricataSensor.query.order_by(SuricataSensor.id.asc()).first()
        if not sensor:
            return jsonify({'error': 'no sensor configured'}), 400

        ssh_key_path = _suricata_get_ssh_key_path(sensor.ssh_key_id)
        base = sensor.log_dir.rstrip('/')

        # Read recent lines (simple + fast). For deep history, use the DB buckets instead.
        ok_fast, fast_txt = _suricata_remote_cmd(sensor.user, sensor.host, f"sudo tail -n 5000 {shlex.quote(base + '/fast.log')} 2>/dev/null", ssh_key_path, timeout=30)
        ok_eve, eve_txt = _suricata_remote_cmd(sensor.user, sensor.host, f"sudo tail -n 5000 {shlex.quote(base + '/eve.json')} 2>/dev/null", ssh_key_path, timeout=30)

        endpoints = {}

        # Parse fast.log endpoints
        fast_rx = re.compile(r'^(?P<ts>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+).*?\{(?P<proto>\w+)\}\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+)\s+->\s+(?P<dst_ip>\d+\.\d+\.\d+\.\d+):(?P<dst_port>\d+)')
        if ok_fast:
            for line in (fast_txt or '').splitlines():
                m = fast_rx.match(line)
                if not m:
                    continue
                dst = m.group('dst_ip')
                proto = m.group('proto')
                key = f"{dst}"
                ent = endpoints.setdefault(key, {'endpoint': key, 'alerts': 0, 'protocols': {}, 'sources': {}})
                ent['alerts'] += 1
                ent['protocols'][proto] = ent['protocols'].get(proto, 0) + 1
                src = m.group('src_ip')
                ent['sources'][src] = ent['sources'].get(src, 0) + 1

        # Parse eve.json alerts endpoints
        if ok_eve:
            for line in (eve_txt or '').splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                if obj.get('event_type') != 'alert':
                    continue
                dst = obj.get('dest_ip')
                src = obj.get('src_ip')
                proto = obj.get('proto') or obj.get('app_proto') or 'unknown'
                if not dst:
                    continue
                key = f"{dst}"
                ent = endpoints.setdefault(key, {'endpoint': key, 'alerts': 0, 'protocols': {}, 'sources': {}})
                ent['alerts'] += 1
                ent['protocols'][proto] = ent['protocols'].get(proto, 0) + 1
                if src:
                    ent['sources'][src] = ent['sources'].get(src, 0) + 1

        # Shape response: top protocols/sources
        out = []
        for ent in endpoints.values():
            top_protos = sorted(ent['protocols'].items(), key=lambda x: x[1], reverse=True)[:5]
            top_src = sorted(ent['sources'].items(), key=lambda x: x[1], reverse=True)[:5]
            out.append({
                'endpoint': ent['endpoint'],
                'alerts': ent['alerts'],
                'top_protocols': [{'name': n, 'count': c} for (n, c) in top_protos],
                'top_sources': [{'ip': n, 'count': c} for (n, c) in top_src],
            })

        out.sort(key=lambda x: x['alerts'], reverse=True)
        return jsonify({'sensor': sensor.to_dict(), 'range': range_key, 'endpoints': out[:200]})



@app.route('/suricata/endpoint_stats', methods=['GET'])
def suricata_endpoint_stats():
    """DB-backed endpoint/port/source aggregates for the Endpoint Stats dashboard."""
    sensor_id = request.args.get('sensor_id', type=int)
    range_key = (request.args.get('range') or '24h').strip()
    if range_key not in ('1h', '6h', '24h', '7d'):
        range_key = '24h'
    seconds = {'1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800}[range_key]
    now = int(time.time())
    start_ts = now - seconds

    with app.app_context():
        if sensor_id:
            sensor = SuricataSensor.query.get(int(sensor_id))
        else:
            sensor = SuricataSensor.query.order_by(SuricataSensor.updated_at.desc(), SuricataSensor.id.desc()).first()
        if not sensor:
            return jsonify({'error': 'no sensor configured'}), 400

        try:
            have = db.session.query(sql_text('count(1)')).select_from(SuricataFastAlertBucket)                .filter(SuricataFastAlertBucket.sensor_id == sensor.id, SuricataFastAlertBucket.bucket_ts >= start_ts, SuricataFastAlertBucket.dst_ip.isnot(None)).scalar()
        except Exception:
            have = 0

        if not have:
            base = suricata_endpoints()
            try:
                payload = base.get_json()
            except Exception:
                payload = {'endpoints': []}
            eps = payload.get('endpoints') or []
            return jsonify({
                'sensor': sensor.to_dict(),
                'range': range_key,
                'total_endpoints': len({e.get('endpoint') for e in eps if e.get('endpoint')}),
                'alerts_by_endpoint': eps
            })

        rows = db.session.query(SuricataFastAlertBucket.dst_ip, sql_text('sum(count) as c'))            .filter(SuricataFastAlertBucket.sensor_id == sensor.id, SuricataFastAlertBucket.bucket_ts >= start_ts, SuricataFastAlertBucket.dst_ip.isnot(None))            .group_by(SuricataFastAlertBucket.dst_ip)            .order_by(sql_text('c desc')).limit(500).all()
        alerts_by_endpoint = [{'endpoint': ip, 'alerts': int(c)} for (ip, c) in rows if ip]

        port_rows = db.session.query(SuricataFastAlertBucket.dst_port, sql_text('sum(count) as c'))            .filter(SuricataFastAlertBucket.sensor_id == sensor.id, SuricataFastAlertBucket.bucket_ts >= start_ts, SuricataFastAlertBucket.dst_port.isnot(None))            .group_by(SuricataFastAlertBucket.dst_port)            .order_by(sql_text('c desc')).limit(200).all()
        alerts_by_port = [{'port': int(p), 'alerts': int(c)} for (p, c) in port_rows if p is not None]

        # If ports/sources are missing (older ingests before we stored dst_port/src_ip), derive them from a recent fast.log tail.
        if not alerts_by_port:
            try:
                ssh_key_path = _suricata_get_ssh_key_path(sensor.ssh_key_id)
                base_dir = sensor.log_dir.rstrip('/')
                ok_fast, fast_txt = _suricata_remote_cmd(sensor.user, sensor.host, f"sudo tail -n 20000 {shlex.quote(base_dir + '/fast.log')} 2>/dev/null", ssh_key_path, timeout=30)
                if ok_fast:
                    fast_rx = re.compile(r'^(?P<ts>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+).*?\{(?P<proto>\w+)\}\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+)\s+->\s+(?P<dst_ip>\d+\.\d+\.\d+\.\d+):(?P<dst_port>\d+)')
                    port_counts = {}
                    ep_counts = {}
                    src_by_ep = {}
                    matrix_counts = {}
                    for line in (fast_txt or '').splitlines():
                        m = fast_rx.match(line)
                        if not m:
                            continue
                        ep = m.group('dst_ip')
                        dp = int(m.group('dst_port'))
                        sp = m.group('src_ip')
                        ep_counts[ep] = ep_counts.get(ep, 0) + 1
                        port_counts[dp] = port_counts.get(dp, 0) + 1
                        src_by_ep.setdefault(ep, {})[sp] = src_by_ep[ep].get(sp, 0) + 1
                        key = (ep, dp)
                        matrix_counts[key] = matrix_counts.get(key, 0) + 1

                    if ep_counts:
                        # override alerts_by_endpoint only if DB seems empty-ish
                        if not alerts_by_endpoint:
                            alerts_by_endpoint = [{'endpoint': k, 'alerts': v} for k,v in sorted(ep_counts.items(), key=lambda x: x[1], reverse=True)]
                        alerts_by_port = [{'port': int(k), 'alerts': int(v)} for k,v in sorted(port_counts.items(), key=lambda x: x[1], reverse=True)]

                        top_eps = [e['endpoint'] for e in alerts_by_endpoint[:12]]
                        top_ports = [p['port'] for p in alerts_by_port[:8]]
                        matrix = [{'endpoint': ep, 'port': int(port), 'alerts': int(c)} for (ep, port), c in matrix_counts.items() if ep in top_eps and port in top_ports]

                        top_sources = []
                        for ep in top_eps[:5]:
                            srcs = sorted((src_by_ep.get(ep) or {}).items(), key=lambda x: x[1], reverse=True)[:5]
                            top_sources.append({'endpoint': ep, 'sources': [{'ip': s, 'count': int(c)} for s,c in srcs]})
            except Exception:
                pass

        top_eps = [e['endpoint'] for e in alerts_by_endpoint[:12]]
        top_ports = [p['port'] for p in alerts_by_port[:8]]
        matrix = []
        if top_eps and top_ports:
            mrows = db.session.query(SuricataFastAlertBucket.dst_ip, SuricataFastAlertBucket.dst_port, sql_text('sum(count) as c'))                .filter(SuricataFastAlertBucket.sensor_id == sensor.id, SuricataFastAlertBucket.bucket_ts >= start_ts, SuricataFastAlertBucket.dst_ip.in_(top_eps), SuricataFastAlertBucket.dst_port.in_(top_ports))                .group_by(SuricataFastAlertBucket.dst_ip, SuricataFastAlertBucket.dst_port).all()
            matrix = [{'endpoint': ip, 'port': int(port), 'alerts': int(c)} for (ip, port, c) in mrows]

        src_rows = db.session.query(SuricataFastAlertBucket.dst_ip, SuricataFastAlertBucket.src_ip, sql_text('sum(count) as c'))            .filter(SuricataFastAlertBucket.sensor_id == sensor.id, SuricataFastAlertBucket.bucket_ts >= start_ts, SuricataFastAlertBucket.dst_ip.isnot(None), SuricataFastAlertBucket.src_ip.isnot(None))            .group_by(SuricataFastAlertBucket.dst_ip, SuricataFastAlertBucket.src_ip)            .order_by(sql_text('c desc')).limit(2000).all()
        top_sources_by_endpoint = {}
        for dst, src, c in src_rows:
            if not dst or not src:
                continue
            top_sources_by_endpoint.setdefault(dst, []).append({'ip': src, 'count': int(c)})

        top_sources = []
        for ep in top_eps[:5]:
            srcs = sorted(top_sources_by_endpoint.get(ep, []), key=lambda x: x['count'], reverse=True)[:5]
            top_sources.append({'endpoint': ep, 'sources': srcs})

        return jsonify({
            'sensor': sensor.to_dict(),
            'range': range_key,
            'total_endpoints': int(len(alerts_by_endpoint)),
            'alerts_by_endpoint': alerts_by_endpoint,
            'alerts_by_port': alerts_by_port,
            'endpoint_port_matrix': matrix,
            'top_sources': top_sources
        })
@app.route('/suricata/raw', methods=['POST'])
def suricata_raw():
    """Return raw tail output from a Suricata log file (optionally filtered by query)."""
    data = request.get_json(force=True, silent=True) or {}
    sensor_id = data.get('sensor_id')
    filename = (data.get('filename') or 'suricata.log').strip()
    query = (data.get('query') or '').strip()
    max_lines = int(data.get('max_lines') or 500)
    max_lines = max(10, min(5000, max_lines))

    if filename not in SURICATA_ALLOWED_FILES:
        return jsonify({'error': 'invalid filename'}), 400

    with app.app_context():
        if sensor_id:
            sensor = SuricataSensor.query.get(int(sensor_id))
        else:
            sensor = SuricataSensor.query.order_by(SuricataSensor.id.asc()).first()
        if not sensor:
            return jsonify({'error': 'no sensor configured'}), 400

        ssh_key_path = _suricata_get_ssh_key_path(sensor.ssh_key_id)
        full = sensor.log_dir.rstrip('/') + '/' + filename

        base_cmd = f"sudo tail -n {max_lines} {shlex.quote(full)} 2>/dev/null"
        if query:
            # Basic literal filter (case-insensitive). Avoid regex surprises.
            base_cmd = base_cmd + f" | grep -i -F -- {shlex.quote(query)} || true"

        ok, out = _suricata_remote_cmd(sensor.user, sensor.host, base_cmd, ssh_key_path, timeout=30)
        if not ok:
            return jsonify({'error': (out or '').strip()[:200]}), 500

        return jsonify({'sensor': sensor.to_dict(), 'filename': filename, 'query': query, 'content': out})


@app.route('/ssh-keys', methods=['GET'])
def get_ssh_keys():
    """Get list of stored SSH keys with verification status"""
    try:
        keys = SSHKey.query.all()
        results = []
        for key in keys:
            key_dict = key.to_dict()
            
            # Add integrity status
            plaintext = _sshkey_plaintext_from_model(key)
            if key.key_checksum and plaintext:
                if verify_key_checksum(plaintext, key.key_checksum):
                    key_dict['integrity_status'] = 'verified'
                else:
                    key_dict['integrity_status'] = 'corrupted'
            else:
                key_dict['integrity_status'] = 'unknown'
            
            results.append(key_dict)
        
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/settings/sshkey-encryption/status', methods=['GET'])
def sshkey_encryption_status():
    """Return whether SSH key encryption is configured."""
    return jsonify({'configured': bool(sshkey_crypto_configured()), 'env_var': 'AILOG_SSHKEY_MASTER_KEY'})

@app.route('/settings/sshkey-encryption/generate', methods=['POST'])
def sshkey_encryption_generate():
    """Generate a new master key (not persisted)."""
    try:
        key = generate_master_key()
        return jsonify({'master_key': key, 'env_var': 'AILOG_SSHKEY_MASTER_KEY'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/settings/sshkey-encryption/validate', methods=['POST'])
def sshkey_encryption_validate():
    """Validate that a provided master key (or env var) can encrypt/decrypt."""
    data = request.get_json(silent=True) or {}
    key = (data.get('master_key') or '').strip() or None
    try:
        test_pt = 'ailog-sshkey-test'
        tok = encrypt_str(test_pt, explicit_key=key)
        pt = decrypt_str(tok, explicit_key=key)
        if pt != test_pt:
            return jsonify({'valid': False, 'error': 'roundtrip mismatch'}), 400
        return jsonify({'valid': True})
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)}), 400

@app.route('/ssh-keys/upload', methods=['POST'])
def upload_ssh_key():
    """Upload SSH key from file"""
    try:
        key_name = request.form.get('key_name')
        print(f"[ssh-keys/upload] key_name={key_name!r}", flush=True)
        uploaded_file = request.files.get('key_file')
        
        if not key_name or not uploaded_file:
            return jsonify({'error': 'key_name and key_file required'}), 400
        
        existing = SSHKey.query.filter_by(key_name=key_name).first()
        if existing:
            return jsonify({'error': 'Key with this name already exists'}), 400
        
        key_content = uploaded_file.read().decode('utf-8')
        key_content = key_content.strip()
        if not key_content:
            return jsonify({'error': 'Empty key file'}), 400
        if not sshkey_crypto_configured():
            return jsonify({'error': 'SSH key encryption not configured (set AILOG_SSHKEY_MASTER_KEY)'}), 500
        enc = encrypt_str(key_content)
        
        ssh_key = SSHKey(
            key_name=key_name,
            key_type='file',
            is_encrypted=True,
            enc_version='fernet-v1',
            key_content=enc
        )
        db.session.add(ssh_key)
        db.session.commit()
        
        return jsonify({'message': 'SSH key uploaded', 'id': ssh_key.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/ssh-keys/save', methods=['POST'])
def save_ssh_key():
    """Save SSH key from pasted content"""
    try:
        data = request.get_json()
        try:
            pass
        except Exception:
            pass
        key_name = (data.get('key_name') or '').strip()
        key_content = data.get('key_content') or ''
        # Only strip leading/trailing whitespace, but preserve internal newlines
        key_content = key_content.strip()
        print(f"[ssh-keys/save] key_name={key_name!r} bytes={len(key_content)}", flush=True)
        print(f"[ssh-keys/save] key_content repr (first 100): {repr(key_content[:100])}", flush=True)
        print(f"[ssh-keys/save] key_content repr (last 100): {repr(key_content[-100:])}", flush=True)
        
        if not key_name or not key_content:
            return jsonify({'error': 'key_name and key_content required'}), 400

        if 'BEGIN' not in key_content or 'KEY' not in key_content or 'END' not in key_content:
            return jsonify({'error': 'Key content does not look like a private key'}), 400
        
        # Check if key is passphrase-protected
        if 'ENCRYPTED' in key_content:
            return jsonify({'error': 'SSH key is passphrase-protected. Please decrypt it first before uploading. SSH cannot use encrypted keys in batch mode.'}), 400
        
        if not sshkey_crypto_configured():
            return jsonify({'error': 'SSH key encryption not configured (set AILOG_SSHKEY_MASTER_KEY)'}), 500
        
        # Compute checksum of plaintext before encryption
        checksum = compute_key_checksum(key_content)
        print(f"[ssh-keys/save] Computed checksum: {checksum}", flush=True)
        
        enc = encrypt_str(key_content)
        
        existing = SSHKey.query.filter_by(key_name=key_name).first()
        if existing:
            return jsonify({'error': 'Key with this name already exists'}), 400
        
        ssh_key = SSHKey(
            key_name=key_name,
            key_type='pasted',
            is_encrypted=True,
            enc_version='fernet-v1',
            key_content=enc,
            key_checksum=checksum
        )
        db.session.add(ssh_key)
        db.session.commit()
        
        return jsonify({'message': 'SSH key saved', 'id': ssh_key.id, 'checksum': checksum}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/ssh-keys/<int:key_id>', methods=['GET'])
def get_ssh_key(key_id):
    """Get a specific SSH key metadata"""
    try:
        key = SSHKey.query.get(key_id)
        if not key:
            return jsonify({'error': 'Key not found'}), 404
        return jsonify(key.to_dict())
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/ssh-keys/<int:key_id>', methods=['DELETE'])
def delete_ssh_key(key_id):
    """Delete an SSH key"""
    try:
        key = SSHKey.query.get(key_id)
        if not key:
            return jsonify({'error': 'Key not found'}), 404
        
        # Check if key is in use by any hosts
        hosts_using_key = Host.query.filter_by(ssh_key_id=key_id).all()
        if hosts_using_key:
            host_names = ', '.join([h.friendly_name or h.hostname or h.ip_address for h in hosts_using_key])
            return jsonify({
                'error': f'Key is in use by hosts: {host_names}',
                'in_use_by': [h.id for h in hosts_using_key]
            }), 409
        
        db.session.delete(key)
        db.session.commit()
        
        # Clean up cached decrypted key file
        if key_id in _ssh_key_file_cache:
            try:
                os.unlink(_ssh_key_file_cache[key_id])
            except:
                pass
            del _ssh_key_file_cache[key_id]
        
        return jsonify({'message': f'Key {key_id} deleted'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/ssh-keys/<int:key_id>/test-decrypt', methods=['GET'])
def test_decrypt_ssh_key(key_id):
    """Test decryption of an SSH key (for debugging)"""
    try:
        key = SSHKey.query.get(key_id)
        if not key:
            return jsonify({'error': 'Key not found'}), 404
        
        # Try to decrypt
        plaintext = _sshkey_plaintext_from_model(key)
        
        # Check validity
        checks = {
            'has_content': len(plaintext) > 0,
            'starts_with_begin': plaintext.lstrip().startswith('BEGIN'),
            'ends_with_end': plaintext.strip().endswith('END'),
            'is_valid_pem': 'BEGIN' in plaintext and 'END' in plaintext
        }
        
        return jsonify({
            'key_id': key_id,
            'key_name': key.key_name,
            'is_encrypted': key.is_encrypted,
            'encrypted_bytes': len(key.key_content),
            'decrypted_bytes': len(plaintext),
            'validation_checks': checks,
            'plaintext_preview': plaintext[:200] + '...' if len(plaintext) > 200 else plaintext
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/wizard/validate-hosts', methods=['POST'])
def validate_hosts():
    """Validate SSH connectivity for multiple hosts"""
    try:
        data = request.get_json()
        ips = data.get('ips', [])
        usernames = data.get('usernames', [])
        ssh_key_id = data.get('ssh_key_id')
        key_content = data.get('key_content')
        
        if not ips:
            return jsonify({'error': 'No IP addresses provided'}), 400
        
        ssh_key_path = None
        if ssh_key_id:
            ssh_key = SSHKey.query.get(ssh_key_id)
            if ssh_key:
                temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem')
                temp_file.write(_sshkey_plaintext_from_model(ssh_key))
                temp_file.close()
                os.chmod(temp_file.name, 0o600)
                ssh_key_path = temp_file.name
        elif key_content:
            temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem')
            temp_file.write(key_content)
            temp_file.close()
            os.chmod(temp_file.name, 0o600)
            ssh_key_path = temp_file.name
        
        results = []
        for i, ip in enumerate(ips):
            if len(usernames) > i:
                user = usernames[i]
            elif usernames:
                user = usernames[0]
            else:
                user = 'root'
            
            result = test_ssh_connection(user, ip, ssh_key_path)
            results.append(result)
        
        if ssh_key_path and os.path.exists(ssh_key_path):
            try:
                os.unlink(ssh_key_path)
            except:
                pass
        
        return jsonify({
            'total': len(ips),
            'results': results,
            'successful': sum(1 for r in results if r['status'] == 'success')
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/wizard/collect-info', methods=['POST'])
def collect_host_info():
    """Collect system information from validated hosts"""
    try:
        data = request.get_json()
        ips = data.get('ips', [])
        usernames = data.get('usernames', [])
        ssh_key_id = data.get('ssh_key_id')
        key_content = data.get('key_content')
        
        if not ips:
            return jsonify({'error': 'No IP addresses provided'}), 400
        
        ssh_key_path = None
        if ssh_key_id:
            ssh_key = SSHKey.query.get(ssh_key_id)
            if ssh_key:
                temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem')
                temp_file.write(_sshkey_plaintext_from_model(ssh_key))
                temp_file.close()
                os.chmod(temp_file.name, 0o600)
                ssh_key_path = temp_file.name
        elif key_content:
            temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem')
            temp_file.write(key_content)
            temp_file.close()
            os.chmod(temp_file.name, 0o600)
            ssh_key_path = temp_file.name
        
        results = []
        for i, ip in enumerate(ips):
            if len(usernames) > i:
                user = usernames[i]
            elif usernames:
                user = usernames[0]
            else:
                user = 'root'
            
            info = {
                'ip': ip,
                'user': user,
                'system_info': collect_system_info(user, ip, ssh_key_path),
                'services': collect_services(user, ip, ssh_key_path)
            }
            results.append(info)
        
        if ssh_key_path and os.path.exists(ssh_key_path):
            try:
                os.unlink(ssh_key_path)
            except:
                pass
        
        return jsonify({
            'total': len(ips),
            'results': results
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/wizard/add-devices', methods=['POST'])
def add_devices_from_wizard():
    """Add multiple devices from wizard with collected info"""
    try:
        data = request.get_json() or {}
        devices = data.get('devices', []) or []
        ssh_key_id = data.get('ssh_key_id')
        
        if not devices:
            return jsonify({'error': 'No devices provided'}), 400
        
        added_hosts = []
        skipped_hosts = []
        
        # Use nested transactions (SAVEPOINT) so one failure doesn't rollback everything.
        for device in devices:
            ip = (device or {}).get('ip')
            if not ip:
                skipped_hosts.append({'ip': None, 'reason': 'missing ip'})
                continue
            
            # Skip duplicates by IP (common case when rerunning wizard)
            existing = Host.query.filter_by(ip_address=ip).first()
            if existing:
                skipped_hosts.append({'ip': ip, 'reason': 'already exists', 'existing_id': existing.id, 'hostname': existing.hostname})
                continue
            
            try:
                with db.session.begin_nested():
                    host = Host(
                        hostname=device.get('hostname', ip),
                        friendly_name=device.get('friendly_name', ip),
                        ip_address=ip,
                        ssh_user=device.get('user', 'root'),
                        ssh_key_id=ssh_key_id,
                        description=device.get('description', ''),
                        status='online'
                    )
                    db.session.add(host)
                    db.session.flush()
                    
                    if device.get('system_info'):
                        sys_info = device['system_info']
                        system_info = SystemInfo(
                            host_id=host.id,
                            os_version=sys_info.get('os_version'),
                            hostname=sys_info.get('hostname'),
                            ram_total=sys_info.get('ram_total'),
                            ram_used=sys_info.get('ram_used'),
                            disk_total=sys_info.get('disk_total'),
                            disk_used=sys_info.get('disk_used'),
                            cpu_type=sys_info.get('cpu_type'),
                            cpu_cores=sys_info.get('cpu_cores'),
                            netbird_ip=sys_info.get('netbird_ip'),
                            main_ip=sys_info.get('main_ip')
                        )
                        db.session.add(system_info)
                    
                    if device.get('services'):
                        for svc in device['services']:
                            service = Service(
                                host_id=host.id,
                                service_name=svc.get('service_name'),
                                status=svc.get('status'),
                                is_running=svc.get('is_running', False)
                            )
                            db.session.add(service)
                    
                    log_content = f"Host onboarded from wizard\nIP: {ip}\nUser: {device.get('user')}\nSystem Info collected: {bool(device.get('system_info'))}"
                    host_log = HostLog(
                        host_id=host.id,
                        log_content=log_content,
                        log_type='setup'
                    )
                    db.session.add(host_log)
                    
                    added_hosts.append({'id': host.id, 'hostname': host.hostname, 'ip': host.ip_address})
            except IntegrityError as e:
                skipped_hosts.append({'ip': ip, 'reason': 'integrity error'})
                continue
            except Exception as e:
                skipped_hosts.append({'ip': ip, 'reason': str(e)[:200]})
                continue
        
        db.session.commit()
        return jsonify({
            'message': f'Added {len(added_hosts)} devices ({len(skipped_hosts)} skipped)',
            # Back-compat: keep 'devices' as the added devices list
            'devices': added_hosts,
            'skipped': skipped_hosts,
            'counts': {'added': len(added_hosts), 'skipped': len(skipped_hosts), 'total': len(devices)},
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/hosts/db/<int:host_id>/info', methods=['GET'])
def get_host_info(host_id):
    """Return detailed host info including system info and services."""
    try:
        from database import Host, SystemInfo, Service
        host = Host.query.get(host_id)
        if not host:
            return jsonify({'error': 'Host not found'}), 404

        host_dict = host.to_dict()  # already nests system_info and groups/tags

        # Add services with simple summary
        services = Service.query.filter_by(host_id=host_id).all()
        services_list = [s.to_dict() for s in services]
        running = [s for s in services_list if s.get('status') == 'active' or s.get('is_running')]
        stopped = [s for s in services_list if s.get('status') not in ('active',) and not s.get('is_running')]

        host_dict['services'] = services_list
        host_dict['services_summary'] = {
            'total': len(services_list),
            'running': len(running),
            'stopped': len(stopped)
        }

        return jsonify(host_dict)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/hosts/db/<int:host_id>/rescan', methods=['POST'])
def rescan_host(host_id):
    '''Re-scan a DB host to refresh system info (including wt0 netbird IP) and services.'''
    try:
        host = Host.query.get(host_id)
        if not host:
            return jsonify({'error': 'Host not found'}), 404

        user = host.ssh_user
        ip = host.ip_address

        # IMPORTANT: ssh_keys.key_content is stored encrypted. Use the materializer which decrypts
        # and writes a proper private key file.
        ssh_key_path = _materialize_ssh_key_path(host.ssh_key_id)

        sys_info = collect_system_info(user, ip, ssh_key_path)
        services = collect_services(user, ip, ssh_key_path)

        # Update host status
        host.status = 'online'
        host.last_seen = datetime.datetime.utcnow()

        # Upsert SystemInfo
        si = SystemInfo.query.filter_by(host_id=host_id).order_by(SystemInfo.captured_at.desc()).first()
        if not si:
            si = SystemInfo(host_id=host_id)
            db.session.add(si)

        si.os_version = sys_info.get('os_version')
        si.hostname = sys_info.get('hostname')
        si.ram_total = sys_info.get('ram_total')
        si.ram_used = sys_info.get('ram_used')
        si.disk_total = sys_info.get('disk_total')
        si.disk_used = sys_info.get('disk_used')
        si.cpu_type = sys_info.get('cpu_type')
        si.cpu_cores = sys_info.get('cpu_cores')
        si.main_ip = sys_info.get('main_ip')
        si.netbird_ip = sys_info.get('netbird_ip')
        si.last_update = datetime.datetime.utcnow()
        si.captured_at = datetime.datetime.utcnow()

        # Replace services snapshot
        Service.query.filter_by(host_id=host_id).delete()
        for svc in services or []:
            db.session.add(Service(
                host_id=host_id,
                service_name=svc.get('service_name'),
                status=svc.get('status'),
                is_running=bool(svc.get('is_running'))
            ))

        # Log
        db.session.add(HostLog(
            host_id=host_id,
            log_content=(
                "Host rescan completed\n"
                f"IP: {ip}\n"
                f"User: {user}\n"
                f"Main IP: {sys_info.get('main_ip')}\n"
                f"Netbird IP: {sys_info.get('netbird_ip')}\n"
                f"Services: {len(services or [])}"
            ),
            log_type='discovery'
        ))

        db.session.commit()

        # Return updated host info in same shape as /hosts/db/<id>/info
        host_dict = host.to_dict()
        services_list = [s.to_dict() for s in Service.query.filter_by(host_id=host_id).all()]
        running = [s for s in services_list if s.get('status') == 'active' or s.get('is_running')]
        stopped = [s for s in services_list if s.get('status') not in ('active',) and not s.get('is_running')]
        host_dict['services'] = services_list
        host_dict['services_summary'] = {
            'total': len(services_list),
            'running': len(running),
            'stopped': len(stopped)
        }

        return jsonify(host_dict)

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500



@app.route('/hosts/db/rescan-all', methods=['POST'])
def rescan_all_hosts():
    '''Re-scan all DB hosts to refresh system info (including wt0 netbird IP) and services.'''
    try:
        hosts = Host.query.all()
        results = []
        success_count = 0

        for host in hosts:
            user = host.ssh_user
            ip = host.ip_address
            # IMPORTANT: ssh_keys.key_content is stored encrypted. Use the materializer which decrypts
            # and writes a proper private key file.
            ssh_key_path = _materialize_ssh_key_path(host.ssh_key_id)

            try:
                sys_info = collect_system_info(user, ip, ssh_key_path)
                services = collect_services(user, ip, ssh_key_path)

                host.status = 'online'
                host.last_seen = datetime.datetime.utcnow()

                si = SystemInfo.query.filter_by(host_id=host.id).order_by(SystemInfo.captured_at.desc()).first()
                if not si:
                    si = SystemInfo(host_id=host.id)
                    db.session.add(si)

                si.os_version = sys_info.get('os_version')
                si.hostname = sys_info.get('hostname')
                si.ram_total = sys_info.get('ram_total')
                si.ram_used = sys_info.get('ram_used')
                si.disk_total = sys_info.get('disk_total')
                si.disk_used = sys_info.get('disk_used')
                si.cpu_type = sys_info.get('cpu_type')
                si.cpu_cores = sys_info.get('cpu_cores')
                si.main_ip = sys_info.get('main_ip')
                si.netbird_ip = sys_info.get('netbird_ip')
                si.last_update = datetime.datetime.utcnow()
                si.captured_at = datetime.datetime.utcnow()

                Service.query.filter_by(host_id=host.id).delete()
                for svc in services or []:
                    db.session.add(Service(
                        host_id=host.id,
                        service_name=svc.get('service_name'),
                        status=svc.get('status'),
                        is_running=bool(svc.get('is_running'))
                    ))

                db.session.add(HostLog(
                    host_id=host.id,
                    log_content=(
                        "Host rescan completed\n"
                        f"IP: {ip}\n"
                        f"User: {user}\n"
                        f"Main IP: {sys_info.get('main_ip')}\n"
                        f"Netbird IP: {sys_info.get('netbird_ip')}\n"
                        f"Services: {len(services or [])}"
                    ),
                    log_type='discovery'
                ))

                results.append({
                    'host_id': host.id,
                    'friendly_name': host.friendly_name,
                    'hostname': host.hostname,
                    'ip_address': host.ip_address,
                    'main_ip': sys_info.get('main_ip'),
                    'netbird_ip': sys_info.get('netbird_ip'),
                    'services_count': len(services or []),
                    'status': 'success'
                })
                success_count += 1

            except Exception as e:
                host.status = 'offline'
                results.append({
                    'host_id': host.id,
                    'friendly_name': host.friendly_name,
                    'hostname': host.hostname,
                    'ip_address': host.ip_address,
                    'status': 'error',
                    'error': str(e)
                })
            # Note: _materialize_ssh_key_path manages temp files and caching; nothing to clean up here.

        db.session.commit()
        return jsonify({
            'total': len(hosts),
            'successful': success_count,
            'failed': len(hosts) - success_count,
            'results': results
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
@app.route('/hosts/db', methods=['POST'])
def get_hosts_db():
    """Get all hosts from database"""
    try:
        hosts = Host.query.all()
        return jsonify([h.to_dict() for h in hosts])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/hosts/db/<int:host_id>', methods=['POST'])
def get_host_db(host_id):
    """Get specific host from database with all details"""
    try:
        host = Host.query.get(host_id)
        if not host:
            return jsonify({'error': 'Host not found'}), 404
        return jsonify(host.to_dict())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/groups', methods=['GET'])
def get_groups():
    """Get all groups"""
    try:
        groups = Group.query.all()
        return jsonify([g.to_dict() for g in groups])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/groups', methods=['POST'])
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



@app.route('/groups/<int:group_id>', methods=['PUT'])
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


@app.route('/groups/<int:group_id>', methods=['DELETE'])
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


@app.route('/groups/<int:group_id>/hosts', methods=['GET'])
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
@app.route('/tags', methods=['GET'])
def get_tags():
    """Get all tags"""
    try:
        tags = Tag.query.all()
        return jsonify([t.to_dict() for t in tags])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/tags', methods=['POST'])
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

@app.route('/hosts/db/<int:host_id>/groups', methods=['POST'])
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

@app.route('/hosts/db/<int:host_id>/tags', methods=['POST'])
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

@app.route('/export/ansible-inventory', methods=['POST'])
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

@app.route('/export/ssh-config', methods=['POST'])
def export_ssh_config():
    """Generate SSH config file"""
    try:
        hosts = Host.query.all()
        
        ssh_config = "# Auto-generated SSH config from AI Log Viewer\n"
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

def _get_sqlite_db_file_path():
    '''Return sqlite file path if DATABASE_URL is sqlite:////... else None.'''
    url = app.config.get('SQLALCHEMY_DATABASE_URI', '') or ''
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


@app.route('/admin/db/backup', methods=['GET'])
def backup_database():
    '''Download a copy of the current sqlite database.'''
    try:
        db_path = _get_sqlite_db_file_path()
        if not db_path:
            return jsonify({'error': 'Database backup only supported for sqlite'}), 400
        if not os.path.exists(db_path):
            return jsonify({'error': f'Database file not found: {db_path}'}), 404

        ts = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        filename = f"ailog-backup-{ts}.db"

        with open(db_path, 'rb') as f:
            data = f.read()

        return Response(
            data,
            mimetype='application/octet-stream',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin/db/restore', methods=['POST'])
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
            with open(tmp_path, 'rb') as fh:
                header = fh.read(16)
            if header != b'SQLite format 3\x00':
                return jsonify({'error': 'Uploaded file is not a valid sqlite database'}), 400

            os.makedirs(os.path.dirname(db_path) or '.', exist_ok=True)

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

        return jsonify({'message': 'Database restored successfully. Please refresh the page.'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# --- SERVER-SENT EVENTS (SSE) STREAMING ENDPOINTS ---

import uuid as uuid_lib
from threading import Lock

# Global dictionary to store event queues for each wizard session
wizard_sessions = {}
sessions_lock = Lock()



@app.route('/admin/db/restore-selective', methods=['POST'])
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
            with open(tmp_path, 'rb') as fh:
                header = fh.read(16)
            if header != b'SQLite format 3\x00':
                return jsonify({'error': 'Uploaded file is not a valid sqlite database'}), 400

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
                            _setting_set(r['key'], json.loads(r['value_json']) if r['value_json'] else None)
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
@app.route('/wizard/session/create', methods=['POST'])
def create_wizard_session():
    """Create a new wizard session ID for streaming"""
    session_id = str(uuid_lib.uuid4())
    with sessions_lock:
        wizard_sessions[session_id] = {
            'created_at': datetime.datetime.utcnow(),
            'status': 'active'
        }
    return jsonify({'session_id': session_id})

@app.route('/wizard/session/<session_id>/validate-hosts-stream', methods=['POST'])
def validate_hosts_stream(session_id):
    """Stream SSH validation progress via SSE"""
    # Read JSON body once so generator doesn't depend on request context
    data = request.get_json(silent=True) or {}
    ips = data.get('ips', []) or []
    usernames = data.get('usernames', []) or []
    ssh_key_id = data.get('ssh_key_id')
    key_content = data.get('key_content')

    @stream_with_context
    def generate():
        try:
            if not ips:
                yield "data: " + json.dumps({'error': 'No IP addresses provided'}) + "\n\n"
                return
            
            yield "data: " + json.dumps({'type': 'start', 'total': len(ips)}) + "\n\n"
            
            ssh_key_path = None
            if ssh_key_id:
                ssh_key = SSHKey.query.get(ssh_key_id)
                if ssh_key:
                    ssh_key_path = _write_temp_ssh_key_file(_sshkey_plaintext_from_model(ssh_key))
            elif key_content:
                ssh_key_path = _write_temp_ssh_key_file(key_content)
            
            results = []
            for i, ip in enumerate(ips):
                if len(usernames) > i:
                    user = usernames[i]
                elif usernames:
                    user = usernames[0]
                else:
                    user = 'root'
                
                timestamp = datetime.datetime.utcnow().isoformat()
                msg = {'type': 'progress', 'current': i, 'total': len(ips), 'message': 'Testing ' + ip + '...'}
                yield "data: " + json.dumps(msg) + "\n\n"
                
                result = test_ssh_connection(user, ip, ssh_key_path)
                results.append(result)
                debug_msg = result['message']
                if ssh_key_path:
                    debug_msg += f" (using key at {ssh_key_path}; key_id={ssh_key_id})"
                elif key_content:
                    debug_msg += f" (using inline key content, {len(key_content)} bytes)"
                else:
                    debug_msg += " (no key provided - using default SSH identities)"
                
                msg = {'type': 'result', 'ip': ip, 'user': user, 'status': result['status'], 'message': debug_msg, 'command': result.get('command'), 'details': result.get('details'), 'returncode': result.get('returncode'), 'timestamp': timestamp}
                yield "data: " + json.dumps(msg) + "\n\n"
            
            if ssh_key_path and os.path.exists(ssh_key_path):
                try:
                    os.unlink(ssh_key_path)
                except:
                    pass
            
            success_count = sum(1 for r in results if r['status'] == 'success')
            msg = {'type': 'complete', 'total': len(ips), 'successful': success_count, 'results': results}
            yield "data: " + json.dumps(msg) + "\n\n"
        
        except Exception as e:
            msg = {'type': 'error', 'error': str(e)}
            yield "data: " + json.dumps(msg) + "\n\n"
    
    return Response(generate(), mimetype='text/event-stream', headers={
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no'
    })

@app.route('/wizard/session/<session_id>/collect-info-stream', methods=['POST'])
def collect_info_stream(session_id):
    """Stream system information collection progress via SSE"""
    # Read JSON body once so generator doesn't depend on request context
    data = request.get_json(silent=True) or {}
    ips = data.get('ips', []) or []
    usernames = data.get('usernames', []) or []
    ssh_key_id = data.get('ssh_key_id')
    key_content = data.get('key_content')

    @stream_with_context
    def generate():
        try:
            if not ips:
                yield "data: " + json.dumps({'error': 'No IP addresses provided'}) + "\n\n"
                return
            
            yield "data: " + json.dumps({'type': 'start', 'total': len(ips)}) + "\n\n"
            
            ssh_key_path = None
            if ssh_key_id:
                ssh_key = SSHKey.query.get(ssh_key_id)
                if ssh_key:
                    ssh_key_path = _write_temp_ssh_key_file(_sshkey_plaintext_from_model(ssh_key))
            elif key_content:
                ssh_key_path = _write_temp_ssh_key_file(key_content)
            
            results = []
            for i, ip in enumerate(ips):
                if len(usernames) > i:
                    user = usernames[i]
                elif usernames:
                    user = usernames[0]
                else:
                    user = 'root'
                
                timestamp = datetime.datetime.utcnow().isoformat()
                msg = {'type': 'progress', 'current': i, 'total': len(ips), 'message': 'Collecting info from ' + ip + '...'}
                yield "data: " + json.dumps(msg) + "\n\n"
                
                sys_info = collect_system_info(user, ip, ssh_key_path)
                
                if sys_info.get('os_version'):
                    os_msg = sys_info['os_version'][:80]
                    msg = {'type': 'log', 'ip': ip, 'message': 'OS: ' + os_msg, 'timestamp': timestamp}
                    yield "data: " + json.dumps(msg) + "\n\n"
                
                if sys_info.get('ram_total'):
                    ram_gb = sys_info['ram_total'] / (1024**3)
                    ram_used_gb = sys_info.get('ram_used', 0) / (1024**3)
                    ram_msg = 'RAM: {:.1f}GB total, {:.1f}GB used'.format(ram_gb, ram_used_gb)
                    msg = {'type': 'log', 'ip': ip, 'message': ram_msg, 'timestamp': timestamp}
                    yield "data: " + json.dumps(msg) + "\n\n"
                
                if sys_info.get('disk_total'):
                    disk_gb = sys_info['disk_total'] / (1024**3)
                    disk_used_gb = sys_info.get('disk_used', 0) / (1024**3)
                    disk_msg = 'Disk: {:.1f}GB total, {:.1f}GB used'.format(disk_gb, disk_used_gb)
                    msg = {'type': 'log', 'ip': ip, 'message': disk_msg, 'timestamp': timestamp}
                    yield "data: " + json.dumps(msg) + "\n\n"
                
                if sys_info.get('cpu_type'):
                    cpu_msg = 'CPU: ' + sys_info['cpu_type']
                    msg = {'type': 'log', 'ip': ip, 'message': cpu_msg, 'timestamp': timestamp}
                    yield "data: " + json.dumps(msg) + "\n\n"
                
                services = collect_services(user, ip, ssh_key_path)
                running_count = sum(1 for s in services if s.get('is_running'))
                svc_msg = 'Services: {} total, {} running'.format(len(services), running_count)
                msg = {'type': 'log', 'ip': ip, 'message': svc_msg, 'timestamp': timestamp}
                yield "data: " + json.dumps(msg) + "\n\n"
                
                results.append({
                    'ip': ip,
                    'user': user,
                    'system_info': sys_info,
                    'services': services
                })
                
                msg = {'type': 'host_complete', 'ip': ip, 'current': i+1, 'total': len(ips)}
                yield "data: " + json.dumps(msg) + "\n\n"
            
            if ssh_key_path and os.path.exists(ssh_key_path):
                try:
                    os.unlink(ssh_key_path)
                except:
                    pass
            
            msg = {'type': 'complete', 'total': len(ips), 'results': results}
            yield "data: " + json.dumps(msg) + "\n\n"
        
        except Exception as e:
            msg = {'type': 'error', 'error': str(e)}
            yield "data: " + json.dumps(msg) + "\n\n"
    
    return Response(generate(), mimetype='text/event-stream', headers={
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no'
    })


# Debug endpoint to test SSE
@app.route('/wizard/test-sse')
def test_sse():
    """Simple test SSE endpoint"""
    def generate():
        yield "data: " + json.dumps({'type': 'test', 'message': 'Connected to SSE'}) + "\n\n"
        for i in range(3):
            yield "data: " + json.dumps({'type': 'count', 'number': i}) + "\n\n"
    
    return Response(generate(), mimetype='text/event-stream', headers={
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no'
    })

if __name__ == '__main__':
    # Initialize application
    initialize_app()
    
    # Start scheduler
    scheduler.start()
    startup_scheduler()
    atexit.register(lambda: scheduler.shutdown())
    
    # Start Flask app
    app.run(host='0.0.0.0', port=5001, debug=False)


@app.route('/ssh-keys/verify-integrity', methods=['GET'])
def verify_ssh_keys_integrity():
    """Verify integrity of all SSH keys by checking their checksums.
    Returns status for each key: verified, corrupted, or unknown (no checksum).
    """
    try:
        keys = SSHKey.query.all()
        results = []
        
        for key in keys:
            plaintext = _sshkey_plaintext_from_model(key)
            
            result = {
                'key_id': key.id,
                'key_name': key.key_name,
                'is_encrypted': key.is_encrypted,
                'has_checksum': bool(key.key_checksum),
                'status': 'unknown',  # unknown, verified, corrupted
                'decrypted_bytes': len(plaintext)
            }
            
            if key.key_checksum and plaintext:
                if verify_key_checksum(plaintext, key.key_checksum):
                    result['status'] = 'verified'
                else:
                    result['status'] = 'corrupted'
                    result['expected_checksum'] = key.key_checksum
                    result['actual_checksum'] = compute_key_checksum(plaintext)
            
            results.append(result)
        
        # Summary
        verified_count = sum(1 for r in results if r['status'] == 'verified')
        corrupted_count = sum(1 for r in results if r['status'] == 'corrupted')
        unknown_count = sum(1 for r in results if r['status'] == 'unknown')
        
        return jsonify({
            'keys': results,
            'summary': {
                'total': len(results),
                'verified': verified_count,
                'corrupted': corrupted_count,
                'unknown': unknown_count
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
