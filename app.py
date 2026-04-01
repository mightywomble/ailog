import subprocess
from flask import Flask, render_template, jsonify, request, Response, stream_with_context
import shlex
import os
import datetime
import openai
import requests
import json
import atexit
from apscheduler.schedulers.background import BackgroundScheduler
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from functools import lru_cache
import ast
import tempfile
from database import db, Host, SystemInfo, Service, HostLog, SSHKey, Group, Tag
from wizard_helpers import test_ssh_connection, collect_system_info, collect_services

# --- INITIALIZATION ---
app = Flask(__name__)

# --- DATABASE CONFIGURATION ---
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///ailog.db')
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Create database tables on startup
with app.app_context():
    db.create_all()

scheduler = BackgroundScheduler(daemon=True)

# --- CONFIGURATION ---
LOG_DIRECTORY = '/var/log'
MAX_CHAR_COUNT = 40000 
DISCORD_ALERT_KEYWORDS = ['error', 'issue', 'failed', 'warning', 'critical', 'exception', 'denied', 'unable']
CONFIG_FILE = 'scheduler_config.json'
HOSTS_FILE = 'hosts.json'

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

def get_ssh_prefix_args(user, ip):
    """Constructs the SSH command prefix as a list of arguments directly from inputs."""
    return [
        "ssh", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes", f"{user}@{ip}"
    ]

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
                        }
                except Exception as e:
                    print(f"[ERROR] Failed to resolve DB host '{hostname}': {e}")

        if not host_info:
            raise ValueError(f"Host ID '{hostname}' not found in configuration or database.")

        ssh_prefix_args = get_ssh_prefix_args(host_info['user'], host_info['ip'])

    cmd_list = ssh_prefix_args + [command_str] if ssh_prefix_args else [command_str]
    # Use shell=False for remote commands for security, shell=True for local for simplicity with sudo
    shell_mode = not bool(ssh_prefix_args)
    return subprocess.run(cmd_list, shell=shell_mode, capture_output=True, text=True, check=True, timeout=timeout)

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

def send_discord_notification(webhook_url, log_name, host_id, analysis_text):
    if not webhook_url: return
    headers = {'Content-Type': 'application/json'}
    
    # Retrieve the friendly name of the host
    hosts = load_hosts()
    host_info = hosts.get(host_id, {'friendly_name': host_id})
    friendly_name = host_info.get('friendly_name', host_id)
    
    discord_payload = {"embeds": [{"title": f"🚨 AI Alert for: {log_name} on {friendly_name}","description": analysis_text[:4000],"color": 15158332, "footer": { "text": "Log Viewer AI Analysis" },"timestamp": datetime.datetime.now().isoformat()}]}
    try:
        requests.post(webhook_url, data=json.dumps(discord_payload), headers=headers, timeout=10)
    except requests.exceptions.RequestException as e:
        print(f"Error sending Discord notification: {e}")

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
                    'source': 'db'
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
        ollama_url = config.get('ollama_url', '').strip()
    
    if not ollama_url:
        return jsonify({'error': 'Ollama URL not provided.'}), 400
    
    if not ollama_url.startswith('http'):
        ollama_url = f'http://{ollama_url}'
    
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
    
    truncated_content = log_content
    if len(log_content) > MAX_CHAR_COUNT:
        truncated_content = f"[--- Log truncated due to size limit... ---]\n" + log_content[-MAX_CHAR_COUNT:]
    
    prompt = f"Analyse this log for {log_name} for errors, create a summary report, and give troubleshooting tips.\n\n{truncated_content}"
    
    try:
        response = requests.post(
            f'{ollama_url}/api/generate',
            json={'model': ollama_model, 'prompt': prompt, 'stream': False},
            timeout=60
        )
        response.raise_for_status()
        result = response.json()
        return result.get('response', 'No response from Ollama')
    except Exception as e:
        raise Exception(f'Ollama analysis failed: {str(e)}')

# --- ANALYSIS & SCHEDULER ROUTES (RESTORED) ---
def save_config(config):
    with open(CONFIG_FILE, 'w') as f: json.dump(config, f, indent=4)
def load_config():
    if not os.path.exists(CONFIG_FILE): return {}
    with open(CONFIG_FILE, 'r') as f:
        try: return json.load(f)
        except json.JSONDecodeError: return {}

@app.route('/analyse', methods=['POST'])
def analyse_log():
    data = request.get_json()
    log_content = data.get('log_content')
    log_name = data.get('log_name')
    webhook_url = data.get('webhook_url')
    provider = data.get('provider', 'openai')  # 'openai' or 'ollama'
    
    if not log_content:
        return jsonify({'error': 'Missing log_content.'}), 400
    
    analysis = None
    
    try:
        if provider == 'ollama':
            # Use Ollama
            config = load_config()
            ollama_url = config.get('ollama_url')
            ollama_model = config.get('ollama_model')
            
            if not ollama_url or not ollama_model:
                return jsonify({'error': 'Ollama not configured. Please set up Ollama in Settings.'}), 400
            
            analysis = analyse_with_ollama(log_content, log_name, ollama_url, ollama_model)
        else:
            # Use OpenAI (default)
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
        
        # Check for alerts and send Discord notification if needed
        discord_sent = False
        if webhook_url and analysis and any(keyword in analysis.lower() for keyword in DISCORD_ALERT_KEYWORDS):
            send_discord_notification(webhook_url, log_name, 'local', analysis)
            discord_sent = True
        
        return jsonify({'analysis': analysis, 'discord_sent': discord_sent})
    except Exception as e:
        return jsonify({'error': f'An error occurred during AI Analysis: {str(e)}'}), 500

@app.route('/test_discord', methods=['POST'])
def test_discord():
    webhook_url = request.get_json().get('webhook_url')
    if not webhook_url: return jsonify({'error': 'Webhook URL is missing.'}), 400
    payload = json.dumps({'content': '✅ Test message from Log Viewer.'})
    try:
        response = requests.post(webhook_url, data=payload, headers={'Content-Type': 'application/json'}, timeout=5)
        response.raise_for_status()
        return jsonify({'message': 'Test message sent successfully!'})
    except requests.exceptions.RequestException as e: return jsonify({'error': f'Failed to send test message: {str(e)}'}), 500

def _do_analysis_task():
    print("--- Commencing scheduled log analysis task ---")
    config = load_config()
    webhook_url, sources = config.get('webhook_url'), config.get('sources', [])
    provider = config.get('analysis_provider', 'openai')  # Get configured provider
    
    if not all([webhook_url, sources]):
        print("Scheduled analysis aborted: Missing webhook URL or sources.")
        return
    
    # Validate provider is configured
    if provider == 'ollama':
        if not config.get('ollama_url') or not config.get('ollama_model'):
            print("Scheduled analysis aborted: Ollama not configured.")
            return
    else:
        if not config.get('api_key'):
            print("Scheduled analysis aborted: OpenAI API key not configured.")
            return
    
    for source in sources:
        log_name, log_type, host = source.get('name'), source.get('type'), source.get('host', 'local')
        print(f"Analyzing {log_type}: {log_name} on {host} using {provider}")
        try:
            command = f"sudo zcat {shlex.quote(os.path.join(LOG_DIRECTORY, log_name))} 2>/dev/null | tail -n 500" if log_name.endswith('.gz') else f"sudo tail -n 500 {shlex.quote(os.path.join(LOG_DIRECTORY, log_name))}"
            if log_type != 'file': command = f"sudo journalctl -u {shlex.quote(log_name)} -n 500 --no-pager"
            
            result = execute_command(host, command)
            log_content = result.stdout
            if not log_content: continue
            
            truncated_content = log_content
            if len(log_content) > MAX_CHAR_COUNT:
                truncated_content = f"[--- Log truncated... ---]\n" + log_content[-MAX_CHAR_COUNT:]

            # Use configured provider for analysis
            if provider == 'ollama':
                analysis = analyse_with_ollama(log_content, f"{log_name} on {host}", config.get('ollama_url'), config.get('ollama_model'))
            else:
                prompt = "Analyse this log for any errors and create a summary report, troubleshooting tips and any other advice relating to any other issues found."
                client = openai.OpenAI(api_key=config.get('api_key'))
                response = client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role": "system", "content": "You are a helpful assistant that analyses log files for potential issues."},
                        {"role": "user", "content": f"{prompt}\n\n--- LOG for {log_name} on {host} ---\n{truncated_content}"}
                    ]
                )
                analysis = response.choices[0].message.content
            
            if any(keyword in analysis.lower() for keyword in DISCORD_ALERT_KEYWORDS):
                print(f"Issue found in {log_name} on {host}. Sending alert to Discord.")
                send_discord_notification(webhook_url, log_name, host, analysis)
        except Exception as e:
            print(f"Error during scheduled analysis of {log_name} on {host}: {e}")

def perform_scheduled_analysis():
    config = load_config()
    if not config.get('is_running'):
        print("Scheduler is paused. Skipping scheduled run.")
        return
    _do_analysis_task()

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

@app.route('/schedule/status', methods=['POST'])
def schedule_status():
    config = load_config()
    job = scheduler.get_job('scheduled_analysis')
    status = {'is_running': False, 'sources': config.get('sources', []), 'interval': config.get('interval')}
    if job and config.get('is_running'):
        status.update({'is_running': True, 'next_run': job.next_run_time.isoformat() if job.next_run_time else None})
    return jsonify(status)

# --- STARTUP & SHUTDOWN ---
def startup_scheduler():
    config = load_config()
    if config.get('is_running'):
        print("Restarting previously active schedule.")
        interval = config.get('interval', 1)
        scheduler.add_job(perform_scheduled_analysis, 'interval', hours=interval, id='scheduled_analysis', replace_existing=True)

# --- STARTUP INITIALIZATION ---
def initialize_app():
    """Initialize application components on startup"""
    print("=== AI Log Viewer Startup ===")
    
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



# --- NEW WIZARD & SSH KEY MANAGEMENT ENDPOINTS ---

@app.route('/ssh-keys', methods=['GET'])
def get_ssh_keys():
    """Get list of stored SSH keys"""
    try:
        keys = SSHKey.query.all()
        return jsonify([k.to_dict() for k in keys])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/ssh-keys/upload', methods=['POST'])
def upload_ssh_key():
    """Upload SSH key from file"""
    try:
        key_name = request.form.get('key_name')
        uploaded_file = request.files.get('key_file')
        
        if not key_name or not uploaded_file:
            return jsonify({'error': 'key_name and key_file required'}), 400
        
        existing = SSHKey.query.filter_by(key_name=key_name).first()
        if existing:
            return jsonify({'error': 'Key with this name already exists'}), 400
        
        key_content = uploaded_file.read().decode('utf-8')
        
        ssh_key = SSHKey(
            key_name=key_name,
            key_type='file',
            key_content=key_content
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
        key_name = data.get('key_name')
        key_content = data.get('key_content')
        
        if not key_name or not key_content:
            return jsonify({'error': 'key_name and key_content required'}), 400
        
        existing = SSHKey.query.filter_by(key_name=key_name).first()
        if existing:
            return jsonify({'error': 'Key with this name already exists'}), 400
        
        ssh_key = SSHKey(
            key_name=key_name,
            key_type='pasted',
            key_content=key_content
        )
        db.session.add(ssh_key)
        db.session.commit()
        
        return jsonify({'message': 'SSH key saved', 'id': ssh_key.id}), 201
    except Exception as e:
        db.session.rollback()
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
                temp_file.write(ssh_key.key_content)
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
                temp_file.write(ssh_key.key_content)
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
        data = request.get_json()
        devices = data.get('devices', [])
        ssh_key_id = data.get('ssh_key_id')
        
        if not devices:
            return jsonify({'error': 'No devices provided'}), 400
        
        added_hosts = []
        for device in devices:
            try:
                host = Host(
                    hostname=device.get('hostname', device['ip']),
                    friendly_name=device.get('friendly_name', device['ip']),
                    ip_address=device['ip'],
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
                
                log_content = f"Host onboarded from wizard\nIP: {device['ip']}\nUser: {device.get('user')}\nSystem Info collected: {bool(device.get('system_info'))}"
                host_log = HostLog(
                    host_id=host.id,
                    log_content=log_content,
                    log_type='setup'
                )
                db.session.add(host_log)
                
                added_hosts.append({
                    'id': host.id,
                    'hostname': host.hostname,
                    'ip': host.ip_address
                })
            except Exception as e:
                print(f"Error adding device {device}: {e}")
                db.session.rollback()
                continue
        
        db.session.commit()
        return jsonify({
            'message': f'Added {len(added_hosts)} devices',
            'devices': added_hosts
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

        ssh_key_path = None
        if host.ssh_key and host.ssh_key.key_content:
            temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem')
            temp_file.write(host.ssh_key.key_content)
            temp_file.close()
            os.chmod(temp_file.name, 0o600)
            ssh_key_path = temp_file.name

        try:
            sys_info = collect_system_info(user, ip, ssh_key_path)
            services = collect_services(user, ip, ssh_key_path)
        finally:
            if ssh_key_path and os.path.exists(ssh_key_path):
                try:
                    os.unlink(ssh_key_path)
                except Exception:
                    pass

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
    """Generate Ansible inventory YAML"""
    try:
        groups = Group.query.all()
        ungrouped = Host.query.filter(~Host.groups.any()).all()
        
        inventory = {'all': {'children': {}}}
        
        for group in groups:
            inventory['all']['children'][group.name] = {
                'hosts': {}
            }
            for host in group.hosts:
                host_name = host.friendly_name or host.hostname
                si = getattr(host, 'system_info', None)
                main_ip = getattr(si, 'main_ip', None) if si else None
                netbird_ip = getattr(si, 'netbird_ip', None) if si else None
                base_ip = main_ip or host.ip_address

                inventory['all']['children'][group.name]['hosts'][host_name] = {
                    'ansible_host': base_ip,
                    'ansible_user': host.ssh_user
                }

                if netbird_ip:
                    inventory['all']['children'][group.name]['hosts'][f"{host_name}-netbird"] = {
                        'ansible_host': netbird_ip,
                        'ansible_user': host.ssh_user
                    }
        
        if ungrouped:
            inventory['all']['children']['ungrouped'] = {'hosts': {}}
            for host in ungrouped:
                host_name = host.friendly_name or host.hostname
                si = getattr(host, 'system_info', None)
                main_ip = getattr(si, 'main_ip', None) if si else None
                netbird_ip = getattr(si, 'netbird_ip', None) if si else None
                base_ip = main_ip or host.ip_address

                inventory['all']['children']['ungrouped']['hosts'][host_name] = {
                    'ansible_host': base_ip,
                    'ansible_user': host.ssh_user
                }

                if netbird_ip:
                    inventory['all']['children']['ungrouped']['hosts'][f"{host_name}-netbird"] = {
                        'ansible_host': netbird_ip,
                        'ansible_user': host.ssh_user
                    }
        
        try:
            import yaml
            yaml_output = yaml.dump(inventory, default_flow_style=False)
        except ImportError:
            yaml_output = json.dumps(inventory, indent=2)
        
        return Response(
            yaml_output,
            mimetype='text/yaml',
            headers={'Content-Disposition': 'attachment; filename=inventory.yaml'}
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
        
        for host in hosts:
            host_name = host.friendly_name or host.hostname
            si = getattr(host, 'system_info', None)
            main_ip = getattr(si, 'main_ip', None) if si else None
            netbird_ip = getattr(si, 'netbird_ip', None) if si else None
            base_ip = main_ip or host.ip_address

            def append_host_block(name, hostname_or_ip):
                nonlocal ssh_config
                ssh_config += f"Host {name}\n"
                ssh_config += f"    HostName {hostname_or_ip}\n"
                ssh_config += f"    User {host.ssh_user}\n"
                if host.ssh_key:
                    ssh_config += f"    IdentityFile ~/.ssh/{host.ssh_key.key_name}\n"
                ssh_config += f"    StrictHostKeyChecking no\n"
                ssh_config += f"    UserKnownHostsFile=/dev/null\n"
                ssh_config += "\n"

            append_host_block(host_name, base_ip)
            if netbird_ip:
                append_host_block(f"{host_name}-netbird", netbird_ip)
        
        return Response(
            ssh_config,
            mimetype='text/plain',
            headers={'Content-Disposition': 'attachment; filename=ssh_config'}
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- SERVER-SENT EVENTS (SSE) STREAMING ENDPOINTS ---

import uuid as uuid_lib
from threading import Lock

# Global dictionary to store event queues for each wizard session
wizard_sessions = {}
sessions_lock = Lock()

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
                    temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem')
                    temp_file.write(ssh_key.key_content)
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
                
                timestamp = datetime.datetime.utcnow().isoformat()
                msg = {'type': 'progress', 'current': i, 'total': len(ips), 'message': 'Testing ' + ip + '...'}
                yield "data: " + json.dumps(msg) + "\n\n"
                
                result = test_ssh_connection(user, ip, ssh_key_path)
                results.append(result)
                
                msg = {'type': 'result', 'ip': ip, 'status': result['status'], 'message': result['message'], 'timestamp': timestamp}
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
                    temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem')
                    temp_file.write(ssh_key.key_content)
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
    app.run(host='0.0.0.0', port=5001, debug=False)
