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

# --- INITIALIZATION ---
app = Flask(__name__)
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
    ssh_prefix_args = []
    if hostname != 'local':
        hosts = load_hosts()
        host_info = hosts.get(hostname)
        if not host_info:
            raise ValueError(f"Host ID '{hostname}' not found in configuration.")
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

@app.route('/sources/all', methods=['GET'])
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

@app.route('/sources/table', methods=['GET'])
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
    return jsonify(load_hosts())

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
    hosts = load_hosts()
    if host_id in hosts:
        del hosts[host_id]
        save_hosts(hosts)
        return jsonify({'message': 'Host deleted.'})
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
    log_content, log_name, api_key = data.get('log_content'), data.get('log_name'), data.get('api_key')
    webhook_url = data.get('webhook_url') 
    if not api_key: return jsonify({'error': 'OpenAI API key not provided.'}), 400
    if not log_content: return jsonify({'error': 'Missing log_content.'}), 400
    
    truncated_content = log_content
    if len(log_content) > MAX_CHAR_COUNT:
        truncated_content = f"[--- Log truncated due to size limit... ---]\n" + log_content[-MAX_CHAR_COUNT:]
    
    try:
        client = openai.OpenAI(api_key=api_key)
        response = client.chat.completions.create(model="gpt-3.5-turbo", messages=[{"role": "system", "content": "You are a helpful assistant that analyses log files."}, {"role": "user", "content": f"Analyse this log for {log_name} for errors, create a summary report, and give troubleshooting tips.\n\n{truncated_content}"}])
        analysis = response.choices[0].message.content
        discord_sent = False
        if webhook_url and any(keyword in analysis.lower() for keyword in DISCORD_ALERT_KEYWORDS):
            send_discord_notification(webhook_url, log_name, 'local', analysis)
            discord_sent = True
        return jsonify({'analysis': analysis, 'discord_sent': discord_sent})
    except Exception as e: return jsonify({'error': f'An error occurred during AI Analysis: {str(e)}'}), 500

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
    api_key, webhook_url, sources = config.get('api_key'), config.get('webhook_url'), config.get('sources', [])
    if not all([api_key, webhook_url, sources]):
        print("Scheduled analysis aborted: Missing config.")
        return
    for source in sources:
        log_name, log_type, host = source.get('name'), source.get('type'), source.get('host', 'local')
        print(f"Analyzing {log_type}: {log_name} on {host}")
        try:
            command = f"sudo zcat {shlex.quote(os.path.join(LOG_DIRECTORY, log_name))} 2>/dev/null | tail -n 500" if log_name.endswith('.gz') else f"sudo tail -n 500 {shlex.quote(os.path.join(LOG_DIRECTORY, log_name))}"
            if log_type != 'file': command = f"sudo journalctl -u {shlex.quote(log_name)} -n 500 --no-pager"
            
            result = execute_command(host, command)
            log_content = result.stdout
            if not log_content: continue
            
            truncated_content = log_content
            if len(log_content) > MAX_CHAR_COUNT:
                truncated_content = f"[--- Log truncated... ---]\n" + log_content[-MAX_CHAR_COUNT:]

            client = openai.OpenAI(api_key=api_key)
            prompt = "Analyse this log for any errors and create a summary report, troubleshooting tips and any other advice relating to any other issues found."
            response = client.chat.completions.create(model="gpt-3.5-turbo", messages=[{"role": "system", "content": "You are a helpful assistant that analyses log files for potential issues."}, {"role": "user", "content": f"{prompt}\n\n--- LOG for {log_name} on {host} ---\n{truncated_content}"}])
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

@app.route('/schedule/status', methods=['GET'])
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

if __name__ == '__main__':
    scheduler.start()
    startup_scheduler()
    atexit.register(lambda: scheduler.shutdown())
    app.run(host='0.0.0.0', port=5001, debug=False)
