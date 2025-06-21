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

# --- INITIALIZATION ---
app = Flask(__name__)
scheduler = BackgroundScheduler(daemon=True)

# --- CONFIGURATION ---
LOG_DIRECTORY = '/var/log'
MAX_CHAR_COUNT = 40000 
DISCORD_ALERT_KEYWORDS = ['error', 'issue', 'failed', 'warning', 'critical', 'exception', 'denied', 'unable']
CONFIG_FILE = 'scheduler_config.json'
# New configuration for remote hosts
HOSTS_FILE = 'hosts.json'

# --- HELPER FUNCTIONS for HOSTS ---
def load_hosts():
    """Loads the remote hosts configuration from a JSON file."""
    if not os.path.exists(HOSTS_FILE):
        with open(HOSTS_FILE, 'w') as f:
            json.dump({}, f)
        return {}
    try:
        with open(HOSTS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as e:
        raise ValueError(f"Error decoding '{HOSTS_FILE}'. Please check for syntax errors or invalid characters. Details: {e}")

def save_hosts(hosts):
    """Saves the remote hosts configuration to a JSON file."""
    with open(HOSTS_FILE, 'w') as f:
        json.dump(hosts, f, indent=4)

def get_ssh_prefix_args(hostname):
    """
    Constructs the SSH command prefix as a list of arguments.
    Raises ValueError if the host is not configured.
    """
    if not hostname or hostname in ['localhost', 'local']:
        return []
    hosts = load_hosts()
    host_info = hosts.get(hostname)
    if not host_info or not host_info.get('user'):
        raise ValueError(f"Host '{hostname}' is not configured. Please add it in Settings.")
    
    user = host_info['user']
    return [
        "ssh", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes", f"{user}@{hostname}"
    ]

# --- CORE LOGIC (Refactored for Remote Execution) ---

def execute_command(hostname, command_str):
    """
    Executes a command either locally or remotely via SSH.
    Returns the subprocess result object.
    """
    ssh_prefix_args = get_ssh_prefix_args(hostname)
    cmd_list = ssh_prefix_args + [command_str] if ssh_prefix_args else [command_str]
    shell_mode = not bool(ssh_prefix_args)
    return subprocess.run(cmd_list, shell=shell_mode, capture_output=True, text=True, check=True, timeout=20)

def get_log_sources_from_host_stream(hostname='localhost'):
    """
    Fetches log sources from a host, yielding progress updates as a Server-Sent Events (SSE) stream.
    """
    def generate_event(data):
        return f"data: {json.dumps(data)}\n\n"

    try:
        # Step 1: List log files
        yield generate_event({'status': 'progress', 'message': 'Listing log files...', 'progress': 5})
        cmd_ls = f"sudo ls -p {shlex.quote(LOG_DIRECTORY)}"
        res_ls = execute_command(hostname, cmd_ls)
        filenames = [entry for entry in res_ls.stdout.strip().split('\n') if not entry.endswith('/') and entry]
        total_files = len(filenames)
        yield generate_event({'status': 'progress', 'message': f'Found {total_files} potential log files.', 'progress': 10})

        # Step 2: Stat each file and stream results
        for i, filename in enumerate(filenames):
            progress = 10 + int((i / total_files) * 80) if total_files > 0 else 90
            yield generate_event({'status': 'progress', 'message': f'Checking: {filename}', 'progress': progress})
            try:
                cmd_stat = f"sudo stat -c '%s %Y' {shlex.quote(os.path.join(LOG_DIRECTORY, filename))}"
                res_stat = execute_command(hostname, cmd_stat)
                size_bytes, mod_time_epoch = map(int, res_stat.stdout.strip().split())
                source_data = {
                    'type': 'file', 'name': filename, 'size_bytes': size_bytes,
                    'size_formatted': format_bytes(size_bytes), 'modified_epoch': mod_time_epoch,
                    'modified_formatted': format_relative_time(mod_time_epoch)
                }
                yield generate_event({'status': 'source', 'data': source_data})
            except (subprocess.CalledProcessError, ValueError, subprocess.TimeoutExpired) as e:
                print(f"Could not stat file '{filename}' on '{hostname}': {e}")
                continue
        
        # Step 3: Fetch journald units
        yield generate_event({'status': 'progress', 'message': 'Fetching journald services...', 'progress': 95})
        try:
            cmd_journal = "sudo journalctl --field _SYSTEMD_UNIT | sort | uniq"
            res_journal = execute_command(hostname, cmd_journal)
            journal_units = [unit for unit in res_journal.stdout.strip().split('\n') if unit]
            for unit in journal_units:
                source_data = {
                    'type': 'journal', 'name': unit, 'size_bytes': 0, 'size_formatted': 'N/A',
                    'modified_epoch': 0, 'modified_formatted': 'Journald Service'
                }
                yield generate_event({'status': 'source', 'data': source_data})
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            print(f"Could not fetch journald units from '{hostname}': {e}")
        
        yield generate_event({'status': 'complete', 'message': 'Done!'})

    except Exception as e:
        yield generate_event({'status': 'error', 'message': str(e)})


# --- HELPER FUNCTIONS (Unchanged) ---
def format_bytes(size_bytes):
    if size_bytes == 0: return "0B"
    power, n = 1024, 0
    power_labels = {0: 'B', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
    while size_bytes >= power and n < len(power_labels) -1 :
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

def send_discord_notification(webhook_url, log_name, analysis_text):
    if not webhook_url: return
    headers = {'Content-Type': 'application/json'}
    discord_payload = {
        "embeds": [{"title": f"🚨 AI Alert for: {log_name}","description": analysis_text[:4000],"color": 15158332, "footer": { "text": "Log Viewer AI Analysis" },"timestamp": datetime.datetime.now().isoformat()}]
    }
    try:
        requests.post(webhook_url, data=json.dumps(discord_payload), headers=headers, timeout=10)
    except requests.exceptions.RequestException as e:
        print(f"Error sending Discord notification: {e}")

# --- FLASK ROUTES ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/sources/local')
def get_local_sources():
    return Response(stream_with_context(get_log_sources_from_host_stream('local')), mimetype='text/event-stream')

@app.route('/sources/remote/<hostname>')
def get_remote_sources(hostname):
    if '/' in hostname or '..' in hostname:
        return Response(f"data: {json.dumps({'status': 'error', 'message': 'Invalid hostname format.'})}\n\n", mimetype='text/event-stream')
    return Response(stream_with_context(get_log_sources_from_host_stream(hostname)), mimetype='text/event-stream')

@app.route('/log/<path:filename>')
def get_log_content(filename):
    hostname = request.args.get('host', 'localhost')
    if '/' in filename or '..' in filename: return jsonify({'error': 'Invalid filename.'}), 400
    try:
        command_str = f"sudo zcat {shlex.quote(os.path.join(LOG_DIRECTORY, filename))} 2>/dev/null | tail -n 500" if filename.endswith('.gz') else f"sudo tail -n 500 {shlex.quote(os.path.join(LOG_DIRECTORY, filename))}"
        result = execute_command(hostname, command_str)
        return jsonify({'content': result.stdout, 'will_be_truncated': len(result.stdout) > MAX_CHAR_COUNT})
    except Exception as e: 
        return jsonify({'error': f"Could not read log file '{filename}' on '{hostname}': {e}"}), 500

@app.route('/journal/<path:unit>')
def get_journal_content(unit):
    hostname = request.args.get('host', 'localhost')
    if not unit or '/' in unit or '..' in unit: return jsonify({'error': 'Invalid unit name.'}), 400
    try:
        command_str = f"sudo journalctl -u {shlex.quote(unit)} -n 500 --no-pager"
        result = execute_command(hostname, command_str)
        return jsonify({'content': result.stdout, 'will_be_truncated': len(result.stdout) > MAX_CHAR_COUNT})
    except Exception as e: 
        return jsonify({'error': f"Could not read journal for unit '{unit}' on '{hostname}': {e}"}), 500

# --- HOST MANAGEMENT ROUTES ---
@app.route('/hosts', methods=['GET', 'POST'])
def manage_hosts():
    if request.method == 'POST':
        data = request.get_json()
        hostname, user = data.get('hostname'), data.get('user')
        if not all([hostname, user]): return jsonify({'error': 'Hostname and user are required.'}), 400
        hosts = load_hosts()
        hosts[hostname] = {'user': user}
        save_hosts(hosts)
        return jsonify({'message': f"Host '{hostname}' added successfully."})
    try:
        return jsonify(load_hosts())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/hosts/delete', methods=['POST'])
def delete_host():
    hostname = request.get_json().get('hostname')
    if not hostname: return jsonify({'error': 'Hostname is required.'}), 400
    hosts = load_hosts()
    if hostname in hosts:
        del hosts[hostname]
        save_hosts(hosts)
        return jsonify({'message': f"Host '{hostname}' deleted."})
    return jsonify({'error': 'Host not found.'}), 404

# --- ANALYSIS & SCHEDULER ROUTES (Unchanged) ---
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
            send_discord_notification(webhook_url, log_name, analysis)
            discord_sent = True
        return jsonify({'analysis': analysis, 'discord_sent': discord_sent})
    except Exception as e: return jsonify({'error': f'An error occurred during AI Analysis: {str(e)}'}), 500

def save_config(config):
    with open(CONFIG_FILE, 'w') as f: json.dump(config, f, indent=4)
def load_config():
    if not os.path.exists(CONFIG_FILE): return {}
    with open(CONFIG_FILE, 'r') as f:
        try: return json.load(f)
        except json.JSONDecodeError: return {}
def _do_analysis_task():
    print("--- Commencing scheduled log analysis task ---")
    config = load_config()
    api_key, webhook_url, sources = config.get('api_key'), config.get('webhook_url'), config.get('sources', [])
    if not all([api_key, webhook_url, sources]):
        print("Scheduled analysis aborted: Missing config.")
        return
    for source in sources:
        log_name, log_type = source.get('name'), source.get('type')
        print(f"Analyzing {log_type}: {log_name} on localhost")
        try:
            command = f"sudo zcat {shlex.quote(os.path.join(LOG_DIRECTORY, log_name))} 2>/dev/null | tail -n 500" if log_name.endswith('.gz') else f"sudo tail -n 500 {shlex.quote(os.path.join(LOG_DIRECTORY, log_name))}"
            if log_type != 'file': command = f"sudo journalctl -u {shlex.quote(log_name)} -n 500 --no-pager"
            result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
            log_content = result.stdout
            if not log_content: continue
            if len(log_content) > MAX_CHAR_COUNT: log_content = f"[--- Log truncated... ---]\n" + log_content[-MAX_CHAR_COUNT:]
            client = openai.OpenAI(api_key=api_key)
            prompt = "Analyse this log for any errors and create a summary report, troubleshooting tips and any other advice relating to any other issues found."
            response = client.chat.completions.create(model="gpt-3.5-turbo", messages=[{"role": "system", "content": "You are a helpful assistant that analyses log files for potential issues."}, {"role": "user", "content": f"{prompt}\n\n--- LOG for {log_name} ---\n{log_content}"}])
            analysis = response.choices[0].message.content
            if any(keyword in analysis.lower() for keyword in DISCORD_ALERT_KEYWORDS):
                print(f"Issue found in {log_name}. Sending alert to Discord.")
                send_discord_notification(webhook_url, log_name, analysis)
        except Exception as e:
            print(f"Error during scheduled analysis of {log_name}: {e}")
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
