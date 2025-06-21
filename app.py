import subprocess
from flask import Flask, render_template, jsonify, request
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
        # If the file doesn't exist, create it with an empty object
        with open(HOSTS_FILE, 'w') as f:
            json.dump({}, f)
        return {}
    try:
        with open(HOSTS_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {}

def save_hosts(hosts):
    """Saves the remote hosts configuration to a JSON file."""
    with open(HOSTS_FILE, 'w') as f:
        json.dump(hosts, f, indent=4)

def get_ssh_prefix(hostname):
    """Constructs the SSH command prefix for a given hostname."""
    # Treat 'local' and 'localhost' as the local machine by returning an empty string.
    if not hostname or hostname in ['localhost', 'local']:
        return ""
    hosts = load_hosts()
    host_info = hosts.get(hostname)
    # Check if host_info exists and has a 'user' key.
    if not host_info or not host_info.get('user'):
        # Return an invalid command to ensure failure if host is not configured properly
        # This prevents accidental command execution on the local machine.
        return "echo 'Error: Host not configured properly. Please check settings.' && exit 1 #"
    
    user = host_info['user']
    # Securely create the SSH prefix using shlex.quote for user and hostname.
    return f"ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no {shlex.quote(user)}@{shlex.quote(hostname)}"


# --- CORE LOGIC (Refactored for Remote Execution) ---

def get_log_sources_from_host(hostname='localhost'):
    """
    Fetches the list of syslog files and journald units from a host.
    If hostname is 'localhost' or 'local', it targets the local machine.
    Otherwise, it uses SSH to connect to the remote host.
    """
    all_sources = []
    ssh_prefix = get_ssh_prefix(hostname)

    # Command to get log files, their sizes, and modification times
    # -p adds a slash to directories, which we filter out.
    cmd_ls_remote = f"sudo ls -p {shlex.quote(LOG_DIRECTORY)}"
    full_cmd_ls = f"{ssh_prefix} '{cmd_ls_remote}'" if ssh_prefix else cmd_ls_remote
    
    try:
        res_ls = subprocess.run(full_cmd_ls, shell=True, capture_output=True, text=True, check=True, timeout=20)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        stderr = e.stderr if hasattr(e, 'stderr') else 'Timeout'
        raise ConnectionError(f"Failed to list logs on '{hostname}'. STDERR: {stderr}")

    filenames = [entry for entry in res_ls.stdout.strip().split('\n') if not entry.endswith('/') and entry]
    
    for filename in filenames:
        try:
            # Command to get stats for each file (size in bytes, modification time as epoch)
            cmd_stat_remote = f"sudo stat -c '%s %Y' {shlex.quote(os.path.join(LOG_DIRECTORY, filename))}"
            full_cmd_stat = f"{ssh_prefix} '{cmd_stat_remote}'" if ssh_prefix else cmd_stat_remote
            
            res_stat = subprocess.run(full_cmd_stat, shell=True, capture_output=True, text=True, check=True, timeout=10)
            size_bytes, mod_time_epoch = map(int, res_stat.stdout.strip().split())
            
            all_sources.append({
                'type': 'file',
                'name': filename,
                'size_bytes': size_bytes,
                'size_formatted': format_bytes(size_bytes),
                'modified_epoch': mod_time_epoch,
                'modified_formatted': format_relative_time(mod_time_epoch)
            })
        except (subprocess.CalledProcessError, ValueError, subprocess.TimeoutExpired) as e:
            # Ignore files that we can't stat (e.g., permissions error on remote, timeout)
            print(f"Could not stat file '{filename}' on '{hostname}': {e}")
            continue

    # Command to get all unique journald units
    cmd_journal_remote = "sudo journalctl --field _SYSTEMD_UNIT | sort | uniq"
    full_cmd_journal = f"{ssh_prefix} '{cmd_journal_remote}'" if ssh_prefix else cmd_journal_remote
    
    try:
        res_journal = subprocess.run(full_cmd_journal, shell=True, capture_output=True, text=True, check=True, timeout=20)
        journal_units = [unit for unit in res_journal.stdout.strip().split('\n') if unit]
        for unit in journal_units:
            all_sources.append({
                'type': 'journal',
                'name': unit,
                'size_bytes': 0, 
                'size_formatted': 'N/A',
                'modified_epoch': 0, 
                'modified_formatted': 'Journald Service'
            })
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"Could not fetch journald units from '{hostname}': {e}")

    return all_sources

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
    """Renders the main page."""
    return render_template('index.html')

@app.route('/sources/<hostname>')
def get_sources(hostname):
    """API endpoint to get log sources from the specified host."""
    try:
        sources = get_log_sources_from_host(hostname)
        return jsonify(sources)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/log/<path:filename>')
def get_log_content(filename):
    """
    Gets content for a specific log file.
    Accepts a 'host' query parameter for remote fetching.
    """
    hostname = request.args.get('host', 'localhost')
    if '/' in filename or '..' in filename: return jsonify({'error': 'Invalid filename.'}), 400
    
    file_path = os.path.join(LOG_DIRECTORY, filename)
    ssh_prefix = get_ssh_prefix(hostname)
    
    try:
        remote_cmd = f"sudo zcat {shlex.quote(file_path)} 2>/dev/null | tail -n 500" if filename.endswith('.gz') else f"sudo tail -n 500 {shlex.quote(file_path)}"
        command = f"{ssh_prefix} '{remote_cmd}'" if ssh_prefix else remote_cmd
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True, timeout=20)
        return jsonify({'content': result.stdout, 'will_be_truncated': len(result.stdout) > MAX_CHAR_COUNT})
    except Exception as e: 
        return jsonify({'error': f"Could not read log file '{filename}' on '{hostname}': {e}"}), 500

@app.route('/journal/<path:unit>')
def get_journal_content(unit):
    """
    Gets content for a specific journald unit.
    Accepts a 'host' query parameter for remote fetching.
    """
    hostname = request.args.get('host', 'localhost')
    if not unit or '/' in unit or '..' in unit: return jsonify({'error': 'Invalid unit name.'}), 400

    ssh_prefix = get_ssh_prefix(hostname)

    try:
        remote_cmd = f"sudo journalctl -u {shlex.quote(unit)} -n 500 --no-pager"
        command = f"{ssh_prefix} '{remote_cmd}'" if ssh_prefix else remote_cmd
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True, timeout=20)
        return jsonify({'content': result.stdout, 'will_be_truncated': len(result.stdout) > MAX_CHAR_COUNT})
    except Exception as e: 
        return jsonify({'error': f"Could not read journal for unit '{unit}' on '{hostname}': {e}"}), 500

# --- NEW ROUTES FOR HOST MANAGEMENT ---
@app.route('/hosts', methods=['GET', 'POST'])
def manage_hosts():
    """Endpoint to get the list of hosts or add a new one."""
    if request.method == 'POST':
        data = request.get_json()
        hostname = data.get('hostname')
        user = data.get('user')
        if not hostname or not user:
            return jsonify({'error': 'Hostname and user are required.'}), 400
        
        hosts = load_hosts()
        hosts[hostname] = {'user': user}
        save_hosts(hosts)
        return jsonify({'message': f"Host '{hostname}' added successfully."})
    
    # GET request
    hosts = load_hosts()
    return jsonify(hosts)

@app.route('/hosts/delete', methods=['POST'])
def delete_host():
    """Endpoint to delete a host."""
    data = request.get_json()
    hostname = data.get('hostname')
    if not hostname:
        return jsonify({'error': 'Hostname is required.'}), 400

    hosts = load_hosts()
    if hostname in hosts:
        del hosts[hostname]
        save_hosts(hosts)
        return jsonify({'message': f"Host '{hostname}' deleted."})
    return jsonify({'error': 'Host not found.'}), 404

# --- ANALYSIS, SCHEDULER & OTHER ROUTES (Largely Unchanged) ---
@app.route('/test_discord', methods=['POST'])
def test_discord():
    data = request.get_json()
    webhook_url = data.get('webhook_url')
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

# --- SCHEDULER (Unchanged but included for completeness) ---
def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)
def load_config():
    if not os.path.exists(CONFIG_FILE): return {}
    with open(CONFIG_FILE, 'r') as f:
        try: return json.load(f)
        except json.JSONDecodeError: return {}

def _do_analysis_task():
    """Contains the core logic for analyzing logs. Can be called on-demand or by the scheduler."""
    print("--- Commencing scheduled log analysis task ---")
    config = load_config()
    api_key = config.get('api_key')
    webhook_url = config.get('webhook_url')
    sources_to_check = config.get('sources', [])

    if not all([api_key, webhook_url, sources_to_check]):
        print("Scheduled analysis aborted: Missing API key, webhook, or sources in config.")
        return

    for source in sources_to_check:
        log_name = source.get('name')
        log_type = source.get('type')
        # NOTE: Scheduled tasks currently only support localhost.
        print(f"Analyzing {log_type}: {log_name} on localhost")

        try:
            if log_type == 'file':
                command = f"sudo zcat {shlex.quote(os.path.join(LOG_DIRECTORY, log_name))} 2>/dev/null | tail -n 500" if log_name.endswith('.gz') else f"sudo tail -n 500 {shlex.quote(os.path.join(LOG_DIRECTORY, log_name))}"
            else: # journal
                command = f"sudo journalctl -u {shlex.quote(log_name)} -n 500 --no-pager"
            
            result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
            log_content = result.stdout
            if not log_content: continue

            if len(log_content) > MAX_CHAR_COUNT:
                log_content = f"[--- Log truncated... ---]\n" + log_content[-MAX_CHAR_COUNT:]

            client = openai.OpenAI(api_key=api_key)
            prompt = "Analyse this log for any errors and create a summary report, troubleshooting tips and any other advice relating to any other issues found."
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a helpful assistant that analyses log files for potential issues."},
                    {"role": "user", "content": f"{prompt}\n\n--- LOG for {log_name} ---\n{log_content}"}
                ]
            )
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
