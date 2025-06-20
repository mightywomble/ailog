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

# Initialize Flask App and Scheduler
app = Flask(__name__)
scheduler = BackgroundScheduler(daemon=True)

# --- CONFIGURATION ---
LOG_DIRECTORY = '/var/log'
MAX_CHAR_COUNT = 40000 
DISCORD_ALERT_KEYWORDS = ['error', 'issue', 'failed', 'warning', 'critical', 'exception', 'denied', 'unable']
CONFIG_FILE = 'scheduler_config.json'

# --- HELPER FUNCTIONS ---
def format_bytes(size_bytes):
    if size_bytes == 0: return "0B"
    power, n = 1024, 0
    power_labels = {0: 'B', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
    while size_bytes >= power and n < len(power_labels) -1 :
        size_bytes /= power
        n += 1
    return f"{size_bytes:.1f} {power_labels[n]}" if n > 0 else f"{int(size_bytes)} {power_labels[n]}"

def format_relative_time(epoch_time):
    delta = datetime.datetime.now() - datetime.datetime.fromtimestamp(epoch_time)
    if delta.days > 1: return f"{delta.days} days ago"
    if delta.days == 1: return "Yesterday"
    if delta.seconds >= 3600: return f"{delta.seconds // 3600} hours ago"
    if delta.seconds >= 60: return f"{delta.seconds // 60} mins ago"
    return "Just now"

def send_discord_notification(webhook_url, log_name, analysis_text):
    """Sends a formatted alert to a Discord webhook."""
    if not webhook_url: return
    headers = {'Content-Type': 'application/json'}
    discord_payload = {
        "embeds": [{
            "title": f"🚨 AI Alert for: {log_name}",
            "description": analysis_text[:4000], # Discord description limit
            "color": 15158332, # Red
            "footer": { "text": "Log Viewer AI Analysis" },
            "timestamp": datetime.datetime.now().isoformat()
        }]
    }
    try:
        requests.post(webhook_url, data=json.dumps(discord_payload), headers=headers, timeout=10)
    except requests.exceptions.RequestException as e:
        print(f"Error sending Discord notification: {e}")

# --- CORE ANALYSIS LOGIC ---
def _do_analysis_task():
    """Contains the core logic for analyzing logs. Can be called on-demand or by the scheduler."""
    print("--- Commencing log analysis task ---")
    config = load_config()
    api_key = config.get('api_key')
    webhook_url = config.get('webhook_url')
    sources_to_check = config.get('sources', [])

    if not all([api_key, webhook_url, sources_to_check]):
        print("Analysis task aborted: Missing API key, webhook, or sources in config.")
        return

    for source in sources_to_check:
        log_name = source.get('name')
        log_type = source.get('type')
        print(f"Analyzing {log_type}: {log_name}")

        try:
            # Fetch log content
            if log_type == 'file':
                command = f"sudo zcat {shlex.quote(os.path.join(LOG_DIRECTORY, log_name))} | tail -n 500" if log_name.endswith('.gz') else f"sudo tail -n 500 {shlex.quote(os.path.join(LOG_DIRECTORY, log_name))}"
            else: # journal
                command = f"sudo journalctl -u {shlex.quote(log_name)} -n 500 --no-pager"
            
            result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
            log_content = result.stdout
            if not log_content: continue

            # Truncate if necessary
            if len(log_content) > MAX_CHAR_COUNT:
                log_content = f"[--- Log truncated... ---]\n" + log_content[-MAX_CHAR_COUNT:]

            # Get AI Analysis
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

            # Notify Discord if keywords are found
            if any(keyword in analysis.lower() for keyword in DISCORD_ALERT_KEYWORDS):
                print(f"Issue found in {log_name}. Sending alert to Discord.")
                send_discord_notification(webhook_url, log_name, analysis)
        
        except Exception as e:
            print(f"Error during analysis of {log_name}: {e}")

# --- SCHEDULED TASK WRAPPER ---
def perform_scheduled_analysis():
    """The wrapper for the scheduled job, respects the 'is_running' flag."""
    config = load_config()
    if not config.get('is_running'):
        print("Scheduler is paused. Skipping scheduled run.")
        return
    _do_analysis_task()

# --- PERSISTENCE ---
def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

def load_config():
    if not os.path.exists(CONFIG_FILE): return {}
    with open(CONFIG_FILE, 'r') as f:
        try: return json.load(f)
        except json.JSONDecodeError: return {}

# --- FLASK ROUTES ---
@app.route('/')
def index():
    # ... (This route is unchanged) ...
    all_sources = []
    error = None
    try:
        cmd_ls = f"sudo ls -p {shlex.quote(LOG_DIRECTORY)}"
        res_ls = subprocess.run(cmd_ls, shell=True, capture_output=True, text=True, check=True)
        filenames = [entry for entry in res_ls.stdout.strip().split('\n') if not entry.endswith('/') and entry]
        for filename in filenames:
            file_path = os.path.join(LOG_DIRECTORY, filename)
            cmd_stat = f"sudo stat -c '%s %Y' {shlex.quote(file_path)}"
            res_stat = subprocess.run(cmd_stat, shell=True, capture_output=True, text=True, check=True)
            size_bytes, mod_time_epoch = map(int, res_stat.stdout.strip().split())
            all_sources.append({'type': 'file','name': filename,'size_bytes': size_bytes,'size_formatted': format_bytes(size_bytes),'modified_epoch': mod_time_epoch,'modified_formatted': format_relative_time(mod_time_epoch)})
            
        cmd_journal = "sudo journalctl --field _SYSTEMD_UNIT | sort | uniq"
        res_journal = subprocess.run(cmd_journal, shell=True, capture_output=True, text=True, check=True)
        journal_units = [unit for unit in res_journal.stdout.strip().split('\n') if unit]
        for unit in journal_units:
             all_sources.append({'type': 'journal','name': unit,'size_bytes': 0, 'size_formatted': 'N/A','modified_epoch': 0, 'modified_formatted': 'Journald Service'})
    except Exception as e:
        error = f"An unexpected error occurred: {str(e)}"
    return render_template('index.html', sources=all_sources, error=error)

# ... (Existing /log, /journal, and /test_discord routes remain the same) ...
@app.route('/log/<path:filename>')
def get_log_content(filename):
    if '/' in filename or '..' in filename: return jsonify({'error': 'Invalid filename.'}), 400
    file_path = os.path.join(LOG_DIRECTORY, filename)
    try:
        command = f"sudo zcat {shlex.quote(file_path)} | tail -n 500" if filename.endswith('.gz') else f"sudo tail -n 500 {shlex.quote(file_path)}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        return jsonify({'content': result.stdout, 'will_be_truncated': len(result.stdout) > MAX_CHAR_COUNT})
    except Exception as e: return jsonify({'error': f"Could not read log file '{filename}': {str(e)}"}), 500

@app.route('/journal/<path:unit>')
def get_journal_content(unit):
    if not unit or '/' in unit or '..' in unit: return jsonify({'error': 'Invalid unit name.'}), 400
    try:
        command = f"sudo journalctl -u {shlex.quote(unit)} -n 500 --no-pager"
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        return jsonify({'content': result.stdout, 'will_be_truncated': len(result.stdout) > MAX_CHAR_COUNT})
    except Exception as e: return jsonify({'error': f"Could not read journal for unit '{unit}': {str(e)}"}), 500

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
    webhook_url = data.get('webhook_url') # For manual alerts
    if not api_key: return jsonify({'error': 'OpenAI API key not provided.'}), 400
    if not log_content: return jsonify({'error': 'Missing log_content.'}), 400
    if len(log_content) > MAX_CHAR_COUNT:
        log_content = f"[--- Log truncated... ---]\n" + log_content[-MAX_CHAR_COUNT:]
    try:
        client = openai.OpenAI(api_key=api_key)
        response = client.chat.completions.create(model="gpt-3.5-turbo", messages=[{"role": "system", "content": "You are a helpful assistant that analyses log files."}, {"role": "user", "content": f"Analyse this log for {log_name} for errors, create a summary report, and give troubleshooting tips.\n\n{log_content}"}])
        analysis = response.choices[0].message.content
        discord_sent = False
        if webhook_url and any(keyword in analysis.lower() for keyword in DISCORD_ALERT_KEYWORDS):
            send_discord_notification(webhook_url, log_name, analysis)
            discord_sent = True
        return jsonify({'analysis': analysis, 'discord_sent': discord_sent})
    except Exception as e: return jsonify({'error': f'An error occurred: {str(e)}'}), 500

# --- SCHEDULER ROUTES ---
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
    """Triggers an immediate, one-off execution of the analysis task."""
    config = load_config()
    if not all([config.get('api_key'), config.get('webhook_url'), config.get('sources')]):
         return jsonify({'error': 'Cannot run. Configure API key, webhook, and select logs first.'}), 400
    
    # Run the analysis in a background thread to avoid blocking the request
    thread = threading.Thread(target=_do_analysis_task)
    thread.daemon = True
    thread.start()
    
    return jsonify({'message': 'Immediate analysis triggered. Alerts will be sent for any issues found.'})

@app.route('/schedule/status', methods=['GET'])
def schedule_status():
    config = load_config()
    job = scheduler.get_job('scheduled_analysis')
    if job and config.get('is_running'):
        return jsonify({'is_running': True, 'interval': config.get('interval'), 'sources': config.get('sources', []), 'next_run': job.next_run_time.isoformat() if job.next_run_time else None})
    return jsonify({'is_running': False, 'sources': config.get('sources', []), 'interval': config.get('interval')})

# --- STARTUP & SHUTDOWN ---
def startup_scheduler():
    config = load_config()
    if config.get('is_running'):
        print("Restarting previously active schedule.")
        scheduler.add_job(perform_scheduled_analysis, 'interval', hours=config.get('interval', 1), id='scheduled_analysis', replace_existing=True)

if __name__ == '__main__':
    scheduler.start()
    startup_scheduler()
    atexit.register(lambda: scheduler.shutdown())
    app.run(host='0.0.0.0', port=5001, debug=False)
