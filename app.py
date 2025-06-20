import subprocess
from flask import Flask, render_template, jsonify, request
import shlex
import os
import datetime
import openai

# Initialize the Flask application
app = Flask(__name__)

# --- SECURITY WARNING ---
# This application runs commands with 'sudo'. This is a significant security risk.
# It is designed for use ONLY on a trusted, isolated development network where the
# user running this app has pre-configured 'sudo nopasswd' access.
# DO NOT EXPOSE THIS APPLICATION TO THE INTERNET or any untrusted network.
# ---

LOG_DIRECTORY = '/var/log'

def format_bytes(size_bytes):
    """Converts bytes to a human-readable format (KB, MB, etc.)."""
    if size_bytes == 0:
        return "0B"
    power = 1024
    n = 0
    power_labels = {0: 'B', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
    while size_bytes >= power and n < len(power_labels) - 1:
        size_bytes /= power
        n += 1
    if n > 0:
        return f"{size_bytes:.1f} {power_labels[n]}"
    else:
        return f"{int(size_bytes)} {power_labels[n]}"

def format_relative_time(epoch_time):
    """Converts an epoch timestamp into a relative time string."""
    now = datetime.datetime.now()
    dt_time = datetime.datetime.fromtimestamp(epoch_time)
    delta = now - dt_time
    
    if delta.days > 1:
        return f"{delta.days} days ago"
    elif delta.days == 1:
        return "Yesterday"
    elif delta.seconds >= 3600:
        return f"{delta.seconds // 3600} hours ago"
    elif delta.seconds >= 60:
        return f"{delta.seconds // 60} mins ago"
    else:
        return "Just now"


@app.route('/')
def index():
    """Renders the main page with log file data."""
    files_data = []
    error = None
    try:
        command_ls = f"sudo ls -p {shlex.quote(LOG_DIRECTORY)}"
        result_ls = subprocess.run(command_ls, shell=True, capture_output=True, text=True, check=True)
        
        all_entries = result_ls.stdout.strip().split('\n')
        filenames = [entry for entry in all_entries if not entry.endswith('/') and entry]

        for filename in filenames:
            file_path = os.path.join(LOG_DIRECTORY, filename)
            command_stat = f"sudo stat -c '%s %Y' {shlex.quote(file_path)}"
            result_stat = subprocess.run(command_stat, shell=True, capture_output=True, text=True, check=True)
            size_bytes, mod_time_epoch = map(int, result_stat.stdout.strip().split())
            
            files_data.append({
                'name': filename,
                'size_bytes': size_bytes,
                'size_formatted': format_bytes(size_bytes),
                'modified_epoch': mod_time_epoch,
                'modified_formatted': format_relative_time(mod_time_epoch)
            })
    except subprocess.CalledProcessError as e:
        error = f"Error processing log files: {e.stderr}"
    except Exception as e:
        error = f"An unexpected error occurred: {str(e)}"
        
    # The openai_configured flag is no longer needed here
    return render_template('index.html', files=files_data, error=error)


@app.route('/log/<path:filename>')
def get_log_content(filename):
    """API endpoint to get the content of a specific log file."""
    if '/' in filename or '..' in filename:
        return jsonify({'error': 'Invalid filename.'}), 400

    file_path = os.path.join(LOG_DIRECTORY, filename)
    
    try:
        command = f"sudo tail -n 500 {shlex.quote(file_path)}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        return jsonify({'content': result.stdout})
    except Exception as e:
        return jsonify({'error': f"Could not read log file: {str(e)}"}), 500

@app.route('/analyse', methods=['POST'])
def analyse_log():
    """API endpoint to analyse log content using OpenAI."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request.'}), 400
        
    log_content = data.get('log_content')
    api_key = data.get('api_key')

    if not api_key:
        return jsonify({'error': 'OpenAI API key not provided. Please set it in the settings menu.'}), 400
    if not log_content:
        return jsonify({'error': 'Missing log_content in request.'}), 400

    prompt = "Analyse this log for any errors and create a summary report, troubleshooting tips and any other advice relating to any other issues found."

    try:
        # Set the API key for this specific request
        client = openai.OpenAI(api_key=api_key)
        
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful assistant that analyses log files."},
                {"role": "user", "content": f"{prompt}\n\n--- LOG CONTENT ---\n{log_content}"}
            ]
        )
        analysis = response.choices[0].message.content
        return jsonify({'analysis': analysis})
    except openai.AuthenticationError:
        return jsonify({'error': 'Invalid OpenAI API key. Please check the key in the settings menu.'}), 401
    except Exception as e:
        return jsonify({'error': f'An error occurred with the OpenAI API: {str(e)}'}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
