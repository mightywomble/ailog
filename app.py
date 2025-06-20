import subprocess
from flask import Flask, render_template, jsonify
import shlex
import os

# Initialize the Flask application
app = Flask(__name__)

# --- SECURITY WARNING ---
# This application runs commands with 'sudo'. This is a significant security risk.
# It is designed for use ONLY on a trusted, isolated development network where the
# user running this app has pre-configured 'sudo nopasswd' access.
# DO NOT EXPOSE THIS APPLICATION TO THE INTERNET or any untrusted network.
# The filename handling is basic and relies on the user not being malicious.
# ---

LOG_DIRECTORY = '/var/log'

@app.route('/')
def index():
    """
    Renders the main page.
    It gets a list of files from /var/log using 'sudo ls' and passes them
    to the template.
    """
    files = []
    error = None
    try:
        # Command to list files in the log directory
        command = f"sudo ls -p {shlex.quote(LOG_DIRECTORY)}"
        # The '-p' flag adds a '/' to directory names
        
        # Execute the command
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=True
        )
        
        # Filter out directories from the list
        all_entries = result.stdout.strip().split('\n')
        files = [entry for entry in all_entries if not entry.endswith('/')]

    except subprocess.CalledProcessError as e:
        # Handle cases where the command fails (e.g., permission issues)
        error = f"Error listing log files: {e.stderr}"
    except Exception as e:
        # Handle other potential exceptions
        error = f"An unexpected error occurred: {str(e)}"
        
    return render_template('index.html', files=files, error=error)


@app.route('/log/<path:filename>')
def get_log_content(filename):
    """
    API endpoint to get the content of a specific log file.
    Takes a filename, reads it with 'sudo cat', and returns the content as JSON.
    """
    # Basic security check to prevent directory traversal attacks
    if '/' in filename or '..' in filename:
        return jsonify({'error': 'Invalid filename.'}), 400

    file_path = os.path.join(LOG_DIRECTORY, filename)

    try:
        # Command to read the last 500 lines of the log file to avoid huge files
        # You can change '500' to a different number or use 'cat' to get the whole file
        command = f"sudo tail -n 500 {shlex.quote(file_path)}"
        
        # Execute the command
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=True
        )
        
        # Return the content in a JSON response
        return jsonify({'content': result.stdout})

    except subprocess.CalledProcessError as e:
        # Handle errors, e.g., file not found or not readable
        error_message = f"Could not read log file '{filename}'. Error: {e.stderr}"
        return jsonify({'error': error_message}), 500
    except Exception as e:
        return jsonify({'error': f"An unexpected error occurred: {str(e)}"}), 500


if __name__ == '__main__':
    # Running in debug mode is convenient but should be disabled in a "production" dev environment
    # Use host='0.0.0.0' to make it accessible from other machines on your network
    app.run(host='0.0.0.0', port=5001, debug=True)
