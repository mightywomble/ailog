Local Log File Viewer & AI Analyser
An advanced, modern web application for viewing local system logs from /var/log and journalctl, supercharged with both manual and scheduled AI analysis and proactive Discord alerting. This tool provides a powerful, elegant interface for developers and system administrators to monitor logs directly from their web browser.

⚠️ Security Warning
This application is designed for use on a trusted, internal development network only. It runs commands with sudo and provides access to potentially sensitive log data.

DO NOT expose this application to the public internet. Doing so would create a significant security risk. The sudoers configuration is designed to be as restrictive as possible, but any web-facing application with this level of privilege must be handled with extreme care.

Built with Flask and styled with Tailwind CSS, it offers a clean UI that includes on-the-fly Gzip decompression and dynamic controls for filtering and sorting logs. Its standout features are the one-click manual analysis and the "set and forget" scheduled analysis, which automatically monitors selected logs and sends alerts to a Discord channel when potential issues are detected by the AI.

Features
Unified Log Access: View traditional logs from /var/log and journalctl logs for systemd services in a single interface.

Scheduled AI Monitoring: Select specific logs and set a recurring interval (in hours) for automatic AI analysis.

Proactive Discord Alerts: Automatically sends a rich, formatted notification to a Discord channel via webhook if the manual or scheduled AI analysis detects keywords like "error", "issue", or "warning".

On-Demand Analysis: Trigger an immediate analysis of all monitored logs with a single "Run Now" button.

Log Type Filtering: Easily filter the view to show only syslog files, only journald services, or all sources combined.

Gzip Decompression: Automatically decompresses and displays .gz log archives.

Secure Configuration: API keys and Discord webhooks are managed via a settings menu and stored securely in the browser's local storage. The scheduler configuration is stored locally and excluded from version control.

Intelligent Truncation: Automatically shortens oversized logs before sending for analysis to prevent API errors.

Modern UI: A beautiful and responsive interface built with Tailwind CSS.

Installation & Setup on Ubuntu 24.04
This guide provides complete instructions for setting up the application and running it as a systemd service.

Prerequisites
An Ubuntu 24.04 server.

A non-root user with sudo privileges. We will use david in this guide; be sure to replace david with your actual username in all commands.

Step 1: Install System Dependencies
Update your package list and install Python, pip, and the virtual environment module.

sudo apt update
sudo apt install python3-pip python3.12-venv -y

Step 2: Set Up Project Directory and Clone Repo
Create a directory for the application and clone the project repository into it.

mkdir -p ~/code
cd ~/code
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name

Step 3: Create Python Virtual Environment & Install Requirements
It's best practice to run a Python application in a virtual environment.

python3 -m venv venv
source venv/bin/activate

Create a file named requirements.txt in your project directory with the following content:

# requirements.txt
Flask
openai
requests
APScheduler

Now, install these requirements using pip.

pip install -r requirements.txt

Step 4: Configure Passwordless Sudo Access
The application uses sudo to read system logs. To allow the application to run without a password prompt, grant passwordless access to the specific commands it needs.

Open the sudoers file for editing using visudo. This is the safest way to edit this file.

sudo visudo

Scroll to the bottom of the file and add the following line. Remember to replace david with your username.

# Allow the 'david' user to run specific log-reading commands without a password
david ALL=(ALL) NOPASSWD: /usr/bin/ls -p /var/log, /usr/bin/stat -c %s %Y /var/log/*, /usr/bin/tail -n 500 /var/log/*, /usr/bin/zcat /var/log/*.gz, /usr/bin/journalctl --field _SYSTEMD_UNIT, /usr/bin/journalctl -u * -n 500 --no-pager

Save and exit the editor (Ctrl+X, then Y, then Enter).

Step 5: Set Up the Systemd Service
Create a systemd service to ensure the application runs automatically on boot.

Create a new service file:

sudo nano /etc/systemd/system/logviewer.service

Paste the following configuration into the file. Crucially, replace david with your username and your-repo-name with your project's directory name.

[Unit]
Description=Flask Log Viewer Application
After=network.target

[Service]
User=david
Group=www-data
WorkingDirectory=/home/david/code/your-repo-name
# Use 'debug=False' for production stability with the scheduler
ExecStart=/home/david/code/your-repo-name/venv/bin/python3 /home/david/code/your-repo-name/app.py
Restart=always

[Install]
WantedBy=multi-user.target

Save and close the file.

Step 6: Start and Enable the Service
Reload the systemd daemon, then start and enable the service.

sudo systemctl daemon-reload
sudo systemctl start logviewer
sudo systemctl enable logviewer

Step 7: Verify the Service is Running
Check the status of the service to ensure it's active.

sudo systemctl status logviewer

You should see output indicating the service is active (running).

Usage
Once the service is running, access the application by navigating to your server's IP address on port 5001:

http://<your-server-ip>:5001

Initial Configuration
Before using the AI features, you must provide your credentials.

Click the Settings (gear) icon in the top right.

Enter your OpenAI API Key.

To enable Discord alerts, create a webhook in your Discord server (Server Settings > Integrations > Webhooks) and paste the Webhook URL into the settings.

Use the Test button to confirm the webhook is working correctly.

Click Save & Close. Credentials are stored securely in your browser's local storage.

Manual Log Analysis
Click on any log or service from the list on the left.

Once the content appears on the right, the AI Analyse button will become active.

Click it to get an immediate, on-demand analysis of that specific log.

Scheduled Monitoring & Alerts
The app can automatically monitor multiple logs and alert you on Discord if the AI finds a problem.

Select Logs: In the Settings modal, click the Select Logs for Schedule... button. A new window will appear. Check the box next to every log and service you want to monitor. Click Confirm Selections.

Set Interval: In the settings modal, enter how often (in hours) you want the analysis to run.

Start Schedule: Click the green Start button. The status will update to "Running" and show you when the next analysis is scheduled.

Run On-Demand: You can trigger an immediate analysis of all your selected logs at any time by clicking the amber Run Now button. This does not affect the regular schedule.

Stop Schedule: Click the red Stop button to pause all scheduled monitoring.

The schedule configuration is saved on the server and will automatically resume if the application or server restarts.

