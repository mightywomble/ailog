Local Log File Viewer & AI Analyser
A simple, modern web application for viewing local log files from /var/log and journalctl with the power of AI analysis. This tool provides an elegant and efficient interface for developers and system administrators to monitor logs directly from their web browser.

Built with Flask and styled with Tailwind CSS, it offers a clean, responsive UI that includes dynamic filtering, sorting, and on-the-fly decompression of .gz archives. Its standout feature is the one-click integration with the OpenAI API, allowing you to get an AI-powered summary, error analysis, and troubleshooting tips for your logs.



<h2><b>Features</b></h2>
<li>Unified Log Access: View traditional logs from /var/log and journalctl logs for systemd services in a single interface.
<li>Log Type Filtering: Easily filter the view to show only syslog files, only journald services, or all sources combined.
<li>AI-Powered Analysis: Send log contents to the OpenAI API for a detailed analysis with a single click.
<li>Gzip Decompression: Automatically decompresses and displays .gz log archives on the fly.
<li>Dynamic Filtering: Instantly search and filter the combined log source list.
<li>Smart Sorting: Sort logs by name, size, or modification date.
<li>Secure API Key Storage: API key is managed via a settings menu and stored in the browser's local storage.
<li>Intelligent Truncation: Automatically shortens oversized logs before sending for analysis to prevent API errors.
<li>Modern UI: A beautiful and responsive interface built with Tailwind CSS.

Installation & Setup on Ubuntu 24.04
This guide provides complete instructions for setting up the application and running it as a systemd service on a fresh Ubuntu 24.04 server.

Prerequisites
An Ubuntu 24.04 server.

A non-root user with sudo privileges. We will use the username david in this guide; be sure to replace david with your actual username in all commands.

Step 1: Install System Dependencies
First, update your package list and install Python, pip, and the virtual environment module.

sudo apt update<br>
sudo apt install python3-pip python3.12-venv -y<br>

Step 2: Set Up Project Directory and Clone Repo
Create a directory for the application and clone the project repository into it.

# Create the parent directory
mkdir -p ~/code
cd ~/code

# Clone your repository (replace with your actual repo URL)
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name

Step 3: Create Python Virtual Environment & Install Requirements
It's best practice to run a Python application in a virtual environment.

# Create the virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate

Create a file named requirements.txt in your project directory with the following content:

# requirements.txt
Flask
openai

Now, install these requirements using pip.

# Install the Python libraries
pip install -r requirements.txt

Step 4: Configure Passwordless Sudo Access
The application uses sudo to read system logs. To allow the application to run without a password prompt, you must grant passwordless access to the specific commands it needs. This is a critical security step.

Open the sudoers file for editing using visudo. This is the safest way to edit this file.

sudo visudo

Scroll to the bottom of the file and add the following line. Remember to replace david with your username. This rule is specifically crafted to only allow the commands needed by the application.

# Allow the 'david' user to run specific log-reading commands without a password
david ALL=(ALL) NOPASSWD: /usr/bin/ls -p /var/log, /usr/bin/stat -c %s %Y /var/log/*, /usr/bin/tail -n 500 /var/log/*, /usr/bin/zcat /var/log/*.gz, /usr/bin/journalctl --field _SYSTEMD_UNIT, /usr/bin/journalctl -u * -n 500 --no-pager

Save and exit the editor. In nano (the default), this is Ctrl+X, then Y, then Enter.

Step 5: Set Up the Systemd Service
To ensure the application runs automatically on boot and restarts on failure, create a systemd service.

Create a new service file:

sudo nano /etc/systemd/system/logviewer.service

Paste the following configuration into the file. Crucially, you must replace david with your username and your-repo-name with your project's directory name.

[Unit]
Description=Flask Log Viewer Application
After=network.target

[Service]
User=david
Group=www-data
WorkingDirectory=/home/david/code/your-repo-name
ExecStart=/home/david/code/your-repo-name/venv/bin/python3 /home/david/code/your-repo-name/app.py
Restart=always

[Install]
WantedBy=multi-user.target

Save and close the file.

Step 6: Start and Enable the Service
Now, reload the systemd daemon, then start and enable the service.

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

To use the AI analysis feature:

Click the Settings (gear) icon in the top right.

Enter your OpenAI API Key and click Save.

Select a log file or journald service and click the AI Analyse button.

⚠️ Security Warning
This application is designed for use on a trusted, internal development network only. It runs commands with sudo and provides access to potentially sensitive log data.

DO NOT expose this application to the public internet. Doing so would create a significant security risk. The sudoers configuration is designed to be as restrictive as possible, but any web-facing application with this level of privilege must be handled with extreme care.
