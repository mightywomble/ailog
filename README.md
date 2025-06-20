Local Log File Viewer & AI AnalyserA simple, modern web application for viewing local log files from /var/log with the power of AI analysis. This tool provides an elegant and efficient interface for developers and system administrators to monitor logs directly from their web browser, without needing to SSH into a machine.Built with Flask and styled with Tailwind CSS, it offers a clean, responsive UI that includes dynamic filtering, sorting, and on-the-fly decompression of .gz archives. Its standout feature is the one-click integration with the OpenAI API, allowing you to get an AI-powered summary, error analysis, and troubleshooting tips for your logs.FeaturesReal-time Log Viewing: View log files from /var/log in a clean, readable format.AI-Powered Analysis: Send log contents to the OpenAI API for a detailed analysis with a single click.Gzip Decompression: Automatically decompresses and displays .gz log archives on the fly.Dynamic Filtering: Instantly search and filter the log file list.Smart Sorting: Sort logs by name, size, or modification date.Secure API Key Storage: API key is managed via a settings menu and stored securely in the browser's local storage.Intelligent Truncation: Automatically shortens oversized logs before sending for analysis to prevent API errors.Modern UI: A beautiful and responsive interface built with Tailwind CSS.Installation & Setup on Ubuntu 24.04This guide provides complete instructions for setting up the application and running it as a systemd service on a fresh Ubuntu 24.04 server.PrerequisitesAn Ubuntu 24.04 server.A non-root user with sudo privileges. We will use the username david in this guide; be sure to replace david with your actual username in all commands.Step 1: Install System DependenciesFirst, update your package list and install Python, pip, and the virtual environment module.sudo apt update
sudo apt install python3-pip python3.12-venv -y
Step 2: Set Up Project Directory and Clone RepoCreate a directory for the application and clone the project repository into it.# Create the parent directory
mkdir ~/code
cd ~/code

# Clone your repository (replace with your actual repo URL)
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name
Step 3: Create Python Virtual Environment & Install RequirementsIt's best practice to run a Python application in a virtual environment to isolate its dependencies.# Create the virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate

# Before installing, create a requirements.txt file
Create a file named requirements.txt in your project directory with the following content:# requirements.txt
Flask
openai
Now, install these requirements using pip.# Install the Python libraries
pip install -r requirements.txt
Step 4: Configure Passwordless Sudo AccessThe application uses sudo to read system logs. To allow the application to run without asking for a password, you must grant passwordless access to the specific commands it needs. This is a critical security step.Open the sudoers file for editing using visudo. This is the safest way to edit this file.sudo visudo
Scroll to the bottom of the file and add the following line. Remember to replace david with your username.# Allow the 'david' user to run specific log-reading commands without a password
david ALL=(ALL) NOPASSWD: /usr/bin/ls /var/log, /usr/bin/stat -c %s %Y /var/log/*, /usr/bin/tail -n 500 /var/log/*, /usr/bin/zcat /var/log/*.gz
Save and exit the editor. In nano (the default), this is Ctrl+X, then Y, then Enter.Step 5: Set Up the Systemd ServiceTo ensure the application runs automatically and restarts on failure, we will create a systemd service for it.Create a new service file using a text editor like nano.sudo nano /etc/systemd/system/logviewer.service
Paste the following configuration into the file. Crucially, you must replace david with your username in the User and ExecStart lines.[Unit]
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
Save and close the file.Step 6: Start and Enable the ServiceNow, reload the systemd daemon to recognize the new service, then start and enable it.# Reload the systemd daemon
sudo systemctl daemon-reload

# Start the logviewer service
sudo systemctl start logviewer

# Enable the service to start automatically on boot
sudo systemctl enable logviewer
Step 7: Verify the Service is RunningYou can check the status of the service to make sure it's active and running without errors.sudo systemctl status logviewer
You should see an output indicating that the service is active (running).UsageOnce the service is running, you can access the application by navigating to your server's IP address on port 5001 in your web browser:http://<your-server-ip>:5001To use the AI analysis feature:Click the Settings (gear) icon in the top right.Enter your OpenAI API Key and click Save. The key is stored in your browser's local storage and will be remembered.Select a log file and click the AI Analyse button.⚠️ Security WarningThis application is designed for use on a trusted, internal development network only. By its nature, it runs commands with sudo and provides access to potentially sensitive log data.DO NOT expose this application to the public internet. Doing so would create a significant security risk. The sudoers configuration is designed to be as restrictive as possible, but any web-facing application with this level of privilege should be handled with extreme care.
