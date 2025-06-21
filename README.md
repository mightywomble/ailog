# Local & Remote Log Viewer with AI Analysis

An advanced, modern web application for viewing system logs from `/var/log` and `journalctl` on both the **local** machine and **remote** servers via **SSH**. This tool is supercharged with both manual and scheduled AI analysis and proactive Discord alerting, providing a powerful, elegant interface for developers and system administrators to monitor logs directly from their web browser.

### ⚠️ Security Warning

This application is designed for use on a trusted, internal development network only. It runs commands with `sudo` on local and remote machines and provides access to potentially sensitive log data.

**DO NOT expose this application to the public internet.** Doing so would create a significant security risk. You must ensure that passwordless SSH key-based authentication is set up correctly and that the principle of least privilege is followed.

### Key Features

* **Unified Log Access:** View traditional logs from `/var/log` and `journalctl` logs for systemd services in a single interface.
* **Multi-Host Management:**
    * Seamlessly switch between `localhost` and any number of configured remote servers from a dropdown menu.
    * Add, edit, and delete remote hosts with friendly names, IP addresses, SSH users, and descriptions.
    * **SSH Connection Testing:** A built-in test button verifies the SSH connection and `sudo` access to a remote server *before* adding it, ensuring a correct configuration.
* **Streaming Log Loading:**
    * When connecting to a host, a progress bar provides real-time feedback as logs are discovered and loaded.
    * Syslog files are loaded first for a fast, responsive UI, while slower `journalctl` services are loaded in the background.
* **Scheduled AI Monitoring:**
    * Select specific logs from **any configured host** and set a recurring interval (in hours) for automatic AI analysis.
    * The scheduler is now aware of remote hosts and will execute analysis on the correct machine.
* **Proactive Discord Alerts:** Automatically sends a rich, formatted notification to a Discord channel via webhook if the manual or scheduled AI analysis detects keywords like "error", "issue", or "warning".
* **On-Demand Analysis:** Trigger an immediate analysis of all monitored logs with a single "Run Now" button.
* **Dynamic UI:**
    * Filter the view to show only syslog files, only journald services, or all sources combined.
    * Sort logs by name, size, or modification date.
* **Gzip Decompression:** Automatically decompresses and displays `.gz` log archives on the fly.
* **Secure Credential Storage:** OpenAI API keys and Discord webhooks are stored securely in the browser's local storage and are never transmitted to the server except when making direct API calls.

### Installation & Setup on Ubuntu 24.04

This guide provides complete instructions for setting up the application and running it as a `systemd` service.

#### Prerequisites

* An Ubuntu 24.04 server (or any Debian-based system) to run the Log Viewer application.
* A non-root user with `sudo` privileges. We will use `david` in this guide; be sure to replace `david` with your actual username in all commands.
* Passwordless SSH key access from the Log Viewer server to any remote hosts you wish to monitor.

#### Step 1: Install System Dependencies

Update your package list and install Python, pip, and the virtual environment module.
```bash
sudo apt update
sudo apt install python3-pip python3.12-venv -y
```

#### Step 2: Set Up Project Directory and Clone Repo

Create a directory for the application and clone the project repository into it.
```bash
mkdir -p ~/code
cd ~/code
git clone [https://github.com/your-username/your-repo-name.git](https://github.com/your-username/your-repo-name.git)
cd your-repo-name
```

#### Step 3: Create Python Virtual Environment & Install Requirements

It's best practice to run a Python application in a virtual environment.
```bash
python3 -m venv venv
source venv/bin/activate
```
Create a file named `requirements.txt` in your project directory with the following content:

**requirements.txt**
```
Flask
openai
requests
APScheduler
```
Now, install these requirements using pip.
```bash
pip install -r requirements.txt
```

#### Step 4: Configure Passwordless `sudo` Access

For the application to read logs, the user running it needs passwordless `sudo` access **for the specific commands required**.

**This** configuration must be applied to every machine **the Log Viewer will access (including `localhost` and all remote servers).**

1.  On each server, open the sudoers file for editing using `visudo`. This is the safest way to edit this file.

    ```bash
    sudo visudo
    ```

2.  Scroll to the bottom of the file and add the following line. Remember to replace `david` with the username that will be used for SSH/local access on that specific machine.

    ```
    # Allow the 'david' user to run specific log-reading commands without a password
    david ALL=(ALL) NOPASSWD: /usr/bin/ls -p /var/log, /usr/bin/stat -c %s %Y /var/log/*, /usr/bin/tail -n 500 /var/log/*, /usr/bin/zcat /var/log/*.gz, /usr/bin/journalctl --field _SYSTEMD_UNIT, /usr/bin/journalctl -u * -n 500 --no-pager
    ```

3.  Save and exit the editor (`Ctrl+X`, then `Y`, then `Enter`).

#### Step 5: Set Up the Systemd Service

Create a `systemd` service on the main Log Viewer server to ensure the application runs automatically on boot.

1.  Create a new service file:

    ```bash
    sudo nano /etc/systemd/system/logviewer.service
    ```

2.  Paste the following configuration into the file. Crucially, replace `david` with your username and `your-repo-name` with your project's directory name.

    ```ini
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
    ```

3.  Save and close the file.

#### Step 6: Start and Enable the Service

Reload the `systemd` daemon, then start and enable the service.
```bash
sudo systemctl daemon-reload
sudo systemctl start logviewer
sudo systemctl enable logviewer
```

#### Step 7: Verify the Service is Running

Check the status of the service to ensure it's active.
```bash
sudo systemctl status logviewer
```
You should see output indicating the service is `active (running)`.

### Usage

Once the service is running, access the application by navigating to your server's IP address on port `5001`: `http://<your-server-ip>:5001`

1.  **Initial Configuration**:
    * Click the **Settings** (gear) icon in the top right.
    * In the **Credentials** section, enter your OpenAI API Key and Discord Webhook URL.
    * Click **Save Credentials & Close**. These are stored in your browser's local storage.

2.  **Managing Remote Hosts**:
    * In Settings, click the **Add New** button in the **Remote Hosts** panel.
    * Fill in the **Friendly Name** (e.g., "Web Server 1"), IP Address, and SSH User.
    * Click the yellow **Test Connection** button. The app will attempt to SSH and run a `sudo` command.
        * On success, the button will turn green. You can now click **Add Host**.
        * On failure, an error will be displayed. You must fix the issue (e.g., SSH keys, `sudoers` permissions) and re-test.
    * Existing hosts can be edited or deleted from the list in the Settings panel.

3.  **Viewing and Analyzing Logs**:
    * Select the desired server from the **Host** dropdown in the header.
    * The log list will load with a progress bar.
    * Click on any log or service to view its content.
    * Click the **AI Analyse** button for an on-demand analysis.

4.  **Scheduled Monitoring**:
    * In Settings, click the **Select Logs for Schedule...** button.
    * The selection modal will show logs for the currently selected host in the main UI.
    * Check the logs you wish to monitor and click **Confirm Selections**. Your selections are saved per-host.
