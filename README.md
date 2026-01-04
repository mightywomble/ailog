# AI Log Viewer - Multi-Host Log Analysis Platform

A comprehensive, modern web application for viewing and analyzing system logs from `/var/log` and `journalctl` across both **local** and **remote** servers. This advanced platform combines real-time log viewing, powerful search capabilities, AI-powered analysis, and proactive alerting in a sleek, responsive interface designed for developers and system administrators.

### ⚠️ Security Warning

This application is designed for use on a trusted, internal development network only. It runs commands with `sudo` on local and remote machines and provides access to potentially sensitive log data.

**DO NOT expose this application to the public internet.** Doing so would create a significant security risk. You must ensure that passwordless SSH key-based authentication is set up correctly and that the principle of least privilege is followed.

## 🚀 Key Features

### 📊 **Unified Log Management**
* **Multi-Source Access:** View traditional syslog files from `/var/log` and systemd journal entries in a unified interface
* **Cross-Platform Compatibility:** Works seamlessly across Linux distributions with systemd support
* **Automatic Decompression:** Handles `.gz` compressed log archives transparently

### 🌐 **Multi-Host Architecture**
* **Host Management Dashboard:** Intuitive interface for managing local and remote servers
* **SSH Connection Testing:** Built-in validation ensures proper SSH key setup and sudo permissions before adding hosts
* **Dynamic Host Switching:** Seamlessly switch between configured servers with real-time log loading
* **Connection Status Monitoring:** Visual indicators show host connectivity status

### 🔍 **Advanced Search Capabilities**
* **Global Search:** Search across all logs from all configured hosts simultaneously
* **Scoped Search:** Target specific log files or journal units for precise results
* **Case-Sensitive Options:** Fine-tune search behavior with case sensitivity controls
* **Real-Time Results:** Instant search results with highlighted matches and line numbers
* **Cross-Host Discovery:** Find log entries across your entire infrastructure from a single search

### 🤖 **AI-Powered Analysis**
* **On-Demand Analysis:** Manual log analysis using OpenAI's GPT models with intelligent error detection
* **Scheduled Monitoring:** Automated recurring analysis with customizable intervals
* **Multi-Host Scheduling:** Monitor logs across different servers with unified scheduling
* **Smart Alerting:** Proactive Discord notifications for detected issues and anomalies

### 📈 **Real-Time Progress Tracking**
* **Streaming Updates:** Server-Sent Events (SSE) provide real-time feedback during log loading
* **Progress Visualization:** Detailed progress bars and status messages for all operations
* **Error Recovery:** Automatic retry mechanisms for failed host connections
* **Performance Optimization:** Concurrent processing with timeout handling for reliable operations

### 🔒 **Security & Privacy**
* **Local Credential Storage:** API keys and webhooks stored securely in browser localStorage
* **SSH Key Authentication:** Passwordless SSH access with proper key-based security
* **Granular Sudo Permissions:** Minimal required permissions for enhanced security
* **Network Isolation:** Designed for trusted internal networks only

## 🛠 Installation & Setup

### System Requirements
* **Operating System:** Ubuntu 20.04+ / Debian 11+ / CentOS 8+ (systemd-based distributions)
* **Python:** 3.8 or higher
* **Memory:** 512MB+ RAM (1GB+ recommended for multiple hosts)
* **Network:** Internal network access to monitored hosts
* **SSH:** Key-based authentication configured for remote hosts

### Prerequisites

* A Linux server to host the AI Log Viewer application
* Non-root user with sudo privileges (we'll use `david` in examples - replace with your username)
* SSH key-based authentication configured for remote host access
* OpenAI API key for AI analysis features (optional but recommended)
* Discord webhook URL for notifications (optional)

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
The project includes a `requirements.txt` file with all necessary dependencies:

**requirements.txt**
```
Flask>=2.3.3
Werkzeug>=2.3.7
openai>=1.3.0
requests>=2.31.0
APScheduler>=3.10.4
```

Install the dependencies:
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

## 📖 Usage Guide

### Getting Started

Access the application at: `http://<your-server-ip>:5001`

The interface features a clean, modern design with:
- **Host sidebar** for server selection
- **Log list panel** showing available logs
- **Content viewer** for log analysis
- **Global search bar** for cross-host searches

### 🔧 Initial Setup

1. **Configure Credentials**:
   - Click the **Settings** ⚙️ icon in the header
   - Enter your **OpenAI API Key** for AI analysis
   - Add your **Discord Webhook URL** for notifications
   - Click **Save Credentials & Close**

2. **Add Remote Hosts**:
   - In Settings → **Remote Hosts** → **Add New**
   - Fill in host details:
     - **Friendly Name**: "Production Server", "Database Host", etc.
     - **IP Address**: Server IP or hostname
     - **SSH User**: Username for SSH access
     - **Description**: Optional host description
   - Click **Test Connection** to verify SSH and sudo access
   - On success (green indicator), click **Save Host**

### 🔍 Search Functionality

#### Global Search
1. Enter search terms in the top search bar
2. Select search scope:
   - **All logs**: Search across all hosts and log files
   - **Selected log only**: Search within currently viewed log
3. Toggle **Case sensitive** if needed
4. Click **Search** or press Enter

#### Search Features
- **Cross-host results**: Find logs from any configured server
- **Highlighted matches**: Search terms highlighted in results
- **Line numbers**: Exact line location for each match
- **Quick navigation**: Click results to jump to specific logs
- **Failed host handling**: Clear indicators for unreachable servers

### 📊 Log Management

#### Viewing Logs
1. **Select Host**: Choose from the host sidebar (localhost always available)
2. **Browse Logs**: Real-time loading with progress indicators
3. **View Content**: Click any log file or journal unit
4. **AI Analysis**: Use **AI Analyse** button for automated insights

#### Log Types
- **📄 File logs**: Traditional syslog files from `/var/log`
- **🔧 Journal entries**: systemd journal units via `journalctl`
- **📦 Compressed logs**: Automatic `.gz` decompression

### 🤖 AI Analysis & Monitoring

#### Manual Analysis
1. Load any log file or journal unit
2. Click **AI Analyse** (requires OpenAI API key)
3. View detailed analysis in popup modal
4. Automatic Discord alerts for detected issues

#### Scheduled Monitoring
1. **Settings** → **Select Logs for Schedule...**
2. **Cross-host selection**: Choose logs from multiple servers
3. **Set interval**: Configure analysis frequency (hours)
4. **Start monitoring**: Enable automated analysis
5. **Run Now**: Trigger immediate analysis of all monitored logs

### 📈 Advanced Features

#### Multi-Host Operations
- **Concurrent processing**: Parallel operations across multiple hosts
- **Retry mechanisms**: Automatic retry for failed connections
- **Progress tracking**: Real-time status for all operations
- **Error recovery**: Graceful handling of network issues

#### Performance Optimization
- **Streaming data**: Server-Sent Events for real-time updates
- **Caching**: Intelligent caching of host data
- **Timeout handling**: Configurable timeouts for reliability
- **Resource management**: Efficient memory usage for large logs

### 🚨 Troubleshooting

#### Common Issues
1. **Host connection failures**:
   - Verify SSH key authentication
   - Check sudo permissions (see sudoers configuration)
   - Ensure network connectivity

2. **Search not working**:
   - Check host connectivity in sidebar
   - Verify log file permissions
   - Look for timeout errors in browser console

3. **AI analysis errors**:
   - Validate OpenAI API key in Settings
   - Check API quota and billing
   - Ensure log content is not empty

#### Debug Information
The application provides detailed startup logs showing:
- Number of configured hosts loaded
- Host connection details
- Scheduler status and configuration
- Service startup confirmation

## 🏗️ Technical Architecture

### Backend (Flask)
- **Framework**: Flask with APScheduler for background tasks
- **APIs**: RESTful endpoints for log access, search, and host management
- **Streaming**: Server-Sent Events (SSE) for real-time progress updates
- **Concurrency**: ThreadPoolExecutor for parallel host operations
- **Security**: SSH key-based authentication with minimal sudo permissions

### Frontend (Vanilla JavaScript)
- **UI Framework**: Tailwind CSS for responsive design
- **Real-time Updates**: EventSource API for SSE communication
- **State Management**: Local storage for credentials and preferences
- **Progressive Enhancement**: Graceful degradation for network issues

### Data Flow
1. **Host Configuration**: JSON-based host storage with validation
2. **Log Discovery**: Parallel scanning across configured hosts
3. **Search Processing**: Distributed grep operations with result aggregation
4. **AI Analysis**: OpenAI API integration with Discord webhook notifications
5. **Scheduling**: APScheduler for automated monitoring tasks

## 📝 Recent Updates

### v2.1.0 - Advanced Search & Multi-Host Enhancements
- ✨ **Global Search**: Search across all logs from all hosts simultaneously
- 🎯 **Scoped Search**: Target specific logs or journal units
- 🔍 **Search Highlighting**: Visual highlighting of search terms in results
- 📊 **Progress Tracking**: Real-time progress for all operations
- 🔄 **Retry Mechanisms**: Automatic retry for failed host connections
- 🐛 **Bug Fixes**: Resolved const redeclaration issues and improved error handling
- 🎨 **UI Improvements**: Enhanced visual feedback and user experience

### v2.0.0 - Multi-Host Architecture
- 🌐 **Multi-Host Support**: Manage multiple remote servers from single interface
- 🔒 **SSH Integration**: Secure passwordless authentication
- ⚡ **Concurrent Processing**: Parallel operations across hosts
- 📈 **Streaming Updates**: Real-time progress with Server-Sent Events
- 🤖 **Cross-Host AI Monitoring**: Schedule analysis across multiple servers

### v1.0.0 - Initial Release
- 📄 **Log Viewing**: Basic syslog and journal viewing
- 🤖 **AI Analysis**: OpenAI-powered log analysis
- 🔔 **Discord Alerts**: Webhook notifications
- 📅 **Scheduling**: Automated monitoring capabilities

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests for any improvements.

### Development Setup
```bash
# Clone repository
git clone <your-repo-url>
cd ailog

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run development server
python3 app.py
```

### Testing
- Test with multiple host configurations
- Verify SSH key authentication
- Check sudo permissions on target hosts
- Test search functionality across different log types

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

**Security Notice**: This application is intended for use in trusted, internal networks only. It requires elevated permissions and SSH access to monitored systems. Ensure proper network isolation and access controls are in place.

**AI Analysis**: AI-powered analysis requires an OpenAI API key and usage may incur costs based on your OpenAI plan.

## 📞 Support

For issues, feature requests, or questions:
1. Check the troubleshooting section above
2. Review application logs for detailed error information
3. Open an issue on the project repository
4. Include system information and error logs for faster resolution
