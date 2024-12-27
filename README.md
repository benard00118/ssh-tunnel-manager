Here is your organized README file for the **SSH Tunnel Manager** project: 

```markdown
# SSH Tunnel Manager

A robust Python script for managing SSH tunnels with enhanced security, dynamic configuration reloading, and detailed logging.

---

## Features

- **Security Validation**: Ensures secure file permissions and path sanitization.
- **Dynamic Configuration**: Reloads configuration changes without restarting the application.
- **Logging**: Comprehensive logging with file rotation.
- **Metrics Tracking**: Tracks tunnel uptime, restarts, and other metrics.
- **Error Handling**: Custom exceptions with categorized errors for better troubleshooting.
- **Dependency Checking**: Verifies necessary tools like `ssh` and `autossh` are available.

---

## Prerequisites

- Python 3.8 or newer
- `ssh` client (OpenSSH)
- `autossh` for managing persistent SSH tunnels

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/benard00118/ssh-tunnel-manager
   cd ssh-tunnel-manager
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Setup Configuration:
   - Create or edit `tunnel_config.ini` in the project directory with your SSH details and tunnel configurations.  
   - Here's an example structure:
     ```ini
     [SSH]
     remote_host = your.remote.server
     remote_user = username
     identity_file = ~/.ssh/id_rsa
     keepalive_interval = 60
     compression = yes
     compression_level = 6
     log_level = INFO
     log_max_size = 5000000
     log_backup_count = 5
     max_retries = 10
     retry_initial_delay = 1
     retry_max_delay = 300
     process_poll_interval = 1
     cleanup_timeout = 5

     [Tunnel:example_tunnel]
     local_port = 22
     remote_port = 2222
     enabled = yes
     ```

4. Permissions:
   - Ensure your SSH key file (`identity_file`) has permissions set to `600` and is owned by the user running this script.
   - The configuration file should have permissions no more permissive than `644`.

---

## Running the Script

To start managing SSH tunnels:

```bash
python main.py
```

Or if you've named your script differently:

```bash
python your_script_name.py
```

---

## Monitoring

- Logs are stored in the `logs/` directory with daily rotation.
- Metrics are saved to `logs/tunnel_metrics.json`.

---

## Contributing

1. Fork the repository.
2. Create your feature branch:
   ```bash
   git checkout -b feature/AmazingFeature
   ```
3. Commit your changes:
   ```bash
   git commit -m 'Add some AmazingFeature'
   ```
4. Push to the branch:
   ```bash
   git push origin feature/AmazingFeature
   ```
5. Open a pull request.

---

Enjoy seamless SSH tunnel management!
```
