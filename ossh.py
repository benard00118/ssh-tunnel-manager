#!/usr/bin/env python3
import os
import sys
import time
import json
import shutil
import socket
import signal
import logging
import subprocess
import configparser
from typing import Optional, Dict, Any, List, Set
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass
import unittest.mock
from concurrent.futures import ThreadPoolExecutor
import stat
import re
from typing import Union


class SSHTunnelException(Exception):
    """Custom exception for SSH tunnel errors with error categories."""
    def __init__(self, message: str, category: str = "general"):
        self.category = category
        super().__init__(message)

class SecurityValidator:
    """Security validation utilities for SSH tunnel configuration."""
    
    @staticmethod
    def validate_path(path: str) -> Path:
        """
        Validate and normalize file paths, preventing directory traversal.
        
        Args:
            path: File path to validate as a string.
            
        Returns:
            Normalized Path object.
            
        Raises:
            SSHTunnelException: If path validation fails.
        """
        try:
            normalized_path = Path(os.path.expanduser(path)).resolve()
            
            # Check for directory traversal attempts
            if not normalized_path.is_relative_to(Path.home()):
                raise SSHTunnelException("Path is outside of home directory", category="security")
                
            return normalized_path
            
        except Exception as e:
            raise SSHTunnelException(f"Invalid path: {str(e)}", category="security")

    @staticmethod
    def validate_ssh_key_permissions(key_path: Path) -> None:
        """
        Verify SSH key file has correct permissions.
        
        Args:
            key_path: Path to SSH key file.
            
        Raises:
            SSHTunnelException: If permissions are incorrect.
        """
        try:
            stat_info = key_path.stat()
            
            # Check file ownership
            if stat_info.st_uid != os.getuid():
                raise SSHTunnelException(f"SSH key {key_path} must be owned by the current user", category="security")
            
            # Check permissions (600 or stricter)
            if stat_info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise SSHTunnelException(f"SSH key {key_path} has too permissive mode {stat_info.st_mode & 0o777:o}. Should be 600 or stricter", category="security")
                
        except FileNotFoundError:
            raise SSHTunnelException(f"SSH key file not found: {key_path}", category="security")

    @staticmethod
    def validate_port(port: Union[str, int]) -> int:
        """
        Validate port number.
        
        Args:
            port: Port number to validate.
            
        Returns:
            Validated port number.
            
        Raises:
            SSHTunnelException: If port is invalid.
        """
        try:
            port_num = int(port)
            if not 1 <= port_num <= 65535:
                raise ValueError("Port out of range")
            return port_num
        except ValueError as e:
            raise SSHTunnelException(f"Invalid port number {port}: {str(e)}", category="security")

    @staticmethod
    def sanitize_hostname(hostname: str) -> str:
        """
        Sanitize and validate hostname.
        
        Args:
            hostname: Hostname to validate.
            
        Returns:
            Sanitized hostname.
            
        Raises:
            SSHTunnelException: If hostname is invalid.
        """
        hostname_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
        
        if not hostname_pattern.match(hostname):
            raise SSHTunnelException(f"Invalid hostname format: {hostname}", category="security")
        
        return hostname

    @staticmethod
    def validate_config_permissions(config_path: Path) -> None:
        """
        Verify configuration file has secure permissions.
        
        Args:
            config_path: Path to configuration file.
            
        Raises:
            SSHTunnelException: If permissions are incorrect.
        """
        try:
            stat_info = config_path.stat()
            
            # Check file ownership
            if stat_info.st_uid != os.getuid():
                raise SSHTunnelException(f"Config file {config_path} must be owned by the current user", category="security")
            
            # Check permissions (644 or stricter)
            if stat_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise SSHTunnelException(f"Config file {config_path} has too permissive mode {stat_info.st_mode & 0o777:o}. Should be 644 or stricter", category="security")
                
        except FileNotFoundError:
            raise SSHTunnelException(f"Configuration file not found: {config_path}", category="security")

@dataclass
class TunnelMetrics:
    """Store metrics for tunnel monitoring."""
    start_time: float
    total_retries: int = 0
    current_uptime: float = 0
    total_uptime: float = 0
    last_reload: float = 0
    active_tunnels: Set[str] = None

    def __post_init__(self):
        self.active_tunnels = set()

    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary for reporting."""
        current_time = time.time()
        return {
            'start_time': datetime.fromtimestamp(self.start_time).isoformat(),
            'uptime_seconds': int(current_time - self.start_time),
            'current_uptime_seconds': int(self.current_uptime),
            'total_uptime_seconds': int(self.total_uptime),
            'total_retries': self.total_retries,
            'last_reload': datetime.fromtimestamp(self.last_reload).isoformat(),
            'active_tunnels': list(self.active_tunnels)
        }

class ConfigManager:
    """Handle tunnel configuration with dynamic reloading."""
    def __init__(self, config_file: str):
        self.config_file = Path(config_file)
        self.last_modified = 0
        self.config: Dict[str, Any] = {}
        self.load_config()

    def load_config(self) -> None:
        """Load configuration from file."""
        if not self.config_file.exists():
            self._create_default_config()
            raise SSHTunnelException(f"Default configuration created at {self.config_file}. Please edit before running.", category="configuration")

        parser = ConfigParser()
        with open(self.config_file, 'r') as config_file:
            parser.read_file(config_file)
        self.config = self._parse_config(parser)
        self.last_modified = self.config_file.stat().st_mtime

    def check_reload(self) -> bool:
        """Check if configuration file has been modified."""
        try:
            current_mtime = self.config_file.stat().st_mtime
            if current_mtime > self.last_modified:
                self.load_config()
                return True
        except Exception as e:
            logging.warning(f"Failed to check configuration: {e}")
        return False

    def _parse_config(self, parser: ConfigParser) -> Dict[str, Any]:
        """Parse and validate configuration sections."""
        config = {}
        
        # Parse main SSH section
        if 'SSH' not in parser:
            raise SSHTunnelException("Missing required SSH section in config", category="configuration")
        
        config.update(dict(parser['SSH']))
        
        # Parse additional tunnel sections
        tunnels = {}
        for section in parser.sections():
            if section.startswith('Tunnel:'):
                tunnel_name = section.split(':', 1)[1]
                tunnels[tunnel_name] = dict(parser[section])
        
        config['tunnels'] = tunnels
        return config

    def _create_default_config(self) -> None:
        """Create detailed default configuration file."""
        config = ConfigParser()
        
        # Main SSH configuration
        config['SSH'] = {
            'remote_host': 'your.remote.server',
            'remote_user': 'username',
            'identity_file': '~/.ssh/id_rsa',
            'keepalive_interval': '60',
            'compression': 'yes',
            'compression_level': '6',
            'allowed_remote_ips': '127.0.0.1,localhost',
            'log_level': 'INFO',
            'log_max_size': '5000000',
            'log_backup_count': '5',
            'max_retries': '10',
            'retry_initial_delay': '1',
            'retry_max_delay': '300',
            'process_poll_interval': '1',
            'cleanup_timeout': '5'
        }
        
        # Example tunnel configuration
        config['Tunnel:example'] = {
            'local_port': '22',
            'remote_port': '2222',
            'enabled': 'yes'
        }
        
        with open(self.config_file, 'w') as f:
            config.write(f)

class TunnelManager:
    """Manage SSH tunnels."""
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.metrics = TunnelMetrics(start_time=time.time())
        self.logger = self._setup_logging()
        self.processes: Dict[str, subprocess.Popen] = {}

    def _setup_logging(self) -> logging.Logger:
        """Setup enhanced logging with rotation."""
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / f'ssh_tunnel_{datetime.now().strftime("%Y%m%d")}.log'
        log_level = getattr(logging, self.config_manager.config.get('log_level', 'INFO').upper())
        
        logger = logging.getLogger('SSHTunnel')
        logger.setLevel(log_level)
        
        logger.handlers = []
        
        # File handler with rotation
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=int(self.config_manager.config.get('log_max_size', 5_000_000)),
            backupCount=int(self.config_manager.config.get('log_backup_count', 5))
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - [%(name)s] - %(message)s')
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger

    def check_dependencies(self) -> None:
        """Enhanced dependency checking with version verification."""
        def check_version(command: List[str]) -> str:
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=5)
                return result.stdout or result.stderr
            except Exception as e:
                raise SSHTunnelException(f"Failed to check version: {e}", category="dependency")

        # Check SSH version
        if not shutil.which('ssh'):
            raise SSHTunnelException("ssh is not installed. Please install OpenSSH client.", category="dependency")
        ssh_version = check_version(['ssh', '-V'])
        self.logger.info(f"Found SSH: {ssh_version.strip()}")

        # Check autossh version
        if not shutil.which('autossh'):
            raise SSHTunnelException("autossh is not installed. Please install autossh.", category="dependency")
        autossh_version = check_version(['autossh', '-V'])
        self.logger.info(f"Found autossh: {autossh_version.strip()}")

    def manage_tunnels(self) -> None:
        """Manage SSH tunnels based on configuration."""
        self.check_dependencies()
        
        while True:
            try:
                # Check for configuration changes
                if self.config_manager.check_reload():
                    self.logger.info("Configuration changed, updating tunnels...")
                    self._update_tunnels()

                # Monitor and maintain active tunnels
                self._monitor_tunnels()

                # Update metrics
                self._update_metrics()

                # Sleep briefly
                time.sleep(float(self.config_manager.config.get('process_poll_interval', 1)))

            except KeyboardInterrupt:
                self.logger.info("Received keyboard interrupt...")
                break
            except Exception as e:
                self.logger.error(f"Error in main loop: {e}")
                time.sleep(1)

        self._cleanup()

    def _update_tunnels(self) -> None:
        """Update running tunnels based on current configuration."""
        config_tunnels = {name for name, conf in self.config_manager.config['tunnels'].items() if conf.get('enabled', '').lower() == 'yes'}
        
        # Stop tunnels that are no longer configured
        for name in list(self.processes.keys()):
            if name not in config_tunnels:
                self._stop_tunnel(name)
        
        # Start new tunnels
        for name in config_tunnels:
            if name not in self.processes:
                self._start_tunnel(name)

    def _start_tunnel(self, name: str) -> None:
        """Start a new tunnel process."""
        tunnel_config = self.config_manager.config['tunnels'][name]
        
        cmd = self._build_tunnel_command(name, tunnel_config)
        
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.processes[name] = process
            self.metrics.active_tunnels.add(name)
            self.logger.info(f"Started tunnel: {name}")
        except Exception as e:
            self.logger.error(f"Failed to start tunnel {name}: {e}")

    def _stop_tunnel(self, name: str) -> None:
        """Stop a running tunnel process."""
        if name in self.processes:
            try:
                process = self.processes[name]
                process.terminate()
                try:
                    process.wait(timeout=float(self.config_manager.config.get('cleanup_timeout', 5)))
                except subprocess.TimeoutExpired:
                    process.kill()
                
                del self.processes[name]
                self.metrics.active_tunnels.remove(name)
                self.logger.info(f"Stopped tunnel: {name}")
            except Exception as e:
                self.logger.error(f"Error stopping tunnel {name}: {e}")

    def _build_tunnel_command(self, name: str, tunnel_config: Dict[str, str]) -> List[str]:
        """Build command for tunnel process."""
        cmd = [
            'autossh',
            '-M', '0',
            '-N',
            '-i', os.path.expanduser(self.config_manager.config['identity_file']),
            '-o', 'StrictHostKeyChecking=yes',
            '-o', 'PasswordAuthentication=no',
            '-o', f"ServerAliveInterval={self.config_manager.config['keepalive_interval']}",
            '-o', 'ExitOnForwardFailure=yes',
            '-o', 'ControlMaster=no',
            '-R', f"{tunnel_config['remote_port']}:localhost:{tunnel_config['local_port']}"
        ]

        if self.config_manager.config.get('compression', '').lower() == 'yes':
            cmd.extend([
                '-C',
                '-o', f"CompressionLevel={self.config_manager.config['compression_level']}"
            ])

        cmd.append(f"{self.config_manager.config['remote_user']}@{self.config_manager.config['remote_host']}")
        
        return cmd

    def _monitor_tunnels(self) -> None:
        """Monitor and maintain tunnel processes."""
        for name, process in list(self.processes.items()):
            if process.poll() is not None:
                self.logger.warning(f"Tunnel {name} has died, restarting...")
                self._stop_tunnel(name)
                self._start_tunnel(name)
                self.metrics.total_retries += 1

    def _update_metrics(self) -> None:
        """Update tunnel metrics."""
        current_time = time.time()
        self.metrics.current_uptime = current_time - self.metrics.start_time
        self.metrics.total_uptime += float(self.config_manager.config.get('process_poll_interval', 1))
        
        # Write metrics to file
        metrics_file = Path('logs/tunnel_metrics.json')
        try:
            with open(metrics_file, 'w') as f:
                json.dump(self.metrics.to_dict(), f, indent=2)
        except Exception as e:
            self.logger.warning(f"Failed to write metrics: {e}")

    def _cleanup(self) -> None:
        """Enhanced cleanup process."""
        self.logger.info("Starting cleanup process...")
        
        # Stop all tunnels
        for name in list(self.processes.keys()):
            self._stop_tunnel(name)
        
        self.logger.info("Cleanup completed")

def main():
    """Main function to run the SSH tunneling application."""
    try:
        config_manager = ConfigManager('tunnel_config.ini')
        tunnel_manager = TunnelManager(config_manager)
        tunnel_manager.manage_tunnels()
    except SSHTunnelException as e:
        logging.error(f"SSH Tunnel Error:\n{str(e)}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error:\n{str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()