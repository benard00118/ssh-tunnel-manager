import unittest
from unittest.mock import patch, MagicMock, mock_open
import os
import subprocess
import json
from pathlib import Path
from datetime import datetime
import time

from ossh import ConfigManager, TunnelManager, TunnelMetrics, SSHTunnelException

class TestConfigManager(unittest.TestCase):
    def setUp(self):
        self.sample_config = """
[SSH]
remote_host = test.server
remote_user = testuser
identity_file = ~/.ssh/id_rsa
keepalive_interval = 60

[Tunnel:test1]
local_port = 8080
remote_port = 80
enabled = yes

[Tunnel:test2]
local_port = 5432
remote_port = 5432
enabled = no
"""

    @patch('pathlib.Path.exists')
    @patch('builtins.open', new_callable=mock_open)
    def test_load_valid_config(self, mock_file, mock_exists):
        mock_exists.return_value = True
        mock_file.return_value.read.return_value = self.sample_config
        
        config_manager = ConfigManager('test_config.ini')
        
        self.assertEqual(config_manager.config['remote_host'], 'test.server')
        self.assertEqual(len(config_manager.config['tunnels']), 2)
        self.assertEqual(config_manager.config['tunnels']['test1']['local_port'], '8080')

    def test_config_reload(self):
        config_manager = ConfigManager('test_config.ini')
        config_manager.last_modified = 0
        
        with patch('pathlib.Path.stat') as mock_stat:
            mock_stat.return_value.st_mtime = 1  # Simulate modification time change
            
            self.assertTrue(config_manager.check_reload())

class TestTunnelManager(unittest.TestCase):
    @patch('subprocess.Popen')
    def test_start_tunnel(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        
        config_manager = ConfigManager('test_config.ini')
        config_manager.config = {
            'SSH': {
                'remote_host': 'test.server',
                'remote_user': 'testuser',
                'identity_file': '~/.ssh/id_rsa',
                'keepalive_interval': '60'
            },
            'tunnels': {
                'test1': {
                    'local_port': '8080',
                    'remote_port': '80',
                    'enabled': 'yes'
                }
            }
        }
        
        tunnel_manager = TunnelManager(config_manager)
        tunnel_manager._start_tunnel('test1')
        
        mock_popen.assert_called_once()
        self.assertIn('test1', tunnel_manager.metrics.active_tunnels)

    @patch('subprocess.Popen')
    def test_build_tunnel_command(self, mock_popen):
        config_manager = ConfigManager('test_config.ini')
        config_manager.config = {
            'remote_host': 'test.server',
            'remote_user': 'testuser',
            'identity_file': '~/.ssh/id_rsa',
            'keepalive_interval': '60',
            'compression': 'yes',
            'compression_level': '6'
        }
        
        tunnel_manager = TunnelManager(config_manager)
        tunnel_config = {
            'local_port': '8080',
            'remote_port': '80'
        }
        
        cmd = tunnel_manager._build_tunnel_command('test1', tunnel_config)
        
        self.assertTrue(any('-C' in arg for arg in cmd))
        self.assertTrue(any('CompressionLevel=6' in arg for arg in cmd))
        self.assertTrue(any('8080' in arg for arg in cmd))

    @patch('time.sleep', return_value=None)
    def test_monitor_tunnels(self, mock_sleep):
        config_manager = ConfigManager('test_config.ini')
        tunnel_manager = TunnelManager(config_manager)
        mock_process = MagicMock()
        mock_process.poll.return_value = 1
        
        tunnel_manager.processes = {'test1': mock_process}
        tunnel_manager.metrics.active_tunnels.add('test1')
        
        with patch.object(tunnel_manager, '_stop_tunnel') as mock_stop:
            with patch.object(tunnel_manager, '_start_tunnel') as mock_start:
                tunnel_manager._monitor_tunnels()
                
                mock_stop.assert_called_once_with('test1')
                mock_start.assert_called_once_with('test1')
                self.assertEqual(tunnel_manager.metrics.total_retries, 1)

class TestTunnelMetrics(unittest.TestCase):
    def test_metrics_conversion(self):
        metrics = TunnelMetrics(start_time=time.time())
        metrics.total_retries = 5
        metrics.current_uptime = 300
        metrics.total_uptime = 3600
        metrics.active_tunnels.add('test1')
        
        metrics_dict = metrics.to_dict()
        
        self.assertEqual(metrics_dict['total_retries'], 5)
        self.assertEqual(metrics_dict['current_uptime_seconds'], 300)
        self.assertEqual(metrics_dict['total_uptime_seconds'], 3600)
        self.assertEqual(metrics_dict['active_tunnels'], ['test1'])

class TestSecurity(unittest.TestCase):
    @patch('os.path.expanduser', return_value='/home/user')
    def test_validate_path(self, mock_expanduser):
        # Test path traversal attempts
        with self.assertRaises(SSHTunnelException):
            ConfigManager._validate_path('/etc/passwd')
        
        with self.assertRaises(SSHTunnelException):
            ConfigManager._validate_path('/root/.ssh/id_rsa')
            
    def test_validate_ports(self):
        # Test invalid port numbers
        with self.assertRaises(SSHTunnelException):
            ConfigManager._validate_port('-1')
        
        with self.assertRaises(SSHTunnelException):
            ConfigManager._validate_port('65536')

if __name__ == '__main__':
    unittest.main()