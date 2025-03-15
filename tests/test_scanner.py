import pytest
from unittest.mock import patch, MagicMock
from src.core.scanner import NetworkScanner, HostInfo, ScannerError
from src.utils.config_manager import ConfigManager
import platform
import subprocess
import ipaddress
from tqdm import tqdm

class TestNetworkScanner:
    @pytest.fixture
    def config_manager(self):
        """Fixture que fornece um mock do ConfigManager para os testes"""
        mock_config = MagicMock(spec=ConfigManager)
        
        # Configura o mock com valores padrão necessários
        mock_config._config = {
            'scan_profiles': {
                'basic': {
                    'name': 'Basic Scan',
                    'options': ['-sn'],
                    'ports': '80,443,22,3389',
                    'timing': 3
                },
                'stealth': {
                    'name': 'Stealth Scan',
                    'options': ['-sS', '-Pn'],
                    'ports': '1-1024',
                    'timing': 2
                }
            },
            'timeouts': {
                'discovery': 30,
                'port_scan': 180
            }
        }
        
        mock_config.get_scan_profile.side_effect = lambda profile: mock_config._config['scan_profiles'].get(profile)
        mock_config.get_timeout.side_effect = lambda key: mock_config._config['timeouts'].get(key)
        
        return mock_config

    @pytest.fixture
    def scanner(self, config_manager):
        """Fixture que fornece uma instância do NetworkScanner com mock do ConfigManager"""
        scanner = NetworkScanner("nmap")
        scanner.config_manager = config_manager
        return scanner

    def test_scan_network_success(self, scanner):
        mock_discovery = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                hostname="router.local",
                mac="00:11:22:33:44:55",
                vendor="Test Vendor"
            )
        }
        
        with patch.object(scanner, '_discovery_scan', return_value=mock_discovery):
            result = scanner.scan_network("192.168.1.0/24")
            assert len(result) == 1
            assert "192.168.1.1" in result
            assert result["192.168.1.1"].hostname == "router.local"

    def test_scan_network_empty(self, scanner):
        with patch.object(scanner, '_discovery_scan', return_value={}):
            with patch.object(scanner, '_fallback_discovery', return_value={}):
                result = scanner.scan_network("192.168.1.0/24")
                assert len(result) == 0

    def test_scan_network_error(self, scanner):
        with patch.object(scanner, '_discovery_scan', side_effect=Exception("Test error")):
            with patch.object(scanner, '_fallback_discovery', side_effect=Exception("Fallback error")):
                with pytest.raises(ScannerError) as exc_info:
                    scanner.scan_network("192.168.1.0/24")
                assert str(exc_info.value) == "Both discovery methods failed"

    def test_discovery_scan_output_parsing(self, scanner):
        mock_output = """
Nmap scan report for router.local (192.168.1.1)
Host is up (0.0050s latency).
MAC Address: 00:11:22:33:44:55 (Vendor Corp)
Nmap scan report for 192.168.1.2
Host is up (0.0050s latency).
MAC Address: AA:BB:CC:DD:EE:FF (Other Vendor)
"""
        with patch("subprocess.Popen") as mock_popen:
            mock_process = MagicMock()
            mock_process.communicate.return_value = (mock_output, "")
            mock_process.returncode = 0
            mock_popen.return_value = mock_process
            mock_popen.return_value.communicate.return_value = (mock_output, "")
            mock_popen.return_value.returncode = 0

            result = scanner._discovery_scan("192.168.1.0/24")
            assert "192.168.1.1" in result
            assert result["192.168.1.1"].mac == "00:11:22:33:44:55"
            assert result["192.168.1.1"].vendor == "Vendor Corp"
            assert "192.168.1.2" in result
            assert result["192.168.1.2"].mac == "AA:BB:CC:DD:EE:FF"
            assert result["192.168.1.2"].vendor == "Other Vendor"

    def test_detailed_scan_success(self, scanner):
        mock_output = """
Nmap scan report for 192.168.1.1
Host is up (0.025s latency).
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41
443/tcp open  https   nginx 1.18.0
"""
        target_ips = {"192.168.1.1"}
        
        with patch("subprocess.Popen") as mock_popen:
            mock_process = MagicMock()
            mock_process.communicate.return_value = (mock_output, "")
            mock_process.returncode = 0
            mock_popen.return_value = mock_process
            mock_popen.return_value.communicate.return_value = (mock_output, "")
            mock_popen.return_value.returncode = 0
            
            with patch.object(scanner, '_discovery_scan', return_value={"192.168.1.1": HostInfo(ip="192.168.1.1")}):
                result = scanner.detailed_scan(target_ips)
                
                assert "192.168.1.1" in result
                assert len(result["192.168.1.1"].ports) == 2
                assert "80/tcp" in result["192.168.1.1"].ports
                assert "443/tcp" in result["192.168.1.1"].ports
                assert any("Apache" in service for service in result["192.168.1.1"].services)
                assert any("nginx" in service for service in result["192.168.1.1"].services)

    def test_detailed_scan_output_parsing(self, scanner):
        mock_output = """
Nmap scan report for 192.168.1.1
Host is up (0.025s latency).
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41
443/tcp open  https   nginx 1.18.0
"""
        target_ips = {"192.168.1.1"}
        
        with patch("subprocess.Popen") as mock_popen:
            mock_process = MagicMock()
            mock_process.communicate.return_value = (mock_output, "")
            mock_process.returncode = 0
            mock_popen.return_value = mock_process
            mock_popen.return_value.communicate.return_value = (mock_output, "")
            mock_popen.return_value.returncode = 0
            
            with patch.object(scanner, '_discovery_scan', return_value={"192.168.1.1": HostInfo(ip="192.168.1.1")}):
                result = scanner.detailed_scan(target_ips)
                
                assert "192.168.1.1" in result
                assert len(result["192.168.1.1"].ports) == 2
                assert "80/tcp" in result["192.168.1.1"].ports
                assert "443/tcp" in result["192.168.1.1"].ports
                assert any("Apache" in service for service in result["192.168.1.1"].services)
                assert any("nginx" in service for service in result["192.168.1.1"].services)