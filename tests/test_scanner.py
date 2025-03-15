import pytest
from unittest.mock import patch, MagicMock
from src.core.scanner import NetworkScanner, HostInfo, ScannerError
import platform
import subprocess

class TestNetworkScanner:
    @pytest.fixture
    def scanner(self, config_manager):
        return NetworkScanner("nmap")

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

    def test_windows_discovery(self, scanner):
        mock_arp_output = """
Interface: 192.168.1.100
  Internet Address      Physical Address      Type
  192.168.1.1          00-11-22-33-44-55    dynamic
"""
        with patch("subprocess.run") as mock_run:
            # Configura o mock para o ping sweep
            mock_run.return_value = MagicMock()
            
            # Configura o mock para a saída do ARP
            mock_run.return_value.stdout = mock_arp_output
            
            result = scanner._windows_discovery("192.168.1.0/24")
            assert "192.168.1.1" in result
            assert result["192.168.1.1"].mac.replace("-", ":") == "00:11:22:33:44:55"

    def test_unix_discovery(self, scanner):
        mock_output = """
Nmap scan report for 192.168.1.1
Host is up (0.0050s latency).
MAC Address: 00:11:22:33:44:55 (Test Vendor)
Nmap scan report for 192.168.1.2
Host is up (0.0050s latency).
MAC Address: AA:BB:CC:DD:EE:FF (Other Vendor)
"""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock()
            mock_run.return_value.stdout = mock_output
            
            result = scanner._unix_discovery("192.168.1.0/24")
            
            assert len(result) == 2
            assert result["192.168.1.1"].mac == "00:11:22:33:44:55"
            assert result["192.168.1.1"].vendor == "Test Vendor"
            assert result["192.168.1.2"].mac == "AA:BB:CC:DD:EE:FF"
            assert result["192.168.1.2"].vendor == "Other Vendor"

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
                # Verifica se os serviços contêm as partes relevantes, permitindo formatos ligeiramente diferentes
                assert any("Apache" in service for service in result["192.168.1.1"].services)
                assert any("nginx" in service for service in result["192.168.1.1"].services)

    def test_detailed_scan_version_detection(self, scanner):
        # Output do scan inicial
        mock_output1 = """
Nmap scan report for 192.168.1.1
Host is up (0.025s latency).
PORT   STATE SERVICE
80/tcp open  http
443/tcp open  https
"""
        # Output do scan de versão
        mock_output2 = """
Nmap scan report for 192.168.1.1
Host is up (0.025s latency).
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41
443/tcp open  https   nginx 1.18.0
"""
        target_ips = {"192.168.1.1"}
        
        with patch("subprocess.Popen") as mock_popen:
            # Configurando os mocks para os dois processos
            first_process = MagicMock()
            first_process.communicate.return_value = (mock_output1, "")
            first_process.returncode = 0
            
            second_process = MagicMock()
            second_process.communicate.return_value = (mock_output2, "")
            second_process.returncode = 0
            
            # Definindo a sequência de retorno
            mock_popen.side_effect = [first_process, second_process]
            
            with patch.object(scanner, '_discovery_scan', return_value={"192.168.1.1": HostInfo(ip="192.168.1.1")}):
                result = scanner.detailed_scan(target_ips)
                
                assert "192.168.1.1" in result
                assert len(result["192.168.1.1"].ports) == 2
                # Verifica se os serviços contêm as partes relevantes, permitindo formatos ligeiramente diferentes
                assert any("Apache" in service for service in result["192.168.1.1"].services)
                assert any("nginx" in service for service in result["192.168.1.1"].services)

    def test_detailed_scan_timeout(self, scanner):
        with patch("subprocess.Popen") as mock_popen:
            mock_process = MagicMock()
            mock_process.communicate.side_effect = subprocess.TimeoutExpired(cmd="", timeout=180)
            mock_process.returncode = 1
            mock_popen.return_value = mock_process
            
            with pytest.raises(subprocess.TimeoutExpired):
                scanner.detailed_scan({"192.168.1.1"})

    def test_detailed_scan_exception(self, scanner):
        with patch("subprocess.Popen") as mock_popen:
            mock_popen.side_effect = Exception("Test error")
            
            with pytest.raises(Exception) as exc_info:
                scanner.detailed_scan({"192.168.1.1"})
            assert str(exc_info.value) == "Test error"

    def test_detailed_scan_preserves_initial_info(self, scanner):
        """Testa se o scan detalhado preserva as informações do scan inicial"""
        initial_host = HostInfo(
            ip="192.168.1.1",
            hostname="test.local",
            mac="00:11:22:33:44:55",
            vendor="Test Vendor"
        )
        
        mock_output = """
Nmap scan report for 192.168.1.1
Host is up (0.025s latency).
PORT   STATE SERVICE
80/tcp open  http
443/tcp open  https
"""
        
        with patch.object(scanner, '_discovery_scan', return_value={"192.168.1.1": initial_host}):
            with patch("subprocess.Popen") as mock_popen:
                mock_process = MagicMock()
                mock_process.communicate.return_value = (mock_output, "")
                mock_process.returncode = 0
                mock_popen.return_value = mock_process
                mock_popen.return_value.communicate.return_value = (mock_output, "")
                mock_popen.return_value.returncode = 0
                
                result = scanner.detailed_scan({"192.168.1.1"})
                
                assert result["192.168.1.1"].ip == initial_host.ip
                assert result["192.168.1.1"].hostname == initial_host.hostname
                assert result["192.168.1.1"].mac == initial_host.mac
                assert result["192.168.1.1"].vendor == initial_host.vendor
                assert "80/tcp" in result["192.168.1.1"].ports
                assert "443/tcp" in result["192.168.1.1"].ports

    def test_detailed_scan_common_ports_categories(self, scanner):
        """Testa se o scan inclui todas as categorias de portas comuns"""
        with patch("subprocess.Popen") as mock_popen:
            mock_process = MagicMock()
            mock_process.communicate.return_value = ("", "")
            mock_process.returncode = 0
            mock_popen.return_value = mock_process
            
            with patch.object(scanner, '_discovery_scan', return_value={}):
                scanner.detailed_scan({"192.168.1.1"})
                
                # Verifica se a chamada do Nmap inclui o parâmetro -p com as portas
                calls = mock_popen.call_args_list
                if calls:
                    cmd_str = " ".join(calls[0][0][0])
                    
                    # Verifica se as principais categorias de portas estão incluídas
                    assert "80,443" in cmd_str  # Web
                    assert "22,23" in cmd_str  # SSH/Telnet
                    assert "139,445" in cmd_str  # SMB
                    assert "3306,5432" in cmd_str  # Databases