import pytest
from unittest.mock import patch, MagicMock, call
from src.core.scanner import NetworkScanner, HostInfo, ScannerError
import subprocess
import ipaddress

class TestHostInfo:
    """Testes da classe HostInfo"""
    
    def test_host_info_initialization(self):
        """Testa a inicialização da classe HostInfo com valores padrão"""
        host = HostInfo(ip="192.168.1.1")
        assert host.ip == "192.168.1.1"
        assert host.hostname == "N/A"
        assert host.mac == "N/A"
        assert host.vendor == "N/A"
        assert host.ports == []
        assert host.is_up == False
        assert host.status == "down"
    
    def test_host_info_initialization_with_values(self):
        """Testa a inicialização da classe HostInfo com valores fornecidos"""
        ports = [{"port": 80, "protocol": "tcp", "state": "open", "service": "http"}]
        host = HostInfo(
            ip="192.168.1.1",
            hostname="test.local",
            mac="00:11:22:33:44:55",
            vendor="Test Vendor",
            ports=ports,
            is_up=True
        )
        assert host.ip == "192.168.1.1"
        assert host.hostname == "test.local"
        assert host.mac == "00:11:22:33:44:55"
        assert host.vendor == "Test Vendor"
        assert host.ports == ports
        assert host.is_up == True
        assert host.status == "up"
    
    def test_host_info_status_property(self):
        """Testa as propriedades de status do HostInfo"""
        host = HostInfo(ip="192.168.1.1")
        assert host.status == "down"
        
        host.is_up = True
        assert host.status == "up"
        
        host.status = "down"
        assert host.is_up == False
        
        host._status = "filtered"
        assert host.status == "filtered"

    def test_host_info_services_property(self):
        """Testa a propriedade services do HostInfo"""
        host = HostInfo(ip="192.168.1.1")
        host.ports = [
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
            {"port": 443, "protocol": "tcp", "state": "closed", "service": "https"},
            {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"}
        ]
        services = host.services
        assert len(services) == 2
        assert "http" in services
        assert "ssh" in services
        assert "https" not in services  # closed port
    
    def test_host_info_str_representation(self):
        """Testa a representação em string do HostInfo"""
        host = HostInfo(
            ip="192.168.1.1",
            hostname="test.local",
            mac="00:11:22:33:44:55",
            vendor="Test Vendor"
        )
        host.is_up = True
        host.ports = [{"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "Apache 2.4"}]
        
        result = str(host)
        assert "Host: 192.168.1.1" in result
        assert "Hostname: test.local" in result
        assert "MAC: 00:11:22:33:44:55" in result
        assert "Vendor: Test Vendor" in result
        assert "Status: up" in result
        assert "80/tcp" in result
        assert "http" in result
        assert "Apache 2.4" in result


class TestNetworkScanner:
    """Testes da classe NetworkScanner"""
    
    @pytest.fixture
    def mock_config_manager(self):
        """Fixture que fornece um mock do ConfigManager"""
        with patch('src.core.scanner.ConfigManager') as mock:
            # Configure o mock para fornecer valores de configuração
            mock_instance = MagicMock()
            mock_instance.get_scan_profile.return_value = {
                'options': ['-sS', '--top-ports', '100']
            }
            mock_instance.get_retry_config.return_value = {
                'max_attempts': 3,
                'delay_between_attempts': 1
            }
            mock_instance.get_timeout.return_value = 30
            
            # Configure o mock para ter a estrutura _config com scan_profiles
            mock_instance._config = {
                'scan_profiles': {
                    'basic': {'options': ['-sS', '--top-ports', '100']},
                    'version': {'options': ['-sS', '-sV', '--top-ports', '1000']},
                    'complete': {'options': ['-sS', '-sV', '-O', '-A', '-p-']}
                }
            }
            
            mock.return_value = mock_instance
            yield mock
    
    @pytest.fixture
    def scanner(self, mock_config_manager):
        """Fixture que fornece uma instância do NetworkScanner com ConfigManager mockado"""
        scanner = NetworkScanner()
        scanner._nmap_path = "nmap"  # Garantir que está usando o nome correto
        scanner._config_manager = mock_config_manager.return_value  # Usa o mock configurado
        return scanner
    
    def test_initialization(self, scanner):
        """Testa a inicialização do scanner"""
        assert scanner.network_range == ""
        assert scanner.verbosity == 0
        assert scanner._nmap_path == "nmap"
        assert scanner._scan_profile == "basic"
        assert scanner._quiet_mode == False
        
    def test_set_scan_profile(self, scanner):
        """Testa a definição do perfil de scan"""
        # Verificar a configuração do mock
        assert 'version' in scanner._config_manager._config['scan_profiles']
        
        # Definir um perfil válido
        scanner.set_scan_profile("version")
        assert scanner._scan_profile == "version"
        
        # Quando um perfil inválido é fornecido, deve usar o basic
        scanner.set_scan_profile("invalid_profile")
        assert scanner._scan_profile == "basic"
    
    def test_set_quiet_mode(self, scanner):
        """Testa a definição do modo silencioso"""
        scanner.set_quiet_mode(True)
        assert scanner._quiet_mode == True
        
        scanner.set_quiet_mode(False)
        assert scanner._quiet_mode == False
    
    def test_get_scan_options(self, scanner):
        """Testa a obtenção das opções de scan com base no perfil"""
        options = scanner._get_scan_options()
        assert options == ['-sS', '--top-ports', '100']
        
        # Com verbosidade aumentada
        scanner.verbosity = 1
        options = scanner._get_scan_options()
        assert options == ['-sS', '--top-ports', '100', '-v']
    
    def test_validate_network_range_valid(self, scanner):
        """Testa a validação de um range de rede válido"""
        # Estes não devem gerar exceções
        scanner._validate_network_range("192.168.1.0/24")
        scanner._validate_network_range("10.0.0.1")
        scanner._validate_network_range("172.16.0.0/16")
    
    def test_validate_network_range_invalid(self, scanner):
        """Testa a validação de um range de rede inválido"""
        with pytest.raises(ValueError):
            scanner._validate_network_range("300.168.1.1")
            
        with pytest.raises(ValueError):
            scanner._validate_network_range("192.168.1.0/33")
            
        with pytest.raises(ValueError):
            scanner._validate_network_range("invalid_range")
    
    def test_parse_nmap_output_host_discovery(self, scanner):
        """Testa o parsing da saída do Nmap para descoberta de hosts"""
        sample_output = """
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-01 12:00 UTC
Nmap scan report for 192.168.1.1
Host is up (0.0050s latency).
MAC Address: AA:BB:CC:DD:EE:FF (Vendor Name)

Nmap scan report for router.local (192.168.1.254)
Host is up (0.0050s latency).
MAC Address: 11:22:33:44:55:66 (Other Vendor)

Nmap done: 256 IP addresses (2 hosts up) scanned in 2.05 seconds
        """
        
        results = scanner._parse_nmap_output(sample_output)
        assert len(results) == 2
        
        # Verifica o primeiro host
        assert "192.168.1.1" in results
        host1 = results["192.168.1.1"]
        assert host1.ip == "192.168.1.1"
        assert host1.mac == "AA:BB:CC:DD:EE:FF"
        assert host1.vendor == "Vendor Name"
        assert host1.is_up == True
        
        # Verifica o segundo host
        assert "192.168.1.254" in results
        host2 = results["192.168.1.254"]
        assert host2.ip == "192.168.1.254"
        assert host2.hostname == "router.local"
        assert host2.mac == "11:22:33:44:55:66"
        assert host2.vendor == "Other Vendor"
        assert host2.is_up == True
        
    def test_parse_nmap_output_port_scan(self, scanner):
        """Testa o parsing da saída do Nmap para scan de portas"""
        sample_output = """
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-01 12:00 UTC
Nmap scan report for 192.168.1.1
Host is up (0.0050s latency).

PORT     STATE  SERVICE      VERSION
22/tcp   open   ssh          OpenSSH 8.2p1
80/tcp   open   http         Apache 2.4.29
443/tcp  closed https
3306/tcp open   mysql        MySQL 5.7.30

Nmap done: 1 IP address (1 host up) scanned in 1.05 seconds
        """
        
        results = scanner._parse_nmap_output(sample_output)
        assert len(results) == 1
        
        host = results["192.168.1.1"]
        assert host.ip == "192.168.1.1"
        assert host.is_up == True
        
        # Verifica as portas - são 4 portas no total
        assert len(host.ports) == 4
        
        # Verifica as informações específicas das portas
        ssh_port = next((p for p in host.ports if p['port'] == 22), None)
        assert ssh_port is not None
        assert ssh_port['protocol'] == 'tcp'
        assert ssh_port['state'] == 'open'
        assert ssh_port['service'] == 'ssh'
        
        # Verifica a porta fechada
        https_port = next((p for p in host.ports if p['port'] == 443), None)
        assert https_port is not None
        assert https_port['state'] == 'closed'
    
    @patch('subprocess.Popen')
    @patch('time.sleep')
    @patch('tqdm.tqdm')
    def test_scan_network(self, mock_tqdm, mock_sleep, mock_popen, scanner):
        """Testa o método scan_network"""
        # Configure os mocks
        mock_process = MagicMock()
        mock_process.poll.side_effect = [None, None, 0]  # Primeiro é None, depois None, então 0 (concluído)
        mock_process.returncode = 0
        mock_process.communicate.return_value = (
            """
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-01 12:00 UTC
Nmap scan report for 192.168.1.1
Host is up (0.0050s latency).
MAC Address: AA:BB:CC:DD:EE:FF (Vendor Name)

Nmap done: 256 IP addresses (1 host up) scanned in 2.05 seconds
            """, 
            ""
        )
        mock_popen.return_value = mock_process
        
        # Configurar o progresso simulado
        mock_progress_bar = MagicMock()
        mock_tqdm.return_value.__enter__.return_value = mock_progress_bar
        
        # Executa o scan
        results = scanner.scan_network("192.168.1.0/24")
        
        # Verifica se o comando nmap foi chamado corretamente
        mock_popen.assert_called_once()
        cmd_args = mock_popen.call_args[0][0]
        assert cmd_args[0] == "nmap"
        assert "-sn" in cmd_args
        assert "192.168.1.0/24" in cmd_args
        
        # Verifica o resultado
        assert len(results) == 1
        assert "192.168.1.1" in results
        host = results["192.168.1.1"]
        assert host.mac == "AA:BB:CC:DD:EE:FF"
        assert host.vendor == "Vendor Name"
    
    @patch('subprocess.run')
    def test_detailed_scan(self, mock_run, scanner):
        """Testa o método detailed_scan"""
        # Dados de entrada: hosts descobertos no scan inicial
        initial_hosts = {
            "192.168.1.1": HostInfo(ip="192.168.1.1", hostname="host1", is_up=True),
            "192.168.1.2": HostInfo(ip="192.168.1.2", hostname="host2", is_up=True),
        }
        
        # Configuração do mock para uma resposta com portas
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = """
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-01 12:00 UTC
Nmap scan report for 192.168.1.1
Host is up (0.0050s latency).
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap scan report for 192.168.1.2
Host is up (0.0050s latency).
PORT     STATE SERVICE
3389/tcp open  ms-wbt-server

Nmap done: 2 IP addresses (2 hosts up) scanned in 3.05 seconds
        """
        
        mock_run.return_value = mock_result
        
        # Reduzir o batch_size para testar com apenas 1 host por grupo
        scanner._batch_size = 1
        
        with patch('tqdm.tqdm') as mock_tqdm:
            mock_progress_bar = MagicMock()
            mock_tqdm.return_value.__enter__.return_value = mock_progress_bar
            
            # Executa o scan detalhado
            with patch.object(scanner, '_parse_nmap_output') as mock_parse:
                # Mock para o parse da saída para simular as portas encontradas
                mock_parse.return_value = {
                    "192.168.1.1": HostInfo(
                        ip="192.168.1.1",
                        hostname="host1",
                        is_up=True,
                        ports=[
                            {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
                            {"port": 80, "protocol": "tcp", "state": "open", "service": "http"}
                        ]
                    ),
                    "192.168.1.2": HostInfo(
                        ip="192.168.1.2",
                        hostname="host2",
                        is_up=True,
                        ports=[
                            {"port": 3389, "protocol": "tcp", "state": "open", "service": "ms-wbt-server"}
                        ]
                    )
                }
                
                results = scanner.detailed_scan(initial_hosts)
                
                # Verifica se subprocess.run foi chamado para cada host (com batch_size=1)
                assert mock_run.call_count == 2
                
                # Verifica se os resultados contêm as portas para ambos os hosts
                assert len(results) == 2
                
                host1 = results["192.168.1.1"]
                assert len(host1.ports) == 2
                assert any(p['port'] == 22 and p['service'] == 'ssh' for p in host1.ports)
                assert any(p['port'] == 80 and p['service'] == 'http' for p in host1.ports)
                
                host2 = results["192.168.1.2"]
                assert len(host2.ports) == 1
                assert any(p['port'] == 3389 and p['service'] == 'ms-wbt-server' for p in host2.ports)
    
    @patch('subprocess.run')
    def test_detailed_scan_with_retry(self, mock_run, scanner):
        """Testa o retry mechanism no detailed_scan"""
        initial_hosts = {
            "192.168.1.1": HostInfo(ip="192.168.1.1", is_up=True)
        }
        
        # Primeira tentativa falha, segunda tem sucesso
        mock_run.side_effect = [
            subprocess.TimeoutExpired(cmd="nmap", timeout=30),
            MagicMock(stdout="""
            Nmap scan report for 192.168.1.1
            Host is up.
            PORT     STATE  SERVICE
            22/tcp   open   ssh
            """)
        ]
        
        with patch('tqdm.tqdm'):
            with patch('time.sleep'):
                # Mock o método _parse_nmap_output para retornar um resultado específico
                with patch.object(scanner, '_parse_nmap_output') as mock_parse:
                    mock_parse.return_value = {
                        "192.168.1.1": HostInfo(
                            ip="192.168.1.1",
                            is_up=True,
                            ports=[
                                {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"}
                            ]
                        )
                    }
                    
                    results = scanner.detailed_scan(initial_hosts)
        
        # Verifica se houve retry
        assert mock_run.call_count == 2
        
        # Verifica se o resultado final foi processado corretamente
        assert len(results) == 1
        host = results["192.168.1.1"]
        assert len(host.ports) == 1
        assert host.ports[0]['port'] == 22
    
    @patch('subprocess.run')
    def test_detailed_scan_all_retries_fail(self, mock_run, scanner):
        """Testa quando todas as tentativas falham no detailed_scan"""
        initial_hosts = {
            "192.168.1.1": HostInfo(ip="192.168.1.1", hostname="host1", is_up=True)
        }
        
        # Todas as tentativas falham
        mock_run.side_effect = [
            subprocess.TimeoutExpired(cmd="nmap", timeout=30),
            subprocess.TimeoutExpired(cmd="nmap", timeout=30),
            subprocess.TimeoutExpired(cmd="nmap", timeout=30)
        ]
        
        with patch('tqdm.tqdm'):
            with patch('time.sleep'):
                with patch('src.core.scanner.error'):  # Para não logar erros durante o teste
                    results = scanner.detailed_scan(initial_hosts)
        
        # Verifica se houve 3 tentativas (o máximo configurado)
        assert mock_run.call_count == 3
        
        # Verifica se retornou os dados originais quando falha
        assert len(results) == 1
        assert results["192.168.1.1"].hostname == "host1"
        assert not results["192.168.1.1"].ports  # Não deve ter portas adicionadas
    
    @patch('subprocess.run')
    def test_scan_ports(self, mock_run, scanner):
        """Testa o método scan_ports"""
        mock_result = MagicMock()
        mock_result.stdout = """
        Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-01 12:00 UTC
        Nmap scan report for 192.168.1.1
        Host is up (0.0050s latency).
        PORT     STATE  SERVICE
        22/tcp   open   ssh
        80/tcp   open   http
        
        Nmap done: 1 IP address (1 host up) scanned in 1.05 seconds
        """
        
        mock_run.return_value = mock_result
        
        # Mock o método _parse_nmap_output para retornar um resultado específico
        with patch.object(scanner, '_parse_nmap_output') as mock_parse:
            mock_parse.return_value = {
                "192.168.1.1": HostInfo(
                    ip="192.168.1.1",
                    is_up=True,
                    ports=[
                        {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
                        {"port": 80, "protocol": "tcp", "state": "open", "service": "http"}
                    ]
                )
            }
            
            # Executa o scan
            results = scanner.scan_ports("192.168.1.1")
        
        # Verifica se o comando foi executado corretamente
        mock_run.assert_called_once()
        cmd_args = mock_run.call_args[0][0]
        assert cmd_args[0] == "nmap"
        assert "192.168.1.1" in cmd_args
        
        # Verifica o resultado
        assert len(results) == 1
        assert "192.168.1.1" in results
        host = results["192.168.1.1"]
        assert len(host.ports) == 2