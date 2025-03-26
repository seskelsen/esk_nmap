import pytest
import subprocess
import re
from unittest.mock import patch, MagicMock

from src.core.scanner import HostInfo, NetworkScanner, ScannerError

class TestHostInfo:
    def test_host_info_initialization(self):
        """Testa a inicialização básica da classe HostInfo"""
        host = HostInfo(ip="192.168.1.1")
        assert host.ip == "192.168.1.1"
        assert host.hostname == "N/A"
        assert host.mac == "N/A"
        assert host.vendor == "N/A"
        assert host.ports == []
        assert host.is_up == False
        assert host._status == "down"
    
    def test_host_info_initialization_with_values(self):
        """Testa a inicialização com valores da classe HostInfo"""
        host = HostInfo(
            ip="192.168.1.1",
            hostname="test.local",
            mac="00:11:22:33:44:55",
            vendor="Test Vendor",
            ports=[{"port": 80, "protocol": "tcp", "state": "open", "service": "http"}],
            is_up=True
        )
        assert host.ip == "192.168.1.1"
        assert host.hostname == "test.local"
        assert host.mac == "00:11:22:33:44:55"
        assert host.vendor == "Test Vendor"
        assert len(host.ports) == 1
        assert host.ports[0]["port"] == 80
        assert host.is_up == True
        assert host._status == "up"
    
    def test_host_info_status_property(self):
        """Testa as propriedades de status do HostInfo"""
        # Inicializa com is_up=False
        host = HostInfo(ip="192.168.1.1")
        assert host._status == "down"
        assert host.status == "down"
        
        # Modifica is_up para True
        host.is_up = True
        assert host._status == "up"
        assert host.status == "up"
        
        # Testa o setter do status
        host.status = "filtered"
        assert host._status == "filtered"
        assert host.status == "filtered"
        assert host.is_up == False
        
        # Testa mudar para "up" via setter
        host.status = "up"
        assert host._status == "up"
        assert host.status == "up"
        assert host.is_up == True
    
    def test_host_info_services_property(self):
        """Testa a propriedade services do HostInfo"""
        host = HostInfo(ip="192.168.1.1")
        
        # Sem portas
        assert host.services == []
        
        # Com portas no formato dict
        host.ports = [
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
            {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
            {"port": 443, "protocol": "tcp", "state": "closed", "service": "https"}
        ]
        
        # Apenas portas abertas devem retornar serviços
        assert len(host.services) == 2
        assert "http" in host.services
        assert "ssh" in host.services
        assert "https" not in host.services
        
        # Com portas em formato string (legado)
        host.ports = ["80/tcp", "22/tcp"]
        assert len(host.services) == 2
        assert all(service == "unknown" for service in host.services)
    
    def test_host_info_str_representation(self):
        """Testa a representação em string do HostInfo"""
        host = HostInfo(
            ip="192.168.1.1",
            hostname="test.local",
            mac="00:11:22:33:44:55",
            vendor="Test Vendor"
        )
        
        # Define is_up como True para garantir que status seja "up"
        host.is_up = True
        host.ports = [{"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "Apache 2.4"}]
        
        result = str(host)
        assert "Host: 192.168.1.1" in result
        assert "Hostname: test.local" in result
        assert "MAC: 00:11:22:33:44:55" in result
        assert "Vendor: Test Vendor" in result
        # Verifica que o status é exibido corretamente
        assert "Status: up" in result
        assert "Portas abertas:" in result
        assert "80/tcp: http (Apache 2.4)" in result
        
        # Testa com diferentes formatos de portas
        host.ports = [
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
            "443/tcp"  # formato legado
        ]
        
        result = str(host)
        assert "80/tcp: http" in result
        assert "443/tcp" in result


class TestNetworkScanner:
    @pytest.fixture
    def mock_config_instance(self):
        """Fixture para criar uma instância mockada do ConfigManager"""
        mock_instance = MagicMock()
        mock_instance._config = {
            'scan_profiles': {
                'basic': {
                    'options': ['-F'],
                    'description': 'Fast scan'
                },
                'stealth': {
                    'options': ['-sS', '-T2'],
                    'description': 'Stealth scan'
                }
            },
            'retry': {
                'max_attempts': 2,
                'delay_between_attempts': 1
            },
            'timeout': 30
        }
        
        mock_instance.get_scan_profile.return_value = {
            'options': ['-F'],
            'description': 'Fast scan'
        }
        mock_instance.get_retry_config.return_value = {
            'max_attempts': 2,
            'delay_between_attempts': 1
        }
        mock_instance.get_timeout.side_effect = lambda operation=None: 30
        return mock_instance

    @pytest.fixture
    def scanner(self, mock_config_instance):
        """Fixture para criar um scanner para testes"""
        with patch('src.core.scanner.ConfigManager') as mock_config:
            # Configura o singleton mockado
            mock_config._instance = mock_config_instance
            mock_config.return_value = mock_config_instance
            
            scanner = NetworkScanner("nmap")
            yield scanner
    
    def test_initialization(self, scanner):
        """Testa a inicialização básica do NetworkScanner"""
        assert scanner._nmap_path == "nmap"
        assert scanner._scan_profile == "basic"
        assert scanner._quiet_mode == False
        assert scanner._batch_size == 10
        assert scanner._max_threads == 5
        assert scanner._throttle_delay == 0.5
    
    def test_set_scan_profile(self, scanner):
        """Testa a definição do perfil de scan"""
        # Perfil válido
        scanner.set_scan_profile("stealth")
        assert scanner._scan_profile == "stealth"
        
        # Perfil inválido deve usar fallback para basic
        with patch('src.core.scanner.warning') as mock_warning:  # Corrigido o path do mock
            scanner.set_scan_profile("nonexistent")
            assert scanner._scan_profile == "basic"
            mock_warning.assert_called_once()
    
    def test_set_quiet_mode(self, scanner):
        """Testa a definição do modo silencioso"""
        assert scanner._quiet_mode == False
        scanner.set_quiet_mode(True)
        assert scanner._quiet_mode == True
    
    def test_get_scan_options(self, scanner):
        """Testa a obtenção das opções de scan"""
        # Sem verbosidade
        options = scanner._get_scan_options()
        assert options == ['-F']
        
        # Com verbosidade 1
        scanner.verbosity = 1
        options = scanner._get_scan_options()
        assert options == ['-F', '-v']
        
        # Com verbosidade 2+
        scanner.verbosity = 2
        options = scanner._get_scan_options()
        assert options == ['-F', '-vv']
    
    def test_validate_network_range_valid(self, scanner):
        """Testa a validação de ranges de rede válidos"""
        # IP único
        scanner._validate_network_range("192.168.1.1")
        
        # Range CIDR
        scanner._validate_network_range("192.168.1.0/24")
        
        # Sem exceção significa que passou
        assert True
    
    def test_validate_network_range_invalid(self, scanner):
        """Testa a validação de ranges de rede inválidos"""
        # IP inválido
        with pytest.raises(ValueError):
            scanner._validate_network_range("300.168.1.1")
        
        # Range CIDR inválido
        with pytest.raises(ValueError):
            scanner._validate_network_range("192.168.1.0/33")
        
        # Formato completamente inválido
        with pytest.raises(ValueError):
            scanner._validate_network_range("invalid")
    
    def test_parse_nmap_output_host_discovery(self, scanner):
        """Testa o parsing da saída do Nmap para descoberta de hosts"""
        sample_output = """
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-01 12:00 UTC
Nmap scan report for router.local (192.168.1.1)
Host is up (0.0050s latency).
MAC Address: 00:11:22:33:44:55 (Vendor Co)

Nmap scan report for 192.168.1.2
Host is up (0.0100s latency).
MAC Address: AA:BB:CC:DD:EE:FF (Another Vendor)

Nmap scan report for 192.168.1.3
Host is down.

Nmap done: 3 IP addresses (2 hosts up) scanned in 1.05 seconds
        """
        
        results = scanner._parse_nmap_output(sample_output)
        assert len(results) == 3
        
        # Verifica o primeiro host
        host1 = results["192.168.1.1"]
        assert host1.ip == "192.168.1.1"
        assert host1.hostname == "router.local"
        assert host1.mac == "00:11:22:33:44:55"
        assert host1.vendor == "Vendor Co"
        assert host1.is_up == True
        
        # Verifica o segundo host
        host2 = results["192.168.1.2"]
        assert host2.ip == "192.168.1.2"
        assert host2.hostname == "N/A"
        assert host2.mac == "AA:BB:CC:DD:EE:FF"
        assert host2.vendor == "Another Vendor"
        assert host2.is_up == True
        
        # Verifica o terceiro host
        host3 = results["192.168.1.3"]
        assert host3.ip == "192.168.1.3"
        assert host3.is_up == False
    
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
        
        # Verifica as portas capturadas pelo parser
        assert len(host.ports) == 4, f"Esperado 4 portas, encontrado {len(host.ports)}: {host.ports}"
        
        # Verifica cada porta individualmente para diagnóstico mais preciso
        port_numbers = sorted([p['port'] for p in host.ports])
        assert port_numbers == [22, 80, 443, 3306], f"Portas esperadas: [22, 80, 443, 3306], encontrado: {port_numbers}"
        
        # Verifica serviços específicos
        ssh_port = next(p for p in host.ports if p['port'] == 22)
        assert ssh_port['service'] == 'ssh'
        assert ssh_port['state'] == 'open'
        
        mysql_port = next(p for p in host.ports if p['port'] == 3306)
        assert mysql_port['service'] == 'mysql'
        assert mysql_port['state'] == 'open'
    
    @patch('subprocess.Popen')
    @patch('time.sleep')
    def test_scan_network(self, mock_sleep, mock_popen, scanner):
        """Testa o método scan_network"""
        # Mock do processo
        process_mock = MagicMock()
        process_mock.poll.side_effect = [None, 0]  # Simula processo em execução e depois terminado
        process_mock.communicate.return_value = (
            """
Nmap scan report for 192.168.1.1
Host is up.
MAC Address: 00:11:22:33:44:55 (Test Vendor)

Nmap scan report for 192.168.1.2
Host is down.
            """, 
            ""
        )
        process_mock.returncode = 0
        mock_popen.return_value = process_mock
        
        # Executa o scan
        with patch('tqdm.tqdm'):
            results = scanner.scan_network("192.168.1.0/24")
        
        # Verifica se os comandos corretos foram chamados
        mock_popen.assert_called_once()
        args, kwargs = mock_popen.call_args
        cmd = args[0]
        assert "nmap" in cmd
        assert "-sn" in cmd
        assert "192.168.1.0/24" in cmd
        
        # Verifica resultados
        assert len(results) == 2
        assert "192.168.1.1" in results
        assert "192.168.1.2" in results
        assert results["192.168.1.1"].is_up == True
        assert results["192.168.1.2"].is_up == False
    
    @patch('tqdm.tqdm')
    @patch('subprocess.run')
    @patch('time.sleep')
    def test_detailed_scan(self, mock_sleep, mock_run, mock_tqdm, scanner):
        """Testa o método detailed_scan"""
        # Prepara os hosts iniciais
        initial_hosts = {
            "192.168.1.1": HostInfo(ip="192.168.1.1", is_up=True),
            "192.168.1.2": HostInfo(ip="192.168.1.2", is_up=False)  # Não deve ser escaneado
        }
        
        # Mock do subprocess.run
        mock_run.return_value = MagicMock(
            stdout="""
Nmap scan report for 192.168.1.1
Host is up.
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
            """,
            stderr="",
            returncode=0
        )
        
        # Executa o scan
        results = scanner.detailed_scan(initial_hosts)
        
        # Verifica se subprocess.run foi chamado apenas para o host ativo
        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        cmd = args[0]
        assert "192.168.1.1" in cmd
        assert "192.168.1.2" not in cmd
        
        # Verifica resultados
        assert "192.168.1.1" in results
        assert "192.168.1.2" in results
        assert results["192.168.1.1"].is_up == True
    
    @patch('subprocess.run')
    @patch('time.sleep')
    @patch('tqdm.tqdm')
    def test_detailed_scan_with_retry(self, mock_tqdm, mock_sleep, mock_run, scanner):
        """Testa o retry mechanism no detailed_scan"""
        # Hosts iniciais
        initial_hosts = {
            "192.168.1.1": HostInfo(ip="192.168.1.1", is_up=True)
        }
        
        # Configura o mock para falhar na primeira tentativa e ter sucesso na segunda
        mock_run.side_effect = [
            subprocess.TimeoutExpired("nmap", 30),  # Primeira chamada: timeout
            MagicMock(  # Segunda chamada: sucesso
                stdout="""
Nmap scan report for 192.168.1.1
Host is up.
PORT   STATE SERVICE
22/tcp open  ssh
                """,
                stderr="",
                returncode=0
            )
        ]
        
        # Executa o teste
        results = scanner.detailed_scan(initial_hosts)
        
        # Verifica se o método foi chamado duas vezes (retry)
        assert mock_run.call_count == 2
        
        # Verifica resultado
        assert "192.168.1.1" in results
        assert len(results["192.168.1.1"].ports) == 1
    
    @patch('subprocess.run')
    @patch('time.sleep')
    @patch('tqdm.tqdm')
    def test_detailed_scan_all_retries_fail(self, mock_tqdm, mock_sleep, mock_run, scanner):
        """Testa o detailed_scan quando todas as tentativas falham"""
        # Hosts iniciais
        initial_hosts = {
            "192.168.1.1": HostInfo(ip="192.168.1.1", is_up=True)
        }
        
        # Configura o mock para sempre falhar
        mock_run.side_effect = [
            subprocess.TimeoutExpired("nmap", 30),
            subprocess.TimeoutExpired("nmap", 30)  # Apenas 2 tentativas, não 3
        ]
        
        # Executa o teste
        results = scanner.detailed_scan(initial_hosts)
        
        # Verifica se o método foi chamado duas vezes (retry)
        assert mock_run.call_count == 2
        
        # Verifica que resultados estão vazios (host original é mantido)
        assert "192.168.1.1" in results
        assert len(results["192.168.1.1"].ports) == 0
    
    @patch('subprocess.run')
    def test_scan_ports(self, mock_run, scanner):
        """Testa o método scan_ports"""
        # Mock do subprocess.run
        mock_run.return_value = MagicMock(
            stdout="""
Nmap scan report for 192.168.1.1
Host is up.
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
            """,
            stderr="",
            returncode=0
        )
        
        # Executa o scan
        results = scanner.scan_ports("192.168.1.1")
        
        # Verifica se subprocess.run foi chamado corretamente
        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        cmd = args[0]
        assert "nmap" in cmd
        assert "192.168.1.1" in cmd
        
        # Verifica resultados
        assert "192.168.1.1" in results
        assert results["192.168.1.1"].is_up == True
        assert len(results["192.168.1.1"].ports) == 2
        
    def test_set_source_port(self, scanner):
        """Testa o método set_source_port"""
        # Verifica o valor padrão
        assert not hasattr(scanner, '_source_port') or scanner._source_port is None
        
        # Testa definindo uma porta válida
        scanner.set_source_port(53)
        assert scanner._source_port == 53
        
        # Testa com valor inválido
        scanner.set_source_port(0)
        assert scanner._source_port is None
        
        scanner.set_source_port(65536)  # Porta muito alta
        assert scanner._source_port is None
        
        scanner.set_source_port(None)
        assert scanner._source_port is None
        
        # Configura uma porta válida novamente
        scanner.set_source_port(443)
        assert scanner._source_port == 443
    
    @patch('subprocess.run')
    def test_source_port_in_command(self, mock_run, scanner):
        """Testa se a porta de origem é incluída no comando nmap"""
        # Configura a saída do comando nmap
        mock_run.return_value = MagicMock(
            stdout="""
Nmap scan report for 192.168.1.1
Host is up.
PORT   STATE SERVICE
22/tcp open  ssh
            """,
            stderr="",
            returncode=0
        )
        
        # Configure uma porta de origem
        scanner.set_source_port(53)
        
        # Execute o scan detalhado
        initial_hosts = {
            "192.168.1.1": HostInfo(ip="192.168.1.1", is_up=True)
        }
        
        # Patch o método _scan_host_batch para verificar se a porta de origem é incluída
        with patch.object(scanner, '_scan_host_batch', wraps=scanner._scan_host_batch) as wrapped_method:
            # Execute o scan
            scanner.detailed_scan(initial_hosts)
            
            # Verifique se o método foi chamado
            wrapped_method.assert_called_once()
            
            # Verifique se a porta de origem está no comando
            mock_run.assert_called_once()
            args, kwargs = mock_run.call_args
            cmd = args[0]
            assert "--source-port" in cmd
            source_port_index = cmd.index("--source-port")
            assert source_port_index + 1 < len(cmd)
            assert cmd[source_port_index + 1] == "53"