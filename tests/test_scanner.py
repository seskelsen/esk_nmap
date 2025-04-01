import pytest
import ipaddress
import subprocess
from unittest.mock import patch, MagicMock, call
from src.core.scanner import HostInfo, NetworkScanner, ScannerError


class TestHostInfo:
    """Testes para a classe HostInfo"""
    
    def test_init_default_values(self):
        """Testa inicialização com valores padrão"""
        host = HostInfo("192.168.1.1")
        assert host.ip == "192.168.1.1"
        assert host.hostname == "N/A"
        assert host.mac == "N/A"
        assert host.vendor == "N/A"
        assert host.ports == []
        assert host.is_up is False
        assert host.status == "down"
    
    def test_init_with_values(self):
        """Testa inicialização com valores específicos"""
        ports = [
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
            {"port": 443, "protocol": "tcp", "state": "open", "service": "https"}
        ]
        host = HostInfo(
            ip="192.168.1.1",
            hostname="router.local",
            mac="00:11:22:33:44:55",
            vendor="Cisco",
            ports=ports,
            is_up=True
        )
        assert host.ip == "192.168.1.1"
        assert host.hostname == "router.local"
        assert host.mac == "00:11:22:33:44:55"
        assert host.vendor == "Cisco"
        assert host.ports == ports
        assert host.is_up is True
        assert host.status == "up"
    
    def test_is_up_property(self):
        """Testa o property is_up"""
        host = HostInfo("192.168.1.1")
        assert host.is_up is False
        assert host.status == "down"
        
        host.is_up = True
        assert host.is_up is True
        assert host.status == "up"
        
        host.is_up = False
        assert host.is_up is False
        assert host.status == "down"
    
    def test_status_property(self):
        """Testa o property status"""
        host = HostInfo("192.168.1.1")
        assert host.status == "down"
        assert host.is_up is False
        
        host.status = "up"
        assert host.status == "up"
        assert host.is_up is True
        
        host.status = "filtered"
        assert host.status == "filtered"
        assert host.is_up is False
    
    def test_services_property_dict_ports(self):
        """Testa o property services com portas em formato dict"""
        ports = [
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
            {"port": 443, "protocol": "tcp", "state": "open", "service": "https"},
            {"port": 22, "protocol": "tcp", "state": "closed", "service": "ssh"}  # Não deve aparecer nos serviços
        ]
        host = HostInfo("192.168.1.1", ports=ports)
        
        services = host.services
        assert len(services) == 2
        assert "http" in services
        assert "https" in services
        assert "ssh" not in services
    
    def test_services_property_string_ports(self):
        """Testa o property services com portas em formato string"""
        ports = ["80/tcp", "443/tcp"]
        host = HostInfo("192.168.1.1", ports=ports)
        
        services = host.services
        assert len(services) == 2
        assert all(service == "unknown" for service in services)
    
    def test_str_representation(self):
        """Testa a representação string da classe"""
        ports = [
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "Apache 2.4"},
            {"port": 443, "protocol": "tcp", "state": "open", "service": "https"}
        ]
        host = HostInfo(
            ip="192.168.1.1",
            hostname="router.local",
            mac="00:11:22:33:44:55",
            vendor="Cisco",
            ports=ports,
            is_up=True
        )
        
        str_rep = str(host)
        assert "Host: 192.168.1.1" in str_rep
        assert "Hostname: router.local" in str_rep
        assert "MAC: 00:11:22:33:44:55" in str_rep
        assert "Vendor: Cisco" in str_rep
        assert "Status: up" in str_rep
        assert "Portas abertas:" in str_rep
        assert "80/tcp: http (Apache 2.4)" in str_rep
        assert "443/tcp: https" in str_rep
        
        # Teste com portas em formato string
        host.ports = ["80/tcp", "443/tcp"]
        str_rep = str(host)
        assert "80/tcp" in str_rep
        assert "443/tcp" in str_rep


class TestNetworkScanner:
    """Testes para a classe NetworkScanner"""
    
    @pytest.fixture
    def scanner(self):
        """Fixture que retorna uma instância de NetworkScanner"""
        with patch('src.core.scanner.ConfigManager') as mock_config:
            # Configurar o mock do ConfigManager
            config_instance = mock_config.return_value
            config_instance._config = {
                'scan_profiles': {
                    'basic': {'options': ['-sn'], 'timing': 4},
                    'discovery': {'options': ['-sn', '-PE'], 'timing': 3},
                    'intensive': {'options': ['-sS', '-sV', '--version-all'], 'timing': 4},
                    'stealth': {'options': ['-sS', '--source-port', '53'], 'timing': 2}
                },
                'timeout': {
                    'discovery': 60,
                    'port_scan': 120,
                    'batch_scan': 300
                },
                'retry': {
                    'max_attempts': 3,
                    'delay_between_attempts': 2
                }
            }
            
            config_instance.get_scan_profile.side_effect = lambda profile: config_instance._config['scan_profiles'].get(profile, {})
            config_instance.get_timeout.side_effect = lambda key: config_instance._config['timeout'].get(key, 60)
            config_instance.get_retry_config.return_value = config_instance._config['retry']
            
            scanner = NetworkScanner("nmap")
            # Definir modo silencioso para evitar barras de progresso nos testes
            scanner.set_quiet_mode(True)
            return scanner
    
    def test_init(self, scanner):
        """Testa inicialização da classe"""
        assert scanner._nmap_path == "nmap"
        assert scanner._scan_profile == "basic"
        assert scanner._quiet_mode is True
        assert scanner._batch_size == 10
        assert scanner._max_threads == 5
        assert scanner._throttle_delay == 0.5
    
    def test_set_scan_profile_valid(self, scanner):
        """Testa definição de perfil de scan válido"""
        scanner.set_scan_profile("intensive")
        assert scanner._scan_profile == "intensive"
        
        scanner.set_scan_profile("discovery")
        assert scanner._scan_profile == "discovery"
    
    def test_set_scan_profile_invalid(self, scanner):
        """Testa definição de perfil de scan inválido"""
        with patch('src.core.scanner.warning') as mock_warning:
            scanner.set_scan_profile("non_existent")
            assert scanner._scan_profile == "basic"  # Volta para o perfil padrão
            mock_warning.assert_called_once()
    
    def test_set_source_port_valid(self, scanner):
        """Testa definição de porta de origem válida"""
        scanner.set_source_port(53)
        assert scanner._source_port == 53
    
    def test_set_source_port_invalid(self, scanner):
        """Testa definição de porta de origem inválida"""
        scanner.set_source_port(0)  # Porta inválida
        assert scanner._source_port is None
        
        scanner.set_source_port(65537)  # Porta inválida
        assert scanner._source_port is None
    
    def test_set_batch_size_valid(self, scanner):
        """Testa definição de tamanho de batch válido"""
        scanner.set_batch_size(20)
        assert scanner._batch_size == 20
    
    def test_set_batch_size_invalid(self, scanner):
        """Testa definição de tamanho de batch inválido"""
        with pytest.raises(ValueError, match="O tamanho do batch deve ser pelo menos 1"):
            scanner.set_batch_size(0)
    
    def test_set_max_threads_valid(self, scanner):
        """Testa definição de número máximo de threads válido"""
        scanner.set_max_threads(10)
        assert scanner._max_threads == 10
    
    def test_set_max_threads_invalid(self, scanner):
        """Testa definição de número máximo de threads inválido"""
        with pytest.raises(ValueError, match="O número de threads deve ser pelo menos 1"):
            scanner.set_max_threads(0)
    
    def test_set_throttle_delay_valid(self, scanner):
        """Testa definição de delay de throttle válido"""
        scanner.set_throttle_delay(1.5)
        assert scanner._throttle_delay == 1.5
    
    def test_set_throttle_delay_invalid(self, scanner):
        """Testa definição de delay de throttle inválido"""
        with pytest.raises(ValueError, match="O atraso deve ser não-negativo"):
            scanner.set_throttle_delay(-1)
    
    def test_get_scan_options(self, scanner):
        """Testa obtenção de opções de scan baseadas no perfil"""
        # Teste com perfil básico
        scanner.set_scan_profile("basic")
        options = scanner._get_scan_options()
        assert options == ["-sn"]
        
        # Teste com verbosidade 1
        scanner.verbosity = 1
        options = scanner._get_scan_options()
        assert options == ["-sn", "-v"]
        
        # Teste com verbosidade 2
        scanner.verbosity = 2
        options = scanner._get_scan_options()
        assert options == ["-sn", "-vv"]
        
        # Teste com outro perfil
        scanner.set_scan_profile("intensive")
        scanner.verbosity = 0
        options = scanner._get_scan_options()
        assert options == ["-sS", "-sV", "--version-all"]
    
    def test_validate_network_range_valid(self, scanner):
        """Testa validação de ranges de rede válidos"""
        # IP único
        scanner._validate_network_range("192.168.1.1")
        
        # Range CIDR
        scanner._validate_network_range("192.168.1.0/24")
        
        # IP v6
        scanner._validate_network_range("2001:db8::1")
    
    def test_validate_network_range_invalid(self, scanner):
        """Testa validação de ranges de rede inválidos"""
        with pytest.raises(ValueError):
            scanner._validate_network_range("192.168.1.256")  # IP inválido
            
        with pytest.raises(ValueError):
            scanner._validate_network_range("192.168.1.0/33")  # Prefixo inválido
            
        with pytest.raises(ValueError):
            scanner._validate_network_range("invalid_range")  # Formato inválido
    
    def test_parse_nmap_output_empty(self, scanner):
        """Testa parsing de saída vazia do nmap"""
        result = scanner._parse_nmap_output("")
        assert result == {}
    
    def test_parse_nmap_output_single_host(self, scanner):
        """Testa parsing de saída do nmap para um único host"""
        nmap_output = """
Starting Nmap 7.91 ( https://nmap.org ) at 2025-04-01 12:00 CEST
Nmap scan report for router.local (192.168.1.1)
Host is up (0.0050s latency).
MAC Address: 00:11:22:33:44:55 (Cisco)
Nmap done: 1 IP address (1 host up) scanned in 0.50 seconds
        """
        
        with patch('src.core.scanner.debug'):
            result = scanner._parse_nmap_output(nmap_output)
        
        assert len(result) == 1
        assert "192.168.1.1" in result
        host = result["192.168.1.1"]
        assert host.ip == "192.168.1.1"
        assert host.hostname == "router.local"
        assert host.mac == "00:11:22:33:44:55"
        assert host.vendor == "Cisco"
        assert host.is_up is True
        assert host.ports == []
    
    def test_parse_nmap_output_with_ports(self, scanner):
        """Testa parsing de saída do nmap com informações de portas"""
        nmap_output = """
Starting Nmap 7.91 ( https://nmap.org ) at 2025-04-01 12:00 CEST
Nmap scan report for webserver.local (192.168.1.2)
Host is up (0.0050s latency).
MAC Address: AA:BB:CC:DD:EE:FF (Dell)

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.41
443/tcp  open  https   nginx 1.18.0
22/tcp   closed ssh

Nmap done: 1 IP address (1 host up) scanned in 1.20 seconds
        """
        
        with patch('src.core.scanner.debug'):
            result = scanner._parse_nmap_output(nmap_output)
        
        assert len(result) == 1
        assert "192.168.1.2" in result
        host = result["192.168.1.2"]
        assert host.ip == "192.168.1.2"
        assert host.hostname == "webserver.local"
        assert host.mac == "AA:BB:CC:DD:EE:FF"
        assert host.vendor == "Dell"
        assert host.is_up is True
        
        # Verifica as portas
        assert len(host.ports) == 2  # Apenas portas abertas
        
        port_80 = next((p for p in host.ports if p["port"] == 80), None)
        assert port_80 is not None
        assert port_80["protocol"] == "tcp"
        assert port_80["state"] == "open"
        assert port_80["service"] == "http"
        assert port_80["version"] == "Apache httpd 2.4.41"
        
        port_443 = next((p for p in host.ports if p["port"] == 443), None)
        assert port_443 is not None
        assert port_443["protocol"] == "tcp"
        assert port_443["state"] == "open"
        assert port_443["service"] == "https"
        assert port_443["version"] == "nginx 1.18.0"
    
    def test_parse_nmap_output_multiple_hosts(self, scanner):
        """Testa parsing de saída do nmap para múltiplos hosts"""
        nmap_output = """
Starting Nmap 7.91 ( https://nmap.org ) at 2025-04-01 12:00 CEST
Nmap scan report for router.local (192.168.1.1)
Host is up (0.0050s latency).
MAC Address: 00:11:22:33:44:55 (Cisco)

Nmap scan report for 192.168.1.2
Host is up (0.0080s latency).
MAC Address: AA:BB:CC:DD:EE:FF (Unknown)

PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for 192.168.1.3
Host is up (0.0100s latency).

Nmap done: 3 IP addresses (3 hosts up) scanned in 1.50 seconds
        """
        
        with patch('src.core.scanner.debug'):
            result = scanner._parse_nmap_output(nmap_output)
        
        assert len(result) == 3
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result
        assert "192.168.1.3" in result
        
        # Verifica o primeiro host
        host1 = result["192.168.1.1"]
        assert host1.hostname == "router.local"
        assert host1.mac == "00:11:22:33:44:55"
        assert host1.vendor == "Cisco"
        assert host1.is_up is True
        assert host1.ports == []
        
        # Verifica o segundo host
        host2 = result["192.168.1.2"]
        assert host2.hostname == "N/A"
        assert host2.mac == "AA:BB:CC:DD:EE:FF"
        assert host2.vendor == "Unknown"
        assert host2.is_up is True
        assert len(host2.ports) == 1
        assert host2.ports[0]["port"] == 80
        assert host2.ports[0]["protocol"] == "tcp"
        assert host2.ports[0]["state"] == "open"
        assert host2.ports[0]["service"] == "http"
        
        # Verifica o terceiro host
        host3 = result["192.168.1.3"]
        assert host3.hostname == "N/A"
        assert host3.mac == "N/A"
        assert host3.vendor == "N/A"
        assert host3.is_up is True
        assert host3.ports == []
    
    def test_scan_network_success(self, scanner):
        """Testa scan de rede bem-sucedido"""
        mock_stdout = """
Starting Nmap 7.91 ( https://nmap.org ) at 2025-04-01 12:00 CEST
Nmap scan report for router.local (192.168.1.1)
Host is up (0.0050s latency).
MAC Address: 00:11:22:33:44:55 (Cisco)

Nmap scan report for 192.168.1.2
Host is up (0.0080s latency).
MAC Address: AA:BB:CC:DD:EE:FF (Unknown)

Nmap done: 256 IP addresses (2 hosts up) scanned in 10.50 seconds
        """
        
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = mock_stdout
        mock_process.stderr = ""
        
        with patch('subprocess.run', return_value=mock_process), \
             patch('src.core.scanner.debug'), \
             patch('src.core.scanner.error'):
            result = scanner.scan_network("192.168.1.0/24")
        
        assert len(result) == 2
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result
    
    def test_scan_network_error(self, scanner):
        """Testa scan de rede com erro"""
        mock_process = MagicMock()
        mock_process.returncode = 1
        mock_process.stdout = ""
        mock_process.stderr = "Error: Permission denied"
        
        with patch('subprocess.run', return_value=mock_process), \
             patch('src.core.scanner.debug'), \
             patch('src.core.scanner.error'):
            with pytest.raises(ScannerError, match="Nmap retornou código de erro 1"):
                scanner.scan_network("192.168.1.0/24")
    
    def test_scan_network_timeout(self, scanner):
        """Testa scan de rede com timeout"""
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired("nmap", 60)), \
             patch('src.core.scanner.debug'), \
             patch('src.core.scanner.error'):
            with pytest.raises(ScannerError, match="Timeout durante scan de descoberta"):
                scanner.scan_network("192.168.1.0/24")
    
    def test_scan_network_exception(self, scanner):
        """Testa scan de rede com exceção genérica"""
        with patch('subprocess.run', side_effect=Exception("Test error")), \
             patch('src.core.scanner.debug'), \
             patch('src.core.scanner.error'):
            with pytest.raises(ScannerError, match="Erro durante scan de descoberta"):
                scanner.scan_network("192.168.1.0/24")
    
    def test_scan_host_batch_success(self, scanner):
        """Testa scan de batch de hosts bem-sucedido"""
        mock_stdout = """
Starting Nmap 7.91 ( https://nmap.org ) at 2025-04-01 12:00 CEST
Nmap scan report for 192.168.1.1
Host is up (0.0050s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41

Nmap scan report for 192.168.1.2
Host is up (0.0080s latency).

PORT    STATE SERVICE VERSION
443/tcp open  https   nginx 1.18.0

Nmap done: 2 IP addresses (2 hosts up) scanned in 5.50 seconds
        """
        
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = mock_stdout
        mock_process.stderr = ""
        
        with patch('subprocess.run', return_value=mock_process), \
             patch('src.core.scanner.debug'), \
             patch('src.core.scanner.warning'):
            result = scanner._scan_host_batch(["192.168.1.1", "192.168.1.2"])
        
        assert len(result) == 2
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result
        
        # Verifica as portas do primeiro host
        host1 = result["192.168.1.1"]
        assert len(host1.ports) == 1
        assert host1.ports[0]["port"] == 80
        
        # Verifica as portas do segundo host
        host2 = result["192.168.1.2"]
        assert len(host2.ports) == 1
        assert host2.ports[0]["port"] == 443
    
    def test_scan_host_batch_retry(self, scanner):
        """Testa retry de scan de batch após falha"""
        # Primeiro run falha, segundo run sucede
        mock_stdout_success = """
Starting Nmap 7.91 ( https://nmap.org ) at 2025-04-01 12:00 CEST
Nmap scan report for 192.168.1.1
Host is up (0.0050s latency).
PORT   STATE SERVICE
80/tcp open  http
Nmap done: 1 IP address (1 host up) scanned in 3.50 seconds
        """
        
        mock_fail = MagicMock()
        mock_fail.returncode = 1
        mock_fail.stdout = ""
        mock_fail.stderr = "Error: Network error"
        
        mock_success = MagicMock()
        mock_success.returncode = 0
        mock_success.stdout = mock_stdout_success
        mock_success.stderr = ""
        
        with patch('subprocess.run', side_effect=[mock_fail, mock_success]), \
             patch('time.sleep'), \
             patch('src.core.scanner.debug'), \
             patch('src.core.scanner.warning'):
            result = scanner._scan_host_batch(["192.168.1.1"])
        
        assert len(result) == 1
        assert "192.168.1.1" in result
    
    def test_scan_host_batch_timeout_retry(self, scanner):
        """Testa retry de scan de batch após timeout"""
        # Primeiro run causa timeout, segundo run sucede
        mock_stdout_success = """
Starting Nmap 7.91 ( https://nmap.org ) at 2025-04-01 12:00 CEST
Nmap scan report for 192.168.1.1
Host is up (0.0050s latency).
PORT   STATE SERVICE
80/tcp open  http
Nmap done: 1 IP address (1 host up) scanned in 3.50 seconds
        """
        
        mock_success = MagicMock()
        mock_success.returncode = 0
        mock_success.stdout = mock_stdout_success
        mock_success.stderr = ""
        
        with patch('subprocess.run', side_effect=[subprocess.TimeoutExpired("nmap", 300), mock_success]), \
             patch('time.sleep'), \
             patch('src.core.scanner.debug'), \
             patch('src.core.scanner.warning'):
            result = scanner._scan_host_batch(["192.168.1.1"])
        
        assert len(result) == 1
        assert "192.168.1.1" in result
    
    def test_scan_host_batch_all_attempts_fail(self, scanner):
        """Testa caso onde todas as tentativas de scan de batch falham"""
        with patch('subprocess.run', side_effect=Exception("Test error")), \
             patch('time.sleep'), \
             patch('src.core.scanner.debug'), \
             patch('src.core.scanner.warning'), \
             patch('src.core.scanner.error'):
            result = scanner._scan_host_batch(["192.168.1.1"])
        
        assert result == {}
    
    def test_process_host_batch_parallel(self, scanner):
        """Testa processamento paralelo de batches de hosts"""
        # Mock para _scan_host_batch que retorna resultados diferentes para cada batch
        def mock_scan_batch(ips):
            if "192.168.1.1" in ips:
                host1 = HostInfo("192.168.1.1", ports=[{"port": 80, "protocol": "tcp", "state": "open", "service": "http"}])
                return {"192.168.1.1": host1}
            elif "192.168.1.2" in ips:
                host2 = HostInfo("192.168.1.2", ports=[{"port": 443, "protocol": "tcp", "state": "open", "service": "https"}])
                return {"192.168.1.2": host2}
            return {}
        
        with patch.object(scanner, '_scan_host_batch', side_effect=mock_scan_batch), \
             patch('time.sleep'):
            result = scanner._process_host_batch_parallel([["192.168.1.1"], ["192.168.1.2"]])
        
        assert len(result) == 2
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result
        assert result["192.168.1.1"].ports[0]["port"] == 80
        assert result["192.168.1.2"].ports[0]["port"] == 443
    
    def test_process_host_batch_parallel_error(self, scanner):
        """Testa processamento paralelo com erro em um dos batches"""
        # Mock para _scan_host_batch que retorna resultados para o primeiro batch mas falha no segundo
        def mock_scan_batch(ips):
            if "192.168.1.1" in ips:
                host1 = HostInfo("192.168.1.1", ports=[{"port": 80, "protocol": "tcp", "state": "open", "service": "http"}])
                return {"192.168.1.1": host1}
            elif "192.168.1.2" in ips:
                raise Exception("Test error")
            return {}
        
        with patch.object(scanner, '_scan_host_batch', side_effect=mock_scan_batch), \
             patch('time.sleep'), \
             patch('src.core.scanner.error'):
            result = scanner._process_host_batch_parallel([["192.168.1.1"], ["192.168.1.2"]])
        
        # Deve retornar resultados do primeiro batch mesmo com erro no segundo
        assert len(result) == 1
        assert "192.168.1.1" in result
        assert result["192.168.1.1"].ports[0]["port"] == 80
    
    def test_detailed_scan_empty_hosts(self, scanner):
        """Testa detailed_scan com lista de hosts vazia"""
        with patch('src.core.scanner.warning'):
            result = scanner.detailed_scan({})
        assert result == {}
    
    def test_detailed_scan_no_active_hosts(self, scanner):
        """Testa detailed_scan sem hosts ativos"""
        hosts = {
            "192.168.1.1": HostInfo("192.168.1.1", is_up=False),
            "192.168.1.2": HostInfo("192.168.1.2", is_up=False)
        }
        
        with patch('src.core.scanner.warning'):
            result = scanner.detailed_scan(hosts)
        
        # Deve retornar os hosts originais
        assert result == hosts
    
    def test_detailed_scan_active_hosts(self, scanner):
        """Testa detailed_scan com hosts ativos"""
        hosts = {
            "192.168.1.1": HostInfo("192.168.1.1", hostname="router.local", is_up=True),
            "192.168.1.2": HostInfo("192.168.1.2", is_up=True),
            "192.168.1.3": HostInfo("192.168.1.3", is_up=False)  # Não deve ser escaneado
        }
        
        # Mock para _scan_host_batch que adiciona portas aos hosts
        def mock_scan_batch(ips):
            result = {}
            if "192.168.1.1" in ips:
                result["192.168.1.1"] = HostInfo(
                    "192.168.1.1",
                    ports=[{"port": 80, "protocol": "tcp", "state": "open", "service": "http"}],
                    is_up=True
                )
            if "192.168.1.2" in ips:
                result["192.168.1.2"] = HostInfo(
                    "192.168.1.2",
                    ports=[{"port": 443, "protocol": "tcp", "state": "open", "service": "https"}],
                    is_up=True
                )
            return result
        
        with patch.object(scanner, '_scan_host_batch', side_effect=mock_scan_batch), \
             patch('src.core.scanner.info'):
            result = scanner.detailed_scan(hosts)
        
        # Verifica se todos os hosts originais estão presentes
        assert len(result) == 3
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result
        assert "192.168.1.3" in result
        
        # Verifica se as portas foram adicionadas aos hosts ativos
        assert len(result["192.168.1.1"].ports) == 1
        assert result["192.168.1.1"].ports[0]["port"] == 80
        assert result["192.168.1.1"].hostname == "router.local"  # Manteve o hostname original
        
        assert len(result["192.168.1.2"].ports) == 1
        assert result["192.168.1.2"].ports[0]["port"] == 443
        
        # Verifica que o host inativo não foi modificado
        assert result["192.168.1.3"].ports == []
    
    def test_scan_ports_success(self, scanner):
        """Testa scan_ports bem-sucedido"""
        mock_stdout = """
Starting Nmap 7.91 ( https://nmap.org ) at 2025-04-01 12:00 CEST
Nmap scan report for 192.168.1.1
Host is up (0.0050s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41
443/tcp open  https   nginx 1.18.0

Nmap done: 1 IP address (1 host up) scanned in 3.50 seconds
        """
        
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = mock_stdout
        mock_process.stderr = ""
        
        with patch('subprocess.run', return_value=mock_process), \
             patch('src.core.scanner.debug'), \
             patch('src.core.scanner.warning'):
            result = scanner.scan_ports("192.168.1.1")
        
        assert len(result) == 1
        assert "192.168.1.1" in result
        host = result["192.168.1.1"]
        assert len(host.ports) == 2
        assert host.ports[0]["port"] == 80
        assert host.ports[1]["port"] == 443
    
    def test_scan_ports_timeout(self, scanner):
        """Testa scan_ports com timeout"""
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired("nmap", 120)), \
             patch('src.core.scanner.debug'), \
             patch('src.core.scanner.error'):
            with pytest.raises(ScannerError, match="Timeout durante scan de"):
                scanner.scan_ports("192.168.1.1")
    
    def test_scan_ports_exception(self, scanner):
        """Testa scan_ports com exceção genérica"""
        with patch('subprocess.run', side_effect=Exception("Test error")), \
             patch('src.core.scanner.debug'), \
             patch('src.core.scanner.error'):
            with pytest.raises(ScannerError, match="Erro durante scan de"):
                scanner.scan_ports("192.168.1.1")