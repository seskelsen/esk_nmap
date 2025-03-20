import pytest
import os
import json
import sqlite3
import tempfile
from unittest.mock import patch, MagicMock
from datetime import datetime

from src.core.scanner import NetworkScanner, HostInfo
from src.core.history_manager import HistoryManager
from src.reports.report_generator import ReportGenerator, ReportFormat
from src.utils.config_manager import ConfigManager
from src.ui.cli import CLI

class TestIntegration:
    """Testes de integração do ESK_NMAP para validar a interação entre componentes"""
    
    @pytest.fixture
    def mock_nmap_output(self):
        """Fixture que fornece uma saída simulada de nmap para teste"""
        return """
        Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-01 12:00 UTC
        Nmap scan report for 192.168.1.1
        Host is up (0.0050s latency).
        MAC Address: AA:BB:CC:DD:EE:FF (Vendor Name)
        
        PORT     STATE  SERVICE      VERSION
        22/tcp   open   ssh          OpenSSH 8.2p1
        80/tcp   open   http         Apache 2.4.29
        443/tcp  open   https        nginx 1.18.0
        
        Nmap scan report for router.local (192.168.1.254)
        Host is up (0.0050s latency).
        MAC Address: 11:22:33:44:55:66 (Other Vendor)
        
        PORT     STATE  SERVICE      VERSION
        80/tcp   open   http         Apache 2.4.29
        8080/tcp open   http-proxy   Squid proxy 4.10
        
        Nmap done: 256 IP addresses (2 hosts up) scanned in 2.05 seconds
        """
    
    @pytest.fixture
    def sample_hosts_data(self):
        """Fixture que fornece dados de host para teste"""
        return {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                is_up=True,
                mac="AA:BB:CC:DD:EE:FF",
                vendor="Vendor Name",
                ports=[
                    {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
                    {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
                    {"port": 443, "protocol": "tcp", "state": "open", "service": "https"}
                ]
            ),
            "192.168.1.254": HostInfo(
                ip="192.168.1.254",
                hostname="router.local",
                is_up=True,
                mac="11:22:33:44:55:66",
                vendor="Other Vendor",
                ports=[
                    {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
                    {"port": 8080, "protocol": "tcp", "state": "open", "service": "http-proxy"}
                ]
            )
        }
    
    @pytest.fixture
    def temp_db_path(self):
        """Fixture que cria um banco de dados temporário para o teste"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = os.path.join(tmp_dir, 'test_scan_history.db')
            yield db_path
    
    @pytest.fixture
    def history_manager(self, temp_db_path):
        """Fixture que fornece uma instância do HistoryManager com banco temporário"""
        # Importante: usar nova instância para não afetar o banco de dados real
        with patch('src.core.history_manager.HistoryManager._instance', None):
            with patch('src.core.history_manager.HistoryManager._initialized', False):
                manager = HistoryManager(db_path=temp_db_path)
                yield manager
    
    def test_scan_to_report_integration(self, mock_nmap_output, tmp_path, sample_hosts_data):
        """Testa a integração entre Scanner e ReportGenerator"""
        # Mock do scanner para retornar dados de teste
        with patch('subprocess.Popen') as mock_popen, \
             patch('subprocess.run') as mock_run, \
             patch('tqdm.tqdm'):
            
            # Configura o mock de processo para retornar a saída simulada
            mock_process = MagicMock()
            mock_process.poll.return_value = 0
            mock_process.returncode = 0
            mock_process.communicate.return_value = (mock_nmap_output, "")
            mock_popen.return_value = mock_process
            
            # Configura o mock de subprocess.run para retornar resultados também
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = mock_nmap_output
            mock_run.return_value = mock_result
            
            # Inicializa o scanner com configuração mock
            with patch('src.core.scanner.ConfigManager') as mock_config:
                mock_config_instance = MagicMock()
                mock_config_instance.get_scan_profile.return_value = {
                    'options': ['-sS', '-sV', '-p-']
                }
                mock_config_instance.get_retry_config.return_value = {
                    'max_attempts': 1,
                    'delay_between_attempts': 0
                }
                mock_config_instance.get_timeout.return_value = 30
                mock_config_instance._config = {
                    'scan_profiles': {
                        'basic': {'options': ['-sS']}
                    }
                }
                mock_config.return_value = mock_config_instance
                
                scanner = NetworkScanner()
                scanner._nmap_path = "nmap"  # Garante que o nmap seja encontrado
                
                # Adiciona mock para _parse_nmap_output para retornar hosts com portas
                with patch.object(scanner, '_parse_nmap_output') as mock_parse:
                    # Configurando o mock para retornar dados consistentes
                    mock_parse.return_value = sample_hosts_data
                    
                    # 1. Executa o scan inicial
                    network_range = "192.168.1.0/24"
                    initial_results = scanner.scan_network(network_range)
                    
                    # 2. Executa o scan detalhado
                    detailed_results = scanner.detailed_scan(initial_results)
                    
                    # Verifica os resultados básicos de scanner
                    assert len(detailed_results) == 2
                    assert "192.168.1.1" in detailed_results
                    assert "192.168.1.254" in detailed_results
                    
                    # Garante que o host tenha portas encontradas
                    assert len(detailed_results["192.168.1.1"].ports) >= 1
                    
                    # 3. Gera relatórios em diferentes formatos
                    for format in [ReportFormat.TEXT, ReportFormat.JSON, ReportFormat.CSV, ReportFormat.XML, ReportFormat.HTML]:
                        report_path = tmp_path / f"report.{format.name.lower()}"
                        ReportGenerator.generate_report(str(report_path), detailed_results, network_range, format)
                        
                        # Verificar se os relatórios foram criados
                        assert os.path.exists(report_path)
                        
                        # Verificar conteúdo básico dos relatórios
                        with open(report_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            assert "192.168.1.1" in content
                            
                            if format == ReportFormat.JSON:
                                data = json.loads(content)
                                assert "metadata" in data
                                assert "hosts" in data
                                assert "192.168.1.1" in data["hosts"]
    
    def test_scan_to_history_integration(self, mock_nmap_output, history_manager, sample_hosts_data):
        """Testa a integração entre Scanner e HistoryManager"""
        # Mock do scanner para retornar dados de teste
        with patch('subprocess.Popen') as mock_popen, \
             patch('subprocess.run') as mock_run, \
             patch('tqdm.tqdm'):
            
            # Configura o mock para retornar a saída simulada
            mock_process = MagicMock()
            mock_process.poll.return_value = 0
            mock_process.returncode = 0
            mock_process.communicate.return_value = (mock_nmap_output, "")
            mock_popen.return_value = mock_process
            
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = mock_nmap_output
            mock_run.return_value = mock_result
            
            # Inicializa o scanner com configuração mock
            with patch('src.core.scanner.ConfigManager') as mock_config:
                mock_config_instance = MagicMock()
                mock_config_instance.get_scan_profile.return_value = {
                    'options': ['-sS', '-sV']
                }
                mock_config_instance.get_retry_config.return_value = {
                    'max_attempts': 1,
                    'delay_between_attempts': 0
                }
                mock_config_instance.get_timeout.return_value = 30
                mock_config_instance._config = {
                    'scan_profiles': {
                        'basic': {'options': ['-sS']}
                    }
                }
                mock_config.return_value = mock_config_instance
                
                scanner = NetworkScanner()
                scanner._nmap_path = "nmap"
                
                # Adiciona mock para _parse_nmap_output
                with patch.object(scanner, '_parse_nmap_output') as mock_parse:
                    # Configurando o mock para retornar dados consistentes
                    mock_parse.return_value = sample_hosts_data
                    
                    # 1. Executa o scan
                    network_range = "192.168.1.0/24"
                    initial_results = scanner.scan_network(network_range)
                    detailed_results = scanner.detailed_scan(initial_results)
                    
                    # 2. Salva os resultados no histórico
                    profile_name = "basic"
                    scan_id = history_manager.save_scan_results(network_range, detailed_results, profile_name)
                    
                    # Verifica se o scan foi salvo
                    assert scan_id > 0
                    
                    # 3. Recupera os dados do histórico
                    scan_data = history_manager.get_scan_by_id(scan_id)
                    
                    # Verifica se os dados recuperados correspondem aos salvos
                    assert scan_data is not None
                    assert scan_data['network'] == network_range
                    assert scan_data['scan_profile'] == profile_name
                    assert len(scan_data['hosts']) == 2
                    assert "192.168.1.1" in scan_data['hosts']
                    assert "192.168.1.254" in scan_data['hosts']
                    
                    # 4. Verifica detalhes específicos dos hosts
                    host_data = scan_data['hosts']["192.168.1.1"]
                    assert host_data['ip'] == "192.168.1.1"
                    assert len(host_data['ports']) > 0
    
    def test_history_comparison_integration(self, history_manager, sample_hosts_data):
        """Testa a integração de comparação de scans no HistoryManager"""
        network_range = "192.168.1.0/24"
        
        # 1. Primeiro scan - salva os dados fornecidos pela fixture
        scan_id1 = history_manager.save_scan_results(network_range, sample_hosts_data, "basic")
        
        # 2. Cria uma versão modificada do scan para comparação
        modified_hosts = dict(sample_hosts_data)
        
        # Remove um host
        del modified_hosts["192.168.1.254"]
        
        # Adiciona um novo host
        modified_hosts["192.168.1.10"] = HostInfo(
            ip="192.168.1.10",
            hostname="new-server.local",
            is_up=True,
            mac="CC:DD:EE:FF:00:11",
            vendor="New Vendor",
            ports=[
                {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
                {"port": 3306, "protocol": "tcp", "state": "open", "service": "mysql"}
            ]
        )
        
        # Modifica um host existente (adiciona uma porta)
        modified_hosts["192.168.1.1"].ports.append(
            {"port": 21, "protocol": "tcp", "state": "open", "service": "ftp"}
        )
        
        # 3. Salva o segundo scan no histórico
        scan_id2 = history_manager.save_scan_results(network_range, modified_hosts, "basic")
        
        # 4. Executa a comparação
        comparison = history_manager.compare_scans(scan_id1, scan_id2)
        
        # 5. Verifica os resultados da comparação
        assert comparison is not None
        assert comparison['network'] == network_range
        
        # Verifica hosts novos, removidos e alterados
        assert len(comparison['new_hosts']) == 1
        assert "192.168.1.10" in comparison['new_hosts']
        
        assert len(comparison['removed_hosts']) == 1
        assert "192.168.1.254" in comparison['removed_hosts']
        
        assert len(comparison['changed_hosts']) == 1
        assert "192.168.1.1" in comparison['changed_hosts']
        assert "21/tcp" in str(comparison['changed_hosts']["192.168.1.1"]['new_ports'])
    
    def test_cli_and_scanner_integration(self, mock_nmap_output, sample_hosts_data):
        """Testa a integração entre a interface CLI e o Scanner"""
        # Mock principal para evitar execução real do nmap
        with patch('src.ui.cli.NetworkScanner') as mock_scanner_class:
            # Configure a instância mockada do scanner
            mock_scanner = MagicMock()
            mock_scanner.scan_network.return_value = sample_hosts_data
            mock_scanner_class.return_value = mock_scanner
            
            # Mock para SystemUtils.find_nmap_path
            with patch('src.utils.system_utils.SystemUtils.find_nmap_path') as mock_find_nmap:
                mock_find_nmap.return_value = "/usr/bin/nmap"
                
                # Inicializa o CLI
                cli = CLI()
                
                # Mock argparse para simular argumentos da linha de comando
                with patch('argparse.ArgumentParser.parse_args') as mock_args:
                    mock_args.return_value = MagicMock(
                        command='scan',
                        network='192.168.1.0/24',
                        profile='basic',
                        output=None,
                        format='text',
                        verbose=0,
                        quiet=False,
                        config=None,
                    )
                    
                    # IMPORTANTE: Em vez de chamar handle_command e fazer mock do handler,
                    # vamos chamar diretamente handle_scan_command para testar o fluxo real
                    with patch('src.ui.cli.CLI.display_hosts_table'):
                        cli.handle_scan_command(mock_args.return_value)
                
                # Verifica se o scanner foi chamado corretamente
                mock_scanner.set_scan_profile.assert_called_once()
                mock_scanner.scan_network.assert_called_once()
    
    def test_complete_workflow_integration(self, mock_nmap_output, tmp_path):
        """Testa o fluxo completo: Scan -> Histórico -> Relatório -> Comparação"""
        # Mock para todos os componentes que usam o sistema operacional
        with patch('subprocess.Popen') as mock_popen, \
             patch('subprocess.run') as mock_run, \
             patch('tqdm.tqdm'):
            
            # Configure o mock de processo para retornar a saída simulada
            mock_process = MagicMock()
            mock_process.poll.return_value = 0
            mock_process.returncode = 0
            mock_process.communicate.return_value = (mock_nmap_output, "")
            mock_popen.return_value = mock_process
            
            # Configure o mock de subprocess.run também
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = mock_nmap_output
            mock_run.return_value = mock_result
            
            # Cria um histórico temporário
            db_path = os.path.join(tmp_path, 'workflow_test.db')
            
            # Inicializa componentes necessários com os mocks
            with patch('src.core.history_manager.HistoryManager._instance', None), \
                 patch('src.core.history_manager.HistoryManager._initialized', False), \
                 patch('src.core.scanner.ConfigManager') as mock_config:
                
                # Configure o mock do ConfigManager
                mock_config_instance = MagicMock()
                mock_config_instance.get_scan_profile.return_value = {
                    'options': ['-sS', '-sV'], 'timing': 4
                }
                mock_config_instance.get_retry_config.return_value = {
                    'max_attempts': 1, 'delay_between_attempts': 0
                }
                mock_config_instance.get_timeout.return_value = 30
                mock_config_instance._config = {
                    'scan_profiles': {'complete': {'options': ['-sS', '-sV'], 'timing': 4}}
                }
                mock_config.return_value = mock_config_instance
                
                # Inicializa componentes
                history_manager = HistoryManager(db_path=db_path)
                scanner = NetworkScanner()
                scanner._nmap_path = "nmap"
                scanner._config_manager = mock_config_instance
                
                # Fluxo do teste:
                network_range = "192.168.1.0/24"
                
                # 1. Primeiro scan
                initial_results = scanner.scan_network(network_range)
                detailed_results1 = scanner.detailed_scan(initial_results)
                
                # 2. Salva no histórico
                scan_id1 = history_manager.save_scan_results(
                    network_range, detailed_results1, "complete"
                )
                
                # 3. Gera relatório
                report_path = os.path.join(tmp_path, "scan_report.html")
                ReportGenerator.generate_report(
                    report_path, detailed_results1, network_range, ReportFormat.HTML
                )
                
                # 4. Segundo scan com dados ligeiramente diferentes
                # Simula a descoberta de uma nova porta no segundo scan
                second_mock_output = mock_nmap_output.replace(
                    "PORT     STATE  SERVICE      VERSION", 
                    "PORT     STATE  SERVICE      VERSION\n21/tcp   open   ftp          vsftpd 3.0.3"
                )
                mock_process.communicate.return_value = (second_mock_output, "")
                mock_result.stdout = second_mock_output
                
                # Executa o segundo scan
                initial_results2 = scanner.scan_network(network_range)
                detailed_results2 = scanner.detailed_scan(initial_results2)
                
                # 5. Salva segundo scan
                scan_id2 = history_manager.save_scan_results(
                    network_range, detailed_results2, "complete"
                )
                
                # 6. Compara os scans
                comparison = history_manager.compare_scans(scan_id1, scan_id2)
                
                # 7. Exporta a comparação
                comparison_path = os.path.join(tmp_path, "comparison.json")
                with open(comparison_path, 'w', encoding='utf-8') as f:
                    json.dump(comparison, f, indent=2)
                
                # Verificações:
                assert os.path.exists(report_path)
                assert os.path.exists(comparison_path)
                assert comparison is not None
                assert scan_id1 > 0
                assert scan_id2 > 0
