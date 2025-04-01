import os
import io
import pytest
import tempfile
import argparse
from unittest.mock import patch, MagicMock, call
from src.ui.cli import CLI
from src.core.scanner import NetworkScanner
from src.reports.report_generator import ReportFormat, ReportGenerator
from src.core.history_manager import HistoryManager
from src.utils.system_utils import SystemUtils

class TestCLI:
    """Testes para o módulo cli.py"""
    
    @pytest.fixture
    def cli_instance(self):
        """Fixture que retorna uma instância limpa do CLI com mocks"""
        with patch('src.ui.cli.ConfigManager') as mock_config, \
             patch('src.ui.cli.HistoryManager') as mock_history, \
             patch('src.ui.cli.NetworkScanner') as mock_scanner:
            
            # Configura os mocks
            mock_config_instance = MagicMock()
            mock_config.return_value = mock_config_instance
            
            mock_history_instance = MagicMock()
            mock_history.return_value = mock_history_instance
            
            mock_scanner_instance = MagicMock()
            mock_scanner.return_value = mock_scanner_instance
            
            # Cria a instância de CLI com os mocks
            cli = CLI()
            
            # Injeta os mocks para verificação
            cli._mock_config = mock_config_instance
            cli._mock_history = mock_history_instance
            cli._mock_scanner = mock_scanner_instance
            
            yield cli
    
    def test_show_header(self):
        """Testa se o cabeçalho é exibido corretamente"""
        with patch('builtins.print') as mock_print:
            CLI.show_header()
            
            # Verifica se print foi chamado com o cabeçalho esperado
            mock_print.assert_any_call("=" * 60)
            mock_print.assert_any_call("ESK_NMAP - Scanner de Rede da Eskel Cybersecurity")
            mock_print.assert_any_call("=" * 60)
    
    def test_show_banner(self):
        """Testa se o banner (alias para show_header) é exibido corretamente"""
        with patch('src.ui.cli.CLI.show_header') as mock_header:
            CLI.show_banner()
            
            # Verifica se show_header foi chamado
            mock_header.assert_called_once()
    
    def test_ask_continue_without_root_yes(self):
        """Testa a pergunta de continuação sem root (resposta sim)"""
        with patch('builtins.input', return_value='s'):
            result = CLI.ask_continue_without_root()
            assert result is True
    
    def test_ask_continue_without_root_no(self):
        """Testa a pergunta de continuação sem root (resposta não)"""
        with patch('builtins.input', return_value='n'):
            result = CLI.ask_continue_without_root()
            assert result is False
    
    def test_ask_continue_without_root_invalid_then_yes(self):
        """Testa a pergunta de continuação sem root (resposta inválida seguida de sim)"""
        with patch('builtins.input', side_effect=['x', 's']):
            with patch('builtins.print') as mock_print:
                result = CLI.ask_continue_without_root()
                
                # Verifica se o retorno está correto e se a mensagem de erro foi exibida
                assert result is True
                mock_print.assert_called_with("Por favor, responda com 's' ou 'n'")
    
    def test_ask_detailed_scan_yes(self):
        """Testa a pergunta sobre scan detalhado (resposta sim)"""
        # Testa diferentes formas de resposta "sim"
        for response in ['s', 'sim', 'y', 'yes']:
            with patch('builtins.input', return_value=response):
                result = CLI.ask_detailed_scan()
                assert result is True
    
    def test_ask_detailed_scan_no(self):
        """Testa a pergunta sobre scan detalhado (resposta não)"""
        # Testa diferentes formas de resposta "não"
        for response in ['n', 'nao', 'não', 'no']:
            with patch('builtins.input', return_value=response):
                result = CLI.ask_detailed_scan()
                assert result is False
    
    def test_ask_detailed_scan_invalid_then_yes(self):
        """Testa a pergunta sobre scan detalhado (resposta inválida seguida de sim)"""
        with patch('builtins.input', side_effect=['x', 's']):
            with patch('builtins.print') as mock_print:
                result = CLI.ask_detailed_scan()
                
                # Verifica se o retorno está correto e se a mensagem de erro foi exibida
                assert result is True
                mock_print.assert_called_with("Por favor, responda 's' ou 'n'.")
    
    def test_display_hosts_table_no_hosts(self):
        """Testa a exibição da tabela de hosts vazia"""
        with patch('builtins.print') as mock_print:
            CLI.display_hosts_table({})
            
            # Verifica se a mensagem de nenhum host foi exibida
            mock_print.assert_called_with("\nNenhum host encontrado na rede.")
    
    def test_display_hosts_table_with_hosts(self):
        """Testa a exibição da tabela de hosts com dados"""
        hosts = {
            "192.168.1.1": MagicMock(
                ip="192.168.1.1",
                status="up",
                hostname="router.local",
                mac="00:11:22:33:44:55",
                vendor="Cisco"
            )
        }
        
        with patch('builtins.print') as mock_print:
            CLI.display_hosts_table(hosts)
            
            # Verifica se os cabeçalhos esperados são exibidos
            mock_print.assert_any_call("\nHosts descobertos:")
            mock_print.assert_any_call(f"\nTotal de hosts descobertos: {len(hosts)}")
    
    def test_display_scan_profiles(self, cli_instance):
        """Testa a exibição dos perfis de scan"""
        # Configura o mock do ConfigManager para retornar perfis predefinidos
        profiles = {
            'basic': {
                'name': 'Scan Básico',
                'description': 'Scan rápido para visão geral da rede',
                'timing': 4,
                'ports': '21-23,25,53,80,443',
                'options': ['-T4', '-sn', '-n']
            },
            'stealth': {
                'name': 'Scan Silencioso',
                'description': 'Scan mais discreto usando SYN stealth',
                'timing': 2,
                'ports': '21-23,25,53,80,443',
                'options': ['-sS', '-T2', '-n']
            }
        }
        
        cli_instance._mock_config._config = {'scan_profiles': profiles}
        
        with patch('builtins.print') as mock_print:
            cli_instance.display_scan_profiles()
            
            # Verifica se os perfis são exibidos
            mock_print.assert_any_call("\nPerfis de Scan Disponíveis:")
            mock_print.assert_any_call("=" * 60)
            
            # Verifica se detalhes dos perfis são exibidos
            for key, profile in profiles.items():
                mock_print.assert_any_call(f"\n{profile['name']} ({key})")
    
    def test_select_scan_profile(self, cli_instance):
        """Testa a seleção de perfil de scan"""
        # Configura o mock do ConfigManager para retornar perfis predefinidos
        profiles = {
            'basic': {'name': 'Scan Básico'},
            'stealth': {'name': 'Scan Silencioso'}
        }
        cli_instance._mock_config._config = {'scan_profiles': profiles}
        
        # Quando o usuário escolhe um perfil existente
        with patch('builtins.input', return_value='stealth'):
            with patch.object(cli_instance, 'display_scan_profiles') as mock_display:
                choice = cli_instance.select_scan_profile()
                
                # Verifica se o perfil correto foi retornado
                assert choice == 'stealth'
                mock_display.assert_called_once()
        
        # Quando o usuário escolhe um perfil inválido e depois um válido
        with patch('builtins.input', side_effect=['invalid', 'basic']):
            with patch('builtins.print') as mock_print:
                with patch.object(cli_instance, 'display_scan_profiles'):
                    choice = cli_instance.select_scan_profile()
                    
                    # Verifica se o perfil correto foi retornado após erro
                    assert choice == 'basic'
                    mock_print.assert_any_call("\nPerfil inválido. Escolha um dos perfis disponíveis: basic, stealth")
    
    def test_get_available_profiles(self, cli_instance):
        """Testa a obtenção dos perfis disponíveis"""
        # Configura o mock do ConfigManager para retornar perfis predefinidos
        profiles = {
            'basic': {'name': 'Scan Básico'},
            'stealth': {'name': 'Scan Silencioso'}
        }
        cli_instance._mock_config._config = {'scan_profiles': profiles}
        
        result = cli_instance.get_available_profiles()
        
        # Verifica se a lista de perfis é correta
        assert set(result) == {'basic', 'stealth'}
    
    def test_display_scan_list_empty(self, cli_instance):
        """Testa a exibição da lista de scans vazia"""
        # Configura mock do HistoryManager para retornar lista vazia
        cli_instance._mock_history.get_scan_list.return_value = []
        
        with patch('builtins.print') as mock_print:
            cli_instance.display_scan_list()
            
            # Verifica se a mensagem correta é exibida
            mock_print.assert_any_call(f"\nÚltimos 10 scans realizados:")
            mock_print.assert_any_call("Nenhum scan encontrado.")
    
    def test_display_scan_list_with_data(self, cli_instance):
        """Testa a exibição da lista de scans com dados"""
        # Configura mock do HistoryManager para retornar scans
        scan_list = [
            {
                'id': 1,
                'timestamp': '2025-03-30T14:30:00',
                'network': '192.168.1.0/24',
                'scan_profile': 'basic',
                'total_hosts': 10
            }
        ]
        cli_instance._mock_history.get_scan_list.return_value = scan_list
        
        with patch('builtins.print') as mock_print:
            cli_instance.display_scan_list()
            
            # Verifica se as chamadas corretas foram feitas
            mock_print.assert_any_call(f"\nÚltimos 10 scans realizados:")
    
    def test_display_scan_list_by_network(self, cli_instance):
        """Testa a exibição da lista de scans filtrada por rede"""
        # Configura mock do HistoryManager para retornar scans
        scan_list = [
            {
                'id': 1,
                'timestamp': '2025-03-30T14:30:00',
                'network': '192.168.1.0/24',
                'scan_profile': 'basic',
                'total_hosts': 10
            }
        ]
        cli_instance._mock_history.get_scans_by_network.return_value = scan_list
        
        with patch('builtins.print') as mock_print:
            cli_instance.display_scan_list("192.168.1.0/24")
            
            # Verifica se as chamadas corretas foram feitas
            mock_print.assert_any_call(f"\nScans encontrados para a rede 192.168.1.0/24:")
    
    def test_handle_scan_command(self, cli_instance):
        """Testa o tratamento do comando scan"""
        # Cria argumentos mock
        args = MagicMock()
        args.network = "192.168.1.0/24"
        args.profile = "basic"
        args.quiet = False
        args.output = None
    
        # Configura mock para SystemUtils.find_nmap_path
        with patch('src.utils.system_utils.SystemUtils.find_nmap_path', return_value="/usr/bin/nmap"):
            # Mock para a classe NetworkScanner que é instanciada dentro do método
            mock_scanner = MagicMock()
            
            # Mock a nova instância do NetworkScanner que é criada no método handle_scan_command
            with patch('src.ui.cli.NetworkScanner', return_value=mock_scanner) as mock_scanner_class:
                # Configura o retorno do scan_network
                mock_scanner.scan_network.return_value = {"192.168.1.1": MagicMock()}
    
                # Chama o método
                cli_instance.handle_scan_command(args)
    
                # Verifica se uma nova instância do NetworkScanner foi criada com o nmap_path
                mock_scanner_class.assert_called_with("/usr/bin/nmap")
                
                # Verifica se a propriedade quiet_mode foi definida
                assert mock_scanner.quiet_mode == args.quiet
                
                # Verifica se os métodos foram chamados corretamente
                mock_scanner.set_scan_profile.assert_called_with("basic")
                mock_scanner.scan_network.assert_called_with("192.168.1.0/24")
    
    def test_handle_scan_command_with_output(self, cli_instance):
        """Testa o tratamento do comando scan com geração de relatório"""
        # Cria argumentos mock
        args = MagicMock()
        args.network = "192.168.1.0/24"
        args.profile = "basic"
        args.quiet = False
        args.output = "report.txt"
        args.format = "text"
    
        # Configura mocks
        with patch('src.utils.system_utils.SystemUtils.find_nmap_path', return_value="/usr/bin/nmap"):
            # Cria mock para nova instância do NetworkScanner
            mock_scanner = MagicMock()
            scan_results = {"192.168.1.1": MagicMock()}
            mock_scanner.scan_network.return_value = scan_results
            
            # Mock a nova instância do NetworkScanner
            with patch('src.ui.cli.NetworkScanner', return_value=mock_scanner):
                # Mock para ReportGenerator
                mock_report = MagicMock()
                with patch('src.reports.report_generator.ReportGenerator', return_value=mock_report) as mock_report_class:
                    # Chama o método
                    cli_instance.handle_scan_command(args)
    
                    # Verifica se o gerador de relatório foi criado e chamado corretamente
                    mock_report_class.assert_called_once()
                    mock_report.generate_report.assert_called_with(
                        scan_results,  # Os resultados do scan devem ser passados diretamente
                        "report.txt",
                        "text"
                    )
    
    def test_scan_no_network_or_ip(self, cli_instance):
        """Testa o comando scan sem rede ou IP"""
        # Cria argumentos mock
        args = MagicMock()
        args.network = None
        args.ip = None
        
        with patch('builtins.print') as mock_print:
            cli_instance.scan(args)
            
            # Verifica se o erro é exibido
            mock_print.assert_called_with("Erro: É necessário especificar uma rede (--network) ou um IP (--ip)")
    
    def test_scan_network(self, cli_instance):
        """Testa o scan de rede"""
        # Cria argumentos mock
        args = MagicMock()
        args.network = "192.168.1.0/24"
        args.ip = None
        args.quiet = True
        args.source_port = None
        
        # Configura o scanner mock para retornar hosts
        hosts = {"192.168.1.1": MagicMock()}
        cli_instance._mock_scanner.scan_network.return_value = hosts
        
        # Patch da função de processamento para verificar se é chamada com os hosts corretos
        with patch.object(cli_instance, 'process_results') as mock_process:
            cli_instance.scan(args)
            
            # Verifica se as chamadas corretas foram feitas
            cli_instance._mock_scanner.set_quiet_mode.assert_called_with(True)
            cli_instance._mock_scanner.scan_network.assert_called_with("192.168.1.0/24")
            mock_process.assert_called_with(hosts)
    
    def test_history_comparison(self, cli_instance):
        """Testa o comando history com comparação"""
        # Cria argumentos mock para comparação
        args = MagicMock()
        args.compare = [1, 2]
        args.output = "comparison.txt"
        args.format = "text"
        
        # Patch da função de exibição para verificar se é chamada corretamente
        with patch.object(cli_instance, 'display_scan_comparison') as mock_display:
            cli_instance.history(args)
            
            # Verifica se a função de comparação foi chamada com os argumentos corretos
            mock_display.assert_called_with(1, 2, "comparison.txt", "text")
    
    def test_history_list(self, cli_instance):
        """Testa o comando history com listagem"""
        # Cria argumentos mock para listagem
        args = MagicMock()
        args.compare = None
        args.limit = 5
        
        # Configura mock para histórico
        history = [
            {
                'id': 1,
                'timestamp': '2025-03-30T14:30:00',
                'network': '192.168.1.0/24',
                'scan_profile': 'basic',
                'total_hosts': 10
            }
        ]
        cli_instance._mock_history.get_scan_list.return_value = history
        
        with patch('builtins.print') as mock_print:
            cli_instance.history(args)
            
            # Verifica se as chamadas corretas foram feitas
            cli_instance._mock_history.get_scan_list.assert_called_with(limit=5)
            mock_print.assert_any_call("\nHistórico de Scans:")
    
    def test_history_empty(self, cli_instance):
        """Testa o comando history com histórico vazio"""
        # Cria argumentos mock
        args = MagicMock()
        args.compare = None
        args.limit = 10
        
        # Configura mock para histórico vazio
        cli_instance._mock_history.get_scan_list.return_value = []
        
        with patch('builtins.print') as mock_print:
            cli_instance.history(args)
            
            # Verifica se a mensagem de vazio é exibida
            mock_print.assert_called_with("Nenhum registro encontrado no histórico.")
    
    def test_report_no_results(self, cli_instance):
        """Testa o comando report sem resultados disponíveis"""
        # Cria argumentos mock
        args = MagicMock()
        args.use_history = False
        args.output = "report.txt"
        args.format = "text"
        
        # Configura para não ter resultados
        cli_instance.last_results = None
        
        with patch('builtins.print') as mock_print:
            cli_instance.report(args)
            
            # Verifica se a mensagem de erro é exibida
            mock_print.assert_called_with("Nenhum resultado de scan disponível.")
    
    def test_report_with_last_results(self, cli_instance):
        """Testa o comando report com os últimos resultados"""
        # Cria argumentos mock
        args = MagicMock()
        args.use_history = False
        args.output = "report.txt"
        args.format = "text"
    
        # Configura resultados
        cli_instance.last_results = {"192.168.1.1": MagicMock()}
    
        # Mock para ReportGenerator
        with patch('src.reports.report_generator.ReportGenerator') as mock_report_class:
            mock_report = MagicMock()
            mock_report_class.return_value = mock_report
    
            # Chama o método
            cli_instance.report(args)
    
            # Verifica se o relatório foi gerado com os últimos resultados
            mock_report.generate_report.assert_called_with(
                cli_instance.last_results,
                "report.txt",
                "text"
            )