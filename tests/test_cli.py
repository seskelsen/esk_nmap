import pytest
import platform
import os
import subprocess
import sys
from unittest.mock import patch, MagicMock
from src.ui.cli import CLI
from src.core.scanner import HostInfo
from src.reports.report_generator import ReportFormat

class TestCLI:
    @pytest.fixture
    def sample_hosts_data(self):
        return {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                hostname="router.local",
                mac="00:11:22:33:44:55",
                vendor="Test Vendor",
                is_up=True
            ),
            "192.168.1.2": HostInfo(
                ip="192.168.1.2",
                hostname="pc.local",
                mac="AA:BB:CC:DD:EE:FF",
                vendor="Another Vendor",
                is_up=True
            )
        }

    def test_show_banner(self, capsys):
        CLI.show_banner()
        captured = capsys.readouterr()
        assert "ESK_NMAP" in captured.out
        assert "Scanner de Rede" in captured.out

    def test_show_usage(self, capsys):
        CLI.show_usage("esk_nmap.py")
        captured = capsys.readouterr()
        assert "python esk_nmap.py" in captured.out
        assert "192.168.1.0/24" in captured.out

    @pytest.mark.parametrize("user_input,expected", [
        ("s", True),
        ("S", True),
        ("n", False),
        ("N", False),
    ])
    def test_ask_continue_without_root(self, user_input, expected):
        with patch("builtins.input", return_value=user_input):
            assert CLI.ask_continue_without_root() == expected

    @pytest.mark.parametrize("user_input,expected", [
        ("s", True),
        ("S", True),
        ("n", False),
        ("N", False),
    ])
    def test_ask_detailed_scan(self, user_input, expected):
        with patch("builtins.input", return_value=user_input):
            assert CLI.ask_detailed_scan() == expected
            
    def test_ask_continue_invalid_then_valid(self):
        with patch("builtins.input", side_effect=["invalid", "s"]):
            assert CLI.ask_continue_without_root() == True
            
    def test_ask_detailed_scan_invalid_then_valid(self):
        with patch("builtins.input", side_effect=["invalid", "n"]):
            assert CLI.ask_detailed_scan() == False

    def test_display_hosts_table(self, sample_hosts_data, capsys):
        CLI.display_hosts_table(sample_hosts_data)
        captured = capsys.readouterr()
        assert "192.168.1.1" in captured.out
        assert "router.local" in captured.out
        assert "00:11:22:33:44:55" in captured.out
        assert "Test Vendor" in captured.out
        assert "Total de hosts descobertos: 2" in captured.out

    def test_display_scan_list_with_data(self, capsys):
        """Testa exibição da lista de scans com dados"""
        cli = CLI()
        mock_scans = [
            {
                'id': 1,
                'timestamp': '2024-01-01T10:00:00',
                'network': '192.168.1.0/24',
                'scan_profile': 'basic',
                'total_hosts': 5
            }
        ]
        
        with patch.object(cli.history_manager, 'get_scan_list', return_value=mock_scans):
            cli.display_scan_list()
            captured = capsys.readouterr()
            assert '192.168.1.0/24' in captured.out
            assert 'basic' in captured.out
            assert '2024-01-01' in captured.out
    
    def test_display_scan_list_empty(self, capsys):
        """Testa exibição da lista de scans vazia"""
        cli = CLI()
        with patch.object(cli.history_manager, 'get_scan_list', return_value=[]):
            cli.display_scan_list()
            captured = capsys.readouterr()
            assert 'Nenhum scan encontrado' in captured.out
    
    def test_display_scan_list_with_network_filter(self, capsys):
        """Testa exibição da lista de scans com filtro de rede"""
        cli = CLI()
        mock_scans = [
            {
                'id': 1,
                'timestamp': '2024-01-01T10:00:00',
                'network': '192.168.1.0/24',
                'scan_profile': 'basic',
                'total_hosts': 3
            }
        ]
        
        with patch.object(cli.history_manager, 'get_scans_by_network', return_value=mock_scans):
            cli.display_scan_list(network='192.168.1.0/24')
            captured = capsys.readouterr()
            assert 'Scans encontrados para a rede 192.168.1.0/24' in captured.out
    
    def test_display_scan_details_found(self, capsys, sample_hosts_data):
        """Testa exibição dos detalhes de um scan existente"""
        cli = CLI()
        mock_scan = {
            'id': 1,
            'timestamp': '2024-01-01T10:00:00',
            'network': '192.168.1.0/24',
            'scan_profile': 'basic',
            'total_hosts': 2,
            'hosts': sample_hosts_data
        }
        
        with patch.object(cli.history_manager, 'get_scan_by_id', return_value=mock_scan):
            cli.display_scan_details(1)
            captured = capsys.readouterr()
            assert 'Detalhes do Scan 1' in captured.out
            assert '192.168.1.0/24' in captured.out
            assert 'basic' in captured.out
    
    def test_display_scan_details_not_found(self, capsys):
        """Testa exibição dos detalhes de um scan inexistente"""
        cli = CLI()
        with patch.object(cli.history_manager, 'get_scan_by_id', return_value=None):
            cli.display_scan_details(999)
            captured = capsys.readouterr()
            assert 'Scan 999 não encontrado' in captured.out
    
    def test_display_scan_details_export_json(self, capsys, sample_hosts_data):
        """Testa exportação dos detalhes de um scan para JSON"""
        cli = CLI()
        mock_scan = {
            'id': 1,
            'timestamp': '2024-01-01T10:00:00',
            'network': '192.168.1.0/24',
            'scan_profile': 'basic',
            'total_hosts': 2,
            'hosts': sample_hosts_data
        }
        
        with patch.object(cli.history_manager, 'get_scan_by_id', return_value=mock_scan):
            with patch.object(cli.history_manager, 'export_scan_to_json', return_value=True):
                cli.display_scan_details(1, output='scan.json', format='json')
                captured = capsys.readouterr()
                assert 'exportados para scan.json' in captured.out
    
    def test_display_scan_details_export_error(self, capsys, sample_hosts_data):
        """Testa erro na exportação dos detalhes de um scan"""
        cli = CLI()
        mock_scan = {
            'id': 1,
            'timestamp': '2024-01-01T10:00:00',
            'network': '192.168.1.0/24',
            'scan_profile': 'basic',
            'total_hosts': 2,
            'hosts': sample_hosts_data
        }
        
        with patch.object(cli.history_manager, 'get_scan_by_id', return_value=mock_scan):
            with patch.object(cli.history_manager, 'export_scan_to_json', return_value=False):
                cli.display_scan_details(1, output='scan.json', format='json')
                captured = capsys.readouterr()
                assert 'Erro ao exportar scan' in captured.out
    
    def test_display_scan_comparison(self, capsys):
        """Testa exibição da comparação entre dois scans"""
        cli = CLI()
        mock_comparison = {
            'network': '192.168.1.0/24',
            'scan1': {'timestamp': '2024-01-01T10:00:00', 'total_hosts': 3},
            'scan2': {'timestamp': '2024-01-02T10:00:00', 'total_hosts': 4},
            'summary': {
                'new_hosts': 1,
                'removed_hosts': 0,
                'changed_hosts': 1,
                'unchanged_hosts': 2
            },
            'new_hosts': {'192.168.1.4': {'hostname': 'new.local'}},
            'removed_hosts': {},
            'changed_hosts': {
                '192.168.1.1': {
                    'hostname': 'changed.local',
                    'new_ports': ['80'],
                    'closed_ports': ['443']
                }
            }
        }
        
        with patch.object(cli.history_manager, 'compare_scans', return_value=mock_comparison):
            cli.display_scan_comparison(1, 2)
            captured = capsys.readouterr()
            assert 'Comparação entre Scan 1 e Scan 2' in captured.out
            assert 'Hosts novos: 1' in captured.out
            assert 'new.local' in captured.out
    
    def test_display_scan_comparison_error(self, capsys):
        """Testa exibição de erro na comparação entre scans"""
        cli = CLI()
        with patch.object(cli.history_manager, 'compare_scans', return_value={'error': 'Scans não encontrados'}):
            cli.display_scan_comparison(1, 2)
            captured = capsys.readouterr()
            assert 'Erro ao comparar scans' in captured.out
    
    def test_display_scan_comparison_export_error(self, capsys):
        """Testa erro na exportação da comparação de scans"""
        cli = CLI()
        mock_comparison = {
            'network': '192.168.1.0/24',
            'scan1': {'timestamp': '2024-01-01T10:00:00', 'total_hosts': 3},
            'scan2': {'timestamp': '2024-01-02T10:00:00', 'total_hosts': 4},
            'summary': {'new_hosts': 1, 'removed_hosts': 0, 'changed_hosts': 0, 'unchanged_hosts': 2},
            'new_hosts': {'192.168.1.4': {'hostname': 'new.local'}},
            'removed_hosts': {},
            'changed_hosts': {}
        }
        
        with patch.object(cli.history_manager, 'compare_scans', return_value=mock_comparison):
            with patch('builtins.open', side_effect=Exception('Erro de permissão')):
                cli.display_scan_comparison(1, 2, output='compare.json')
                captured = capsys.readouterr()
                assert 'Erro ao exportar comparação' in captured.out
    
    def test_delete_scan_confirmed(self, capsys):
        """Testa exclusão de scan com confirmação"""
        cli = CLI()
        with patch('builtins.input', return_value='s'):
            with patch.object(cli.history_manager, 'delete_scan', return_value=True):
                cli.delete_scan(1)
                captured = capsys.readouterr()
                assert 'excluído com sucesso' in captured.out
    
    def test_delete_scan_cancelled(self, capsys):
        """Testa cancelamento da exclusão de scan"""
        cli = CLI()
        with patch('builtins.input', return_value='n'):
            cli.delete_scan(1)
            captured = capsys.readouterr()
            assert 'Operação cancelada' in captured.out

    def test_parse_arguments_scan(self, monkeypatch):
        """Testa parser de argumentos para comando scan"""
        test_args = ['scan', '192.168.1.0/24', '--profile', 'basic', '--output', 'report.json', '--format', 'json', '--quiet']
        monkeypatch.setattr('sys.argv', ['esk_nmap.py'] + test_args)
        args = CLI.parse_arguments()
        assert args.command == 'scan'
        assert args.network == '192.168.1.0/24'
        assert args.profile == 'basic'
        assert args.output == 'report.json'
        assert args.format == 'json'
        assert args.quiet == True

    def test_parse_arguments_history_list(self, monkeypatch):
        """Testa parser de argumentos para comando history list"""
        test_args = ['history', 'list', '--network', '192.168.1.0/24', '--limit', '5']
        monkeypatch.setattr('sys.argv', ['esk_nmap.py'] + test_args)
        args = CLI.parse_arguments()
        assert args.command == 'history'
        assert args.history_command == 'list'
        assert args.network == '192.168.1.0/24'
        assert args.limit == 5

    def test_parse_arguments_history_show(self, monkeypatch):
        """Testa parser de argumentos para comando history show"""
        test_args = ['history', 'show', '1', '--output', 'scan.json', '--format', 'json']
        monkeypatch.setattr('sys.argv', ['esk_nmap.py'] + test_args)
        args = CLI.parse_arguments()
        assert args.command == 'history'
        assert args.history_command == 'show'
        assert args.id == 1
        assert args.output == 'scan.json'
        assert args.format == 'json'

    def test_handle_scan_command_with_report(self):
        """Testa comando scan com geração de relatório"""
        cli = CLI()
        args = type('Args', (), {
            'network': '192.168.1.0/24',
            'profile': 'basic',
            'output': 'report.txt',
            'format': 'text',
            'quiet': False
        })()
        
        mock_results = {
            '192.168.1.1': HostInfo(
                ip='192.168.1.1',
                hostname='test.local',
                mac='00:11:22:33:44:55',
                vendor='Test Vendor',
                is_up=True
            )
        }
        
        nmap_path = '/usr/bin/nmap'
        with patch('src.utils.system_utils.SystemUtils.find_nmap_path', return_value=nmap_path):
            with patch('src.ui.cli.NetworkScanner', autospec=True) as MockScanner:
                mock_scanner_instance = MockScanner.return_value
                mock_scanner_instance.scan_network.return_value = mock_results
                
                with patch('src.reports.report_generator.ReportGenerator.generate_report') as mock_generate:
                    cli.handle_scan_command(args)
                    
                    MockScanner.assert_called_once_with(nmap_path)
                    mock_scanner_instance.scan_network.assert_called_once_with(args.network)
                    mock_generate.assert_called_once_with(mock_results, 'report.txt', 'text')

    def test_handle_command_scan(self):
        """Testa manipulação do comando scan"""
        cli = CLI()
        args = type('Args', (), {
            'command': 'scan',
            'network': '192.168.1.0/24',
            'profile': 'basic',
            'output': None,
            'format': 'text',
            'quiet': False
        })()
        
        with patch.object(cli, 'handle_scan_command') as mock_handle:
            cli.handle_command(args)
            mock_handle.assert_called_once_with(args)
    
    def test_handle_command_history(self):
        """Testa manipulação do comando history"""
        cli = CLI()
        args = type('Args', (), {
            'command': 'history',
            'history_command': 'list',
            'network': None,
            'limit': 10
        })()
        
        with patch.object(cli, 'handle_history_commands') as mock_handle:
            cli.handle_command(args)
            mock_handle.assert_called_once_with(args)

import pytest
from argparse import Namespace
from unittest.mock import patch, MagicMock, Mock, call

from src.ui.cli import CLI
from src.core.scanner import HostInfo, ScannerError

class TestCLI:
    @pytest.fixture
    def cli(self):
        """Fixture para criar uma instância de CLI para testes"""
        with patch('src.core.scanner.NetworkScanner') as mock_scanner:
            # Configure mock scanner
            scanner_instance = mock_scanner.return_value
            
            # Create CLI instance with mock scanner
            cli_instance = CLI()
            cli_instance.scanner = scanner_instance
            
            # Return both CLI and scanner mock for use in tests
            yield (cli_instance, scanner_instance)
    
    def test_show_header(self, cli, capfd):
        """Testa a exibição do cabeçalho do CLI"""
        cli_instance, _ = cli
        cli_instance.show_header()
        
        captured = capfd.readouterr()
        assert "ESK Nmap Scanner" in captured.out
        assert "Versão" in captured.out
    
    def test_parse_arguments_defaults(self):
        """Testa o parser de argumentos com valores padrão"""
        with patch('sys.argv', ['esk_nmap.py']):
            cli = CLI()
            args = cli.parse_arguments()
            
            assert args.network is None
            assert args.ip is None
            assert args.profile == "basic"
            assert args.quiet is False
            assert args.batch_size == 10
            assert args.max_threads == 5
            assert args.verbose == 0
    
    def test_parse_arguments_custom(self):
        """Testa o parser de argumentos com valores customizados"""
        with patch('sys.argv', [
            'esk_nmap.py',
            '--network', '192.168.1.0/24',
            '--profile', 'stealth',
            '--quiet',
            '--batch-size', '20',
            '--max-threads', '10',
            '-v'
        ]):
            cli = CLI()
            args = cli.parse_arguments()
            
            assert args.network == '192.168.1.1.0/24'
            assert args.profile == "stealth"
            assert args.quiet is True
            assert args.batch_size == 20
            assert args.max_threads == 10
            assert args.verbose == 1
    
    def test_scan_network(self, cli):
        """Testa o método scan_network do CLI"""
        cli_instance, scanner_mock = cli
        
        # Configure mock returns
        scanner_mock.scan_network.return_value = {
            "192.168.1.1": HostInfo(ip="192.168.1.1", is_up=True),
            "192.168.1.2": HostInfo(ip="192.168.1.2", is_up=False)
        }
        
        # Call method
        args = Namespace(network="192.168.1.0/24", quiet=False)
        results = cli_instance.scan_network(args)
        
        # Verify calls
        scanner_mock.scan_network.assert_called_once_with("192.168.1.0/24")
        
        # Verify results
        assert len(results) == 2
        assert "192.168.1.1" in results
        assert "192.168.1.2" in results
    
    def test_detailed_scan(self, cli):
        """Testa o método detailed_scan do CLI"""
        cli_instance, scanner_mock = cli
        
        # Configure initial hosts
        hosts = {
            "192.168.1.1": HostInfo(ip="192.168.1.1", is_up=True),
            "192.168.1.2": HostInfo(ip="192.168.1.2", is_up=True)
        }
        
        # Configure mock returns
        scanner_mock.detailed_scan.return_value = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                is_up=True,
                ports=[
                    {"port": 80, "protocol": "tcp", "state": "open", "service": "http"}
                ]
            ),
            "192.168.1.2": HostInfo(
                ip="192.168.1.2",
                is_up=True,
                ports=[
                    {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"}
                ]
            )
        }
        
        # Call method
        results = cli_instance.detailed_scan(hosts)
        
        # Verify calls
        scanner_mock.detailed_scan.assert_called_once_with(hosts, parallel=True)
        
        # Verify results
        assert len(results) == 2
        assert len(results["192.168.1.1"].ports) == 1
        assert results["192.168.1.1"].ports[0]["port"] == 80
        assert len(results["192.168.1.2"].ports) == 1
        assert results["192.168.1.2"].ports[0]["port"] == 22
    
    def test_process_results(self, cli, capfd):
        """Testa o método process_results do CLI"""
        cli_instance, _ = cli
        
        # Create test results
        results = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                hostname="host1.local",
                mac="00:11:22:33:44:55",
                vendor="Vendor1",
                is_up=True,
                ports=[
                    {"port": 80, "protocol": "tcp", "state": "open", "service": "http"}
                ]
            ),
            "192.168.1.2": HostInfo(
                ip="192.168.1.2",
                is_up=False
            )
        }
        
        # Test method
        cli_instance.process_results(results)
        
        # Verify output
        captured = capfd.readouterr()
        assert "192.168.1.1" in captured.out
        assert "host1.local" in captured.out
        assert "00:11:22:33:44:55" in captured.out
        assert "Vendor1" in captured.out
        assert "80/tcp" in captured.out
        assert "http" in captured.out
        assert "192.168.1.2" in captured.out
        assert "down" in captured.out
    
    def test_scan_ports_with_ip(self, cli):
        """Testa o método scan_ports com um IP específico"""
        cli_instance, scanner_mock = cli
        
        # Configure mock returns
        scanner_mock.scan_ports.return_value = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                is_up=True,
                ports=[
                    {"port": 80, "protocol": "tcp", "state": "open", "service": "http"}
                ]
            )
        }
        
        # Call method with IP
        args = Namespace(ip="192.168.1.1", quiet=False)
        results = cli_instance.scan_ports(args)
        
        # Verify calls
        scanner_mock.scan_ports.assert_called_once_with("192.168.1.1")
        
        # Verify results
        assert "192.168.1.1" in results
        assert len(results["192.168.1.1"].ports) == 1
    
    def test_scan_command_network(self, cli):
        """Testa o comando scan com argumento de rede"""
        cli_instance, scanner_mock = cli
        
        # Configure mock returns for both scan methods
        scanner_mock.scan_network.return_value = {
            "192.168.1.1": HostInfo(ip="192.168.1.1", is_up=True),
            "192.168.1.2": HostInfo(ip="192.168.1.2", is_up=False)
        }
        
        scanner_mock.detailed_scan.return_value = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                is_up=True,
                ports=[{"port": 80, "protocol": "tcp", "state": "open", "service": "http"}]
            ),
            "192.168.1.2": HostInfo(ip="192.168.1.2", is_up=False)
        }
        
        # Call scan command
        args = Namespace(
            network="192.168.1.0/24",
            ip=None,
            profile="basic",
            quiet=False,
            batch_size=10,
            max_threads=5,
            verbose=0
        )
        with patch('builtins.input', return_value='y'):
            cli_instance.scan(args)
        
        # Verify calls
        scanner_mock.scan_network.assert_called_once_with("192.168.1.0/24")
        scanner_mock.detailed_scan.assert_called_once()
    
    def test_scan_command_no_confirmation(self, cli, capfd):
        """Testa o comando scan quando o usuário não confirma"""
        cli_instance, scanner_mock = cli
        
        # Configure mock for scan_network
        scanner_mock.scan_network.return_value = {
            "192.168.1.1": HostInfo(ip="192.168.1.1", is_up=True)
        }
        
        # Call scan command with mock input returning 'n'
        args = Namespace(
            network="192.168.1.0/24",
            ip=None,
            profile="basic",
            quiet=False,
            batch_size=10,
            max_threads=5,
            verbose=0
        )
        with patch('builtins.input', return_value='n'):
            cli_instance.scan(args)
        
        # Verify scan_network was called but detailed_scan was not
        scanner_mock.scan_network.assert_called_once()
        scanner_mock.detailed_scan.assert_not_called()
        
        # Check output
        captured = capfd.readouterr()
        assert "Scan de portas cancelado" in captured.out
    
    def test_scan_command_ip(self, cli):
        """Testa o comando scan com argumento de IP"""
        cli_instance, scanner_mock = cli
        
        # Configure mock returns
        scanner_mock.scan_ports.return_value = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                is_up=True,
                ports=[{"port": 80, "protocol": "tcp", "state": "open", "service": "http"}]
            )
        }
        
        # Call scan command
        args = Namespace(
            network=None,
            ip="192.168.1.1",
            profile="basic",
            quiet=False,
            batch_size=10,
            max_threads=5,
            verbose=0
        )
        cli_instance.scan(args)
        
        # Verify calls
        scanner_mock.scan_ports.assert_called_once_with("192.168.1.1")
        scanner_mock.scan_network.assert_not_called()
        scanner_mock.detailed_scan.assert_not_called()
    
    def test_scan_command_no_args(self, cli, capfd):
        """Testa o comando scan sem argumentos"""
        cli_instance, _ = cli
        
        # Call scan command without args
        args = Namespace(
            network=None,
            ip=None,
            profile="basic",
            quiet=False,
            batch_size=10,
            max_threads=5,
            verbose=0
        )
        cli_instance.scan(args)
        
        # Check error message
        captured = capfd.readouterr()
        assert "Erro: É necessário especificar um endereço IP ou uma rede" in captured.out
    
    @patch('src.core.history_manager.HistoryManager')
    def test_history_command(self, mock_history_manager, cli, capfd):
        """Testa o comando history"""
        cli_instance, _ = cli
        
        # Configure mock history manager
        history_mgr_instance = mock_history_manager.return_value
        history_mgr_instance.get_scan_list.return_value = [
            {
                "id": 1,
                "timestamp": "2024-01-01T10:00:00",
                "network": "192.168.1.0/24",
                "scan_profile": "basic",
                "total_hosts": 2
            }
        ]
        
        # Call history command
        args = Namespace(command='history', limit=5)
        cli_instance.history(args)
        
        # Check output
        captured = capfd.readouterr()
        assert "Histórico de Scans" in captured.out
        assert "2024-01-01" in captured.out
        assert "192.168.1.0/24" in captured.out
        assert "basic" in captured.out
    
    @patch('src.reports.report_generator.ReportGenerator')
    def test_report_command_with_history(self, mock_report_generator, cli, capfd):
        """Testa o comando report usando dados do histórico"""
        cli_instance, _ = cli
        
        # Configure mock report generator
        report_gen_instance = mock_report_generator.return_value
        
        # Call report command with history option
        args = Namespace(
            format="html",
            output="report.html",
            use_history=True,
            index=0
        )
        cli_instance.report(args)
        
        # Check calls and output
        report_gen_instance.generate_from_history.assert_called_once_with(
            format_type="html",
            output_file="report.html",
            history_index=0
        )
        
        captured = capfd.readouterr()
        assert "Gerando relatório a partir do histórico" in captured.out
    
    @patch('src.reports.report_generator.ReportGenerator')
    def test_report_command_with_results(self, mock_report_generator, cli, capfd):
        """Testa o comando report usando resultados atuais"""
        cli_instance, _ = cli
        
        # Configure mock report generator
        report_gen_instance = mock_report_generator.return_value
        
        # Set some scan results
        cli_instance.last_results = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                is_up=True,
                ports=[{"port": 80, "protocol": "tcp", "state": "open", "service": "http"}]
            )
        }
        
        # Call report command with current results
        args = Namespace(
            format="html",
            output="report.html",
            use_history=False,
            index=None
        )
        cli_instance.report(args)
        
        # Check calls and output
        report_gen_instance.generate.assert_called_once_with(
            scan_results=cli_instance.last_results,
            format_type="html",
            output_file="report.html"
        )
        
        captured = capfd.readouterr()
        assert "Gerando relatório a partir dos resultados atuais" in captured.out
    
    @patch('src.reports.report_generator.ReportGenerator')
    def test_report_command_no_results(self, mock_report_generator, cli, capfd):
        """Testa o comando report quando não há resultados disponíveis"""
        cli_instance, _ = cli
        
        # No results available
        cli_instance.last_results = None
        
        # Call report command
        args = Namespace(
            format="html",
            output="report.html",
            use_history=False,
            index=None
        )
        cli_instance.report(args)
        
        # Check output
        captured = capfd.readouterr()
        assert "Erro: Nenhum resultado de scan disponível" in captured.out
        
        # Ensure report generator was not called
        mock_report_generator.assert_not_called()
    
    def test_main(self, cli):
        """Testa o método main do CLI"""
        cli_instance, _ = cli
        
        # Mock parse_arguments and dispatch methods
        cli_instance.parse_arguments = MagicMock(return_value=Namespace(
            func=MagicMock(),  # Mock the command function
        ))
        
        # Call main
        cli_instance.main()
        
        # Verify parse_arguments was called and the command function was executed
        cli_instance.parse_arguments.assert_called_once()
        cli_instance.parse_arguments().func.assert_called_once_with(cli_instance.parse_arguments())

import pytest
from argparse import Namespace
from unittest.mock import patch, MagicMock, Mock, call
from src.ui.cli import CLI
from src.core.scanner import HostInfo, NetworkScanner
from src.reports.report_generator import ReportFormat

class TestCLI:
    @pytest.fixture
    def sample_hosts_data(self):
        """Fixture que fornece dados de exemplo de hosts para testes"""
        return {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                hostname="router.local",
                mac="00:11:22:33:44:55",
                vendor="Test Vendor",
                is_up=True,
                ports=[{"port": 80, "state": "open", "service": "http"}]
            ),
            "192.168.1.2": HostInfo(
                ip="192.168.1.2",
                hostname="desktop.local",
                mac="AA:BB:CC:DD:EE:FF",
                vendor="Test Vendor 2",
                is_up=True,
                ports=[{"port": 22, "state": "open", "service": "ssh"}]
            )
        }

    @pytest.fixture
    def cli(self):
        """Fixture para criar uma instância de CLI para testes"""
        return CLI()

    def test_show_banner(self, capsys):
        """Testa se o banner é exibido corretamente"""
        CLI.show_banner()
        captured = capsys.readouterr()
        assert "ESK_NMAP" in captured.out
        assert "Scanner de Rede" in captured.out

    def test_show_header(self, capsys):
        """Testa se o header é exibido corretamente (deve ser igual ao banner)"""
        CLI.show_header()
        captured = capsys.readouterr()
        assert "ESK_NMAP" in captured.out
        assert "Scanner de Rede" in captured.out

    def test_parse_arguments_scan_command(self, monkeypatch):
        """Testa o parser com comando scan"""
        test_args = ['scan', '--network', '192.168.1.0/24', '--profile', 'basic']
        monkeypatch.setattr('sys.argv', ['esk_nmap.py'] + test_args)
        
        args = CLI.parse_arguments()
        assert args.command == 'scan'
        assert args.network == '192.168.1.0/24'
        assert args.profile == 'basic'

    def test_parse_arguments_scan_ip(self, monkeypatch):
        """Testa o parser com scan de IP específico"""
        test_args = ['scan', '--ip', '192.168.1.1']
        monkeypatch.setattr('sys.argv', ['esk_nmap.py'] + test_args)
        
        args = CLI.parse_arguments()
        assert args.command == 'scan'
        assert args.ip == '192.168.1.1'

    def test_parse_arguments_history_command(self, monkeypatch):
        """Testa o parser com comando history"""
        test_args = ['history', '--limit', '5']
        monkeypatch.setattr('sys.argv', ['esk_nmap.py'] + test_args)
        
        args = CLI.parse_arguments()
        assert args.command == 'history'
        assert args.limit == 5

    def test_parse_arguments_report_command(self, monkeypatch):
        """Testa o parser com comando report"""
        test_args = ['report', '--output', 'report.json', '--format', 'json']
        monkeypatch.setattr('sys.argv', ['esk_nmap.py'] + test_args)
        
        args = CLI.parse_arguments()
        assert args.command == 'report'
        assert args.output == 'report.json'
        assert args.format == 'json'

    @pytest.mark.parametrize("user_input,expected", [
        ("s", True),
        ("S", True),
        ("n", False),
        ("N", False),
    ])
    def test_ask_detailed_scan(self, user_input, expected):
        with patch("builtins.input", return_value=user_input):
            assert CLI.ask_detailed_scan() == expected

    def test_scan_network(self, cli):
        """Testa o método scan_network"""
        with patch.object(cli.scanner, 'scan_network') as mock_scan:
            mock_scan.return_value = {
                "192.168.1.1": HostInfo(ip="192.168.1.1", is_up=True)
            }
            
            args = Namespace(network="192.168.1.0/24", quiet=False, profile="basic")
            results = cli.scan_network(args)
            
            mock_scan.assert_called_once_with("192.168.1.0/24")
            assert "192.168.1.1" in results

    def test_detailed_scan(self, cli):
        """Testa o método detailed_scan"""
        hosts = {
            "192.168.1.1": HostInfo(ip="192.168.1.1", is_up=True)
        }
        
        with patch.object(cli.scanner, 'detailed_scan') as mock_scan:
            mock_scan.return_value = {
                "192.168.1.1": HostInfo(
                    ip="192.168.1.1",
                    is_up=True,
                    ports=[{"port": 80, "state": "open"}]
                )
            }
            
            results = cli.detailed_scan(hosts)
            mock_scan.assert_called_once_with(hosts)
            assert len(results["192.168.1.1"].ports) == 1

    def test_scan_ports(self, cli):
        """Testa o método scan_ports"""
        with patch.object(cli.scanner, 'scan_ports') as mock_scan:
            mock_scan.return_value = {
                "192.168.1.1": HostInfo(
                    ip="192.168.1.1",
                    is_up=True,
                    ports=[{"port": 80, "state": "open"}]
                )
            }
            
            args = Namespace(ip="192.168.1.1", quiet=False)
            results = cli.scan_ports(args)
            
            mock_scan.assert_called_once_with("192.168.1.1")
            assert "192.168.1.1" in results

    def test_process_results(self, cli, capsys, sample_hosts_data):
        """Testa o processamento e exibição dos resultados"""
        cli.process_results(sample_hosts_data)
        captured = capsys.readouterr()
        
        assert "192.168.1.1" in captured.out
        assert "router.local" in captured.out
        assert "Test Vendor" in captured.out

    def test_scan_command_network(self, cli):
        """Testa o comando scan com rede"""
        args = Namespace(
            command='scan',
            network='192.168.1.0/24',
            ip=None,
            profile='basic',
            quiet=False
        )
        
        with patch.object(cli, 'scan_network') as mock_scan_net, \
             patch.object(cli, 'detailed_scan') as mock_detailed, \
             patch.object(cli, 'process_results') as mock_process, \
             patch.object(cli, 'ask_detailed_scan', return_value=True):
            
            mock_scan_net.return_value = {"192.168.1.1": MagicMock()}
            cli.scan(args)
            
            mock_scan_net.assert_called_once_with(args)
            mock_detailed.assert_called_once()
            mock_process.assert_called_once()

    def test_scan_command_ip(self, cli):
        """Testa o comando scan com IP"""
        args = Namespace(
            command='scan',
            network=None,
            ip='192.168.1.1',
            profile='basic',
            quiet=False
        )
        
        with patch.object(cli, 'scan_ports') as mock_scan_ports, \
             patch.object(cli, 'process_results') as mock_process:
            
            cli.scan(args)
            
            mock_scan_ports.assert_called_once_with(args)
            mock_process.assert_called_once()

    def test_history_command(self, cli, capsys):
        """Testa o comando history"""
        args = Namespace(command='history', limit=5)
        mock_history = [
            {
                "id": 1,
                "timestamp": "2024-01-01T10:00:00",
                "network": "192.168.1.0/24",
                "scan_profile": "basic",
                "total_hosts": 2
            }
        ]
        
        with patch.object(cli.history_manager, 'get_scan_list', return_value=mock_history):
            cli.history(args)
            
            captured = capsys.readouterr()
            assert "Histórico de Scans" in captured.out
            assert "2024-01-01" in captured.out
            assert "192.168.1.0/24" in captured.out
            assert "basic" in captured.out

    def test_report_command(self, cli, capsys):
        """Testa o comando report"""
        args = Namespace(
            command='report',
            output='report.json',
            format='json',
            use_history=False
        )
        
        cli.last_results = {"192.168.1.1": MagicMock()}
        
        with patch('src.reports.report_generator.ReportGenerator.generate_report') as mock_generate:
            cli.report(args)
            
            mock_generate.assert_called_once()
            captured = capsys.readouterr()
            assert "Relatório gerado" in captured.out

    def test_main_with_valid_command(self, cli):
        """Testa o método main com comando válido"""
        mock_args = Namespace(
            command='scan',
            func=MagicMock(),
        )
        
        with patch.object(cli, 'parse_arguments', return_value=mock_args), \
             patch.object(cli, 'show_header') as mock_header:
            
            cli.main()
            
            mock_header.assert_called_once()
            mock_args.func.assert_called_once_with(mock_args)

    def test_main_without_command(self, cli, capsys):
        """Testa o método main sem comando"""
        mock_args = Namespace(command=None)
        
        with patch.object(cli, 'parse_arguments', return_value=mock_args), \
             patch.object(cli, 'show_header'):
            
            cli.main()
            captured = capsys.readouterr()
            
            assert "Use --help" in captured.out