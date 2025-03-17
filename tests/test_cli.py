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
                status="up"
            ),
            "192.168.1.2": HostInfo(
                ip="192.168.1.2",
                hostname="pc.local",
                mac="AA:BB:CC:DD:EE:FF",
                vendor="Another Vendor",
                status="up"
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
                status='up'
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