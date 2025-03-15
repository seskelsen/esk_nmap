import pytest
from unittest.mock import patch
from io import StringIO
from src.ui.cli import CLI
from src.core.scanner import HostInfo

class TestCLI:
    @pytest.fixture
    def sample_hosts_data(self):
        return {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                hostname="router.local",
                mac="00:11:22:33:44:55",
                vendor="Test Vendor"
            ),
            "192.168.1.2": HostInfo(
                ip="192.168.1.2",
                hostname="pc.local",
                mac="AA:BB:CC:DD:EE:FF",
                vendor="Another Vendor"
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
        
        # Verificar se os dados importantes estão na tabela
        assert "192.168.1.1" in captured.out
        assert "router.local" in captured.out
        assert "00:11:22:33:44:55" in captured.out
        assert "Test Vendor" in captured.out
        assert "Total de hosts descobertos: 2" in captured.out