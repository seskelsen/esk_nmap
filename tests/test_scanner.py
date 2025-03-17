import pytest
from unittest.mock import patch
from src.core.scanner import NetworkScanner, HostInfo, ScannerError

class TestNetworkScanner:
    @pytest.fixture
    def scanner(self):
        """Fixture que fornece uma instância do NetworkScanner"""
        return NetworkScanner("192.168.1.0/24")

    def test_host_info_str_representation(self):
        """Testa a representação em string do HostInfo"""
        host = HostInfo(
            ip="192.168.1.1",
            hostname="test.local",
            mac="00:11:22:33:44:55",
            vendor="Test Vendor"
        )
        host.is_up = True
        host.ports = [{"port": 80, "protocol": "tcp", "service": "http", "version": "Apache 2.4"}]
        
        result = str(host)
        assert "Host: 192.168.1.1" in result
        assert "Hostname: test.local" in result
        assert "MAC: 00:11:22:33:44:55" in result
        assert "Vendor: Test Vendor" in result
        assert "Status: up" in result
        assert "80/tcp" in result
        assert "Apache 2.4" in result

    def test_scan_host(self):
        """Testa o scan de um único host"""
        expected_host_info = HostInfo(
            ip="127.0.0.1",
            hostname="localhost",
            is_up=True,
            ports=[{"port": 80, "state": "open", "service": "http"}]
        )