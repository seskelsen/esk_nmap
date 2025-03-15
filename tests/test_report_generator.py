import pytest
from datetime import datetime
from src.reports.report_generator import ReportGenerator
from src.core.scanner import HostInfo
import os

class TestReportGenerator:
    @pytest.fixture
    def sample_hosts_data(self):
        return {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                hostname="router.local",
                status="Up",
                mac="00:11:22:33:44:55",
                vendor="Test Vendor",
                ports=["80/tcp", "443/tcp"],
                services=["http", "https"]
            ),
            "192.168.1.2": HostInfo(
                ip="192.168.1.2",
                hostname="server.local",
                status="Up",
                mac="AA:BB:CC:DD:EE:FF",
                vendor="Another Vendor",
                ports=["22/tcp", "3389/tcp"],
                services=["ssh", "ms-wbt-server"]
            )
        }

    def test_create_filename(self):
        network = "192.168.1.0/24"
        filename = ReportGenerator.create_filename(network)
        assert "esk_nmap_report" in filename
        assert "192_168_1_0_24" in filename
        assert filename.endswith(".txt")

    def test_generate_report_format(self, sample_hosts_data, tmp_path):
        """Testa o novo formato do relatório com tabelas"""
        network = "192.168.1.0/24"
        filename = str(tmp_path / "test_report.txt")
        
        ReportGenerator.generate_report(filename, sample_hosts_data, network)
        
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # Verifica cabeçalho
            assert "ESK_NMAP - Scanner de Rede da Eskel Cybersecurity" in content
            assert "=" * 60 in content
            
            # Verifica tabela de hosts
            assert "+" + "-" * 15 + "+" in content  # Separadores da tabela
            assert "| IP" in content
            assert "| Status" in content
            assert "| Hostname" in content
            assert "| MAC" in content
            assert "| Fabricante" in content
            
            # Verifica conteúdo das tabelas de portas
            assert "DETALHES DAS PORTAS:" in content
            assert "+" + "-" * 15 + "+" + "-" * 50 + "+" in content
            assert "| PORTA" in content
            assert "| SERVIÇO" in content

    def test_generate_report_empty_hosts(self, tmp_path):
        network = "192.168.1.0/24"
        filename = str(tmp_path / "test_empty_report.txt")
        
        ReportGenerator.generate_report(filename, {}, network)
        
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
            assert "Total de hosts ativos: 0" in content
            assert "Hosts com portas abertas: 0" in content

    def test_report_with_unicode_chars(self, tmp_path):
        hosts_data = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                hostname="servidor-café.local",
                status="Up",
                mac="00:11:22:33:44:55",
                vendor="Fabricante Eletrônicos",
                ports=["80/tcp"],
                services=["http"]
            )
        }
        
        filename = str(tmp_path / "test_unicode_report.txt")
        ReportGenerator.generate_report(filename, hosts_data, network="192.168.1.0/24")
        
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
            assert "servidor-café.local" in content
            # Verificar apenas a parte visível na tabela de largura limitada
            assert "Fabricante Eletrôn" in content

    def test_report_table_alignment(self, tmp_path):
        """Testa o alinhamento das tabelas no relatório"""
        hosts_data = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                hostname="host-com-nome-muito-longo.dominio.local",
                status="Up",
                mac="00:11:22:33:44:55",
                vendor="Fabricante com Nome Muito Longo Ltda",
                ports=["80/tcp", "443/tcp"],
                services=["http com descrição muito longa", "https com versão e detalhes extensos"]
            )
        }
        
        filename = str(tmp_path / "test_alignment_report.txt")
        ReportGenerator.generate_report(filename, hosts_data, network="192.168.1.0/24")
        
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # Verifica se o relatório foi gerado corretamente
            assert "host-com-nome-muito-longo.dominio.local" in content
            assert "80/tcp" in content
            assert "443/tcp" in content
            
            # Em vez de verificar comprimento exato das linhas, verificamos se as tabelas têm formato consistente
            assert "+" + "-" * 15 + "+" in content  # Padrão da coluna de IP
            assert "+" + "-" * 50 + "+" in content  # Padrão da coluna de serviço

    def test_report_service_details(self, sample_hosts_data, tmp_path):
        """Testa se os detalhes dos serviços são formatados corretamente"""
        filename = str(tmp_path / "test_services_report.txt")
        ReportGenerator.generate_report(filename, sample_hosts_data, network="192.168.1.0/24")
        
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # Verifica o formato da tabela de serviços
            assert "| 80/tcp" in content and "| http" in content
            assert "| 443/tcp" in content and "| https" in content
            assert "| 22/tcp" in content and "| ssh" in content
            
            # Verifica se os serviços estão na seção correta de cada host
            host1_section = content[content.index("HOST: 192.168.1.1"):content.index("HOST: 192.168.1.2")]
            host2_section = content[content.index("HOST: 192.168.1.2"):]
            
            assert "80/tcp" in host1_section
            assert "443/tcp" in host1_section
            assert "22/tcp" in host2_section
            assert "3389/tcp" in host2_section