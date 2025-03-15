import pytest
from datetime import datetime
import json
import csv
import xml.etree.ElementTree as ET
from src.reports.report_generator import ReportGenerator, ReportFormat
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

    def test_create_filename_with_format(self):
        """Testa a criação de nomes de arquivo para diferentes formatos"""
        network = "192.168.1.0/24"
        formats = {
            ReportFormat.TEXT: ".text",
            ReportFormat.JSON: ".json",
            ReportFormat.CSV: ".csv",
            ReportFormat.XML: ".xml"
        }
        
        for format, extension in formats.items():
            filename = ReportGenerator.create_filename(network, format)
            assert "esk_nmap_report" in filename
            assert "192_168_1_0_24" in filename
            assert filename.endswith(extension)

    def test_generate_text_report(self, sample_hosts_data, tmp_path):
        """Testa o formato do relatório texto com tabelas"""
        network = "192.168.1.0/24"
        filename = str(tmp_path / "test_report.txt")
        
        ReportGenerator.generate_report(filename, sample_hosts_data, network, ReportFormat.TEXT)
        
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

    def test_generate_json_report(self, sample_hosts_data, tmp_path):
        """Testa a geração do relatório em formato JSON"""
        network = "192.168.1.0/24"
        filename = str(tmp_path / "test_report.json")
        
        ReportGenerator.generate_report(filename, sample_hosts_data, network, ReportFormat.JSON)
        
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
            # Verifica a estrutura do JSON
            assert "metadata" in data
            assert "network" in data["metadata"]
            assert "total_hosts" in data["metadata"]
            assert "hosts" in data
            
            # Verifica os dados dos hosts
            assert "192.168.1.1" in data["hosts"]
            assert "192.168.1.2" in data["hosts"]
            
            # Verifica detalhes específicos
            host1 = data["hosts"]["192.168.1.1"]
            assert host1["hostname"] == "router.local"
            assert len(host1["ports"]) == 2
            assert host1["ports"][0]["port"] == "80/tcp"
            assert host1["ports"][0]["service"] == "http"

    def test_generate_csv_report(self, sample_hosts_data, tmp_path):
        """Testa a geração do relatório em formato CSV"""
        network = "192.168.1.0/24"
        filename = str(tmp_path / "test_report.csv")
        
        ReportGenerator.generate_report(filename, sample_hosts_data, network, ReportFormat.CSV)
        
        with open(filename, 'r', encoding='utf-8', newline='') as f:
            lines = list(csv.reader(f))
            
            # Verifica os metadados no cabeçalho
            assert lines[0][0] == "# ESK_NMAP Report"
            assert "# Rede" in lines[2][0]
            assert network in lines[2][1]
            
            # Encontra a linha do cabeçalho da tabela
            header_index = next(i for i, row in enumerate(lines) if "IP" in row)
            headers = lines[header_index]
            assert all(h in headers for h in ["IP", "Status", "Hostname", "MAC", "Fabricante", "Portas", "Serviços"])
            
            # Verifica os dados dos hosts
            data_rows = lines[header_index + 1:]
            assert len(data_rows) == 2  # Dois hosts no sample_hosts_data
            
            # Verifica o primeiro host
            assert "192.168.1.1" in data_rows[0][0]
            assert "80/tcp|443/tcp" in data_rows[0][5]  # Portas
            assert "http|https" in data_rows[0][6]      # Serviços

    def test_generate_xml_report(self, sample_hosts_data, tmp_path):
        """Testa a geração do relatório em formato XML"""
        network = "192.168.1.0/24"
        filename = str(tmp_path / "test_report.xml")
        
        ReportGenerator.generate_report(filename, sample_hosts_data, network, ReportFormat.XML)
        
        tree = ET.parse(filename)
        root = tree.getroot()
        
        # Verifica a estrutura básica
        assert root.tag == "esk_nmap_report"
        assert root.find("metadata") is not None
        assert root.find("metadata/network").text == network
        
        # Verifica os hosts
        hosts = root.find("hosts")
        assert len(hosts.findall("host")) == 2
        
        # Verifica detalhes do primeiro host
        host1 = hosts.find("host[ip='192.168.1.1']")
        assert host1 is not None
        assert host1.find("hostname").text == "router.local"
        assert len(host1.findall(".//port")) == 2
        
        # Verifica as portas e serviços
        ports = host1.findall(".//port")
        assert any(p.get("number") == "80/tcp" for p in ports)
        assert any(p.find("service").text == "http" for p in ports)

    def test_generate_report_empty_hosts(self, tmp_path):
        """Testa a geração de relatórios com lista vazia de hosts em todos os formatos"""
        network = "192.168.1.0/24"
        formats = [ReportFormat.TEXT, ReportFormat.JSON, ReportFormat.CSV, ReportFormat.XML]
        
        for format in formats:
            filename = str(tmp_path / f"test_empty_report.{format.name.lower()}")
            ReportGenerator.generate_report(filename, {}, network, format)
            
            # Verifica se o arquivo foi criado
            assert os.path.exists(filename)
            
            # Verifica conteúdo específico por formato
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
                if format == ReportFormat.TEXT:
                    assert "Total de hosts ativos: 0" in content
                elif format == ReportFormat.JSON:
                    data = json.loads(content)
                    assert data["metadata"]["total_hosts"] == 0
                elif format == ReportFormat.CSV:
                    lines = content.splitlines()
                    total_hosts_line = next((line for line in lines if "Total de hosts" in line), None)
                    assert total_hosts_line is not None
                    assert ",0" in total_hosts_line
                elif format == ReportFormat.XML:
                    root = ET.fromstring(content)
                    assert root.find("metadata/total_hosts").text == "0"

    def test_report_with_unicode_chars(self, tmp_path):
        """Testa o suporte a caracteres Unicode em todos os formatos"""
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
        network = "192.168.1.0/24"
        
        for format in ReportFormat:
            filename = str(tmp_path / f"test_unicode_report.{format.name.lower()}")
            ReportGenerator.generate_report(filename, hosts_data, network, format)
            
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
                assert "café" in content
                assert "Eletrôn" in content
    
    def test_report_service_details(self, sample_hosts_data, tmp_path):
        """Testa se os detalhes dos serviços são formatados corretamente em todos os formatos"""
        network = "192.168.1.0/24"
        
        for format in ReportFormat:
            filename = str(tmp_path / f"test_services_report.{format.name.lower()}")
            ReportGenerator.generate_report(filename, sample_hosts_data, network, format)
            
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
                assert "80/tcp" in content
                assert "443/tcp" in content
                assert "http" in content
                assert "https" in content