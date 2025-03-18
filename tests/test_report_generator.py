import pytest
from datetime import datetime
import json
import csv
import xml.etree.ElementTree as ET
import os
import tempfile
from src.reports.report_generator import ReportGenerator, ReportFormat
from src.core.scanner import HostInfo

class TestReportGenerator:
    @pytest.fixture
    def sample_hosts_data(self):
        """Fixture com dados de teste compatíveis com a implementação atual de HostInfo"""
        return {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                hostname="router.local",
                mac="00:11:22:33:44:55",
                vendor="Test Vendor",
                is_up=True,
                ports=[
                    {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
                    {"port": 443, "protocol": "tcp", "state": "open", "service": "https"}
                ]
            ),
            "192.168.1.2": HostInfo(
                ip="192.168.1.2",
                hostname="server.local",
                mac="AA:BB:CC:DD:EE:FF",
                vendor="Another Vendor",
                is_up=True,
                ports=[
                    {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
                    {"port": 3389, "protocol": "tcp", "state": "open", "service": "ms-wbt-server"}
                ]
            )
        }

    def test_create_filename_with_format(self):
        """Testa a criação de nomes de arquivo para diferentes formatos"""
        network = "192.168.1.0/24"
        formats = {
            ReportFormat.TEXT: ".text",
            ReportFormat.JSON: ".json",
            ReportFormat.CSV: ".csv",
            ReportFormat.XML: ".xml",
            ReportFormat.HTML: ".html"
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
            
            # Verifica se os dados específicos estão presentes
            assert "192.168.1.1" in content
            assert "router.local" in content
            assert "00:11:22:33:44:55" in content
            assert "192.168.1.2" in content
            assert "server.local" in content
            assert "AA:BB:CC:DD:EE:FF" in content

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
            assert host1["ports"][0]["port"] == 80
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
            first_row = next(row for row in data_rows if "192.168.1.1" in row)
            assert "router.local" in first_row
            assert "00:11:22:33:44:55" in first_row
            assert "80/tcp" in first_row[5]  # Portas
            assert "http" in first_row[6]    # Serviços

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
        
        # Verifica as portas e serviços
        ports = host1.findall(".//port")
        assert len(ports) == 2
        
        # Verifica se as portas específicas existem
        port_numbers = [port.get("number") for port in ports]
        assert "80" in port_numbers
        
        # Verifica serviços
        services = [port.find("service").text for port in ports]
        assert "http" in services

    def test_generate_html_report(self, sample_hosts_data, tmp_path):
        """Testa a geração do relatório em formato HTML"""
        network = "192.168.1.0/24"
        filename = str(tmp_path / "test_report.html")
        
        ReportGenerator.generate_report(filename, sample_hosts_data, network, ReportFormat.HTML)
        
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # Verifica estrutura HTML básica
            assert "<!DOCTYPE html>" in content
            assert "<html>" in content
            assert "<head>" in content
            assert "<body>" in content
            
            # Verifica conteúdo específico
            assert "ESK_NMAP - Network Scan Report" in content
            assert "192.168.1.1" in content
            assert "router.local" in content
            assert "192.168.1.2" in content
            assert "server.local" in content
            assert "80/tcp" in content or ">80<" in content
            assert "443/tcp" in content or ">443<" in content
            assert "http" in content
            assert "https" in content

    def test_generate_report_empty_hosts(self, tmp_path):
        """Testa a geração de relatórios com lista vazia de hosts em todos os formatos"""
        network = "192.168.1.0/24"
        formats = [ReportFormat.TEXT, ReportFormat.JSON, ReportFormat.CSV, ReportFormat.XML, ReportFormat.HTML]
        
        for format in formats:
            filename = str(tmp_path / f"test_empty_report.{format.name.lower()}")
            ReportGenerator.generate_report(filename, {}, network, format)
            
            # Verifica se o arquivo foi criado
            assert os.path.exists(filename)
            
            # Verifica conteúdo específico por formato
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
                if format == ReportFormat.TEXT:
                    assert "No hosts found" in content
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
                elif format == ReportFormat.HTML:
                    assert "No hosts found" in content

    def test_report_with_unicode_chars(self, tmp_path):
        """Testa o suporte a caracteres Unicode em todos os formatos"""
        hosts_data = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                hostname="servidor-café.local",
                is_up=True,
                mac="00:11:22:33:44:55",
                vendor="Fabricante Eletrônicos",
                ports=[
                    {"port": 80, "protocol": "tcp", "state": "open", "service": "http"}
                ]
            )
        }
        network = "192.168.1.0/24"
        
        for format in [ReportFormat.TEXT, ReportFormat.JSON, ReportFormat.CSV, ReportFormat.XML, ReportFormat.HTML]:
            filename = str(tmp_path / f"test_unicode_report.{format.name.lower()}")
            ReportGenerator.generate_report(filename, hosts_data, network, format)
            
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
                assert "café" in content
                assert "Eletrôn" in content

    def test_host_info_na_values(self, tmp_path):
        """Testa o tratamento de valores N/A em todos os formatos"""
        hosts_data = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                hostname="N/A",
                is_up=True,
                mac="N/A",
                vendor="N/A",
                ports=[]
            )
        }
        network = "192.168.1.0/24"
        
        for format in [ReportFormat.TEXT, ReportFormat.JSON, ReportFormat.CSV, ReportFormat.XML, ReportFormat.HTML]:
            filename = str(tmp_path / f"test_na_report.{format.name.lower()}")
            ReportGenerator.generate_report(filename, hosts_data, network, format)
            
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
                if format == ReportFormat.JSON:
                    data = json.loads(content)
                    assert data["hosts"]["192.168.1.1"]["hostname"] is None
                    assert data["hosts"]["192.168.1.1"]["mac"] is None
                    assert data["hosts"]["192.168.1.1"]["vendor"] is None
                elif format == ReportFormat.XML:
                    root = ET.fromstring(content)
                    host = root.find(".//host[ip='192.168.1.1']")
                    assert host.find("hostname") is None
                    assert host.find("mac") is None
                    assert host.find("vendor") is None

    def test_create_filename_special_chars(self):
        """Testa a criação de nomes de arquivo com caracteres especiais na rede"""
        special_networks = [
            "192.168.1.0/24",
            "fe80::1/64",
            "2001:db8::/32",
            "10.0.0.0/8"
        ]
        
        for network in special_networks:
            filename = ReportGenerator.create_filename(network)
            assert "/" not in filename
            assert "\\" not in filename
            assert ":" not in filename
            assert filename.startswith("esk_nmap_report_")
            assert ".text" in filename

    def test_report_very_long_values(self, tmp_path):
        """Testa o tratamento de valores muito longos em todos os formatos"""
        long_hostname = "a" * 100
        long_vendor = "b" * 100
        
        hosts_data = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                hostname=long_hostname,
                is_up=True,
                mac="00:11:22:33:44:55",
                vendor=long_vendor,
                ports=[
                    {"port": 80, "protocol": "tcp", "state": "open", "service": "http-" + "x" * 50}
                ]
            )
        }
        network = "192.168.1.0/24"
        
        for format in [ReportFormat.TEXT, ReportFormat.JSON, ReportFormat.CSV, ReportFormat.XML, ReportFormat.HTML]:
            filename = str(tmp_path / f"test_long_values.{format.name.lower()}")
            ReportGenerator.generate_report(filename, hosts_data, network, format)
            
            # Verifica apenas se o relatório foi gerado sem erros
            assert os.path.exists(filename)
            
            if format == ReportFormat.TEXT:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                    lines = content.splitlines()
                    # Verifica se as linhas da tabela não estão quebradas
                    for line in lines:
                        if "| " in line and " |" in line and len(line.split("|")) >= 3:
                            # As células não devem exceder os limites da tabela
                            valid_format = all(len(cell.strip()) <= 50 for cell in line.split("|")[1:-1])
                            assert valid_format, f"Formato de tabela inválido: {line}"

    def test_report_with_mixed_port_formats(self, tmp_path):
        """Testa o relatório com diferentes formatos de portas"""
        hosts_data = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                hostname="test.local",
                is_up=True,
                mac="00:11:22:33:44:55",
                vendor="Test Vendor",
                ports=[
                    {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
                    {"port": 443, "protocol": "tcp", "state": "open", "service": "https"},
                    {"port": 53, "protocol": "udp", "state": "open", "service": "dns"},
                    {"port": 3306, "protocol": "tcp", "state": "open", "service": "mysql"}
                ]
            )
        }
        network = "192.168.1.0/24"
        
        for format in [ReportFormat.TEXT, ReportFormat.JSON, ReportFormat.CSV, ReportFormat.XML, ReportFormat.HTML]:
            filename = str(tmp_path / f"test_port_formats.{format.name.lower()}")
            ReportGenerator.generate_report(filename, hosts_data, network, format)
            
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Verificações específicas por formato
                if format == ReportFormat.JSON:
                    data = json.loads(content)
                    ports = data["hosts"]["192.168.1.1"]["ports"]
                    port_values = [p["port"] for p in ports]
                    protocols = [p["protocol"] for p in ports]
                    assert 80 in port_values
                    assert 443 in port_values
                    assert 53 in port_values
                    assert 3306 in port_values
                    assert "tcp" in protocols
                    assert "udp" in protocols
                else:
                    # Para outros formatos podemos procurar as strings diretamente
                    assert "80" in content
                    assert "443" in content
                    assert "53" in content
                    assert "3306" in content
                    assert "tcp" in content
                    assert "udp" in content

    def test_report_with_special_chars_in_service(self, tmp_path):
        """Testa a geração de relatórios com caracteres especiais nos serviços"""
        hosts_data = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                hostname="test.local",
                is_up=True,
                mac="00:11:22:33:44:55",
                vendor="Test Vendor",
                ports=[
                    {"port": 80, "protocol": "tcp", "state": "open", "service": "http-proxy&special<chars>"}
                ]
            )
        }
        network = "192.168.1.0/24"
        
        for format in [ReportFormat.TEXT, ReportFormat.JSON, ReportFormat.CSV]:
            filename = str(tmp_path / f"test_special_chars.{format.name.lower()}")
            ReportGenerator.generate_report(filename, hosts_data, network, format)
            
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
                assert "http-proxy&special<chars>" in content

    def test_invalid_report_format(self, tmp_path, sample_hosts_data):
        """Testa o comportamento com um formato de relatório inválido"""
        network = "192.168.1.0/24"
        filename = str(tmp_path / "test_invalid.txt")
        
        # Usando uma string como formato deve lançar uma exceção
        with pytest.raises(ValueError):
            ReportGenerator.generate_report(filename, sample_hosts_data, network, "invalid_format")

    def test_api_methods(self, sample_hosts_data):
        """Testa os métodos da API que retornam conteúdo ao invés de escrever em arquivo"""
        # Teste generate_text_report
        text_report = ReportGenerator.generate_text_report(sample_hosts_data)
        assert isinstance(text_report, str)
        assert "192.168.1.1" in text_report
        assert "router.local" in text_report
        assert "80/tcp" in text_report
        
        # Teste generate_html_report
        html_report = ReportGenerator.generate_html_report(sample_hosts_data)
        assert isinstance(html_report, str)
        assert "<!DOCTYPE html>" in html_report
        assert "192.168.1.1" in html_report
        assert "router.local" in html_report
        
        # Teste generate_json_report
        json_report = ReportGenerator.generate_json_report(sample_hosts_data)
        assert isinstance(json_report, dict)
        assert "192.168.1.1" in json_report
        assert json_report["192.168.1.1"]["hostname"] == "router.local"

    def test_empty_results_api_methods(self):
        """Testa os métodos da API com resultados vazios"""
        empty_results = {}
        
        # Teste generate_text_report com resultados vazios
        text_report = ReportGenerator.generate_text_report(empty_results)
        assert isinstance(text_report, str)
        assert "No hosts found" in text_report
        
        # Teste generate_html_report com resultados vazios
        html_report = ReportGenerator.generate_html_report(empty_results)
        assert isinstance(html_report, str)
        assert "No hosts found" in html_report
        
        # Teste generate_json_report com resultados vazios
        json_report = ReportGenerator.generate_json_report(empty_results)
        assert isinstance(json_report, dict)
        assert len(json_report) == 0