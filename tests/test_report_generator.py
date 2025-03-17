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
                mac="00:11:22:33:44:55",
                vendor="Test Vendor",
                is_up=True,
                ports=["80/tcp", "443/tcp"],
                services=["http", "https"]
            ),
            "192.168.1.2": HostInfo(
                ip="192.168.1.2",
                hostname="server.local",
                mac="AA:BB:CC:DD:EE:FF",
                vendor="Another Vendor",
                is_up=True,
                ports=["22/tcp", "3389/tcp"],
                services=["ssh", "ms-wbt-server"]
            )
        }

    @pytest.fixture
    def report_generator(self):
        return ReportGenerator()

    @pytest.fixture
    def sample_results(self):
        results = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                mac="00:11:22:33:44:55",
                vendor="Vendor1"
            ),
            "192.168.1.2": HostInfo(
                ip="192.168.1.2",
                mac="AA:BB:CC:DD:EE:FF",
                vendor="Vendor2"
            )
        }
        results["192.168.1.1"].ports = ["80/tcp", "443/tcp"]
        results["192.168.1.1"].services = ["http", "https"]
        results["192.168.1.2"].ports = ["22/tcp"]
        results["192.168.1.2"].services = ["ssh"]
        return results

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
                is_up=True,
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

    def test_host_info_na_values(self, tmp_path):
        """Testa o tratamento de valores N/A em todos os formatos"""
        hosts_data = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                hostname="N/A",
                is_up=True,
                mac="N/A",
                vendor="N/A",
                ports=[],
                services=[]
            )
        }
        network = "192.168.1.0/24"
        
        for format in ReportFormat:
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
        long_service = "c" * 100
        
        hosts_data = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                hostname=long_hostname,
                is_up=True,
                mac="00:11:22:33:44:55",
                vendor=long_vendor,
                ports=["80/tcp"],
                services=[long_service]
            )
        }
        network = "192.168.1.0/24"
        
        for format in ReportFormat:
            filename = str(tmp_path / f"test_long_values.{format.name.lower()}")
            ReportGenerator.generate_report(filename, hosts_data, network, format)
            
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
                if format == ReportFormat.TEXT:
                    lines = content.splitlines()
                    # Verifica se as linhas da tabela não estão quebradas
                    for line in lines:
                        if "|" in line:
                            cells = [cell.strip() for cell in line.split("|")]
                            assert all(len(cell) <= 35 for cell in cells), "Células não devem exceder o limite"
                elif format == ReportFormat.CSV:
                    # CSV deve preservar os valores completos
                    assert long_hostname in content
                    assert long_vendor in content
                    assert long_service in content

    def test_report_multiple_ports_formatting(self, tmp_path):
        """Testa a formatação de múltiplas portas e serviços"""
        hosts_data = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                hostname="test.local",
                is_up=True,
                mac="00:11:22:33:44:55",
                vendor="Test Vendor",
                ports=["21/tcp", "22/tcp", "80/tcp", "443/tcp", "3306/tcp"],
                services=["ftp", "ssh", "http", "https", "mysql"]
            )
        }
        network = "192.168.1.0/24"
        
        for format in ReportFormat:
            filename = str(tmp_path / f"test_multiple_ports.{format.name.lower()}")
            ReportGenerator.generate_report(filename, hosts_data, network, format)
            
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
                if format == ReportFormat.TEXT:
                    assert all(port in content for port in ["21/tcp", "22/tcp", "80/tcp", "443/tcp", "3306/tcp"])
                    assert all(service in content for service in ["ftp", "ssh", "http", "https", "mysql"])
                elif format == ReportFormat.JSON:
                    data = json.loads(content)
                    ports_data = data["hosts"]["192.168.1.1"]["ports"]
                    assert len(ports_data) == 5
                    assert all(p["service"] in ["ftp", "ssh", "http", "https", "mysql"] for p in ports_data)
                elif format == ReportFormat.CSV:
                    assert "21/tcp|22/tcp|80/tcp|443/tcp|3306/tcp" in content
                    assert "ftp|ssh|http|https|mysql" in content
                elif format == ReportFormat.XML:
                    root = ET.fromstring(content)
                    ports = root.findall(".//port")
                    assert len(ports) == 5
                    services = [p.find("service").text for p in ports]
                    assert all(s in services for s in ["ftp", "ssh", "http", "https", "mysql"])

    def test_invalid_report_format(self, tmp_path):
        """Testa o comportamento com um formato de relatório inválido"""
        hosts_data = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                hostname="test.local",
                is_up=True
            )
        }
        network = "192.168.1.0/24"
        filename = str(tmp_path / "test_invalid.txt")
        
        # Tenta usar um formato inválido
        with pytest.raises(AttributeError):
            ReportGenerator.generate_report(filename, hosts_data, network, "invalid_format")

    def test_report_file_permissions(self, tmp_path):
        """Testa a geração de relatório com diferentes permissões de arquivo"""
        hosts_data = {"192.168.1.1": HostInfo(ip="192.168.1.1")}
        network = "192.168.1.0/24"
        
        # Cria um diretório com permissões restritas
        restricted_dir = tmp_path / "restricted"
        restricted_dir.mkdir()
        filename = str(restricted_dir / "test_report.text")
        
        # Tenta gerar o relatório
        ReportGenerator.generate_report(filename, hosts_data, network, ReportFormat.TEXT)
        
        # Verifica se o arquivo foi criado e pode ser lido
        assert os.path.exists(filename)
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
            assert "ESK_NMAP" in content

    def test_report_with_mixed_port_formats(self, tmp_path):
        """Testa o relatório com diferentes formatos de portas"""
        hosts_data = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                hostname="test.local",
                is_up=True,
                mac="00:11:22:33:44:55",
                vendor="Test Vendor",
                ports=["80/tcp", "443", "udp/53", "3306/tcp"],
                services=["http", "https", "dns", "mysql"]
            )
        }
        network = "192.168.1.0/24"
        
        for format in ReportFormat:
            filename = str(tmp_path / f"test_port_formats.{format.name.lower()}")
            ReportGenerator.generate_report(filename, hosts_data, network, format)
            
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
                assert "80/tcp" in content
                assert "443" in content
                assert "udp/53" in content
                assert "3306/tcp" in content

    def test_report_with_special_chars_in_service(self, tmp_path):
        """Testa a geração de relatórios com caracteres especiais nos serviços"""
        hosts_data = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                hostname="test.local",
                is_up=True,
                mac="00:11:22:33:44:55",
                vendor="Test Vendor",
                ports=["80/tcp"],
                services=["http-proxy&special<chars>"]
            )
        }
        network = "192.168.1.0/24"
        
        for format in ReportFormat:
            filename = str(tmp_path / f"test_special_chars.{format.name.lower()}")
            ReportGenerator.generate_report(filename, hosts_data, network, format)
            
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
                assert "http-proxy&special<chars>" in content
    
    def test_report_with_empty_optional_fields(self, tmp_path):
        """Testa a geração de relatórios quando campos opcionais estão vazios"""
        hosts_data = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                hostname="N/A",
                is_up=True,
                mac="N/A",
                vendor="N/A",
                ports=[],
                services=[]
            )
        }
        network = "192.168.1.0/24"
        
        for format in ReportFormat:
            filename = str(tmp_path / f"test_empty_fields.{format.name.lower()}")
            ReportGenerator.generate_report(filename, hosts_data, network, format)
    
    def test_report_with_very_long_values(self, tmp_path):
        """Testa o truncamento adequado de valores muito longos nos relatórios"""
        long_hostname = "a" * 100
        long_vendor = "b" * 100
        long_service = "c" * 100
        
        hosts_data = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                hostname=long_hostname,
                is_up=True,
                mac="00:11:22:33:44:55",
                vendor=long_vendor,
                ports=["80/tcp"],
                services=[long_service]
            )
        }
        network = "192.168.1.0/24"
        
        for format in ReportFormat:
            filename = str(tmp_path / f"test_long_values.{format.name.lower()}")
            ReportGenerator.generate_report(filename, hosts_data, network, format)

    def test_create_filename_with_invalid_chars(self):
        """Testa a criação de nome de arquivo com caracteres inválidos na rede"""
        network = "192.168.1.0/24:*?<>|"
        filename = ReportGenerator.create_filename(network)
        
        invalid_chars = [":", "*", "?", "<", ">", "|"]
        for char in invalid_chars:
            assert char not in filename
            
    def test_report_with_non_ascii_chars(self, tmp_path):
        """Testa a geração de relatórios com caracteres não ASCII"""
        hosts_data = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                hostname="téstê.local",
                is_up=True,
                mac="00:11:22:33:44:55",
                vendor="Vendedor Padrão",
                ports=["80/tcp"],
                services=["serviço-web"]
            )
        }
        network = "192.168.1.0/24"
        
        for format in ReportFormat:
            filename = str(tmp_path / f"test_non_ascii.{format.name.lower()}")
            ReportGenerator.generate_report(filename, hosts_data, network, format)
            
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
                assert "téstê.local" in content
                assert "Vendedor Padrão" in content
                assert "serviço-web" in content

    def test_generate_text_report(self, report_generator, sample_results):
        report = report_generator.generate_text_report(sample_results)
        assert "192.168.1.1" in report
        assert "192.168.1.2" in report
        assert "00:11:22:33:44:55" in report
        assert "AA:BB:CC:DD:EE:FF" in report
        assert "80/tcp" in report
        assert "443/tcp" in report
        assert "22/tcp" in report

    def test_generate_json_report(self, report_generator, sample_results):
        report = report_generator.generate_json_report(sample_results)
        assert isinstance(report, dict)
        assert "192.168.1.1" in report
        assert "192.168.1.2" in report
        assert report["192.168.1.1"]["mac"] == "00:11:22:33:44:55"
        assert report["192.168.1.2"]["mac"] == "AA:BB:CC:DD:EE:FF"
        assert "80/tcp" in report["192.168.1.1"]["ports"]
        assert "22/tcp" in report["192.168.1.2"]["ports"]

    def test_generate_html_report(self, report_generator, sample_results):
        report = report_generator.generate_html_report(sample_results)
        assert "<!DOCTYPE html>" in report
        assert "192.168.1.1" in report
        assert "192.168.1.2" in report
        assert "00:11:22:33:44:55" in report
        assert "AA:BB:CC:DD:EE:FF" in report
        assert "80/tcp" in report
        assert "443/tcp" in report
        assert "22/tcp" in report

    def test_empty_results(self, report_generator):
        empty_results = {}
        text_report = report_generator.generate_text_report(empty_results)
        json_report = report_generator.generate_json_report(empty_results)
        html_report = report_generator.generate_html_report(empty_results)
        
        assert "No hosts found" in text_report
        assert isinstance(json_report, dict)
        assert len(json_report) == 0
        assert "No hosts found" in html_report

    def test_host_without_ports(self, report_generator):
        results = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                mac="00:11:22:33:44:55",
                vendor="Vendor1"
            )
        }
        text_report = report_generator.generate_text_report(results)
        assert "No open ports" in text_report