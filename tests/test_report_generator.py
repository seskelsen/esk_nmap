import os
import json
import pytest
import tempfile
from unittest.mock import patch, MagicMock, mock_open
from io import StringIO
from src.reports.report_generator import (
    ReportGenerator, 
    ComparisonReportGenerator, 
    ReportFormat, 
    ComparisonFormat
)

class TestReportGenerator:
    """Testes para o ReportGenerator"""
    
    @pytest.fixture
    def mock_hosts(self):
        """Fixture que cria hosts fictícios para testes"""
        host1 = MagicMock()
        host1.ip = "192.168.1.1"
        host1.status = "up"
        host1.hostname = "router.local"
        host1.mac = "00:11:22:33:44:55"
        host1.vendor = "Cisco"
        host1.ports = [
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
            {"port": 443, "protocol": "tcp", "state": "open", "service": "https"}
        ]
        
        host2 = MagicMock()
        host2.ip = "192.168.1.2"
        host2.status = "up"
        host2.hostname = "N/A"  # Testar caso sem hostname
        host2.mac = "N/A"       # Testar caso sem MAC
        host2.vendor = "N/A"    # Testar caso sem vendor
        host2.ports = []        # Testar caso sem portas
        
        hosts = {
            "192.168.1.1": host1,
            "192.168.1.2": host2
        }
        
        return hosts
    
    @pytest.fixture
    def mock_hosts_string_ports(self):
        """Fixture que cria hosts fictícios com portas em formato string"""
        host1 = MagicMock()
        host1.ip = "192.168.1.1"
        host1.status = "up"
        host1.hostname = "router.local"
        host1.mac = "00:11:22:33:44:55"
        host1.vendor = "Cisco"
        host1.ports = ["80/tcp", "443/tcp"]
        host1.services = ["http", "https"]
        
        hosts = {
            "192.168.1.1": host1
        }
        
        return hosts
    
    def test_create_filename(self):
        """Testa a criação de nomes de arquivo para relatórios"""
        # Testa formato TEXT
        with patch('time.strftime', return_value="20250401_123456"):
            filename = ReportGenerator.create_filename("192.168.1.0/24", ReportFormat.TEXT)
            assert filename == "esk_nmap_report_192_168_1_0_24_20250401_123456.text"
        
        # Testa formato JSON
        with patch('time.strftime', return_value="20250401_123456"):
            filename = ReportGenerator.create_filename("192.168.1.0/24", ReportFormat.JSON)
            assert filename == "esk_nmap_report_192_168_1_0_24_20250401_123456.json"
        
        # Testa caracteres especiais
        with patch('time.strftime', return_value="20250401_123456"):
            filename = ReportGenerator.create_filename("test/with*special?chars", ReportFormat.TEXT)
            assert filename == "esk_nmap_report_test_with_special_chars_20250401_123456.text"
    
    def test_generate_text_report_string(self, mock_hosts):
        """Testa a geração de relatório em formato texto como string"""
        report = ReportGenerator.generate_text_report(mock_hosts)
        
        # Verifica se o relatório contém as informações esperadas
        assert "ESK_NMAP - Scanner de Rede da Eskel Cybersecurity" in report
        assert "192.168.1.1" in report
        assert "router.local" in report
        assert "00:11:22:33:44:55" in report
        assert "Cisco" in report
        assert "Total de hosts descobertos: 2" in report
        assert "80/tcp" in report
        assert "443/tcp" in report
        assert "http" in report
        assert "https" in report
    
    def test_generate_json_report_dict(self, mock_hosts):
        """Testa a geração de relatório em formato JSON como dicionário"""
        report_data = ReportGenerator.generate_json_report(mock_hosts)
        
        # Verifica se o dicionário contém as informações esperadas
        assert "metadata" in report_data
        assert report_data["metadata"]["total_hosts"] == 2
        assert report_data["metadata"]["hosts_with_open_ports"] == 1
        
        assert "192.168.1.1" in report_data
        assert report_data["192.168.1.1"]["status"] == "up"
        assert report_data["192.168.1.1"]["hostname"] == "router.local"
        assert report_data["192.168.1.1"]["mac"] == "00:11:22:33:44:55"
        assert report_data["192.168.1.1"]["vendor"] == "Cisco"
        assert 80 in report_data["192.168.1.1"]["ports"]
        assert 443 in report_data["192.168.1.1"]["ports"]
        
        assert "192.168.1.2" in report_data
        assert report_data["192.168.1.2"]["hostname"] is None
        assert report_data["192.168.1.2"]["mac"] is None
        assert report_data["192.168.1.2"]["vendor"] is None
        assert report_data["192.168.1.2"]["ports"] == []
    
    def test_generate_html_report_string(self, mock_hosts):
        """Testa a geração de relatório em formato HTML como string"""
        report = ReportGenerator.generate_html_report(mock_hosts)
        
        # Verifica se o relatório contém as informações esperadas
        assert "<!DOCTYPE html>" in report
        assert "<title>ESK_NMAP - Network Scan Report</title>" in report
        assert "192.168.1.1" in report
        assert "router.local" in report
        assert "00:11:22:33:44:55" in report
        assert "Cisco" in report
        assert "192.168.1.2" in report
        assert "80/tcp" in report
        assert "443/tcp" in report
        assert "http" in report
        assert "https" in report
    
    def test_generate_report_text(self, mock_hosts):
        """Testa a geração de relatório em formato texto para arquivo"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".text") as tmp:
            output_file = tmp.name
        
        try:
            with patch('time.strftime', return_value="20250401_123456"):
                ReportGenerator.generate_report(output_file, mock_hosts, "192.168.1.0/24", ReportFormat.TEXT)
            
            # Verifica se o arquivo foi criado
            assert os.path.exists(output_file)
            
            # Lê o conteúdo do arquivo
            with open(output_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Verifica se o conteúdo contém as informações esperadas
            assert "ESK_NMAP - Scanner de Rede da Eskel Cybersecurity" in content
            assert "Rede: 192.168.1.0/24" in content
            assert "192.168.1.1" in content
            assert "router.local" in content
            assert "00:11:22:33:44:55" in content
            assert "Cisco" in content
            assert "Total de hosts descobertos: 2" in content
            
        finally:
            # Limpa o arquivo temporário
            try:
                os.unlink(output_file)
            except:
                pass
    
    def test_generate_report_json(self, mock_hosts):
        """Testa a geração de relatório em formato JSON para arquivo"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
            output_file = tmp.name
        
        try:
            with patch('time.strftime', return_value="20250401_123456"):
                ReportGenerator.generate_report(output_file, mock_hosts, "192.168.1.0/24", ReportFormat.JSON)
            
            # Verifica se o arquivo foi criado
            assert os.path.exists(output_file)
            
            # Lê o conteúdo do arquivo
            with open(output_file, 'r', encoding='utf-8') as f:
                content = json.load(f)
            
            # Verifica se o conteúdo contém as informações esperadas
            assert "metadata" in content
            assert content["metadata"]["network"] == "192.168.1.0/24"
            assert content["metadata"]["total_hosts"] == 2
            assert content["hosts"]["192.168.1.1"]["hostname"] == "router.local"
            assert content["hosts"]["192.168.1.1"]["status"] == "up"
            assert content["hosts"]["192.168.1.1"]["mac"] == "00:11:22:33:44:55"
            assert content["hosts"]["192.168.1.1"]["vendor"] == "Cisco"
            assert len(content["hosts"]["192.168.1.1"]["ports"]) == 2
            
        finally:
            # Limpa o arquivo temporário
            try:
                os.unlink(output_file)
            except:
                pass
    
    def test_generate_report_csv(self, mock_hosts):
        """Testa a geração de relatório em formato CSV para arquivo"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
            output_file = tmp.name
        
        try:
            with patch('time.strftime', return_value="20250401_123456"):
                ReportGenerator.generate_report(output_file, mock_hosts, "192.168.1.0/24", ReportFormat.CSV)
            
            # Verifica se o arquivo foi criado
            assert os.path.exists(output_file)
            
            # Lê o conteúdo do arquivo
            with open(output_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Verifica se o conteúdo contém as informações esperadas
            assert "# ESK_NMAP Report" in content
            assert "# Rede,192.168.1.0/24" in content
            assert "IP,Status,Hostname,MAC,Fabricante,Portas,Serviços" in content
            assert "192.168.1.1,up,router.local,00:11:22:33:44:55,Cisco" in content
            assert "192.168.1.2,up,,,," in content
            
        finally:
            # Limpa o arquivo temporário
            try:
                os.unlink(output_file)
            except:
                pass
    
    def test_generate_report_xml(self, mock_hosts):
        """Testa a geração de relatório em formato XML para arquivo"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as tmp:
            output_file = tmp.name
        
        try:
            with patch('time.strftime', return_value="20250401_123456"):
                ReportGenerator.generate_report(output_file, mock_hosts, "192.168.1.0/24", ReportFormat.XML)
            
            # Verifica se o arquivo foi criado
            assert os.path.exists(output_file)
            
            # Lê o conteúdo do arquivo
            with open(output_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Verifica se o conteúdo contém as informações esperadas
            assert "<?xml version=" in content
            assert "<esk_nmap_report>" in content
            assert "<network>192.168.1.0/24</network>" in content
            assert "<ip>192.168.1.1</ip>" in content
            assert "<hostname>router.local</hostname>" in content
            assert "<mac>00:11:22:33:44:55</mac>" in content
            assert "<vendor>Cisco</vendor>" in content
            assert "<ip>192.168.1.2</ip>" in content
            
        finally:
            # Limpa o arquivo temporário
            try:
                os.unlink(output_file)
            except:
                pass
    
    def test_generate_report_html(self, mock_hosts):
        """Testa a geração de relatório em formato HTML para arquivo"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp:
            output_file = tmp.name
        
        try:
            with patch('time.strftime', return_value="20250401_123456"):
                ReportGenerator.generate_report(output_file, mock_hosts, "192.168.1.0/24", ReportFormat.HTML)
            
            # Verifica se o arquivo foi criado
            assert os.path.exists(output_file)
            
            # Lê o conteúdo do arquivo
            with open(output_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Verifica se o conteúdo contém as informações esperadas
            assert "<!DOCTYPE html>" in content
            assert "<title>ESK_NMAP - Network Scan Report</title>" in content
            assert "<p><strong>Network:</strong> 192.168.1.0/24</p>" in content
            assert "192.168.1.1" in content
            assert "router.local" in content
            assert "00:11:22:33:44:55" in content
            assert "Cisco" in content
            assert "192.168.1.2" in content
            
        finally:
            # Limpa o arquivo temporário
            try:
                os.unlink(output_file)
            except:
                pass
    
    def test_generate_report_unsupported_format(self, mock_hosts):
        """Testa a geração de relatório com formato não suportado"""
        with pytest.raises(ValueError, match="Formato de relatório não suportado"):
            # Criar um formato inválido para teste
            invalid_format = MagicMock()
            invalid_format.name = "INVALID"
            
            ReportGenerator.generate_report("test.txt", mock_hosts, "192.168.1.0/24", invalid_format)
    
    def test_report_with_string_ports(self, mock_hosts_string_ports):
        """Testa a geração de relatório com portas em formato string"""
        # Teste para o formato texto
        report = ReportGenerator.generate_text_report(mock_hosts_string_ports)
        
        # Verifica se o relatório contém as informações esperadas
        assert "80/tcp" in report
        assert "443/tcp" in report
        assert "http" in report
        assert "https" in report
        
        # Teste para o formato JSON
        report_data = ReportGenerator.generate_json_report(mock_hosts_string_ports)
        
        # Verifica se o dicionário contém as informações esperadas
        assert "metadata" in report_data
        assert report_data["metadata"]["hosts_with_open_ports"] == 1
        assert "192.168.1.1" in report_data
        # Verifica que as portas são tratadas corretamente como strings
        assert "80/tcp" in report_data["192.168.1.1"]["ports"]
        assert "443/tcp" in report_data["192.168.1.1"]["ports"]
        # Verifica se os serviços estão presentes
        assert len(report_data["192.168.1.1"]["services"]) == 2
        assert "http" in report_data["192.168.1.1"]["services"]
        assert "https" in report_data["192.168.1.1"]["services"]


class TestComparisonReportGenerator:
    """Testes para o ComparisonReportGenerator"""
    
    @pytest.fixture
    def mock_comparison_data(self):
        """Fixture que cria dados de comparação fictícios para testes"""
        return {
            "network": "192.168.1.0/24",
            "scan1": {
                "id": 1,
                "timestamp": "2025-04-01T12:00:00",
                "profile": "basic",
                "total_hosts": 3
            },
            "scan2": {
                "id": 2,
                "timestamp": "2025-04-01T13:00:00",
                "profile": "basic",
                "total_hosts": 4
            },
            "new_hosts": {
                "192.168.1.4": {
                    "hostname": "new-host.local",
                    "mac": "11:22:33:44:55:66",
                    "vendor": "HP",
                    "status": "up",
                    "ports": ["80/tcp"],
                    "services": ["http"]
                }
            },
            "removed_hosts": {
                "192.168.1.3": {
                    "hostname": "old-host.local",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "vendor": "Dell",
                    "status": "up",
                    "ports": ["22/tcp"],
                    "services": ["ssh"]
                }
            },
            "changed_hosts": {
                "192.168.1.2": {
                    "hostname": "server.local",
                    "new_ports": ["443/tcp"],
                    "closed_ports": ["22/tcp"]
                }
            },
            "summary": {
                "total_hosts_before": 3,
                "total_hosts_after": 4,
                "new_hosts": 1,
                "removed_hosts": 1,
                "changed_hosts": 1,
                "unchanged_hosts": 1
            }
        }
    
    def test_from_string(self):
        """Testa a conversão de string para formato válido"""
        # Testa formatos válidos
        assert ComparisonFormat.from_string("text") == "text"
        assert ComparisonFormat.from_string("json") == "json"
        assert ComparisonFormat.from_string("csv") == "csv"
        assert ComparisonFormat.from_string("xml") == "xml"
        assert ComparisonFormat.from_string("html") == "html"
        
        # Testa formatos em maiúsculas
        assert ComparisonFormat.from_string("TEXT") == "text"
        assert ComparisonFormat.from_string("JSON") == "json"
        
        # Testa formato inválido (deve retornar texto)
        assert ComparisonFormat.from_string("invalid") == "text"
    
    def test_export_comparison_to_text(self, mock_comparison_data):
        """Testa a exportação de comparação para formato texto"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp:
            output_file = tmp.name
        
        try:
            # Patch o logger para evitar dependências externas
            with patch('src.reports.report_generator.ComparisonReportGenerator._export_comparison_to_text') as mock_export:
                # Configura o mock para simular sucesso
                mock_export.return_value = True
                
                # Executa a exportação
                result = ComparisonReportGenerator.export_comparison_report(
                    mock_comparison_data, output_file, ComparisonFormat.TEXT)
                
                # Verifica se o método correto foi chamado com os parâmetros corretos
                mock_export.assert_called_once_with(mock_comparison_data, output_file)
                assert result is True
            
            # Testa a implementação real em uma segunda execução
            with patch('src.utils.logger.info'):  # patch corretamente o logger
                result = ComparisonReportGenerator._export_comparison_to_text(mock_comparison_data, output_file)
                assert result is True
                
                # Verifica se o arquivo foi criado
                assert os.path.exists(output_file)
                
                # Lê o conteúdo do arquivo
                with open(output_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Verifica se o conteúdo contém as informações esperadas
                assert "ESK NMAP - RELATÓRIO DE COMPARAÇÃO DE SCANS" in content
                assert "Rede: 192.168.1.0/24" in content
                assert "Scan 1: 2025-04-01T12:00:00 (ID: 1)" in content
                assert "Scan 2: 2025-04-01T13:00:00 (ID: 2)" in content
                assert "RESUMO DA COMPARAÇÃO:" in content
                assert "Total de hosts no scan 1: 3" in content
                assert "Total de hosts no scan 2: 4" in content
                assert "Hosts novos: 1" in content
                assert "Hosts removidos: 1" in content
                assert "Hosts alterados: 1" in content
                assert "HOSTS NOVOS:" in content
                assert "IP: 192.168.1.4" in content
                assert "Hostname: new-host.local" in content
                assert "HOSTS REMOVIDOS:" in content
                assert "IP: 192.168.1.3" in content
                assert "Hostname: old-host.local" in content
                assert "HOSTS COM ALTERAÇÕES:" in content
                assert "IP: 192.168.1.2" in content
                assert "Hostname: server.local" in content
                assert "Novas portas:" in content
                assert "443/tcp" in content
                assert "Portas fechadas:" in content
                assert "22/tcp" in content
                
        finally:
            # Limpa o arquivo temporário
            try:
                os.unlink(output_file)
            except:
                pass
    
    def test_export_comparison_to_json(self, mock_comparison_data):
        """Testa a exportação de comparação para formato JSON"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
            output_file = tmp.name
        
        try:
            # Patch o logger para evitar dependências externas
            with patch('src.reports.report_generator.ComparisonReportGenerator._export_comparison_to_json') as mock_export:
                # Configura o mock para simular sucesso
                mock_export.return_value = True
                
                # Executa a exportação
                result = ComparisonReportGenerator.export_comparison_report(
                    mock_comparison_data, output_file, ComparisonFormat.JSON)
                
                # Verifica se o método correto foi chamado com os parâmetros corretos
                mock_export.assert_called_once_with(mock_comparison_data, output_file)
                assert result is True
            
            # Testa a implementação real em uma segunda execução
            with patch('src.utils.logger.info'):  # patch corretamente o logger
                result = ComparisonReportGenerator._export_comparison_to_json(mock_comparison_data, output_file)
                assert result is True
                
                # Verifica se o arquivo foi criado
                assert os.path.exists(output_file)
                
                # Lê o conteúdo do arquivo
                with open(output_file, 'r', encoding='utf-8') as f:
                    content = json.load(f)
                
                # Verifica se o conteúdo contém as informações esperadas
                assert content["network"] == "192.168.1.0/24"
                assert content["scan1"]["id"] == 1
                assert content["scan2"]["id"] == 2
                assert "192.168.1.4" in content["new_hosts"]
                assert "192.168.1.3" in content["removed_hosts"]
                assert "192.168.1.2" in content["changed_hosts"]
                assert content["summary"]["new_hosts"] == 1
                
        finally:
            # Limpa o arquivo temporário
            try:
                os.unlink(output_file)
            except:
                pass
    
    def test_export_comparison_to_csv(self, mock_comparison_data):
        """Testa a exportação de comparação para formato CSV"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
            output_file = tmp.name
        
        try:
            # Patch o logger para evitar dependências externas
            with patch('src.reports.report_generator.ComparisonReportGenerator._export_comparison_to_csv') as mock_export:
                # Configura o mock para simular sucesso
                mock_export.return_value = True
                
                # Executa a exportação
                result = ComparisonReportGenerator.export_comparison_report(
                    mock_comparison_data, output_file, ComparisonFormat.CSV)
                
                # Verifica se o método correto foi chamado com os parâmetros corretos
                mock_export.assert_called_once_with(mock_comparison_data, output_file)
                assert result is True
            
            # Testa a implementação real em uma segunda execução
            with patch('src.utils.logger.info'):  # patch corretamente o logger
                result = ComparisonReportGenerator._export_comparison_to_csv(mock_comparison_data, output_file)
                assert result is True
                
                # Verifica se o arquivo foi criado
                assert os.path.exists(output_file)
                
                # Lê o conteúdo do arquivo
                with open(output_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Verifica se o conteúdo contém as informações esperadas
                assert "Tipo,IP,Hostname,MAC,Vendor,Alteração,Detalhes" in content
                assert "Novo,192.168.1.4,new-host.local,11:22:33:44:55:66,HP,Host adicionado,80/tcp" in content
                assert "Removido,192.168.1.3,old-host.local,AA:BB:CC:DD:EE:FF,Dell,Host removido," in content
                assert "Alterado,192.168.1.2,server.local,,,Novas portas,443/tcp" in content
                assert "Alterado,192.168.1.2,server.local,,,Portas fechadas,22/tcp" in content
                
        finally:
            # Limpa o arquivo temporário
            try:
                os.unlink(output_file)
            except:
                pass
    
    def test_export_comparison_to_xml(self, mock_comparison_data):
        """Testa a exportação de comparação para formato XML"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as tmp:
            output_file = tmp.name
        
        try:
            # Patch o logger para evitar dependências externas
            with patch('src.reports.report_generator.ComparisonReportGenerator._export_comparison_to_xml') as mock_export:
                # Configura o mock para simular sucesso
                mock_export.return_value = True
                
                # Executa a exportação
                result = ComparisonReportGenerator.export_comparison_report(
                    mock_comparison_data, output_file, ComparisonFormat.XML)
                
                # Verifica se o método correto foi chamado com os parâmetros corretos
                mock_export.assert_called_once_with(mock_comparison_data, output_file)
                assert result is True
            
            # Testa a implementação real em uma segunda execução
            with patch('src.utils.logger.info'):  # patch corretamente o logger
                result = ComparisonReportGenerator._export_comparison_to_xml(mock_comparison_data, output_file)
                assert result is True
                
                # Verifica se o arquivo foi criado
                assert os.path.exists(output_file)
                
                # Lê o conteúdo do arquivo
                with open(output_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Verifica se o conteúdo contém as informações esperadas
                assert "<?xml version=" in content
                assert "<comparison>" in content
                assert "<network>192.168.1.0/24</network>" in content
                assert "<new_hosts>" in content
                assert "<host ip=\"192.168.1.4\"" in content
                assert "<removed_hosts>" in content
                assert "<host ip=\"192.168.1.3\"" in content
                assert "<changed_hosts>" in content
                assert "<host ip=\"192.168.1.2\"" in content
                assert "<new_ports>" in content
                assert "<port number=\"443/tcp\"" in content
                assert "<closed_ports>" in content
                assert "<port number=\"22/tcp\"" in content
                
        finally:
            # Limpa o arquivo temporário
            try:
                os.unlink(output_file)
            except:
                pass
    
    def test_export_comparison_to_html(self, mock_comparison_data):
        """Testa a exportação de comparação para formato HTML"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp:
            output_file = tmp.name
        
        try:
            # Patch o logger para evitar dependências externas
            with patch('src.reports.report_generator.ComparisonReportGenerator._export_comparison_to_html') as mock_export:
                # Configura o mock para simular sucesso
                mock_export.return_value = True
                
                # Executa a exportação
                result = ComparisonReportGenerator.export_comparison_report(
                    mock_comparison_data, output_file, ComparisonFormat.HTML)
                
                # Verifica se o método correto foi chamado com os parâmetros corretos
                mock_export.assert_called_once_with(mock_comparison_data, output_file)
                assert result is True
            
            # Testa a implementação real em uma segunda execução
            with patch('src.utils.logger.info'), patch('src.utils.logger.debug'):  # patch corretamente o logger
                result = ComparisonReportGenerator._export_comparison_to_html(mock_comparison_data, output_file)
                assert result is True
                
                # Verifica se o arquivo foi criado
                assert os.path.exists(output_file)
                
                # Lê o conteúdo do arquivo
                with open(output_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Verifica se o conteúdo contém as informações esperadas
                assert "<!DOCTYPE html>" in content
                assert "<title>ESK NMAP - Relatório de Comparação</title>" in content
                assert "<h1>ESK NMAP - Relatório de Comparação de Scans</h1>" in content
                assert "<strong>Rede:</strong> 192.168.1.0/24" in content
                assert "<strong>Scan 1:</strong> 2025-04-01T12:00:00 (ID: 1)" in content
                assert "<strong>Scan 2:</strong> 2025-04-01T13:00:00 (ID: 2)" in content
                assert "<h2>Resumo da Comparação</h2>" in content
                assert "<h2>Hosts Novos</h2>" in content
                assert "192.168.1.4" in content
                assert "new-host.local" in content
                assert "<h2>Hosts Removidos</h2>" in content
                assert "192.168.1.3" in content
                assert "old-host.local" in content
                assert "<h2>Hosts com Alterações</h2>" in content
                assert "192.168.1.2" in content
                assert "server.local" in content
                assert "443/tcp" in content
                assert "22/tcp" in content
                
        finally:
            # Limpa o arquivo temporário
            try:
                os.unlink(output_file)
            except:
                pass
    
    def test_export_comparison_error_handling(self, mock_comparison_data):
        """Testa o tratamento de erros na exportação de comparação"""
        # Testa caso de erro para JSON
        with patch('src.reports.report_generator.ComparisonReportGenerator._export_comparison_to_json') as mock_export:
            with patch('src.utils.logger.error') as mock_error:  # patch corretamente o logger
                # Configura o mock para lançar exceção
                mock_export.side_effect = Exception("Erro de teste")
                
                # Executa a exportação
                result = ComparisonReportGenerator.export_comparison_report(
                    mock_comparison_data, "output.json", ComparisonFormat.JSON)
                
                # Verifica se o método de log de erro foi chamado
                mock_error.assert_called_once()
                assert result is False
    
    def test_export_comparison_invalid_format(self, mock_comparison_data):
        """Testa a exportação de comparação com formato inválido (deve usar texto como padrão)"""
        with patch('src.reports.report_generator.ComparisonReportGenerator._export_comparison_to_text') as mock_export:
            # Configura o mock para simular sucesso
            mock_export.return_value = True
            
            # Executa a exportação com formato inválido
            result = ComparisonReportGenerator.export_comparison_report(
                mock_comparison_data, "output.txt", "invalid")
            
            # Verifica se o método correto foi chamado (deve usar texto como padrão)
            mock_export.assert_called_once_with(mock_comparison_data, "output.txt")
            assert result is True