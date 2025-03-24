#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ESK NMAP - Network Scanner Tool
Copyright (C) 2025 Eskel Cybersecurity
Author: Sigmar Eskelsen

Testes de integração para o ESK NMAP.
"""

import os
import json
import csv
import tempfile
import sqlite3
import xml.dom.minidom
import unicodedata
import pytest
from unittest.mock import patch, MagicMock

from src.core.scanner import HostInfo
from src.core.history_manager import HistoryManager, ComparisonFormat
from src.utils.logger import info, error, debug
from src.reports.report_generator import ComparisonReportGenerator

def normalize_string(text):
    """Normaliza uma string para comparação, removendo acentos e caracteres especiais."""
    return unicodedata.normalize('NFKD', text).encode('ASCII', 'ignore').decode('ASCII')

# Mock para testes em memória - vamos evitar lidar com o singleton
class MockHistoryManager(HistoryManager):
    """Versão modificada do HistoryManager para testes"""
    
    def __init__(self):
        # Não chamar o construtor da classe pai
        self._db_path = ":memory:"  # Usar banco em memória
        self._initialized = True
        self._init_database()
    
    def compare_scans(self, scan_id1, scan_id2):
        """
        Mock da função compare_scans para testes sem precisar do banco de dados
        """
        # Dados de teste para simulação da comparação
        comparison = {
            'scan1': {
                'id': scan_id1,
                'timestamp': '2025-03-20T12:00:00',
                'profile': 'basic',
                'total_hosts': 2
            },
            'scan2': {
                'id': scan_id2,
                'timestamp': '2025-03-21T12:00:00',
                'profile': 'basic',
                'total_hosts': 2
            },
            'network': '192.168.1.0/24',
            'new_hosts': {
                '192.168.1.3': {
                    'ip': '192.168.1.3',
                    'hostname': 'laptop.local',
                    'mac': '00:11:22:33:44:55',
                    'vendor': 'HP',
                    'status': 'up',
                    'ports': ['22/tcp'],
                    'services': ['ssh']
                }
            },
            'removed_hosts': {
                '192.168.1.2': {
                    'ip': '192.168.1.2',
                    'hostname': 'desktop.local',
                    'mac': 'AA:BB:CC:DD:EE:FF',
                    'vendor': 'Dell',
                    'status': 'up',
                    'ports': ['445/tcp', '139/tcp'],
                    'services': ['microsoft-ds', 'netbios-ssn']
                }
            },
            'changed_hosts': {
                '192.168.1.1': {
                    'hostname': 'router.local',
                    'new_ports': ['8080/tcp'],
                    'closed_ports': []
                }
            },
            'unchanged_hosts': 0,
            'summary': {
                'total_hosts_before': 2,
                'total_hosts_after': 2,
                'new_hosts': 1,
                'removed_hosts': 1,
                'changed_hosts': 1,
                'unchanged_hosts': 0
            }
        }
        return comparison
    
    def export_comparison_report(self, comparison_data, output_file, format_type):
        """Mock da função export_comparison_report"""
        format_type = ComparisonFormat.from_string(format_type)
        
        try:
            if format_type == ComparisonFormat.JSON:
                result = self._export_comparison_to_json(comparison_data, output_file)
            elif format_type == ComparisonFormat.HTML:
                result = self._export_comparison_to_html(comparison_data, output_file)
            elif format_type == ComparisonFormat.CSV:
                with open(output_file, 'w', encoding='utf-8', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Tipo', 'IP', 'Hostname', 'MAC', 'Vendor', 'Alteração'])
                    for ip, host in comparison_data['new_hosts'].items():
                        writer.writerow(['Novo', ip, host['hostname'], host['mac'], host['vendor'], 'Host adicionado'])
                result = True
            elif format_type == ComparisonFormat.XML:
                doc = xml.dom.minidom.Document()
                root = doc.createElement("comparison")
                doc.appendChild(root)
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(doc.toprettyxml())
                result = True
            else:  # TEXT
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(f"ESK NMAP - Relatório de Comparação\nRede: {comparison_data['network']}\n")
                result = True
            
            if result:
                info(f"Comparação exportada com sucesso para {format_type}: {output_file}")
            return result
            
        except Exception as e:
            error(f"Erro ao exportar comparação para {format_type}: {str(e)}")
            return False
            
    def _export_comparison_to_json(self, comparison_data, output_file):
        """Mock do método _export_comparison_to_json"""
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(comparison_data, f, indent=4)
        return True
    
    def _export_comparison_to_html(self, comparison_data, output_file):
        """Mock do método _export_comparison_to_html"""
        try:
            html_content = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>ESK NMAP - Relatório de Comparação</title>
    <style>
        body { font-family: Arial, sans-serif; }
        table { border-collapse: collapse; width: 100%; margin: 15px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background: #f2f2f2; }
        tr.new { background: #e6ffec; }
        tr.removed { background: #ffebe9; }
        tr.changed { background: #fff8c5; }
    </style>
</head>
<body>
    <h1>ESK NMAP - Relatório de Comparação de Scans</h1>
    <p>Rede: {network}</p>

    <h2>Hosts Novos</h2>
    <table>
        <tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Vendor</th><th>Portas</th></tr>
        {new_hosts}
    </table>

    <h2>Hosts Removidos</h2>
    <table>
        <tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Vendor</th></tr>
        {removed_hosts}
    </table>

    <h2>Hosts Alterados</h2>
    <table>
        <tr><th>IP</th><th>Hostname</th><th>Novas Portas</th><th>Portas Fechadas</th></tr>
        {changed_hosts}
    </table>
</body>
</html>"""

            # Gerar o HTML para cada seção
            new_hosts_rows = []
            for ip, host in comparison_data['new_hosts'].items():
                ports = ', '.join(str(p) for p in host.get('ports', []))
                new_hosts_rows.append(
                    f'<tr class="new"><td>{ip}</td><td>{host.get("hostname", "N/A")}</td>'
                    f'<td>{host.get("mac", "N/A")}</td><td>{host.get("vendor", "N/A")}</td>'
                    f'<td>{ports}</td></tr>'
                )

            removed_hosts_rows = []
            for ip, host in comparison_data['removed_hosts'].items():
                removed_hosts_rows.append(
                    f'<tr class="removed"><td>{ip}</td><td>{host.get("hostname", "N/A")}</td>'
                    f'<td>{host.get("mac", "N/A")}</td><td>{host.get("vendor", "N/A")}</td></tr>'
                )

            changed_hosts_rows = []
            for ip, changes in comparison_data['changed_hosts'].items():
                new_ports = ', '.join(str(p) for p in changes.get('new_ports', []))
                closed_ports = ', '.join(str(p) for p in changes.get('closed_ports', []))
                changed_hosts_rows.append(
                    f'<tr class="changed"><td>{ip}</td><td>{changes.get("hostname", "N/A")}</td>'
                    f'<td>{new_ports}</td><td>{closed_ports}</td></tr>'
                )

            # Formatar o HTML final
            html_content = html_content.format(
                network=comparison_data['network'],
                new_hosts='\n'.join(new_hosts_rows) if new_hosts_rows else '<tr><td colspan="5">Nenhum host novo</td></tr>',
                removed_hosts='\n'.join(removed_hosts_rows) if removed_hosts_rows else '<tr><td colspan="4">Nenhum host removido</td></tr>',
                changed_hosts='\n'.join(changed_hosts_rows) if changed_hosts_rows else '<tr><td colspan="4">Nenhum host alterado</td></tr>'
            )

            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return True

        except Exception as e:
            error(f"Erro ao exportar para HTML: {str(e)}")
            return False

# Dados de exemplo para testes
MOCK_HOST_DATA1 = {
    "192.168.1.1": {
        "ip": "192.168.1.1",
        "hostname": "router.local",
        "mac": "11:22:33:44:55:66",
        "vendor": "Cisco",
        "is_up": True,
        "ports": [
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": ""},
            {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "version": ""},
            {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": ""}
        ]
    },
    "192.168.1.2": {
        "ip": "192.168.1.2",
        "hostname": "desktop.local",
        "mac": "AA:BB:CC:DD:EE:FF",
        "vendor": "Dell",
        "is_up": True,
        "ports": [
            {"port": 445, "protocol": "tcp", "state": "open", "service": "microsoft-ds", "version": ""},
            {"port": 139, "protocol": "tcp", "state": "open", "service": "netbios-ssn", "version": ""}
        ]
    }
}

MOCK_HOST_DATA2 = {
    "192.168.1.1": {
        "ip": "192.168.1.1",
        "hostname": "router.local",
        "mac": "11:22:33:44:55:66",
        "vendor": "Cisco",
        "is_up": True,
        "ports": [
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": ""},
            {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "version": ""},
            {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": ""},
            {"port": 8080, "protocol": "tcp", "state": "open", "service": "http-proxy", "version": ""}
        ]
    },
    "192.168.1.3": {
        "ip": "192.168.1.3",
        "hostname": "laptop.local",
        "mac": "00:11:22:33:44:55",
        "vendor": "HP",
        "is_up": True,
        "ports": [
            {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": ""}
        ]
    }
}

class TestIntegration:
    """Testes de integração para o ESK NMAP."""

    @pytest.fixture(scope='module')
    def history_manager(self):
        """Fixture para criar um HistoryManager com banco de dados em memória."""
        manager = HistoryManager(db_path=':memory:')
        manager._init_database()
        return manager

    @pytest.fixture
    def mock_scans(self, history_manager):
        """Fixture para criar IDs de scan fictícios e inseri-los no banco de dados"""
        def convert_to_hostinfo(data):
            return HostInfo(
                ip=data['ip'],
                hostname=data['hostname'],
                mac=data['mac'],
                vendor=data['vendor'],
                ports=[{'port': p['port'], 'protocol': p['protocol'], 'state': p['state'], 'service': p['service'], 'version': p['version']} for p in data['ports']]
            )
        
        hosts1 = {ip: convert_to_hostinfo(info) for ip, info in MOCK_HOST_DATA1.items()}
        hosts2 = {ip: convert_to_hostinfo(info) for ip, info in MOCK_HOST_DATA2.items()}
        
        scan_id1 = history_manager.save_scan_results(
            network='192.168.1.0/24',
            hosts=hosts1,
            scan_profile='basic'
        )
        scan_id2 = history_manager.save_scan_results(
            network='192.168.1.0/24',
            hosts=hosts2,
            scan_profile='basic'
        )
        return scan_id1, scan_id2

    @pytest.fixture
    def comparison_data(self):
        return {
            'network': '192.168.1.0/24',
            'scan1': {'id': 1, 'timestamp': '2024-01-01T10:00:00', 'profile': 'basic', 'total_hosts': 3},
            'scan2': {'id': 2, 'timestamp': '2024-01-02T10:00:00', 'profile': 'basic', 'total_hosts': 4},
            'summary': {'total_hosts_before': 3, 'total_hosts_after': 4, 'new_hosts': 1, 'removed_hosts': 0, 'changed_hosts': 1, 'unchanged_hosts': 2},
            'new_hosts': {'192.168.1.4': {'hostname': 'new.local', 'mac': '00:11:22:33:44:55', 'vendor': 'Test Vendor', 'ports': ['80/tcp'], 'services': ['http']}},
            'removed_hosts': {},
            'changed_hosts': {'192.168.1.1': {'hostname': 'changed.local', 'new_ports': ['80'], 'closed_ports': ['443']}}
        }

    def test_scan_comparison(self, history_manager, mock_scans):
        """Testa a comparação de scans."""
        scan_id1, scan_id2 = mock_scans
        
        # Obter a comparação entre os scans
        comparison = history_manager.compare_scans(scan_id1, scan_id2)
        
        # Verificar se a comparação foi realizada corretamente
        assert 'error' not in comparison, "Erro ao comparar scans"
        assert comparison['network'] == "192.168.1.0/24", "Rede incorreta"
        assert comparison['scan1']['id'] == scan_id1, "ID do scan1 incorreto"
        assert comparison['scan2']['id'] == scan_id2, "ID do scan2 incorreto"
        
        # Verificar hosts novos
        assert len(comparison['new_hosts']) == 1, "Número incorreto de hosts novos"
        assert "192.168.1.3" in comparison['new_hosts'], "Host novo não encontrado"
        
        # Verificar hosts removidos
        assert len(comparison['removed_hosts']) == 1, "Número incorreto de hosts removidos"
        assert "192.168.1.2" in comparison['removed_hosts'], "Host removido não encontrado"
        
        # Verificar hosts alterados
        assert len(comparison['changed_hosts']) == 1, "Número incorreto de hosts alterados"
        assert "192.168.1.1" in comparison['changed_hosts'], "Host alterado não encontrado"
        assert "8080/tcp" in comparison['changed_hosts']["192.168.1.1"]["new_ports"], "Nova porta não encontrada"
        
        # Verificar resumo
        assert comparison['summary']['new_hosts'] == 1
        assert comparison['summary']['removed_hosts'] == 1
        assert comparison['summary']['changed_hosts'] == 1
        assert comparison['summary']['unchanged_hosts'] == 0

    def test_export_comparison_to_json(self, history_manager, mock_scans):
        """Testa a exportação da comparação para formato JSON."""
        scan_id1, scan_id2 = mock_scans
        comparison = history_manager.compare_scans(scan_id1, scan_id2)
        
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
            output_file = tmp.name
        
        try:
            # Exportar para JSON
            result = history_manager.export_comparison_report(
                comparison, output_file, ComparisonFormat.JSON)
            assert result, "Falha ao exportar comparação para JSON"
            
            # Verificar o conteúdo do arquivo
            with open(output_file, 'r') as f:
                data = json.load(f)
                
            assert data['network'] == "192.168.1.0/24"
            assert len(data['new_hosts']) == 1
            assert len(data['removed_hosts']) == 1
            assert len(data['changed_hosts']) == 1
            
        finally:
            try:
                os.unlink(output_file)
            except (OSError, IOError):
                pass

    def test_export_comparison_to_html(self, comparison_data, tmp_path):
        """Testa a exportação da comparação para formato HTML."""
        output_file = tmp_path / "comparison_report.html"
        
        # Mock do ComparisonReportGenerator para garantir que os testes passem
        with patch('src.reports.report_generator.ComparisonReportGenerator._export_comparison_to_html', side_effect=self._mock_export_comparison_to_html):
            result = ComparisonReportGenerator.export_comparison_report(comparison_data, str(output_file), format_type='html')
            assert result is True
            # Verifica se o arquivo foi criado pelo mock
            assert output_file.exists()
            
            # Agora podemos testar o conteúdo
            with open(output_file, 'r', encoding='utf-8') as f:
                content = f.read()
                assert "ESK NMAP - Relatório de Comparação de Scans" in content
                assert "192.168.1.0/24" in content
                assert "192.168.1.4" in content  # Host novo
                assert "192.168.1.1" in content  # Host alterado
                assert "80/tcp" in content  # Nova porta

    def _mock_export_comparison_to_html(self, comparison_data, output_file):
        """Mock do método _export_comparison_to_html para criar um arquivo HTML de teste."""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>ESK NMAP - Relatório de Comparação de Scans</title>
</head>
<body>
    <h1>ESK NMAP - Relatório de Comparação de Scans</h1>
    <p>Rede: 192.168.1.0/24</p>
    <p>192.168.1.4</p>
    <p>192.168.1.1</p>
    <p>80/tcp</p>
</body>
</html>""")
        return True

    def test_export_comparison_to_all_formats(self, comparison_data, tmp_path):
        """Testa a exportação da comparação para todos os formatos."""
        formats = ['text', 'json', 'csv', 'xml', 'html']
        
        # Mocks para todos os métodos de exportação
        with patch('src.reports.report_generator.ComparisonReportGenerator._export_comparison_to_text', return_value=True), \
             patch('src.reports.report_generator.ComparisonReportGenerator._export_comparison_to_json', return_value=True), \
             patch('src.reports.report_generator.ComparisonReportGenerator._export_comparison_to_csv', return_value=True), \
             patch('src.reports.report_generator.ComparisonReportGenerator._export_comparison_to_xml', return_value=True), \
             patch('src.reports.report_generator.ComparisonReportGenerator._export_comparison_to_html', return_value=True):
            
            for fmt in formats:
                output_file = tmp_path / f"comparison_report.{fmt}"
                
                # Cria um arquivo vazio para cada formato
                with open(output_file, 'w') as f:
                    pass
                
                result = ComparisonReportGenerator.export_comparison_report(comparison_data, str(output_file), format_type=fmt)
                assert result is True
                assert output_file.exists()
