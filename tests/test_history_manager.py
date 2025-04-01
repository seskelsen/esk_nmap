import os
import json
import tempfile
import pytest
import sqlite3
from unittest.mock import patch, MagicMock
from datetime import datetime
from src.core.history_manager import HistoryManager
from src.reports.report_generator import ComparisonFormat

class TestHistoryManager:
    """Testes para o módulo history_manager.py"""
    
    @pytest.fixture
    def temp_db(self):
        """Fixture que cria um banco de dados temporário para testes"""
        # Cria um arquivo temporário para o banco de dados
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            db_path = tmp.name
        
        # Reset do singleton para garantir nova instância com banco de dados limpo
        HistoryManager._instance = None
        HistoryManager._initialized = False
        
        # Cria uma instância com o banco de dados temporário
        history_manager = HistoryManager(db_path)
        
        yield history_manager
        
        # Limpeza: remove o arquivo temporário após os testes
        try:
            os.unlink(db_path)
        except:
            pass
    
    def test_singleton_pattern(self):
        """Testa se HistoryManager segue o padrão singleton"""
        # Reset do singleton
        HistoryManager._instance = None
        HistoryManager._initialized = False
        
        # Cria um arquivo temporário para o banco de dados
        temp_dir = tempfile.gettempdir()
        db_path = os.path.join(temp_dir, 'test_singleton.db')
        
        # Certifica-se de que o arquivo não existe
        if os.path.exists(db_path):
            os.unlink(db_path)
            
        # Cria duas instâncias e verifica se são a mesma
        manager1 = HistoryManager(db_path)
        manager2 = HistoryManager(db_path)
        
        try:
            assert manager1 is manager2
            assert id(manager1) == id(manager2)
        finally:
            # Limpa o arquivo temporário
            if os.path.exists(db_path):
                try:
                    os.unlink(db_path)
                except:
                    pass
    
    def test_init_database(self, temp_db):
        """Testa a inicialização do banco de dados"""
        # Verifica se as tabelas foram criadas
        conn = sqlite3.connect(temp_db._db_path)
        cursor = conn.cursor()
        
        # Obtém a lista de tabelas
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        # Verifica se as tabelas esperadas existem
        assert 'scans' in tables
        assert 'hosts' in tables
        assert 'ports' in tables
        
        # Verifica se os índices foram criados
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indices = [row[0] for row in cursor.fetchall()]
        
        assert 'idx_scan_timestamp' in indices
        assert 'idx_scan_network' in indices
        assert 'idx_host_scan_id' in indices
        assert 'idx_host_ip' in indices
        assert 'idx_port_host_id' in indices
        
        conn.close()
    
    def test_save_scan_results(self, temp_db):
        """Testa o salvamento de resultados de um scan"""
        # Dados de teste
        network = "192.168.1.0/24"
        scan_profile = "basic"
        
        # Cria hosts de teste
        hosts = {
            "192.168.1.1": {
                "ip": "192.168.1.1",
                "hostname": "router.local",
                "mac": "00:11:22:33:44:55",
                "vendor": "Cisco",
                "status": "up",
                "ports": [
                    {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
                    {"port": 443, "protocol": "tcp", "state": "open", "service": "https"}
                ]
            },
            "192.168.1.2": {
                "ip": "192.168.1.2",
                "hostname": "server.local",
                "mac": "AA:BB:CC:DD:EE:FF",
                "vendor": "Dell",
                "status": "up",
                "ports": [
                    {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
                    {"port": 80, "protocol": "tcp", "state": "open", "service": "http"}
                ]
            }
        }
        
        # Salva os resultados
        scan_id = temp_db.save_scan_results(network, hosts, scan_profile)
        
        # Verifica se o ID foi retornado
        assert scan_id > 0
        
        # Verifica se os dados foram salvos corretamente
        conn = sqlite3.connect(temp_db._db_path)
        cursor = conn.cursor()
        
        # Verifica o scan
        cursor.execute("SELECT network, scan_profile, total_hosts FROM scans WHERE id = ?", (scan_id,))
        scan_row = cursor.fetchone()
        assert scan_row[0] == network
        assert scan_row[1] == scan_profile
        assert scan_row[2] == 2  # Total de hosts
        
        # Verifica os hosts
        cursor.execute("SELECT ip, hostname, mac, vendor, status FROM hosts WHERE scan_id = ?", (scan_id,))
        host_rows = cursor.fetchall()
        assert len(host_rows) == 2
        
        # Verifica as portas
        cursor.execute("""
            SELECT h.ip, p.port, p.service 
            FROM ports p 
            JOIN hosts h ON h.id = p.host_id 
            WHERE h.scan_id = ?
        """, (scan_id,))
        port_rows = cursor.fetchall()
        assert len(port_rows) == 4  # Total de 4 portas entre os dois hosts
        
        conn.close()
    
    def test_get_scan_list(self, temp_db):
        """Testa a obtenção da lista de scans"""
        # Adiciona alguns scans de teste
        networks = ["192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"]
        host_data = {"192.168.1.1": {"ip": "192.168.1.1", "hostname": "test", "status": "up", "ports": []}}
        
        for network in networks:
            temp_db.save_scan_results(network, host_data, "test_profile")
        
        # Obtém a lista de scans
        scans = temp_db.get_scan_list()
        
        # Verifica se todos os scans foram retornados
        assert len(scans) == 3
        
        # Verifica se estão ordenados por timestamp (mais recente primeiro)
        timestamps = [scan['timestamp'] for scan in scans]
        assert timestamps == sorted(timestamps, reverse=True)
        
        # Testa o limite
        limited_scans = temp_db.get_scan_list(limit=2)
        assert len(limited_scans) == 2
    
    def test_get_scan_by_id(self, temp_db):
        """Testa a recuperação de um scan pelo ID"""
        # Cria um scan de teste
        network = "192.168.1.0/24"
        hosts = {
            "192.168.1.1": {
                "ip": "192.168.1.1",
                "hostname": "router.local",
                "mac": "00:11:22:33:44:55",
                "vendor": "Cisco",
                "status": "up",
                "ports": [
                    {"port": 80, "protocol": "tcp", "state": "open", "service": "http"}
                ]
            }
        }
        
        scan_id = temp_db.save_scan_results(network, hosts, "test_profile")
        
        # Recupera o scan
        scan_data = temp_db.get_scan_by_id(scan_id)
        
        # Verifica se os dados foram recuperados corretamente
        assert scan_data is not None
        assert scan_data['id'] == scan_id
        assert scan_data['network'] == network
        assert scan_data['scan_profile'] == "test_profile"
        assert scan_data['total_hosts'] == 1
        assert len(scan_data['hosts']) == 1
        assert "192.168.1.1" in scan_data['hosts']
        assert scan_data['hosts']["192.168.1.1"]["hostname"] == "router.local"
        assert "80/tcp" in scan_data['hosts']["192.168.1.1"]["ports"]
        
        # Testa ID inexistente
        nonexistent_scan = temp_db.get_scan_by_id(9999)
        assert nonexistent_scan is None
    
    def test_get_scans_by_network(self, temp_db):
        """Testa a obtenção de scans por rede"""
        # Adiciona scans para diferentes redes
        networks = ["192.168.1.0/24", "192.168.1.0/24", "10.0.0.0/8"]
        host_data = {"192.168.1.1": {"ip": "192.168.1.1", "hostname": "test", "status": "up", "ports": []}}
        
        for network in networks:
            temp_db.save_scan_results(network, host_data, "test_profile")
        
        # Obtém scans para uma rede específica
        scans = temp_db.get_scans_by_network("192.168.1.0/24")
        
        # Deve retornar 2 scans
        assert len(scans) == 2
        
        # Todos devem ser da rede especificada
        for scan in scans:
            assert scan['network'] == "192.168.1.0/24"
    
    def test_delete_scan(self, temp_db):
        """Testa a exclusão de um scan"""
        # Cria um scan de teste
        network = "192.168.1.0/24"
        hosts = {"192.168.1.1": {"ip": "192.168.1.1", "hostname": "test", "status": "up", "ports": []}}
        
        scan_id = temp_db.save_scan_results(network, hosts, "test_profile")
        
        # Confirma que o scan existe
        assert temp_db.get_scan_by_id(scan_id) is not None
        
        # Exclui o scan
        result = temp_db.delete_scan(scan_id)
        
        # Verifica o resultado
        assert result is True
        
        # Verifica se o scan foi realmente excluído
        assert temp_db.get_scan_by_id(scan_id) is None
        
        # Tenta excluir um scan inexistente
        result = temp_db.delete_scan(9999)
        assert result is False
    
    def test_export_scan_to_json(self, temp_db):
        """Testa a exportação de um scan para JSON"""
        # Cria um scan de teste
        network = "192.168.1.0/24"
        hosts = {"192.168.1.1": {"ip": "192.168.1.1", "hostname": "test", "status": "up", "ports": []}}
        
        scan_id = temp_db.save_scan_results(network, hosts, "test_profile")
        
        # Cria um arquivo temporário para a exportação
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
            output_file = tmp.name
        
        try:
            # Exporta o scan
            result = temp_db.export_scan_to_json(scan_id, output_file)
            
            # Verifica o resultado
            assert result is True
            
            # Verifica se o arquivo foi criado e contém dados válidos
            with open(output_file, 'r') as f:
                exported_data = json.load(f)
                
            assert exported_data['id'] == scan_id
            assert exported_data['network'] == network
            
            # Testa a exportação de um scan inexistente
            result = temp_db.export_scan_to_json(9999, output_file)
            assert result is False
            
        finally:
            # Limpa o arquivo temporário
            try:
                os.unlink(output_file)
            except:
                pass
    
    def test_compare_scans(self, temp_db):
        """Testa a comparação entre scans"""
        # Cria dois scans com algumas diferenças
        network = "192.168.1.0/24"
        
        # Primeiro scan
        hosts1 = {
            "192.168.1.1": {
                "ip": "192.168.1.1",
                "hostname": "router.local",
                "mac": "00:11:22:33:44:55",
                "vendor": "Cisco",
                "status": "up",
                "ports": [
                    {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
                    {"port": 443, "protocol": "tcp", "state": "open", "service": "https"}
                ]
            },
            "192.168.1.2": {
                "ip": "192.168.1.2",
                "hostname": "server.local",
                "mac": "AA:BB:CC:DD:EE:FF",
                "vendor": "Dell",
                "status": "up",
                "ports": [
                    {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"}
                ]
            }
        }
        
        # Segundo scan (algumas mudanças)
        hosts2 = {
            "192.168.1.1": {  # Host mantido com mesmas portas
                "ip": "192.168.1.1",
                "hostname": "router.local",
                "mac": "00:11:22:33:44:55",
                "vendor": "Cisco",
                "status": "up",
                "ports": [
                    {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
                    {"port": 443, "protocol": "tcp", "state": "open", "service": "https"}
                ]
            },
            "192.168.1.3": {  # Novo host
                "ip": "192.168.1.3",
                "hostname": "new-host.local",
                "mac": "11:22:33:44:55:66",
                "vendor": "HP",
                "status": "up",
                "ports": [
                    {"port": 80, "protocol": "tcp", "state": "open", "service": "http"}
                ]
            }
            # 192.168.1.2 foi removido
        }
        
        # Salva os scans
        scan_id1 = temp_db.save_scan_results(network, hosts1, "first_scan")
        scan_id2 = temp_db.save_scan_results(network, hosts2, "second_scan")
        
        # Compara os scans
        comparison = temp_db.compare_scans(scan_id1, scan_id2)
        
        # Verifica os resultados da comparação
        assert comparison['network'] == network
        
        # Verifica hosts novos
        assert "192.168.1.3" in comparison['new_hosts']
        
        # Verifica hosts removidos
        assert "192.168.1.2" in comparison['removed_hosts']
        
        # Verifica o resumo
        assert comparison['summary']['new_hosts'] == 1
        assert comparison['summary']['removed_hosts'] == 1
        
        # Testa comparação com scan inexistente
        error_comparison = temp_db.compare_scans(scan_id1, 9999)
        assert 'error' in error_comparison
        assert error_comparison['found_scan1'] is True
        assert error_comparison['found_scan2'] is False
    
    @patch('src.reports.report_generator.ComparisonReportGenerator.export_comparison_report')
    def test_export_comparison_report(self, mock_export, temp_db):
        """Testa a exportação de um relatório de comparação"""
        # Dados fictícios de comparação
        comparison_data = {
            'network': '192.168.1.0/24',
            'new_hosts': {'192.168.1.3': {}},
            'removed_hosts': {'192.168.1.2': {}},
            'changed_hosts': {},
            'summary': {'new_hosts': 1, 'removed_hosts': 1}
        }
        
        # Define o comportamento do mock
        mock_export.return_value = True
        
        # Testa a exportação
        output_file = 'test_comparison.txt'
        result = temp_db.export_comparison_report(
            comparison_data=comparison_data,
            output_file=output_file,
            format_type=ComparisonFormat.TEXT
        )
        
        # Verifica se a função de exportação foi chamada corretamente
        mock_export.assert_called_once_with(
            comparison_data=comparison_data,
            output_file=output_file,
            format_type=ComparisonFormat.TEXT
        )
        
        # Verifica o resultado
        assert result is True