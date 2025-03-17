import pytest
import os
import sqlite3
import tempfile
from unittest.mock import patch, MagicMock
from datetime import datetime

from src.core.history_manager import HistoryManager
from src.core.scanner import HostInfo

class TestHistoryManager:
    @pytest.fixture
    def temp_db_path(self):
        """Cria um caminho temporário para o banco de dados de teste"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            db_path = tmp.name
        
        # Retorna o caminho e depois limpa o arquivo após o teste
        yield db_path
        
        if os.path.exists(db_path):
            os.remove(db_path)
    
    @pytest.fixture
    def history_manager(self, temp_db_path):
        """Cria uma instância de HistoryManager com banco de dados temporário"""
        # Reseta a instância singleton para garantir um novo banco de dados
        HistoryManager._instance = None
        HistoryManager._initialized = False
        
        # Cria e retorna uma nova instância
        return HistoryManager(temp_db_path)
    
    @pytest.fixture
    def populated_history_manager(self, history_manager):
        """Preenche o banco de dados com alguns dados de teste"""
        # Scan 1: 192.168.1.0/24 com 2 hosts
        hosts1 = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                hostname="router.local",
                mac="00:11:22:33:44:55",
                vendor="Vendor A",
                ports=["80/tcp", "443/tcp"],
                services=["http", "https"]
            ),
            "192.168.1.2": HostInfo(
                ip="192.168.1.2",
                hostname="server.local",
                mac="AA:BB:CC:DD:EE:FF",
                vendor="Vendor B",
                ports=["22/tcp", "3306/tcp"],
                services=["ssh", "mysql"]
            )
        }
        
        scan_id1 = history_manager.save_scan_results("192.168.1.0/24", hosts1, "basic")
        
        # Scan 2: 192.168.1.0/24 com 3 hosts (um novo, um modificado)
        hosts2 = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                hostname="router.local",
                mac="00:11:22:33:44:55",
                vendor="Vendor A",
                ports=["80/tcp", "443/tcp", "8080/tcp"],  # Nova porta
                services=["http", "https", "http-proxy"]
            ),
            "192.168.1.2": HostInfo(
                ip="192.168.1.2",
                hostname="server.local",
                mac="AA:BB:CC:DD:EE:FF",
                vendor="Vendor B",
                ports=["22/tcp"],  # Porta 3306/tcp fechada
                services=["ssh"]
            ),
            "192.168.1.3": HostInfo(  # Host novo
                ip="192.168.1.3",
                hostname="workstation.local",
                mac="11:22:33:44:55:66",
                vendor="Vendor C",
                ports=["135/tcp", "445/tcp"],
                services=["msrpc", "microsoft-ds"]
            )
        }
        
        scan_id2 = history_manager.save_scan_results("192.168.1.0/24", hosts2, "complete")
        
        # Scan 3: Outra rede
        hosts3 = {
            "10.0.0.1": HostInfo(
                ip="10.0.0.1",
                hostname="gateway",
                mac="FF:EE:DD:CC:BB:AA",
                vendor="Vendor X",
                ports=["80/tcp"],
                services=["http"]
            )
        }
        
        scan_id3 = history_manager.save_scan_results("10.0.0.0/24", hosts3, "basic")
        
        return history_manager, scan_id1, scan_id2, scan_id3
    
    def test_singleton_pattern(self, temp_db_path):
        """Testa se o HistoryManager segue o padrão singleton"""
        manager1 = HistoryManager(temp_db_path)
        manager2 = HistoryManager(temp_db_path)
        assert manager1 is manager2
    
    def test_init_database(self, history_manager, temp_db_path):
        """Testa se o banco de dados é inicializado corretamente"""
        # Verifica se o arquivo foi criado
        assert os.path.exists(temp_db_path)
        
        # Conecta diretamente ao banco para verificar a estrutura
        conn = sqlite3.connect(temp_db_path)
        cursor = conn.cursor()
        
        # Obtém lista de tabelas
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        
        # Verifica se as tabelas necessárias foram criadas
        assert 'scans' in tables
        assert 'hosts' in tables
        assert 'ports' in tables
        
        # Verifica índices
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indexes = {row[0] for row in cursor.fetchall()}
        
        assert 'idx_scan_timestamp' in indexes
        assert 'idx_scan_network' in indexes
        assert 'idx_host_scan_id' in indexes
        assert 'idx_host_ip' in indexes
        assert 'idx_port_host_id' in indexes
        
        conn.close()
    
    def test_save_scan_results(self, history_manager):
        """Testa se os resultados do scan são salvos corretamente"""
        hosts = {
            "192.168.1.1": HostInfo(
                ip="192.168.1.1",
                hostname="test.local",
                is_up=True,
                ports=[{"port": 80, "state": "open", "service": "http"}]
            )
        }
        
        scan_id = history_manager.save_scan_results("192.168.1.0/24", hosts, "basic")
        
        # Verifica se retornou um ID válido
        assert isinstance(scan_id, int)
        assert scan_id > 0
        
        # Consulta diretamente o banco para verificar se os dados foram salvos
        conn = sqlite3.connect(history_manager._db_path)
        cursor = conn.cursor()
        
        # Verifica scan
        cursor.execute("SELECT network, scan_profile, total_hosts FROM scans WHERE id = ?", (scan_id,))
        scan_row = cursor.fetchone()
        assert scan_row is not None
        assert scan_row[0] == "192.168.1.0/24"
        assert scan_row[1] == "basic"
        assert scan_row[2] == 1
        
        # Verifica host
        cursor.execute("SELECT ip, hostname, mac, vendor FROM hosts WHERE scan_id = ?", (scan_id,))
        host_row = cursor.fetchone()
        assert host_row is not None
        assert host_row[0] == "192.168.1.1"
        assert host_row[1] == "test.local"
        assert host_row[2] == "00:11:22:33:44:55"
        assert host_row[3] == "Test Vendor"
        
        # Verifica portas
        cursor.execute("SELECT h.ip, p.port, p.service FROM hosts h JOIN ports p ON h.id = p.host_id WHERE h.scan_id = ?", (scan_id,))
        port_rows = cursor.fetchall()
        assert len(port_rows) == 2
        
        ports = {row[1]: row[2] for row in port_rows}
        assert "80/tcp" in ports
        assert "443/tcp" in ports
        assert ports["80/tcp"] == "http"
        assert ports["443/tcp"] == "https"
        
        conn.close()
    
    def test_get_scan_list(self, populated_history_manager):
        """Testa a obtenção da lista de scans"""
        history_manager, scan_id1, scan_id2, scan_id3 = populated_history_manager
        
        # Obtém lista com limite padrão
        scan_list = history_manager.get_scan_list()
        assert len(scan_list) == 3
        
        # Verifica ordenação (mais recente primeiro)
        assert scan_list[0]['id'] == scan_id3
        assert scan_list[1]['id'] == scan_id2
        assert scan_list[2]['id'] == scan_id1
        
        # Testa com limite personalizado
        scan_list_limited = history_manager.get_scan_list(limit=2)
        assert len(scan_list_limited) == 2
        assert scan_list_limited[0]['id'] == scan_id3
        assert scan_list_limited[1]['id'] == scan_id2
    
    def test_get_scan_by_id(self, populated_history_manager):
        """Testa a obtenção de um scan específico pelo ID"""
        history_manager, scan_id1, _, _ = populated_history_manager
        
        scan = history_manager.get_scan_by_id(scan_id1)
        
        assert scan is not None
        assert scan['id'] == scan_id1
        assert scan['network'] == "192.168.1.0/24"
        assert scan['scan_profile'] == "basic"
        assert scan['total_hosts'] == 2
        
        # Verifica hosts
        hosts = scan['hosts']
        assert len(hosts) == 2
        assert "192.168.1.1" in hosts
        assert "192.168.1.2" in hosts
        
        # Verifica portas
        assert set(hosts["192.168.1.1"]["ports"]) == {"80/tcp", "443/tcp"}
        assert set(hosts["192.168.1.2"]["ports"]) == {"22/tcp", "3306/tcp"}
    
    def test_get_scan_by_id_nonexistent(self, history_manager):
        """Testa a obtenção de um scan inexistente"""
        scan = history_manager.get_scan_by_id(999)
        assert scan is None
    
    def test_get_scans_by_network(self, populated_history_manager):
        """Testa a obtenção de scans de uma rede específica"""
        history_manager, scan_id1, scan_id2, scan_id3 = populated_history_manager
        
        # Obtém scans da primeira rede
        scans = history_manager.get_scans_by_network("192.168.1.0/24")
        assert len(scans) == 2
        assert {scan['id'] for scan in scans} == {scan_id1, scan_id2}
        
        # Obtém scans da segunda rede
        scans = history_manager.get_scans_by_network("10.0.0.0/24")
        assert len(scans) == 1
        assert scans[0]['id'] == scan_id3
        
        # Testa com rede inexistente
        scans = history_manager.get_scans_by_network("172.16.0.0/24")
        assert len(scans) == 0
    
    def test_delete_scan(self, populated_history_manager):
        """Testa a exclusão de um scan"""
        history_manager, scan_id1, _, _ = populated_history_manager
        
        # Confirma que existe antes de excluir
        assert history_manager.get_scan_by_id(scan_id1) is not None
        
        # Exclui
        result = history_manager.delete_scan(scan_id1)
        assert result is True
        
        # Verifica se foi excluído
        assert history_manager.get_scan_by_id(scan_id1) is None
    
    def test_delete_nonexistent_scan(self, history_manager):
        """Testa a exclusão de um scan inexistente"""
        result = history_manager.delete_scan(999)
        assert result is False
    
    def test_export_scan_to_json(self, populated_history_manager, tmp_path):
        """Testa a exportação de um scan para JSON"""
        history_manager, scan_id1, _, _ = populated_history_manager
        
        output_file = os.path.join(tmp_path, "scan_export.json")
        result = history_manager.export_scan_to_json(scan_id1, output_file)
        
        assert result is True
        assert os.path.exists(output_file)
        
        # Verifica se o arquivo contém dados válidos
        import json
        with open(output_file, 'r') as f:
            data = json.load(f)
        
        assert data['id'] == scan_id1
        assert data['network'] == "192.168.1.0/24"
        assert len(data['hosts']) == 2
    
    def test_export_nonexistent_scan(self, history_manager, tmp_path):
        """Testa a exportação de um scan inexistente"""
        output_file = os.path.join(tmp_path, "nonexistent_scan.json")
        result = history_manager.export_scan_to_json(999, output_file)
        
        assert result is False
        assert not os.path.exists(output_file)
    
    def test_compare_scans(self, populated_history_manager):
        """Testa a comparação entre dois scans"""
        history_manager, scan_id1, scan_id2, _ = populated_history_manager
        
        comparison = history_manager.compare_scans(scan_id1, scan_id2)
        
        # Verifica metadados
        assert comparison['scan1']['id'] == scan_id1
        assert comparison['scan2']['id'] == scan_id2
        assert comparison['network'] == "192.168.1.0/24"
        
        # Verifica hosts novos
        assert "192.168.1.3" in comparison['new_hosts']
        
        # Verifica hosts removidos
        assert len(comparison['removed_hosts']) == 0
        
        # Verifica hosts alterados
        assert "192.168.1.1" in comparison['changed_hosts']  # Nova porta 8080
        assert "192.168.1.2" in comparison['changed_hosts']  # Porta 3306 fechada
        
        # Verifica alterações específicas
        assert "8080/tcp" in comparison['changed_hosts']["192.168.1.1"]["new_ports"]
        assert "3306/tcp" in comparison['changed_hosts']["192.168.1.2"]["closed_ports"]
        
        # Verifica resumo
        assert comparison['summary']['total_hosts_before'] == 2
        assert comparison['summary']['total_hosts_after'] == 3
        assert comparison['summary']['new_hosts'] == 1
        assert comparison['summary']['removed_hosts'] == 0
        assert comparison['summary']['changed_hosts'] == 2
        assert comparison['summary']['unchanged_hosts'] == 0
    
    def test_compare_nonexistent_scans(self, history_manager):
        """Testa a comparação com scans inexistentes"""
        comparison = history_manager.compare_scans(999, 1000)
        
        assert 'error' in comparison
        assert comparison['found_scan1'] is False
        assert comparison['found_scan2'] is False
    
    def test_compare_scans_different_networks(self, populated_history_manager):
        """Testa a comparação entre scans de redes diferentes"""
        history_manager, scan_id1, _, scan_id3 = populated_history_manager
        
        # Deve funcionar, mas gerar warning sobre redes diferentes
        with patch('src.core.history_manager.warning') as mock_warning:
            comparison = history_manager.compare_scans(scan_id1, scan_id3)
            mock_warning.assert_called_once()
            assert "redes diferentes" in mock_warning.call_args[0][0]
        
        # A comparação ainda deve retornar resultados
        assert comparison['new_hosts']
        assert comparison['removed_hosts']