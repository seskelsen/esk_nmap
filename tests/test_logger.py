import pytest
import os
import json
import logging
from src.utils.logger import ESKLogger

class TestESKLogger:
    @pytest.fixture
    def logger_instance(self, tmp_path):
        # Configura o diretório temporário para os logs durante os testes
        ESKLogger._instance = None
        ESKLogger._initialized = False
        instance = ESKLogger()
        # Definindo o diretório temporário antes de inicializar
        instance.log_dir = str(tmp_path)
        # Chamar reset para forçar a reinicialização com o novo diretório
        instance.reset()
        return instance

    def test_singleton_pattern(self):
        """Testa se o logger segue o padrão singleton"""
        logger1 = ESKLogger()
        logger2 = ESKLogger()
        assert logger1 is logger2

    def test_log_file_creation(self, logger_instance, tmp_path):
        """Testa se os arquivos de log são criados"""
        assert os.path.exists(logger_instance.log_dir)
        logger = logger_instance.get_logger()
        logger.info("Test message")
        
        log_file = os.path.join(tmp_path, "esk_nmap.log")
        json_file = os.path.join(tmp_path, "esk_nmap.json.log")
        
        assert os.path.exists(log_file), f"Log file not found at {log_file}"
        assert os.path.exists(json_file), f"JSON log file not found at {json_file}"

    def test_log_levels(self, logger_instance, caplog):
        """Testa se diferentes níveis de log funcionam"""
        logger = logger_instance.get_logger()
        
        with caplog.at_level(logging.DEBUG):
            logger.debug("Debug message")
            logger.info("Info message")
            logger.warning("Warning message")
            logger.error("Error message")
            
            assert "Debug message" in caplog.text
            assert "Info message" in caplog.text
            assert "Warning message" in caplog.text
            assert "Error message" in caplog.text

    def test_json_log_format(self, logger_instance, tmp_path):
        """Testa se os logs JSON estão formatados corretamente"""
        logger = logger_instance.get_logger()
        test_message = "Test JSON logging"
        logger.info(test_message)
        
        json_file = os.path.join(tmp_path, "esk_nmap.json.log")
        
        assert os.path.exists(json_file), f"JSON log file not found at {json_file}"
        
        with open(json_file, 'r', encoding='utf-8') as f:
            content = f.read()
            assert content, "JSON log file is empty"
            # Tenta ler a primeira linha do arquivo que deve ser um JSON válido
            log_entry = json.loads(content.splitlines()[0])
            assert log_entry['message'] == test_message
            assert 'timestamp' in log_entry
            assert log_entry['level'] == 'INFO'
            assert log_entry['name'] == 'esk_nmap'