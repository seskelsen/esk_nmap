import os
import pytest
import logging
import json
import tempfile
from unittest.mock import patch, MagicMock
from src.utils.logger import ESKLogger, debug, info, warning, error, critical

class TestLogger:
    """Testes para o módulo logger.py"""
    
    @pytest.fixture
    def logger_instance(self):
        """Fixture que retorna uma instância limpa do ESKLogger"""
        # Cria um diretório temporário para os logs
        with tempfile.TemporaryDirectory() as temp_dir:
            # Configura o diretório de logs temporário
            ESKLogger.log_dir = temp_dir
            # Reseta o estado singleton para garantir uma instância limpa
            ESKLogger._instance = None
            ESKLogger._initialized = False
            
            logger = ESKLogger()
            yield logger
            
            # Limpeza após o teste
            logger.reset()
    
    def test_singleton_pattern(self):
        """Testa se o ESKLogger segue o padrão singleton"""
        ESKLogger._instance = None
        ESKLogger._initialized = False
        
        logger1 = ESKLogger()
        logger2 = ESKLogger()
        
        assert logger1 is logger2
        assert id(logger1) == id(logger2)
    
    def test_initialization(self, logger_instance):
        """Testa se o logger é inicializado corretamente"""
        # Verifica se a instância tem os atributos esperados
        assert hasattr(logger_instance, 'logger')
        assert isinstance(logger_instance.logger, logging.Logger)
        
        # Verifica os handlers
        assert len(logger_instance.logger.handlers) >= 3  # Deve ter pelo menos 3 handlers
        
        # Verifica se os arquivos de log foram criados
        log_dir = logger_instance.log_dir
        assert os.path.exists(os.path.join(log_dir, 'esk_nmap.log'))
        assert os.path.exists(os.path.join(log_dir, 'esk_nmap.json.log'))
    
    def test_file_handler_rotation(self, logger_instance):
        """Testa a rotação de arquivos de log"""
        # Obtém o handler de arquivo
        file_handlers = [h for h in logger_instance.logger.handlers 
                       if isinstance(h, logging.handlers.RotatingFileHandler)]
        assert len(file_handlers) >= 1
        
        # Verifica configurações de rotação
        file_handler = file_handlers[0]
        assert file_handler.maxBytes == 5*1024*1024  # 5MB
        assert file_handler.backupCount == 5
    
    def test_log_functions(self, logger_instance):
        """Testa as funções de logging"""
        # Mock para capturar as chamadas de log
        with patch.object(logger_instance.logger, 'debug') as mock_debug, \
             patch.object(logger_instance.logger, 'info') as mock_info, \
             patch.object(logger_instance.logger, 'warning') as mock_warning, \
             patch.object(logger_instance.logger, 'error') as mock_error, \
             patch.object(logger_instance.logger, 'critical') as mock_critical:
            
            # Testa cada função de log
            debug("Mensagem de debug")
            info("Mensagem de info")
            warning("Mensagem de warning")
            error("Mensagem de error")
            critical("Mensagem crítica")
            
            # Verifica se as funções foram chamadas com os argumentos corretos
            mock_debug.assert_called_once_with("Mensagem de debug")
            mock_info.assert_called_once_with("Mensagem de info")
            mock_warning.assert_called_once_with("Mensagem de warning")
            mock_error.assert_called_once_with("Mensagem de error")
            mock_critical.assert_called_once_with("Mensagem crítica")
    
    def test_json_log_format(self, logger_instance):
        """Testa o formato JSON do log"""
        # Encontra o handler JSON
        json_handlers = [h for h in logger_instance.logger.handlers 
                       if isinstance(h, logging.handlers.RotatingFileHandler) 
                       and h.baseFilename.endswith('.json.log')]
        assert len(json_handlers) >= 1
        json_handler = json_handlers[0]
        
        # Gera uma mensagem de log
        test_message = f"Test JSON log {id(self)}"
        logger_instance.logger.info(test_message)
        
        # Lê o arquivo de log JSON
        with open(json_handler.baseFilename, 'r', encoding='utf-8') as f:
            log_content = f.read()
            
        # Verifica se a mensagem está no log e é um JSON válido
        assert test_message in log_content
        
        # Tenta fazer o parse da última linha como JSON
        last_line = log_content.strip().split('\n')[-1]
        log_entry = json.loads(last_line)
        
        # Verifica se tem os campos esperados
        assert 'level' in log_entry
        assert 'message' in log_entry
        assert 'timestamp' in log_entry
        assert log_entry['level'] == 'INFO'
        assert test_message in log_entry['message']
    
    def test_reset_method(self, logger_instance):
        """Testa o método reset"""
        # Guarda referências aos handlers originais
        original_handlers = list(logger_instance.logger.handlers)
        assert len(original_handlers) > 0
        
        # Reseta o logger
        logger_instance.reset()
        
        # Verifica se os handlers foram recriados (não são os mesmos objetos)
        new_handlers = logger_instance.logger.handlers
        assert len(new_handlers) == len(original_handlers)
        assert all(new != old for new, old in zip(new_handlers, original_handlers))
    
    def test_get_logger(self, logger_instance):
        """Testa o método get_logger"""
        logger = logger_instance.get_logger()
        assert isinstance(logger, logging.Logger)
        assert logger.name == 'esk_nmap'