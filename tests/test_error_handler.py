import pytest
import sys
from unittest.mock import patch, MagicMock
from src.utils.error_handler import ErrorHandler, ErrorCategory, ScannerError

class TestErrorHandler:
    """Testes para o módulo error_handler.py"""
    
    def test_scanner_error_initialization(self):
        """Testa a inicialização da exceção ScannerError"""
        error = ScannerError("Mensagem de teste", ErrorCategory.NETWORK)
        assert error.message == "Mensagem de teste"
        assert error.category == ErrorCategory.NETWORK
        assert str(error) == "Mensagem de teste"
    
    def test_error_categorization(self):
        """Testa a categorização automática de diferentes tipos de exceções"""
        # Teste de erros de rede
        assert ErrorHandler.categorize_error(ConnectionError()) == ErrorCategory.NETWORK
        
        # Teste de erros de permissão
        assert ErrorHandler.categorize_error(PermissionError()) == ErrorCategory.PERMISSION
        
        # Teste de erros de timeout
        timeout_error = TimeoutError()
        assert ErrorHandler.categorize_error(timeout_error) == ErrorCategory.TIMEOUT
        
        # Teste de erros de configuração
        assert ErrorHandler.categorize_error(KeyError("chave")) == ErrorCategory.CONFIGURATION
        
        # Teste de erros de dependências
        assert ErrorHandler.categorize_error(ModuleNotFoundError()) == ErrorCategory.DEPENDENCY
        
        # Teste de erros de execução de comandos
        assert ErrorHandler.categorize_error(OSError()) == ErrorCategory.COMMAND_EXECUTION
        
        # Teste de erros de parsing
        assert ErrorHandler.categorize_error(SyntaxError()) == ErrorCategory.PARSING
        
        # Teste de erros de entrada do usuário
        assert ErrorHandler.categorize_error(ValueError("input inválido")) == ErrorCategory.USER_INPUT
        
        # Teste de erros de sistema de arquivos
        assert ErrorHandler.categorize_error(FileNotFoundError()) == ErrorCategory.FILESYSTEM
        
        # Teste de erro desconhecido
        assert ErrorHandler.categorize_error(Exception()) == ErrorCategory.UNKNOWN
    
    def test_scanner_error_categorization(self):
        """Testa que ScannerError mantém sua categoria ao ser categorizado"""
        error = ScannerError("Erro de teste", ErrorCategory.NETWORK)
        assert ErrorHandler.categorize_error(error) == ErrorCategory.NETWORK
    
    @patch('src.utils.error_handler.error')
    @patch('src.utils.error_handler.debug')
    def test_handle_exception(self, mock_debug, mock_error):
        """Testa o método handle_exception"""
        e = ValueError("Mensagem de erro")
        details = ErrorHandler.handle_exception(e, context="teste", exit_on_error=False)
        
        # Verifica se os logs foram chamados
        mock_error.assert_called_once()
        mock_debug.assert_called_once()
        
        # Verifica se os detalhes do erro foram retornados corretamente
        assert details["type"] == "ValueError"
        assert details["message"] == "Mensagem de erro"
        assert details["context"] == "teste"
        assert "traceback" in details
    
    @patch('src.utils.error_handler.warning')
    @patch('src.utils.error_handler.sys.exit')
    def test_handle_exception_with_exit(self, mock_exit, mock_warning):
        """Testa o método handle_exception com saída do programa"""
        e = ValueError("Erro crítico")
        ErrorHandler.handle_exception(e, exit_on_error=True, exit_code=42)
        
        # Verifica se o aviso foi registrado
        mock_warning.assert_called_once()
        
        # Verifica se sys.exit foi chamado com o código correto
        mock_exit.assert_called_once_with(42)
    
    def test_with_retry_success(self):
        """Testa o método with_retry com sucesso na primeira tentativa"""
        mock_func = MagicMock(return_value="sucesso")
        
        result = ErrorHandler.with_retry(mock_func, "arg1", kwarg1="valor")
        
        # Verifica se a função foi chamada com os argumentos corretos
        mock_func.assert_called_once_with("arg1", kwarg1="valor")
        
        # Verifica se o resultado está correto
        assert result == "sucesso"
    
    def test_with_retry_eventual_success(self):
        """Testa o método with_retry com sucesso após algumas falhas"""
        # Mock que falha nas primeiras duas chamadas e depois tem sucesso
        mock_func = MagicMock(side_effect=[
            ConnectionError("Falha 1"),
            ConnectionError("Falha 2"),
            "sucesso"
        ])
        
        result = ErrorHandler.with_retry(
            mock_func, 
            retry_categories=[ErrorCategory.NETWORK], 
            max_retries=3
        )
        
        # Verifica se a função foi chamada o número correto de vezes
        assert mock_func.call_count == 3
        
        # Verifica se o resultado está correto
        assert result == "sucesso"
    
    def test_with_retry_failure(self):
        """Testa o método with_retry com falha em todas as tentativas"""
        # Mock que sempre falha
        mock_func = MagicMock(side_effect=ConnectionError("Falha de conexão"))
        
        with patch('src.utils.error_handler.error') as mock_error:
            with patch('src.utils.error_handler.warning') as mock_warning:
                result = ErrorHandler.with_retry(
                    mock_func,
                    retry_categories=[ErrorCategory.NETWORK],
                    max_retries=2,
                    context="operação de teste"
                )
                
                # Verifica se a função foi chamada o número correto de vezes
                assert mock_func.call_count == 2
                
                # Verifica se os logs foram chamados
                assert mock_warning.call_count >= 1
                assert mock_error.call_count >= 1
                
                # Verifica se o resultado é None após falhas
                assert result is None
    
    def test_with_retry_non_retryable_error(self):
        """Testa o método with_retry com erro não retryable"""
        # Mock que lança um erro que não está nas categorias de retry
        mock_func = MagicMock(side_effect=ValueError("Erro não retryable"))
        
        # O erro deve ser propagado
        with pytest.raises(ValueError):
            ErrorHandler.with_retry(
                mock_func,
                retry_categories=[ErrorCategory.NETWORK, ErrorCategory.TIMEOUT]
            )
            
        # Verifica se a função foi chamada apenas uma vez
        mock_func.assert_called_once()