import pytest
import sys
from unittest.mock import patch, MagicMock, call
import subprocess
from src.utils.error_handler import ErrorHandler, ErrorCategory

class TestErrorHandler:
    def test_categorize_network_error(self):
        """Testa categorização de erros de rede"""
        e = ConnectionError("Falha na conexão")
        category = ErrorHandler.categorize_error(e)
        assert category == ErrorCategory.NETWORK
        
    def test_categorize_permission_error(self):
        """Testa categorização de erros de permissão"""
        e = PermissionError("Acesso negado")
        category = ErrorHandler.categorize_error(e)
        assert category == ErrorCategory.PERMISSION
        
    def test_categorize_timeout_error(self):
        """Testa categorização de erros de timeout"""
        e = subprocess.TimeoutExpired(cmd="nmap", timeout=30)
        category = ErrorHandler.categorize_error(e)
        assert category == ErrorCategory.TIMEOUT
        
    def test_categorize_config_error(self):
        """Testa categorização de erros de configuração"""
        e = ValueError("Valor de configuração inválido")
        category = ErrorHandler.categorize_error(e)
        assert category == ErrorCategory.CONFIGURATION
        
    def test_categorize_dependency_error(self):
        """Testa categorização de erros de dependências"""
        e = ModuleNotFoundError("No module named 'nonexistent'")
        category = ErrorHandler.categorize_error(e)
        assert category == ErrorCategory.DEPENDENCY
        
    def test_categorize_command_error(self):
        """Testa categorização de erros de execução de comandos"""
        e = subprocess.CalledProcessError(returncode=1, cmd="nmap")
        category = ErrorHandler.categorize_error(e)
        assert category == ErrorCategory.COMMAND_EXECUTION
        
    def test_categorize_parsing_error(self):
        """Testa categorização de erros de parsing"""
        e = SyntaxError("Erro de sintaxe")
        category = ErrorHandler.categorize_error(e)
        assert category == ErrorCategory.PARSING
        
    def test_categorize_user_input_error(self):
        """Testa categorização de erros de entrada do usuário"""
        e = ValueError("Argumento input inválido")
        category = ErrorHandler.categorize_error(e)
        assert category == ErrorCategory.USER_INPUT
        
    def test_categorize_filesystem_error(self):
        """Testa categorização de erros de sistema de arquivos"""
        e = FileNotFoundError("Arquivo não encontrado")
        category = ErrorHandler.categorize_error(e)
        assert category == ErrorCategory.FILESYSTEM
        
    def test_categorize_unknown_error(self):
        """Testa categorização de erros desconhecidos"""
        class CustomError(Exception):
            pass
        e = CustomError("Erro personalizado")
        category = ErrorHandler.categorize_error(e)
        assert category == ErrorCategory.UNKNOWN

    @patch('src.utils.error_handler.error')
    @patch('src.utils.error_handler.debug')
    def test_handle_exception(self, mock_debug, mock_error):
        """Testa o manipulador de exceções"""
        e = ValueError("Erro de teste")
        result = ErrorHandler.handle_exception(e, context="teste unitário")
        
        # Verifica se os logs foram chamados
        mock_error.assert_called_once()
        mock_debug.assert_called_once()
        
        # Verifica o conteúdo do resultado
        assert result["type"] == "ValueError"
        assert result["message"] == "Erro de teste"
        assert result["context"] == "teste unitário"
        assert "traceback" in result
        assert result["category"] == ErrorCategory.CONFIGURATION.value
        
    @patch('src.utils.error_handler.sys.exit')
    @patch('src.utils.error_handler.warning')
    def test_handle_exception_with_exit(self, mock_warning, mock_exit):
        """Testa o manipulador de exceções com saída do programa"""
        e = ValueError("Erro crítico")
        ErrorHandler.handle_exception(e, exit_on_error=True, exit_code=2)
        
        # Verifica se warning e exit foram chamados corretamente
        mock_warning.assert_called_once()
        mock_exit.assert_called_once_with(2)

    def test_with_retry_success(self):
        """Testa o mecanismo de retry com função bem-sucedida"""
        mock_func = MagicMock(return_value="sucesso")
        
        result = ErrorHandler.with_retry(mock_func, "arg1", kwarg="valor")
        
        assert result == "sucesso"
        mock_func.assert_called_once_with("arg1", kwarg="valor")
        
    def test_with_retry_eventually_succeeds(self):
        """Testa o mecanismo de retry que eventualmente tem sucesso"""
        # Mock que falha nas primeiras duas chamadas e sucede na terceira
        mock_func = MagicMock(side_effect=[
            ConnectionError("Falha na tentativa 1"),
            ConnectionError("Falha na tentativa 2"),
            "sucesso"
        ])
        
        with patch('src.utils.error_handler.warning') as mock_warning:
            with patch('src.utils.error_handler.info') as mock_info:
                result = ErrorHandler.with_retry(
                    mock_func, 
                    context="operação de teste",
                    max_retries=3
                )
                
                assert result == "sucesso"
                assert mock_func.call_count == 3
                assert mock_warning.call_count == 2
                assert mock_info.call_count == 2
                
    def test_with_retry_always_fails(self):
        """Testa o mecanismo de retry que sempre falha"""
        # Mock que sempre falha
        mock_func = MagicMock(side_effect=ConnectionError("Falha de conexão"))
        
        with patch('src.utils.error_handler.warning') as mock_warning:
            with patch('src.utils.error_handler.error') as mock_error:
                with patch('src.utils.error_handler.info') as mock_info:
                    result = ErrorHandler.with_retry(
                        mock_func, 
                        context="operação de teste", 
                        max_retries=2
                    )
                    
                    assert result is None
                    assert mock_func.call_count == 2
                    assert mock_warning.call_count == 2
                    # Verifica as chamadas específicas para o error
                    assert mock_error.call_count == 2
                    calls = [
                        call("Erro de rede durante operação de teste: Falha de conexão (ConnectionError)"),
                        call("Todas as 2 tentativas para operação de teste falharam.")
                    ]
                    mock_error.assert_has_calls(calls)
                    assert mock_info.call_count == 1

    def test_with_retry_non_retryable_error(self):
        """Testa o mecanismo de retry com um erro que não deve ser repetido"""
        # Mock que falha com um erro que não deve acionar retry
        mock_func = MagicMock(side_effect=ValueError("Erro de configuração"))
        
        with patch('src.utils.error_handler.error') as mock_error:
            with pytest.raises(ValueError, match="Erro de configuração"):
                ErrorHandler.with_retry(
                    mock_func, 
                    retry_categories=[ErrorCategory.NETWORK]  # Apenas erros de rede geram retry
                )