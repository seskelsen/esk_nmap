#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ESK NMAP - Network Scanner Tool
Copyright (C) 2025 Eskel Cybersecurity
Author: Sigmar Eskelsen
"""

import sys
import traceback
from enum import Enum
from typing import Optional, Dict, Any, Callable
from .logger import error, debug, warning, info

class ErrorCategory(Enum):
    """Categorias de erro para melhor classificação"""
    NETWORK = "Erro de rede"
    PERMISSION = "Erro de permissão"
    TIMEOUT = "Erro de timeout"
    CONFIGURATION = "Erro de configuração"
    DEPENDENCY = "Erro de dependência"
    COMMAND_EXECUTION = "Erro na execução de comando"
    PARSING = "Erro de parsing"
    USER_INPUT = "Erro de entrada do usuário"
    FILESYSTEM = "Erro de sistema de arquivos"
    UNKNOWN = "Erro desconhecido"

class ScannerError(Exception):
    """Exceção personalizada para erros relacionados ao scanner"""
    def __init__(self, message: str, category: ErrorCategory = ErrorCategory.UNKNOWN):
        self.message = message
        self.category = category
        super().__init__(self.message)

class ErrorHandler:
    """Classe para tratamento centralizado de erros"""
    
    MAX_RETRIES = 3  # Número máximo de tentativas para operações com retry
    
    @staticmethod
    def categorize_error(exception: Exception) -> ErrorCategory:
        """Categoriza o erro com base no tipo da exceção"""
        # Se já é um ScannerError, usa a categoria definida
        if isinstance(exception, ScannerError):
            return exception.category
            
        error_type = type(exception).__name__
        error_message = str(exception).lower()
        
        # Erros de rede
        if error_type in ('ConnectionError', 'ConnectionRefusedError', 'ConnectionAbortedError', 
                          'ConnectionResetError', 'socket.error'):
            return ErrorCategory.NETWORK
            
        # Erros de permissão
        elif error_type in ('PermissionError', 'AccessDenied') or 'permission' in error_message:
            return ErrorCategory.PERMISSION
            
        # Erros de timeout
        elif 'TimeoutExpired' in error_type or 'timeout' in error_message:
            return ErrorCategory.TIMEOUT
            
        # Erros de configuração
        elif error_type in ('ConfigError', 'KeyError') or (error_type == 'ValueError' and 'input' not in error_message):
            return ErrorCategory.CONFIGURATION
            
        # Erros de dependências
        elif error_type in ('ModuleNotFoundError', 'ImportError'):
            return ErrorCategory.DEPENDENCY
            
        # Erros de execução de comandos
        elif 'CalledProcessError' in error_type or error_type == 'OSError':
            return ErrorCategory.COMMAND_EXECUTION
            
        # Erros de parsing
        elif error_type in ('JSONDecodeError', 'ParseError', 'SyntaxError'):
            return ErrorCategory.PARSING
            
        # Erros de entrada do usuário
        elif (error_type in ('ValueError', 'TypeError') and 
              any(x in error_message for x in ['input', 'argument', 'inválido'])):
            return ErrorCategory.USER_INPUT
            
        # Erros de sistema de arquivos
        elif error_type in ('FileNotFoundError', 'NotADirectoryError', 'IsADirectoryError'):
            return ErrorCategory.FILESYSTEM
            
        # Erro desconhecido
        else:
            return ErrorCategory.UNKNOWN
    
    @staticmethod
    def handle_exception(e: Exception, context: Optional[str] = None, 
                         exit_on_error: bool = False, exit_code: int = 1) -> Dict[str, Any]:
        """
        Manipula exceções de forma centralizada
        
        Args:
            e: A exceção capturada
            context: Contexto onde a exceção ocorreu
            exit_on_error: Se True, encerra o programa
            exit_code: Código de saída se exit_on_error=True
            
        Returns:
            Dicionário com detalhes do erro
        """
        category = ErrorHandler.categorize_error(e)
        error_type = type(e).__name__
        error_message = str(e)
        
        # Registrar o erro com diferentes níveis de verbosidade
        error_context = f" durante {context}" if context else ""
        error(f"{category.value}{error_context}: {error_message} ({error_type})")
        debug(f"Traceback completo:\n{''.join(traceback.format_exception(None, e, e.__traceback__))}")
        
        # Detalhes do erro para possível processamento
        error_details = {
            "category": category.value,
            "type": error_type,
            "message": error_message,
            "context": context,
            "traceback": traceback.format_exception(None, e, e.__traceback__)
        }
        
        # Saída do programa se necessário
        if exit_on_error:
            warning(f"Encerrando o programa devido a um erro crítico: {error_message}")
            sys.exit(exit_code)
            
        return error_details
    
    @staticmethod
    def with_retry(func: Callable, *args, max_retries: int = None, 
                   retry_categories: list = None, context: str = None, **kwargs):
        """
        Executa uma função com mecanismo de retry automático
        
        Args:
            func: A função a ser executada
            args: Argumentos posicionais para a função
            max_retries: Número máximo de tentativas (default: MAX_RETRIES)
            retry_categories: Lista de categorias de erro que disparam retry
            context: Contexto da operação para logging
            kwargs: Argumentos nomeados para a função
            
        Returns:
            O resultado da função ou None se falhar em todas as tentativas
            
        Raises:
            Exception: Re-levanta a exceção se o erro não for retryable
        """
        if max_retries is None:
            max_retries = ErrorHandler.MAX_RETRIES
            
        if retry_categories is None:
            # Por padrão, apenas tentamos novamente erros de rede e timeout
            retry_categories = [ErrorCategory.NETWORK, ErrorCategory.TIMEOUT]
            
        attempt = 0
        last_error = None
        retried = False
        
        while attempt < max_retries:
            try:
                attempt += 1
                return func(*args, **kwargs)
            except Exception as e:
                category = ErrorHandler.categorize_error(e)
                last_error = e
                
                if category in retry_categories:
                    # Este é um erro que podemos tentar novamente
                    retried = True
                    remaining = max_retries - attempt
                    retry_context = f"{context} " if context else ""
                    warning(f"Tentativa {attempt} de {max_retries} para {retry_context}falhou: {str(e)}")
                    
                    if remaining > 0:
                        info(f"Tentando novamente... ({remaining} tentativa(s) restante(s))")
                        continue
                else:
                    # Se o erro não é retryable, registramos e propagamos
                    ErrorHandler.handle_exception(e, context=context)
                    raise
                    
                # Se chegou aqui, é um erro retryable mas acabaram as tentativas
                ErrorHandler.handle_exception(e, context=context)
                break
                
        # Se chegou aqui, todas as tentativas falharam e houve pelo menos um retry
        if last_error and retried:
            error_context = f"{context} " if context else ""
            error(f"Todas as {max_retries} tentativas para {error_context}falharam.")
            
        return None