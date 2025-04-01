#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ESK NMAP - Network Scanner Tool
Copyright (C) 2025 Eskel Cybersecurity
Author: Sigmar Eskelsen
"""

import logging
import sys
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pythonjsonlogger import json as jsonlogger
import yaml

class ESKLogger:
    _instance = None
    _initialized = False
    
    # Diretório padrão para logs
    log_dir = 'logs'

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ESKLogger, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if ESKLogger._initialized:
            return
            
        self.logger = logging.getLogger('esk_nmap')
        self.logger.setLevel(logging.DEBUG)
        # Limpar handlers pré-existentes para evitar duplicidade
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        
        # Criar diretório de logs se não existir
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
            
        self._setup_file_handler()
        self._setup_console_handler()
        self._setup_json_handler()
        
        ESKLogger._initialized = True

    def _setup_file_handler(self):
        """Configura handler para arquivo com rotação"""
        log_file = os.path.join(self.log_dir, 'esk_nmap.log')
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=5*1024*1024,  # 5MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    def _setup_console_handler(self):
        """Configura handler para console"""
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        formatter = logging.Formatter(
            '%(levelname)s: %(message)s'
        )
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

    def _setup_json_handler(self):
        """Configura handler para logs em formato JSON"""
        json_file = os.path.join(self.log_dir, 'esk_nmap.json.log')
        json_handler = RotatingFileHandler(
            json_file,
            maxBytes=5*1024*1024,
            backupCount=5,
            encoding='utf-8'
        )
        json_handler.setLevel(logging.DEBUG)
        formatter = jsonlogger.JsonFormatter(
            '%(timestamp)s %(levelname)s %(name)s %(message)s',
            rename_fields={'levelname': 'level'},
            timestamp=True
        )
        json_handler.setFormatter(formatter)
        self.logger.addHandler(json_handler)
        
    def reset(self):
        """Reseta o logger para um estado limpo - útil para testes"""
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
            handler.close()
        ESKLogger._initialized = False
        self.__init__()

    def get_logger(self):
        """Retorna a instância do logger"""
        return self.logger

# Função para carregar a configuração do arquivo config.yaml
def load_config():
    with open('config.yaml', 'r') as file:
        return yaml.safe_load(file)

# Carregar a configuração
config = load_config()

# Definir o nível de log com base no ambiente
environment = config.get('environment', 'production')
log_level = config.get('log_level', {}).get(environment, 'INFO').upper()

# Configurar o logger
logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/esk_nmap.log"),
        logging.StreamHandler()
    ]
)

# Criar instância global do logger
logger = ESKLogger().get_logger()

# Funções de conveniência
def debug(msg, *args, **kwargs):
    logger.debug(msg, *args, **kwargs)

def info(msg, *args, **kwargs):
    logger.info(msg, *args, **kwargs)

def warning(msg, *args, **kwargs):
    logger.warning(msg, *args, **kwargs)

def error(msg, *args, **kwargs):
    logger.error(msg, *args, **kwargs)

def critical(msg, *args, **kwargs):
    logger.critical(msg, *args, **kwargs)