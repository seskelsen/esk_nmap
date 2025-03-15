import os
import yaml
from typing import Dict, Any, Optional
from ..utils.logger import info, error, debug

class ConfigManager:
    """Gerenciador de configurações do ESK_NMAP"""
    _instance = None
    _config = None
    _config_path = None
    
    def __new__(cls, config_path: Optional[str] = None):
        if cls._instance is None:
            cls._instance = super(ConfigManager, cls).__new__(cls)
            cls._instance._config = None
            cls._instance._config_path = None
        return cls._instance
    
    def __init__(self, config_path: Optional[str] = None):
        if config_path:
            self._config_path = config_path
            self._config = None  # Força recarregamento se o caminho mudou
        elif not self._config_path:
            self._config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'config.yaml')
        
        if self._config is None:
            self._load_config()
    
    def _load_config(self):
        """Carrega as configurações do arquivo YAML"""
        try:
            if os.path.exists(self._config_path):
                with open(self._config_path, 'r', encoding='utf-8') as f:
                    self._config = yaml.safe_load(f)
                debug(f"Configurações carregadas com sucesso de {self._config_path}")
            else:
                info("Arquivo de configuração não encontrado. Usando configurações padrão.")
                self._config = self._get_default_config()
                
            # Garante que todas as seções necessárias existem
            if not self._config:
                self._config = {}
            
            # Merge com as configurações padrão para garantir que todos os campos existam
            default_config = self._get_default_config()
            for section in ['scan_profiles', 'timeouts', 'retry', 'reporting']:
                if section not in self._config:
                    self._config[section] = default_config[section]
                elif isinstance(self._config[section], dict):
                    # Preserva os valores customizados mas garante que todos os campos padrão existam
                    merged = default_config[section].copy()
                    merged.update(self._config[section])
                    self._config[section] = merged
                
        except Exception as e:
            error(f"Erro ao carregar configurações: {str(e)}")
            self._config = self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Retorna as configurações padrão"""
        return {
            'scan_profiles': {
                'basic': {
                    'name': 'Scan Básico',
                    'description': 'Scan rápido para visão geral da rede',
                    'options': ['-T4', '-sn', '-n'],
                    'ports': '21-23,25,53,80,443,3306,3389',
                    'timing': 4
                },
                'stealth': {
                    'name': 'Scan Silencioso',
                    'description': 'Scan mais discreto usando SYN stealth',
                    'options': ['-sS', '-T2', '-n'],
                    'ports': '21-23,25,53,80,443,3306,3389',
                    'timing': 2
                },
                'version': {
                    'name': 'Scan com Detecção de Versão',
                    'description': 'Scan com identificação de serviços',
                    'options': ['-sV', '-T4', '-n'],
                    'ports': '21-23,25,53,80,443,3306,3389,8080',
                    'timing': 4
                },
                'complete': {
                    'name': 'Scan Completo',
                    'description': 'Scan detalhado com scripts NSE',
                    'options': ['-sV', '-sC', '-O', '-T4', '-n'],
                    'ports': '1-1024,3306,3389,5432,8080,8443',
                    'timing': 4
                }
            },
            'timeouts': {
                'discovery': 180,
                'port_scan': 300,
                'version_scan': 120
            },
            'retry': {
                'max_attempts': 3,
                'delay_between_attempts': 5
            },
            'reporting': {
                'format': 'text',
                'include_closed_ports': False,
                'group_by_port': True
            }
        }
    
    def get_scan_profile(self, profile_name: str) -> Dict[str, Any]:
        """Retorna as configurações de um perfil específico"""
        if self._config is None:
            self._load_config()
        profiles = self._config.get('scan_profiles', {})
        return profiles.get(profile_name, profiles.get('basic'))
    
    def get_timeout(self, operation: str) -> int:
        """Retorna o timeout configurado para uma operação"""
        if self._config is None:
            self._load_config()
        return self._config.get('timeouts', {}).get(operation, 60)
    
    def get_retry_config(self) -> Dict[str, int]:
        """Retorna as configurações de retry"""
        if self._config is None:
            self._load_config()
        return self._config.get('retry', {
            'max_attempts': 3,
            'delay_between_attempts': 5
        })
    
    def get_reporting_config(self) -> Dict[str, Any]:
        """Retorna as configurações de relatório"""
        if self._config is None:
            self._load_config()
        return self._config.get('reporting', {
            'format': 'text',
            'include_closed_ports': False,
            'group_by_port': True
        })