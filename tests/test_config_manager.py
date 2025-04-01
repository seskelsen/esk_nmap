import os
import pytest
import tempfile
import yaml
from src.utils.config_manager import ConfigManager

@pytest.fixture
def config_manager():
    """Fixture que retorna uma instância limpa do ConfigManager"""
    # Reset do singleton para cada teste
    ConfigManager._instance = None
    return ConfigManager()

def test_singleton_pattern():
    """Testa se o ConfigManager segue o padrão singleton"""
    ConfigManager._instance = None  # Reset do singleton
    manager1 = ConfigManager()
    manager2 = ConfigManager()
    assert manager1 is manager2
    assert id(manager1) == id(manager2)

def test_load_default_config(config_manager):
    """Testa se as configurações padrão são carregadas corretamente"""
    config = config_manager._config
    assert 'scan_profiles' in config
    assert 'basic' in config['scan_profiles']
    assert 'timeouts' in config
    assert 'retry' in config
    assert 'reporting' in config

def test_get_scan_profile_existing(config_manager):
    """Testa se retorna um perfil de scan existente"""
    profile = config_manager.get_scan_profile('basic')
    assert profile is not None
    assert profile['name'] == 'Scan Básico'
    assert isinstance(profile['options'], list)
    assert isinstance(profile['ports'], str)

def test_get_scan_profile_nonexistent(config_manager):
    """Testa se retorna o perfil básico quando solicita um perfil inexistente"""
    profile = config_manager.get_scan_profile('nonexistent')
    assert profile is not None
    assert profile['name'] == 'Scan Básico'

def test_get_timeout(config_manager):
    """Testa se retorna o timeout correto para uma operação"""
    timeout = config_manager.get_timeout('discovery')
    assert isinstance(timeout, int)
    assert timeout > 0

def test_get_timeout_default(config_manager):
    """Testa se retorna o timeout padrão para operação inexistente"""
    timeout = config_manager.get_timeout('nonexistent')
    assert timeout == 60

def test_get_retry_config(config_manager):
    """Testa se retorna as configurações de retry"""
    retry_config = config_manager.get_retry_config()
    assert 'max_attempts' in retry_config
    assert 'delay_between_attempts' in retry_config
    assert retry_config['max_attempts'] >= 1
    assert retry_config['delay_between_attempts'] >= 0

def test_get_reporting_config(config_manager):
    """Testa se retorna as configurações de relatório"""
    report_config = config_manager.get_reporting_config()
    assert 'format' in report_config
    assert 'include_closed_ports' in report_config
    assert 'group_by_port' in report_config

def test_custom_config_file():
    """Testa se carrega corretamente um arquivo de configuração customizado"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as tmp:
        # Cria um arquivo de configuração temporário
        custom_config = {
            'scan_profiles': {
                'test': {
                    'name': 'Test Profile',
                    'description': 'Profile for testing',
                    'options': ['-T4'],
                    'ports': '80',
                    'timing': 4
                }
            }
        }
        yaml.dump(custom_config, tmp)
        tmp_path = tmp.name
    
    try:
        # Usa o arquivo temporário como configuração
        ConfigManager._instance = None  # Reset do singleton
        manager = ConfigManager(tmp_path)
        
        # Verifica se o perfil customizado foi carregado
        assert 'test' in manager._config['scan_profiles']
        profile = manager.get_scan_profile('test')
        assert profile['name'] == 'Test Profile'
        assert profile['ports'] == '80'
    finally:
        # Limpa o arquivo temporário
        os.unlink(tmp_path)

def test_invalid_yaml_config():
    """Testa o comportamento com arquivo YAML inválido"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as tmp:
        # Cria um arquivo YAML inválido
        tmp.write("invalid: yaml: content:")
        tmp_path = tmp.name
    
    try:
        # Usa o arquivo inválido como configuração
        ConfigManager._instance = None  # Reset do singleton
        manager = ConfigManager(tmp_path)
        
        # Deve carregar as configurações padrão em caso de erro
        assert 'basic' in manager._config['scan_profiles']
    finally:
        # Limpa o arquivo temporário
        os.unlink(tmp_path)

def test_is_running_as_root():
    """Testa a verificação de privilégios de administrador"""
    # Apenas verificamos se a função executa sem erros
    ConfigManager._instance = None  # Reset do singleton
    manager = ConfigManager()
    # O resultado depende do ambiente, então apenas verificamos o tipo
    assert isinstance(manager.is_running_as_root(), bool)