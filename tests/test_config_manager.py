import os
import pytest
import yaml

@pytest.fixture
def config_manager():
    """Fixture que retorna uma instância limpa do ConfigManager"""
    ConfigManager._instance = None  # Reset singleton
    manager = ConfigManager()  # Cria nova instância que já carrega configuração padrão
    return manager

def test_singleton_pattern():
    """Testa se o ConfigManager segue o padrão singleton"""
    manager1 = ConfigManager()
    manager2 = ConfigManager()
    assert manager1 is manager2

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
    assert timeout == 180

def test_get_timeout_default(config_manager):
    """Testa se retorna o timeout padrão para operação inexistente"""
    timeout = config_manager.get_timeout('nonexistent')
    assert timeout == 60

def test_get_retry_config(config_manager):
    """Testa se retorna as configurações de retry"""
    retry_config = config_manager.get_retry_config()
    assert retry_config['max_attempts'] == 3
    assert retry_config['delay_between_attempts'] == 5

def test_get_reporting_config(config_manager):
    """Testa se retorna as configurações de relatório"""
    report_config = config_manager.get_reporting_config()
    assert report_config['format'] == 'text'
    assert not report_config['include_closed_ports']
    assert report_config['group_by_port']

def test_custom_config_file(tmp_path):
    """Testa se carrega corretamente um arquivo de configuração customizado"""
    # Cria um arquivo de configuração temporário
    config_file = tmp_path / "config.yaml"
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
    
    with open(config_file, 'w', encoding='utf-8') as f:
        yaml.dump(custom_config, f)
    
    # Instancia o ConfigManager com o arquivo customizado
    manager = ConfigManager(str(config_file))
    
    # Verifica se o perfil customizado foi carregado e mesclado com os padrões
    assert 'test' in manager._config['scan_profiles']
    assert 'basic' in manager._config['scan_profiles']  # Perfil padrão ainda existe
    
    profile = manager.get_scan_profile('test')
    assert profile['name'] == 'Test Profile'
    assert profile['ports'] == '80'
    
    # Verifica se as outras seções padrão foram mantidas
    assert 'timeouts' in manager._config
    assert 'retry' in manager._config
    assert 'reporting' in manager._config