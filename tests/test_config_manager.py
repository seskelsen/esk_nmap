import os
import pytest
import yaml
import threading
import tempfile
from src.utils.config_manager import ConfigManager

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

def test_singleton_thread_safety():
    """Testa se o singleton é thread-safe"""
    instances = []
    def create_instance():
        instances.append(ConfigManager())
    
    threads = [threading.Thread(target=create_instance) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    # Verifica se todas as instâncias são a mesma
    first = instances[0]
    for inst in instances[1:]:
        assert inst is first

def test_load_default_config(config_manager):
    """Testa se as configurações padrão são carregadas corretamente"""
    config = config_manager._config
    assert 'scan_profiles' in config
    assert 'basic' in config['scan_profiles']
    assert 'timeouts' in config
    assert 'retry' in config
    assert 'reporting' in config

def test_invalid_yaml_config():
    """Testa o comportamento com arquivo YAML inválido"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as tmp:
        tmp.write("invalid: yaml: content:")  # YAML inválido
        tmp.flush()
        
        manager = ConfigManager(tmp.name)
        # Deve carregar as configurações padrão
        assert 'basic' in manager._config['scan_profiles']
        assert manager.get_timeout('discovery') == 180

def test_all_default_scan_profiles(config_manager):
    """Testa se todos os perfis de scan padrão estão presentes e corretos"""
    profiles = ['basic', 'stealth', 'version', 'complete']
    for profile_name in profiles:
        profile = config_manager.get_scan_profile(profile_name)
        assert profile is not None
        assert 'name' in profile
        assert 'description' in profile
        assert 'options' in profile
        assert 'ports' in profile
        assert 'timing' in profile

def test_merge_config_sections():
    """Testa se o merge de configurações preserva valores customizados"""
    custom_config = {
        'timeouts': {
            'discovery': 300,  # Valor customizado
            'new_timeout': 60  # Novo timeout
        }
    }
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as tmp:
        yaml.dump(custom_config, tmp)
        tmp.flush()
        
        manager = ConfigManager(tmp.name)
        assert manager.get_timeout('discovery') == 300  # Valor customizado
        assert manager.get_timeout('port_scan') == 300  # Valor padrão mantido
        assert manager.get_timeout('new_timeout') == 60  # Novo valor adicionado

def test_empty_config_file():
    """Testa o comportamento com arquivo de configuração vazio"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as tmp:
        tmp.write("")  # Arquivo vazio
        tmp.flush()
        
        manager = ConfigManager(tmp.name)
        # Deve carregar todas as configurações padrão
        assert manager._config is not None
        assert 'scan_profiles' in manager._config
        assert 'timeouts' in manager._config
        assert 'retry' in manager._config
        assert 'reporting' in manager._config

def test_nonexistent_config_file():
    """Testa o comportamento com arquivo de configuração inexistente"""
    nonexistent_path = "/path/that/does/not/exist.yaml"
    manager = ConfigManager(nonexistent_path)
    # Deve carregar configurações padrão
    assert manager._config is not None
    assert manager.get_scan_profile('basic') is not None

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
    
    manager = ConfigManager(str(config_file))
    
    assert 'test' in manager._config['scan_profiles']
    assert 'basic' in manager._config['scan_profiles']
    
    profile = manager.get_scan_profile('test')
    assert profile['name'] == 'Test Profile'
    assert profile['ports'] == '80'
    
    assert 'timeouts' in manager._config
    assert 'retry' in manager._config
    assert 'reporting' in manager._config

def test_reload_config_with_new_path():
    """Testa se a configuração é recarregada quando muda o caminho"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as tmp1:
        yaml.dump({'timeouts': {'discovery': 100}}, tmp1)
        tmp1.flush()
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as tmp2:
            yaml.dump({'timeouts': {'discovery': 200}}, tmp2)
            tmp2.flush()
            
            manager = ConfigManager(tmp1.name)
            assert manager.get_timeout('discovery') == 100
            
            # Deve recarregar com novo valor
            manager = ConfigManager(tmp2.name)
            assert manager.get_timeout('discovery') == 200

def test_config_merge_with_invalid_section():
    """Testa o merge de configurações com uma seção inválida"""
    custom_config = {
        'invalid_section': {
            'some_value': 123
        }
    }
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as tmp:
        yaml.dump(custom_config, tmp)
        tmp.flush()
        
        manager = ConfigManager(tmp.name)
        # Deve manter as seções padrão mesmo com seção inválida
        assert 'scan_profiles' in manager._config
        assert 'timeouts' in manager._config
        assert 'retry' in manager._config
        assert 'reporting' in manager._config
        # A seção inválida deve ser mantida
        assert 'invalid_section' in manager._config

def test_config_with_empty_sections():
    """Testa o comportamento com seções vazias"""
    custom_config = {
        'scan_profiles': {},
        'timeouts': {},
        'retry': {},
        'reporting': {}
    }
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as tmp:
        yaml.dump(custom_config, tmp)
        tmp.flush()
        
        manager = ConfigManager(tmp.name)
        # Deve usar valores padrão para seções vazias
        assert manager.get_timeout('discovery') == 180
        assert manager.get_retry_config()['max_attempts'] == 3
        assert manager.get_reporting_config()['format'] == 'text'
        
        # Deve ter o perfil básico mesmo com scan_profiles vazio
        profile = manager.get_scan_profile('basic')
        assert profile is not None
        assert profile['name'] == 'Scan Básico'

def test_config_with_invalid_yaml_syntax():
    """Testa o comportamento com sintaxe YAML inválida"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as tmp:
        tmp.write("""
        scan_profiles:
          basic:
            name: 'Test
            description: Invalid YAML
        """)
        tmp.flush()
        
        manager = ConfigManager(tmp.name)
        # Deve usar configuração padrão quando YAML é inválido
        assert manager.get_scan_profile('basic')['name'] == 'Scan Básico'
        assert manager.get_timeout('discovery') == 180