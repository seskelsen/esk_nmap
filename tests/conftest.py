import pytest
import os
import sys
from src.core.history_manager import HistoryManager

# Adicionar o diretório raiz ao PYTHONPATH para que os imports funcionem
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

@pytest.fixture(autouse=True)
def mock_env_vars(monkeypatch):
    """Remove variáveis de ambiente que podem afetar os testes"""
    monkeypatch.delenv("PYTHONPATH", raising=False)
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)

@pytest.fixture(scope='module')
def history_manager():
    """Fixture para criar um HistoryManager com banco de dados em memória."""
    manager = HistoryManager(db_path=':memory:')
    manager._init_database()
    return manager