import pytest
import os
import sys

# Adicionar o diretório raiz ao PYTHONPATH para que os imports funcionem
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

@pytest.fixture(autouse=True)
def mock_env_vars(monkeypatch):
    """Remove variáveis de ambiente que podem afetar os testes"""
    monkeypatch.delenv("PYTHONPATH", raising=False)
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)