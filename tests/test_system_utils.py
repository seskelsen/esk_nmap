import pytest
import platform
import os
import subprocess
import shutil
from unittest.mock import patch, MagicMock
from src.utils.system_utils import SystemUtils

class TestSystemUtils:
    def test_is_command_available_exists(self):
        """Testa verificação de comando disponível no PATH"""
        with patch('shutil.which') as mock_which:
            mock_which.return_value = "/usr/bin/test"
            assert SystemUtils.is_command_available("test") == True
    
    def test_is_command_available_not_exists(self):
        """Testa verificação de comando não disponível"""
        with patch('shutil.which') as mock_which:
            mock_which.return_value = None
            assert SystemUtils.is_command_available("nonexistent") == False
    
    def test_find_nmap_windows_where_command(self, monkeypatch):
        """Testa localização do nmap no Windows usando where"""
        monkeypatch.setattr(platform, "system", lambda: "Windows")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = r"C:\Program Files (x86)\Nmap\nmap.exe"  # Removido \n
            assert SystemUtils.find_nmap_path() == r"C:\Program Files (x86)\Nmap\nmap.exe"
    
    def test_find_nmap_windows_program_files(self, monkeypatch):
        """Testa localização do nmap em Program Files no Windows"""
        monkeypatch.setattr(platform, "system", lambda: "Windows")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda x: x == r"c:\Program Files (x86)\Nmap\nmap.exe"
                assert SystemUtils.find_nmap_path() == r"c:\Program Files (x86)\Nmap\nmap.exe"
    
    def test_find_nmap_windows_fallback(self, monkeypatch):
        """Testa fallback quando nmap não é encontrado no Windows"""
        monkeypatch.setattr(platform, "system", lambda: "Windows")
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = Exception("Comando não encontrado")
            with patch("os.path.exists") as mock_exists:
                mock_exists.return_value = False
                assert SystemUtils.find_nmap_path() == "nmap"
    
    def test_find_nmap_unix_which_command(self, monkeypatch):
        """Testa localização do nmap no Unix usando which"""
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "/usr/bin/nmap\n"
            assert SystemUtils.find_nmap_path() == "/usr/bin/nmap"
    
    def test_find_nmap_unix_path_search(self, monkeypatch):
        """Testa localização do nmap em caminhos padrão do Unix"""
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda x: x == "/usr/local/bin/nmap"
                assert SystemUtils.find_nmap_path() == "/usr/local/bin/nmap"
    
    def test_find_nmap_unix_fallback(self, monkeypatch):
        """Testa fallback quando nmap não é encontrado no Unix"""
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = Exception("Comando não encontrado")
            with patch("os.path.exists") as mock_exists:
                mock_exists.return_value = False
                assert SystemUtils.find_nmap_path() == "nmap"
    
    def test_check_nmap_installed_absolute_path_exists(self):
        """Testa verificação de nmap instalado com caminho absoluto existente"""
        with patch("os.path.exists") as mock_exists:
            mock_exists.return_value = True
            assert SystemUtils.check_nmap_installed("/usr/bin/nmap") == True
    
    def test_check_nmap_installed_absolute_path_not_exists(self):
        """Testa verificação de nmap instalado com caminho absoluto inexistente"""
        with patch("os.path.exists") as mock_exists:
            mock_exists.return_value = False
            assert SystemUtils.check_nmap_installed("/usr/bin/nmap") == False
    
    def test_check_root_windows_success(self, monkeypatch):
        """Testa verificação de privilégios admin no Windows com sucesso"""
        monkeypatch.setattr(platform, "system", lambda: "Windows")
        with patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=1):
            assert SystemUtils.check_root() == True
    
    def test_check_root_windows_failure(self, monkeypatch):
        """Testa verificação de privilégios admin no Windows com falha"""
        monkeypatch.setattr(platform, "system", lambda: "Windows")
        with patch("ctypes.windll.shell32.IsUserAnAdmin", side_effect=Exception):
            assert SystemUtils.check_root() == False
    
    def test_check_root_unix(self, monkeypatch):
        """Testa verificação de root no Unix"""
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        if hasattr(os, 'geteuid'):
            with patch("os.geteuid") as mock_geteuid:
                mock_geteuid.return_value = 0
                assert SystemUtils.check_root() == True
                mock_geteuid.return_value = 1000
                assert SystemUtils.check_root() == False
    
    def test_check_permissions_windows_error(self, monkeypatch):
        """Testa verificação de permissões no Windows com erro"""
        monkeypatch.setattr(platform, "system", lambda: "Windows")
        with patch("ctypes.windll.shell32.IsUserAnAdmin", side_effect=Exception):
            result = SystemUtils.check_permissions("nmap")
            assert result[0] == False
            assert "Não foi possível verificar privilégios" in result[1]
    
    def test_check_permissions_unix_not_executable(self, monkeypatch):
        """Testa verificação de permissões no Unix com arquivo não executável"""
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        with patch("os.path.isabs") as mock_isabs:
            mock_isabs.return_value = True
            with patch("os.access") as mock_access:
                mock_access.return_value = False
                result = SystemUtils.check_permissions("/usr/bin/nmap")
                assert result[0] == False
                assert "não tem permissão de execução" in result[1]
    
    def test_check_permissions_unix_not_root(self, monkeypatch):
        """Testa verificação de permissões no Unix sem privilégios root"""
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        with patch("os.path.isabs") as mock_isabs:
            mock_isabs.return_value = True
            with patch("os.access") as mock_access:
                mock_access.return_value = True
                if hasattr(os, 'geteuid'):
                    with patch("os.geteuid") as mock_geteuid:
                        mock_geteuid.return_value = 1000
                        result = SystemUtils.check_permissions("/usr/bin/nmap")
                        assert result[0] == False
                        assert "privilégios de root" in result[1]
    
    def test_find_nmap_path_windows(self, monkeypatch):
        monkeypatch.setattr(platform, "system", lambda: "Windows")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = r"C:\Program Files (x86)\Nmap\nmap.exe"
            assert "nmap.exe" in SystemUtils.find_nmap_path()

    def test_find_nmap_path_unix(self, monkeypatch):
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "/usr/bin/nmap"
            assert "nmap" in SystemUtils.find_nmap_path()

    def test_check_nmap_installed_absolute_path(self, monkeypatch):
        with patch("os.path.exists") as mock_exists:
            mock_exists.return_value = True
            assert SystemUtils.check_nmap_installed("/usr/bin/nmap") == True

    def test_check_nmap_installed_command(self, monkeypatch):
        with patch("shutil.which") as mock_which:
            mock_which.return_value = "/usr/bin/nmap"
            assert SystemUtils.check_nmap_installed("nmap") == True
            mock_which.return_value = None
            assert SystemUtils.check_nmap_installed("nmap") == False

    @pytest.mark.parametrize("is_admin,expected", [
        (True, (True, "")),
        (False, (False, "AVISO: No Windows, privilégios de administrador são necessários para scan completo.")),
    ])
    def test_check_permissions_windows(self, monkeypatch, is_admin, expected):
        monkeypatch.setattr(platform, "system", lambda: "Windows")
        with patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=is_admin):
            assert SystemUtils.check_permissions("nmap") == expected

    def test_check_permissions_unix(self, monkeypatch):
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        
        # Mock os.geteuid apenas se não estivermos no Windows
        if hasattr(os, 'geteuid'):
            monkeypatch.setattr(os, "geteuid", lambda: 0)  # Simula root
        else:
            # No Windows, vamos simular o comportamento do Unix
            with patch.object(os, "access", return_value=True):
                with patch.object(os, "path") as mock_path:
                    mock_path.isabs.return_value = True
                    assert SystemUtils.check_permissions("/usr/bin/nmap") == (True, "")