import pytest
import platform
import os
from unittest.mock import patch, MagicMock
from src.utils.system_utils import SystemUtils

class TestSystemUtils:
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