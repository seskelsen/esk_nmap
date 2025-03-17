import os
import platform
import subprocess
import shutil
import ctypes
from typing import Optional

class SystemUtils:
    @staticmethod
    def is_command_available(command: str) -> bool:
        """Verifica se um comando está disponível no PATH do sistema"""
        return shutil.which(command) is not None

    @staticmethod
    def find_nmap_path() -> str:
        """Localiza o caminho do executável do Nmap no sistema"""
        if platform.system() == "Windows":
            return SystemUtils._find_nmap_windows()
        return SystemUtils._find_nmap_unix()

    @staticmethod
    def _find_nmap_windows() -> str:
        """Localiza o Nmap no Windows"""
        try:
            result = subprocess.run(['where', 'nmap'], capture_output=True, text=True, check=False)
            if result.returncode == 0:
                return result.stdout.strip().split('\n')[0].strip()
            
            windows_paths = [
                r"c:\Program Files (x86)\Nmap\nmap.exe",
                r"c:\Program Files\Nmap\nmap.exe"
            ]
            for path in windows_paths:
                if os.path.exists(path):
                    return path
        except Exception:
            pass
        return "nmap"

    @staticmethod
    def _find_nmap_unix() -> str:
        """Localiza o Nmap em sistemas Unix-like"""
        try:
            result = subprocess.run(['which', 'nmap'], capture_output=True, text=True, check=False)
            if result.returncode == 0:
                return result.stdout.strip()
            
            unix_paths = [
                "/usr/bin/nmap",
                "/usr/local/bin/nmap",
                "/bin/nmap",
                "/opt/nmap/bin/nmap"
            ]
            for path in unix_paths:
                if os.path.exists(path):
                    return path
        except Exception:
            pass
        return "nmap"

    @staticmethod
    def check_nmap_installed(nmap_path: str) -> bool:
        """Verifica se o Nmap está instalado"""
        if os.path.isabs(nmap_path):
            return os.path.exists(nmap_path)
        return shutil.which('nmap') is not None

    @staticmethod
    def check_root() -> bool:
        """Verifica se o programa está sendo executado com privilégios elevados"""
        if platform.system() == "Windows":
            try:
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except:
                return False
        else:
            # Em sistemas Unix, verifica se é root (UID 0)
            return os.geteuid() == 0 if hasattr(os, 'geteuid') else False

    @staticmethod
    def check_permissions(nmap_path: str) -> tuple[bool, str]:
        """Verifica permissões do Nmap e retorna (tem_permissao, mensagem)"""
        if platform.system() == "Windows":
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if not is_admin:
                    return False, "AVISO: No Windows, privilégios de administrador são necessários para scan completo."
            except:
                return False, "AVISO: Não foi possível verificar privilégios de administrador."
            return True, ""
            
        if not os.path.isabs(nmap_path):
            return True, ""
            
        if not os.access(nmap_path, os.X_OK):
            return False, f"Aviso: {nmap_path} não tem permissão de execução."
            
        # Verificação de root apenas em sistemas Unix
        if hasattr(os, 'geteuid') and os.geteuid() != 0:
            return False, "Aviso: Alguns tipos de scan do Nmap podem exigir privilégios de root."
            
        return True, ""