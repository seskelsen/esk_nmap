#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ESK NMAP - Network Scanner Tool
Copyright (C) 2025 Eskel Cybersecurity
Author: Sigmar Eskelsen

Este módulo contém as classes e funções para realizar scans de rede.
"""

import subprocess
import re
import ipaddress
import time
import threading
from typing import Dict, List, Set, Optional
import platform
from tqdm import tqdm
from ..utils.logger import info, debug, error
from ..utils.config_manager import ConfigManager

class ScannerError(Exception):
    """Exceção para erros relacionados ao scanner de rede."""
    pass

class HostInfo:
    """Classe para armazenar informações de um host na rede."""
    
    def __init__(self, ip: str, hostname: str = "", mac: str = "", vendor: str = "", 
                 status: str = "up", ports: List[str] = None, services: List[str] = None):
        self.ip = ip
        self.hostname = hostname
        self.mac = mac
        self.vendor = vendor
        self.status = status
        self.ports = ports if ports is not None else []
        self.services = services if services is not None else []

class NetworkScanner:
    """Classe para realizar scans de rede usando o Nmap."""
    
    def __init__(self, nmap_path: str):
        """
        Inicializa o scanner com o caminho do Nmap.
        
        Args:
            nmap_path (str): Caminho para o executável do Nmap
        """
        self.nmap_path = nmap_path
        self._scan_profile = "basic"
        self.config_manager = ConfigManager()
        self.quiet_mode = False
    
    def set_quiet_mode(self, quiet: bool) -> None:
        """
        Define se o modo silencioso está ativo (sem barras de progresso).
        
        Args:
            quiet (bool): True para modo silencioso, False para exibir barras de progresso
        """
        self.quiet_mode = quiet
    
    def set_scan_profile(self, profile: str) -> None:
        """
        Define o perfil de scan a ser utilizado.
        
        Args:
            profile (str): Nome do perfil de scan
        """
        # Verifica se o perfil existe no ConfigManager
        if profile not in self.config_manager._config.get('scan_profiles', {}):
            raise ScannerError(f"Perfil de scan desconhecido: {profile}")
        self._scan_profile = profile
        debug(f"Perfil de scan definido: {profile}")
    
    def scan_network(self, network: str) -> Dict[str, HostInfo]:
        """
        Realiza um scan de rede para descoberta de hosts.
        
        Args:
            network (str): Endereço de rede a ser escaneado (ex: 192.168.1.0/24)
            
        Returns:
            Dict[str, HostInfo]: Dicionário de hosts encontrados
            
        Raises:
            ScannerError: Se ocorrer erro tanto no scan principal quanto no fallback
        """
        debug(f"Iniciando scan de rede em {network}")
        
        if self.quiet_mode:
            try:
                return self._discovery_scan(network)
            except Exception as e:
                error(f"Erro durante o scan de rede: {str(e)}")
                debug("Tentando método alternativo de descoberta")
                try:
                    return self._fallback_discovery(network)
                except Exception as e2:
                    raise ScannerError("Both discovery methods failed") from e2
        
        # Se não estiver em modo silencioso, usa barra de progresso
        with tqdm(total=100, desc=f"Descobrindo hosts em {network}") as pbar:
            try:
                scan_result = None
                scan_error = None
                
                def run_scan():
                    nonlocal scan_result, scan_error
                    try:
                        scan_result = self._discovery_scan(network)
                    except Exception as e:
                        scan_error = e
                
                scan_thread = threading.Thread(target=run_scan)
                scan_thread.start()
                
                progress = 0
                while scan_thread.is_alive() and progress < 95:
                    time.sleep(0.1)
                    progress += 1
                    pbar.update(1)
                
                scan_thread.join()
                pbar.update(100 - progress)
                
                if scan_error:
                    error(f"Erro durante o scan de rede: {str(scan_error)}")
                    debug("Tentando método alternativo de descoberta")
                    try:
                        return self._fallback_discovery(network)
                    except Exception as e:
                        raise ScannerError("Both discovery methods failed") from e
                
                return scan_result
            except Exception as e:
                if isinstance(e, ScannerError):
                    raise
                error(f"Erro durante o scan de rede: {str(e)}")
                debug("Tentando método alternativo de descoberta")
                try:
                    return self._fallback_discovery(network)
                except Exception as e2:
                    raise ScannerError("Both discovery methods failed") from e2
    
    def _discovery_scan(self, network: str) -> Dict[str, HostInfo]:
        """
        Realiza um scan de descoberta usando o Nmap.
        
        Args:
            network (str): Rede a ser escaneada
            
        Returns:
            Dict[str, HostInfo]: Hosts descobertos
        """
        # Obtém as opções do perfil de scan atual
        profile = self.config_manager.get_scan_profile(self._scan_profile)
        debug(f"Usando perfil: {profile['name']}")
        
        # Monta o comando base
        cmd = [self.nmap_path]
        
        # Adiciona as opções do perfil se for um scan de descoberta
        if "-sn" in profile['options'] or profile['options'] == ["-sn"]:
            cmd.extend(profile['options'])
        else:
            # Se o perfil não incluir -sn, forçamos apenas para a descoberta
            cmd.append("-sn")
        
        # Adiciona o alvo
        cmd.append(network)
        
        debug(f"Executando comando: {' '.join(cmd)}")
        
        timeout = self.config_manager.get_timeout('discovery')
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output, _ = process.communicate(timeout=timeout)
        
        if process.returncode != 0:
            raise ScannerError(f"Nmap retornou código de saída {process.returncode}")
        
        return self._parse_discovery_output(output)
    
    def _parse_discovery_output(self, output: str) -> Dict[str, HostInfo]:
        """Analisa a saída do scan de descoberta do Nmap."""
        hosts = {}
        current_ip = None
        current_host = None
        
        for line in output.splitlines():
            line = line.strip()
            
            # Procura por IP e hostname
            if "Nmap scan report for" in line:
                parts = line.replace("Nmap scan report for", "").strip().split()
                
                # Extrai IP e hostname
                if "(" in line and ")" in line:
                    # Formato: hostname (IP)
                    hostname = " ".join(parts[:-1])
                    ip = parts[-1].strip("()")
                else:
                    # Formato: IP ou hostname
                    ip = parts[0]
                    hostname = " ".join(parts[1:]) if len(parts) > 1 else ""
                
                current_ip = ip
                current_host = HostInfo(ip=ip, hostname=hostname)
                hosts[current_ip] = current_host
                continue
            
            # Procura por MAC e vendor
            if "MAC Address:" in line:
                parts = line.replace("MAC Address:", "").strip().split("(", 1)
                if len(parts) >= 1:
                    mac = parts[0].strip()
                    vendor = parts[1].strip(")").strip() if len(parts) > 1 else ""
                    if current_host:
                        current_host.mac = mac
                        current_host.vendor = vendor
        
        return hosts

    def _parse_detailed_output(self, output: str, results: Dict[str, HostInfo]) -> None:
        """Analisa a saída detalhada do scan do Nmap."""
        current_ip = None
        
        for line in output.splitlines():
            line = line.strip()
            
            if "Nmap scan report for" in line:
                parts = line.replace("Nmap scan report for", "").strip().split()
                
                if "(" in line and ")" in line:
                    hostname = " ".join(parts[:-1])
                    ip = parts[-1].strip("()")
                else:
                    ip = parts[0]
                    hostname = " ".join(parts[1:]) if len(parts) > 1 else ""
                
                current_ip = ip
                if current_ip not in results:
                    results[current_ip] = HostInfo(ip=current_ip, hostname=hostname)
                elif hostname and not results[current_ip].hostname:
                    results[current_ip].hostname = hostname
                continue
            
            if current_ip and "/tcp" in line and "open" in line:
                parts = line.split(None, 3)  # Split by whitespace into max 4 parts
                if len(parts) >= 3:
                    port = parts[0]
                    state = parts[1]
                    service = parts[2]
                    version = parts[3].strip() if len(parts) > 3 else ""
                    
                    if current_ip in results:
                        if port not in results[current_ip].ports:
                            results[current_ip].ports.append(port)
                        
                        # Format service string
                        service_str = service
                        if version:
                            service_str = f"{service} ({version})"
                        
                        if service_str not in results[current_ip].services:
                            results[current_ip].services.append(service_str)

    def _fallback_discovery(self, network: str) -> Dict[str, HostInfo]:
        """
        Método alternativo de descoberta de hosts quando o Nmap falha.
        
        Args:
            network (str): Rede a ser escaneada
            
        Returns:
            Dict[str, HostInfo]: Hosts descobertos
        """
        if platform.system() == "Windows":
            return self._windows_discovery(network)
        else:
            return self._unix_discovery(network)
    
    def _windows_discovery(self, network: str) -> Dict[str, HostInfo]:
        """Executa descoberta de hosts no Windows usando ping e ARP."""
        hosts = {}
        network_obj = ipaddress.ip_network(network)

        debug(f"Descobrindo hosts na rede {network}")
        
        # Single ping sweep first
        subprocess.run(['ping', '-n', '1', '-w', '500', str(next(network_obj.hosts()))],
                     stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)
        
        # Obtém a tabela ARP
        debug("Analisando respostas ARP...")
        arp_output = subprocess.run(['arp', '-a'], capture_output=True, text=True).stdout
        
        # Processa a saída do ARP
        current_ip = None
        for line in arp_output.splitlines():
            line = line.strip()
            if line.startswith('Interface:'):
                current_ip = line.split()[1]
                continue
                
            if line and not line.startswith('Internet') and 'dynamic' in line.lower():
                parts = [p for p in line.split() if p]
                if len(parts) >= 2:
                    ip = parts[0]
                    try:
                        if ipaddress.ip_address(ip) in network_obj:
                            mac = parts[1].replace('-', ':')
                            hosts[ip] = HostInfo(ip=ip, mac=mac)
                    except ValueError:
                        continue  # Ignora IPs inválidos
        
        return hosts

    def _unix_discovery(self, network: str) -> Dict[str, HostInfo]:
        """
        Descoberta de hosts em sistemas Unix usando comandos alternativos.
        
        Args:
            network (str): Rede a ser escaneada
            
        Returns:
            Dict[str, HostInfo]: Hosts descobertos
        """
        hosts = {}
        try:
            # Usa uma versão simplificada do comando nmap
            if not self.quiet_mode:
                print("Executando scan de descoberta alternativo...")
                
            output = subprocess.run(
                [self.nmap_path, "-sn", "-n", network],
                stdout=subprocess.PIPE, text=True, check=False
            ).stdout
            
            # Analisa a saída do nmap
            current_ip = None
            
            ip_regex = re.compile(r"Nmap scan report for (?:([^\s]+) )?(?:\()?(\d+\.\d+\.\d+\.\d+)(?:\))?")
            mac_regex = re.compile(r"MAC Address: ([0-9A-F:]+) \(([^)]+)\)")
            
            for line in output.splitlines():
                ip_match = ip_regex.search(line)
                if ip_match:
                    hostname = ip_match.group(1) or ""
                    ip = ip_match.group(2)
                    current_ip = ip
                    hosts[current_ip] = HostInfo(ip=ip, hostname=hostname)
                    continue
                
                mac_match = mac_regex.search(line)
                if mac_match and current_ip and current_ip in hosts:
                    hosts[current_ip].mac = mac_match.group(1)
                    hosts[current_ip].vendor = mac_match.group(2)
            
        except Exception as e:
            debug(f"Erro no scan Unix alternativo: {str(e)}")
        
        return hosts
    
    def detailed_scan(self, target_ips: Set[str]) -> Dict[str, HostInfo]:
        """Executa um scan detalhado nos hosts especificados."""
        debug(f"Iniciando scan detalhado de {len(target_ips)} hosts")
        
        # Obtém informações iniciais dos hosts
        initial_hosts = self._discovery_scan(", ".join(target_ips))
        results = initial_hosts.copy()  # Preserva as informações iniciais
        
        # Prepara as portas comuns para scan
        profile = self.config_manager.get_scan_profile(self._scan_profile)
        ports = profile.get('ports', '')
        timeout = self.config_manager.get_timeout('port_scan')
        
        # Garante que portas comuns importantes estejam incluídas
        common_ports = ["22", "23", "80", "443", "3389"]
        if not ports:
            ports = ",".join(common_ports)
        else:
            # Adiciona portas que não estão no perfil
            current_ports = set(ports.split(","))
            missing_ports = [p for p in common_ports if p not in current_ports]
            if missing_ports:
                ports = f"{ports},{','.join(missing_ports)}"
        
        with tqdm(total=100, desc=f"Escaneando portas em {len(target_ips)} host(s)") as pbar:
            try:
                cmd = [
                    self.nmap_path,
                    '-p', ports,
                    '-sV',  # Detecção de versão
                    f'-T{profile["timing"]}',
                ] + list(target_ips)
                
                debug(f"Executando comando: {' '.join(cmd)}")
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                output, error = process.communicate(timeout=timeout)
                if process.returncode != 0:
                    raise ScannerError(f"Erro no scan detalhado: {error}")
                
                self._parse_detailed_output(output, results)
                pbar.update(100)
                
            except subprocess.TimeoutExpired:
                process.kill()
                raise
            except Exception as e:
                error(f"Erro durante o scan detalhado: {str(e)}")
                raise
        
        return results
