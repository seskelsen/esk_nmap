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
from dataclasses import dataclass, field

class ScannerError(Exception):
    """Exceção para erros relacionados ao scanner de rede."""
    pass

class HostInfo:
    """Class representing information about a discovered host."""
    
    def __init__(self, ip: str, hostname: str = "", mac: str = "", vendor: str = "", 
                 ports: List[Dict] = None, is_up: bool = False, status: str = None):
        self.ip = ip
        self.hostname = hostname if hostname else "N/A"
        self.mac = mac if mac else "N/A"
        self.vendor = vendor if vendor else "N/A"
        self.ports = ports if ports is not None else []
        self._is_up = is_up
        self._status = status

    @property
    def status(self) -> str:
        """Returns the status of the host"""
        if self._status:
            return self._status
        return "up" if self._is_up else "down"

    @status.setter
    def status(self, value: str):
        """Sets the status of the host"""
        self._status = value
        self._is_up = (value.lower() == "up")

    @property
    def is_up(self) -> bool:
        """Returns whether the host is up"""
        return self._is_up

    @is_up.setter
    def is_up(self, value: bool):
        """Sets whether the host is up"""
        self._is_up = value
        if value:
            self._status = "up"
        else:
            self._status = "down"

    @property
    def services(self) -> List[str]:
        """Returns list of services from open ports"""
        return [port.get('service', 'unknown') for port in self.ports if port.get('state', '').lower() == 'open']

    def __str__(self) -> str:
        parts = [f"Host: {self.ip}"]
        if self.hostname != "N/A":
            parts.append(f"Hostname: {self.hostname}")
        if self.mac != "N/A":
            parts.append(f"MAC: {self.mac}")
        if self.vendor != "N/A":
            parts.append(f"Vendor: {self.vendor}")
        parts.append(f"Status: {self.status}")
        if self.ports:
            parts.append("Open ports:")
            for port in self.ports:
                port_str = f"  {port['port']}/{port.get('protocol', 'tcp')} - {port.get('service', 'unknown')}"
                if 'version' in port:
                    port_str += f" {port['version']}"
                parts.append(port_str)
        return "\n".join(parts)

@dataclass
class NetworkScanner:
    """Class responsible for network scanning operations."""
    
    network_range: str = ""
    verbosity: int = 0
    _nmap_path: str = field(default_factory=lambda: "nmap")
    _scan_profile: str = "basic"
    _quiet_mode: bool = False
    _config_manager: ConfigManager = field(default_factory=ConfigManager)
    _batch_size: int = 3  # Reduzido para 3 hosts por grupo
    
    def set_scan_profile(self, profile: str = "basic"):
        """Set the scan profile to use for scanning operations."""
        valid_profiles = self._config_manager._config.get('scan_profiles', {}).keys()
        if profile not in valid_profiles:
            profile = "basic"
        self._scan_profile = profile
    
    def set_quiet_mode(self, quiet: bool):
        """Set quiet mode for the scanner."""
        self._quiet_mode = quiet
        
    def _get_scan_options(self) -> List[str]:
        """Get nmap options based on the current scan profile."""
        profile_config = self._config_manager.get_scan_profile(self._scan_profile)
        options = profile_config.get('options', ['-sS', '--top-ports', '100'])  # Default to basic scan options
        
        if self.verbosity > 0:
            options.append("-v")
        return options

    def scan_network(self, network: str) -> Dict[str, HostInfo]:
        """Perform initial network scan to discover hosts."""
        self._validate_network_range(network)

        # Cria uma barra de progresso simulada para o scan inicial
        with tqdm(total=10, disable=self._quiet_mode, 
                 desc="Descobrindo hosts na rede", 
                 unit="", ncols=80,
                 bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}') as progress_bar:
            try:
                cmd = [self._nmap_path, "-sn", network]  # Host discovery only
                if self.verbosity > 0:
                    cmd.append("-v")
                
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )

                # Atualiza a barra enquanto o scan está em andamento
                while process.poll() is None:
                    progress_bar.n = min(progress_bar.n + 0.1, progress_bar.total - 0.5)
                    progress_bar.refresh()
                    time.sleep(0.1)

                stdout, stderr = process.communicate()
                
                if process.returncode != 0:
                    error(f"Erro no scan inicial: {stderr}")
                    raise ScannerError(f"Erro no scan de descoberta: {stderr}")

                progress_bar.n = progress_bar.total
                progress_bar.refresh()
                
                return self._parse_nmap_output(stdout)

            except subprocess.TimeoutExpired:
                error("Timeout durante scan inicial")
                raise ScannerError("Timeout durante scan de descoberta")
            except Exception as e:
                error(f"Erro durante scan inicial: {str(e)}")
                raise ScannerError(f"Erro durante scan de descoberta: {str(e)}")
            finally:
                progress_bar.close()

    def detailed_scan(self, targets: Dict[str, HostInfo]) -> Dict[str, HostInfo]:
        """Perform a detailed scan of discovered hosts using the current profile."""
        if not targets:
            return {}
            
        results = {}
        ip_list = list(targets.keys())
        total_batches = (len(ip_list) + self._batch_size - 1) // self._batch_size
        retry_config = self._config_manager.get_retry_config()

        # Cria barra de progresso para o scan detalhado
        with tqdm(total=len(ip_list), disable=self._quiet_mode,
                 desc="Escaneando hosts", unit="host",
                 ncols=80, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} hosts') as progress_bar:

            for i in range(0, len(ip_list), self._batch_size):
                batch = ip_list[i:i + self._batch_size]
                batch_num = (i // self._batch_size) + 1
                
                if not self._quiet_mode:
                    info(f"Escaneando grupo {batch_num}/{total_batches} ({len(batch)} hosts)")
                
                timeout = self._config_manager.get_timeout('port_scan')
                if self._scan_profile in ['version', 'complete']:
                    timeout = max(timeout, self._config_manager.get_timeout('version_scan'))
                
                cmd = [self._nmap_path] + self._get_scan_options()
                cmd.extend(batch)

                attempt = 1
                success = False
                last_error = None
                
                while attempt <= retry_config['max_attempts'] and not success:
                    try:
                        if attempt > 1 and not self._quiet_mode:
                            info(f"Tentativa {attempt}/{retry_config['max_attempts']} para o grupo {batch_num}")
                        
                        result = subprocess.run(
                            cmd, 
                            capture_output=True, 
                            text=True, 
                            check=True, 
                            timeout=timeout
                        )
                        
                        scan_results = self._parse_nmap_output(result.stdout)
                        
                        # Processa os resultados mantendo as informações originais
                        for ip in batch:
                            if ip in scan_results:
                                # Preserva informações existentes e atualiza com novos dados
                                scan_results[ip].hostname = targets[ip].hostname or scan_results[ip].hostname
                                scan_results[ip].mac = targets[ip].mac or scan_results[ip].mac
                                scan_results[ip].vendor = targets[ip].vendor or scan_results[ip].vendor
                                results[ip] = scan_results[ip]
                            else:
                                # Se não houver novos dados, mantém as informações originais
                                results[ip] = targets[ip]
                        
                        success = True
                        progress_bar.update(len(batch))

                    except subprocess.TimeoutExpired:
                        last_error = "timeout"
                        error(f"Timeout ao escanear grupo {batch_num} (tentativa {attempt})")
                    except subprocess.CalledProcessError as e:
                        last_error = str(e)
                        error(f"Erro ao escanear grupo {batch_num} (tentativa {attempt}): {str(e)}")
                    except Exception as e:
                        last_error = str(e)
                        error(f"Erro inesperado ao escanear grupo {batch_num} (tentativa {attempt}): {str(e)}")
                    
                    if not success and attempt < retry_config['max_attempts']:
                        time.sleep(retry_config['delay_between_attempts'])
                    attempt += 1
                
                if not success:
                    error(f"Todas as tentativas falharam para o grupo {batch_num}: {last_error}")
                    # Em caso de falha, mantém as informações originais dos hosts
                    for ip in batch:
                        results[ip] = targets[ip]
                    progress_bar.update(len(batch))
                
                # Pausa entre grupos para não sobrecarregar a rede
                if batch_num < total_batches:
                    time.sleep(2)

        return results

    def discover_hosts(self, network: str) -> Dict[str, HostInfo]:
        """Discover hosts in the specified network range."""
        return self.scan_network(network)

    def scan_ports(self, target: str) -> Dict[str, HostInfo]:
        """Scan ports on a specific target."""
        self._validate_network_range(target)
        cmd = [self._nmap_path] + self._get_scan_options() + [target]
        
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return self._parse_nmap_output(result.stdout)

    def _validate_network_range(self, network: str):
        """Validate the network range format."""
        try:
            if '/' in network:
                ipaddress.ip_network(network)
            else:
                ipaddress.ip_address(network)
        except ValueError as e:
            raise ValueError(f"Invalid network range: {network}") from e

    def _parse_nmap_output(self, output: str) -> Dict[str, HostInfo]:
        """Parse nmap output and return structured data."""
        hosts: Dict[str, HostInfo] = {}
        current_ip = None
        
        for line in output.splitlines():
            if "Nmap scan report for" in line:
                ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                if ip_match:
                    current_ip = ip_match.group(0)
                    hosts[current_ip] = HostInfo(ip=current_ip)
                    hosts[current_ip].is_up = True
                    
                    hostname_match = re.search(r'for ([^\s(]+)', line)
                    if hostname_match and not re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', hostname_match.group(1)):
                        hosts[current_ip].hostname = hostname_match.group(1)
                        
            elif current_ip and "MAC Address:" in line:
                mac_match = re.search(r'MAC Address: ([0-9A-F:]{17})(?: \((.+)\))?', line, re.IGNORECASE)
                if mac_match:
                    hosts[current_ip].mac = mac_match.group(1)
                    if mac_match.group(2):
                        hosts[current_ip].vendor = mac_match.group(2)
                        
            elif current_ip and re.match(r'\d+/\w+\s+\w+\s+\w+', line):
                port_info = re.match(r'(\d+)/(\w+)\s+(\w+)\s+(.+)', line)
                if port_info:
                    port_num = int(port_info.group(1))
                    service = port_info.group(4).split()[0].lower()  # Get first word of service info
                    port_data = {
                        'port': port_num,
                        'protocol': port_info.group(2),
                        'state': port_info.group(3),
                        'service': service
                    }
                    hosts[current_ip].ports.append(port_data)
                    
        return hosts
