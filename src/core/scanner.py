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
        """
        debug(f"Iniciando scan de rede em {network}")
        try:
            # Exibe barra de progresso para a descoberta
            if not self.quiet_mode:
                # Calcula o tamanho da rede para estimar o tempo
                try:
                    net_size = sum(1 for _ in ipaddress.ip_network(network).hosts())
                except ValueError:
                    # Se for um único IP, considera tamanho 1
                    net_size = 1
                
                # Estima o tempo baseado no tamanho da rede
                est_time = min(max(5, int(net_size * 0.12)), 120)  # Entre 5s e 120s
                
                with tqdm(total=100, 
                         desc=f"Descobrindo hosts em {network}", 
                         bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as pbar:
                    
                    # Inicia o scan em uma thread separada para poder atualizar a barra
                    scan_result = [None]  # Para armazenar o resultado do scan
                    scan_error = [None]   # Para armazenar possíveis erros
                    
                    def run_scan():
                        try:
                            scan_result[0] = self._discovery_scan(network)
                        except Exception as e:
                            scan_error[0] = e
                    
                    scan_thread = threading.Thread(target=run_scan)
                    scan_thread.start()
                    
                    # Atualiza a barra de progresso enquanto o scan está em execução
                    steps = min(50, est_time)  # Número de atualizações
                    step_size = 100 / steps     # Tamanho de cada atualização
                    sleep_time = est_time / steps  # Tempo entre atualizações
                    
                    for i in range(steps):
                        if not scan_thread.is_alive():
                            # O scan terminou antes do tempo estimado
                            remaining = 100 - pbar.n
                            if remaining > 0:
                                pbar.update(remaining)
                            break
                        
                        # Atualiza progressivamente
                        progress = min(95, step_size * (i + 1))  # Nunca chega a 100% até terminar
                        update_size = progress - pbar.n
                        if update_size > 0:
                            pbar.update(update_size)
                        
                        time.sleep(sleep_time)
                    
                    # Aguarda a conclusão do thread
                    scan_thread.join()
                    
                    # Completa a barra se necessário
                    if pbar.n < 100:
                        pbar.update(100 - pbar.n)
                    
                    # Verifica se houve erro no scan
                    if scan_error[0]:
                        error(f"Erro durante o scan de rede: {str(scan_error[0])}")
                        debug("Tentando método alternativo de descoberta")
                        return self._fallback_discovery(network)
                    
                    return scan_result[0]
            else:
                # Modo silencioso, sem barra de progresso
                return self._discovery_scan(network)
        except Exception as e:
            error(f"Erro durante o scan de rede: {str(e)}")
            try:
                # Tenta método alternativo em caso de falha
                debug("Tentando método alternativo de descoberta")
                return self._fallback_discovery(network)
            except Exception as e2:
                error(f"Método alternativo também falhou: {str(e2)}")
                raise ScannerError("Both discovery methods failed")
    
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
        """
        Analisa a saída do scan de descoberta do Nmap.
        
        Args:
            output (str): Saída do comando Nmap
            
        Returns:
            Dict[str, HostInfo]: Informações dos hosts encontrados
        """
        hosts = {}
        current_ip = None
        current_host = None
        
        # Expressões regulares para extrair informações
        ip_regex = re.compile(r"Nmap scan report for (?:([^\s]+) )?(?:\()?(\d+\.\d+\.\d+\.\d+)(?:\))?")
        mac_regex = re.compile(r"MAC Address: ([0-9A-F:]+) \(([^)]+)\)")
        
        for line in output.splitlines():
            ip_match = ip_regex.search(line)
            if ip_match:
                hostname = ip_match.group(1) or ""
                ip = ip_match.group(2)
                current_ip = ip
                current_host = HostInfo(ip=ip, hostname=hostname)
                hosts[current_ip] = current_host
                continue
            
            mac_match = mac_regex.search(line)
            if mac_match and current_host:
                current_host.mac = mac_match.group(1)
                current_host.vendor = mac_match.group(2)
        
        return hosts
    
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
        """
        Descoberta de hosts em sistemas Windows usando ping e arp.
        
        Args:
            network (str): Rede a ser escaneada
            
        Returns:
            Dict[str, HostInfo]: Hosts descobertos
        """
        hosts = {}
        net = ipaddress.ip_network(network)
        
        # Usa ping para descobrir hosts ativos
        hosts_list = list(net.hosts())
        
        # Utiliza tqdm apenas se não estiver em modo silencioso
        if not self.quiet_mode and hosts_list:
            ping_iter = tqdm(hosts_list, desc="Executando pings", 
                          bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]")
        else:
            ping_iter = hosts_list
            
        for ip in ping_iter:
            ip_str = str(ip)
            try:
                subprocess.run(["ping", "-n", "1", "-w", "500", ip_str], 
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            except Exception:
                pass
        
        # Usa ARP para obter informações de MAC
        try:
            if not self.quiet_mode:
                print("Analisando respostas ARP...")
                
            arp_output = subprocess.run(["arp", "-a"], stdout=subprocess.PIPE, 
                                       text=True, check=False).stdout
            
            # Analisa a saída do ARP
            for line in arp_output.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    # Formato Windows: Interface: 192.168.1.1 --- 0x3
                    #                  IP            MAC           Type
                    if parts[0] == "Interface:":
                        continue
                    
                    ip = parts[0]
                    if ip in net:
                        mac = parts[1].replace("-", ":")
                        hosts[ip] = HostInfo(ip=ip, mac=mac)
        except Exception as e:
            debug(f"Erro ao processar saída do ARP: {str(e)}")
        
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
        """
        Realiza um scan detalhado dos hosts especificados.
        
        Args:
            target_ips (Set[str]): Conjunto de IPs a serem escaneados em detalhe
            
        Returns:
            Dict[str, HostInfo]: Informações detalhadas dos hosts
        """
        if not target_ips:
            return {}
        
        debug(f"Iniciando scan detalhado de {len(target_ips)} hosts")
        results = {}
        
        # Inicializa os resultados com informações básicas
        for ip in target_ips:
            results[ip] = HostInfo(ip=ip)
        
        # Obtém o perfil de scan atual
        profile = self.config_manager.get_scan_profile(self._scan_profile)
            
        # Comando Nmap para scan detalhado
        target_list = ",".join(target_ips)
        cmd = [self.nmap_path]
        
        # Adiciona a lista de portas do perfil
        cmd.extend(["-p", profile['ports']])
        
        # Adiciona as opções do perfil (exceto as que são apenas para descoberta)
        for option in profile['options']:
            if option != "-sn" and not option.startswith("-T"):
                cmd.append(option)
        
        # Adiciona a detecção de versão se não estiver nas opções
        if "-sV" not in cmd:
            cmd.append("-sV")
        
        # Adiciona o timing baseado no perfil
        cmd.extend([f"-T{profile['timing']}"])
        
        # Adiciona o alvo
        cmd.append(target_list)
        
        debug(f"Executando comando: {' '.join(cmd)}")
        
        try:
            timeout = self.config_manager.get_timeout('port_scan')
            
            # Se não estiver em modo silencioso, exibe uma barra de progresso
            if not self.quiet_mode:
                # Estima quantas portas serão escaneadas
                port_count = 0
                ports_str = profile['ports']
                for port_range in ports_str.split(','):
                    if '-' in port_range:
                        start, end = map(int, port_range.split('-'))
                        port_count += (end - start + 1)
                    else:
                        port_count += 1
                
                # Estima o tempo baseado no número de hosts e portas
                est_time = min(timeout, max(10, len(target_ips) * port_count * 0.1))
                
                with tqdm(total=100, 
                         desc=f"Escaneando portas em {len(target_ips)} host(s)", 
                         bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as pbar:
                    
                    # Inicia o scan em uma thread separada
                    scan_result = [None]
                    scan_error = [None]
                    
                    def run_detailed_scan():
                        try:
                            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                            output, _ = process.communicate(timeout=timeout)
                            if process.returncode == 0:
                                # Parse da saída
                                self._parse_detailed_output(output, results)
                                scan_result[0] = results
                            else:
                                debug(f"Scan detalhado retornou código de erro {process.returncode}")
                                scan_error[0] = ScannerError(f"Nmap retornou código de saída {process.returncode}")
                        except Exception as e:
                            scan_error[0] = e
                    
                    scan_thread = threading.Thread(target=run_detailed_scan)
                    scan_thread.start()
                    
                    # Atualiza a barra de progresso enquanto o scan está em execução
                    steps = min(50, int(est_time))
                    step_size = 100 / steps
                    sleep_time = est_time / steps
                    
                    for i in range(steps):
                        if not scan_thread.is_alive():
                            remaining = 100 - pbar.n
                            if remaining > 0:
                                pbar.update(remaining)
                            break
                        
                        # Atualiza progressivamente com base no tempo decorrido
                        # A velocidade de atualização é maior no início e diminui no final
                        progress = min(95, (i + 1) / steps * 100)
                        update_size = progress - pbar.n
                        if update_size > 0:
                            pbar.update(update_size)
                        
                        time.sleep(sleep_time)
                    
                    # Aguarda a conclusão do thread
                    scan_thread.join()
                    
                    # Completa a barra
                    if pbar.n < 100:
                        pbar.update(100 - pbar.n)
                    
                    # Verifica se houve erro
                    if scan_error[0]:
                        raise scan_error[0]
            else:
                # Modo silencioso, sem barra de progresso
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                output, _ = process.communicate(timeout=timeout)
                
                if process.returncode == 0:
                    # Analisa a saída do scan detalhado
                    self._parse_detailed_output(output, results)
                else:
                    debug(f"Scan detalhado retornou código de erro {process.returncode}")
                
        except subprocess.TimeoutExpired:
            error(f"Scan detalhado expirou o tempo limite de {timeout}s")
            raise
        except Exception as e:
            error(f"Erro durante scan detalhado: {str(e)}")
            raise
        
        return results
    
    def _parse_detailed_output(self, output: str, results: Dict[str, HostInfo]) -> None:
        """
        Analisa a saída do scan detalhado do Nmap.
        
        Args:
            output (str): Saída do comando Nmap
            results (Dict[str, HostInfo]): Dicionário para armazenar os resultados
        """
        current_ip = None
        
        ip_regex = re.compile(r"Nmap scan report for (?:([^\s]+) )?(?:\()?(\d+\.\d+\.\d+\.\d+)(?:\))?")
        port_regex = re.compile(r"(\d+)/(\w+)\s+(\w+)\s+(\w+)\s*(.*)")
        
        for line in output.splitlines():
            ip_match = ip_regex.search(line)
            if ip_match:
                current_ip = ip_match.group(2)
                # Se o hostname estiver presente, atualiza
                hostname = ip_match.group(1)
                if hostname and current_ip in results:
                    results[current_ip].hostname = hostname
                continue
            
            # Tenta extrair informações de porta e serviço
            port_match = port_regex.search(line)
            if port_match and current_ip and current_ip in results:
                port_num = port_match.group(1)
                port_proto = port_match.group(2)
                port_status = port_match.group(3)
                service = port_match.group(4)
                version = port_match.group(5).strip()
                
                if port_status == "open":
                    port_str = f"{port_num}/{port_proto}"
                    results[current_ip].ports.append(port_str)
                    
                    service_str = service
                    if version:
                        service_str += f" ({version})"
                    
                    results[current_ip].services.append(service_str)