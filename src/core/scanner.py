#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ESK NMAP - Network Scanner Tool
Copyright (C) 2025 Eskel Cybersecurity
Author: Sigmar Eskelsen

Este módulo contém as classes e funções para escaneamento de redes.
"""

import subprocess
import ipaddress
import re
import time
import concurrent.futures
from typing import Dict, List, Any, Optional, Union, Set
from tqdm import tqdm

from ..utils.logger import info, error, debug, warning
from ..utils.config_manager import ConfigManager

class ScannerError(Exception):
    """Exceção personalizada para erros no scanner"""
    pass

class HostInfo:
    """Classe para armazenar informações sobre um host na rede"""
    
    def __init__(self, ip: str, hostname: str = "N/A", mac: str = "N/A", 
                vendor: str = "N/A", ports: List[Any] = None, is_up: bool = False):
        """
        Inicializa um objeto HostInfo.
        
        Args:
            ip (str): Endereço IP do host
            hostname (str): Nome do host (opcional)
            mac (str): Endereço MAC do host (opcional)
            vendor (str): Fabricante do dispositivo (opcional)
            ports (List[Union[Dict, str]]): Lista de portas abertas (opcional)
            is_up (bool): Se o host está ativo (opcional)
        """
        self.ip = ip
        self.hostname = hostname
        self.mac = mac
        self.vendor = vendor
        self.ports = ports or []
        self._is_up = False
        self._status = "down"
        # Garante que is_up atualize o status corretamente
        self.is_up = is_up

    @property
    def is_up(self) -> bool:
        """Retorna se o host está online"""
        return self._is_up

    @is_up.setter
    def is_up(self, value: bool):
        """Define se o host está online"""
        self._is_up = value
        # Atualiza o status baseado no valor de is_up
        self._status = "up" if value else "down"

    @property
    def status(self) -> str:
        """Retorna o status do host (up, down, filtered, etc)"""
        return self._status
    
    @status.setter
    def status(self, value: str) -> None:
        """Define o status do host e atualiza is_up se necessário"""
        self._status = value
        self._is_up = (value == "up")
    
    @property
    def services(self) -> List[str]:
        """Retorna a lista de serviços nos portas abertas"""
        services = []
        for port_info in self.ports:
            if isinstance(port_info, dict):
                if port_info.get('state', '').lower() == 'open':
                    services.append(port_info.get('service', 'unknown'))
            else:
                # Assume que é uma string no formato "80/tcp" se não for um dict
                services.append("unknown")
        return services
    
    def __str__(self) -> str:
        """Representação em string do objeto HostInfo"""
        result = [f"Host: {self.ip}"]
        if self.hostname != "N/A":
            result.append(f"Hostname: {self.hostname}")
        if self.mac != "N/A":
            result.append(f"MAC: {self.mac}")
        if self.vendor != "N/A":
            result.append(f"Vendor: {self.vendor}")
        result.append(f"Status: {self.status}")
        
        if self.ports:
            result.append("Portas abertas:")
            for port_info in self.ports:
                if isinstance(port_info, dict):
                    port_str = f"{port_info['port']}/{port_info.get('protocol', 'tcp')}"
                    port_service = port_info.get('service', 'unknown')
                    port_version = f" ({port_info.get('version', '')})" if port_info.get('version') else ""
                    result.append(f"  {port_str}: {port_service}{port_version}")
                else:
                    # Assume que é uma string se não for um dict
                    result.append(f"  {port_info}")
                    
        return "\n".join(result)

class NetworkScanner:
    """Classe para escaneamento de redes usando nmap"""
    
    def __init__(self, nmap_path: Optional[str] = None):
        """
        Inicializa o NetworkScanner.
        
        Args:
            nmap_path (Optional[str]): Caminho para o executável do nmap.
                Se não for fornecido, será usado o nmap no PATH.
        """
        self.network_range = ""
        self.verbosity = 0
        self._nmap_path = nmap_path or "nmap"
        self._scan_profile = "basic"
        self._quiet_mode = False
        self._batch_size = 10  # Número de hosts para escanear em cada batch
        self._max_threads = 5  # Número máximo de threads para paralelização
        self._throttle_delay = 0.5  # Delay entre execuções de threads (segundos)
        self._config_manager = ConfigManager()
    
    def set_scan_profile(self, profile_name: str) -> None:
        """
        Define o perfil de scan a ser utilizado.
        
        Args:
            profile_name (str): Nome do perfil de scan
        """
        # Verifica se o perfil existe na configuração
        profiles = self._config_manager._config.get('scan_profiles', {})
        if profile_name in profiles:
            self._scan_profile = profile_name
        else:
            warning(f"Perfil '{profile_name}' não encontrado. Usando perfil 'basic' como fallback.")
            self._scan_profile = "basic"
    
    def set_quiet_mode(self, quiet_mode: bool) -> None:
        """
        Define o modo silencioso.
        
        Args:
            quiet_mode (bool): Se True, não exibe barras de progresso
        """
        self._quiet_mode = quiet_mode
    
    def set_batch_size(self, batch_size: int) -> None:
        """
        Define o tamanho do lote para processamento em batch.
        
        Args:
            batch_size (int): Número de hosts para processar em cada lote
        """
        if batch_size < 1:
            raise ValueError("O tamanho do batch deve ser pelo menos 1")
        self._batch_size = batch_size

    def set_max_threads(self, max_threads: int) -> None:
        """
        Define o número máximo de threads para paralelização.
        
        Args:
            max_threads (int): Número máximo de threads a serem utilizadas
        """
        if max_threads < 1:
            raise ValueError("O número de threads deve ser pelo menos 1")
        self._max_threads = max_threads
    
    def set_throttle_delay(self, delay: float) -> None:
        """
        Define o atraso entre execuções de threads para controle de tráfego.
        
        Args:
            delay (float): Atraso em segundos
        """
        if delay < 0:
            raise ValueError("O atraso deve ser não-negativo")
        self._throttle_delay = delay

    def _get_scan_options(self) -> List[str]:
        """
        Obtém as opções de scan com base no perfil selecionado.
        
        Returns:
            List[str]: Lista de opções para o comando nmap
        """
        profile_config = self._config_manager.get_scan_profile(self._scan_profile)
        options = profile_config.get('options', []).copy()  # Faz uma cópia para não modificar o original
        
        # Adiciona opções de verbosidade se necessário
        if self.verbosity >= 2:
            options.append('-vv')
        elif self.verbosity == 1:
            options.append('-v')
        
        return options
    
    def _validate_network_range(self, network_range: str) -> None:
        """
        Valida se o range de rede é válido.
        
        Args:
            network_range (str): Range de rede em formato CIDR ou IP único
            
        Raises:
            ValueError: Se o range for inválido
        """
        try:
            # Se é um range CIDR
            if '/' in network_range:
                ipaddress.ip_network(network_range, strict=False)
            # Se é um IP único
            else:
                ipaddress.ip_address(network_range)
        except ValueError as e:
            raise ValueError(f"Range de rede inválido: {network_range}. Erro: {str(e)}")
    
    def _parse_nmap_output(self, output: str) -> Dict[str, HostInfo]:
        """
        Parseia a saída do nmap para extrair informações dos hosts.
        
        Args:
            output (str): Saída do comando nmap
            
        Returns:
            Dict[str, HostInfo]: Dicionário de hosts encontrados
        """
        hosts = {}
        
        # Encontra os blocos de relatório para cada host
        host_blocks = re.finditer(r'Nmap scan report for (\S+)(?:\s*\(([^\)]+)\))?\n(.*?)(?=Nmap scan report for|\Z)', 
                                  output, re.DOTALL)
        
        for match in host_blocks:
            hostname_or_ip = match.group(1)
            possible_ip = match.group(2)
            host_data = match.group(3)
            
            # Determina o IP e o hostname
            if possible_ip and re.match(r'\d+\.\d+\.\d+\.\d+', possible_ip):
                ip = possible_ip
                hostname = hostname_or_ip
            else:
                ip = hostname_or_ip
                hostname = "N/A"
            
            # Verifica se o host está up
            is_up = "Host is up" in host_data
            
            # Extrai MAC address e vendor, se disponíveis
            mac_match = re.search(r'MAC Address: ([0-9A-Fa-f:]{17}) \(?([^\)]+)?\)?', host_data)
            mac = mac_match.group(1) if mac_match else "N/A"
            vendor = mac_match.group(2) if mac_match and mac_match.group(2) else "N/A"
            
            # Extrai informações de portas, se disponíveis
            ports = []
            
            # Procura a linha PORT STATE SERVICE VERSION que indica o início da lista de portas
            port_data = re.search(r'PORT\s+STATE\s+SERVICE(?:\s+VERSION)?\n(.*?)(?=\n\n|\Z)', host_data, re.DOTALL)
            if port_data:
                # Processa cada linha de porta individualmente
                port_lines = port_data.group(1).strip().split('\n')
                for line in port_lines:
                    if not line.strip():
                        continue
                        
                    # Separa os campos da linha
                    parts = line.split(None, 3)  # Divide em no máximo 4 partes
                    if len(parts) < 3:
                        continue
                        
                    # Processa o número da porta e protocolo
                    port_proto = parts[0].split('/')
                    if len(port_proto) != 2:
                        continue
                        
                    port = int(port_proto[0])
                    protocol = port_proto[1]
                    state = parts[1]
                    service = parts[2]
                    version = parts[3] if len(parts) > 3 else ""
                    
                    ports.append({
                        'port': port,
                        'protocol': protocol,
                        'state': state,
                        'service': service,
                        'version': version.strip()
                    })
            
            # Cria o objeto HostInfo
            hosts[ip] = HostInfo(
                ip=ip,
                hostname=hostname,
                mac=mac,
                vendor=vendor,
                ports=ports,
                is_up=is_up
            )
        
        return hosts
    
    def scan_network(self, network_range: str) -> Dict[str, HostInfo]:
        """
        Executa um scan na rede para descobrir hosts ativos.
        
        Args:
            network_range (str): Range de rede para escanear (ex: 192.168.1.0/24)
            
        Returns:
            Dict[str, HostInfo]: Dicionário de hosts encontrados
        """
        self._validate_network_range(network_range)
        self.network_range = network_range
        
        # Comando básico para descoberta de hosts
        cmd = [self._nmap_path]
        
        # Adiciona todas as opções do perfil
        profile_options = self._get_scan_options()
        cmd.extend(profile_options)
        
        # Adiciona o range de rede
        cmd.append(network_range)
        
        debug(f"Executando comando: {' '.join(cmd)}")
        
        try:
            # Executa o comando nmap com timeout
            timeout_value = self._config_manager.get_timeout('discovery')
            debug(f"Timeout configurado para scan de descoberta: {timeout_value}s")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_value
            )
            
            if result.returncode != 0:
                error(f"Erro ao executar nmap: {result.stderr}")
                raise ScannerError(f"Nmap retornou código de erro {result.returncode}: {result.stderr}")
            
            # Parseia a saída para encontrar hosts
            hosts = self._parse_nmap_output(result.stdout)
            
            debug(f"Descobertos {len(hosts)} hosts ativos na rede {network_range}")
            
            return hosts
            
        except subprocess.TimeoutExpired:
            error(f"Timeout ao executar scan de descoberta na rede {network_range}")
            raise ScannerError(f"Timeout durante scan de descoberta. O scan excedeu {timeout_value}s.")
        except Exception as e:
            error(f"Erro durante scan de descoberta: {str(e)}")
            raise ScannerError(f"Erro durante scan de descoberta: {str(e)}")

    def _scan_host_batch(self, host_ips: List[str]) -> Dict[str, HostInfo]:
        """
        Escaneia um lote de hosts para detectar portas e serviços.
        
        Args:
            host_ips (List[str]): Lista de IPs para escanear
            
        Returns:
            Dict[str, HostInfo]: Dicionário com os resultados do scan
        """
        if not host_ips:
            return {}
        
        # Prepara o comando nmap com as opções do perfil
        cmd = [self._nmap_path] + self._get_scan_options()
        cmd.extend(host_ips)
        
        debug(f"Escaneando batch de {len(host_ips)} hosts: {', '.join(host_ips)}")
        
        # Executa com retry automático em caso de falha
        retry_config = self._config_manager.get_retry_config()
        max_attempts = retry_config.get('max_attempts', 3)
        delay = retry_config.get('delay_between_attempts', 2)
        timeout = self._config_manager.get_timeout('batch_scan')
        
        for attempt in range(1, max_attempts + 1):
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                
                if result.returncode != 0:
                    warning(f"nmap retornou código de erro {result.returncode} no batch {host_ips}")
                    if attempt < max_attempts:
                        debug(f"Tentativa {attempt}/{max_attempts} falhou. Tentando novamente em {delay}s...")
                        time.sleep(delay)
                        continue
                
                # Sucesso - parseia a saída
                return self._parse_nmap_output(result.stdout)
                
            except subprocess.TimeoutExpired:
                warning(f"Timeout ao escanear batch {host_ips}")
                if attempt < max_attempts:
                    debug(f"Tentativa {attempt}/{max_attempts} falhou (timeout). Tentando novamente em {delay}s...")
                    time.sleep(delay)
                else:
                    error(f"Todas as {max_attempts} tentativas falharam para o batch {host_ips}")
                    return {}  # Retorna vazio após todas as tentativas
            except Exception as e:
                error(f"Erro ao escanear batch {host_ips}: {str(e)}")
                if attempt < max_attempts:
                    debug(f"Tentativa {attempt}/{max_attempts} falhou. Tentando novamente em {delay}s...")
                    time.sleep(delay)
                else:
                    error(f"Todas as {max_attempts} tentativas falharam para o batch {host_ips}")
                    return {}
        
        # Se chegou aqui, todas as tentativas falharam
        return {}

    def _process_host_batch_parallel(self, host_batches: List[List[str]]) -> Dict[str, HostInfo]:
        """
        Processa múltiplos batches de hosts em paralelo usando ThreadPoolExecutor.
        
        Args:
            host_batches (List[List[str]]): Lista de batches, onde cada batch é uma lista de IPs
            
        Returns:
            Dict[str, HostInfo]: Dicionário combinado com resultados de todos os batches
        """
        results = {}
        
        # Configura o executor com o número máximo de threads
        with concurrent.futures.ThreadPoolExecutor(max_workers=self._max_threads) as executor:
            # Submete os jobs e aplica throttling se configurado
            futures = []
            for batch in host_batches:
                futures.append(executor.submit(self._scan_host_batch, batch))
                if self._throttle_delay > 0:
                    time.sleep(self._throttle_delay)  # Throttling entre submissões
            
            # Processa os resultados à medida que são concluídos
            for future in concurrent.futures.as_completed(futures):
                try:
                    batch_result = future.result()
                    results.update(batch_result)
                except Exception as e:
                    error(f"Erro ao processar batch em paralelo: {str(e)}")
        
        return results

    def detailed_scan(self, hosts: Dict[str, HostInfo]) -> Dict[str, HostInfo]:
        """
        Executa um scan detalhado dos hosts descobertos para encontrar portas e serviços.
        
        Args:
            hosts (Dict[str, HostInfo]): Dicionário de hosts encontrados na fase de descoberta
            
        Returns:
            Dict[str, HostInfo]: Dicionário atualizado com informações detalhadas
        """
        if not hosts:
            warning("Nenhum host para scan detalhado")
            return {}
        
        # Filtra apenas hosts ativos
        active_hosts = {ip: info for ip, info in hosts.items() if info.is_up}
        
        if not active_hosts:
            warning("Nenhum host ativo para scan detalhado")
            return hosts  # Retorna a lista original
        
        # Divide os hosts em batches para processamento
        host_ips = list(active_hosts.keys())
        total_hosts = len(host_ips)
        
        # Cria batches de hosts
        host_batches = []
        for i in range(0, total_hosts, self._batch_size):
            batch = host_ips[i:i + self._batch_size]
            host_batches.append(batch)
        
        info(f"Escaneando grupo 1/{len(host_batches)} ({total_hosts} hosts)")
        
        # Feedback visual
        if not self._quiet_mode:
            with tqdm(total=total_hosts, desc="Escaneando hosts") as pbar:
                # Processa os batches em paralelo se tiver mais de um batch
                if len(host_batches) > 1 and self._max_threads > 1:
                    detailed_results = self._process_host_batch_parallel(host_batches)
                    pbar.update(total_hosts)  # Atualiza a barra de progresso no final
                else:
                    # Processamento sequencial para um único batch ou se _max_threads = 1
                    detailed_results = {}
                    for batch in host_batches:
                        batch_results = self._scan_host_batch(batch)
                        detailed_results.update(batch_results)
                        pbar.update(len(batch))
        else:
            # Modo silencioso, sem barra de progresso
            if len(host_batches) > 1 and self._max_threads > 1:
                detailed_results = self._process_host_batch_parallel(host_batches)
            else:
                detailed_results = {}
                for batch in host_batches:
                    batch_results = self._scan_host_batch(batch)
                    detailed_results.update(batch_results)
        
        # Merge dos resultados detalhados nos hosts originais
        for ip, detailed_info in detailed_results.items():
            if ip in hosts:
                # Mantém as informações originais do host
                original_host = hosts[ip]
                detailed_info.hostname = original_host.hostname if original_host.hostname != "N/A" else detailed_info.hostname
                detailed_info.mac = original_host.mac if original_host.mac != "N/A" else detailed_info.mac
                detailed_info.vendor = original_host.vendor if original_host.vendor != "N/A" else detailed_info.vendor
                hosts[ip] = detailed_info
        
        return hosts

    def scan_ports(self, target: str) -> Dict[str, HostInfo]:
        """
        Escaneia portas em um único target.
        
        Args:
            target (str): IP ou hostname para escanear
            
        Returns:
            Dict[str, HostInfo]: Dicionário com resultado do scan
        """
        # Prepara o comando nmap com as opções do perfil
        cmd = [self._nmap_path] + self._get_scan_options()
        cmd.append(target)
        
        debug(f"Escaneando portas em {target}")
        
        # Executa o comando
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._config_manager.get_timeout('port_scan')
            )
            
            if result.returncode != 0:
                warning(f"nmap retornou código de erro {result.returncode}")
            
            # Parseia a saída para encontrar hosts e portas
            return self._parse_nmap_output(result.stdout)
            
        except subprocess.TimeoutExpired:
            error(f"Timeout ao escanear {target}")
            raise ScannerError(f"Timeout durante scan de {target}")
        except Exception as e:
            error(f"Erro ao escanear {target}: {str(e)}")
            raise ScannerError(f"Erro durante scan de {target}: {str(e)}")
