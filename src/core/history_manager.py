#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ESK NMAP - Network Scanner Tool
Copyright (C) 2025 Eskel Cybersecurity
Author: Sigmar Eskelsen

Este módulo contém as classes e funções para gerenciar o histórico de scans.
"""

import os
import json
import time
import sqlite3
import csv
import xml.dom.minidom
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union, Literal
from ..utils.logger import info, debug, error, warning
from ..core.scanner import HostInfo
from ..reports.report_generator import ReportFormat, ComparisonFormat, ComparisonReportGenerator

class HistoryManager:
    """
    Classe responsável por gerenciar o histórico de scans realizados.
    Implementa funcionalidades para armazenar e recuperar resultados de scans anteriores.
    """
    
    _instance = None
    _db_path = None
    _initialized = False
    
    def __new__(cls, db_path: Optional[str] = None):
        """Implementa o padrão singleton para o HistoryManager"""
        if cls._instance is None:
            cls._instance = super(HistoryManager, cls).__new__(cls)
            cls._instance._initialized = False
        
        return cls._instance
    
    def __init__(self, db_path: Optional[str] = None):
        """
        Inicializa o HistoryManager.
        
        Args:
            db_path (Optional[str]): Caminho para o banco de dados SQLite.
                Se não for fornecido, usa o padrão na pasta de dados da aplicação.
        """
        if self._initialized:
            return
        
        if db_path:
            self._db_path = db_path
        else:
            # Define o caminho padrão para o banco de dados
            app_data = os.path.join(os.path.expanduser('~'), '.esk_nmap')
            os.makedirs(app_data, exist_ok=True)
            self._db_path = os.path.join(app_data, 'scan_history.db')
        
        debug(f"Inicializando HistoryManager com banco de dados em: {self._db_path}")
        self._init_database()
        self._initialized = True
    
    def _init_database(self) -> None:
        """Inicializa o esquema do banco de dados se necessário."""
        try:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            
            # Tabela de scans
            cursor.execute('''CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                network TEXT NOT NULL,
                scan_profile TEXT NOT NULL,
                total_hosts INTEGER NOT NULL
            )''')
            
            # Tabela de hosts
            cursor.execute('''CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                ip TEXT NOT NULL,
                hostname TEXT,
                mac TEXT,
                vendor TEXT,
                status TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE,
                UNIQUE (scan_id, ip)
            )''')
            
            # Tabela de portas/serviços
            cursor.execute('''CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                port TEXT NOT NULL,
                service TEXT,
                FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE,
                UNIQUE (host_id, port)
            )''')
            
            # Índices para melhorar a performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON scans (timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_network ON scans (network)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_host_scan_id ON hosts (scan_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_host_ip ON hosts (ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_port_host_id ON ports (host_id)')
            
            conn.commit()
            conn.close()
            debug("Esquema do banco de dados inicializado com sucesso")
            
        except sqlite3.Error as e:
            error(f"Erro ao inicializar banco de dados: {str(e)}")
            raise
    
    def save_scan_results(self, 
                         network: str, 
                         hosts: Dict[str, Union[Dict[str, Any], 'HostInfo']], 
                         scan_profile: str) -> int:
        """
        Salva os resultados de um scan no banco de dados.
        
        Args:
            network (str): Rede que foi escaneada (ex: 192.168.1.0/24)
            hosts (Dict[str, Union[Dict[str, Any], HostInfo]]): Dicionário de hosts descobertos
                Pode ser um dicionário de objetos HostInfo ou um dicionário de dicionários
            scan_profile (str): Nome do perfil de scan utilizado
            
        Returns:
            int: ID do scan salvo no banco de dados
        """
        timestamp = datetime.now().isoformat()
        total_hosts = len(hosts)
        
        try:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            
            # Insere o registro do scan
            cursor.execute(
                'INSERT INTO scans (timestamp, network, scan_profile, total_hosts) VALUES (?, ?, ?, ?)',
                (timestamp, network, scan_profile, total_hosts)
            )
            scan_id = cursor.lastrowid
            
            # Insere os hosts
            for ip, host_info in hosts.items():
                # Verifica se host_info é um dicionário ou um objeto
                if isinstance(host_info, dict):
                    hostname = host_info.get('hostname', '')
                    mac = host_info.get('mac', '')
                    vendor = host_info.get('vendor', '')
                    status = host_info.get('status', 'unknown')
                    ports_list = host_info.get('ports', [])
                else:
                    # Assume que é um objeto HostInfo
                    hostname = host_info.hostname
                    mac = host_info.mac
                    vendor = host_info.vendor
                    status = host_info.status
                    ports_list = host_info.ports
                
                cursor.execute(
                    'INSERT INTO hosts (scan_id, ip, hostname, mac, vendor, status) VALUES (?, ?, ?, ?, ?, ?)',
                    (scan_id, ip, hostname, mac, vendor, status)
                )
                host_id = cursor.lastrowid
                
                # Insere as portas
                if ports_list:
                    for port_info in ports_list:
                        if isinstance(port_info, dict) and port_info.get('state', '').lower() == 'open':
                            port_str = f"{port_info['port']}/{port_info['protocol']}"
                            service = port_info.get('service', '')
                            cursor.execute(
                                'INSERT INTO ports (host_id, port, service) VALUES (?, ?, ?)',
                                (host_id, port_str, service)
                            )
            
            conn.commit()
            conn.close()
            info(f"Scan {scan_id} salvo com sucesso no histórico ({network}, {total_hosts} hosts)")
            return scan_id
            
        except sqlite3.Error as e:
            error(f"Erro ao salvar resultados do scan: {str(e)}")
            raise
    
    def get_scan_list(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Retorna a lista dos scans mais recentes.
        
        Args:
            limit (int): Número máximo de scans a retornar (padrão: 10)
            
        Returns:
            List[Dict[str, Any]]: Lista de scans, ordenados do mais recente para o mais antigo
        """
        try:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row  # Para acessar colunas por nome
            cursor = conn.cursor()
            
            cursor.execute(
                'SELECT id, timestamp, network, scan_profile, total_hosts FROM scans ORDER BY timestamp DESC LIMIT ?',
                (limit,)
            )
            
            scans = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return scans
            
        except sqlite3.Error as e:
            error(f"Erro ao obter lista de scans: {str(e)}")
            raise
    
    def get_scan_by_id(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """
        Recupera um scan específico pelo ID, incluindo todos os hosts e portas.
        
        Args:
            scan_id (int): ID do scan a ser recuperado
            
        Returns:
            Optional[Dict[str, Any]]: Dados completos do scan ou None se não encontrado
        """
        try:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Obtém informações do scan
            cursor.execute(
                'SELECT id, timestamp, network, scan_profile, total_hosts FROM scans WHERE id = ?',
                (scan_id,)
            )
            scan_row = cursor.fetchone()
            
            if not scan_row:
                conn.close()
                warning(f"Scan com ID {scan_id} não encontrado")
                return None
            
            scan_data = dict(scan_row)
            scan_data['hosts'] = {}
            
            # Obtém hosts do scan
            cursor.execute(
                'SELECT id, ip, hostname, mac, vendor, status FROM hosts WHERE scan_id = ?',
                (scan_id,)
            )
            
            for host_row in cursor.fetchall():
                host_data = dict(host_row)
                host_id = host_data['id']
                ip = host_data['ip']
                
                # Obtém portas/serviços do host
                cursor.execute(
                    'SELECT port, service FROM ports WHERE host_id = ?',
                    (host_id,)
                )
                
                ports = []
                services = []
                for port_row in cursor.fetchall():
                    ports.append(port_row['port'])
                    services.append(port_row['service'])
                
                # Remove o ID interno do host
                del host_data['id']
                
                # Adiciona portas e serviços ao host
                host_data['ports'] = ports
                host_data['services'] = services
                
                # Adiciona o host ao scan
                scan_data['hosts'][ip] = host_data
            
            conn.close()
            return scan_data
            
        except sqlite3.Error as e:
            error(f"Erro ao recuperar scan com ID {scan_id}: {str(e)}")
            raise
    
    def get_scans_by_network(self, network: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Retorna a lista de scans para uma rede específica.
        
        Args:
            network (str): Rede a ser filtrada (ex: 192.168.1.0/24)
            limit (int): Número máximo de scans a retornar (padrão: 10)
            
        Returns:
            List[Dict[str, Any]]: Lista de scans, ordenados do mais recente para o mais antigo
        """
        try:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute(
                'SELECT id, timestamp, network, scan_profile, total_hosts FROM scans WHERE network = ? ORDER BY timestamp DESC LIMIT ?',
                (network, limit)
            )
            
            scans = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return scans
            
        except sqlite3.Error as e:
            error(f"Erro ao obter scans para a rede {network}: {str(e)}")
            raise
    
    def delete_scan(self, scan_id: int) -> bool:
        """
        Exclui um scan do histórico.
        
        Args:
            scan_id (int): ID do scan a ser excluído
            
        Returns:
            bool: True se o scan foi excluído, False caso contrário
        """
        try:
            conn = sqlite3.connect(self._db_path)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
            deleted = cursor.rowcount > 0
            
            conn.commit()
            conn.close()
            
            if deleted:
                info(f"Scan {scan_id} excluído com sucesso")
            else:
                warning(f"Scan {scan_id} não encontrado para exclusão")
                
            return deleted
            
        except sqlite3.Error as e:
            error(f"Erro ao excluir scan {scan_id}: {str(e)}")
            raise
    
    def export_scan_to_json(self, scan_id: int, output_file: str) -> bool:
        """
        Exporta os resultados de um scan para um arquivo JSON.
        
        Args:
            scan_id (int): ID do scan a ser exportado
            output_file (str): Caminho para o arquivo de saída
            
        Returns:
            bool: True se a exportação foi bem-sucedida, False caso contrário
        """
        scan_data = self.get_scan_by_id(scan_id)
        if not scan_data:
            return False
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(scan_data, f, indent=4)
            
            info(f"Scan {scan_id} exportado com sucesso para {output_file}")
            return True
            
        except IOError as e:
            error(f"Erro ao exportar scan para JSON: {str(e)}")
            return False
    
    def export_comparison_report(self, 
                               comparison_data: Dict[str, Any], 
                               output_file: str,
                               format_type: str = ComparisonFormat.TEXT) -> bool:
        """
        Exporta os resultados de uma comparação para um arquivo no formato especificado.
        
        Args:
            comparison_data (Dict[str, Any]): Dados da comparação gerados por compare_scans()
            output_file (str): Caminho para o arquivo de saída
            format_type (str): Formato do relatório (text, json, csv, xml, html)
            
        Returns:
            bool: True se a exportação foi bem-sucedida, False caso contrário
        """
        # Utiliza a classe ComparisonReportGenerator para exportar o relatório
        return ComparisonReportGenerator.export_comparison_report(
            comparison_data=comparison_data,
            output_file=output_file,
            format_type=format_type
        )
    
    def compare_scans(self, 
                       scan_id1: int, 
                       scan_id2: int) -> Dict[str, Any]:
        """
        Compara dois scans e retorna as diferenças.
        
        Args:
            scan_id1 (int): ID do primeiro scan (mais antigo)
            scan_id2 (int): ID do segundo scan (mais recente)
            
        Returns:
            Dict[str, Any]: Dicionário com as diferenças encontradas
        """
        scan1 = self.get_scan_by_id(scan_id1)
        scan2 = self.get_scan_by_id(scan_id2)
        
        if not scan1 or not scan2:
            error("Não foi possível comparar os scans: um ou ambos não foram encontrados")
            return {
                'error': 'Um ou ambos os scans não foram encontrados',
                'found_scan1': scan1 is not None,
                'found_scan2': scan2 is not None
            }
        
        # Verifica se os scans são da mesma rede
        if scan1['network'] != scan2['network']:
            warning(f"Comparando scans de redes diferentes: {scan1['network']} e {scan2['network']}")
        
        # Obtém os conjuntos de IPs de cada scan
        ips1 = set(scan1['hosts'].keys())
        ips2 = set(scan2['hosts'].keys())
        
        # Encontra hosts novos, removidos e comuns
        new_hosts = ips2 - ips1
        removed_hosts = ips1 - ips2
        common_hosts = ips1 & ips2
        
        # Analisa as diferenças em hosts comuns
        changed_hosts = {}
        for ip in common_hosts:
            host1 = scan1['hosts'][ip]
            host2 = scan2['hosts'][ip]
            
            # Converte listas para conjuntos para comparação
            ports1 = set(host1['ports'])
            ports2 = set(host2['ports'])
            
            # Encontra portas novas e removidas
            new_ports = ports2 - ports1
            closed_ports = ports1 - ports2
            
            # Se houver mudanças, registra-as
            if new_ports or closed_ports:
                changed_hosts[ip] = {
                    'hostname': host2['hostname'],
                    'new_ports': list(new_ports),
                    'closed_ports': list(closed_ports)
                }
        
        # Prepara o resultado da comparação
        comparison = {
            'scan1': {
                'id': scan_id1,
                'timestamp': scan1['timestamp'],
                'profile': scan1['scan_profile'],
                'total_hosts': scan1['total_hosts']
            },
            'scan2': {
                'id': scan_id2,
                'timestamp': scan2['timestamp'],
                'profile': scan2['scan_profile'],
                'total_hosts': scan2['total_hosts']
            },
            'network': scan1['network'],
            'new_hosts': {ip: scan2['hosts'][ip] for ip in new_hosts},
            'removed_hosts': {ip: scan1['hosts'][ip] for ip in removed_hosts},
            'changed_hosts': changed_hosts,
            'unchanged_hosts': len(common_hosts) - len(changed_hosts),
            'summary': {
                'total_hosts_before': len(ips1),
                'total_hosts_after': len(ips2),
                'new_hosts': len(new_hosts),
                'removed_hosts': len(removed_hosts),
                'changed_hosts': len(changed_hosts),
                'unchanged_hosts': len(common_hosts) - len(changed_hosts)
            }
        }
        
        return comparison