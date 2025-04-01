#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ESK NMAP - Network Scanner Tool
Copyright (C) 2025 Eskel Cybersecurity
Author: Sigmar Eskelsen
"""

from typing import Dict, List, Union, TextIO, Any, Optional
import time
import json
import csv
import re
import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime
from ..core.scanner import HostInfo
from enum import Enum, auto
from io import StringIO

class ReportFormat(Enum):
    """Formatos suportados para relatórios"""
    TEXT = auto()
    JSON = auto()
    CSV = auto()
    XML = auto()
    HTML = auto()

class ComparisonFormat:
    """Formatos suportados para relatórios de comparação"""
    TEXT = "text"
    JSON = "json"
    CSV = "csv"
    XML = "xml"
    HTML = "html"
    
    @staticmethod
    def from_string(format_str: str) -> str:
        """Converte uma string para um formato válido"""
        format_str = format_str.lower()
        if format_str in [ComparisonFormat.TEXT, ComparisonFormat.JSON, 
                          ComparisonFormat.CSV, ComparisonFormat.XML, 
                          ComparisonFormat.HTML]:
            return format_str
        return ComparisonFormat.TEXT

class ReportGenerator:
    @staticmethod
    def create_filename(network: str, format: ReportFormat = ReportFormat.TEXT) -> str:
        """Cria o nome do arquivo de relatório baseado na rede, timestamp e formato"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        # Sanitiza a rede para um nome de arquivo válido
        network_formatted = re.sub(r'[^\w\-_]', '_', network)
        extension = format.name.lower()
        return f"esk_nmap_report_{network_formatted}_{timestamp}.{extension}"

    @staticmethod
    def generate_report(filename: str, hosts: Dict[str, HostInfo], network: str, format: ReportFormat = ReportFormat.TEXT) -> None:
        """Gera o relatório no formato especificado"""
        if format == ReportFormat.TEXT:
            ReportGenerator._generate_text_report(filename, hosts, network)
        elif format == ReportFormat.JSON:
            ReportGenerator._generate_json_report(filename, hosts, network)
        elif format == ReportFormat.CSV:
            ReportGenerator._generate_csv_report(filename, hosts, network)
        elif format == ReportFormat.XML:
            ReportGenerator._generate_xml_report(filename, hosts, network)
        elif format == ReportFormat.HTML:
            ReportGenerator._generate_html_report(filename, hosts, network)
        else:
            raise ValueError(f"Formato de relatório não suportado: {format}")

    @staticmethod
    def generate_text_report(hosts: Dict[str, HostInfo]) -> str:
        """Generate text report and return as string"""
        output = StringIO()
        ReportGenerator._write_text_report(output, hosts, "")
        return output.getvalue()

    @staticmethod
    def generate_html_report(hosts: Dict[str, HostInfo]) -> str:
        """Generate HTML report and return as string"""
        output = StringIO()
        ReportGenerator._write_html_report(output, hosts, "")
        return output.getvalue()

    @staticmethod
    def generate_json_report(hosts: Dict[str, HostInfo]) -> dict:
        """Generate JSON report and return as dict"""
        report_data = {
            "metadata": {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "total_hosts": len(hosts),
                "hosts_with_open_ports": sum(1 for h in hosts.values() if h.ports)  # Simplificado para contar qualquer host com portas
            }
        }

        # Se não houver hosts, retorne um dicionário vazio
        if not hosts:
            return {}
        
        # Adiciona cada host ao relatório
        for ip, info in hosts.items():
            report_data[ip] = {
                "status": info.status,
                "hostname": info.hostname if info.hostname != "N/A" else None,
                "mac": info.mac if info.mac != "N/A" else None,
                "vendor": info.vendor if info.vendor != "N/A" else None,
                "ports": [],
                "services": info.services if hasattr(info, 'services') else []
            }
            
            # Adiciona portas, lidando tanto com dicionários quanto com strings
            if info.ports:
                for port_info in info.ports:
                    if isinstance(port_info, dict):
                        port = port_info.get('port')
                        if port:
                            report_data[ip]["ports"].append(port)
                    else:
                        # Se port_info for uma string (por exemplo, "80/tcp"), extraia o número da porta
                        port_match = re.match(r'(\d+)', str(port_info))
                        if port_match:
                            report_data[ip]["ports"].append(int(port_match.group(1)))
                        else:
                            # Se não conseguir extrair, adicione a string completa
                            report_data[ip]["ports"].append(str(port_info))

        return report_data

    @staticmethod
    def _write_text_report(file: TextIO, hosts: Dict[str, HostInfo], network: str) -> None:
        """Escreve o relatório em formato texto para o arquivo ou StringIO"""
        # Cabeçalho
        file.write("=" * 60 + "\n")
        file.write("ESK_NMAP - Scanner de Rede da Eskel Cybersecurity\n")
        file.write("=" * 60 + "\n")
        file.write(f"Data/Hora: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        if network:
            file.write(f"Rede: {network}\n")
        
        file.write("=" * 60 + "\n\n")

        # Verificar se há hosts
        if not hosts:
            file.write("No hosts found\n")
            return

        # Resumo inicial
        file.write("RESUMO:\n")
        total_hosts = len(hosts)
        hosts_with_ports = len([h for h in hosts.values() if any(p.get('state', '').lower() == 'open' for p in h.ports)])
        file.write(f"Total de hosts ativos: {total_hosts}\n")
        file.write(f"Hosts com portas abertas: {hosts_with_ports}\n\n")

        # Tabela de hosts descobertos
        file.write("HOSTS DESCOBERTOS:\n")
        file.write("+" + "-" * 15 + "+" + "-" * 8 + "+" + "-" * 35 + "+" + "-" * 19 + "+" + "-" * 20 + "+\n")
        file.write("| {:<13} | {:<6} | {:<33} | {:<17} | {:<18} |\n".format(
            "IP", "Status", "Hostname", "MAC", "Fabricante"))
        file.write("+" + "-" * 15 + "+" + "-" * 8 + "+" + "-" * 35 + "+" + "-" * 19 + "+" + "-" * 20 + "+\n")

        for ip, info in hosts.items():
            hostname = info.hostname if info.hostname != "N/A" else ""
            mac = info.mac if info.mac != "N/A" else ""
            vendor = info.vendor if info.vendor != "N/A" else ""
            
            file.write("| {:<13} | {:<6} | {:<33} | {:<17} | {:<18} |\n".format(
                ip, info.status, hostname[:33], mac[:17], vendor[:18]))
            file.write("+" + "-" * 15 + "+" + "-" * 8 + "+" + "-" * 35 + "+" + "-" * 19 + "+" + "-" * 20 + "+\n")

        file.write(f"\nTotal de hosts descobertos: {len(hosts)}\n")
        file.write("\n" + "=" * 60 + "\n")

        # Detalhes das portas de cada host
        file.write("\nDETALHES DAS PORTAS:\n")
        file.write("=" * 60 + "\n\n")

        for ip, info in hosts.items():
            file.write(f"HOST: {ip}\n")
            if info.hostname != "N/A":
                file.write(f"Hostname: {info.hostname}\n")
            
            if info.ports:
                # Obtém portas abertas, tentando pegar de dict ou usar diretamente
                if isinstance(info.ports[0], dict):
                    open_ports = [p for p in info.ports if p.get('state', '').lower() == 'open']
                else:
                    open_ports = info.ports  # Assume que são todas strings
                
                if open_ports:
                    file.write("\nPortas abertas:\n")
                    file.write("+" + "-" * 15 + "+" + "-" * 50 + "+\n")
                    file.write("| {:<13} | {:<48} |\n".format("PORTA", "SERVIÇO"))
                    file.write("+" + "-" * 15 + "+" + "-" * 50 + "+\n")
                    
                    for i, port_info in enumerate(open_ports):
                        if isinstance(port_info, dict):
                            port_str = f"{port_info['port']}/{port_info.get('protocol', 'tcp')}"
                            service = port_info.get('service', 'unknown')
                            version = port_info.get('version', '')
                            service_str = f"{service} {version}".strip()
                        else:
                            # Assume port_info is a string like "80/tcp"
                            port_str = port_info
                            service_str = info.services[i] if hasattr(info, 'services') and i < len(info.services) else "unknown"
                        
                        file.write("| {:<13} | {:<48} |\n".format(port_str, service_str[:48]))
                        file.write("+" + "-" * 15 + "+" + "-" * 50 + "+\n")
                else:
                    file.write("\nNo open ports\n")
            else:
                file.write("\nNo open ports\n")
            
            file.write("\n" + "=" * 60 + "\n")
        
        file.write("\nINFO: Scan concluído com sucesso!")

    @staticmethod
    def _generate_text_report(filename: str, hosts: Dict[str, HostInfo], network: str) -> None:
        """Gera o relatório em formato texto"""
        with open(filename, "w", encoding="utf-8") as f:
            ReportGenerator._write_text_report(f, hosts, network)
    
    @staticmethod
    def _write_html_report(file: TextIO, hosts: Dict[str, HostInfo], network: str) -> None:
        """Escreve o relatório em formato HTML para o arquivo ou StringIO"""
        # HTML header
        file.write("<!DOCTYPE html>\n")
        file.write("<html>\n<head>\n")
        file.write("<meta charset=\"utf-8\">\n")
        file.write("<title>ESK_NMAP - Network Scan Report</title>\n")
        file.write("<style>\n")
        file.write("body { font-family: Arial, sans-serif; margin: 20px; }\n")
        file.write("table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }\n")
        file.write("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n")
        file.write("th { background-color: #f2f2f2; }\n")
        file.write("h1, h2 { color: #333; }\n")
        file.write("</style>\n</head>\n<body>\n")

        # Report header
        file.write("<h1>ESK_NMAP - Network Scan Report</h1>\n")
        file.write("<p><strong>Date/Time:</strong> " + time.strftime("%Y-%m-%d %H:%M:%S") + "</p>\n")
        
        if network:
            file.write("<p><strong>Network:</strong> " + network + "</p>\n")

        # Check if there are hosts
        if not hosts:
            file.write("<p>No hosts found</p>\n")
            file.write("</body>\n</html>")
            return

        # Summary
        file.write("<h2>Summary</h2>\n")
        total_hosts = len(hosts)
        hosts_with_ports = len([h for h in hosts.values() if hasattr(h, 'ports') and h.ports])
        file.write(f"<p>Total active hosts: {total_hosts}</p>\n")
        file.write(f"<p>Hosts with open ports: {hosts_with_ports}</p>\n")

        # Hosts table
        file.write("<h2>Discovered Hosts</h2>\n")
        file.write("<table>\n")
        file.write("<tr><th>IP</th><th>Status</th><th>Hostname</th><th>MAC</th><th>Vendor</th></tr>\n")

        for ip, info in hosts.items():
            hostname = info.hostname if info.hostname != "N/A" else ""
            mac = info.mac if info.mac != "N/A" else ""
            vendor = info.vendor if info.vendor != "N/A" else ""
            
            file.write(f"<tr><td>{ip}</td><td>{info.status}</td><td>{hostname}</td>")
            file.write(f"<td>{mac}</td><td>{vendor}</td></tr>\n")

        file.write("</table>\n")

        # Ports details
        file.write("<h2>Ports Details</h2>\n")

        for ip, info in hosts.items():
            file.write(f"<h3>Host: {ip}</h3>\n")
            if info.hostname != "N/A":
                file.write(f"<p>Hostname: {info.hostname}</p>\n")
            
            if info.ports:
                # Create a table for open ports
                if isinstance(info.ports[0], dict):
                    open_ports = [p for p in info.ports if p.get('state', '').lower() == 'open']
                else:
                    open_ports = info.ports  # Assume that all are strings
                
                if open_ports:
                    file.write("<table>\n")
                    file.write("<tr><th>Port</th><th>Service</th></tr>\n")
                    
                    for i, port_info in enumerate(open_ports):
                        if isinstance(port_info, dict):
                            port_str = f"{port_info['port']}/{port_info.get('protocol', 'tcp')}"
                            service = port_info.get('service', 'unknown')
                            version = port_info.get('version', '')
                            service_str = f"{service} {version}".strip()
                        else:
                            # Assume port_info is a string like "80/tcp"
                            port_str = port_info
                            service_str = info.services[i] if hasattr(info, 'services') and i < len(info.services) else "unknown"
                        
                        file.write(f"<tr><td>{port_str}</td><td>{service_str}</td></tr>\n")
                    
                    file.write("</table>\n")
                else:
                    file.write("<p>No open ports</p>\n")
            else:
                file.write("<p>No open ports</p>\n")

        # Footer
        file.write("<hr>\n")
        file.write("<p>Scan completed successfully</p>\n")
        file.write("</body>\n</html>")

    @staticmethod
    def _generate_html_report(filename: str, hosts: Dict[str, HostInfo], network: str) -> None:
        """Gera o relatório em formato HTML"""
        with open(filename, "w", encoding="utf-8") as f:
            ReportGenerator._write_html_report(f, hosts, network)

    @staticmethod
    def _generate_json_report(filename: str, hosts: Dict[str, HostInfo], network: str) -> None:
        """Gera o relatório em formato JSON"""
        report_data = {
            "metadata": {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "network": network,
                "total_hosts": len(hosts),
                "hosts_with_open_ports": len([h for h in hosts.values() if any(p.get('state', '').lower() == 'open' for p in h.ports)])
            },
            "hosts": {}
        }

        for ip, info in hosts.items():
            report_data["hosts"][ip] = {
                "status": info.status,
                "hostname": info.hostname if info.hostname != "N/A" else None,
                "mac": info.mac if info.mac != "N/A" else None,
                "vendor": info.vendor if info.vendor != "N/A" else None,
                "ports": [
                    {
                        "port": port_info['port'] if isinstance(port_info, dict) else port_info,
                        "protocol": port_info.get('protocol', 'tcp') if isinstance(port_info, dict) else 'tcp',
                        "state": port_info.get('state', 'open') if isinstance(port_info, dict) else 'open',
                        "service": port_info.get('service', 'unknown') if isinstance(port_info, dict) else 
                                 (info.services[i] if hasattr(info, 'services') and i < len(info.services) else 'unknown'),
                        "version": port_info.get('version', '') if isinstance(port_info, dict) else ''
                    }
                    for i, port_info in enumerate(info.ports)
                ] if info.ports else []
            }

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

    @staticmethod
    def _generate_csv_report(filename: str, hosts: Dict[str, HostInfo], network: str) -> None:
        """Gera o relatório em formato CSV"""
        with open(filename, "w", encoding="utf-8", newline='') as f:
            writer = csv.writer(f)
            
            # Escreve o cabeçalho com metadados
            writer.writerow(["# ESK_NMAP Report"])
            writer.writerow(["# Data/Hora", time.strftime("%Y-%m-%d %H:%M:%S")])
            writer.writerow(["# Rede", network])
            writer.writerow(["# Total de hosts", str(len(hosts))])
            writer.writerow(["# Hosts com portas abertas", str(len([h for h in hosts.values() if any(p.get('state', '').lower() == 'open' for p in h.ports)]))])
            writer.writerow([])  # Linha em branco para separação
            
            # Escreve o cabeçalho da tabela de hosts
            writer.writerow(["IP", "Status", "Hostname", "MAC", "Fabricante", "Portas", "Serviços"])
            
            # Escreve os dados dos hosts
            for ip, info in hosts.items():
                hostname = info.hostname if info.hostname != "N/A" else ""
                mac = info.mac if info.mac != "N/A" else ""
                vendor = info.vendor if info.vendor != "N/A" else ""
                
                # Formata portas e serviços
                ports = []
                services = []
                
                if info.ports:
                    for i, port_info in enumerate(info.ports):
                        if isinstance(port_info, dict):
                            if port_info.get('state', '').lower() == 'open':
                                port_str = f"{port_info['port']}/{port_info.get('protocol', 'tcp')}"
                                service_str = f"{port_info.get('service', 'unknown')}"
                                if port_info.get('version'):
                                    service_str += f" {port_info['version']}"
                                ports.append(port_str)
                                services.append(service_str)
                        else:
                            # Assume que port_info é uma string como "80/tcp"
                            ports.append(port_info)
                            service_str = info.services[i] if hasattr(info, 'services') and i < len(info.services) else "unknown"
                            services.append(service_str)
                
                writer.writerow([
                    ip,
                    info.status,
                    hostname,
                    mac,
                    vendor,
                    "|".join(ports),
                    "|".join(services)
                ])

    @staticmethod
    def _generate_xml_report(filename: str, hosts: Dict[str, HostInfo], network: str) -> None:
        """Gera o relatório em formato XML"""
        # Cria o elemento raiz
        root = ET.Element("esk_nmap_report")
        
        # Adiciona metadados
        metadata = ET.SubElement(root, "metadata")
        ET.SubElement(metadata, "timestamp").text = time.strftime("%Y-%m-%d %H:%M:%S")
        ET.SubElement(metadata, "network").text = network
        ET.SubElement(metadata, "total_hosts").text = str(len(hosts))
        ET.SubElement(metadata, "hosts_with_open_ports").text = str(len([h for h in hosts.values() if any(p.get('state', '').lower() == 'open' for p in h.ports)]))
        
        # Adiciona hosts
        hosts_element = ET.SubElement(root, "hosts")
        for ip, info in hosts.items():
            host = ET.SubElement(hosts_element, "host")
            ET.SubElement(host, "ip").text = ip
            ET.SubElement(host, "status").text = info.status
            
            if info.hostname != "N/A":
                ET.SubElement(host, "hostname").text = info.hostname
            if info.mac != "N/A":
                ET.SubElement(host, "mac").text = info.mac
            if info.vendor != "N/A":
                ET.SubElement(host, "vendor").text = info.vendor
            
            if info.ports:
                ports_element = ET.SubElement(host, "ports")
                for i, port_info in enumerate(info.ports):
                    if isinstance(port_info, dict):
                        port_element = ET.SubElement(ports_element, "port")
                        port_element.set("number", str(port_info['port']))
                        port_element.set("protocol", port_info.get('protocol', 'tcp'))
                        port_element.set("state", port_info.get('state', 'open'))
                        
                        service_element = ET.SubElement(port_element, "service")
                        service_element.text = port_info.get('service', 'unknown')
                        if port_info.get('version'):
                            service_element.set("version", port_info['version'])
                    else:
                        # Assume que port_info é uma string como "80/tcp"
                        port_element = ET.SubElement(ports_element, "port")
                        port_element.set("number", port_info)
                        port_element.set("protocol", "tcp")
                        port_element.set("state", "open")
                        
                        service_element = ET.SubElement(port_element, "service")
                        service_element.text = info.services[i] if hasattr(info, 'services') and i < len(info.services) else "unknown"
        
        # Formata o XML para ser legível
        xmlstr = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(xmlstr)

class ComparisonReportGenerator:
    """
    Classe responsável por gerar relatórios de comparação entre dois scans de rede.
    """
    
    @staticmethod
    def export_comparison_report(
        comparison_data: Dict[str, Any], 
        output_file: str,
        format_type: str = ComparisonFormat.TEXT) -> bool:
        """
        Exporta os resultados de uma comparação para um arquivo no formato especificado.
        
        Args:
            comparison_data (Dict[str, Any]): Dados da comparação gerados pela função compare_scans()
            output_file (str): Caminho para o arquivo de saída
            format_type (str): Formato do relatório (text, json, csv, xml, html)
            
        Returns:
            bool: True se a exportação foi bem-sucedida, False caso contrário
        """
        format_type = ComparisonFormat.from_string(format_type)
        
        try:
            if format_type == ComparisonFormat.JSON:
                return ComparisonReportGenerator._export_comparison_to_json(comparison_data, output_file)
            elif format_type == ComparisonFormat.CSV:
                return ComparisonReportGenerator._export_comparison_to_csv(comparison_data, output_file)
            elif format_type == ComparisonFormat.XML:
                return ComparisonReportGenerator._export_comparison_to_xml(comparison_data, output_file)
            elif format_type == ComparisonFormat.HTML:
                return ComparisonReportGenerator._export_comparison_to_html(comparison_data, output_file)
            else:  # Default: TEXT
                return ComparisonReportGenerator._export_comparison_to_text(comparison_data, output_file)
        
        except Exception as e:
            from ..utils.logger import error
            error(f"Erro ao exportar comparação para {format_type}: {str(e)}")
            return False
    
    @staticmethod
    def _export_comparison_to_json(comparison_data: Dict[str, Any], output_file: str) -> bool:
        """Exporta a comparação para JSON"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(comparison_data, f, indent=4)
            from ..utils.logger import info
            info(f"Comparação exportada com sucesso para JSON: {output_file}")
            return True
        except Exception as e:
            from ..utils.logger import error
            error(f"Erro ao exportar comparação para JSON: {str(e)}")
            return False
    
    @staticmethod
    def _export_comparison_to_text(comparison_data: Dict[str, Any], output_file: str) -> bool:
        """Exporta a comparação para texto formatado"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                # Cabeçalho
                f.write("=" * 70 + "\n")
                f.write("ESK NMAP - RELATÓRIO DE COMPARAÇÃO DE SCANS\n")
                f.write("=" * 70 + "\n\n")
                
                # Informações gerais
                f.write(f"Rede: {comparison_data['network']}\n")
                f.write(f"Scan 1: {comparison_data['scan1']['timestamp']} (ID: {comparison_data['scan1']['id']})\n")
                f.write(f"Scan 2: {comparison_data['scan2']['timestamp']} (ID: {comparison_data['scan2']['id']})\n\n")
                
                # Resumo
                f.write("RESUMO DA COMPARAÇÃO:\n")
                f.write("-" * 70 + "\n")
                f.write(f"Total de hosts no scan 1: {comparison_data['summary']['total_hosts_before']}\n")
                f.write(f"Total de hosts no scan 2: {comparison_data['summary']['total_hosts_after']}\n")
                f.write(f"Hosts novos: {comparison_data['summary']['new_hosts']}\n")
                f.write(f"Hosts removidos: {comparison_data['summary']['removed_hosts']}\n")
                f.write(f"Hosts alterados: {comparison_data['summary']['changed_hosts']}\n")
                f.write(f"Hosts inalterados: {comparison_data['summary']['unchanged_hosts']}\n\n")
                
                # Detalhes dos hosts novos
                if comparison_data['new_hosts']:
                    f.write("HOSTS NOVOS:\n")
                    f.write("-" * 70 + "\n")
                    for ip, host in comparison_data['new_hosts'].items():
                        hostname = host.get('hostname', 'N/A')
                        mac = host.get('mac', 'N/A')
                        vendor = host.get('vendor', 'N/A')
                        f.write(f"IP: {ip}\n")
                        f.write(f"Hostname: {hostname}\n")
                        f.write(f"MAC: {mac}\n")
                        f.write(f"Fabricante: {vendor}\n")
                        
                        if host.get('ports'):
                            f.write("Portas abertas:\n")
                            for i, port in enumerate(host.get('ports', [])):
                                service = host.get('services', [])[i] if i < len(host.get('services', [])) else 'N/A'
                                f.write(f"  - {port}: {service}\n")
                        else:
                            f.write("Portas abertas: Nenhuma detectada\n")
                        f.write("\n")
                
                # Detalhes dos hosts removidos
                if comparison_data['removed_hosts']:
                    f.write("HOSTS REMOVIDOS:\n")
                    f.write("-" * 70 + "\n")
                    for ip, host in comparison_data['removed_hosts'].items():
                        hostname = host.get('hostname', 'N/A')
                        mac = host.get('mac', 'N/A')
                        vendor = host.get('vendor', 'N/A')
                        f.write(f"IP: {ip}\n")
                        f.write(f"Hostname: {hostname}\n")
                        f.write(f"MAC: {mac}\n")
                        f.write(f"Fabricante: {vendor}\n\n")
                
                # Detalhes dos hosts alterados
                if comparison_data['changed_hosts']:
                    f.write("HOSTS COM ALTERAÇÕES:\n")
                    f.write("-" * 70 + "\n")
                    for ip, changes in comparison_data['changed_hosts'].items():
                        f.write(f"IP: {ip}\n")
                        f.write(f"Hostname: {changes.get('hostname', 'N/A')}\n")
                        
                        if changes.get('new_ports'):
                            f.write("Novas portas:\n")
                            for port in changes.get('new_ports', []):
                                f.write(f"  - {port}\n")
                        
                        if changes.get('closed_ports'):
                            f.write("Portas fechadas:\n")
                            for port in changes.get('closed_ports', []):
                                f.write(f"  - {port}\n")
                        f.write("\n")
                
                f.write("=" * 70 + "\n")
                f.write(f"Relatório gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            from ..utils.logger import info
            info(f"Comparação exportada com sucesso para texto: {output_file}")
            return True
        except Exception as e:
            from ..utils.logger import error
            error(f"Erro ao exportar comparação para texto: {str(e)}")
            return False
    
    @staticmethod
    def _export_comparison_to_csv(comparison_data: Dict[str, Any], output_file: str) -> bool:
        """Exporta a comparação para CSV"""
        try:
            with open(output_file, 'w', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                
                # Cabeçalho
                writer.writerow(['Tipo', 'IP', 'Hostname', 'MAC', 'Vendor', 'Alteração', 'Detalhes'])
                
                # Hosts novos
                for ip, host in comparison_data['new_hosts'].items():
                    hostname = host.get('hostname', 'N/A')
                    mac = host.get('mac', 'N/A')
                    vendor = host.get('vendor', 'N/A')
                    ports_str = "; ".join(host.get('ports', []))
                    writer.writerow(['Novo', ip, hostname, mac, vendor, 'Host adicionado', ports_str])
                
                # Hosts removidos
                for ip, host in comparison_data['removed_hosts'].items():
                    hostname = host.get('hostname', 'N/A')
                    mac = host.get('mac', 'N/A')
                    vendor = host.get('vendor', 'N/A')
                    writer.writerow(['Removido', ip, hostname, mac, vendor, 'Host removido', ''])
                
                # Hosts alterados
                for ip, changes in comparison_data['changed_hosts'].items():
                    hostname = changes.get('hostname', 'N/A')
                    new_ports = "; ".join(changes.get('new_ports', []))
                    closed_ports = "; ".join(changes.get('closed_ports', []))
                    
                    if changes.get('new_ports'):
                        writer.writerow(['Alterado', ip, hostname, '', '', 'Novas portas', new_ports])
                    
                    if changes.get('closed_ports'):
                        writer.writerow(['Alterado', ip, hostname, '', '', 'Portas fechadas', closed_ports])
            
            from ..utils.logger import info
            info(f"Comparação exportada com sucesso para CSV: {output_file}")
            return True
        except Exception as e:
            from ..utils.logger import error
            error(f"Erro ao exportar comparação para CSV: {str(e)}")
            return False
    
    @staticmethod
    def _export_comparison_to_xml(comparison_data: Dict[str, Any], output_file: str) -> bool:
        """Exporta a comparação para XML"""
        try:
            doc = minidom.getDOMImplementation().createDocument(None, "comparison", None)
            root = doc.documentElement
            
            # Informações gerais - mudando para formato de elemento em vez de atributo
            network_elem = doc.createElement("network")
            network_elem.appendChild(doc.createTextNode(comparison_data['network']))
            root.appendChild(network_elem)
            
            date_elem = doc.createElement("date")
            date_elem.appendChild(doc.createTextNode(datetime.now().isoformat()))
            root.appendChild(date_elem)
            
            scan1_elem = doc.createElement("scan1")
            scan1_elem.setAttribute("id", str(comparison_data['scan1']['id']))
            scan1_elem.setAttribute("timestamp", comparison_data['scan1']['timestamp'])
            scan1_elem.setAttribute("profile", comparison_data['scan1']['profile'])
            scan1_elem.setAttribute("total_hosts", str(comparison_data['scan1']['total_hosts']))
            root.appendChild(scan1_elem)
            
            scan2_elem = doc.createElement("scan2")
            scan2_elem.setAttribute("id", str(comparison_data['scan2']['id']))
            scan2_elem.setAttribute("timestamp", comparison_data['scan2']['timestamp'])
            scan2_elem.setAttribute("profile", comparison_data['scan2']['profile'])
            scan2_elem.setAttribute("total_hosts", str(comparison_data['scan2']['total_hosts']))
            root.appendChild(scan2_elem)
            
            # Resumo
            summary = doc.createElement("summary")
            for key, value in comparison_data['summary'].items():
                summary.setAttribute(key, str(value))
            root.appendChild(summary)
            
            # Hosts novos
            new_hosts = doc.createElement("new_hosts")
            for ip, host in comparison_data['new_hosts'].items():
                host_elem = doc.createElement("host")
                host_elem.setAttribute("ip", ip)
                host_elem.setAttribute("hostname", host.get('hostname', ''))
                host_elem.setAttribute("mac", host.get('mac', ''))
                host_elem.setAttribute("vendor", host.get('vendor', ''))
                
                if host.get('ports'):
                    ports_elem = doc.createElement("ports")
                    for i, port in enumerate(host.get('ports', [])):
                        port_elem = doc.createElement("port")
                        port_elem.setAttribute("number", port)
                        service = host.get('services', [])[i] if i < len(host.get('services', [])) else ''
                        port_elem.setAttribute("service", service)
                        ports_elem.appendChild(port_elem)
                    host_elem.appendChild(ports_elem)
                
                new_hosts.appendChild(host_elem)
            root.appendChild(new_hosts)
            
            # Hosts removidos
            removed_hosts = doc.createElement("removed_hosts")
            for ip, host in comparison_data['removed_hosts'].items():
                host_elem = doc.createElement("host")
                host_elem.setAttribute("ip", ip)
                host_elem.setAttribute("hostname", host.get('hostname', ''))
                host_elem.setAttribute("mac", host.get('mac', ''))
                host_elem.setAttribute("vendor", host.get('vendor', ''))
                removed_hosts.appendChild(host_elem)
            root.appendChild(removed_hosts)
            
            # Hosts alterados
            changed_hosts = doc.createElement("changed_hosts")
            for ip, changes in comparison_data['changed_hosts'].items():
                host_elem = doc.createElement("host")
                host_elem.setAttribute("ip", ip)
                host_elem.setAttribute("hostname", changes.get('hostname', ''))
                
                if changes.get('new_ports'):
                    new_ports = doc.createElement("new_ports")
                    for port in changes.get('new_ports', []):
                        port_elem = doc.createElement("port")
                        port_elem.setAttribute("number", port)
                        new_ports.appendChild(port_elem)
                    host_elem.appendChild(new_ports)
                
                if changes.get('closed_ports'):
                    closed_ports = doc.createElement("closed_ports")
                    for port in changes.get('closed_ports', []):
                        port_elem = doc.createElement("port")
                        port_elem.setAttribute("number", port)
                        closed_ports.appendChild(port_elem)
                    host_elem.appendChild(closed_ports)
                
                changed_hosts.appendChild(host_elem)
            root.appendChild(changed_hosts)
            
            # Escrever para arquivo
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(doc.toprettyxml(indent="  "))
            
            from ..utils.logger import info
            info(f"Comparação exportada com sucesso para XML: {output_file}")
            return True
        except Exception as e:
            from ..utils.logger import error
            error(f"Erro ao exportar comparação para XML: {str(e)}")
            return False
    
    @staticmethod
    def _export_comparison_to_html(comparison_data: Dict[str, Any], output_file: str) -> bool:
        """Exporta a comparação para HTML com gráficos"""
        try:
            from ..utils.logger import debug
            debug("Iniciando exportação para HTML")
            debug(f"Dados da comparação: {comparison_data}")
            debug(f"Arquivo de saída: {output_file}")
            debug(f"network: {comparison_data['network']}")
            debug(f"scan1_time: {comparison_data['scan1']['timestamp']}")
            debug(f"scan1_id: {comparison_data['scan1']['id']}")
            debug(f"scan2_time: {comparison_data['scan2']['timestamp']}")
            debug(f"scan2_id: {comparison_data['scan2']['id']}")
            debug(f"total_hosts_before: {comparison_data['summary']['total_hosts_before']}")
            debug(f"total_hosts_after: {comparison_data['summary']['total_hosts_after']}")
            debug(f"new_hosts_count: {comparison_data['summary']['new_hosts']}")
            debug(f"removed_hosts_count: {comparison_data['summary']['removed_hosts']}")
            debug(f"changed_hosts_count: {comparison_data['summary']['changed_hosts']}")
            debug(f"unchanged_hosts_count: {comparison_data['summary']['unchanged_hosts']}")

            # HTML base para relatório com gráficos
            html = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ESK NMAP - Relatório de Comparação</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2, h3 { color: #333; }
        .header { background-color: #f0f0f0; padding: 10px; border-radius: 5px; }
        .summary { background-color: #e7f3fe; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .new { background-color: #e6ffec; }
        .removed { background-color: #ffebe9; }
        .changed { background-color: #fff8c5; }
        table { border-collapse: collapse; width: 100%; margin: 15px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:hover { background-color: #f5f5f5; }
        .chart-container { width: 600px; height: 400px; margin: 20px auto; }
        .footer { margin-top: 30px; font-size: 0.8em; color: #666; text-align: center; }
        .ports-list { margin: 5px 0; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.7.1/dist/chart.min.js"></script>
</head>
<body>
    <div class="header">
        <h1>ESK NMAP - Relatório de Comparação de Scans</h1>
        <p><strong>Rede:</strong> {network}</p>
        <p><strong>Scan 1:</strong> {scan1_time} (ID: {scan1_id})</p>
        <p><strong>Scan 2:</strong> {scan2_time} (ID: {scan2_id})</p>
        <p><strong>Relatório gerado em:</strong> {generation_time}</p>
    </div>

    <div class="summary">
        <h2>Resumo da Comparação</h2>
        <p><strong>Total de hosts no scan 1:</strong> {total_hosts_before}</p>
        <p><strong>Total de hosts no scan 2:</strong> {total_hosts_after}</p>
        <p><strong>Hosts novos:</strong> {new_hosts_count}</p>
        <p><strong>Hosts removidos:</strong> {removed_hosts_count}</p>
        <p><strong>Hosts alterados:</strong> {changed_hosts_count}</p>
        <p><strong>Hosts inalterados:</strong> {unchanged_hosts_count}</p>
    </div>

    <div class="chart-container">
        <canvas id="changesChart"></canvas>
    </div>

    <div class="chart-container">
        <canvas id="hostsComparisonChart"></canvas>
    </div>

    {new_hosts_html}
    
    {removed_hosts_html}
    
    {changed_hosts_html}

    <div class="footer">
        <p>ESK NMAP &copy; 2025 Eskel Cybersecurity</p>
    </div>
    
    <script>
        // Gráfico de mudanças
        const changesCtx = document.getElementById('changesChart').getContext('2d');
        const changesChart = new Chart(changesCtx, {{
            type: 'pie',
            data: {{
                labels: ['Novos', 'Removidos', 'Alterados', 'Inalterados'],
                datasets: [{{
                    data: [{new_hosts_count}, {removed_hosts_count}, {changed_hosts_count}, {unchanged_hosts_count}],
                    backgroundColor: [
                        'rgba(75, 192, 192, 0.7)',
                        'rgba(255, 99, 132, 0.7)',
                        'rgba(255, 205, 86, 0.7)',
                        'rgba(201, 203, 207, 0.7)'
                    ],
                    borderWidth: 1
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                    }},
                    title: {{
                        display: true,
                        text: 'Distribuição de Mudanças'
                    }}
                }}
            }}
        }});
        
        // Gráfico de comparação de hosts
        const hostsCtx = document.getElementById('hostsComparisonChart').getContext('2d');
        const hostsChart = new Chart(hostsCtx, {{
            type: 'bar',
            data: {{
                labels: ['Scan 1', 'Scan 2'],
                datasets: [{{
                    label: 'Total de Hosts',
                    data: [{total_hosts_before}, {total_hosts_after}],
                    backgroundColor: [
                        'rgba(54, 162, 235, 0.7)',
                        'rgba(153, 102, 255, 0.7)'
                    ],
                    borderColor: [
                        'rgb(54, 162, 235)',
                        'rgb(153, 102, 255)'
                    ],
                    borderWidth: 1
                }}]
            }},
            options: {{
                responsive: true,
                scales: {{
                    y: {{
                        beginAtZero: true
                    }}
                }},
                plugins: {{
                    title: {{
                        display: true,
                        text: 'Comparação do Número de Hosts'
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""
            
            # Geração das seções HTML
            
            # Hosts novos
            new_hosts_html = "<h2>Hosts Novos</h2>\n"
            if comparison_data['new_hosts']:
                new_hosts_html += "<table>\n"
                new_hosts_html += "<tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Fabricante</th><th>Portas</th></tr>\n"
                for ip, host in comparison_data['new_hosts'].items():
                    hostname = host.get('hostname', 'N/A')
                    mac = host.get('mac', 'N/A')
                    vendor = host.get('vendor', 'N/A')
                    
                    ports_html = "<div class='ports-list'>"
                    if host.get('ports'):
                        for i, port in enumerate(host.get('ports', [])):
                            service = host.get('services', [])[i] if i < len(host.get('services', [])) else 'N/A'
                            ports_html += f"<div>{port}: {service}</div>"
                    else:
                        ports_html += "Nenhuma porta aberta detectada"
                    ports_html += "</div>"
                    
                    new_hosts_html += f"<tr class='new'><td>{ip}</td><td>{hostname}</td><td>{mac}</td><td>{vendor}</td><td>{ports_html}</td></tr>\n"
                new_hosts_html += "</table>\n"
            else:
                new_hosts_html += "<p>Nenhum host novo detectado.</p>\n"
            
            # Hosts removidos
            removed_hosts_html = "<h2>Hosts Removidos</h2>\n"
            if comparison_data['removed_hosts']:
                removed_hosts_html += "<table>\n"
                removed_hosts_html += "<tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Fabricante</th></tr>\n"
                for ip, host in comparison_data['removed_hosts'].items():
                    hostname = host.get('hostname', 'N/A')
                    mac = host.get('mac', 'N/A')
                    vendor = host.get('vendor', 'N/A')
                    removed_hosts_html += f"<tr class='removed'><td>{ip}</td><td>{hostname}</td><td>{mac}</td><td>{vendor}</td></tr>\n"
                removed_hosts_html += "</table>\n"
            else:
                removed_hosts_html += "<p>Nenhum host removido.</p>\n"
            
            # Hosts alterados
            changed_hosts_html = "<h2>Hosts com Alterações</h2>\n"
            if comparison_data['changed_hosts']:
                changed_hosts_html += "<table>\n"
                changed_hosts_html += "<tr><th>IP</th><th>Hostname</th><th>Novas Portas</th><th>Portas Fechadas</th></tr>\n"
                for ip, changes in comparison_data['changed_hosts'].items():
                    hostname = changes.get('hostname', 'N/A')
                    
                    new_ports_html = "<div class='ports-list'>"
                    if changes.get('new_ports'):
                        for port in changes.get('new_ports', []):
                            new_ports_html += f"<div>{port}</div>"
                    else:
                        new_ports_html += "Nenhuma"
                    new_ports_html += "</div>"
                    
                    closed_ports_html = "<div class='ports-list'>"
                    if changes.get('closed_ports'):
                        for port in changes.get('closed_ports', []):
                            closed_ports_html += f"<div>{port}</div>"
                    else:
                        closed_ports_html += "Nenhuma"
                    closed_ports_html += "</div>"
                    
                    changed_hosts_html += f"<tr class='changed'><td>{ip}</td><td>{hostname}</td><td>{new_ports_html}</td><td>{closed_ports_html}</td></tr>\n"
                changed_hosts_html += "</table>\n"
            else:
                changed_hosts_html += "<p>Nenhum host alterado.</p>\n"
            
            # Substituir placeholders - usamos double-brackets para as chaves do JavaScript
            html = html.format(
                network=comparison_data['network'],
                scan1_time=comparison_data['scan1']['timestamp'],
                scan1_id=comparison_data['scan1']['id'],
                scan2_time=comparison_data['scan2']['timestamp'],
                scan2_id=comparison_data['scan2']['id'],
                generation_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                total_hosts_before=comparison_data['summary']['total_hosts_before'],
                total_hosts_after=comparison_data['summary']['total_hosts_after'],
                new_hosts_count=comparison_data['summary']['new_hosts'],
                removed_hosts_count=comparison_data['summary']['removed_hosts'],
                changed_hosts_count=comparison_data['summary']['changed_hosts'],
                unchanged_hosts_count=comparison_data['summary']['unchanged_hosts'],
                new_hosts_html=new_hosts_html,
                removed_hosts_html=removed_hosts_html,
                changed_hosts_html=changed_hosts_html
            )
            
            # Escrever para arquivo
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html)
            
            from ..utils.logger import info
            info(f"Comparação exportada com sucesso para HTML: {output_file}")
            return True
        except Exception as e:
            from ..utils.logger import error
            error(f"Erro ao exportar comparação para HTML: {str(e)}")
            return False