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
                "hosts_with_open_ports": len([h for h in hosts.values() if any(p.get('state', '').lower() == 'open' for p in h.ports)])
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
                "ports": [port.get('port', port) for port in info.ports],
                "services": info.services if hasattr(info, 'services') else []
            }

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