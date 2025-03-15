#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ESK NMAP - Network Scanner Tool
Copyright (C) 2025 Eskel Cybersecurity
Author: Sigmar Eskelsen

Este programa é um software livre; você pode redistribuí-lo e/ou
modificá-lo sob os termos da Licença Pública Geral GNU como publicada
pela Free Software Foundation; na versão 2 da Licença, ou
(a seu critério) qualquer versão posterior.

Este programa é distribuído na esperança de que possa ser útil,
mas SEM NENHUMA GARANTIA; sem uma garantia implícita de ADEQUAÇÃO
a qualquer MERCADO ou APLICAÇÃO EM PARTICULAR. Veja a
Licença Pública Geral GNU para mais detalhes.
"""

from typing import Dict, List
import time
import json
import csv
import xml.etree.ElementTree as ET
from xml.dom import minidom
from ..core.scanner import HostInfo
from enum import Enum, auto

class ReportFormat(Enum):
    """Formatos suportados para relatórios"""
    TEXT = auto()
    JSON = auto()
    CSV = auto()
    XML = auto()

class ReportGenerator:
    @staticmethod
    def create_filename(network: str, format: ReportFormat = ReportFormat.TEXT) -> str:
        """Cria o nome do arquivo de relatório baseado na rede, timestamp e formato"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        # Substitui os pontos por underscores no nome da rede
        network_formatted = network.replace('.', '_').replace('/', '_')
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

    @staticmethod
    def _generate_text_report(filename: str, hosts: Dict[str, HostInfo], network: str) -> None:
        """Gera o relatório em formato texto"""
        with open(filename, "w", encoding="utf-8") as f:
            # Cabeçalho
            f.write("=" * 60 + "\n")
            f.write("ESK_NMAP - Scanner de Rede da Eskel Cybersecurity\n")
            f.write("=" * 60 + "\n")
            f.write(f"Data/Hora: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Rede: {network}\n")
            f.write("=" * 60 + "\n\n")

            # Resumo inicial
            f.write("RESUMO:\n")
            f.write(f"Total de hosts ativos: {len(hosts)}\n")
            f.write(f"Hosts com portas abertas: {len([h for h in hosts.values() if h.ports])}\n\n")

            # Tabela de hosts descobertos
            f.write("HOSTS DESCOBERTOS:\n")
            f.write("+" + "-" * 15 + "+" + "-" * 8 + "+" + "-" * 35 + "+" + "-" * 19 + "+" + "-" * 20 + "+\n")
            f.write("| {:<13} | {:<6} | {:<33} | {:<17} | {:<18} |\n".format(
                "IP", "Status", "Hostname", "MAC", "Fabricante"))
            f.write("+" + "-" * 15 + "+" + "-" * 8 + "+" + "-" * 35 + "+" + "-" * 19 + "+" + "-" * 20 + "+\n")

            for ip, info in hosts.items():
                hostname = info.hostname if info.hostname != "N/A" else ""
                mac = info.mac if info.mac != "N/A" else ""
                vendor = info.vendor if info.vendor != "N/A" else ""
                
                f.write("| {:<13} | {:<6} | {:<33} | {:<17} | {:<18} |\n".format(
                    ip, info.status, hostname[:33], mac[:17], vendor[:18]))
                f.write("+" + "-" * 15 + "+" + "-" * 8 + "+" + "-" * 35 + "+" + "-" * 19 + "+" + "-" * 20 + "+\n")

            f.write(f"\nTotal de hosts descobertos: {len(hosts)}\n")
            f.write("\n" + "=" * 60 + "\n")

            # Detalhes das portas de cada host
            f.write("\nDETALHES DAS PORTAS:\n")
            f.write("=" * 60 + "\n\n")

            for ip, info in hosts.items():
                f.write(f"HOST: {ip}\n")
                if info.hostname != "N/A":
                    f.write(f"Hostname: {info.hostname}\n")
                
                if info.ports:
                    f.write("\nPortas abertas:\n")
                    f.write("+" + "-" * 15 + "+" + "-" * 50 + "+\n")
                    f.write("| {:<13} | {:<48} |\n".format("PORTA", "SERVIÇO"))
                    f.write("+" + "-" * 15 + "+" + "-" * 50 + "+\n")
                    
                    for port, service in zip(info.ports, info.services):
                        f.write("| {:<13} | {:<48} |\n".format(port, service[:48]))
                        f.write("+" + "-" * 15 + "+" + "-" * 50 + "+\n")
                else:
                    f.write("\nNenhuma porta aberta encontrada\n")
                
                f.write("\n" + "=" * 60 + "\n")

    @staticmethod
    def _generate_json_report(filename: str, hosts: Dict[str, HostInfo], network: str) -> None:
        """Gera o relatório em formato JSON"""
        report_data = {
            "metadata": {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "network": network,
                "total_hosts": len(hosts),
                "hosts_with_open_ports": len([h for h in hosts.values() if h.ports])
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
                    {"port": port, "service": service}
                    for port, service in zip(info.ports, info.services)
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
            writer.writerow(["# Hosts com portas abertas", str(len([h for h in hosts.values() if h.ports]))])
            writer.writerow([])  # Linha em branco para separação
            
            # Escreve o cabeçalho da tabela de hosts
            writer.writerow(["IP", "Status", "Hostname", "MAC", "Fabricante", "Portas", "Serviços"])
            
            # Escreve os dados dos hosts
            for ip, info in hosts.items():
                hostname = info.hostname if info.hostname != "N/A" else ""
                mac = info.mac if info.mac != "N/A" else ""
                vendor = info.vendor if info.vendor != "N/A" else ""
                ports = "|".join(info.ports) if info.ports else ""
                services = "|".join(info.services) if info.services else ""
                
                writer.writerow([
                    ip,
                    info.status,
                    hostname,
                    mac,
                    vendor,
                    ports,
                    services
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
        ET.SubElement(metadata, "hosts_with_open_ports").text = str(len([h for h in hosts.values() if h.ports]))
        
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
                ports = ET.SubElement(host, "ports")
                for port, service in zip(info.ports, info.services):
                    port_element = ET.SubElement(ports, "port")
                    port_element.set("number", port)
                    ET.SubElement(port_element, "service").text = service
        
        # Formata o XML para ser legível
        xmlstr = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(xmlstr)