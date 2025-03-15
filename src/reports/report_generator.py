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

from typing import Dict
import time
from ..core.scanner import HostInfo

class ReportGenerator:
    @staticmethod
    def create_filename(network: str) -> str:
        """Cria o nome do arquivo de relatório baseado na rede e timestamp"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        # Substitui os pontos por underscores no nome da rede
        network_formatted = network.replace('.', '_').replace('/', '_')
        return f"esk_nmap_report_{network_formatted}_{timestamp}.txt"

    @staticmethod
    def generate_report(filename: str, hosts: Dict[str, HostInfo], network: str) -> None:
        """Gera o relatório detalhado do scan"""
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