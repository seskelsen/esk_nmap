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

import os
from typing import Dict, Optional
from prettytable import PrettyTable
from ..core.scanner import HostInfo, NetworkScanner
from ..utils.logger import info, error, debug

class CLI:
    """Interface de linha de comando do ESK_NMAP"""

    def __init__(self):
        # Inicialização da CLI sem ConfigManager
        pass

    def run(self):
        # Implementação do método run
        pass

    @staticmethod
    def show_banner():
        print("=" * 60)
        print("ESK_NMAP - Scanner de Rede da Eskel Cybersecurity")
        print("=" * 60)
        print()

    @staticmethod
    def show_usage(program_name: str):
        print("Uso: python", program_name, "<rede>")
        print("Exemplo: python", program_name, "192.168.1.0/24")

    @staticmethod
    def ask_continue_without_root() -> bool:
        while True:
            response = input("\nContinuar sem privilégios de root? (s/n): ").lower()
            if response in ['s', 'n']:
                return response == 's'
            print("Por favor, responda com 's' ou 'n'")

    @staticmethod
    def ask_detailed_scan() -> bool:
        """Pergunta ao usuário se deseja realizar um scan detalhado"""
        while True:
            response = input("\nDeseja realizar um scan detalhado dos hosts? (s/n): ").strip().lower()
            if response in ['s', 'sim', 'y', 'yes']:
                return True
            if response in ['n', 'nao', 'não', 'no']:
                return False
            print("Por favor, responda 's' ou 'n'.")

    @staticmethod
    def display_hosts_table(hosts: Dict[str, HostInfo]) -> None:
        """Exibe a tabela de hosts encontrados"""
        if not hosts:
            print("\nNenhum host encontrado na rede.")
            return

        table = PrettyTable()
        table.field_names = ["IP", "Status", "Hostname", "MAC", "Fabricante"]
        table.align = "l"  # Alinhamento à esquerda
        
        for host in hosts.values():
            table.add_row([
                host.ip,
                host.status,
                host.hostname,
                host.mac,
                host.vendor
            ])
        
        print("\nHosts descobertos:")
        print(table)
        print(f"\nTotal de hosts descobertos: {len(hosts)}")

    @staticmethod
    def display_scan_profiles() -> None:
        print("\nPerfis de Scan Disponíveis:")
        print("=" * 60)
        print("\nBásico (basic)")
        print("-" * len("Básico (basic)"))
        print("Descrição: Scan básico de rede")
        print("Timing: T3")
        print("Portas: 80,443")
        print("Opções: -sV -O")

    @staticmethod
    def select_scan_profile() -> str:
        CLI.display_scan_profiles()
        while True:
            print("\nEscolha um perfil de scan:")
            print("- basic")
            choice = input("\nPerfil (Enter para usar 'basic'): ").strip().lower()
            if not choice:
                return 'basic'
            if choice == 'basic':
                return choice
            print("\nPerfil inválido. Tente novamente.")