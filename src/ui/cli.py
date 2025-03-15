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
import argparse
from typing import Dict, Optional, List
from prettytable import PrettyTable
from ..core.scanner import HostInfo, NetworkScanner
from ..utils.config_manager import ConfigManager
from ..utils.logger import info, error, debug, warning

class CLI:
    """Interface de linha de comando do ESK_NMAP"""

    def __init__(self):
        # Inicialização da CLI com ConfigManager
        self.config_manager = ConfigManager()
    
    @staticmethod
    def parse_arguments():
        """Analisa os argumentos da linha de comando"""
        parser = argparse.ArgumentParser(
            description="ESK NMAP - Network Scanner Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        parser.add_argument("network", help="Rede a ser escaneada (ex: 192.168.1.0/24)")
        parser.add_argument("--config", "-c", help="Caminho para arquivo de configuração personalizado")
        parser.add_argument("--profile", "-p", help="Perfil de scan a ser utilizado")
        parser.add_argument("--output", "-o", help="Arquivo de saída para o relatório")
        parser.add_argument("--verbose", "-v", action="count", default=0, help="Aumentar nível de verbosidade")
        parser.add_argument("--quiet", "-q", action="store_true", help="Modo silencioso")
        
        return parser.parse_args()

    @staticmethod
    def show_banner():
        print("=" * 60)
        print("ESK_NMAP - Scanner de Rede da Eskel Cybersecurity")
        print("=" * 60)
        print()

    @staticmethod
    def show_usage(program_name: str):
        print("Uso: python", program_name, "<rede> [opções]")
        print("Exemplo: python", program_name, "192.168.1.0/24 --profile stealth")
        print("\nOpções:")
        print("  --config, -c  : Arquivo de configuração personalizado")
        print("  --profile, -p : Perfil de scan (basic, stealth, version, complete)")
        print("  --output, -o  : Arquivo de saída para o relatório")
        print("  --verbose, -v : Aumentar nível de verbosidade")
        print("  --quiet, -q   : Modo silencioso")

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

    def display_scan_profiles(self) -> None:
        """Exibe os perfis de scan disponíveis usando o ConfigManager"""
        print("\nPerfis de Scan Disponíveis:")
        print("=" * 60)
        
        # Obter perfis do ConfigManager
        config = self.config_manager._config
        profiles = config.get('scan_profiles', {})
        
        for key, profile in profiles.items():
            print(f"\n{profile['name']} ({key})")
            print("-" * len(f"{profile['name']} ({key})"))
            print(f"Descrição: {profile['description']}")
            print(f"Timing: T{profile['timing']}")
            print(f"Portas: {profile['ports']}")
            print(f"Opções: {' '.join(profile['options'])}")

    def select_scan_profile(self) -> str:
        """Seleciona um perfil de scan"""
        self.display_scan_profiles()
        
        # Obter perfis do ConfigManager
        config = self.config_manager._config
        profiles = config.get('scan_profiles', {})
        profile_names = list(profiles.keys())
        
        while True:
            print("\nEscolha um perfil de scan:")
            print("- " + "\n- ".join(profile_names))
            choice = input(f"\nPerfil (Enter para usar '{profile_names[0]}'): ").strip().lower()
            if not choice:
                return profile_names[0]
            if choice in profile_names:
                return choice
            print(f"\nPerfil inválido. Escolha um dos perfis disponíveis: {', '.join(profile_names)}")

    def get_available_profiles(self) -> List[str]:
        """Retorna a lista de perfis disponíveis"""
        config = self.config_manager._config
        profiles = config.get('scan_profiles', {})
        return list(profiles.keys())