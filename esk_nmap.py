#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ESK NMAP - Network Scanner Tool
Copyright (C) 2025 Eskel Cybersecurity
Author: Sigmar Eskelsen
"""

import os
import sys
import ipaddress
from src.ui.cli import CLI
from src.core.scanner import NetworkScanner
from src.reports.report_generator import ReportGenerator
from src.utils.system_utils import SystemUtils
from src.utils.logger import ESKLogger, info, error, debug
from src.utils.error_handler import ErrorHandler, ErrorCategory

def validate_network(network: str) -> bool:
    """Valida o endereço de rede fornecido"""
    try:
        ipaddress.ip_network(network)
        return True
    except ValueError:
        return False

def main():
    # Configuração inicial do logger
    logger = ESKLogger()
    
    try:
        # Verifica argumentos
        if len(sys.argv) != 2:
            CLI.show_banner()
            CLI.show_usage(sys.argv[0])
            sys.exit(1)

        network = sys.argv[1]
        if not validate_network(network):
            error(f"Rede inválida: {network}")
            sys.exit(1)

        # Verifica permissões e caminho do Nmap
        utils = SystemUtils()
        if not utils.check_root():
            warning = "Aviso: Executando sem privilégios de root. Algumas funcionalidades podem ser limitadas."
            print(warning)
            if not CLI.ask_continue_without_root():
                sys.exit(1)

        nmap_path = utils.find_nmap_path()  # Corrigido de get_nmap_path para find_nmap_path
        if not nmap_path:
            error("Nmap não encontrado. Por favor, instale o Nmap e tente novamente.")
            sys.exit(1)

        # Exibe banner e perfis disponíveis
        CLI.show_banner()
        selected_profile = CLI.select_scan_profile()
        
        # Inicializa o scanner com o perfil selecionado
        scanner = NetworkScanner(nmap_path)
        scanner.set_scan_profile(selected_profile)
        info(f"Iniciando scan da rede {network}...")

        # Scan inicial de descoberta
        debug("Executando scan de descoberta")
        hosts = scanner.scan_network(network)
        CLI.display_hosts_table(hosts)

        if hosts and CLI.ask_detailed_scan():
            # Aqui é a mudança: passamos o dicionário de hosts completo
            detailed_results = {}
            for ip, host_info in hosts.items():
                debug(f"Iniciando scan detalhado do host: {ip}")
                detailed_scan = scanner.detailed_scan({ip})
                if ip in detailed_scan:
                    # Preserva as informações iniciais e adiciona as portas
                    host_info.ports = detailed_scan[ip].ports
                    host_info.services = detailed_scan[ip].services
                    detailed_results[ip] = host_info
                else:
                    # Se não encontrou portas, mantém as informações iniciais
                    detailed_results[ip] = host_info

            # Gerar relatório usando o ReportGenerator
            report_file = ReportGenerator.create_filename(network)
            info(f"Gerando relatório em {report_file}")
            ReportGenerator.generate_report(report_file, detailed_results, network)
            info(f"Relatório completo salvo em: {report_file}")
            
            # Abre o arquivo do relatório para exibição
            with open(report_file, 'r', encoding='utf-8') as f:
                print("\n" + f.read())

    except Exception as e:
        error(f"ERRO: {str(e)}")
        sys.exit(1)

    info("Scan concluído com sucesso!")

if __name__ == "__main__":
    main()