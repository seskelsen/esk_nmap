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
from src.core.history_manager import HistoryManager  # Nova importação
from src.reports.report_generator import ReportGenerator, ReportFormat
from src.utils.system_utils import SystemUtils
from src.utils.logger import ESKLogger, info, error, debug, warning
from src.utils.error_handler import ErrorHandler, ErrorCategory
from src.utils.config_manager import ConfigManager

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
        # Instancia a CLI e faz o parse dos argumentos
        cli = CLI()
        args = cli.parse_arguments()
        
        # Verifica se a rede é válida
        if not validate_network(args.network):
            error(f"Rede inválida: {args.network}")
            sys.exit(1)
        
        # Carrega configuração personalizada se especificada
        config_manager = ConfigManager(args.config) if args.config else ConfigManager()
        
        # Verifica permissões e caminho do Nmap
        utils = SystemUtils()
        if not utils.check_root():
            warning_msg = "Aviso: Executando sem privilégios de root. Algumas funcionalidades podem ser limitadas."
            warning(warning_msg)
            print(warning_msg)
            if not args.quiet and not cli.ask_continue_without_root():
                sys.exit(1)

        nmap_path = utils.find_nmap_path()
        if not nmap_path:
            error("Nmap não encontrado. Por favor, instale o Nmap e tente novamente.")
            sys.exit(1)

        # Exibe banner se não estiver em modo silencioso
        if not args.quiet:
            cli.show_banner()
        
        # Seleciona o perfil de scan (da linha de comando ou interativamente)
        if args.profile and args.profile in cli.get_available_profiles():
            selected_profile = args.profile
            if not args.quiet:
                print(f"Usando perfil de scan especificado: {selected_profile}")
        else:
            if args.profile:
                warning(f"Perfil '{args.profile}' não encontrado. Selecione um perfil disponível.")
            
            # Se estiver em modo silencioso, usa o perfil basic por padrão
            if args.quiet:
                selected_profile = 'basic'
            else:
                selected_profile = cli.select_scan_profile()
        
        # Inicializa o scanner com o perfil selecionado
        scanner = NetworkScanner(nmap_path)
        scanner.set_quiet_mode(args.quiet)
        
        info(f"Iniciando scan da rede {args.network}...")

        # Scan inicial de descoberta (sempre executado)
        debug("Executando scan de descoberta")
        hosts = scanner.scan_network(args.network)
        
        # Exibe os resultados se não estiver em modo silencioso
        if not args.quiet:
            cli.display_hosts_table(hosts)
            print(f"\nTotal de hosts descobertos: {len(hosts)}")

        # Se houver hosts e o usuário quiser scan detalhado
        if hosts and (args.quiet or cli.ask_detailed_scan()):
            info("Iniciando scan detalhado dos hosts...")
            scanner.set_scan_profile(selected_profile)  # Define o perfil para o scan detalhado
            detailed_results = scanner.detailed_scan(hosts)  # Passa o dicionário completo
            
            # Exibe resultados detalhados se não estiver em modo silencioso
            if not args.quiet:
                print("\nResultados do scan detalhado:")
                cli.display_hosts_table(detailed_results)
        else:
            detailed_results = hosts

        # Salva os resultados no histórico
        try:
            history_manager = HistoryManager()
            scan_id = history_manager.save_scan_results(args.network, detailed_results, selected_profile)
            if not args.quiet:
                print(f"\nResultados salvos no histórico com ID: {scan_id}")
        except Exception as e:
            warning(f"Não foi possível salvar os resultados no histórico: {str(e)}")

        # Gera o relatório
        if args.output or not args.quiet:
            report_format = ReportFormat[args.format.upper()]
            report_file = args.output or ReportGenerator.create_filename(args.network, report_format)
            
            info(f"Gerando relatório em {report_file}")
            ReportGenerator.generate_report(report_file, detailed_results, args.network, report_format)
            info(f"Relatório completo salvo em: {report_file}")
            
            # Se não estiver em modo silencioso e for formato texto, exibe o relatório
            if not args.quiet and report_format == ReportFormat.TEXT:
                with open(report_file, 'r', encoding='utf-8') as f:
                    print("\n" + f.read())

    except KeyboardInterrupt:
        print("\nOperação cancelada pelo usuário.")
        sys.exit(0)
    except Exception as e:
        error(f"ERRO: {str(e)}")
        sys.exit(1)

    info("Scan concluído com sucesso!")

if __name__ == "__main__":
    main()