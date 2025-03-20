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
from datetime import datetime
from typing import Dict, Optional, List
from prettytable import PrettyTable
from ..core.scanner import HostInfo, NetworkScanner
from ..core.history_manager import HistoryManager  # Nova importação
from ..utils.config_manager import ConfigManager
from ..utils.logger import info, error, debug, warning
from ..reports.report_generator import ReportFormat

class CLI:
    """Interface de linha de comando do ESK_NMAP"""

    def __init__(self):
        # Inicialização da CLI com ConfigManager e HistoryManager
        self.config_manager = ConfigManager()
        self.history_manager = HistoryManager()
        self.scanner = NetworkScanner()
        self.last_results = None

    @staticmethod
    def show_banner():
        """Alias para show_header para manter compatibilidade com código existente"""
        CLI.show_header()

    @staticmethod
    def show_header():
        """Exibe o cabeçalho do programa"""
        print("=" * 60)
        print("ESK_NMAP - Scanner de Rede da Eskel Cybersecurity")
        print("=" * 60)
        print()

    @staticmethod
    def parse_arguments():
        """Configura e processa os argumentos da linha de comando"""
        parser = argparse.ArgumentParser(description='ESK_NMAP - Scanner de Rede')

        # Argumentos globais
        parser.add_argument("--verbose", "-v", action="count", default=0,
                          help="Aumentar nível de verbosidade")
        parser.add_argument("--quiet", "-q", action="store_true",
                          help="Modo silencioso")
        parser.add_argument("--config", "-c",
                          help="Caminho para arquivo de configuração personalizado")

        # Subcomandos
        subparsers = parser.add_subparsers(dest='command', help='Comandos disponíveis')

        # Comando scan
        scan_parser = subparsers.add_parser('scan', help='Executar um novo scan')
        scan_parser.add_argument("--network",
                               help="Rede a ser escaneada (ex: 192.168.1.0/24)")
        scan_parser.add_argument("--ip",
                               help="IP específico para scan")
        scan_parser.add_argument("--profile", "-p",
                               help="Perfil de scan a ser utilizado")
        scan_parser.add_argument("--output", "-o",
                               help="Arquivo de saída para o relatório")
        scan_parser.add_argument("--format", "-f",
                               choices=[f.name.lower() for f in ReportFormat],
                               default="text",
                               help="Formato do relatório (text, json, csv, xml)")
        scan_parser.add_argument("--batch-size", "-b", type=int, default=10,
                               help="Número de hosts por lote")
        scan_parser.add_argument("--max-threads", "-t", type=int, default=5,
                               help="Número máximo de threads")
        scan_parser.set_defaults(func=lambda args: CLI().scan(args))

        # Comando history
        history_parser = subparsers.add_parser('history', help='Gerenciar histórico')
        history_parser.add_argument("--limit", type=int, default=10,
                                  help="Número máximo de registros")
        history_parser.set_defaults(func=lambda args: CLI().history(args))

        # Comando report
        report_parser = subparsers.add_parser('report', help='Gerar relatórios')
        report_parser.add_argument("--output", "-o", required=True,
                                 help="Arquivo de saída")
        report_parser.add_argument("--format", "-f",
                                 choices=[f.name.lower() for f in ReportFormat],
                                 default="text",
                                 help="Formato do relatório")
        report_parser.add_argument("--use-history", action="store_true",
                                 help="Usar dados do histórico")
        report_parser.add_argument("--index", type=int,
                                 help="Índice do scan no histórico")
        report_parser.set_defaults(func=lambda args: CLI().report(args))

        return parser.parse_args()


    @staticmethod
    def show_usage(program_name: str):
        print("Uso: python", program_name, "<rede> [opções]")
        print("Exemplo: python", program_name, "192.168.1.0/24 --profile stealth")
        print("\nOpções:")
        print("  --config, -c  : Arquivo de configuração personalizado")
        print("  --profile, -p : Perfil de scan (basic, stealth, version, complete)")
        print("  --output, -o  : Arquivo de saída para o relatório")
        print("  --format, -f  : Formato do relatório (text, json, csv, xml)")
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

    def handle_history_commands(self, args) -> None:
        """Gerencia os comandos relacionados ao histórico"""
        if args.history_command == 'list':
            self.display_scan_list(args.network, args.limit)
        elif args.history_command == 'show':
            self.display_scan_details(args.id, args.output, args.format)
        elif args.history_command == 'compare':
            self.display_scan_comparison(args.id1, args.id2, args.output)
        elif args.history_command == 'delete':
            self.delete_scan(args.id)
    
    def display_scan_list(self, network: Optional[str] = None, limit: int = 10) -> None:
        """Exibe a lista de scans realizados"""
        if network:
            scans = self.history_manager.get_scans_by_network(network, limit)
            print(f"\nScans encontrados para a rede {network}:")
        else:
            scans = self.history_manager.get_scan_list(limit)
            print(f"\nÚltimos {limit} scans realizados:")
        
        if not scans:
            print("Nenhum scan encontrado.")
            return
        
        table = PrettyTable()
        table.field_names = ["ID", "Data", "Rede", "Perfil", "Total Hosts"]
        table.align = "l"
        
        for scan in scans:
            date = datetime.fromisoformat(scan['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            table.add_row([
                scan['id'],
                date,
                scan['network'],
                scan['scan_profile'],
                scan['total_hosts']
            ])
        
        print(table)
    
    def display_scan_details(self, scan_id: int, output: Optional[str] = None, format: str = 'text') -> None:
        """Exibe os detalhes de um scan específico"""
        scan = self.history_manager.get_scan_by_id(scan_id)
        if not scan:
            print(f"\nScan {scan_id} não encontrado.")
            return
        
        if output and format == 'json':
            if self.history_manager.export_scan_to_json(scan_id, output):
                print(f"\nResultados do scan {scan_id} exportados para {output}")
                return
            print(f"\nErro ao exportar scan {scan_id}")
            return
        
        print(f"\nDetalhes do Scan {scan_id}:")
        print("=" * 60)
        print(f"Data: {datetime.fromisoformat(scan['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Rede: {scan['network']}")
        print(f"Perfil: {scan['scan_profile']}")
        print(f"Total de Hosts: {scan['total_hosts']}")
        print("\nHosts Encontrados:")
        
        self.display_hosts_table(scan['hosts'])
    
    def display_scan_comparison(self, scan_id1: int, scan_id2: int, output: Optional[str] = None) -> None:
        """Exibe a comparação entre dois scans"""
        comparison = self.history_manager.compare_scans(scan_id1, scan_id2)
        
        if 'error' in comparison:
            print(f"\nErro ao comparar scans: {comparison['error']}")
            return
        
        print(f"\nComparação entre Scan {scan_id1} e Scan {scan_id2}:")
        print("=" * 60)
        print(f"Rede: {comparison['network']}")
        print(f"\nScan 1 ({comparison['scan1']['timestamp']})")
        print(f"- Total de hosts: {comparison['scan1']['total_hosts']}")
        print(f"\nScan 2 ({comparison['scan2']['timestamp']})")
        print(f"- Total de hosts: {comparison['scan2']['total_hosts']}")
        
        print("\nMudanças Detectadas:")
        print(f"- Hosts novos: {comparison['summary']['new_hosts']}")
        print(f"- Hosts removidos: {comparison['summary']['removed_hosts']}")
        print(f"- Hosts alterados: {comparison['summary']['changed_hosts']}")
        print(f"- Hosts inalterados: {comparison['summary']['unchanged_hosts']}")
        
        if comparison['new_hosts']:
            print("\nHosts Novos:")
            for ip, host in comparison['new_hosts'].items():
                print(f"- {ip} ({host['hostname'] or 'sem hostname'})")
        
        if comparison['removed_hosts']:
            print("\nHosts Removidos:")
            for ip, host in comparison['removed_hosts'].items():
                print(f"- {ip} ({host['hostname'] or 'sem hostname'})")
        
        if comparison['changed_hosts']:
            print("\nHosts com Alterações:")
            for ip, changes in comparison['changed_hosts'].items():
                print(f"\n{ip} ({changes['hostname'] or 'sem hostname'}):")
                if changes['new_ports']:
                    print("  Novas portas:", ", ".join(changes['new_ports']))
                if changes['closed_ports']:
                    print("  Portas fechadas:", ", ".join(changes['closed_ports']))
        
        if output:
            import json
            try:
                with open(output, 'w', encoding='utf-8') as f:
                    json.dump(comparison, f, indent=4)
                print(f"\nComparação exportada para {output}")
            except Exception as e:
                print(f"\nErro ao exportar comparação: {str(e)}")
    
    def delete_scan(self, scan_id: int) -> None:
        """Exclui um scan do histórico"""
        confirmation = input(f"\nTem certeza que deseja excluir o scan {scan_id}? (s/n): ").lower()
        if confirmation not in ['s', 'sim', 'y', 'yes']:
            print("Operação cancelada.")
            return
        
        if self.history_manager.delete_scan(scan_id):
            print(f"Scan {scan_id} excluído com sucesso.")
        else:
            print(f"Scan {scan_id} não encontrado.")

    def handle_scan_command(self, args) -> None:
        """Executa o comando de scan"""
        if not args.profile:
            args.profile = self.select_scan_profile()
            
        # Encontra o caminho do nmap
        from ..utils.system_utils import SystemUtils
        nmap_path = SystemUtils.find_nmap_path()
        if not nmap_path:
            print("\nErro: nmap não encontrado no sistema")
            return
            
        scanner = NetworkScanner(nmap_path)
        scanner.quiet_mode = args.quiet
        scanner.set_scan_profile(args.profile)
        
        # Configura as opções de paralelização
        if hasattr(args, 'threads'):
            scanner.set_max_threads(args.threads)
        if hasattr(args, 'batch_size'):
            scanner.set_batch_size(args.batch_size)
        if hasattr(args, 'throttle'):
            scanner.set_throttle_delay(args.throttle)
        
        # Executa o scan e mostra resultados
        results = scanner.scan_network(args.network)
        
        if not args.quiet:
            self.display_hosts_table(results)
        
        if args.output:
            from ..reports.report_generator import ReportGenerator
            report_gen = ReportGenerator()
            report_gen.generate_report(results, args.output, args.format)

    def handle_command(self, args) -> None:
        """Trata os diferentes comandos da CLI"""
        if args.command == 'scan':
            self.handle_scan_command(args)
        elif args.command == 'history':
            self.handle_history_commands(args)

    def scan_network(self, args):
        """Executa o scan inicial da rede"""
        self.scanner.set_quiet_mode(args.quiet)
        if hasattr(args, 'profile'):
            self.scanner.set_scan_profile(args.profile)
        return self.scanner.scan_network(args.network)

    def detailed_scan(self, hosts):
        """Executa o scan detalhado dos hosts"""
        return self.scanner.detailed_scan(hosts)

    def scan_ports(self, args):
        """Executa o scan de portas em um IP específico"""
        self.scanner.set_quiet_mode(args.quiet)
        if hasattr(args, 'profile'):
            self.scanner.set_scan_profile(args.profile)
        return self.scanner.scan_ports(args.ip)

    def process_results(self, results):
        """Processa e exibe os resultados do scan"""
        self.last_results = results
        self.display_hosts_table(results)

    def scan(self, args):
        """Executa o comando scan completo"""
        if not args.network and not args.ip:
            print("Erro: É necessário especificar uma rede (--network) ou um IP (--ip)")
            return

        if args.network:
            # Scan de rede
            if not args.quiet:
                print(f"\nIniciando scan na rede {args.network}")
            
            # Scan inicial
            hosts = self.scan_network(args)
            if not hosts:
                print("Nenhum host encontrado na rede.")
                return

            # Pergunta sobre scan detalhado
            if not args.quiet and self.ask_detailed_scan():
                hosts = self.detailed_scan(hosts)

            # Processa resultados
            self.process_results(hosts)

        else:
            # Scan de IP específico
            if not args.quiet:
                print(f"\nIniciando scan no IP {args.ip}")
            results = self.scan_ports(args)
            self.process_results(results)

    def history(self, args):
        """Executa o comando history"""
        # Obtém o histórico limitado ao número especificado
        history = self.history_manager.get_scan_list(limit=args.limit)
        
        if not history:
            print("Nenhum registro encontrado no histórico.")
            return

        # Exibe o histórico em formato tabular
        table = PrettyTable()
        table.field_names = ["ID", "Data", "Rede", "Perfil", "Total Hosts"]
        table.align = "l"

        for entry in history:
            date = datetime.fromisoformat(entry['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            table.add_row([
                entry['id'],
                date,
                entry['network'],
                entry['scan_profile'],
                entry['total_hosts']
            ])

        print("\nHistórico de Scans:")
        print(table)

    def report(self, args):
        """Executa o comando report"""
        from ..reports.report_generator import ReportGenerator
        
        # Verifica se deve usar dados do histórico
        if args.use_history:
            history = self.history_manager.get_history()
            if not history:
                print("Nenhum registro encontrado no histórico.")
                return
            
            # Usa o índice especificado ou o último scan
            scan_data = history[args.index if args.index is not None else 0]
            data = scan_data["hosts"]
        else:
            # Usa os resultados do último scan
            if not self.last_results:
                print("Nenhum resultado de scan disponível.")
                return
            data = self.last_results

        # Gera o relatório
        report_gen = ReportGenerator()
        report_gen.generate_report(data, args.output, args.format)
        print(f"\nRelatório gerado em: {args.output}")

    def main(self):
        """Método principal do CLI"""
        self.show_header()
        args = self.parse_arguments()
        
        if hasattr(args, 'func'):
            args.func(args)
        else:
            print("Nenhum comando especificado. Use --help para ver os comandos disponíveis.")