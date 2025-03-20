# Changelog

Todas as mudanças notáveis neste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
e este projeto adere ao [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planejado
- Suporte completo a IPv6
- Interface gráfica de usuário (GUI)
- Exportação para dashboards interativos

## [1.8.0] - 2025-03-20

### Adicionado
- Novos testes para o ConfigManager cobrindo casos extremos
- Testes adicionais para o ReportGenerator
- Validação adicional de campos na classe HostInfo
- Testes para cenários de falha no NetworkScanner
- Novo módulo de testes de integração (test_integration.py)
- Implementação da paralelização de scans para melhor performance

### Alterado
- Melhoria significativa na cobertura de testes do ConfigManager (98%)
- Refatoração dos testes do Scanner para melhor organização
- Otimização do parsing de resultados do Nmap
- Conclusão das sprints 1 e 2 conforme planejado

### Corrigido
- Verificação e validação da classe HostInfo (confirmado funcionamento correto)
- Problemas com manipulação de StringIO no ReportGenerator
- Tratamento de caracteres especiais em nomes de arquivo
- Bug na interface de linha de comando ao processar argumentos complexos

## [1.7.0] - 2025-03-16

### Melhorado

- Cobertura de testes do módulo CLI aumentada para 80%
- Implementação robusta de mocks para testes do NetworkScanner
- Correção nos testes de integração do ReportGenerator
- Melhor organização dos casos de teste
- Documentação dos testes atualizada

### Corrigido

- Problemas de mock no teste handle_scan_command_with_report
- Validação do caminho do nmap nos testes
- Testes para comandos com relatórios

## [1.6.0] - 2025-03-15

### Adicionado

- Suporte a múltiplos formatos de saída (JSON, CSV, XML)
- Nova classe ReportFormat para melhor tipagem dos formatos
- Testes unitários para todos os formatos de relatório

### Melhorado

- Cobertura de testes do ReportGenerator para 99%
- Estrutura de dados HostInfo para suportar mais informações
- Documentação dos formatos de relatório
- Interface de linha de comando com suporte a novos formatos

### Corrigido

- Encoding de caracteres especiais em todos os formatos
- Formatação de dados vazios nos relatórios
- Validação de campos opcionais

## [1.5.0] - 2025-03-14

### Adicionado

- Implementação de métodos alternativos de descoberta de hosts (ARP e Ping Sweep)
- Melhorias na detecção de portas e serviços
- Suporte a scans mais agressivos
- Cobertura de testes superior a 70%
- Testes unitários para todos os módulos principais

### Melhorado

- Tratamento de erros e mensagens informativas
- Documentação de uso e exemplos
- Interface de usuário com feedback em tempo real
- Detecção de firewalls mais precisa
- Estrutura do projeto reorganizada em módulos

### Corrigido

- Problemas de codificação em caracteres especiais nos relatórios
- Detecção incorreta de status de firewall
- Timeout em scans muito longos
- Compatibilidade cross-platform melhorada

## [1.4.0] - 2025-03-13

### Adicionado

- Suporte a compilação para Windows e Linux
- Novo formato de relatório mais detalhado
- Verificação de privilégios de administrador

### Melhorado

- Performance em redes grandes
- Formato de saída no terminal
- Documentação do código

## [1.3.0] - 2025-03-12

### Adicionado

- Menu de seleção de perfis de scan
- Novos tipos de scan:
  - Scan Básico (rápido)
  - Scan Silencioso SYN (-sS)
  - Scan com Detecção de Versão (-sV)
  - Scan Completo com scripts NSE
  - Scan Personalizado com opções configuráveis
- Opções avançadas de scan:
  - Fragmentação de pacotes (-f)
  - Controle de timing (T2/T4)
  - Detecção de Sistema Operacional (-O)
  - Scripts básicos de segurança (-sC)

### Melhorado

- Maior flexibilidade na configuração dos scans
- Melhor documentação das opções disponíveis
- Relatórios mais detalhados incluindo parâmetros do scan
- Feedback mais claro sobre o tipo de scan em execução

## [1.2.0] - 2025-03-10

### Adicionado

- Suporte a múltiplos sistemas operacionais
- Detecção automática do caminho do Nmap
- Verificação de dependências

### Melhorado

- Interface de linha de comando
- Tratamento de erros
- Documentação de instalação

## [1.1.0] - 2025-03-08

### Adicionado

- Geração de relatórios em arquivo texto
- Detecção de fabricante de dispositivos
- Scan de portas mais comum

### Melhorado

- Velocidade de scan
- Formato de exibição dos resultados
- Documentação de uso

## [1.0.0] - 2025-03-06

### Adicionado

- Funcionalidade inicial de scan de rede usando Nmap
- Descoberta de hosts na rede com exibição em tempo real
- Scan detalhado opcional de portas para hosts descobertos
- Interface em linha de comando com feedback visual
- Relatório em formato de tabela com separadores entre hosts
- Geração de relatório detalhado em arquivo texto
- Suporte para exibição de:
  - Endereço IP
  - Hostname
  - Status do host
  - Endereço MAC
  - Fabricante do dispositivo
  - Portas abertas
  - Serviços em execução

[Unreleased]: https://github.com/username/esk_nmap/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/username/esk_nmap/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/username/esk_nmap/releases/tag/v0.1.0
