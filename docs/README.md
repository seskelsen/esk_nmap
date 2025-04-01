# ESK NMAP

[![Build Status](https://img.shields.io/travis/username/esk_nmap/master.svg)](https://travis-ci.org/username/esk_nmap)
[![Coverage Status](https://img.shields.io/codecov/c/github/username/esk_nmap/master.svg)](https://codecov.io/gh/username/esk_nmap)
[![License](https://img.shields.io/github/license/username/esk_nmap.svg)](LICENSE)

ESK NMAP é uma ferramenta avançada de varredura de rede baseada no Nmap, desenvolvida pela Eskel Cybersecurity. O projeto combina o poder do Nmap com uma interface amigável e recursos avançados de relatórios e análise.

![ESK NMAP Banner](https://via.placeholder.com/800x200?text=ESK+NMAP)

## 📋 Conteúdo

- [Status do Projeto](#status-do-projeto)
- [Características](#características)
- [Instalação](#instalação)
- [Uso Rápido](#uso-rápido)
- [Perfis de Scan](#perfis-de-scan)
- [Configuração](#configuração)
- [Desenvolvimento](#desenvolvimento)
- [Contribuindo](#contribuindo)
- [Licença](#licença)
- [Autores](#autores)
- [Agradecimentos](#agradecimentos)
- [Suporte](#suporte)

## 🚀 Status do Projeto

**Versão atual**: 0.2.1 (24/03/2025)

### Cobertura de Testes

- ConfigManager: 98%
- Scanner: 85%
- HistoryManager: 90%
- ReportGenerator: 93%
- CLI: 80%
- Total: 89%

## ✨ Características

- 🔍 **Descoberta avançada de dispositivos** - Identificação automática de hosts, MAC addresses, fabricantes e hostnames
- 📊 **Múltiplos formatos de relatório** - Exporte para JSON, CSV, XML ou HTML
- 🔎 **Detecção de serviços** - Identificação detalhada de serviços em execução
- ⚙️ **Sistema flexível de configuração** - Personalização completa via arquivo YAML
- 📝 **Logging estruturado** - Rotação de arquivos e níveis por ambiente (desenvolvimento/produção)
- 🔄 **Sistema de retry** - Recuperação automática de falhas temporárias
- 🚦 **Interface CLI intuitiva** - Feedback visual em tempo real durante scans
- 💾 **Histórico de scans** - Armazenamento persistente de resultados para análise futura
- 📈 **Comparação de resultados** - Identificação de mudanças entre scans
- 🚀 **Paralelização de scans** - Processamento simultâneo para melhor performance
- 🔒 **Validação robusta** - Verificação de permissões e inputs
- ⏱️ **Timeouts configuráveis** - Controle preciso do tempo de execução

## 💻 Instalação

### Pré-requisitos

- Python 3.8+
- Nmap 7.80+
- Privilégios de administrador/root (recomendado)

### Passos para Instalação

1. Clone o repositório:

```bash
git clone https://github.com/eskelsecurity/esk_nmap.git
cd esk_nmap
```

2. Instale as dependências:

```bash
python -m pip install -r requirements.txt
```

3. Verifique a instalação:

```bash
python esk_nmap.py --version
```

## 🚀 Uso Rápido

### Scan básico de descoberta

```bash
python esk_nmap.py scan --network 192.168.1.0/24
```

### Scan com detecção de hostnames e portas

```bash
python esk_nmap.py scan --network 192.168.1.0/24 --profile discovery
```

### Scan com detecção de serviços e versões

```bash
python esk_nmap.py scan --network 192.168.1.0/24 --profile version
```

### Scan completo com scripts NSE e detecção de SO

```bash
python esk_nmap.py scan --network 192.168.1.0/24 --profile complete
```

### Exportar resultados para JSON

```bash
python esk_nmap.py scan --network 192.168.1.0/24 --output resultado.json --format json
```

### Comparar dois scans anteriores

```bash
python esk_nmap.py history compare 1 2 --format html --output comparacao.html
```

## 🔍 Perfis de Scan

O ESK NMAP inclui vários perfis pré-configurados para diferentes necessidades:

| Perfil | Descrição | Opções | Uso Recomendado |
|--------|-----------|--------|-----------------|
| **basic** | Scan rápido para visão geral | `-T5 -sn` | Descoberta inicial de hosts |
| **discovery** | Detecção de hostnames e portas | `-T4 -F` | Inventário detalhado da rede |
| **stealth** | Scan discreto via SYN | `-sS -T2 -n` | Ambientes sensíveis |
| **version** | Identificação de serviços | `-sV -T4 -n` | Auditoria de serviços |
| **complete** | Scan detalhado com scripts | `-sV -sC -O -T4 -n` | Análise completa de segurança |
| **quick** | Scan mínimo de portas comuns | `-T5 -F -n` | Verificação rápida |

## ⚙️ Configuração

O arquivo `config.yaml` permite personalizar completamente o comportamento da ferramenta:

### Perfis de Scan

```yaml
scan_profiles:
  basic:
    name: Scan Básico
    description: Scan rápido para visão geral da rede
    options: ["-T5", "-sn"]
    ports: "21,22,23,25,53,80,443,3389"
    timing: 5
  discovery:
    name: Scan de Descoberta
    description: Scan para encontrar hostnames e portas comuns
    options: ["-T4", "-F"]
    ports: "21,22,23,25,53,80,443,3389"
    timing: 4
```

### Timeouts

```yaml
timeouts:
  discovery: 300  # segundos
  port_scan: 600
  version_scan: 300
```

### Retry

```yaml
retry:
  max_attempts: 3
  delay_between_attempts: 5
```

### Logging

```yaml
environment: development  # ou production
log_level:
  development: DEBUG
  production: INFO
```

## 🛠️ Desenvolvimento

### Preparando o Ambiente

1. Crie um ambiente virtual:

```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
.\venv\Scripts\activate   # Windows
```

2. Instale dependências de desenvolvimento:

```bash
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
```

### Executando Testes

```bash
# Executar todos os testes
pytest

# Executar com relatório de cobertura
pytest --cov=src tests/

# Gerar relatório HTML de cobertura
pytest --cov=src --cov-report=html tests/
```

## 📂 Estrutura do Projeto

O projeto foi reorganizado para seguir as melhores práticas de arquitetura. Abaixo está a estrutura atualizada:

```
/docs/                     # Documentação do projeto
    CHANGELOG.md           # Histórico de mudanças
    README.md              # Instruções gerais
    TODO.md                # Lista de tarefas
/src/                      # Código-fonte principal
    /core/                 # Componentes principais
        history_manager.py
        scanner.py
    /reports/              # Geração de relatórios
        report_generator.py
    /ui/                   # Interface com o usuário
        cli.py
    /utils/                # Utilitários e helpers
        config_manager.py
        error_handler.py
        logger.py
        system_utils.py
/tests/                    # Testes automatizados
    conftest.py
    test_cli.py
    test_config_manager.py
    test_error_handler.py
    test_history_manager.py
    test_integration.py
    test_logger.py
    test_report_generator.py
    test_scanner.py
    test_system_utils.py
/build/                    # Arquivos relacionados ao processo de build
    /config/               # Configurações de build
        esk_nmap.spec
        esk_nmap_linux.spec
    /scripts/              # Scripts de automação
        build_executables.py
/executables/              # Executáveis gerados
    /linux/                # Executáveis para Linux
        esk_nmap
    /windows/              # Executáveis para Windows
        esk_nmap.exe
/requirements/             # Dependências do projeto
    requirements.txt       # Dependências principais
    pytest.ini             # Configurações de testes
config.yaml                # Configuração principal do sistema
```

## 🛠️ Ajustes Recentes

1. **Reorganização do Projeto**:
   - Arquivos `.spec` movidos para `build/config/`.
   - Script de automação `build_executables.py` movido para `build/scripts/`.
   - Documentação centralizada na pasta `docs/`.
   - Dependências e configurações de testes movidas para `requirements/`.

2. **Automação de Build**:
   - O script `build_executables.py` foi atualizado para copiar os executáveis gerados para a pasta `executables/`.

3. **Limpeza de Arquivos**:
   - Remoção de pastas e arquivos temporários, como `build/`, `dist/`, e `__pycache__/`.

4. **Melhorias na Estrutura**:
   - Organização modular para facilitar a manutenção e escalabilidade.

## 📝 Como Contribuir

Consulte o arquivo `TODO.md` na pasta `docs/` para ver as tarefas planejadas e em andamento. Atualize o `CHANGELOG.md` para documentar mudanças significativas.

## 🛠️ Building Executables

To create executables for Windows and Linux, follow these steps:

1. Ensure you have Python and PyInstaller installed.
2. Navigate to the `build_scripts/` folder.
3. Run the following command:

```bash
python build_executables.py
```

This script will:
- Clean old build artifacts.
- Build the executable for Windows using `esk_nmap.spec`.
- Build the executable for Linux using `esk_nmap_linux.spec`.

Ensure the `.spec` files are properly configured before running the script.

## 🤝 Contribuindo

Contribuições são bem-vindas! Siga estes passos:

1. Fork o projeto
2. Crie sua feature branch (`git checkout -b feature/MinhaFeature`)
3. Commit suas mudanças (`git commit -m 'Adiciona MinhaFeature'`)
4. Push para a branch (`git push origin feature/MinhaFeature`)
5. Abra um Pull Request

### Diretrizes

- Mantenha a cobertura de testes acima de 80%
- Documente novas funcionalidades
- Atualize o CHANGELOG.md
- Siga as convenções de estilo PEP 8

## 📜 Licença

Este projeto está licenciado sob a licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

## ✍️ Autores

- **Sigmar Eskelsen** - *Trabalho inicial* - [EskelSecurity](https://github.com/eskelsecurity)

## 🙏 Agradecimentos

- Equipe do Nmap pelo poderoso scanner
- Comunidade Python por feedbacks e contribuições
- Todos os contribuidores que ajudaram a melhorar o projeto

## 📞 Suporte

Para reportar bugs ou solicitar funcionalidades:

1. Verifique se já não existe uma issue similar no repositório oficial no GitHub.
2. Crie uma issue com detalhes sobre a situação no repositório [Eskel Cybersecurity](https://github.com/eskelsecurity/esk_nmap).
3. Inclua logs e passos de reprodução detalhados.

---

Desenvolvido pela [Eskel Cybersecurity](https://github.com/eskelsecurity)
