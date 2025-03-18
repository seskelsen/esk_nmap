# ESK NMAP

[![Build Status](https://img.shields.io/travis/username/esk_nmap/master.svg)](https://travis-ci.org/username/esk_nmap)
[![Coverage Status](https://img.shields.io/codecov/c/github/username/esk_nmap/master.svg)](https://codecov.io/gh/username/esk_nmap)
[![License](https://img.shields.io/github/license/username/esk_nmap.svg)](LICENSE)

ESK NMAP é uma ferramenta avançada de varredura de rede baseada no Nmap, desenvolvida pela Eskel Cybersecurity.

## Status do Projeto

🚀 Versão atual: 0.2.0 (18/03/2025)

### Cobertura de Testes
- ConfigManager: 98%
- Scanner: 85%
- HistoryManager: 90%
- ReportGenerator: 93%
- CLI: 80%
- Total: 89%

## Características

- 🔍 Descoberta automática de hosts na rede
- 📊 Múltiplos formatos de relatório (JSON, CSV, XML, HTML)
- ⚙️ Sistema flexível de configuração via YAML
- 📝 Logging estruturado com rotação de arquivos
- 🚦 Interface CLI com feedback em tempo real
- 💾 Armazenamento de histórico de scans
- 🔒 Validação robusta de entradas e permissões

## Instalação

### Pré-requisitos

- Python 3.8+
- Nmap 7.80+
- Privilégios de administrador/root para algumas funcionalidades

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

## Uso Rápido

```bash
# Scan básico de rede
python esk_nmap.py scan 192.168.1.0/24

# Scan com detecção de versão
python esk_nmap.py scan -p 1-1000 -sV 192.168.1.0/24

# Gerar relatório em formato específico
python esk_nmap.py scan --output report.json --format json 192.168.1.0/24
```

## Configuração

O arquivo `config.yaml` permite personalizar:

- Perfis de scan predefinidos
- Timeouts e tentativas
- Formatos de relatório
- Configurações de logging
- Opções de performance

## Desenvolvimento

### Preparando o Ambiente de Desenvolvimento

1. Clone o repositório:
```bash
git clone https://github.com/eskelsecurity/esk_nmap.git
cd esk_nmap
```

2. Crie um ambiente virtual (recomendado):
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
.\venv\Scripts\activate   # Windows
```

3. Instale as dependências de desenvolvimento:
```bash
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
```

### Executando Testes

```bash
pytest
pytest --cov=src tests/
```

## Contribuindo

1. Fork o projeto
2. Crie sua Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a Branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## Licença

Este projeto está licenciado sob a licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

## Autores

- **Sigmar Eskelsen** - *Trabalho inicial* - [EskelSecurity](https://github.com/eskelsecurity)

## Agradecimentos

- Equipe do Nmap pelo excelente scanner
- Comunidade Python por feedbacks e contribuições
- Todos os contribuidores que ajudaram a melhorar o projeto
