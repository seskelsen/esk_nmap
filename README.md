# ESK_NMAP - Network Scanner Tool

![Python](https://img.shields.io/badge/Python-3.12%2B-blue.svg)
![License](https://img.shields.io/badge/License-GPL%20v2-blue.svg)
![Coverage](https://img.shields.io/badge/Coverage-70%25-yellow.svg)
![Development Status](https://img.shields.io/badge/Status-Beta-yellow.svg)

## 🚀 Sobre o Projeto

ESK_NMAP é uma ferramenta de scanner de rede desenvolvida pela Eskel Cybersecurity. Construída sobre o Nmap, oferece uma interface amigável e recursos adicionais para facilitar a descoberta e análise de hosts em uma rede.

### ✨ Principais Recursos

- 🔍 Descoberta automática de hosts
- 📊 Múltiplos formatos de relatório (TEXT, JSON, CSV, XML)
- 🎯 Perfis de scan predefinidos
- 📈 Barra de progresso em tempo real
- 📝 Sistema de logging estruturado
- 🔄 Histórico de scans com comparação
- ⚙️ Configuração flexível via YAML

### 🛠️ Estado Atual

O projeto está em fase beta, com foco atual em:
- Melhorias de estabilidade
- Correção de bugs
- Otimização de performance
- Aumento da cobertura de testes

## 📋 Pré-requisitos

- Python 3.12 ou superior
- Nmap instalado no sistema
- Sistema operacional: Windows ou Linux
- Privilégios de administrador (recomendado)

## 🔧 Instalação

1. Clone o repositório:
```bash
git clone https://github.com/eskelcyber/esk_nmap.git
```

2. Instale as dependências:
```bash
pip install -r requirements.txt
```

## 🎮 Uso Básico

1. Scan básico de uma rede:
```bash
python esk_nmap.py scan 192.168.1.0/24
```

2. Scan com perfil específico:
```bash
python esk_nmap.py scan 192.168.1.0/24 --profile complete
```

3. Gerar relatório em formato específico:
```bash
python esk_nmap.py scan 192.168.1.0/24 --output relatorio.json --format json
```

## 📊 Perfis de Scan Disponíveis

- basic: Scan rápido para visão geral
- stealth: Scan discreto usando SYN stealth
- version: Scan com detecção de versões
- complete: Scan detalhado com scripts NSE
- quick: Scan rápido de portas comuns

## 📝 Formatos de Relatório

- TEXT: Relatório em texto formatado
- JSON: Formato estruturado para integração
- CSV: Formato tabular para planilhas
- XML: Formato estruturado com metadados

## 🔄 Versionamento

Usamos [SemVer](http://semver.org/) para versionamento.
Consulte o [CHANGELOG.md](CHANGELOG.md) para ver o histórico de alterações.

## 🎯 Roadmap

Consulte o [TODO.md](TODO.md) para ver as próximas melhorias planejadas.

## 🤝 Contribuição

1. Faça um Fork do projeto
2. Crie sua Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a Branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 📜 Licença

Este projeto está licenciado sob a GNU General Public License v2 - veja o arquivo [LICENSE](LICENSE) para detalhes.

## 📞 Contato

Sigmar Eskelsen - sigmar@eskelcyber.com

## ⚠️ Aviso Legal

Esta ferramenta deve ser usada apenas em redes e sistemas que você tem permissão para escanear. O uso indevido pode ser ilegal em sua jurisdição.
