# ESK_NMAP

Copyright (c) 2025 Eskel Cybersecurity. Todos os direitos reservados.

Um scanner de rede avançado baseado no Nmap com interface amigável e relatórios detalhados.

## Características

- Interface de linha de comando intuitiva
- Descoberta automática de hosts na rede
- Múltiplos perfis de scan:
  - Básico (rápido)
  - Silencioso (stealth)
  - Detecção de Versão
  - Completo
  - Personalizado
- Detecção de firewalls
- Relatórios detalhados em formato texto
- Suporte completo para Windows e Linux
- Cobertura de testes unitários > 70%

## Pré-requisitos

- Python 3.7+
- Nmap 7.0+
- Biblioteca prettytable
- Biblioteca pytest (para desenvolvimento)

### Windows

```bash
# Instalar o Nmap
# Baixe e instale de https://nmap.org/download.html#windows

# Instalar dependências Python
pip install -r requirements.txt
```

### Linux

```bash
# Instalar o Nmap
sudo apt install nmap  # Debian/Ubuntu
sudo dnf install nmap  # Fedora
sudo pacman -S nmap   # Arch Linux

# Instalar dependências Python
pip install -r requirements.txt
```

## Instalação

1. Clone o repositório ou baixe o código fonte
2. Instale as dependências:

   ```bash
   pip install -r requirements.txt
   ```

3. Use diretamente com Python ou gere o executável:

   ```bash
   # Windows
   pyinstaller --onefile esk_nmap.py

   # Linux
   pyinstaller --onefile esk_nmap.py
   ```

## Uso

```bash
# Usando código fonte
python esk_nmap.py <rede>

# Usando executável
./esk_nmap <rede>

# Exemplo
python esk_nmap.py 192.168.1.0/24
```

### Perfis de Scan

1. **Scan Básico**
   - Mais rápido
   - Menos detalhado
   - Ideal para visão geral rápida

2. **Scan Silencioso**
   - Utiliza técnicas SYN stealth
   - Menor chance de detecção
   - Mais lento que o básico

3. **Scan com Detecção de Versão**
   - Identifica versões dos serviços
   - Mais informações sobre portas abertas
   - Velocidade moderada

4. **Scan Completo**
   - Todas as portas
   - Scripts NSE básicos
   - Detecção de SO
   - Mais lento, mais detalhado

5. **Scan Personalizado**
   - Escolha suas opções
   - Configure timing e agressividade
   - Total controle sobre o scan

## Desenvolvimento

### Estrutura do Projeto

```
esk_nmap/
├── src/
│   ├── core/        # Lógica principal
│   ├── reports/     # Geração de relatórios
│   ├── ui/          # Interface com usuário
│   └── utils/       # Utilitários
├── tests/           # Testes unitários
├── requirements.txt # Dependências
└── esk_nmap.py     # Ponto de entrada
```

### Testes

```bash
# Executar todos os testes
pytest

# Executar testes com cobertura
pytest --cov=src

# Ver relatório HTML de cobertura
pytest --cov=src --cov-report=html
```

### Compilação

#### Windows

```bash
pyinstaller --onefile --icon=resources/icon.ico esk_nmap.py
```

#### Linux

```bash
pyinstaller --onefile esk_nmap.py
```

## Contribuindo

1. Fork o projeto
2. Crie sua branch de feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## Licença

Copyright (c) 2025 Eskel Cybersecurity. Todos os direitos reservados.

## Suporte

Para suporte, envie um email para <suporte@eskelcyber.com>
