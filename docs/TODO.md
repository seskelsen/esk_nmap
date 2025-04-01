# ESK_NMAP - Lista de Melhorias Planejadas

## Status das Tarefas

- 🔴 Não iniciado
- 🟡 Em progresso
- 🟢 Concluído
- ⭕ Bloqueado

## Tarefas Concluídas Recentemente [🟢]

1. **Sistema de Logging** ✅
   - [x] Configuração flexível por ambiente
   - [x] Rotação automática de logs
   - [x] Formato JSON estruturado
   - [x] Integração com monitoramento

2. **Resolução de Problemas Críticos** ✅
   - [x] Correção do loop infinito durante scans de redes grandes
   - [x] Implementação de timeouts configuráveis
   - [x] Aplicação correta das opções de perfil nos comandos Nmap

3. **Perfis de Scan Aprimorados** ✅
   - [x] Perfil "discovery" para detecção de hostnames e portas
   - [x] Opções de perfil configuráveis via config.yaml
   - [x] Documentação atualizada sobre perfis disponíveis

## Próximos Passos (Sprint Atual) [🟡]

4. **Melhorias de Performance** 🟡
   - [x] Resolver gargalo no scan de descoberta
   - [ ] Otimizar consultas ao banco de dados
   - [ ] Implementar cache para resultados frequentes
   - [ ] Benchmark dos perfis de scan em diferentes ambientes

5. **Documentação** 🟡
   - [x] README atualizado
   - [x] CHANGELOG atualizado
   - [x] TODO atualizado
   - [ ] Wiki do projeto
   - [ ] Guias de contribuição
   - [ ] Documentação da API

6. **Segurança** 🟡
   - [x] Validação de inputs
   - [x] Controle de permissões
   - [ ] Rate limiting
   - [ ] Auditoria de ações

## Backlog Priorizado [🔴]

7. **Interface Web** 🔴
   - [ ] Dashboard básico
   - [ ] Visualização de resultados
   - [ ] Gerenciamento de scans
   - [ ] Comparação visual

8. **Sistema de Plugins** 🔴
   - [ ] Arquitetura base
   - [ ] Sistema de hooks
   - [ ] API de extensão
   - [ ] Documentação para desenvolvedores

9. **Integração com Ferramentas** 🔴
   - [ ] Exportação para Metasploit
   - [ ] Integração com OpenVAS
   - [ ] Integração com SIEM
   - [ ] API REST

10. **Detecção de Vulnerabilidades** 🔴
    - [ ] Integração com CVE
    - [ ] Avaliação de risco
    - [ ] Recomendações de mitigação

11. **Escaneamento Agendado** 🔴
    - [ ] Sistema de agendamento
    - [ ] Notificações
    - [ ] Execução automática

## Criação de Testes Unitários [🟡]

12. **Testes para Módulos Principais** 🟡
    - [x] Testes para `core/history_manager.py`
    - [x] Testes para `core/scanner.py`
    - [x] Testes para `reports/report_generator.py` (Parcialmente - alguns testes ainda falham)
    - [x] Testes para `ui/cli.py`
    - [x] Testes para `utils/config_manager.py`
    - [x] Testes para `utils/error_handler.py`
    - [x] Testes para `utils/logger.py`
    - [x] Testes para `utils/system_utils.py`

### Problemas Pendentes em Testes [🟡]

13. **Correção de Testes Falhos** 🟡
    - [ ] Corrigir o teste `test_report_with_string_ports` - AttributeError: 'str' object has no attribute 'get'
    - [ ] Corrigir o teste `test_export_comparison_to_text` - expectativa vs realidade nas strings
    - [ ] Corrigir o teste `test_export_comparison_to_xml` - estrutura XML esperada vs gerada
    - [ ] Corrigir o teste `test_export_comparison_to_html` - erro na exportação HTML

### Progresso de Correções de Testes [🟡]

14. **Correções Implementadas** 🟡
    - [x] Adicionado tratamento para portas em formato string no método `generate_json_report`
    - [x] Corrigido o problema de patching incorreto do logger nos testes de ComparisonReportGenerator
    - [x] Implementada a correção para HTML templates e output esperado
    - [ ] Implementar correções para os testes restantes

### Notas
- Garantir cobertura de testes > 90%.
- Seguir boas práticas de escrita de testes com `pytest`.
- Priorizar testes para módulos críticos primeiro.

## Melhorias Contínuas

- [ ] Manter cobertura de testes > 90%
- [ ] Otimizar performance
- [ ] Reduzir uso de recursos
- [ ] Melhorar documentação
- [ ] Refatorar código legado

## Notas

- Manter compatibilidade com versões anteriores
- Seguir PEP 8 e boas práticas Python
- Documentar alterações no CHANGELOG.md
- Priorizar features que agregam valor imediato
