# Handoff de Desenvolvimento - SIP/RTP Analyzer V2

_Gerado em: 2026-04-19 15:12 (America/Sao_Paulo)_

## 1. Objetivo da Aplicação

O SIP/RTP Analyzer é uma ferramenta local para acelerar a análise de capturas PCAP/PCAPNG com alto volume de chamadas SIP em ambiente de operadora. O objetivo principal é evitar que o analista precise abrir ou filtrar manualmente um arquivo gigante no Wireshark: a aplicação indexa capturas, permite buscar chamadas por número e horário, exporta um PCAP reduzido da chamada e gera relatórios JSON/HTML com diagnóstico SIP/RTP.

A V2 foi redesenhada para o fluxo operacional real: capturas SIP e RTP ficam em pastas separadas, normalmente com arquivos quebrados em blocos de 50 MB pelo `tcpdump`, e o `mergecap` deixa de ser etapa inicial. O merge agora ocorre apenas no final, para montar o PCAP reduzido da chamada selecionada.

## 2. Estado Atual do Desenvolvimento

A versão V2 está funcional e empacotada em modo portable. O fluxo principal já funciona:

- Interface Tkinter V2 em `v2/app/siprtp_v2_gui.py`.
- CLI V2 em `v2/app/siprtp_v2_cli.py`.
- Motor Rust em `v2/fast_indexer/`, compilado como `siprtp_fast_indexer.exe`.
- SQLite V2 com tabelas para capturas, chamadas, arquivos relacionados e SDP.
- Busca por número + horário diretamente no SQLite.
- Exportação seletiva por `Call-ID`, com recorte por tempo, filtro SIP/RTP e merge final.
- Filtro RTP por SDP para reduzir bastante o tamanho do PCAP exportado.
- Paralelismo controlado por perfil `safe`, `balanced`, `turbo` e `workers=auto|N`.
- Relatório HTML/JSON com diagnóstico técnico mais forte: veredito operacional, timeline SIP, RTP por direção, avisos RTP, streams RTP/RTCP e seções antigas preservadas.

Artefatos atuais:

- `dist_v2/SIPRTPAnalyzerV2.exe`
- `dist_v2/siprtp_fast_indexer.exe`
- `SIPRTPAnalyzerV2_Portable/`
- `SIPRTPAnalyzerV2_Portable.zip`

Validações recentes confirmadas:

- `py_compile` dos módulos alterados: OK.
- `python -m unittest discover -s v2/tests`: 19 testes OK.
- Exportação real de uma chamada de validação: OK.
- HTML real validado contendo `Veredito Operacional`, `Diagnostico`, `Timeline SIP`, `RTP Por Direcao`, `Avisos RTP` e `Streams RTP/RTCP`.
- Smoke test do executável em `dist_v2`: OK.
- Smoke test do portable: OK.

## 3. Histórico Narrativo do Desenvolvimento

O desenvolvimento começou com uma ferramenta V1 baseada em Python/TShark para indexar um PCAP único, buscar chamadas SIP e extrair chamadas específicas. A principal dor operacional era o alto volume de chamadas coletadas de uma vez, que tornava lenta a análise manual no Wireshark e custoso o processamento de um PCAP grande já mesclado.

Depois, o fluxo foi ajustado para a realidade da operadora: capturas são feitas em servidores separados para SIP e RTP, com arquivos de 50 MB, e só depois eram unificadas com `mergecap`. A decisão técnica importante foi inverter esse fluxo: não gerar um PCAP gigante antes da busca. A V2 passou a indexar uma pasta SIP e catalogar uma pasta RTP, correlacionando por horário e SDP apenas quando uma chamada é escolhida.

Foi criado um motor Rust para indexação rápida, mantendo Python/Tkinter para GUI, busca, relatório e orquestração. O motor Rust emite JSON Lines para a GUI exibir progresso em tempo real. O Python mantém fallback via TShark quando o Rust não existe, falha ou retorna índice vazio.

Em seguida, a exportação foi otimizada. Primeiro ela selecionava arquivos RTP por janela de tempo, mas isso ainda podia gerar PCAPs grandes. A melhoria seguinte foi filtrar RTP por IP/porta do SDP, mantendo apenas a mídia relacionada à chamada. Depois, a exportação passou a processar arquivos candidatos em paralelo com `ThreadPoolExecutor`, enquanto o merge final permanece serial e determinístico.

A GUI foi refinada para telas menores, com scroll vertical e seções mais responsivas, e os controles `Desempenho` e `Workers` passaram a afetar tanto a indexação Rust quanto a exportação.

A mudança mais recente foi a Fase 3 de diagnóstico técnico: o relatório deixou de ser apenas uma listagem de achados e arquivos usados. Agora ele traz um veredito operacional no topo, timeline SIP simplificada e análise RTP por direção, incluindo perda, jitter, SSRC, RTCP e divergências com SDP.

## 4. Arquitetura e Fluxo Principal

Fluxo V2 principal:

1. Usuário seleciona `Pasta SIP`, `Pasta RTP`, `Database`, `Saida`, servidores SIP/RTP e perfil de desempenho na GUI.
2. A GUI chama `siprtp_v2_core.index_folders(...)`.
3. O core tenta localizar `siprtp_fast_indexer.exe`.
4. Se o motor Rust existir, ele é chamado via subprocesso com `index-folders`, emitindo progresso em JSON Lines.
5. Se o Rust falhar, não existir ou retornar índice vazio, o core usa fallback Python/TShark.
6. O SQLite V2 armazena chamadas, arquivos catalogados e mídias SDP.
7. A busca usa `siprtp_v2_db.find_calls(...)`, procurando número normalizado em `normalized_numbers` dentro da janela de horário.
8. A exportação usa `siprtp_v2_export.export_call(...)`:
   - consulta chamada, arquivos SIP relacionados, arquivos RTP por interseção temporal e SDP;
   - monta filtro SIP por `sip.Call-ID`;
   - monta filtro RTP por IP/porta SDP quando disponível;
   - roda `editcap` e `tshark` em paralelo por arquivo candidato;
   - roda `mergecap` no final;
   - chama `siprtp_ai.analyze_pcap_file(...)`;
   - grava relatório JSON/HTML via `siprtp_v2_report.write_reports(...)`.

Limites claros:

- Rust indexa e cataloga; Python orquestra, exporta e analisa.
- SQLite é gravado centralmente, não em paralelo direto.
- TShark/Editcap/Mergecap continuam sendo as ferramentas oficiais para recorte, filtro, análise e merge de PCAPs.

## 5. Linguagens, Frameworks, Bibliotecas e Ferramentas

Linguagens:

- Python 3.12 no ambiente atual do Codex runtime.
- Rust 2021 para o motor indexador.

GUI:

- Tkinter/ttk.
- Runtime Tcl/Tk empacotado/copied via `build_v2.ps1`.

Rust crates confirmados em `v2/fast_indexer/Cargo.toml`:

- `clap` com `derive`
- `etherparse`
- `pcap-parser`
- `rusqlite` com feature `bundled`
- `serde`
- `serde_json`

Ferramentas externas:

- Wireshark/TShark (`tshark.exe`)
- Editcap (`editcap.exe`)
- Mergecap (`mergecap.exe`)
- PyInstaller
- Cargo/Rust, apenas para build do motor

Banco:

- SQLite V2, schema em `v2/app/siprtp_v2_db.py`.
- `PRAGMA journal_mode=WAL`, `synchronous=NORMAL`, `temp_store=MEMORY`.

Plataforma alvo:

- Windows 64 bits.
- Wireshark preferencialmente em `C:\Program Files\Wireshark`.

## 6. Habilidades e Competências Aplicadas

- Análise SIP/RTP e diagnóstico VoIP.
- Processamento de PCAP/PCAPNG com TShark, Editcap e Mergecap.
- Indexação incremental e consulta operacional por SQLite.
- Desenvolvimento desktop Python/Tkinter.
- Interoperabilidade Python/Rust via subprocesso e JSON Lines.
- Paralelismo controlado e ajuste por CPU/RAM.
- Empacotamento Windows com PyInstaller.
- Criação de relatórios HTML/JSON.
- Testes unitários para banco, exportação, performance, relatório e diagnóstico.
- Debugging de ambiente Windows/OneDrive/Tcl/Tk/permissões.

## 7. Mapa de Arquivos e Módulos Principais

Compatibilidade reaproveitada:

- `siprtp_ai.py`: engine Python/TShark reaproveitada pela V2 para análise do PCAP reduzido e geração de fatos SIP/RTP. Não remover sem migrar antes `analyze_pcap_file(...)` para um módulo V2.
- O fluxo GUI V1 de PCAP único foi removido da pasta principal após a limpeza solicitada, mas o histórico arquitetural permanece relevante para entender a origem do projeto.

V2 Python:

- `v2/app/siprtp_v2_gui.py`: interface Tkinter V2, campos de pastas, servidores, desempenho, busca, resultados, exportação e logs.
- `v2/app/siprtp_v2_cli.py`: CLI V2 com comandos `indexar-pastas`, `buscar` e `extrair`.
- `v2/app/siprtp_v2_core.py`: orquestra indexação Rust/fallback TShark e formata progresso.
- `v2/app/siprtp_v2_db.py`: schema SQLite V2, inserts e busca.
- `v2/app/siprtp_v2_export.py`: seleção de arquivos, filtros SDP/RTP, recorte paralelo, merge e chamada da análise.
- `v2/app/siprtp_v2_performance.py`: cálculo de workers por perfil, CPU e RAM.
- `v2/app/siprtp_v2_report.py`: renderização HTML/JSON V2.
- `v2/app/siprtp_v2_tk_runtime.py`: configuração Tcl/Tk usada pela GUI V2 antes de importar Tkinter.

V2 Rust:

- `v2/fast_indexer/Cargo.toml`: dependências Rust.
- `v2/fast_indexer/src/main.rs`: CLI `siprtp_fast_indexer`, parsing PCAP, extração SIP/SDP, agregação por Call-ID, catalogação RTP, paralelismo e escrita SQLite.

Testes V2:

- `v2/tests/test_v2_core.py`
- `v2/tests/test_v2_db.py`
- `v2/tests/test_v2_diagnostics.py`
- `v2/tests/test_v2_export.py`
- `v2/tests/test_v2_performance.py`
- `v2/tests/test_v2_report.py`

Build e distribuição:

- `build_v2.ps1`: compila Rust, empacota GUI com PyInstaller e copia dependências.
- `Abrir_SIP_RTP_GUI_V2.bat`: launcher da GUI V2.
- `SIPRTPAnalyzerV2.spec`: spec do PyInstaller.
- `SIPRTPAnalyzerV2_Portable/LEIA-ME.txt`: instruções do pacote portable.

## 8. Comandos Úteis

Abrir GUI V2:

```powershell
.\Abrir_SIP_RTP_GUI_V2.bat
```

Indexar pastas pela CLI V2:

```powershell
& 'C:\Users\Victor\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' .\v2\app\siprtp_v2_cli.py indexar-pastas --sip-dir .\SIP --rtp-dir .\RTP --db .\capturas.siprtp.v2.sqlite --force --performance balanced --workers auto
```

Buscar chamada pela CLI V2:

```powershell
& 'C:\Users\Victor\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' .\v2\app\siprtp_v2_cli.py buscar --db .\capturas.siprtp.v2.sqlite --numero 5511999999999 --inicio "2026-04-17 15:57:36" --janela 10
```

Extrair chamada pela CLI V2:

```powershell
& 'C:\Users\Victor\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' .\v2\app\siprtp_v2_cli.py extrair --db .\capturas.siprtp.v2.sqlite --call-id "CALL_ID_AQUI" --out-dir .\v2_exports --margin 10 --performance balanced --workers auto
```

Compilar motor Rust manualmente:

```powershell
cd .\v2\fast_indexer
cargo build --release
```

Gerar executáveis V2:

```powershell
.\build_v2.ps1
```

Rodar testes V2:

```powershell
& 'C:\Users\Victor\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m unittest discover -s v2/tests
```

Validar sintaxe dos módulos principais:

```powershell
& 'C:\Users\Victor\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m py_compile siprtp_ai.py v2/app/siprtp_v2_report.py v2/app/siprtp_v2_export.py v2/app/siprtp_v2_gui.py
```

Smoke test do executável:

```powershell
.\dist_v2\SIPRTPAnalyzerV2.exe --smoke-test
.\SIPRTPAnalyzerV2_Portable\SIPRTPAnalyzerV2.exe --smoke-test
```

## 9. Decisões Técnicas Relevantes

- A V2 não usa `mergecap` antes da indexação. Capturas SIP/RTP devem permanecer separadas para reduzir custo operacional.
- O Rust é o caminho principal para indexação; Python/TShark é fallback.
- O SQLite V2 preserva compatibilidade parcial com a tabela `calls`, mas adiciona `capture_sets`, `capture_files`, `call_files`, `sdp_media` e `index_warnings`.
- A análise detalhada RTP só ocorre no PCAP reduzido, não na indexação inicial.
- A exportação filtra RTP por SDP quando possível; se não houver IP/porta utilizável, usa filtro amplo legado `rtp || rtcp || udp`.
- O paralelismo fica dentro de uma exportação por chamada; múltiplas chamadas selecionadas continuam sendo exportadas em série para evitar explosão de processos.
- Os perfis de desempenho são:
  - `safe`: conservador.
  - `balanced`: padrão recomendado.
  - `turbo`: maior uso de CPU.
- `Workers` pode ser `auto` ou um número fixo; vale para indexação Rust e exportação.
- O relatório usa regras locais determinísticas; IA generativa é opcional e recebe apenas fatos estruturados, não o PCAP bruto.

## 10. Problemas Conhecidos, Limitações e Riscos

- O motor Rust emite warning para PCAPNG: a mensagem no código diz que a versão inicial prioriza PCAP clássico e recomenda fallback TShark para PCAPNG se necessário.
- O Rust suporta linktypes Ethernet, Linux SLL e Raw conforme constantes no `main.rs`; linktypes desconhecidos geram warning.
- Diretórios temporários antigos podem ficar com ACL/permissão negada após execuções de ferramentas externas, especialmente em validações com `editcap/tshark` em sandbox.
- A exportação depende de `tshark.exe`, `editcap.exe` e `mergecap.exe`. Sem Wireshark instalado, a GUI pode indexar via Rust, mas exportação/análise ficará limitada ou falhará.
- O fallback TShark é mais lento, mas importante para compatibilidade.
- A análise RTP depende do que TShark consegue decodificar como RTP/RTCP. SRTP ou RTP em portas não reconhecidas pode aparecer como ausência de RTP ou exigir decode-as/manual.
- O veredito operacional é por regras locais. Ele prioriza clareza operacional, mas não substitui análise manual em casos complexos.
- Há dados reais de operadora no workspace local, como capturas e relatórios. Evitar commitar ou compartilhar PCAPs, bancos SQLite e relatórios com dados sensíveis.

## 11. Próximos Passos Recomendados

1. Criar um modo de validação/benchmark oficial para rodar chamadas conhecidas e registrar tempo de indexação, busca, exportação, tamanho do PCAP e veredito.
2. Melhorar suporte Rust para PCAPNG e linktypes adicionais, reduzindo dependência do fallback TShark.
3. Adicionar painel de detalhes da chamada na GUI antes da exportação, mostrando Call-ID, SDP, endpoints RTP e arquivos candidatos.
4. Criar botão “Validar ambiente” na GUI para checar Rust, Wireshark tools, permissões de pasta e versão do banco.
5. Versionar releases portable, por exemplo `SIPRTPAnalyzerV2-2.1.0-portable.zip`, com changelog.
6. Adicionar testes end-to-end com fixtures pequenas sem dados reais.
7. Revisar tratamento de diretórios temporários quando `editcap/tshark` falham, para reduzir sobras com permissão problemática.

## 12. Contexto Essencial para Outra IA Continuar

- Antes de editar, rode uma leitura rápida de `README.md`, `v2/app/siprtp_v2_export.py`, `v2/app/siprtp_v2_core.py`, `v2/app/siprtp_v2_report.py` e `siprtp_ai.py`.
- Preserve a separação V1/V2. Não remova `siprtp_ai.py`, porque a V2 ainda usa esse módulo para análise do PCAP reduzido.
- Não altere a estratégia de não fazer merge gigante antes da indexação.
- Se mexer em exportação, valide que o PCAP final abre no Wireshark e que o HTML mantém as seções antigas e novas.
- Se mexer em relatório, rode `v2/tests/test_v2_diagnostics.py` e `v2/tests/test_v2_report.py`.
- Se mexer em paralelismo, rode `v2/tests/test_v2_performance.py` e `v2/tests/test_v2_export.py`.
- Se mexer em Rust, compile com `cargo build --release` e confirme que a CLI continua aceitando `--performance` e `--workers`.
- Use `apply_patch` para edições manuais e evite refatorações amplas sem necessidade.
- Não inclua PCAPs, DBs ou relatórios reais no handoff, README ou commits públicos.

## 13. Informações Redigidas ou Omitidas por Segurança

- IPs públicos e privados reais usados nos servidores e capturas foram omitidos ou generalizados neste handoff.
- Números telefônicos reais vistos em testes, Call-IDs reais e caminhos completos de artefatos com dados de chamada não foram listados.
- Nenhuma credencial, token, chave privada, cookie ou senha foi encontrada ou copiada para este documento.
- PCAPs, SQLite gerados e relatórios de validação não foram reproduzidos no documento por conterem potencialmente dados operacionais sensíveis.

## 14. Lacunas, Inferências e Pontos Não Confirmados

- Inferência: o ambiente principal de operação continuará sendo Windows 64 bits com Wireshark instalado no caminho padrão.
- Inferência: os servidores de captura permanecem sincronizados por NTP, pois isso foi informado durante a conversa e é premissa da correlação por janela temporal.
- Não confirmado por CI: não há pipeline de integração contínua identificado no workspace.
- Não confirmado: cobertura de testes end-to-end com fixtures sintéticas completas para PCAP/PCAPNG; os testes atuais são majoritariamente unitários e houve validação manual/operacional com captura real.
- Não confirmado: suporte completo do motor Rust a todos os formatos PCAPNG e linktypes usados em produção; o próprio código emite warning sobre PCAPNG inicial.
- Não confirmado: comportamento com SRTP sem chaves; a documentação e regras indicam limitação esperada, mas não há fixture dedicada verificada neste handoff.
