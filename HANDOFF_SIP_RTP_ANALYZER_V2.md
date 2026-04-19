# Handoff de Desenvolvimento - SIP/RTP Analyzer V2

_Gerado em: 2026-04-19 20:11 (America/Sao_Paulo)_

## 1. Objetivo da Aplicacao

O SIP/RTP Analyzer V2 e uma ferramenta local para analise operacional de chamadas SIP/RTP em capturas PCAP de alto volume. O publico principal e analista de operadora de telefonia que recebe muitas chamadas em uma unica coleta e precisa localizar rapidamente uma chamada especifica por numero e horario, exportar apenas os pacotes relevantes e gerar um relatorio tecnico.

O problema original era o custo de abrir, filtrar e investigar PCAPs grandes no Wireshark. A V2 evita o fluxo antigo de juntar tudo em um arquivo gigante antes da busca: as capturas SIP e RTP permanecem em pastas separadas, normalmente com arquivos de 50 MB gerados por `tcpdump -C 50`, e o `mergecap` so e usado no final para montar o PCAP reduzido da chamada selecionada.

## 2. Estado Atual do Desenvolvimento

A V2 esta funcional, empacotada e publicada no repositorio. O fluxo principal ja cobre:

- GUI Tkinter V2 em `v2/app/siprtp_v2_gui.py`.
- CLI V2 em `v2/app/siprtp_v2_cli.py`.
- Motor Rust em `v2/fast_indexer/`, compilado como `siprtp_fast_indexer.exe`.
- Banco SQLite V2 com chamadas, arquivos de captura, relacao chamada/arquivo e midias SDP.
- Busca por numero + horario diretamente no SQLite.
- Exportacao seletiva por `Call-ID`.
- Filtro RTP por SDP, reduzindo o PCAP final para os fluxos da chamada quando ha IP/porta disponivel.
- Exportacao paralela controlada por perfil `safe`, `balanced`, `turbo` e `workers=auto|N`.
- Indexacao Rust com `--performance` e `--workers`, incluindo escolha manual de threads.
- Relatorio JSON/HTML com diagnostico tecnico: veredito operacional, timeline SIP, RTP por direcao, avisos RTP, respostas SIP, streams RTP/RTCP e arquivos usados.
- Modo oficial de benchmark de indexacao com datalog JSON/CSV.

Artefatos atuais relevantes:

- `dist_v2/SIPRTPAnalyzerV2.exe`
- `dist_v2/siprtp_fast_indexer.exe`
- `SIPRTPAnalyzerV2_Portable.zip`
- `SIPRTPAnalyzerV2.spec`
- `build_v2.ps1`

Validacoes recentes confirmadas:

- `python -m unittest discover -s v2/tests`: 21 testes OK.
- `cargo test --manifest-path v2/fast_indexer/Cargo.toml`: 7 testes OK.
- `py_compile` dos modulos principais Python: OK.
- `dist_v2/SIPRTPAnalyzerV2.exe --smoke-test`: OK.
- `dist_v2/siprtp_fast_indexer.exe index-folders --help`: OK.
- Benchmark real local apos otimizacao: tempo total aproximado caiu de 60.5s para 9.8s na mesma captura, mantendo 48.479 chamadas e 669.580 eventos SIP indexados.

## 3. Historico Narrativo do Desenvolvimento

O projeto comecou como uma ferramenta V1 em Python/TShark para indexar um PCAP unico, buscar chamadas SIP e extrair chamadas especificas. Essa versao resolveu a prova de conceito, mas ainda herdava o gargalo operacional: trabalhar com um PCAP grande ja mesclado.

Depois o fluxo foi redesenhado para refletir a captura real da operadora. As coletas SIP e RTP sao feitas em servidores separados e quebradas em arquivos de 50 MB. A decisao tecnica central da V2 foi manter esses arquivos separados e indexar apenas o que precisa ser indexado. O SIP e processado com profundidade; o RTP e catalogado por tempo e so e filtrado/analisado quando uma chamada e escolhida.

Foi criado um motor Rust para acelerar a indexacao, enquanto Python continuou responsavel por GUI, CLI, busca, exportacao, relatorio e fallback. O contrato entre Python e Rust usa subprocesso com JSON Lines para progresso em tempo real.

Em seguida, a exportacao foi otimizada. Primeiro ela selecionava arquivos por janela de tempo, o que ainda podia trazer muitos pacotes RTP. Depois passou a filtrar RTP por IP/porta extraidos do SDP. Mais tarde, o recorte/filtro por arquivo foi paralelizado com `ThreadPoolExecutor`, mantendo o `mergecap` final serial e deterministico.

A GUI tambem evoluiu: ficou mais responsiva em telas menores, com scroll e organizacao por blocos, mantendo a logica ja existente. Os controles de desempenho e workers passaram a afetar tanto a indexacao Rust quanto a exportacao.

A fase de diagnostico tecnico fortaleceu o relatorio: agora ele exibe um veredito operacional no topo, timeline SIP simplificada e RTP por direcao, apontando cenarios como chamada falhada, chamada completada sem midia, audio unilateral, divergencia de midia e possivel problema NAT/SDP.

A mudanca mais recente focou desempenho de indexacao. O Rust foi modularizado, ganhou preflight para falhar cedo em formatos/linktypes nao priorizados, modo de benchmark oficial e leitura PCAP classica mais eficiente com `BufReader` e buffer reutilizado. Em captura real local, o catalogo RTP deixou de ser o gargalo principal.

## 4. Arquitetura e Fluxo Principal

Fluxo operacional V2:

1. O usuario seleciona `Pasta SIP`, `Pasta RTP`, `Database`, `Saida`, servidores SIP/RTP, perfil de desempenho e workers na GUI ou CLI.
2. O Python chama `siprtp_v2_core.index_folders(...)`.
3. O core tenta localizar `siprtp_fast_indexer.exe`.
4. Se o Rust estiver disponivel, roda `index-folders` com `--performance` e `--workers`.
5. O Rust emite JSON Lines com progresso, contadores e tempos por fase.
6. Se o Rust nao existir ou falhar em caso recuperavel, o Python usa fallback TShark por arquivo.
7. O SQLite V2 armazena metadados de captura, chamadas, arquivos relacionados e SDP.
8. A busca usa `siprtp_v2_db.find_calls(...)`, normalizando numeros e aplicando janela de horario.
9. A exportacao usa `siprtp_v2_export.export_call(...)`:
   - consulta `calls`, `call_files`, `capture_files` e `sdp_media`;
   - seleciona arquivos SIP relacionados ao `Call-ID`;
   - seleciona arquivos RTP por intersecao de tempo e SDP;
   - recorta por tempo com `editcap`;
   - filtra SIP por `sip.Call-ID`;
   - filtra RTP/RTCP por IP/porta SDP quando possivel;
   - executa recortes/filtros em paralelo;
   - roda `mergecap` no final;
   - chama `siprtp_ai.analyze_pcap_file(...)`;
   - grava relatorio JSON/HTML com `siprtp_v2_report.write_reports(...)`.

Limites de responsabilidade:

- Rust: leitura/indexacao/catologacao rapida e escrita SQLite.
- Python: GUI, CLI, busca, exportacao, relatorio, fallback e orquestracao.
- Wireshark tools: recorte, filtro final, merge e analise detalhada do PCAP reduzido.

## 5. Linguagens, Frameworks, Bibliotecas e Ferramentas

Linguagens:

- Python 3.12 no ambiente atual.
- Rust 2021 para o motor indexador.

GUI:

- Tkinter/ttk.
- Runtime Tcl/Tk copiado/empacotado via `build_v2.ps1`.

Crates Rust confirmados em `v2/fast_indexer/Cargo.toml`:

- `clap` com `derive`
- `etherparse`
- `pcap-parser`
- `rusqlite` com feature `bundled`
- `serde`
- `serde_json`

Ferramentas externas:

- `tshark.exe`
- `editcap.exe`
- `mergecap.exe`
- PyInstaller
- Cargo/Rust para build do motor

Banco:

- SQLite V2.
- Schema e helpers em `v2/app/siprtp_v2_db.py`.
- Escrita Rust centralizada em transacao unica no final da indexacao.

Plataforma alvo:

- Windows 64 bits.
- Wireshark preferencialmente instalado no caminho padrao.

## 6. Habilidades e Competencias Aplicadas

- Analise SIP/RTP e diagnostico VoIP.
- Processamento de PCAP com TShark, Editcap e Mergecap.
- Parsing SIP/SDP em Rust.
- Indexacao operacional com SQLite.
- Desenvolvimento desktop com Python/Tkinter.
- Interoperabilidade Python/Rust por subprocesso e JSON Lines.
- Paralelismo controlado por CPU/RAM/perfil.
- Empacotamento Windows com PyInstaller.
- Relatorios HTML/JSON.
- Benchmark e datalog de performance.
- Testes unitarios Python e Rust.
- Cuidados de seguranca para nao versionar capturas, bancos ou relatorios reais.

## 7. Mapa de Arquivos e Modulos Principais

Raiz do projeto:

- `README.md`: instrucoes de uso, build, CLI e benchmark.
- `HANDOFF_SIP_RTP_ANALYZER_V2.md`: este documento de continuidade.
- `.gitignore`: bloqueia PCAPs, bancos SQLite, exports, benchmarks, capturas e builds temporarios.
- `build_v2.ps1`: build completo da V2, incluindo Rust e PyInstaller.
- `SIPRTPAnalyzerV2.spec`: configuracao PyInstaller.
- `Abrir_SIP_RTP_GUI_V2.bat`: launcher local da GUI V2.
- `SIPRTPAnalyzerV2_Portable.zip`: pacote portable para teste em outra maquina.

Compatibilidade reaproveitada:

- `siprtp_ai.py`: modulo Python legado reaproveitado pela V2 para analise do PCAP reduzido e montagem dos fatos SIP/RTP. Nao remover sem migrar antes `analyze_pcap_file(...)`.

V2 Python:

- `v2/app/siprtp_v2_gui.py`: interface Tkinter V2.
- `v2/app/siprtp_v2_cli.py`: CLI V2, incluindo `benchmark-indexacao`.
- `v2/app/siprtp_v2_core.py`: orquestracao Rust/fallback TShark e parse de progresso JSON Lines.
- `v2/app/siprtp_v2_db.py`: schema SQLite V2, inserts e busca.
- `v2/app/siprtp_v2_export.py`: selecao de arquivos, filtros SIP/RTP, exportacao paralela e merge.
- `v2/app/siprtp_v2_performance.py`: calculo de workers por perfil, CPU e RAM.
- `v2/app/siprtp_v2_report.py`: relatorio HTML/JSON V2.
- `v2/app/siprtp_v2_tk_runtime.py`: configuracao Tcl/Tk antes de importar Tkinter no executavel.
- `v2/app/siprtp_v2_benchmark.py`: benchmark de indexacao e datalog JSON/CSV.

V2 Rust:

- `v2/fast_indexer/Cargo.toml`: dependencias Rust.
- `v2/fast_indexer/src/main.rs`: CLI Rust, coordenacao geral, preflight, progresso e comandos.
- `v2/fast_indexer/src/types.rs`: tipos compartilhados do indexador.
- `v2/fast_indexer/src/pcap_reader.rs`: leitura PCAP classica e decodificacao basica de pacotes.
- `v2/fast_indexer/src/sip_parser.rs`: deteccao SIP, parse SIP/SDP e normalizacao de numeros.
- `v2/fast_indexer/src/aggregator.rs`: agregacao de eventos por Call-ID.
- `v2/fast_indexer/src/db_writer.rs`: escrita SQLite em transacao unica.

Testes:

- `v2/tests/test_v2_core.py`
- `v2/tests/test_v2_db.py`
- `v2/tests/test_v2_diagnostics.py`
- `v2/tests/test_v2_export.py`
- `v2/tests/test_v2_performance.py`
- `v2/tests/test_v2_report.py`
- `v2/tests/test_v2_benchmark.py`
- Testes Rust inline nos modulos do `v2/fast_indexer/src/`.

## 8. Comandos Uteis

Abrir GUI V2:

```powershell
.\Abrir_SIP_RTP_GUI_V2.bat
```

Indexar pastas pela CLI V2:

```powershell
python .\v2\app\siprtp_v2_cli.py indexar-pastas --sip-dir .\SIP --rtp-dir .\RTP --db .\capturas.siprtp.v2.sqlite --force --performance balanced --workers auto
```

Buscar chamada pela CLI V2:

```powershell
python .\v2\app\siprtp_v2_cli.py buscar --db .\capturas.siprtp.v2.sqlite --numero 5511999999999 --inicio "2026-04-17 15:57:36" --janela 10
```

Extrair chamada pela CLI V2:

```powershell
python .\v2\app\siprtp_v2_cli.py extrair --db .\capturas.siprtp.v2.sqlite --call-id "CALL_ID_AQUI" --out-dir .\v2_exports --margin 10 --performance balanced --workers auto
```

Benchmark de indexacao:

```powershell
python .\v2\app\siprtp_v2_cli.py benchmark-indexacao --sip-dir .\SIP --rtp-dir .\RTP --db .\benchmark.sqlite --performance balanced --workers auto --out-dir .\benchmarks
```

Compilar motor Rust:

```powershell
cargo build --release --manifest-path .\v2\fast_indexer\Cargo.toml
```

Rodar testes Rust:

```powershell
cargo test --manifest-path .\v2\fast_indexer\Cargo.toml
```

Rodar testes Python V2:

```powershell
python -m unittest discover -s v2/tests
```

Validar sintaxe dos modulos principais:

```powershell
python -m py_compile siprtp_ai.py v2/app/siprtp_v2_core.py v2/app/siprtp_v2_export.py v2/app/siprtp_v2_report.py v2/app/siprtp_v2_gui.py v2/app/siprtp_v2_db.py v2/app/siprtp_v2_cli.py v2/app/siprtp_v2_benchmark.py
```

Gerar executaveis V2:

```powershell
.\build_v2.ps1
```

Smoke test:

```powershell
.\dist_v2\SIPRTPAnalyzerV2.exe --smoke-test
.\dist_v2\siprtp_fast_indexer.exe index-folders --help
```

## 9. Decisoes Tecnicas Relevantes

- Nao fazer `mergecap` de preparacao. A V2 trabalha com pastas SIP/RTP separadas.
- Indexacao profunda inicial e apenas SIP; RTP e catalogado por tempo e analisado sob demanda.
- Rust e o caminho principal da indexacao; TShark permanece como fallback.
- O fallback deve acontecer cedo quando possivel, especialmente para PCAPNG ou linktype nao priorizado.
- SQLite nao deve ser escrito em paralelo por varias threads. O Rust consolida resultados e grava em transacao unica.
- A exportacao paraleliza `editcap`/`tshark` por arquivo candidato, mas mantem `mergecap` serial.
- O filtro RTP por SDP deve ser preservado para evitar PCAPs finais grandes.
- `workers=auto` e `performance=balanced` sao os padroes seguros.
- Usuario avancado pode usar `--workers N` para forcar threads no Rust e na exportacao.
- Relatorio tecnico usa regras locais deterministicas. IA generativa, quando existir, deve receber apenas fatos estruturados, nao o PCAP bruto.
- PCAPNG nao e o foco desta fase; o formato prioritario e PCAP classico de `tcpdump`.

## 10. Problemas Conhecidos, Limitacoes e Riscos

- O suporte Rust completo a PCAPNG ainda nao e objetivo concluido. O preflight detecta PCAPNG cedo e permite fallback TShark.
- Linktypes fora do conjunto priorizado podem cair em fallback ou gerar aviso.
- A exportacao/análise dependem de `tshark.exe`, `editcap.exe` e `mergecap.exe`.
- Capturas com SRTP sem chaves podem ser identificadas, mas nao terao metricas completas de audio.
- A deteccao RTP depende de SDP e da decodificacao do TShark. Em chamadas com SDP incompleto ou reescrito por SBC/NAT, pode ser necessario validar manualmente.
- O veredito operacional e uma classificacao por regra; ajuda triagem, mas nao substitui analise manual em incidentes complexos.
- Benchmark real local usa capturas operacionais. Os datalogs sao uteis para comparacao, mas nao devem ser publicados se contiverem caminhos ou metadados sensiveis.
- Ainda nao ha pipeline CI identificado no repositorio.
- O build portable inclui binarios e runtime; ao commitar artefatos, conferir explicitamente que nenhum PCAP/SQLite/export real foi adicionado.

## 11. Proximos Passos Recomendados

1. Adicionar botao de benchmark na GUI, usando `siprtp_v2_benchmark.py`, para medir indexacao sem abrir CLI.
2. Criar CI no GitHub Actions para `python -m unittest discover -s v2/tests` e `cargo test --manifest-path v2/fast_indexer/Cargo.toml`.
3. Criar fixtures sinteticas pequenas de SIP/RTP para testes end-to-end sem dados reais.
4. Melhorar suporte Rust a PCAPNG e outros linktypes usados em producao.
5. Adicionar tela de detalhes da chamada antes da exportacao, exibindo Call-ID, SDP, endpoints RTP e arquivos candidatos.
6. Versionar releases portable com nomes como `SIPRTPAnalyzerV2-2.1.0-portable.zip` e changelog.
7. Criar rotina de validacao de ambiente na GUI: Rust indexer, Wireshark tools, permissao de pasta, versao do banco e espaco livre.
8. Revisar limpeza de temporarios quando `editcap` ou `tshark` falham, reduzindo sobras com permissao problematica.

## 12. Contexto Essencial para Outra IA Continuar

- Antes de editar, leia `README.md`, `siprtp_ai.py`, `v2/app/siprtp_v2_core.py`, `v2/app/siprtp_v2_export.py`, `v2/app/siprtp_v2_report.py` e `v2/fast_indexer/src/main.rs`.
- Preserve `siprtp_ai.py`: a V2 ainda depende dele para analisar o PCAP reduzido.
- Nao reintroduza merge gigante antes da indexacao.
- Se mexer em exportacao, valide que o PCAP final abre no Wireshark e que o HTML mantem diagnostico, timeline e RTP por direcao.
- Se mexer em relatorio, rode `v2/tests/test_v2_diagnostics.py` e `v2/tests/test_v2_report.py`.
- Se mexer em paralelismo, rode `v2/tests/test_v2_performance.py`, `v2/tests/test_v2_export.py` e um benchmark pequeno.
- Se mexer em Rust, rode `cargo test --manifest-path v2/fast_indexer/Cargo.toml` e compile release.
- Se mexer em benchmark, rode `v2/tests/test_v2_benchmark.py`.
- Use `apply_patch` para edicoes manuais.
- Nunca inclua PCAPs, bancos SQLite, exports reais ou datalogs sensiveis em commit publico.

## 13. Informacoes Redigidas ou Omitidas por Seguranca

- Numeros telefonicos reais usados em testes foram omitidos.
- Call-IDs reais de producao foram omitidos.
- Caminhos completos de capturas e relatorios reais foram omitidos.
- IPs e detalhes sensiveis de ambiente operacional foram generalizados quando nao eram necessarios para continuidade.
- PCAPs, bancos SQLite, exports e datalogs reais nao foram reproduzidos neste handoff.
- Nenhum token, senha, chave privada, cookie ou credencial foi identificado ou copiado para este documento.

## 14. Lacunas, Inferencias e Pontos Nao Confirmados

- Inferencia: o ambiente principal continua sendo Windows 64 bits com Wireshark instalado.
- Inferencia: as capturas SIP/RTP continuam sincronizadas por horario, pois essa e uma premissa operacional informada durante o desenvolvimento.
- Nao confirmado por CI: nao ha workflow GitHub Actions ativo no workspace atual.
- Nao confirmado: cobertura end-to-end completa com fixtures PCAP/PCAPNG sinteticas.
- Nao confirmado: suporte Rust completo para todos os formatos PCAPNG/linktypes que possam aparecer em producao.
- Nao confirmado: comportamento detalhado com SRTP sem chaves em todos os cenarios.

