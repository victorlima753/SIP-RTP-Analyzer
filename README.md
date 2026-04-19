# SIP/RTP Analyzer V2

Ferramenta local para acelerar análise de chamadas SIP/RTP em capturas grandes de operadora.

A V2 trabalha com capturas separadas em pastas `SIP/` e `RTP/`, evitando gerar um `saida.pcap` gigante antes da busca. O fluxo recomendado é indexar as pastas uma vez, buscar chamadas por número e horário, exportar apenas a chamada selecionada e gerar PCAP reduzido com relatório JSON/HTML.

## Estrutura de Captura

```text
captura_2026_04_17/
  SIP/
    *.pcap
    *.pcapng
  RTP/
    *.pcap
    *.pcapng
```

## Abrir a Interface

```powershell
.\Abrir_SIP_RTP_GUI_V2.bat
```

Também é possível executar diretamente:

```powershell
.\dist_v2\SIPRTPAnalyzerV2.exe
```

## Fluxo na GUI

1. Selecione `Pasta SIP`, `Pasta RTP`, `Database` e `Saida`.
2. Ajuste `Desempenho` e `Workers`, se necessário.
3. Clique em `Indexar pastas`.
4. Informe um ou mais números e horários.
5. Clique em `Buscar`.
6. Selecione as chamadas encontradas.
7. Clique em `Exportar selecionadas` ou `Exportar todas encontradas`.

Formato aceito para múltiplas buscas:

```text
5511965116044; 2026-04-17 15:57:36
5512988839274; 2026-04-17 16:15:15
```

## CLI V2

Indexar pastas:

```powershell
& 'C:\Users\Victor\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' .\v2\app\siprtp_v2_cli.py indexar-pastas --sip-dir .\SIP --rtp-dir .\RTP --db .\capturas.siprtp.v2.sqlite --force --performance balanced --workers auto
```

Buscar chamada:

```powershell
& 'C:\Users\Victor\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' .\v2\app\siprtp_v2_cli.py buscar --db .\capturas.siprtp.v2.sqlite --numero 5511999999999 --inicio "2026-04-17 15:57:36" --janela 10
```

Extrair chamada:

```powershell
& 'C:\Users\Victor\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' .\v2\app\siprtp_v2_cli.py extrair --db .\capturas.siprtp.v2.sqlite --call-id "CALL_ID_AQUI" --out-dir .\v2_exports --margin 10 --performance balanced --workers auto
```

Benchmark da indexacao:

```powershell
& 'C:\Users\Victor\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' .\v2\app\siprtp_v2_cli.py benchmark-indexacao --sip-dir .\SIP --rtp-dir .\RTP --db .\capturas.benchmark.sqlite --performance balanced --workers auto --out-dir .\benchmarks
```

O benchmark gera um datalog `.json` e `.csv` com tempo total, workers usados, quantidade de arquivos SIP/RTP, tamanho das pastas, chamadas/eventos encontrados e tempos por fase: scan SIP, catalogo RTP e escrita SQLite.

## Build

```powershell
.\build_v2.ps1
```

O build gera:

- `dist_v2\SIPRTPAnalyzerV2.exe`
- `dist_v2\siprtp_fast_indexer.exe`
- `dist_v2\_internal\`

Para gerar o motor Rust manualmente:

```powershell
cd .\v2\fast_indexer
cargo build --release
```

## Requisitos

- Windows 64 bits.
- Wireshark instalado, preferencialmente em `C:\Program Files\Wireshark`.
- Python apenas para rodar a versão fonte/CLI.
- Rust/Cargo apenas para recompilar o motor `siprtp_fast_indexer.exe`.

O pacote portable já inclui a GUI empacotada e o motor Rust compilado.

## Desempenho

O motor Rust prioriza PCAP classico gerado por `tcpdump`. Antes de processar a pasta completa, ele valida formato e linktype dos arquivos; se encontrar PCAPNG ou linktype ainda nao suportado, a aplicacao aciona fallback TShark de forma antecipada e registra o aviso no log.

## Relatórios

A exportação gera:

- `call_<numero>_<YYYYMMDD_HHMMSS>.pcapng`
- `call_<numero>_<YYYYMMDD_HHMMSS>_report.json`
- `call_<numero>_<YYYYMMDD_HHMMSS>_report.html`

O HTML inclui:

- Veredito operacional.
- Diagnóstico técnico.
- Timeline SIP.
- RTP por direção.
- Avisos RTP.
- Streams RTP/RTCP.
- Arquivos usados e desempenho.

## Testes

```powershell
& 'C:\Users\Victor\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m unittest discover -s v2/tests
```
