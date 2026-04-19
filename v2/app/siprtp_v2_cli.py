#!/usr/bin/env python3
"""Command line interface for SIP/RTP Analyzer V2."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

try:  # pragma: no cover
    from . import siprtp_v2_benchmark
    from . import siprtp_v2_core
    from . import siprtp_v2_export
except ImportError:  # pragma: no cover
    import siprtp_v2_benchmark
    import siprtp_v2_core
    import siprtp_v2_export


def print_event(payload: dict) -> None:
    print(json.dumps(payload, ensure_ascii=False), flush=True)


def cmd_index(args: argparse.Namespace) -> None:
    result = siprtp_v2_core.index_folders(
        sip_dir=Path(args.sip_dir),
        rtp_dir=Path(args.rtp_dir),
        db_path=Path(args.db) if args.db else None,
        sip_servers=args.sip_servers,
        rtp_servers=args.rtp_servers,
        force=args.force,
        prefer_rust=not args.no_rust,
        fast_indexer=Path(args.fast_indexer) if args.fast_indexer else None,
        tshark_path=args.tshark,
        performance_profile=args.performance,
        workers=args.workers,
        progress_callback=print_event,
    )
    print(json.dumps({"type": "summary", **result}, ensure_ascii=False), flush=True)


def cmd_benchmark(args: argparse.Namespace) -> None:
    base = siprtp_v2_benchmark.default_datalog_base(Path(args.out_dir) if args.out_dir else None)
    out_json = Path(args.out_json) if args.out_json else base.with_suffix(".json")
    out_csv = Path(args.out_csv) if args.out_csv else base.with_suffix(".csv")
    rows = siprtp_v2_benchmark.run_index_benchmark(
        sip_dir=Path(args.sip_dir),
        rtp_dir=Path(args.rtp_dir),
        db_path=Path(args.db),
        sip_servers=args.sip_servers,
        rtp_servers=args.rtp_servers,
        performance_profile=args.performance,
        workers=args.workers,
        iterations=args.iterations,
        prefer_rust=not args.no_rust,
        fast_indexer=Path(args.fast_indexer) if args.fast_indexer else None,
        tshark_path=args.tshark,
        out_json=out_json,
        out_csv=out_csv,
        progress_callback=print_event,
    )
    print(json.dumps({"type": "benchmark", "json": str(out_json), "csv": str(out_csv), "rows": rows}, ensure_ascii=False), flush=True)


def cmd_search(args: argparse.Namespace) -> None:
    rows = siprtp_v2_core.find_calls(Path(args.db), args.numero, args.inicio, args.janela, args.limit)
    for row in rows:
        print(
            "{inicio}  {fim}  {duracao_seg:>8}  {status_code!s:<5}  {from_user} -> {to_user}  {call_id}".format(
                **row
            )
        )


def cmd_export(args: argparse.Namespace) -> None:
    result = siprtp_v2_export.export_call(
        db_path=Path(args.db),
        call_id=args.call_id,
        out_dir=Path(args.out_dir),
        margin_seconds=args.margin,
        filter_rtp_by_sdp=not args.no_sdp_rtp_filter,
        performance_profile=args.performance,
        workers=args.workers,
        status_callback=lambda message: print(json.dumps({"type": "log", "message": message}, ensure_ascii=False)),
    )
    print(f"PCAP reduzido: {result['pcap']}")
    print(f"Relatorio JSON: {result['report_json']}")
    print(f"Relatorio HTML: {result['report_html']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SIP/RTP Analyzer V2")
    sub = parser.add_subparsers(dest="command", required=True)

    index = sub.add_parser("indexar-pastas", help="Indexa pastas SIP e RTP sem merge gigante")
    index.add_argument("--sip-dir", required=True)
    index.add_argument("--rtp-dir", required=True)
    index.add_argument("--db")
    index.add_argument("--sip-servers", default="177.53.16.6,177.53.16.41")
    index.add_argument("--rtp-servers", default="177.53.16.42,177.53.16.43,177.53.16.45")
    index.add_argument("--force", action="store_true")
    index.add_argument("--no-rust", action="store_true", help="Forca fallback Python/TShark")
    index.add_argument("--fast-indexer")
    index.add_argument("--tshark")
    index.add_argument("--performance", choices=["safe", "balanced", "turbo"], default="balanced")
    index.add_argument("--workers", default="auto", help="auto ou numero de workers")
    index.set_defaults(func=cmd_index)

    bench = sub.add_parser("benchmark-indexacao", help="Mede desempenho da indexacao V2 e grava datalog JSON/CSV")
    bench.add_argument("--sip-dir", required=True)
    bench.add_argument("--rtp-dir", required=True)
    bench.add_argument("--db", required=True)
    bench.add_argument("--sip-servers", default="177.53.16.6,177.53.16.41")
    bench.add_argument("--rtp-servers", default="177.53.16.42,177.53.16.43,177.53.16.45")
    bench.add_argument("--performance", choices=["safe", "balanced", "turbo"], default="balanced")
    bench.add_argument("--workers", default="auto", help="auto ou numero de workers")
    bench.add_argument("--iterations", type=int, default=1)
    bench.add_argument("--no-rust", action="store_true", help="Forca fallback Python/TShark")
    bench.add_argument("--fast-indexer")
    bench.add_argument("--tshark")
    bench.add_argument("--out-dir")
    bench.add_argument("--out-json")
    bench.add_argument("--out-csv")
    bench.set_defaults(func=cmd_benchmark)

    search = sub.add_parser("buscar", help="Busca chamadas no SQLite V2")
    search.add_argument("--db", required=True)
    search.add_argument("--numero", required=True)
    search.add_argument("--inicio", required=True)
    search.add_argument("--janela", type=float, default=10.0)
    search.add_argument("--limit", type=int, default=50)
    search.set_defaults(func=cmd_search)

    export = sub.add_parser("extrair", help="Exporta chamada a partir do SQLite V2")
    export.add_argument("--db", required=True)
    export.add_argument("--call-id", required=True)
    export.add_argument("--out-dir", default="v2_exports")
    export.add_argument("--margin", type=float, default=10.0)
    export.add_argument("--no-sdp-rtp-filter", action="store_true", help="Usa o filtro RTP amplo legado em vez de IP/porta do SDP")
    export.add_argument("--performance", choices=["safe", "balanced", "turbo"], default="balanced")
    export.add_argument("--workers", default="auto", help="auto ou numero de workers")
    export.set_defaults(func=cmd_export)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
