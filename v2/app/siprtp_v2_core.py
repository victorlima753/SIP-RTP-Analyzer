#!/usr/bin/env python3
"""Core orchestration for SIP/RTP Analyzer V2."""

from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Iterable

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import siprtp_ai  # noqa: E402

try:  # pragma: no cover - supports both package and script imports
    from . import siprtp_v2_db as db
except ImportError:  # pragma: no cover
    import siprtp_v2_db as db


DEFAULT_SIP_SERVERS = ["177.53.16.6", "177.53.16.41"]
DEFAULT_RTP_SERVERS = ["177.53.16.42", "177.53.16.43", "177.53.16.45"]
PCAP_NAME_MARKERS = (".pcap", ".pcapng", ".cap")


ProgressCallback = Callable[[dict[str, Any]], None]


def default_db_path_for_dirs(sip_dir: Path, rtp_dir: Path | None = None) -> Path:
    base = sip_dir.parent if sip_dir.name.lower() == "sip" else sip_dir
    if rtp_dir and rtp_dir.exists() and rtp_dir.parent == sip_dir.parent:
        base = sip_dir.parent
    return base / "capturas.siprtp.v2.sqlite"


def split_servers(value: str | Iterable[str] | None, default: list[str]) -> list[str]:
    if value is None:
        return list(default)
    if isinstance(value, str):
        items = value.replace(";", ",").split(",")
    else:
        items = list(value)
    clean = [item.strip() for item in items if item and item.strip()]
    return clean or list(default)


def iter_capture_files(directory: Path) -> list[Path]:
    if not directory.exists():
        raise FileNotFoundError(f"Pasta nao encontrada: {directory}")
    if not directory.is_dir():
        raise NotADirectoryError(f"Nao e uma pasta: {directory}")
    return sorted(
        path
        for path in directory.rglob("*")
        if path.is_file() and is_capture_file(path)
    )


def is_capture_file(path: Path) -> bool:
    name = path.name.lower()
    return any(marker in name for marker in PCAP_NAME_MARKERS)


def emit(callback: ProgressCallback | None, payload: dict[str, Any]) -> None:
    if callback:
        callback(payload)


def locate_fast_indexer(explicit: Path | None = None) -> Path | None:
    candidates: list[Path] = []
    if explicit:
        candidates.append(explicit)
    env_value = os.environ.get("SIPRTP_FAST_INDEXER")
    if env_value:
        candidates.append(Path(env_value))
    executable_dir = Path(sys.executable).resolve().parent
    module_dir = Path(__file__).resolve().parent
    candidates.extend(
        [
            executable_dir / "siprtp_fast_indexer.exe",
            executable_dir / "siprtp_fast_indexer",
            module_dir / "siprtp_fast_indexer.exe",
            module_dir / "siprtp_fast_indexer",
            ROOT / "dist_v2" / "siprtp_fast_indexer.exe",
            ROOT / "v2" / "fast_indexer" / "target" / "release" / "siprtp_fast_indexer.exe",
            ROOT / "v2" / "fast_indexer" / "target" / "release" / "siprtp_fast_indexer",
        ]
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def index_folders(
    sip_dir: Path,
    rtp_dir: Path,
    db_path: Path | None = None,
    sip_servers: str | Iterable[str] | None = None,
    rtp_servers: str | Iterable[str] | None = None,
    force: bool = False,
    prefer_rust: bool = True,
    fast_indexer: Path | None = None,
    tshark_path: str | None = None,
    performance_profile: str = "balanced",
    workers: str | int | None = "auto",
    progress_callback: ProgressCallback | None = None,
) -> dict[str, Any]:
    sip_dir = Path(sip_dir).resolve()
    rtp_dir = Path(rtp_dir).resolve()
    db_path = Path(db_path).resolve() if db_path else default_db_path_for_dirs(sip_dir, rtp_dir)
    sip_list = split_servers(sip_servers, DEFAULT_SIP_SERVERS)
    rtp_list = split_servers(rtp_servers, DEFAULT_RTP_SERVERS)

    if prefer_rust:
        indexer = locate_fast_indexer(fast_indexer)
        if indexer:
            try:
                result = index_folders_with_rust(
                    indexer=indexer,
                    sip_dir=sip_dir,
                    rtp_dir=rtp_dir,
                    db_path=db_path,
                    sip_servers=sip_list,
                    rtp_servers=rtp_list,
                    force=force,
                    performance_profile=performance_profile,
                    workers=workers,
                    progress_callback=progress_callback,
                )
                if result.get("call_count", 0) > 0 or result.get("event_count", 0) > 0:
                    return result
                emit(
                    progress_callback,
                    {
                        "type": "warning",
                        "code": "rust_indexer_empty",
                        "message": "Motor Rust terminou sem chamadas SIP; usando fallback TShark para evitar indice vazio.",
                    },
                )
                return index_folders_with_tshark(
                    sip_dir=sip_dir,
                    rtp_dir=rtp_dir,
                    db_path=db_path,
                    sip_servers=sip_list,
                    rtp_servers=rtp_list,
                    force=True,
                    tshark_path=tshark_path,
                    progress_callback=progress_callback,
                )
            except Exception as exc:
                emit(
                    progress_callback,
                    {
                        "type": "warning",
                        "code": "rust_indexer_failed",
                        "message": f"Motor Rust falhou; usando fallback TShark. Detalhe: {exc}",
                    },
                )
        else:
            emit(
                progress_callback,
                {
                    "type": "warning",
                    "code": "rust_indexer_not_found",
                    "message": "Motor Rust nao encontrado; usando fallback TShark por arquivo.",
                },
            )

    return index_folders_with_tshark(
        sip_dir=sip_dir,
        rtp_dir=rtp_dir,
        db_path=db_path,
        sip_servers=sip_list,
        rtp_servers=rtp_list,
        force=force,
        tshark_path=tshark_path,
        progress_callback=progress_callback,
    )


def index_folders_with_rust(
    indexer: Path,
    sip_dir: Path,
    rtp_dir: Path,
    db_path: Path,
    sip_servers: list[str],
    rtp_servers: list[str],
    force: bool,
    performance_profile: str = "balanced",
    workers: str | int | None = "auto",
    progress_callback: ProgressCallback | None = None,
) -> dict[str, Any]:
    args = [
        str(indexer),
        "index-folders",
        "--sip-dir",
        str(sip_dir),
        "--rtp-dir",
        str(rtp_dir),
        "--db",
        str(db_path),
        "--sip-servers",
        ",".join(sip_servers),
        "--rtp-servers",
        ",".join(rtp_servers),
        "--performance",
        performance_profile,
        "--workers",
        str(workers or "auto"),
    ]
    if force:
        args.append("--force")
    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert proc.stdout is not None
    done_payload: dict[str, Any] | None = None
    for line in proc.stdout:
        clean = line.strip()
        if not clean:
            continue
        try:
            payload = json.loads(clean)
        except json.JSONDecodeError:
            payload = {"type": "log", "message": clean}
        emit(progress_callback, payload)
        if payload.get("type") == "done":
            done_payload = payload
    stderr = proc.stderr.read() if proc.stderr else ""
    return_code = proc.wait()
    if return_code != 0:
        raise RuntimeError(stderr.strip() or f"Motor Rust saiu com codigo {return_code}")
    if not done_payload:
        raise RuntimeError("Motor Rust terminou sem evento done")
    return {
        "db_path": str(db_path),
        "mode": "rust",
        "call_count": int(done_payload.get("call_count", 0)),
        "event_count": int(done_payload.get("sip_events", 0)),
        "elapsed_seconds": float(done_payload.get("elapsed_seconds", 0.0)),
    }


def index_folders_with_tshark(
    sip_dir: Path,
    rtp_dir: Path,
    db_path: Path,
    sip_servers: list[str],
    rtp_servers: list[str],
    force: bool,
    tshark_path: str | None = None,
    progress_callback: ProgressCallback | None = None,
) -> dict[str, Any]:
    if db_path.exists() and not force:
        raise FileExistsError(f"Indice ja existe: {db_path}")
    sip_files = iter_capture_files(sip_dir)
    rtp_files = iter_capture_files(rtp_dir)
    if not sip_files:
        raise FileNotFoundError(f"Nenhum PCAP encontrado na pasta SIP: {sip_dir}")
    start = time.perf_counter()
    tshark = siprtp_ai.resolve_tshark(tshark_path)
    if db_path.exists():
        siprtp_ai.delete_sqlite_files(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    config = {"sip_servers": sip_servers, "rtp_servers": rtp_servers, "engine": "python_tshark_fallback"}

    emit(progress_callback, {"type": "start", "sip_dir": str(sip_dir), "rtp_dir": str(rtp_dir), "engine": "tshark"})
    accumulators: dict[str, siprtp_ai.CallAccumulator] = {}
    call_files: dict[tuple[str, int], tuple[float, float]] = {}
    total_sip_events = 0

    with db.connect_db(db_path) as conn:
        db.init_db(conn)
        db.reset_db(conn)
        db.write_metadata(
            conn,
            {
                "tool": "siprtp_analyzer_v2",
                "engine": "python_tshark_fallback",
                "sip_dir": str(sip_dir),
                "rtp_dir": str(rtp_dir),
            },
        )
        capture_set_id = db.create_capture_set(conn, sip_dir, rtp_dir, config)

        for index, pcap in enumerate(sip_files, start=1):
            emit(progress_callback, {"type": "file_start", "role": "sip", "index": index, "total": len(sip_files), "path": str(pcap)})
            file_first: float | None = None
            file_last: float | None = None
            file_events = 0
            file_calls: set[str] = set()
            for row in siprtp_ai.iter_tshark_field_rows(tshark, pcap, "sip", siprtp_ai.SIP_FIELDS):
                event = siprtp_ai.sip_event_from_row(row)
                if event is None:
                    continue
                file_events += 1
                total_sip_events += 1
                file_calls.add(event.call_id)
                file_first = event.ts_epoch if file_first is None else min(file_first, event.ts_epoch)
                file_last = event.ts_epoch if file_last is None else max(file_last, event.ts_epoch)
                accumulator = accumulators.get(event.call_id)
                if accumulator is None:
                    accumulator = siprtp_ai.CallAccumulator(event.call_id)
                    accumulators[event.call_id] = accumulator
                accumulator.update(event)
                if file_events % 50000 == 0:
                    emit(
                        progress_callback,
                        {
                            "type": "progress",
                            "role": "sip",
                            "packets": 0,
                            "sip_events": total_sip_events,
                            "calls": len(accumulators),
                            "path": str(pcap),
                            "elapsed_seconds": round(time.perf_counter() - start, 3),
                        },
                    )
            file_id = db.insert_capture_file(
                conn,
                capture_set_id,
                "sip",
                pcap,
                file_first,
                file_last,
                server_ip=detect_server_ip_from_name(pcap, sip_servers),
                packet_count=file_events,
                parse_status="ok",
            )
            for call_id in file_calls:
                if file_first is not None and file_last is not None:
                    call_files[(call_id, file_id)] = (file_first, file_last)
            emit(
                progress_callback,
                {
                    "type": "file_done",
                    "role": "sip",
                    "path": str(pcap),
                    "first_epoch": file_first,
                    "last_epoch": file_last,
                    "sip_events": file_events,
                    "calls": len(file_calls),
                },
            )

        for index, pcap in enumerate(rtp_files, start=1):
            emit(progress_callback, {"type": "file_start", "role": "rtp", "index": index, "total": len(rtp_files), "path": str(pcap)})
            first_epoch, last_epoch, packet_count = scan_capture_time(tshark, pcap)
            db.insert_capture_file(
                conn,
                capture_set_id,
                "rtp",
                pcap,
                first_epoch,
                last_epoch,
                server_ip=detect_server_ip_from_name(pcap, rtp_servers),
                packet_count=packet_count,
                parse_status="ok",
            )
            emit(
                progress_callback,
                {
                    "type": "file_done",
                    "role": "rtp",
                    "path": str(pcap),
                    "first_epoch": first_epoch,
                    "last_epoch": last_epoch,
                    "packets": packet_count,
                },
            )

        for accumulator in accumulators.values():
            summary = accumulator.to_summary()
            db.insert_call_summary(conn, summary)
            for item in summary.sdp_media:
                db.insert_sdp_media(conn, summary.call_id, item, summary.first_epoch)
        for (call_id, file_id), (first_epoch, last_epoch) in call_files.items():
            db.insert_call_file(conn, call_id, file_id, "sip", first_epoch, last_epoch)
        conn.commit()

    elapsed = time.perf_counter() - start
    result = {
        "type": "done",
        "db_path": str(db_path),
        "mode": "python_tshark_fallback",
        "call_count": len(accumulators),
        "sip_events": total_sip_events,
        "elapsed_seconds": round(elapsed, 3),
    }
    emit(progress_callback, result)
    return {
        "db_path": str(db_path),
        "mode": "python_tshark_fallback",
        "call_count": len(accumulators),
        "event_count": total_sip_events,
        "elapsed_seconds": elapsed,
    }


def detect_server_ip_from_name(path: Path, servers: list[str]) -> str:
    name = path.name
    for server in servers:
        if server in name or server.replace(".", "_") in name:
            return server
    return ""


def scan_capture_time(tshark: str, pcap: Path) -> tuple[float | None, float | None, int]:
    fields = ["frame.time_epoch"]
    first_epoch: float | None = None
    last_epoch: float | None = None
    count = 0
    for row in siprtp_ai.iter_tshark_field_rows(tshark, pcap, "frame", fields):
        value = siprtp_ai.parse_float(row.get("frame.time_epoch"))
        if value is None:
            continue
        count += 1
        first_epoch = value if first_epoch is None else min(first_epoch, value)
        last_epoch = value if last_epoch is None else max(last_epoch, value)
    return first_epoch, last_epoch, count


def find_calls(db_path: Path, number: str, start_time: str, window_minutes: float, limit: int = 50) -> list[dict[str, Any]]:
    return db.find_calls(db_path, number, start_time, window_minutes, limit)


def format_progress(payload: dict[str, Any]) -> str:
    kind = payload.get("type", "log")
    if kind == "start":
        workers = payload.get("workers")
        perf = payload.get("performance_profile")
        suffix = f" | desempenho={perf} | workers={workers}" if workers else ""
        return f"Iniciando indexacao V2: SIP={payload.get('sip_dir')} | RTP={payload.get('rtp_dir')}{suffix}"
    if kind == "file_start":
        return f"[{payload.get('role')}] arquivo {payload.get('index')}/{payload.get('total')}: {payload.get('path')}"
    if kind == "progress":
        return (
            f"Progresso {payload.get('role')}: eventos SIP={payload.get('sip_events')} | "
            f"chamadas={payload.get('calls')} | elapsed={payload.get('elapsed_seconds', '')}s"
        )
    if kind == "file_done":
        return f"[{payload.get('role')}] concluido: {payload.get('path')}"
    if kind == "warning":
        return f"AVISO {payload.get('code')}: {payload.get('message')}"
    if kind == "error":
        return f"ERRO {payload.get('code')}: {payload.get('message')}"
    if kind == "done":
        return (
            f"Indice V2 pronto: chamadas={payload.get('call_count')} | "
            f"eventos SIP={payload.get('sip_events')} | tempo={payload.get('elapsed_seconds')}s | "
            f"workers={payload.get('workers', '')}"
        )
    return payload.get("message") or json.dumps(payload, ensure_ascii=False)
