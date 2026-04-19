#!/usr/bin/env python3
"""Selective export for SIP/RTP Analyzer V2."""

from __future__ import annotations

import datetime as dt
import time
import json
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import siprtp_ai  # noqa: E402

try:  # pragma: no cover
    from . import siprtp_v2_db as db
    from . import siprtp_v2_performance
    from . import siprtp_v2_report
except ImportError:  # pragma: no cover
    import siprtp_v2_db as db
    import siprtp_v2_performance
    import siprtp_v2_report


StatusCallback = Callable[[str], None]
LEGACY_RTP_FILTER = "rtp || rtcp || udp"


@dataclass(frozen=True)
class ExportWorkItem:
    index: int
    role: str
    src: Path
    sliced: Path
    filtered: Path
    display_filter: str


@dataclass(frozen=True)
class ExportWorkResult:
    index: int
    role: str
    src: Path
    filtered: Path | None


def safe_name(value: str) -> str:
    clean = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in value)
    return clean[:80] or "call"


def artifact_base(out_dir: Path, row: dict[str, Any]) -> Path:
    number = row.get("to_user") or row.get("from_user") or row.get("request_uri_user") or "numero"
    digits = "".join(ch for ch in str(number) if ch.isdigit()) or safe_name(str(number))
    try:
        stamp = dt.datetime.strptime(row["inicio"], "%Y-%m-%d %H:%M:%S").strftime("%Y%m%d_%H%M%S")
    except Exception:
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    return out_dir / f"call_{digits}_{stamp}"


def find_tool(name: str, explicit: str | None = None) -> str:
    if explicit:
        return explicit
    resolved = shutil.which(name)
    if resolved:
        return resolved
    wireshark = Path(r"C:\Program Files\Wireshark") / name
    if wireshark.exists():
        return str(wireshark)
    raise FileNotFoundError(f"Ferramenta nao encontrada: {name}")


def iso_time(epoch: float) -> str:
    return dt.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")


def load_call(conn: Any, call_id: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM calls WHERE call_id = ?", (call_id,)).fetchone()
    if row is None:
        raise KeyError(f"Call-ID nao encontrado: {call_id}")
    return db.call_row_to_dict(row)


def parse_json_list(value: Any) -> list[Any]:
    if not value:
        return []
    if isinstance(value, list):
        return value
    try:
        parsed = json.loads(str(value))
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


def clean_sdp_ip(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return text.split("/")[0].strip()


def load_sdp_media(conn: Any, call_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT media, ip, port, payloads_json, attributes_json, ts_epoch, frame_number
        FROM sdp_media
        WHERE call_id = ?
        ORDER BY ts_epoch, frame_number, id
        """,
        (call_id,),
    ).fetchall()
    result: list[dict[str, Any]] = []
    for row in rows:
        result.append(
            {
                "media": row["media"],
                "ip": clean_sdp_ip(row["ip"]),
                "port": row["port"],
                "payloads": parse_json_list(row["payloads_json"]),
                "attributes": parse_json_list(row["attributes_json"]),
                "ts_epoch": row["ts_epoch"],
                "frame_number": row["frame_number"],
            }
        )
    return result


def parse_rtcp_port(attributes: list[Any]) -> int | None:
    for item in attributes:
        text = str(item).strip()
        if not text.lower().startswith("rtcp:"):
            continue
        first = text.split(":", 1)[1].strip().split()
        if first and first[0].isdigit():
            return int(first[0])
    return None


def build_rtp_endpoints(sdp_media: list[dict[str, Any]]) -> list[dict[str, Any]]:
    usable = [item for item in sdp_media if item.get("port")]
    audio = [item for item in usable if str(item.get("media", "")).lower() == "audio"]
    chosen = audio or usable
    endpoints: list[dict[str, Any]] = []
    seen: set[tuple[str, int, int | None, str]] = set()
    for item in chosen:
        try:
            rtp_port = int(item["port"])
        except (TypeError, ValueError):
            continue
        if rtp_port <= 0:
            continue
        ip = clean_sdp_ip(item.get("ip"))
        rtcp_port = parse_rtcp_port(parse_json_list(item.get("attributes")))
        if rtcp_port is None:
            rtcp_port = rtp_port + 1
        key = (ip, rtp_port, rtcp_port, str(item.get("media", "")))
        if key in seen:
            continue
        seen.add(key)
        endpoints.append(
            {
                "media": str(item.get("media", "")),
                "ip": ip,
                "rtp_port": rtp_port,
                "rtcp_port": rtcp_port,
                "payloads": parse_json_list(item.get("payloads")),
                "attributes": parse_json_list(item.get("attributes")),
            }
        )
    return endpoints


def ip_filter_field(ip: str) -> str:
    return "ipv6.addr" if ":" in ip else "ip.addr"


def build_rtp_display_filter(endpoints: list[dict[str, Any]]) -> str:
    terms: list[str] = []
    for endpoint in endpoints:
        ip = clean_sdp_ip(endpoint.get("ip"))
        ports = [endpoint.get("rtp_port"), endpoint.get("rtcp_port")]
        for raw_port in ports:
            try:
                port = int(raw_port)
            except (TypeError, ValueError):
                continue
            if port <= 0:
                continue
            if ip:
                terms.append(f"(udp && {ip_filter_field(ip)} == {ip} && udp.port == {port})")
            else:
                terms.append(f"(udp && udp.port == {port})")
    return " || ".join(dict.fromkeys(terms))


def display_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def run_checked(command: list[str], step: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        if detail:
            raise RuntimeError(f"{step} falhou: {detail}")
        raise RuntimeError(f"{step} falhou com codigo {result.returncode}")
    return result


def format_seconds(value: float) -> str:
    return f"{value:.3f}s"


def process_export_item(
    item: ExportWorkItem,
    editcap: str,
    tshark: str,
    start_epoch: float,
    end_epoch: float,
    status_callback: StatusCallback | None = None,
) -> ExportWorkResult:
    if status_callback:
        status_callback(f"Recortando {item.role}: {item.src.name}")
    run_checked(
        [editcap, "-A", iso_time(start_epoch), "-B", iso_time(end_epoch), str(item.src), str(item.sliced)],
        f"Recorte {item.role} ({item.src.name})",
    )
    if status_callback:
        status_callback(f"Filtrando {item.role}: {item.src.name}")
    run_checked(
        [tshark, "-r", str(item.sliced), "-Y", item.display_filter, "-w", str(item.filtered)],
        f"Filtro {item.role} ({item.src.name})",
    )
    if item.filtered.exists() and item.filtered.stat().st_size > 0:
        return ExportWorkResult(item.index, item.role, item.src, item.filtered)
    return ExportWorkResult(item.index, item.role, item.src, None)


def run_export_work_items(
    items: list[ExportWorkItem],
    editcap: str,
    tshark: str,
    start_epoch: float,
    end_epoch: float,
    worker_plan: siprtp_v2_performance.WorkerPlan,
    status_callback: StatusCallback | None = None,
) -> list[Path]:
    if worker_plan.workers <= 1 or len(items) <= 1:
        results = []
        for item in items:
            try:
                results.append(process_export_item(item, editcap, tshark, start_epoch, end_epoch, status_callback))
            except Exception as exc:
                raise RuntimeError(f"Falha ao exportar {item.role} ({item.src.name}): {exc}") from exc
    else:
        if status_callback:
            status_callback(f"Exportacao paralela ativa: {worker_plan.workers} workers.")
        results: list[ExportWorkResult] = []
        with ThreadPoolExecutor(max_workers=worker_plan.workers) as executor:
            futures = {
                executor.submit(process_export_item, item, editcap, tshark, start_epoch, end_epoch, status_callback): item
                for item in items
            }
            for future in as_completed(futures):
                item = futures[future]
                try:
                    results.append(future.result())
                except Exception as exc:
                    raise RuntimeError(f"Falha ao exportar {item.role} ({item.src.name}): {exc}") from exc
    return [
        result.filtered
        for result in sorted(results, key=lambda value: value.index)
        if result.filtered is not None
    ]


def select_candidate_files(conn: Any, call_id: str, margin_seconds: float) -> list[dict[str, Any]]:
    call = conn.execute("SELECT first_epoch, last_epoch FROM calls WHERE call_id = ?", (call_id,)).fetchone()
    if call is None:
        raise KeyError(f"Call-ID nao encontrado: {call_id}")
    start = float(call["first_epoch"]) - margin_seconds
    end = float(call["last_epoch"]) + margin_seconds
    sip_rows = conn.execute(
        """
        SELECT cf.* FROM capture_files cf
        JOIN call_files cfl ON cfl.file_id = cf.id
        WHERE cfl.call_id = ? AND cf.role = 'sip'
        ORDER BY cf.first_epoch
        """,
        (call_id,),
    ).fetchall()
    rtp_rows = conn.execute(
        """
        SELECT * FROM capture_files
        WHERE role = 'rtp'
          AND (last_epoch IS NULL OR last_epoch >= ?)
          AND (first_epoch IS NULL OR first_epoch <= ?)
        ORDER BY first_epoch
        """,
        (start, end),
    ).fetchall()
    results: list[dict[str, Any]] = []
    for row in list(sip_rows) + list(rtp_rows):
        results.append({key: row[key] for key in row.keys()})
    return results


def export_call(
    db_path: Path,
    call_id: str,
    out_dir: Path,
    margin_seconds: float = 10.0,
    tshark_path: str | None = None,
    editcap_path: str | None = None,
    mergecap_path: str | None = None,
    filter_rtp_by_sdp: bool = True,
    performance_profile: str = "balanced",
    workers: str | int | None = None,
    auto_workers: bool = True,
    status_callback: StatusCallback | None = None,
) -> dict[str, Any]:
    export_started = time.perf_counter()
    out_dir.mkdir(parents=True, exist_ok=True)
    tshark = find_tool("tshark.exe", tshark_path)
    editcap = find_tool("editcap.exe", editcap_path)
    mergecap = find_tool("mergecap.exe", mergecap_path)
    with db.connect_db(db_path) as conn:
        call = load_call(conn, call_id)
        files = select_candidate_files(conn, call_id, margin_seconds)
        sdp_media = load_sdp_media(conn, call_id)
        rtp_endpoints = build_rtp_endpoints(sdp_media)
        sql_call = conn.execute("SELECT first_epoch, last_epoch FROM calls WHERE call_id = ?", (call_id,)).fetchone()
        start = float(sql_call["first_epoch"]) - margin_seconds
        end = float(sql_call["last_epoch"]) + margin_seconds

    rtp_filter = build_rtp_display_filter(rtp_endpoints) if filter_rtp_by_sdp else ""
    if rtp_filter:
        rtp_filter_mode = "sdp"
        if status_callback:
            status_callback(f"Filtro RTP por SDP ativo: {len(rtp_endpoints)} endpoint(s) de midia.")
    else:
        rtp_filter = LEGACY_RTP_FILTER
        rtp_filter_mode = "fallback_amplo"
        if status_callback:
            if filter_rtp_by_sdp:
                status_callback("SDP sem IP/porta RTP utilizavel; usando filtro RTP amplo.")
            else:
                status_callback("Filtro RTP por SDP desativado; usando filtro RTP amplo.")

    worker_override = workers
    if auto_workers and siprtp_v2_performance.parse_worker_override(workers) is None:
        worker_override = None
    worker_plan = siprtp_v2_performance.calculate_worker_plan(
        profile=performance_profile,
        workers=worker_override,
        candidate_count=len(files),
    )
    if status_callback:
        ram_text = "indisponivel"
        if worker_plan.memory_total_gb is not None:
            ram_text = f"{worker_plan.memory_total_gb} GB total / {worker_plan.memory_available_gb} GB livre"
        status_callback(
            "Desempenho: "
            f"{worker_plan.profile_label}; CPU logica={worker_plan.cpu_count}; RAM={ram_text}; "
            f"workers={worker_plan.workers}; arquivos candidatos={worker_plan.candidate_count}."
        )

    base = artifact_base(out_dir, call)
    final_pcap = base.with_suffix(".pcapng")
    temp_dir = Path(tempfile.mkdtemp(prefix="siprtp_v2_export_", dir=str(out_dir)))
    produced: list[Path] = []
    timing: dict[str, float] = {}
    try:
        work_items: list[ExportWorkItem] = []
        for index, item in enumerate(files, start=1):
            src = Path(item["path"])
            role = item["role"]
            sliced = temp_dir / f"{index:04d}_{role}_slice.pcapng"
            filtered = temp_dir / f"{index:04d}_{role}_filtered.pcapng"
            display_filter = f"sip.Call-ID == {display_string(call_id)}" if role == "sip" else rtp_filter
            work_items.append(
                ExportWorkItem(
                    index=index,
                    role=role,
                    src=src,
                    sliced=sliced,
                    filtered=filtered,
                    display_filter=display_filter,
                )
            )

        filter_started = time.perf_counter()
        produced = run_export_work_items(
            work_items,
            editcap,
            tshark,
            start,
            end,
            worker_plan,
            status_callback,
        )
        timing["slice_filter_seconds"] = time.perf_counter() - filter_started
        if produced:
            merge_started = time.perf_counter()
            run_checked([mergecap, "-w", str(final_pcap), *[str(path) for path in produced]], "Merge final")
            timing["merge_seconds"] = time.perf_counter() - merge_started
        else:
            final_pcap.write_bytes(b"")
            timing["merge_seconds"] = 0.0
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    analysis: dict[str, Any] | None = None
    analysis_error = ""
    if final_pcap.exists() and final_pcap.stat().st_size > 0:
        if status_callback:
            status_callback("Analisando PCAP reduzido para gerar diagnostico SIP/RTP.")
        analysis_started = time.perf_counter()
        try:
            analysis = siprtp_ai.analyze_pcap_file(final_pcap, tshark, call_id=call_id)
        except SystemExit as exc:
            analysis_error = str(exc)
        except Exception as exc:
            analysis_error = str(exc)
        timing["analysis_seconds"] = time.perf_counter() - analysis_started
        if analysis_error and status_callback:
            status_callback(f"Analise do PCAP reduzido nao concluida: {analysis_error}")
    else:
        analysis_error = "PCAP reduzido vazio; nao foi possivel executar a analise SIP/RTP."
        timing["analysis_seconds"] = 0.0
    timing["total_seconds"] = time.perf_counter() - export_started
    if status_callback:
        status_callback(
            "Tempos exportacao: "
            f"recorte/filtro={format_seconds(timing['slice_filter_seconds'])}; "
            f"merge={format_seconds(timing['merge_seconds'])}; "
            f"analise={format_seconds(timing['analysis_seconds'])}; "
            f"total={format_seconds(timing['total_seconds'])}."
        )

    payload = {
        "call": call,
        "artifacts": {"pcap": str(final_pcap)},
        "files": [{"role": item["role"], "path": item["path"]} for item in files],
        "analysis": analysis,
        "analysis_error": analysis_error,
        "rtp_filter": {
            "mode": rtp_filter_mode,
            "enabled": bool(filter_rtp_by_sdp),
            "display_filter": rtp_filter,
            "endpoints": rtp_endpoints,
        },
        "performance": {
            "worker_plan": worker_plan.as_dict(),
            "timing_seconds": {key: round(value, 3) for key, value in timing.items()},
            "produced_fragments": len(produced),
        },
        "sdp_media": sdp_media,
        "notes": [
            "Exportacao V2 seleciona arquivos SIP por Call-ID e RTP por intersecao de horario.",
            "Quando ha SDP com IP/porta de midia, a exportacao RTP usa filtro por SDP para reduzir pacotes concorrentes.",
        ],
    }
    reports = siprtp_v2_report.write_reports(base, payload)
    return {"pcap": str(final_pcap), **reports, "call": call, "files": files}
