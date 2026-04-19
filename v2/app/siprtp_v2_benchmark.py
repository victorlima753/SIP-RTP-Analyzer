#!/usr/bin/env python3
"""Indexing benchmark helpers for SIP/RTP Analyzer V2."""

from __future__ import annotations

import csv
import datetime as dt
import json
import time
from pathlib import Path
from typing import Any, Callable

try:  # pragma: no cover
    from . import siprtp_v2_core
except ImportError:  # pragma: no cover
    import siprtp_v2_core


ProgressCallback = Callable[[dict[str, Any]], None]

BENCHMARK_FIELDS = [
    "iteration",
    "mode",
    "performance_profile",
    "workers_requested",
    "workers_used",
    "cpu_count",
    "memory_total_gb",
    "sip_file_count",
    "rtp_file_count",
    "sip_bytes",
    "rtp_bytes",
    "call_count",
    "event_count",
    "sip_scan_seconds",
    "rtp_catalog_seconds",
    "db_write_seconds",
    "elapsed_seconds",
    "wall_seconds",
    "db_path",
]


def default_datalog_base(out_dir: Path | None = None) -> Path:
    target = out_dir or Path.cwd()
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    return target / f"index_benchmark_{stamp}"


def run_index_benchmark(
    sip_dir: Path,
    rtp_dir: Path,
    db_path: Path,
    sip_servers: str | None = None,
    rtp_servers: str | None = None,
    performance_profile: str = "balanced",
    workers: str | int | None = "auto",
    iterations: int = 1,
    prefer_rust: bool = True,
    fast_indexer: Path | None = None,
    tshark_path: str | None = None,
    out_json: Path | None = None,
    out_csv: Path | None = None,
    progress_callback: ProgressCallback | None = None,
) -> list[dict[str, Any]]:
    iterations = max(1, int(iterations))
    records: list[dict[str, Any]] = []
    for iteration in range(1, iterations + 1):
        iteration_db = db_path
        if iterations > 1:
            iteration_db = db_path.with_name(f"{db_path.stem}.bench{iteration}{db_path.suffix or '.sqlite'}")
        started = time.perf_counter()
        result = siprtp_v2_core.index_folders(
            sip_dir=sip_dir,
            rtp_dir=rtp_dir,
            db_path=iteration_db,
            sip_servers=sip_servers,
            rtp_servers=rtp_servers,
            force=True,
            prefer_rust=prefer_rust,
            fast_indexer=fast_indexer,
            tshark_path=tshark_path,
            performance_profile=performance_profile,
            workers=workers,
            progress_callback=progress_callback,
        )
        wall_seconds = time.perf_counter() - started
        records.append(
            {
                "iteration": iteration,
                "mode": result.get("mode", ""),
                "performance_profile": performance_profile,
                "workers_requested": str(workers or "auto"),
                "workers_used": result.get("workers", ""),
                "cpu_count": result.get("cpu_count", ""),
                "memory_total_gb": result.get("memory_total_gb", ""),
                "sip_file_count": result.get("sip_file_count", 0),
                "rtp_file_count": result.get("rtp_file_count", 0),
                "sip_bytes": result.get("sip_bytes", 0),
                "rtp_bytes": result.get("rtp_bytes", 0),
                "call_count": result.get("call_count", 0),
                "event_count": result.get("event_count", 0),
                "sip_scan_seconds": round(float(result.get("sip_scan_seconds", 0.0) or 0.0), 3),
                "rtp_catalog_seconds": round(float(result.get("rtp_catalog_seconds", 0.0) or 0.0), 3),
                "db_write_seconds": round(float(result.get("db_write_seconds", 0.0) or 0.0), 3),
                "elapsed_seconds": round(float(result.get("elapsed_seconds", 0.0) or 0.0), 3),
                "wall_seconds": round(wall_seconds, 3),
                "db_path": str(iteration_db),
            }
        )
    if out_json:
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
    if out_csv:
        out_csv.parent.mkdir(parents=True, exist_ok=True)
        with out_csv.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=BENCHMARK_FIELDS)
            writer.writeheader()
            writer.writerows(records)
    return records
