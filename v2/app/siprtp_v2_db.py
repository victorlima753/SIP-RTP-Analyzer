#!/usr/bin/env python3
"""SQLite schema and query helpers for SIP/RTP Analyzer V2."""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 2


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def connect_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS capture_sets (
            id INTEGER PRIMARY KEY,
            created_at TEXT,
            sip_dir TEXT,
            rtp_dir TEXT,
            config_json TEXT,
            schema_version INTEGER
        );

        CREATE TABLE IF NOT EXISTS capture_files (
            id INTEGER PRIMARY KEY,
            capture_set_id INTEGER,
            role TEXT,
            path TEXT,
            file_name TEXT,
            size_bytes INTEGER,
            first_epoch REAL,
            last_epoch REAL,
            server_ip TEXT,
            packet_count INTEGER,
            parse_status TEXT,
            warning_count INTEGER
        );

        CREATE TABLE IF NOT EXISTS calls (
            call_id TEXT PRIMARY KEY,
            first_epoch REAL,
            last_epoch REAL,
            first_frame INTEGER,
            last_frame INTEGER,
            from_user TEXT,
            to_user TEXT,
            request_uri_user TEXT,
            contact_user TEXT,
            pai_user TEXT,
            normalized_numbers TEXT,
            methods_json TEXT,
            status_code INTEGER,
            reason_phrase TEXT,
            src_ips_json TEXT,
            dst_ips_json TEXT,
            sip_ports_json TEXT,
            packet_count INTEGER,
            completed INTEGER,
            has_invite INTEGER,
            has_ack INTEGER,
            has_bye INTEGER,
            has_cancel INTEGER
        );

        CREATE TABLE IF NOT EXISTS call_files (
            call_id TEXT,
            file_id INTEGER,
            role TEXT,
            first_epoch REAL,
            last_epoch REAL
        );

        CREATE TABLE IF NOT EXISTS sdp_media (
            id INTEGER PRIMARY KEY,
            call_id TEXT,
            frame_number INTEGER,
            ts_epoch REAL,
            media TEXT,
            ip TEXT,
            port INTEGER,
            payloads_json TEXT,
            attributes_json TEXT
        );

        CREATE TABLE IF NOT EXISTS index_warnings (
            id INTEGER PRIMARY KEY,
            file_id INTEGER,
            ts_epoch REAL,
            severity TEXT,
            code TEXT,
            message TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_capture_files_role_time
            ON capture_files(role, first_epoch, last_epoch);
        CREATE INDEX IF NOT EXISTS idx_calls_time ON calls(first_epoch, last_epoch);
        CREATE INDEX IF NOT EXISTS idx_calls_status ON calls(status_code);
        CREATE INDEX IF NOT EXISTS idx_calls_numbers ON calls(normalized_numbers);
        CREATE INDEX IF NOT EXISTS idx_call_files_call ON call_files(call_id);
        CREATE INDEX IF NOT EXISTS idx_sdp_media_call ON sdp_media(call_id);
        """
    )


def reset_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        DELETE FROM metadata;
        DELETE FROM capture_sets;
        DELETE FROM capture_files;
        DELETE FROM calls;
        DELETE FROM call_files;
        DELETE FROM sdp_media;
        DELETE FROM index_warnings;
        """
    )


def write_metadata(conn: sqlite3.Connection, values: dict[str, Any]) -> None:
    rows = {key: str(value) for key, value in values.items()}
    rows["schema_version"] = str(SCHEMA_VERSION)
    rows["indexed_at"] = dt.datetime.now().isoformat(timespec="seconds")
    conn.executemany("INSERT OR REPLACE INTO metadata(key, value) VALUES(?, ?)", rows.items())


def create_capture_set(
    conn: sqlite3.Connection,
    sip_dir: Path,
    rtp_dir: Path,
    config: dict[str, Any],
) -> int:
    cur = conn.execute(
        """
        INSERT INTO capture_sets(created_at, sip_dir, rtp_dir, config_json, schema_version)
        VALUES(?, ?, ?, ?, ?)
        """,
        (
            dt.datetime.now().isoformat(timespec="seconds"),
            str(sip_dir.resolve()),
            str(rtp_dir.resolve()),
            json_dumps(config),
            SCHEMA_VERSION,
        ),
    )
    return int(cur.lastrowid)


def insert_capture_file(
    conn: sqlite3.Connection,
    capture_set_id: int,
    role: str,
    path: Path,
    first_epoch: float | None,
    last_epoch: float | None,
    server_ip: str = "",
    packet_count: int = 0,
    parse_status: str = "ok",
    warning_count: int = 0,
) -> int:
    stat = path.stat()
    cur = conn.execute(
        """
        INSERT INTO capture_files(
            capture_set_id, role, path, file_name, size_bytes, first_epoch, last_epoch,
            server_ip, packet_count, parse_status, warning_count
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            capture_set_id,
            role,
            str(path.resolve()),
            path.name,
            stat.st_size,
            first_epoch,
            last_epoch,
            server_ip,
            packet_count,
            parse_status,
            warning_count,
        ),
    )
    return int(cur.lastrowid)


def insert_warning(
    conn: sqlite3.Connection,
    file_id: int | None,
    severity: str,
    code: str,
    message: str,
    ts_epoch: float | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO index_warnings(file_id, ts_epoch, severity, code, message)
        VALUES(?, ?, ?, ?, ?)
        """,
        (file_id, ts_epoch, severity, code, message),
    )


def insert_call_summary(conn: sqlite3.Connection, summary: Any) -> None:
    conn.execute(
        """
        INSERT OR REPLACE INTO calls (
            call_id, first_epoch, last_epoch, first_frame, last_frame,
            from_user, to_user, request_uri_user, contact_user, pai_user,
            normalized_numbers, methods_json, status_code, reason_phrase,
            src_ips_json, dst_ips_json, sip_ports_json, packet_count,
            completed, has_invite, has_ack, has_bye, has_cancel
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            summary.call_id,
            summary.first_epoch,
            summary.last_epoch,
            summary.first_frame,
            summary.last_frame,
            summary.from_user,
            summary.to_user,
            summary.request_uri_user,
            summary.contact_user,
            getattr(summary, "pai_user", ""),
            summary.normalized_numbers,
            json_dumps(summary.methods),
            summary.status_code,
            summary.reason_phrase,
            json_dumps(summary.src_ips),
            json_dumps(summary.dst_ips),
            json_dumps(summary.sip_ports),
            summary.packet_count,
            int(summary.completed),
            int(summary.has_invite),
            int(summary.has_ack),
            int(summary.has_bye),
            int(summary.has_cancel),
        ),
    )


def insert_call_file(
    conn: sqlite3.Connection,
    call_id: str,
    file_id: int,
    role: str,
    first_epoch: float,
    last_epoch: float,
) -> None:
    conn.execute(
        """
        INSERT INTO call_files(call_id, file_id, role, first_epoch, last_epoch)
        VALUES(?, ?, ?, ?, ?)
        """,
        (call_id, file_id, role, first_epoch, last_epoch),
    )


def insert_sdp_media(conn: sqlite3.Connection, call_id: str, item: dict[str, Any], ts_epoch: float) -> None:
    conn.execute(
        """
        INSERT INTO sdp_media(
            call_id, frame_number, ts_epoch, media, ip, port, payloads_json, attributes_json
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            call_id,
            item.get("frame_number"),
            ts_epoch,
            item.get("media"),
            item.get("ip"),
            item.get("port"),
            json_dumps(item.get("payloads", [])),
            json_dumps(item.get("attributes", [])),
        ),
    )


def number_search_candidates(number: str) -> list[str]:
    digits = "".join(ch for ch in number if ch.isdigit())
    candidates: list[str] = []
    for value in (digits, digits[2:] if digits.startswith("55") else "", digits[-11:], digits[-10:]):
        if value and value not in candidates:
            candidates.append(value)
    return candidates


def parse_search_time(value: str) -> tuple[float | None, int | None]:
    clean = value.strip()
    if clean.replace(".", "", 1).isdigit():
        return float(clean), None
    if len(clean.split(":")) in (2, 3) and "-" not in clean and "/" not in clean:
        parts = [int(part) for part in clean.split(":")]
        hour, minute = parts[0], parts[1]
        second = parts[2] if len(parts) > 2 else 0
        return None, hour * 3600 + minute * 60 + second
    for fmt in ("%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M"):
        try:
            parsed = dt.datetime.strptime(clean, fmt)
            return parsed.timestamp(), None
        except ValueError:
            pass
    parsed = dt.datetime.fromisoformat(clean.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.timestamp(), None
    return parsed.astimezone().timestamp(), None


def epoch_to_local(epoch: float | None) -> str:
    if epoch is None:
        return ""
    return dt.datetime.fromtimestamp(float(epoch)).strftime("%Y-%m-%d %H:%M:%S")


def find_calls(
    db_path: Path,
    number: str,
    start_time: str,
    window_minutes: float,
    limit: int = 50,
) -> list[dict[str, Any]]:
    wanted_epoch, wanted_seconds = parse_search_time(start_time)
    candidates = number_search_candidates(number)
    if not candidates:
        return []
    params: list[Any] = []
    number_clause = " OR ".join("normalized_numbers LIKE ?" for _ in candidates)
    params.extend([f"%{candidate}%" for candidate in candidates])
    where = [f"({number_clause})"]
    if wanted_epoch is not None:
        delta = float(window_minutes) * 60.0
        where.append("last_epoch >= ? AND first_epoch <= ?")
        params.extend([wanted_epoch - delta, wanted_epoch + delta])
    sql = f"""
        SELECT * FROM calls
        WHERE {' AND '.join(where)}
        ORDER BY first_epoch ASC
        LIMIT ?
    """
    params.append(limit)
    with connect_db(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    results: list[dict[str, Any]] = []
    for row in rows:
        if wanted_seconds is not None:
            start = dt.datetime.fromtimestamp(float(row["first_epoch"]))
            seconds = start.hour * 3600 + start.minute * 60 + start.second
            distance = min(abs(seconds - wanted_seconds), 86400 - abs(seconds - wanted_seconds))
            if distance > float(window_minutes) * 60.0:
                continue
        results.append(call_row_to_dict(row))
    return results


def call_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "call_id": row["call_id"],
        "inicio": epoch_to_local(row["first_epoch"]),
        "fim": epoch_to_local(row["last_epoch"]),
        "duracao_seg": round(float(row["last_epoch"] or 0) - float(row["first_epoch"] or 0), 3),
        "from_user": row["from_user"] or "",
        "to_user": row["to_user"] or "",
        "request_uri_user": row["request_uri_user"] or "",
        "contact_user": row["contact_user"] or "",
        "pai_user": row["pai_user"] or "",
        "status_code": row["status_code"],
        "reason_phrase": row["reason_phrase"] or "",
        "methods": json.loads(row["methods_json"] or "[]"),
        "packet_count": row["packet_count"],
        "completed": bool(row["completed"]),
        "has_ack": bool(row["has_ack"]),
        "has_bye": bool(row["has_bye"]),
        "has_cancel": bool(row["has_cancel"]),
        "normalized_numbers": row["normalized_numbers"] or "",
    }

