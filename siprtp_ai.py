#!/usr/bin/env python3
"""
Ferramenta local para indexar, buscar, extrair e analisar chamadas SIP/RTP em
PCAPs grandes usando TShark/Wireshark.

O desenho e intencionalmente hibrido:
- TShark extrai os fatos tecnicos do PCAP.
- Regras locais transformam esses fatos em evidencias.
- Um comando de IA opcional pode receber apenas o JSON estruturado da analise.
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import ipaddress
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


TOOL_VERSION = "0.1.0"
TSHARK_CANDIDATES = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]
EDITCAP_CANDIDATES = [
    r"C:\Program Files\Wireshark\editcap.exe",
    r"C:\Program Files (x86)\Wireshark\editcap.exe",
]
_FIELD_CACHE: dict[str, set[str]] = {}
SIP_RAW_HEADER_FIELD = "sip.msg_hdr"


SIP_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "udp.srcport",
    "tcp.srcport",
    "udp.dstport",
    "tcp.dstport",
    "sip.Call-ID",
    "sip.Method",
    "sip.Status-Code",
    "sip.Reason-Phrase",
    "sip.CSeq.method",
    "sip.from.user",
    "sip.to.user",
    "sip.r-uri.user",
    "sip.contact.user",
    "sip.pai.user",
    "sdp.connection_info.address",
    "sdp.media.port",
    "sdp.media",
    "sdp.media.format",
    "sdp.media_attribute",
]
SIP_EVENT_FIELDS = SIP_FIELDS + [SIP_RAW_HEADER_FIELD]


RTP_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "udp.srcport",
    "udp.dstport",
    "rtp.ssrc",
    "rtp.seq",
    "rtp.p_type",
    "rtp.timestamp",
    "rtp.analysis.jitter",
    "rtp.analysis.delta",
    "rtp.analysis.lost_segment",
    "rtcp.ssrc",
    "rtcp.pt",
]


STATIC_RTP_PAYLOADS = {
    "0": "PCMU",
    "3": "GSM",
    "4": "G723",
    "8": "PCMA",
    "9": "G722",
    "18": "G729",
}


def eprint(message: str) -> None:
    print(message, file=sys.stderr)


def normalize_number(value: str | None) -> str:
    if not value:
        return ""
    return "".join(re.findall(r"\d+", value))


def normalize_number_set(values: Iterable[str]) -> str:
    numbers: set[str] = set()
    for value in values:
        value = value or ""
        direct = normalize_number(value)
        if len(direct) >= 3:
            numbers.add(direct)
        for candidate in re.findall(r"[+]?[\d][\d\s().\-]{2,}\d", value):
            normalized = normalize_number(candidate)
            if len(normalized) >= 3:
                numbers.add(normalized)
    return " ".join(sorted(numbers))


def number_search_candidates(number: str) -> list[str]:
    normalized = normalize_number(number)
    candidates: list[str] = []
    for candidate in (
        normalized,
        normalized[2:] if normalized.startswith("55") and len(normalized) > 12 else "",
        normalized[-11:] if len(normalized) > 11 else "",
        normalized[-10:] if len(normalized) > 10 else "",
    ):
        if candidate and candidate not in candidates:
            candidates.append(candidate)
    return candidates


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def json_loads(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def parse_float(value: str | None) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(str(value).split(",")[0])
    except ValueError:
        return None


def parse_int(value: str | None) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(float(str(value).split(",")[0]))
    except ValueError:
        return None


def parse_multi(value: str | None) -> list[str]:
    if not value:
        return []
    parts: list[str] = []
    for chunk in str(value).split("|"):
        clean = chunk.strip()
        if clean:
            parts.append(clean)
    return parts


def epoch_to_local(epoch: float | None) -> str:
    if epoch is None:
        return ""
    return dt.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")


def safe_filename(value: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")
    return clean[:120] or "call"


def default_db_path(pcap_path: Path) -> Path:
    return pcap_path.with_suffix(pcap_path.suffix + ".siprtp.sqlite")


def delete_sqlite_files(db_path: Path) -> None:
    for path in (db_path, Path(str(db_path) + "-wal"), Path(str(db_path) + "-shm")):
        if path.exists():
            path.unlink()


def resolve_tshark(explicit: str | None = None) -> str:
    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)
    if os.environ.get("TSHARK_PATH"):
        candidates.append(os.environ["TSHARK_PATH"])
    found = shutil.which("tshark")
    if found:
        candidates.append(found)
    candidates.extend(TSHARK_CANDIDATES)
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return str(Path(candidate))
    raise SystemExit(
        "TShark nao foi encontrado. Instale o Wireshark ou informe --tshark "
        r'"C:\Program Files\Wireshark\tshark.exe".'
    )


def resolve_editcap(explicit: str | None = None, tshark: str | None = None) -> str | None:
    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)
    if os.environ.get("EDITCAP_PATH"):
        candidates.append(os.environ["EDITCAP_PATH"])
    found = shutil.which("editcap")
    if found:
        candidates.append(found)
    if tshark:
        candidates.append(str(Path(tshark).with_name("editcap.exe")))
    candidates.extend(EDITCAP_CANDIDATES)
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return str(Path(candidate))
    return None


def get_available_tshark_fields(tshark: str) -> set[str]:
    cache_key = str(Path(tshark).resolve()) if Path(tshark).exists() else tshark
    if cache_key in _FIELD_CACHE:
        return _FIELD_CACHE[cache_key]
    try:
        proc = subprocess.run(
            [tshark, "-G", "fields"],
            text=True,
            capture_output=True,
            check=True,
            encoding="utf-8",
            errors="replace",
        )
    except (subprocess.CalledProcessError, OSError):
        return set()
    fields: set[str] = set()
    for line in proc.stdout.splitlines():
        cols = line.split("\t")
        if len(cols) >= 3 and cols[0] == "F":
            fields.add(cols[2])
    _FIELD_CACHE[cache_key] = fields
    return fields


def supported_fields(tshark: str, desired: list[str]) -> list[str]:
    available = get_available_tshark_fields(tshark)
    if not available:
        return desired
    selected = [field_name for field_name in desired if field_name in available]
    required = {"frame.number", "frame.time_epoch"}
    missing = sorted(required - set(selected))
    if missing:
        raise SystemExit(
            "TShark nao possui campos basicos esperados: " + ", ".join(missing)
        )
    return selected


def build_tshark_field_args(
    tshark: str,
    pcap_path: Path,
    display_filter: str,
    desired_fields: list[str],
) -> tuple[list[str], list[str]]:
    fields = supported_fields(tshark, desired_fields)
    if not fields:
        return [], []
    args = [
        tshark,
        "-n",
        "-q",
        "-r",
        str(pcap_path),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "header=n",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=a",
        "-E",
        "aggregator=|",
    ]
    for field_name in fields:
        args.extend(["-e", field_name])
    return fields, args


def parse_tshark_row(line: str, fields: list[str]) -> dict[str, str] | None:
    row = line.rstrip("\r\n").split("\t")
    if not row or row == [""]:
        return None
    if len(row) < len(fields):
        row.extend([""] * (len(fields) - len(row)))
    return dict(zip(fields, row[: len(fields)]))


def iter_tshark_field_rows(
    tshark: str,
    pcap_path: Path,
    display_filter: str,
    desired_fields: list[str],
) -> Iterable[dict[str, str]]:
    fields, args = build_tshark_field_args(tshark, pcap_path, display_filter, desired_fields)
    if not fields:
        return
    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as exc:
        raise SystemExit(f"Falha ao iniciar TShark: {exc}") from exc

    assert proc.stdout is not None
    for line in proc.stdout:
        row = parse_tshark_row(line, fields)
        if row is not None:
            yield row
    stderr = proc.stderr.read() if proc.stderr else ""
    return_code = proc.wait()
    if return_code != 0:
        raise SystemExit(f"Falha ao executar TShark: {stderr.strip()}")


def run_tshark_fields(
    tshark: str,
    pcap_path: Path,
    display_filter: str,
    desired_fields: list[str],
) -> tuple[list[str], list[dict[str, str]]]:
    fields, args = build_tshark_field_args(tshark, pcap_path, display_filter, desired_fields)
    if not fields:
        return [], []
    try:
        proc = subprocess.run(
            args,
            text=True,
            capture_output=True,
            check=True,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip()
        raise SystemExit(f"Falha ao executar TShark: {detail}") from exc

    rows: list[dict[str, str]] = []
    for line in proc.stdout.splitlines():
        row = parse_tshark_row(line, fields)
        if row is not None:
            rows.append(row)
    return fields, rows


@dataclass
class SdpMedia:
    ip: str | None
    port: int | None
    media: str | None
    payloads: list[str] = field(default_factory=list)
    attributes: list[str] = field(default_factory=list)
    frame_number: int | None = None


@dataclass
class SipEvent:
    call_id: str
    frame_number: int
    ts_epoch: float
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    method: str
    status_code: int | None
    reason_phrase: str
    cseq_method: str
    from_user: str
    to_user: str
    request_uri_user: str
    contact_user: str
    raw_headers: str
    pai_user: str = ""
    sdp_media: list[SdpMedia] = field(default_factory=list)


@dataclass
class CallSummary:
    call_id: str
    first_epoch: float
    last_epoch: float
    first_frame: int
    last_frame: int
    from_user: str = ""
    to_user: str = ""
    request_uri_user: str = ""
    contact_user: str = ""
    normalized_numbers: str = ""
    methods: list[str] = field(default_factory=list)
    status_code: int | None = None
    reason_phrase: str = ""
    src_ips: list[str] = field(default_factory=list)
    dst_ips: list[str] = field(default_factory=list)
    sip_ports: list[int] = field(default_factory=list)
    sdp_media: list[dict[str, Any]] = field(default_factory=list)
    packet_count: int = 0
    completed: bool = False
    has_invite: bool = False
    has_ack: bool = False
    has_bye: bool = False
    has_cancel: bool = False


def row_value(row: dict[str, str], *field_names: str) -> str:
    for field_name in field_names:
        value = row.get(field_name, "")
        if value:
            return value
    return ""


def parse_sdp_media(row: dict[str, str], frame_number: int) -> list[SdpMedia]:
    ips = parse_multi(row.get("sdp.connection_info.address"))
    ports = parse_multi(row.get("sdp.media.port"))
    media = parse_multi(row.get("sdp.media"))
    formats = parse_multi(row.get("sdp.media.format"))
    attrs = parse_multi(row.get("sdp.media_attribute"))
    count = max(len(ports), len(media), len(formats), 1 if ips else 0)
    result: list[SdpMedia] = []
    for idx in range(count):
        ip = ips[idx] if idx < len(ips) else (ips[-1] if ips else None)
        port = parse_int(ports[idx]) if idx < len(ports) else None
        media_name = media[idx] if idx < len(media) else None
        payloads = re.findall(r"\d+", formats[idx]) if idx < len(formats) else []
        result.append(
            SdpMedia(
                ip=ip,
                port=port,
                media=media_name,
                payloads=payloads,
                attributes=attrs,
                frame_number=frame_number,
            )
        )
    return [item for item in result if item.ip or item.port or item.media or item.payloads]


def sip_event_from_row(row: dict[str, str]) -> SipEvent | None:
    call_id = row.get("sip.Call-ID", "").split("|")[0].strip()
    if not call_id:
        return None
    frame_number = parse_int(row.get("frame.number"))
    ts_epoch = parse_float(row.get("frame.time_epoch"))
    if frame_number is None or ts_epoch is None:
        return None
    src_ip = row_value(row, "ip.src", "ipv6.src")
    dst_ip = row_value(row, "ip.dst", "ipv6.dst")
    src_port = parse_int(row_value(row, "udp.srcport", "tcp.srcport"))
    dst_port = parse_int(row_value(row, "udp.dstport", "tcp.dstport"))
    method = row.get("sip.Method", "").split("|")[0].strip().upper()
    status_code = parse_int(row.get("sip.Status-Code"))
    reason_phrase = row.get("sip.Reason-Phrase", "").split("|")[0].strip()
    cseq_method = row.get("sip.CSeq.method", "").split("|")[0].strip().upper()
    return SipEvent(
        call_id=call_id,
        frame_number=frame_number,
        ts_epoch=ts_epoch,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        method=method,
        status_code=status_code,
        reason_phrase=reason_phrase,
        cseq_method=cseq_method,
        from_user=row.get("sip.from.user", "").split("|")[0].strip(),
        to_user=row.get("sip.to.user", "").split("|")[0].strip(),
        request_uri_user=row.get("sip.r-uri.user", "").split("|")[0].strip(),
        contact_user=row.get("sip.contact.user", "").split("|")[0].strip(),
        raw_headers=row.get(SIP_RAW_HEADER_FIELD, ""),
        pai_user=row.get("sip.pai.user", "").split("|")[0].strip(),
        sdp_media=parse_sdp_media(row, frame_number),
    )


def sip_events_from_rows(rows: Iterable[dict[str, str]]) -> list[SipEvent]:
    events: list[SipEvent] = []
    for row in rows:
        event = sip_event_from_row(row)
        if event is not None:
            events.append(event)
    return events


def aggregate_calls(events: Iterable[SipEvent]) -> list[CallSummary]:
    by_call: dict[str, list[SipEvent]] = {}
    for event in events:
        by_call.setdefault(event.call_id, []).append(event)

    summaries: list[CallSummary] = []
    for call_id, call_events in by_call.items():
        call_events.sort(key=lambda item: (item.ts_epoch, item.frame_number))
        first = call_events[0]
        last = call_events[-1]
        methods = sorted({event.method or event.cseq_method for event in call_events if event.method or event.cseq_method})
        statuses = [event for event in call_events if event.status_code is not None]
        final_status = max(
            (event for event in statuses if event.status_code and event.status_code >= 200),
            key=lambda event: (event.status_code or 0, event.ts_epoch),
            default=statuses[-1] if statuses else None,
        )
        number_values: list[str] = []
        for event in call_events:
            number_values.extend(
                [
                    event.from_user,
                    event.to_user,
                    event.request_uri_user,
                    event.contact_user,
                    event.pai_user,
                    event.raw_headers,
                ]
            )
        sdp: list[dict[str, Any]] = []
        for event in call_events:
            for media in event.sdp_media:
                sdp.append(
                    {
                        "ip": media.ip,
                        "port": media.port,
                        "media": media.media,
                        "payloads": media.payloads,
                        "attributes": media.attributes,
                        "frame_number": media.frame_number,
                    }
                )
        src_ips = sorted({event.src_ip for event in call_events if event.src_ip})
        dst_ips = sorted({event.dst_ip for event in call_events if event.dst_ip})
        ports = sorted(
            {
                port
                for event in call_events
                for port in (event.src_port, event.dst_port)
                if port is not None
            }
        )
        summary = CallSummary(
            call_id=call_id,
            first_epoch=first.ts_epoch,
            last_epoch=last.ts_epoch,
            first_frame=first.frame_number,
            last_frame=last.frame_number,
            from_user=first.from_user,
            to_user=first.to_user,
            request_uri_user=first.request_uri_user,
            contact_user=first.contact_user,
            normalized_numbers=normalize_number_set(number_values),
            methods=methods,
            status_code=final_status.status_code if final_status else None,
            reason_phrase=final_status.reason_phrase if final_status else "",
            src_ips=src_ips,
            dst_ips=dst_ips,
            sip_ports=ports,
            sdp_media=sdp,
            packet_count=len(call_events),
            completed=any(event.status_code == 200 and event.cseq_method == "INVITE" for event in call_events),
            has_invite=any(event.method == "INVITE" or event.cseq_method == "INVITE" for event in call_events),
            has_ack=any(event.method == "ACK" or event.cseq_method == "ACK" for event in call_events),
            has_bye=any(event.method == "BYE" or event.cseq_method == "BYE" for event in call_events),
            has_cancel=any(event.method == "CANCEL" or event.cseq_method == "CANCEL" for event in call_events),
        )
        summaries.append(summary)
    return summaries


@dataclass
class CallAccumulator:
    call_id: str
    first_epoch: float | None = None
    last_epoch: float | None = None
    first_frame: int | None = None
    last_frame: int | None = None
    from_user: str = ""
    to_user: str = ""
    request_uri_user: str = ""
    contact_user: str = ""
    number_tokens: set[str] = field(default_factory=set)
    methods: set[str] = field(default_factory=set)
    status_code: int | None = None
    reason_phrase: str = ""
    status_priority: tuple[int, float] = (0, -1.0)
    src_ips: set[str] = field(default_factory=set)
    dst_ips: set[str] = field(default_factory=set)
    sip_ports: set[int] = field(default_factory=set)
    sdp_media: list[dict[str, Any]] = field(default_factory=list)
    packet_count: int = 0
    completed: bool = False
    has_invite: bool = False
    has_ack: bool = False
    has_bye: bool = False
    has_cancel: bool = False

    def update(self, event: SipEvent) -> None:
        if self.first_epoch is None or (event.ts_epoch, event.frame_number) < (
            self.first_epoch,
            self.first_frame or event.frame_number,
        ):
            self.first_epoch = event.ts_epoch
            self.first_frame = event.frame_number
        if self.last_epoch is None or (event.ts_epoch, event.frame_number) > (
            self.last_epoch,
            self.last_frame or event.frame_number,
        ):
            self.last_epoch = event.ts_epoch
            self.last_frame = event.frame_number

        self.from_user = self.from_user or event.from_user
        self.to_user = self.to_user or event.to_user
        self.request_uri_user = self.request_uri_user or event.request_uri_user
        self.contact_user = self.contact_user or event.contact_user
        method = event.method or event.cseq_method
        if method:
            self.methods.add(method)
        self.has_invite = self.has_invite or method == "INVITE" or event.cseq_method == "INVITE"
        self.has_ack = self.has_ack or method == "ACK" or event.cseq_method == "ACK"
        self.has_bye = self.has_bye or method == "BYE" or event.cseq_method == "BYE"
        self.has_cancel = self.has_cancel or method == "CANCEL" or event.cseq_method == "CANCEL"
        self.completed = self.completed or (
            event.status_code == 200 and event.cseq_method == "INVITE"
        )

        for token in normalize_number_set(
            [
                event.from_user,
                event.to_user,
                event.request_uri_user,
                event.contact_user,
                event.pai_user,
                event.raw_headers,
            ]
        ).split():
            self.number_tokens.add(token)

        if event.status_code is not None:
            priority = self._status_priority(event)
            if priority >= self.status_priority:
                self.status_priority = priority
                self.status_code = event.status_code
                self.reason_phrase = event.reason_phrase

        if event.src_ip:
            self.src_ips.add(event.src_ip)
        if event.dst_ip:
            self.dst_ips.add(event.dst_ip)
        for port in (event.src_port, event.dst_port):
            if port is not None:
                self.sip_ports.add(port)
        for media in event.sdp_media:
            self.sdp_media.append(
                {
                    "ip": media.ip,
                    "port": media.port,
                    "media": media.media,
                    "payloads": media.payloads,
                    "attributes": media.attributes,
                    "frame_number": media.frame_number,
                }
            )
        self.packet_count += 1

    @staticmethod
    def _status_priority(event: SipEvent) -> tuple[int, float]:
        if event.status_code is None:
            return (0, event.ts_epoch)
        if event.status_code >= 200 and event.cseq_method == "INVITE":
            return (3, event.ts_epoch)
        if event.status_code >= 200:
            return (2, event.ts_epoch)
        return (1, event.ts_epoch)

    def to_summary(self) -> CallSummary:
        if self.first_epoch is None or self.last_epoch is None:
            raise ValueError("CallAccumulator sem eventos")
        return CallSummary(
            call_id=self.call_id,
            first_epoch=self.first_epoch,
            last_epoch=self.last_epoch,
            first_frame=self.first_frame or 0,
            last_frame=self.last_frame or 0,
            from_user=self.from_user,
            to_user=self.to_user,
            request_uri_user=self.request_uri_user,
            contact_user=self.contact_user,
            normalized_numbers=" ".join(sorted(self.number_tokens)),
            methods=sorted(self.methods),
            status_code=self.status_code,
            reason_phrase=self.reason_phrase,
            src_ips=sorted(self.src_ips),
            dst_ips=sorted(self.dst_ips),
            sip_ports=sorted(self.sip_ports),
            sdp_media=self.sdp_media,
            packet_count=self.packet_count,
            completed=self.completed,
            has_invite=self.has_invite,
            has_ack=self.has_ack,
            has_bye=self.has_bye,
            has_cancel=self.has_cancel,
        )


def aggregate_calls_streaming(
    rows: Iterable[dict[str, str]],
    progress_events: int = 100000,
    on_event: Any | None = None,
    progress_callback: Any | None = None,
) -> tuple[list[CallSummary], int]:
    accumulators: dict[str, CallAccumulator] = {}
    event_count = 0
    for row in rows:
        event = sip_event_from_row(row)
        if event is None:
            continue
        event_count += 1
        if on_event is not None:
            on_event(event)
        accumulator = accumulators.get(event.call_id)
        if accumulator is None:
            accumulator = CallAccumulator(event.call_id)
            accumulators[event.call_id] = accumulator
        accumulator.update(event)
        if progress_events > 0 and event_count % progress_events == 0:
            message = (
                f"Eventos SIP processados: {event_count:,} | "
                f"chamadas parciais: {len(accumulators):,}"
            )
            if progress_callback:
                progress_callback(message)
            else:
                eprint(message)
    return [accumulator.to_summary() for accumulator in accumulators.values()], event_count


def connect_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS calls (
            call_id TEXT PRIMARY KEY,
            first_epoch REAL NOT NULL,
            last_epoch REAL NOT NULL,
            first_frame INTEGER NOT NULL,
            last_frame INTEGER NOT NULL,
            from_user TEXT,
            to_user TEXT,
            request_uri_user TEXT,
            contact_user TEXT,
            normalized_numbers TEXT,
            methods_json TEXT,
            status_code INTEGER,
            reason_phrase TEXT,
            src_ips_json TEXT,
            dst_ips_json TEXT,
            sip_ports_json TEXT,
            sdp_media_json TEXT,
            packet_count INTEGER NOT NULL,
            completed INTEGER NOT NULL,
            has_invite INTEGER NOT NULL,
            has_ack INTEGER NOT NULL,
            has_bye INTEGER NOT NULL,
            has_cancel INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_calls_time ON calls(first_epoch, last_epoch);
        CREATE INDEX IF NOT EXISTS idx_calls_status ON calls(status_code);

        CREATE TABLE IF NOT EXISTS sip_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            call_id TEXT NOT NULL,
            frame_number INTEGER NOT NULL,
            ts_epoch REAL NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            method TEXT,
            status_code INTEGER,
            reason_phrase TEXT,
            cseq_method TEXT,
            from_user TEXT,
            to_user TEXT,
            request_uri_user TEXT,
            contact_user TEXT,
            raw_headers TEXT,
            sdp_media_json TEXT,
            FOREIGN KEY(call_id) REFERENCES calls(call_id)
        );

        CREATE INDEX IF NOT EXISTS idx_events_call ON sip_events(call_id);
        CREATE INDEX IF NOT EXISTS idx_events_time ON sip_events(ts_epoch);
        """
    )


def write_metadata(conn: sqlite3.Connection, pcap_path: Path) -> None:
    stat = pcap_path.stat()
    metadata = {
        "tool_version": TOOL_VERSION,
        "pcap_path": str(pcap_path.resolve()),
        "pcap_size": str(stat.st_size),
        "pcap_mtime_ns": str(stat.st_mtime_ns),
        "indexed_at": dt.datetime.now().isoformat(timespec="seconds"),
    }
    conn.executemany(
        "INSERT OR REPLACE INTO metadata(key, value) VALUES(?, ?)",
        metadata.items(),
    )


def insert_call(conn: sqlite3.Connection, summary: CallSummary) -> None:
    conn.execute(
        """
        INSERT OR REPLACE INTO calls (
            call_id, first_epoch, last_epoch, first_frame, last_frame,
            from_user, to_user, request_uri_user, contact_user, normalized_numbers,
            methods_json, status_code, reason_phrase, src_ips_json, dst_ips_json,
            sip_ports_json, sdp_media_json, packet_count, completed, has_invite,
            has_ack, has_bye, has_cancel
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
            summary.normalized_numbers,
            json_dumps(summary.methods),
            summary.status_code,
            summary.reason_phrase,
            json_dumps(summary.src_ips),
            json_dumps(summary.dst_ips),
            json_dumps(summary.sip_ports),
            json_dumps(summary.sdp_media),
            summary.packet_count,
            int(summary.completed),
            int(summary.has_invite),
            int(summary.has_ack),
            int(summary.has_bye),
            int(summary.has_cancel),
        ),
    )


def insert_event(conn: sqlite3.Connection, event: SipEvent) -> None:
    conn.execute(
        """
        INSERT INTO sip_events (
            call_id, frame_number, ts_epoch, src_ip, dst_ip, src_port, dst_port,
            method, status_code, reason_phrase, cseq_method, from_user, to_user,
            request_uri_user, contact_user, raw_headers, sdp_media_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event.call_id,
            event.frame_number,
            event.ts_epoch,
            event.src_ip,
            event.dst_ip,
            event.src_port,
            event.dst_port,
            event.method,
            event.status_code,
            event.reason_phrase,
            event.cseq_method,
            event.from_user,
            event.to_user,
            event.request_uri_user,
            event.contact_user,
            event.raw_headers,
            json_dumps([media.__dict__ for media in event.sdp_media]),
        ),
    )


def index_pcap_file(
    pcap_path: Path,
    db_path: Path | None = None,
    force: bool = False,
    store_events: bool = False,
    progress_events: int = 100000,
    event_batch_size: int = 5000,
    tshark_path: str | None = None,
    progress_callback: Any | None = None,
) -> dict[str, Any]:
    pcap_path = Path(pcap_path).resolve()
    if not pcap_path.exists():
        raise SystemExit(f"PCAP nao encontrado: {pcap_path}")
    db_path = Path(db_path).resolve() if db_path else default_db_path(pcap_path)
    if db_path.exists() and not force:
        raise SystemExit(
            f"Indice ja existe: {db_path}. Use --force para recriar."
        )
    tshark = resolve_tshark(tshark_path)
    if db_path.exists():
        delete_sqlite_files(db_path)
    mode = "detalhado" if store_events else "leve"
    start_time = dt.datetime.now()

    def notify(message: str) -> None:
        if progress_callback:
            progress_callback(message)
        else:
            eprint(message)

    notify(f"Indexando SIP/SDP em {pcap_path.name} no modo {mode}...")
    desired_fields = SIP_EVENT_FIELDS if store_events else SIP_FIELDS
    with connect_db(db_path) as conn:
        init_db(conn)
        write_metadata(conn, pcap_path)
        conn.execute("DELETE FROM sip_events")
        conn.execute("DELETE FROM calls")
        event_batch: list[SipEvent] = []

        def store_event(event: SipEvent) -> None:
            event_batch.append(event)
            if len(event_batch) >= event_batch_size:
                for pending in event_batch:
                    insert_event(conn, pending)
                event_batch.clear()

        summaries, event_count = aggregate_calls_streaming(
            iter_tshark_field_rows(tshark, pcap_path, "sip", desired_fields),
            progress_events=progress_events,
            on_event=store_event if store_events else None,
            progress_callback=progress_callback,
        )
        if store_events and event_batch:
            for pending in event_batch:
                insert_event(conn, pending)
            event_batch.clear()
        for summary in summaries:
            insert_call(conn, summary)
        conn.commit()
    elapsed = (dt.datetime.now() - start_time).total_seconds()
    return {
        "db_path": str(db_path),
        "pcap_path": str(pcap_path),
        "call_count": len(summaries),
        "event_count": event_count,
        "stored_event_count": event_count if store_events else 0,
        "mode": mode,
        "elapsed_seconds": elapsed,
        "db_bytes": db_path.stat().st_size if db_path.exists() else 0,
    }


def index_pcap(args: argparse.Namespace) -> None:
    stats = index_pcap_file(
        pcap_path=Path(args.pcap),
        db_path=Path(args.db) if args.db else None,
        force=args.force,
        store_events=args.store_events,
        progress_events=args.progress_events,
        event_batch_size=args.event_batch_size,
        tshark_path=args.tshark,
    )
    print(f"Indice criado: {stats['db_path']}")
    print(f"Chamadas indexadas: {stats['call_count']}")
    print(f"Eventos SIP processados: {stats['event_count']}")
    if args.store_events:
        print(f"Eventos SIP gravados: {stats['stored_event_count']}")
    else:
        print("Eventos SIP gravados: 0 (modo leve; use --store-events para auditoria detalhada)")


def parse_search_time(value: str) -> tuple[float | None, int | None]:
    clean = value.strip()
    if re.fullmatch(r"\d+(\.\d+)?", clean):
        return float(clean), None
    if re.fullmatch(r"\d{1,2}:\d{2}(:\d{2})?", clean):
        parts = [int(part) for part in clean.split(":")]
        hour, minute = parts[0], parts[1]
        second = parts[2] if len(parts) > 2 else 0
        return None, hour * 3600 + minute * 60 + second
    iso = clean.replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(iso)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M"):
            try:
                parsed = dt.datetime.strptime(clean, fmt)
                break
            except ValueError:
                continue
        else:
            raise SystemExit(
                "Formato de --inicio invalido. Use epoch, ISO, "
                "'YYYY-MM-DD HH:MM:SS', 'DD/MM/YYYY HH:MM' ou 'HH:MM:SS'."
            )
    if parsed.tzinfo is None:
        return parsed.timestamp(), None
    return parsed.astimezone().timestamp(), None


def call_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "call_id": row["call_id"],
        "inicio": epoch_to_local(row["first_epoch"]),
        "fim": epoch_to_local(row["last_epoch"]),
        "duracao_seg": round(float(row["last_epoch"]) - float(row["first_epoch"]), 3),
        "from_user": row["from_user"] or "",
        "to_user": row["to_user"] or "",
        "request_uri_user": row["request_uri_user"] or "",
        "contact_user": row["contact_user"] or "",
        "status_code": row["status_code"],
        "reason_phrase": row["reason_phrase"] or "",
        "methods": json_loads(row["methods_json"], []),
        "packet_count": row["packet_count"],
        "completed": bool(row["completed"]),
        "has_ack": bool(row["has_ack"]),
        "has_bye": bool(row["has_bye"]),
        "has_cancel": bool(row["has_cancel"]),
        "normalized_numbers": row["normalized_numbers"] or "",
    }


def call_id_candidates(call_id: str) -> list[str]:
    clean = call_id.strip()
    candidates = [clean]
    if clean.startswith(":") and len(clean) > 1:
        candidates.append(clean[1:])
    elif clean:
        candidates.append(":" + clean)
    unique: list[str] = []
    for candidate in candidates:
        if candidate and candidate not in unique:
            unique.append(candidate)
    return unique


def time_of_day_distance_seconds(epoch: float, wanted: int) -> int:
    local = dt.datetime.fromtimestamp(epoch)
    actual = local.hour * 3600 + local.minute * 60 + local.second
    diff = abs(actual - wanted)
    return min(diff, 86400 - diff)


def find_calls(
    pcap_path: Path,
    numero: str,
    inicio: str,
    janela: float = 5,
    db_path: Path | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    pcap_path = Path(pcap_path).resolve()
    db_path = Path(db_path).resolve() if db_path else default_db_path(pcap_path)
    if not db_path.exists():
        raise SystemExit(f"Indice nao encontrado: {db_path}. Rode indexar primeiro.")
    candidates = number_search_candidates(numero)
    if not candidates:
        raise SystemExit("--numero precisa conter ao menos um digito.")
    start_epoch, time_of_day = parse_search_time(inicio)
    window_seconds = int(float(janela) * 60)
    with connect_db(db_path) as conn:
        number_clause = " OR ".join("normalized_numbers LIKE ?" for _ in candidates)
        query = f"SELECT * FROM calls WHERE ({number_clause})"
        params: list[Any] = [f"%{candidate}%" for candidate in candidates]
        if start_epoch is not None:
            query += " AND last_epoch >= ? AND first_epoch <= ?"
            params.extend([start_epoch - window_seconds, start_epoch + window_seconds])
        query += " ORDER BY first_epoch ASC"
        rows = list(conn.execute(query, params))
    if time_of_day is not None:
        rows = [
            row
            for row in rows
            if time_of_day_distance_seconds(float(row["first_epoch"]), time_of_day)
            <= window_seconds
        ]
    return [call_row_to_dict(row) for row in rows[:limit]]


def search_calls(args: argparse.Namespace) -> None:
    pcap_path = Path(args.pcap).resolve()
    db_path = Path(args.db).resolve() if args.db else default_db_path(pcap_path)
    rows = find_calls(pcap_path, args.numero, args.inicio, args.janela, db_path, args.limit)
    if args.json:
        print(json_dumps(rows))
        return
    if not rows:
        print("Nenhuma chamada encontrada para os filtros informados.")
        return
    print(
        "inicio                fim                   dur(s)  status  from -> to              call-id"
    )
    print("-" * 110)
    for item in rows:
        status = item["status_code"] or "-"
        route = f'{item["from_user"] or "?"} -> {item["to_user"] or "?"}'
        print(
            f'{item["inicio"]:<20} {item["fim"]:<20} '
            f'{item["duracao_seg"]:>6}  {status!s:<6}  {route:<23} {item["call_id"]}'
        )


def load_call(conn: sqlite3.Connection, call_id: str) -> sqlite3.Row:
    for candidate in call_id_candidates(call_id):
        row = conn.execute("SELECT * FROM calls WHERE call_id = ?", (candidate,)).fetchone()
        if row is not None:
            if candidate != call_id:
                eprint(f"Call-ID encontrado no indice como: {candidate}")
            return row
    variants = ", ".join(call_id_candidates(call_id))
    raise SystemExit(
        "Call-ID nao encontrado no indice. "
        f"Valor informado/variantes testadas: {variants}"
    )


def display_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def ip_filter(ip: str) -> str:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return f'ip.addr == "{display_string(ip)}"'
    field_name = "ipv6.addr" if parsed.version == 6 else "ip.addr"
    return f"{field_name} == {parsed.compressed}"


def build_extract_filter(row: sqlite3.Row, margin_seconds: float) -> str:
    call_id = row["call_id"]
    first_epoch = float(row["first_epoch"]) - margin_seconds
    last_epoch = float(row["last_epoch"]) + margin_seconds
    time_filter = f"(frame.time_epoch >= {first_epoch:.6f} && frame.time_epoch <= {last_epoch:.6f})"
    sip_filter = f'sip.Call-ID == "{display_string(call_id)}"'
    sdp_media = json_loads(row["sdp_media_json"], [])
    media_filters: list[str] = []
    for media in sdp_media:
        ip = media.get("ip")
        port = media.get("port")
        if not ip or not port:
            continue
        ports = {int(port)}
        if int(port) > 0:
            ports.add(int(port) + 1)
        port_filter = " || ".join(f"udp.port == {candidate}" for candidate in sorted(ports))
        media_filters.append(f"({ip_filter(str(ip))} && ({port_filter}))")
    media_filter = " || ".join(media_filters)
    payload_filter = sip_filter
    if media_filter:
        payload_filter = f"({sip_filter}) || ({media_filter})"
    return f"{time_filter} && ({payload_filter})"


def write_filtered_pcap(tshark: str, source: Path, output: Path, display_filter: str) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    args = [tshark, "-r", str(source), "-Y", display_filter, "-w", str(output)]
    try:
        subprocess.run(args, text=True, capture_output=True, check=True)
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip()
        raise SystemExit(f"Falha ao extrair PCAP: {detail}") from exc


def write_time_slice(
    editcap: str,
    source: Path,
    output: Path,
    first_epoch: float,
    last_epoch: float,
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    args = [
        editcap,
        "-A",
        f"{first_epoch:.6f}",
        "-B",
        f"{last_epoch:.6f}",
        str(source),
        str(output),
    ]
    try:
        subprocess.run(args, text=True, capture_output=True, check=True)
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip()
        raise SystemExit(f"Falha ao criar recorte temporal com editcap: {detail}") from exc


def print_artifact_summary(artifacts: dict[str, str], pcap_label: str = "PCAP") -> None:
    pcap_path = artifacts.get("pcap")
    json_path = artifacts.get("report_json")
    html_path = artifacts.get("report_html")
    if pcap_path:
        print(f"{pcap_label}: {pcap_path}")
    if json_path:
        print(f"Relatorio JSON: {json_path}")
    if html_path:
        print(f"Relatorio HTML: {html_path}")


def export_call_file(
    pcap_path: Path,
    call_id: str,
    db_path: Path | None = None,
    out_dir: Path | None = None,
    margin_seconds: float = 10,
    analyze: bool = False,
    ai_command: str | None = None,
    tshark_path: str | None = None,
    editcap_path: str | None = None,
    no_time_slice: bool = False,
    keep_time_slice: bool = False,
    status_callback: Any | None = None,
) -> dict[str, Any]:
    pcap_path = Path(pcap_path).resolve()
    db_path = Path(db_path).resolve() if db_path else default_db_path(pcap_path)
    if not db_path.exists():
        raise SystemExit(f"Indice nao encontrado: {db_path}. Rode indexar primeiro.")
    tshark = resolve_tshark(tshark_path)
    editcap = resolve_editcap(editcap_path, tshark)

    def notify(message: str) -> None:
        if status_callback:
            status_callback(message)
        else:
            print(message)

    with connect_db(db_path) as conn:
        row = load_call(conn, call_id)
        actual_call_id = row["call_id"]
        display_filter = build_extract_filter(row, margin_seconds)
        first_epoch = float(row["first_epoch"]) - margin_seconds
        last_epoch = float(row["last_epoch"]) + margin_seconds
        start = dt.datetime.fromtimestamp(float(row["first_epoch"])).strftime("%Y%m%d_%H%M%S")
        number = normalize_number(row["from_user"] or row["to_user"] or row["request_uri_user"] or "")
        basename = safe_filename(f"call_{number or 'unknown'}_{start}")
        out_dir = Path(out_dir).resolve() if out_dir else pcap_path.parent / "extracted_calls"
        output = out_dir / f"{basename}.pcapng"
        source_for_filter = pcap_path
        temp_slice: Path | None = None
        if not no_time_slice and editcap:
            temp_slice = out_dir / f".{basename}.time_slice.tmp.pcapng"
            write_time_slice(editcap, pcap_path, temp_slice, first_epoch, last_epoch)
            source_for_filter = temp_slice
            notify(f"Recorte temporal: {temp_slice}")
        elif not no_time_slice:
            notify("editcap nao encontrado; extraindo diretamente do PCAP completo.")
        try:
            write_filtered_pcap(tshark, source_for_filter, output, display_filter)
        finally:
            if temp_slice and temp_slice.exists() and not keep_time_slice:
                temp_slice.unlink()
    result: dict[str, Any] = {
        "pcap": str(output),
        "display_filter": display_filter,
        "call_id": actual_call_id,
        "time_slice": str(temp_slice) if temp_slice and temp_slice.exists() else "",
    }
    if analyze:
        report_dir = output.parent
        analysis = analyze_pcap_file(
            pcap_path=output,
            tshark=tshark,
            call_id=actual_call_id,
            ai_command=ai_command,
        )
        artifacts = write_reports(analysis, report_dir, basename)
        result.update(artifacts)
        result["diagnosis_summary"] = analysis["diagnosis"]["summary"]
    return result


def extract_call(args: argparse.Namespace) -> None:
    result = export_call_file(
        pcap_path=Path(args.pcap),
        call_id=args.call_id,
        db_path=Path(args.db) if args.db else None,
        out_dir=Path(args.out_dir) if args.out_dir else None,
        margin_seconds=args.margin_seconds,
        analyze=args.analisar,
        ai_command=args.ai_command,
        tshark_path=args.tshark,
        editcap_path=args.editcap,
        no_time_slice=args.no_time_slice,
        keep_time_slice=args.keep_time_slice,
    )
    print(f"Filtro usado: {result['display_filter']}")
    print_artifact_summary(result, "PCAP reduzido")
    if result.get("diagnosis_summary"):
        print(f"Diagnostico: {result['diagnosis_summary']}")


@dataclass
class RtpPacket:
    frame_number: int
    ts_epoch: float
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    ssrc: str
    seq: int | None
    payload_type: str
    jitter_ms: float | None
    delta_ms: float | None
    lost_segment: str
    is_rtcp: bool = False


def rtp_packets_from_rows(rows: Iterable[dict[str, str]]) -> list[RtpPacket]:
    packets: list[RtpPacket] = []
    for row in rows:
        frame_number = parse_int(row.get("frame.number"))
        ts_epoch = parse_float(row.get("frame.time_epoch"))
        if frame_number is None or ts_epoch is None:
            continue
        src_ip = row_value(row, "ip.src", "ipv6.src")
        dst_ip = row_value(row, "ip.dst", "ipv6.dst")
        src_port = parse_int(row.get("udp.srcport"))
        dst_port = parse_int(row.get("udp.dstport"))
        rtp_ssrc = row.get("rtp.ssrc", "").split("|")[0].strip()
        rtcp_ssrc = row.get("rtcp.ssrc", "").split("|")[0].strip()
        packets.append(
            RtpPacket(
                frame_number=frame_number,
                ts_epoch=ts_epoch,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                ssrc=rtp_ssrc or rtcp_ssrc,
                seq=parse_int(row.get("rtp.seq")),
                payload_type=row.get("rtp.p_type", "").split("|")[0].strip(),
                jitter_ms=parse_float(row.get("rtp.analysis.jitter")),
                delta_ms=parse_float(row.get("rtp.analysis.delta")),
                lost_segment=row.get("rtp.analysis.lost_segment", ""),
                is_rtcp=not bool(rtp_ssrc) and bool(rtcp_ssrc or row.get("rtcp.pt")),
            )
        )
    return packets


def max_number(values: Iterable[float | int | None]) -> float | int | None:
    clean = [value for value in values if value is not None]
    return max(clean) if clean else None


def packet_loss_percent_by_seq(packets: list[RtpPacket]) -> float:
    seqs = sorted({packet.seq for packet in packets if packet.seq is not None})
    if not seqs:
        return 0
    expected = seqs[-1] - seqs[0] + 1
    if expected <= 0 or expected >= 100000:
        return 0
    lost = max(0, expected - len(seqs))
    return round((lost / expected) * 100, 3) if expected else 0


def rtcp_matches_rtp_direction(rtcp: RtpPacket, rtp_key: tuple[Any, ...]) -> bool:
    src_ip, src_port, dst_ip, dst_port = rtp_key
    if rtcp.src_ip != src_ip or rtcp.dst_ip != dst_ip:
        return False
    if rtcp.src_port is None or rtcp.dst_port is None or src_port is None or dst_port is None:
        return True
    port_pairs = {
        (src_port, dst_port),
        (src_port + 1, dst_port + 1),
        (src_port + 1, dst_port),
        (src_port, dst_port + 1),
    }
    return (rtcp.src_port, rtcp.dst_port) in port_pairs


def summarize_rtp_directions(packets: list[RtpPacket]) -> list[dict[str, Any]]:
    rtp_by_direction: dict[tuple[Any, ...], list[RtpPacket]] = {}
    rtcp_packets: list[RtpPacket] = []
    for packet in packets:
        if packet.is_rtcp:
            rtcp_packets.append(packet)
            continue
        key = (packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port)
        rtp_by_direction.setdefault(key, []).append(packet)

    directions: list[dict[str, Any]] = []
    for key, direction_packets in rtp_by_direction.items():
        direction_packets.sort(key=lambda item: (item.ts_epoch, item.frame_number))
        matched_rtcp = [packet for packet in rtcp_packets if rtcp_matches_rtp_direction(packet, key)]
        payload_types = sorted({packet.payload_type for packet in direction_packets if packet.payload_type})
        payload_names = sorted(
            {
                STATIC_RTP_PAYLOADS.get(payload_type, "")
                for payload_type in payload_types
                if STATIC_RTP_PAYLOADS.get(payload_type, "")
            }
        )
        ssrcs = sorted({packet.ssrc for packet in direction_packets if packet.ssrc})
        first_epoch = direction_packets[0].ts_epoch
        last_epoch = direction_packets[-1].ts_epoch
        directions.append(
            {
                "src_ip": key[0],
                "src_port": key[1],
                "dst_ip": key[2],
                "dst_port": key[3],
                "packets": len(direction_packets),
                "payload_types": payload_types,
                "payload_names": payload_names,
                "ssrcs": ssrcs,
                "first_epoch": round(first_epoch, 6),
                "last_epoch": round(last_epoch, 6),
                "first_time": epoch_to_local(first_epoch),
                "last_time": epoch_to_local(last_epoch),
                "duration_seconds": round(last_epoch - first_epoch, 3),
                "loss_percent_max": packet_loss_percent_by_seq(direction_packets),
                "jitter_max_ms": max_number(packet.jitter_ms for packet in direction_packets),
                "delta_max_ms": max_number(packet.delta_ms for packet in direction_packets),
                "has_rtcp": bool(matched_rtcp),
                "rtcp_packets": len(matched_rtcp),
            }
        )
    return sorted(directions, key=lambda item: item["packets"], reverse=True)


def summarize_rtp(packets: list[RtpPacket]) -> dict[str, Any]:
    streams: dict[tuple[Any, ...], list[RtpPacket]] = {}
    for packet in packets:
        key = (
            packet.src_ip,
            packet.src_port,
            packet.dst_ip,
            packet.dst_port,
            packet.ssrc or "sem-ssrc",
            packet.payload_type or ("RTCP" if packet.is_rtcp else "desconhecido"),
        )
        streams.setdefault(key, []).append(packet)

    stream_summaries: list[dict[str, Any]] = []
    for key, stream_packets in streams.items():
        stream_packets.sort(key=lambda item: (item.ts_epoch, item.frame_number))
        seqs = sorted({packet.seq for packet in stream_packets if packet.seq is not None})
        lost = 0
        expected = None
        if seqs:
            expected = seqs[-1] - seqs[0] + 1
            if 0 < expected < 100000:
                lost = max(0, expected - len(seqs))
            else:
                expected = None
        jitters = [packet.jitter_ms for packet in stream_packets if packet.jitter_ms is not None]
        deltas = [packet.delta_ms for packet in stream_packets if packet.delta_ms is not None]
        payload_type = str(key[5])
        stream_summaries.append(
            {
                "src_ip": key[0],
                "src_port": key[1],
                "dst_ip": key[2],
                "dst_port": key[3],
                "ssrc": key[4],
                "payload_type": payload_type,
                "payload_name": STATIC_RTP_PAYLOADS.get(payload_type, ""),
                "packets": len(stream_packets),
                "first_frame": stream_packets[0].frame_number,
                "last_frame": stream_packets[-1].frame_number,
                "first_epoch": round(stream_packets[0].ts_epoch, 6),
                "last_epoch": round(stream_packets[-1].ts_epoch, 6),
                "first_time": epoch_to_local(stream_packets[0].ts_epoch),
                "last_time": epoch_to_local(stream_packets[-1].ts_epoch),
                "duration_seconds": round(stream_packets[-1].ts_epoch - stream_packets[0].ts_epoch, 3),
                "expected_packets_by_seq": expected,
                "lost_packets_by_seq": lost,
                "loss_percent_by_seq": round((lost / expected) * 100, 3) if expected else 0,
                "jitter_avg_ms": round(sum(jitters) / len(jitters), 3) if jitters else None,
                "jitter_max_ms": round(max(jitters), 3) if jitters else None,
                "delta_max_ms": round(max(deltas), 3) if deltas else None,
                "rtcp": any(packet.is_rtcp for packet in stream_packets),
            }
        )
    return {
        "total_packets": len(packets),
        "total_rtp_packets": len([packet for packet in packets if not packet.is_rtcp]),
        "total_rtcp_packets": len([packet for packet in packets if packet.is_rtcp]),
        "stream_count": len(stream_summaries),
        "streams": sorted(stream_summaries, key=lambda item: item["packets"], reverse=True),
        "directions": summarize_rtp_directions(packets),
        "warnings": [],
    }


def is_private_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def build_sip_timeline(events: list[SipEvent]) -> list[dict[str, Any]]:
    relevant_methods = {"INVITE", "ACK", "BYE", "CANCEL"}
    relevant_statuses = {100, 180, 183, 200}
    timeline: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for event in sorted(events, key=lambda item: (item.ts_epoch, item.frame_number)):
        event_name = ""
        if event.status_code is not None:
            if event.status_code in relevant_statuses or event.status_code >= 300:
                event_name = f"{event.status_code} {event.reason_phrase}".strip()
        elif event.method in relevant_methods:
            event_name = event.method
        if not event_name:
            continue
        dedupe_key = (event.frame_number, event_name, event.src_ip, event.dst_ip)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        timeline.append(
            {
                "frame": event.frame_number,
                "time": epoch_to_local(event.ts_epoch),
                "event": event_name,
                "method": event.method,
                "status_code": event.status_code,
                "reason_phrase": event.reason_phrase,
                "cseq_method": event.cseq_method,
                "src": event.src_ip,
                "src_port": event.src_port,
                "dst": event.dst_ip,
                "dst_port": event.dst_port,
            }
        )
    return timeline


def build_rtp_warnings(sip: dict[str, Any], rtp_summary: dict[str, Any], tolerance_seconds: float = 5.0) -> list[dict[str, Any]]:
    warnings: list[dict[str, Any]] = []
    directions = [item for item in rtp_summary.get("directions", []) if item.get("packets", 0) > 0]
    if sip.get("completed") and rtp_summary.get("total_rtp_packets", 0) == 0:
        warnings.append(
            {
                "code": "no_rtp",
                "severity": "alta",
                "title": "Sem RTP",
                "evidence": "A chamada completou SIP, mas nenhum pacote RTP foi decodificado.",
            }
        )
    if sip.get("completed") and len(directions) == 1:
        direction = directions[0]
        warnings.append(
            {
                "code": "one_way_audio",
                "severity": "alta",
                "title": "Audio unilateral",
                "evidence": (
                    f"Apenas uma direcao RTP util: {direction.get('src_ip')}:{direction.get('src_port')} -> "
                    f"{direction.get('dst_ip')}:{direction.get('dst_port')}."
                ),
            }
        )
    for direction in directions:
        if not direction.get("has_rtcp"):
            warnings.append(
                {
                    "code": "missing_rtcp",
                    "severity": "baixa",
                    "title": "RTCP ausente",
                    "evidence": (
                        f"Sem RTCP observado para {direction.get('src_ip')}:{direction.get('src_port')} -> "
                        f"{direction.get('dst_ip')}:{direction.get('dst_port')}."
                    ),
                }
            )
    first_epoch = sip.get("first_epoch")
    last_epoch = sip.get("last_epoch")
    if first_epoch is not None and last_epoch is not None:
        for direction in directions:
            rtp_first = direction.get("first_epoch")
            rtp_last = direction.get("last_epoch")
            if rtp_first is None or rtp_last is None:
                continue
            if rtp_first < first_epoch - tolerance_seconds or rtp_last > last_epoch + tolerance_seconds:
                warnings.append(
                    {
                        "code": "rtp_outside_sip_window",
                        "severity": "media",
                        "title": "RTP fora da janela SIP esperada",
                        "evidence": (
                            f"{direction.get('src_ip')}:{direction.get('src_port')} -> "
                            f"{direction.get('dst_ip')}:{direction.get('dst_port')} iniciou em "
                            f"{direction.get('first_time')} e terminou em {direction.get('last_time')}."
                        ),
                    }
                )
    return warnings


def sdp_endpoints(sdp_media: list[dict[str, Any]]) -> set[tuple[str, int]]:
    endpoints: set[tuple[str, int]] = set()
    for media in sdp_media:
        ip = str(media.get("ip") or "").strip()
        port = parse_int(str(media.get("port") or ""))
        if ip and port:
            endpoints.add((ip, port))
    return endpoints


def has_rtp_endpoint_mismatch(sdp_media: list[dict[str, Any]], rtp_summary: dict[str, Any]) -> bool:
    endpoints = sdp_endpoints(sdp_media)
    directions = [item for item in rtp_summary.get("directions", []) if item.get("packets", 0) > 0]
    if not endpoints or not directions:
        return False
    for direction in directions:
        src = (str(direction.get("src_ip") or ""), parse_int(str(direction.get("src_port") or "")))
        dst = (str(direction.get("dst_ip") or ""), parse_int(str(direction.get("dst_port") or "")))
        if src in endpoints or dst in endpoints:
            return False
    return True


def build_operational_verdict(facts: dict[str, Any]) -> dict[str, Any]:
    sip = facts["sip"]
    rtp = facts["rtp"]
    sdp = facts["sdp"]
    correlation = facts["correlation"]
    status_code = sip.get("status_code")
    total_rtp = rtp.get("total_rtp_packets", rtp.get("total_packets", 0))
    direction_count = len([item for item in rtp.get("directions", []) if item.get("packets", 0) > 0])
    payload_mismatch = bool(correlation.get("payloads_not_advertised_in_sdp"))
    endpoint_mismatch = bool(correlation.get("rtp_endpoint_mismatch"))
    private_sdp = bool(sdp.get("private_media_addresses"))

    if status_code and status_code >= 300:
        return {
            "status": "failed",
            "severity": "alta" if status_code >= 500 else "media",
            "title": f"Chamada falhou com SIP {status_code}",
            "summary": f"Resposta final observada: {status_code} {sip.get('reason_phrase') or ''}".strip(),
            "evidence": f"Status SIP final {status_code} no Call-ID analisado.",
        }
    if sip.get("has_cancel"):
        return {
            "status": "failed",
            "severity": "media",
            "title": "Chamada cancelada",
            "summary": "Foi observado CANCEL na sinalizacao.",
            "evidence": "Metodo CANCEL presente na timeline SIP.",
        }
    if sip.get("has_invite") and not sip.get("completed"):
        return {
            "status": "failed",
            "severity": "media",
            "title": "Chamada nao completou SIP",
            "summary": "Ha INVITE, mas nao foi observado 200 OK para completar a chamada.",
            "evidence": "Sinalizacao sem 200 OK de INVITE no recorte analisado.",
        }
    if sip.get("completed") and total_rtp == 0:
        return {
            "status": "completed_no_media",
            "severity": "alta",
            "title": "Chamada completou sem RTP",
            "summary": "A sinalizacao completou, mas nao houve midia RTP decodificada.",
            "evidence": "200 OK/ACK observado e total de pacotes RTP igual a zero.",
        }
    if sip.get("completed") and direction_count == 1:
        return {
            "status": "one_way_audio",
            "severity": "alta",
            "title": "Audio unilateral",
            "summary": "A chamada completou, mas o RTP apareceu em apenas uma direcao.",
            "evidence": "Somente uma direcao RTP util foi observada no PCAP reduzido.",
        }
    if payload_mismatch or endpoint_mismatch:
        evidence_parts = []
        if payload_mismatch:
            evidence_parts.append(
                "payload RTP fora do SDP: " + ", ".join(correlation.get("payloads_not_advertised_in_sdp", []))
            )
        if endpoint_mismatch:
            evidence_parts.append("endpoints RTP nao coincidem com IP/porta anunciados no SDP")
        return {
            "status": "media_mismatch",
            "severity": "media",
            "title": "Midia divergente do SDP",
            "summary": "O RTP observado nao bate completamente com a negociacao SDP.",
            "evidence": "; ".join(evidence_parts),
        }
    if private_sdp:
        examples = ", ".join(
            f"{item.get('ip')}:{item.get('port')}"
            for item in sdp.get("private_media_addresses", [])[:5]
        )
        return {
            "status": "possible_nat_sdp",
            "severity": "media",
            "title": "Possivel NAT/SDP incorreto",
            "summary": "O SDP anuncia endereco privado de midia.",
            "evidence": f"Enderecos privados no SDP: {examples}.",
        }
    if sip.get("completed") and direction_count >= 2:
        return {
            "status": "completed_with_media",
            "severity": "info",
            "title": "Chamada completada com midia",
            "summary": "SIP completou e ha RTP em mais de uma direcao.",
            "evidence": f"{direction_count} direcoes RTP uteis observadas.",
        }
    return {
        "status": "inconclusive",
        "severity": "info",
        "title": "Analise inconclusiva",
        "summary": "Nao ha dados suficientes para um veredito operacional definitivo.",
        "evidence": "Verifique timeline SIP, SDP e streams RTP no JSON estruturado.",
    }


def facts_from_events_and_rtp(
    call_id: str,
    sip_events: list[SipEvent],
    rtp_summary: dict[str, Any],
) -> dict[str, Any]:
    summaries = aggregate_calls([event for event in sip_events if event.call_id == call_id])
    call = summaries[0] if summaries else None
    events = [event for event in sip_events if event.call_id == call_id]
    responses = [
        {
            "frame": event.frame_number,
            "time": epoch_to_local(event.ts_epoch),
            "status_code": event.status_code,
            "reason_phrase": event.reason_phrase,
            "cseq_method": event.cseq_method,
            "src": event.src_ip,
            "dst": event.dst_ip,
        }
        for event in events
        if event.status_code is not None
    ]
    methods = [
        {
            "frame": event.frame_number,
            "time": epoch_to_local(event.ts_epoch),
            "method": event.method,
            "cseq_method": event.cseq_method,
            "src": event.src_ip,
            "dst": event.dst_ip,
        }
        for event in events
        if event.method
    ]
    sdp_media = call.sdp_media if call else []
    private_sdp = [
        media
        for media in sdp_media
        if media.get("ip") and is_private_ip(str(media.get("ip")))
    ]
    sdp_payloads = {
        str(payload)
        for media in sdp_media
        for payload in (media.get("payloads") or [])
    }
    rtp_payloads = {
        str(stream.get("payload_type"))
        for stream in rtp_summary.get("streams", [])
        if stream.get("payload_type") not in ("", "RTCP", "desconhecido")
    }
    divergent_payloads = sorted(rtp_payloads - sdp_payloads) if sdp_payloads else []
    endpoint_mismatch = has_rtp_endpoint_mismatch(sdp_media, rtp_summary)
    sender_endpoints = {
        (stream.get("src_ip"), stream.get("src_port"))
        for stream in rtp_summary.get("streams", [])
        if not stream.get("rtcp") and stream.get("packets", 0) > 0
    }
    sip_facts = {
        "first_epoch": round(call.first_epoch, 6) if call else None,
        "last_epoch": round(call.last_epoch, 6) if call else None,
        "first_time": epoch_to_local(call.first_epoch) if call else "",
        "last_time": epoch_to_local(call.last_epoch) if call else "",
        "duration_seconds": round(call.last_epoch - call.first_epoch, 3) if call else 0,
        "from_user": call.from_user if call else "",
        "to_user": call.to_user if call else "",
        "request_uri_user": call.request_uri_user if call else "",
        "status_code": call.status_code if call else None,
        "reason_phrase": call.reason_phrase if call else "",
        "completed": call.completed if call else False,
        "has_invite": call.has_invite if call else False,
        "has_ack": call.has_ack if call else False,
        "has_bye": call.has_bye if call else False,
        "has_cancel": call.has_cancel if call else False,
        "methods": call.methods if call else [],
        "responses": responses,
        "method_events": methods,
        "timeline": build_sip_timeline(events),
    }
    rtp_summary["warnings"] = build_rtp_warnings(sip_facts, rtp_summary)
    facts = {
        "call_id": call_id,
        "sip": sip_facts,
        "sdp": {
            "media": sdp_media,
            "private_media_addresses": private_sdp,
        },
        "rtp": rtp_summary,
        "correlation": {
            "sdp_payloads": sorted(sdp_payloads),
            "rtp_payloads": sorted(rtp_payloads),
            "payloads_not_advertised_in_sdp": divergent_payloads,
            "rtp_sender_endpoint_count": len(sender_endpoints),
            "rtp_direction_count": len([item for item in rtp_summary.get("directions", []) if item.get("packets", 0) > 0]),
            "rtp_endpoint_mismatch": endpoint_mismatch,
        },
    }
    facts["verdict"] = build_operational_verdict(facts)
    return facts


def build_diagnosis(facts: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    sip = facts["sip"]
    rtp = facts["rtp"]
    sdp = facts["sdp"]
    correlation = facts["correlation"]
    status_code = sip.get("status_code")

    if status_code and status_code >= 300:
        findings.append(
            {
                "severity": "alta" if status_code >= 500 else "media",
                "title": f"Chamada falhou com SIP {status_code}",
                "evidence": f"Resposta final: {status_code} {sip.get('reason_phrase') or ''}".strip(),
                "recommendation": "Verificar o motivo SIP, rota, codec e politicas do SBC/operadora.",
            }
        )
    elif sip.get("completed"):
        findings.append(
            {
                "severity": "info",
                "title": "SIP completou a sinalizacao da chamada",
                "evidence": "Foi observada resposta 200 OK relacionada a chamada.",
                "recommendation": "Correlacionar com RTP para confirmar audio bidirecional.",
            }
        )

    if sip.get("completed") and not sip.get("has_ack"):
        findings.append(
            {
                "severity": "alta",
                "title": "200 OK sem ACK observado",
                "evidence": "A chamada recebeu 200 OK, mas nenhum ACK foi indexado no recorte.",
                "recommendation": "Investigar roteamento SIP, NAT, firewall ou perda de mensagens entre os endpoints.",
            }
        )

    if sip.get("has_cancel"):
        findings.append(
            {
                "severity": "media",
                "title": "CANCEL observado",
                "evidence": "A sinalizacao contem metodo CANCEL.",
                "recommendation": "Verificar se o originador cancelou antes do atendimento ou se houve timeout de chamada.",
            }
        )

    if rtp.get("total_packets", 0) == 0:
        findings.append(
            {
                "severity": "alta" if sip.get("completed") else "media",
                "title": "Nenhum RTP decodificado no recorte",
                "evidence": "TShark nao encontrou pacotes RTP/RTCP no PCAP analisado.",
                "recommendation": "Confirmar portas SDP, decode-as RTP no Wireshark, NAT/firewall e se a midia usa SRTP.",
            }
        )
    elif correlation.get("rtp_sender_endpoint_count") == 1:
        findings.append(
            {
                "severity": "alta",
                "title": "RTP aparente em apenas uma direcao",
                "evidence": "Somente um endpoint de origem enviou RTP decodificado.",
                "recommendation": "Investigar audio unilateral, bloqueio de firewall/NAT ou SDP com IP/porta incorretos.",
            }
        )

    high_loss = [
        stream
        for stream in rtp.get("streams", [])
        if stream.get("loss_percent_by_seq", 0) >= 5
    ]
    for stream in high_loss[:3]:
        findings.append(
            {
                "severity": "alta",
                "title": "Perda RTP elevada",
                "evidence": (
                    f"{stream['src_ip']}:{stream['src_port']} -> "
                    f"{stream['dst_ip']}:{stream['dst_port']} com "
                    f"{stream['loss_percent_by_seq']}% de perda estimada por sequencia."
                ),
                "recommendation": "Verificar rede, QoS, congestionamento, interface do SBC e rota de midia.",
            }
        )

    high_jitter = [
        stream
        for stream in rtp.get("streams", [])
        if stream.get("jitter_max_ms") is not None and stream.get("jitter_max_ms", 0) >= 50
    ]
    for stream in high_jitter[:3]:
        findings.append(
            {
                "severity": "media",
                "title": "Jitter RTP alto",
                "evidence": (
                    f"{stream['src_ip']}:{stream['src_port']} -> "
                    f"{stream['dst_ip']}:{stream['dst_port']} com jitter maximo "
                    f"{stream['jitter_max_ms']} ms."
                ),
                "recommendation": "Verificar latencia variavel, filas, QoS e enlaces saturados.",
            }
        )

    if sdp.get("private_media_addresses"):
        examples = ", ".join(
            f"{item.get('ip')}:{item.get('port')}"
            for item in sdp["private_media_addresses"][:5]
        )
        findings.append(
            {
                "severity": "media",
                "title": "SDP anuncia endereco privado",
                "evidence": f"Enderecos privados encontrados no SDP: {examples}.",
                "recommendation": "Confirmar se a chamada atravessa NAT/SBC e se o SDP esta sendo reescrito corretamente.",
            }
        )

    if correlation.get("payloads_not_advertised_in_sdp"):
        findings.append(
            {
                "severity": "media",
                "title": "Payload RTP nao anunciado no SDP",
                "evidence": (
                    "Payloads RTP fora da lista SDP: "
                    + ", ".join(correlation["payloads_not_advertised_in_sdp"])
                ),
                "recommendation": "Verificar negociacao de codec, payload dinamico e possivel decode incorreto.",
            }
        )

    if correlation.get("rtp_endpoint_mismatch"):
        findings.append(
            {
                "severity": "media",
                "title": "Endpoint RTP divergente do SDP",
                "evidence": "Nenhuma direcao RTP observada corresponde aos IPs/portas de midia anunciados no SDP.",
                "recommendation": "Verificar NAT, SBC, ancoragem de midia e reescrita de SDP.",
            }
        )

    for warning in rtp.get("warnings", []):
        if warning.get("code") not in ("missing_rtcp", "rtp_outside_sip_window"):
            continue
        findings.append(
            {
                "severity": warning.get("severity", "baixa"),
                "title": warning.get("title", "Aviso RTP"),
                "evidence": warning.get("evidence", ""),
                "recommendation": "Validar captura RTP, RTCP, janela de exportacao e comportamento do SBC.",
            }
        )

    if not findings:
        findings.append(
            {
                "severity": "info",
                "title": "Nenhum problema obvio detectado pelas regras locais",
                "evidence": "As verificacoes SIP/RTP basicas nao encontraram falhas claras.",
                "recommendation": "Usar o JSON de evidencias para uma revisao manual ou envio a uma IA local.",
            }
        )

    severity_order = {"alta": 0, "media": 1, "baixa": 2, "info": 3}
    findings.sort(key=lambda item: severity_order.get(item["severity"], 9))
    verdict = facts.get("verdict", {}) if isinstance(facts.get("verdict"), dict) else {}
    return {
        "summary": verdict.get("title") or (findings[0]["title"] if findings else "Analise concluida"),
        "findings": findings,
    }


def call_ai_command(command: str | None, facts: dict[str, Any]) -> str | None:
    if not command:
        return None
    prompt = {
        "role": "voip_sip_rtp_diagnostic",
        "instruction": (
            "Analise os fatos estruturados de uma chamada SIP/RTP. "
            "Responda em portugues, cite evidencias objetivas e nao invente "
            "campos que nao estejam no JSON."
        ),
        "facts": facts,
    }
    try:
        proc = subprocess.run(
            command,
            input=json_dumps(prompt),
            text=True,
            shell=True,
            capture_output=True,
            timeout=120,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"IA opcional falhou: {exc}"
    if proc.returncode != 0:
        return f"IA opcional retornou erro: {proc.stderr.strip() or proc.stdout.strip()}"
    return proc.stdout.strip()


def analyze_pcap_file(
    pcap_path: Path,
    tshark: str,
    call_id: str | None = None,
    ai_command: str | None = None,
) -> dict[str, Any]:
    _, sip_rows = run_tshark_fields(tshark, pcap_path, "sip", SIP_FIELDS)
    sip_events = sip_events_from_rows(sip_rows)
    if not sip_events:
        raise SystemExit("Nenhum evento SIP encontrado no PCAP analisado.")
    if call_id is None:
        call_ids = sorted({event.call_id for event in sip_events})
        if len(call_ids) > 1:
            raise SystemExit(
                "Mais de um Call-ID encontrado. Informe --call-id. Encontrados: "
                + ", ".join(call_ids[:10])
            )
        call_id = call_ids[0]
    _, rtp_rows = run_tshark_fields(tshark, pcap_path, "rtp || rtcp", RTP_FIELDS)
    rtp_packets = rtp_packets_from_rows(rtp_rows)
    rtp_summary = summarize_rtp(rtp_packets)
    facts = facts_from_events_and_rtp(call_id, sip_events, rtp_summary)
    diagnosis = build_diagnosis(facts)
    ai_text = call_ai_command(ai_command, facts)
    return {
        "tool_version": TOOL_VERSION,
        "pcap": str(pcap_path.resolve()),
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "facts": facts,
        "diagnosis": diagnosis,
        "ai_text": ai_text,
    }


def html_table(headers: list[str], rows: list[list[Any]]) -> str:
    out = ["<table>", "<thead><tr>"]
    for header in headers:
        out.append(f"<th>{html.escape(str(header))}</th>")
    out.append("</tr></thead><tbody>")
    for row in rows:
        out.append("<tr>")
        for cell in row:
            out.append(f"<td>{html.escape('' if cell is None else str(cell))}</td>")
        out.append("</tr>")
    out.append("</tbody></table>")
    return "".join(out)


def render_html_report(analysis: dict[str, Any]) -> str:
    facts = analysis["facts"]
    sip = facts["sip"]
    rtp = facts["rtp"]
    diagnosis = analysis["diagnosis"]
    finding_rows = [
        [item["severity"], item["title"], item["evidence"], item["recommendation"]]
        for item in diagnosis["findings"]
    ]
    stream_rows = [
        [
            stream["src_ip"],
            stream["src_port"],
            stream["dst_ip"],
            stream["dst_port"],
            stream["payload_type"],
            stream["payload_name"],
            stream["packets"],
            stream["loss_percent_by_seq"],
            stream["jitter_max_ms"],
        ]
        for stream in rtp.get("streams", [])
    ]
    response_rows = [
        [
            response["frame"],
            response["time"],
            response["status_code"],
            response["reason_phrase"],
            response["cseq_method"],
            response["src"],
            response["dst"],
        ]
        for response in sip.get("responses", [])
    ]
    ai_section = ""
    if analysis.get("ai_text"):
        ai_section = (
            "<h2>Diagnostico IA opcional</h2><pre>"
            + html.escape(analysis["ai_text"])
            + "</pre>"
        )
    return f"""<!doctype html>
<html lang="pt-br">
<head>
  <meta charset="utf-8">
  <title>Relatorio SIP/RTP - {html.escape(facts['call_id'])}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #1f2933; }}
    h1, h2 {{ color: #102a43; }}
    table {{ border-collapse: collapse; width: 100%; margin: 12px 0 28px; }}
    th, td {{ border: 1px solid #bcccdc; padding: 7px 9px; text-align: left; vertical-align: top; }}
    th {{ background: #e6f6ff; }}
    code, pre {{ background: #f0f4f8; padding: 8px; display: block; white-space: pre-wrap; }}
    .meta {{ display: grid; grid-template-columns: 220px 1fr; gap: 6px 16px; }}
  </style>
</head>
<body>
  <h1>Relatorio SIP/RTP</h1>
  <div class="meta">
    <strong>Call-ID</strong><span>{html.escape(facts['call_id'])}</span>
    <strong>Arquivo</strong><span>{html.escape(analysis['pcap'])}</span>
    <strong>Gerado em</strong><span>{html.escape(analysis['generated_at'])}</span>
    <strong>Origem</strong><span>{html.escape(sip.get('from_user') or '')}</span>
    <strong>Destino</strong><span>{html.escape(sip.get('to_user') or '')}</span>
    <strong>Status SIP</strong><span>{html.escape(str(sip.get('status_code') or ''))} {html.escape(sip.get('reason_phrase') or '')}</span>
    <strong>Duração SIP</strong><span>{html.escape(str(sip.get('duration_seconds')))} s</span>
    <strong>Pacotes RTP/RTCP</strong><span>{html.escape(str(rtp.get('total_packets', 0)))}</span>
  </div>

  <h2>Diagnostico</h2>
  {html_table(["Severidade", "Achado", "Evidencia", "Recomendacao"], finding_rows)}

  <h2>Respostas SIP</h2>
  {html_table(["Frame", "Horario", "Status", "Reason", "CSeq", "Origem", "Destino"], response_rows)}

  <h2>Streams RTP/RTCP</h2>
  {html_table(["Origem IP", "Origem porta", "Destino IP", "Destino porta", "Payload", "Codec", "Pacotes", "Perda %", "Jitter max ms"], stream_rows)}

  {ai_section}

  <h2>JSON estruturado</h2>
  <pre>{html.escape(json_dumps(analysis))}</pre>
</body>
</html>
"""


def write_reports(analysis: dict[str, Any], out_dir: Path, basename: str) -> dict[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"{basename}_report.json"
    html_path = out_dir / f"{basename}_report.html"
    artifacts = {
        "pcap": analysis["pcap"],
        "report_json": str(json_path),
        "report_html": str(html_path),
    }
    analysis["artifacts"] = artifacts
    json_path.write_text(json_dumps(analysis) + "\n", encoding="utf-8")
    html_path.write_text(render_html_report(analysis), encoding="utf-8")
    return artifacts


def analyze_command(args: argparse.Namespace) -> None:
    pcap_path = Path(args.pcap).resolve()
    if not pcap_path.exists():
        raise SystemExit(f"PCAP nao encontrado: {pcap_path}")
    tshark = resolve_tshark(args.tshark)
    analysis = analyze_pcap_file(
        pcap_path=pcap_path,
        tshark=tshark,
        call_id=args.call_id,
        ai_command=args.ai_command,
    )
    basename = safe_filename(pcap_path.stem)
    out_dir = Path(args.out_dir).resolve() if args.out_dir else pcap_path.parent
    artifacts = write_reports(analysis, out_dir, basename)
    print_artifact_summary(artifacts, "PCAP analisado")
    if args.json:
        print(json_dumps(analysis))
    else:
        print(analysis["diagnosis"]["summary"])


def prompt_ai_command(args: argparse.Namespace) -> None:
    report_path = Path(args.report_json).resolve()
    data = json.loads(report_path.read_text(encoding="utf-8"))
    payload = {
        "role": "voip_sip_rtp_diagnostic",
        "instruction": (
            "Analise os fatos estruturados de uma chamada SIP/RTP. "
            "Responda em portugues, cite evidencias objetivas e nao invente "
            "campos que nao estejam no JSON."
        ),
        "facts": data.get("facts", data),
    }
    print(json_dumps(payload))


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="siprtp_ai",
        description="Indexa, busca, extrai e analisa chamadas SIP/RTP em PCAPs grandes.",
    )
    parser.add_argument("--tshark", help="Caminho para tshark.exe quando nao esta no PATH.")
    parser.add_argument("--editcap", help="Caminho para editcap.exe quando nao esta no PATH.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_index = sub.add_parser("indexar", help="Cria indice SQLite de chamadas SIP/SDP.")
    p_index.add_argument("pcap", help="Arquivo .pcap/.pcapng de origem.")
    p_index.add_argument("--db", help="Caminho do indice SQLite.")
    p_index.add_argument("--force", action="store_true", help="Recria indice existente.")
    p_index.add_argument(
        "--store-events",
        action="store_true",
        help="Grava cada evento SIP no SQLite. Mais lento e maior; use so para auditoria detalhada.",
    )
    p_index.add_argument(
        "--progress-events",
        type=int,
        default=100000,
        help="Mostra progresso a cada N eventos SIP processados. Use 0 para silenciar.",
    )
    p_index.add_argument(
        "--event-batch-size",
        type=int,
        default=5000,
        help="Tamanho do lote ao gravar eventos com --store-events.",
    )
    p_index.set_defaults(func=index_pcap)

    p_search = sub.add_parser("buscar", help="Busca chamadas por numero e janela de horario.")
    p_search.add_argument("pcap", help="Arquivo .pcap/.pcapng usado na indexacao.")
    p_search.add_argument("--db", help="Caminho do indice SQLite.")
    p_search.add_argument("--numero", required=True, help="Numero chamador/chamado a procurar.")
    p_search.add_argument("--inicio", required=True, help="Horario aproximado: ISO, epoch, DD/MM/YYYY HH:MM ou HH:MM:SS.")
    p_search.add_argument("--janela", type=float, default=5, help="Janela em minutos antes/depois. Padrao: 5.")
    p_search.add_argument("--limit", type=int, default=20, help="Numero maximo de resultados.")
    p_search.add_argument("--json", action="store_true", help="Imprime resultados em JSON.")
    p_search.set_defaults(func=search_calls)

    p_extract = sub.add_parser("extrair", help="Extrai PCAP reduzido de uma chamada.")
    p_extract.add_argument("pcap", help="Arquivo .pcap/.pcapng de origem.")
    p_extract.add_argument("--db", help="Caminho do indice SQLite.")
    p_extract.add_argument("--call-id", required=True, help="Call-ID SIP a extrair.")
    p_extract.add_argument("--out-dir", help="Diretorio de saida.")
    p_extract.add_argument("--margin-seconds", type=float, default=10, help="Margem antes/depois da chamada. Padrao: 10s.")
    p_extract.add_argument("--analisar", action="store_true", help="Gera relatorio apos extrair.")
    p_extract.add_argument("--ai-command", help="Comando opcional de IA que recebe JSON no stdin.")
    p_extract.add_argument(
        "--no-time-slice",
        action="store_true",
        help="Desativa o recorte temporal com editcap antes do filtro TShark.",
    )
    p_extract.add_argument(
        "--keep-time-slice",
        action="store_true",
        help="Mantem o arquivo temporario do recorte temporal para depuracao.",
    )
    p_extract.set_defaults(func=extract_call)

    p_analyze = sub.add_parser("analisar", help="Analisa um PCAP ja recortado.")
    p_analyze.add_argument("pcap", help="Arquivo .pcap/.pcapng a analisar.")
    p_analyze.add_argument("--call-id", help="Call-ID quando o recorte contem mais de uma chamada.")
    p_analyze.add_argument("--out-dir", help="Diretorio para relatorios.")
    p_analyze.add_argument("--ai-command", help="Comando opcional de IA que recebe JSON no stdin.")
    p_analyze.add_argument("--json", action="store_true", help="Tambem imprime o JSON no stdout.")
    p_analyze.set_defaults(func=analyze_command)

    p_prompt = sub.add_parser("prompt-ia", help="Gera payload seguro para enviar a uma IA a partir do report JSON.")
    p_prompt.add_argument("report_json", help="Arquivo *_report.json.")
    p_prompt.set_defaults(func=prompt_ai_command)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
