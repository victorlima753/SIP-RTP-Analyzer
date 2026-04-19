#!/usr/bin/env python3
"""Report generation for SIP/RTP Analyzer V2."""

from __future__ import annotations

import datetime as dt
import html
import json
from pathlib import Path
from typing import Any


def html_table(headers: list[str], rows: list[list[Any]]) -> str:
    cells = ["<table>", "<thead><tr>"]
    for header in headers:
        cells.append(f"<th>{html.escape(str(header))}</th>")
    cells.append("</tr></thead><tbody>")
    if rows:
        for row in rows:
            cells.append("<tr>")
            for cell in row:
                cells.append(f"<td>{html.escape('' if cell is None else str(cell))}</td>")
            cells.append("</tr>")
    else:
        cells.append(f"<tr><td colspan=\"{len(headers)}\" class=\"muted\">Sem dados.</td></tr>")
    cells.append("</tbody></table>")
    return "".join(cells)


def analysis_value(payload: dict[str, Any], *keys: str, default: Any = "") -> Any:
    value: Any = payload
    for key in keys:
        if not isinstance(value, dict):
            return default
        value = value.get(key, default)
    return value


def severity_class(severity: Any) -> str:
    return {
        "alta": "severity-high",
        "media": "severity-medium",
        "baixa": "severity-low",
        "info": "severity-info",
    }.get(str(severity or "").lower(), "severity-info")


def render_verdict(facts: dict[str, Any]) -> str:
    verdict = facts.get("verdict", {}) if isinstance(facts, dict) else {}
    if not isinstance(verdict, dict) or not verdict:
        return """
  <h2>Veredito Operacional</h2>
  <div class="verdict severity-info">
    <strong>Analise inconclusiva</strong>
    <p>Nao ha veredito operacional estruturado neste relatorio.</p>
  </div>
"""
    return f"""
  <h2>Veredito Operacional</h2>
  <div class="verdict {severity_class(verdict.get('severity'))}">
    <div class="verdict-status">{html.escape(str(verdict.get('status', '')))}</div>
    <strong>{html.escape(str(verdict.get('title', '')))}</strong>
    <p>{html.escape(str(verdict.get('summary', '')))}</p>
    <p class="muted">{html.escape(str(verdict.get('evidence', '')))}</p>
  </div>
"""


def render_analysis_sections(payload: dict[str, Any]) -> str:
    analysis = payload.get("analysis")
    analysis_error = str(payload.get("analysis_error") or "")
    if not isinstance(analysis, dict):
        detail = html.escape(analysis_error or "Analise SIP/RTP nao disponivel para este relatorio.")
        return f"""
  <h2>Diagnostico</h2>
  <p class="warning">{detail}</p>
"""

    facts = analysis.get("facts", {})
    sip = facts.get("sip", {}) if isinstance(facts, dict) else {}
    rtp = facts.get("rtp", {}) if isinstance(facts, dict) else {}
    diagnosis = analysis.get("diagnosis", {})
    findings = diagnosis.get("findings", []) if isinstance(diagnosis, dict) else []
    finding_rows = [
        [
            item.get("severity", ""),
            item.get("title", ""),
            item.get("evidence", ""),
            item.get("recommendation", ""),
        ]
        for item in findings
        if isinstance(item, dict)
    ]
    response_rows = [
        [
            item.get("frame", ""),
            item.get("time", ""),
            item.get("status_code", ""),
            item.get("reason_phrase", ""),
            item.get("cseq_method", ""),
            item.get("src", ""),
            item.get("dst", ""),
        ]
        for item in sip.get("responses", [])
        if isinstance(item, dict)
    ]
    timeline_rows = [
        [
            item.get("frame", ""),
            item.get("time", ""),
            item.get("event", ""),
            item.get("cseq_method", ""),
            item.get("src", ""),
            item.get("src_port", ""),
            item.get("dst", ""),
            item.get("dst_port", ""),
        ]
        for item in sip.get("timeline", [])
        if isinstance(item, dict)
    ]
    direction_rows = [
        [
            item.get("src_ip", ""),
            item.get("src_port", ""),
            item.get("dst_ip", ""),
            item.get("dst_port", ""),
            item.get("packets", ""),
            ", ".join(str(value) for value in item.get("payload_names", []) or item.get("payload_types", [])),
            ", ".join(str(value) for value in item.get("ssrcs", [])),
            item.get("loss_percent_max", ""),
            item.get("jitter_max_ms", ""),
            item.get("delta_max_ms", ""),
            "sim" if item.get("has_rtcp") else "nao",
            item.get("rtcp_packets", ""),
        ]
        for item in rtp.get("directions", [])
        if isinstance(item, dict)
    ]
    warning_rows = [
        [
            item.get("severity", ""),
            item.get("code", ""),
            item.get("title", ""),
            item.get("evidence", ""),
        ]
        for item in rtp.get("warnings", [])
        if isinstance(item, dict)
    ]
    stream_rows = [
        [
            item.get("src_ip", ""),
            item.get("src_port", ""),
            item.get("dst_ip", ""),
            item.get("dst_port", ""),
            item.get("payload_type", ""),
            item.get("payload_name", ""),
            item.get("packets", ""),
            item.get("loss_percent_by_seq", ""),
            item.get("jitter_max_ms", ""),
        ]
        for item in rtp.get("streams", [])
        if isinstance(item, dict)
    ]
    ai_section = ""
    if analysis.get("ai_text"):
        ai_section = "<h2>Diagnostico IA opcional</h2><pre>" + html.escape(str(analysis["ai_text"])) + "</pre>"
    return f"""
  {render_verdict(facts if isinstance(facts, dict) else {})}
  <h2>Diagnostico</h2>
  {html_table(["Severidade", "Achado", "Evidencia", "Recomendacao"], finding_rows)}
  <h2>Timeline SIP</h2>
  {html_table(["Frame", "Horario", "Evento", "CSeq", "Origem", "Porta", "Destino", "Porta"], timeline_rows)}
  <h2>Respostas SIP</h2>
  {html_table(["Frame", "Horario", "Status", "Reason", "CSeq", "Origem", "Destino"], response_rows)}
  <h2>RTP Por Direcao</h2>
  {html_table(["Origem IP", "Origem porta", "Destino IP", "Destino porta", "Pacotes RTP", "Codec/Payload", "SSRC", "Perda max %", "Jitter max ms", "Delta max ms", "RTCP", "Pacotes RTCP"], direction_rows)}
  <h2>Avisos RTP</h2>
  {html_table(["Severidade", "Codigo", "Achado", "Evidencia"], warning_rows)}
  <h2>Streams RTP/RTCP</h2>
  {html_table(["Origem IP", "Origem porta", "Destino IP", "Destino porta", "Payload", "Codec", "Pacotes", "Perda %", "Jitter max ms"], stream_rows)}
  {ai_section}
"""


def write_reports(out_base: Path, payload: dict[str, Any]) -> dict[str, str]:
    json_path = out_base.with_name(out_base.name + "_report.json")
    html_path = out_base.with_name(out_base.name + "_report.html")
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    html_path.write_text(render_html(payload), encoding="utf-8")
    return {"report_json": str(json_path), "report_html": str(html_path)}


def render_html(payload: dict[str, Any]) -> str:
    call = payload.get("call", {})
    files = payload.get("files", [])
    artifacts = payload.get("artifacts", {})
    analysis = payload.get("analysis") if isinstance(payload.get("analysis"), dict) else {}
    facts = analysis.get("facts", {}) if isinstance(analysis, dict) else {}
    sip_facts = facts.get("sip", {}) if isinstance(facts, dict) else {}
    rtp_facts = facts.get("rtp", {}) if isinstance(facts, dict) else {}
    rtp_filter = payload.get("rtp_filter", {})
    performance = payload.get("performance", {})
    worker_plan = performance.get("worker_plan", {}) if isinstance(performance, dict) else {}
    timing = performance.get("timing_seconds", {}) if isinstance(performance, dict) else {}
    endpoints = rtp_filter.get("endpoints", []) if isinstance(rtp_filter, dict) else []
    notes = payload.get("notes", [])
    generated = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = "\n".join(
        f"<tr><td>{html.escape(item.get('role', ''))}</td><td>{html.escape(item.get('path', ''))}</td></tr>"
        for item in files
    )
    endpoint_rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(str(item.get('media', '')))}</td>"
        f"<td>{html.escape(str(item.get('ip', '')))}</td>"
        f"<td>{html.escape(str(item.get('rtp_port', '')))}</td>"
        f"<td>{html.escape(str(item.get('rtcp_port', '')))}</td>"
        f"<td>{html.escape(', '.join(str(v) for v in item.get('payloads', [])))}</td>"
        "</tr>"
        for item in endpoints
    )
    notes_html = "".join(f"<li>{html.escape(str(note))}</li>" for note in notes)
    filter_mode = str(rtp_filter.get("mode", "")) if isinstance(rtp_filter, dict) else ""
    json_payload = json.dumps(payload, ensure_ascii=False, indent=2)
    call_id = analysis_value(facts, "call_id") or call.get("call_id", "")
    pcap_path = analysis.get("pcap") if isinstance(analysis, dict) else ""
    status_text = (
        f"{sip_facts.get('status_code') or call.get('status_code', '')} "
        f"{sip_facts.get('reason_phrase') or call.get('reason_phrase', '')}"
    ).strip()
    duration = sip_facts.get("duration_seconds", call.get("duracao_seg", ""))
    return f"""<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <title>Relatorio SIP/RTP V2</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #1f2933; }}
    h1 {{ margin-bottom: 4px; }}
    h2 {{ color: #102a43; margin-top: 26px; }}
    .muted {{ color: #62748a; }}
    .warning {{ background: #fff7ed; border: 1px solid #fed7aa; padding: 10px; }}
    .verdict {{ border-left: 6px solid #3b82f6; padding: 14px 16px; margin: 12px 0 22px; background: #eff6ff; }}
    .verdict strong {{ display: block; font-size: 18px; margin-bottom: 6px; }}
    .verdict p {{ margin: 6px 0; }}
    .verdict-status {{ text-transform: uppercase; font-size: 12px; letter-spacing: .08em; color: #52606d; margin-bottom: 4px; }}
    .severity-high {{ border-color: #dc2626; background: #fef2f2; }}
    .severity-medium {{ border-color: #d97706; background: #fffbeb; }}
    .severity-low {{ border-color: #64748b; background: #f8fafc; }}
    .severity-info {{ border-color: #0284c7; background: #f0f9ff; }}
    .meta {{ display: grid; grid-template-columns: 180px 1fr; gap: 6px 14px; margin-top: 18px; }}
    table {{ border-collapse: collapse; width: 100%; margin: 12px 0 24px; }}
    th, td {{ border: 1px solid #d9e2ec; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #e6f6ff; }}
    code {{ background: #f0f4f8; padding: 2px 4px; }}
    pre {{ background: #f0f4f8; padding: 12px; white-space: pre-wrap; overflow-wrap: anywhere; }}
    details {{ margin-top: 18px; }}
  </style>
</head>
<body>
  <h1>Relatorio SIP/RTP V2</h1>
  <div class="muted">Gerado em {html.escape(generated)}</div>
  <div class="meta">
    <strong>Call-ID</strong><span>{html.escape(str(call_id))}</span>
    <strong>Arquivo</strong><span>{html.escape(str(pcap_path or artifacts.get('pcap', '')))}</span>
    <strong>Origem</strong><span>{html.escape(str(sip_facts.get('from_user') or call.get('from_user', '')))}</span>
    <strong>Destino</strong><span>{html.escape(str(sip_facts.get('to_user') or call.get('to_user', '')))}</span>
    <strong>Status SIP</strong><span>{html.escape(status_text)}</span>
    <strong>Duracao SIP</strong><span>{html.escape(str(duration))} s</span>
    <strong>Pacotes RTP/RTCP</strong><span>{html.escape(str(rtp_facts.get('total_packets', 0)))}</span>
  </div>
  {render_analysis_sections(payload)}
  <h2>Artefatos</h2>
  <p><strong>PCAP reduzido:</strong> {html.escape(str(artifacts.get('pcap', '')))}</p>
  <h2>Desempenho</h2>
  <div class="meta">
    <strong>Perfil</strong><span>{html.escape(str(worker_plan.get('profile_label', '')))}</span>
    <strong>Workers</strong><span>{html.escape(str(worker_plan.get('workers', '')))}</span>
    <strong>CPU logica</strong><span>{html.escape(str(worker_plan.get('cpu_count', '')))}</span>
    <strong>Arquivos candidatos</strong><span>{html.escape(str(worker_plan.get('candidate_count', '')))}</span>
    <strong>Recorte/filtro</strong><span>{html.escape(str(timing.get('slice_filter_seconds', '')))} s</span>
    <strong>Merge</strong><span>{html.escape(str(timing.get('merge_seconds', '')))} s</span>
    <strong>Analise</strong><span>{html.escape(str(timing.get('analysis_seconds', '')))} s</span>
    <strong>Total</strong><span>{html.escape(str(timing.get('total_seconds', '')))} s</span>
  </div>
  <h2>Filtro RTP</h2>
  <p><strong>Modo:</strong> {html.escape(filter_mode)}</p>
  <table>
    <thead><tr><th>Midia</th><th>IP SDP</th><th>Porta RTP</th><th>Porta RTCP</th><th>Payloads</th></tr></thead>
    <tbody>{endpoint_rows}</tbody>
  </table>
  <h2>Notas</h2>
  <ul>{notes_html}</ul>
  <h2>Arquivos usados</h2>
  <table>
    <thead><tr><th>Tipo</th><th>Arquivo</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <details>
    <summary>JSON estruturado</summary>
    <pre>{html.escape(json_payload)}</pre>
  </details>
</body>
</html>
"""
