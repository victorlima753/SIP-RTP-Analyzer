from __future__ import annotations

import unittest
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import siprtp_v2_report as report


class V2ReportTests(unittest.TestCase):
    def test_render_html_includes_sip_rtp_analysis_sections(self) -> None:
        html = report.render_html(
            {
                "call": {"call_id": "abc@10.0.0.1", "from_user": "1000", "to_user": "2000"},
                "artifacts": {"pcap": r"C:\tmp\call.pcapng"},
                "files": [{"role": "sip", "path": r"C:\tmp\sip.pcap"}],
                "analysis": {
                    "pcap": r"C:\tmp\call.pcapng",
                    "facts": {
                        "call_id": "abc@10.0.0.1",
                        "sip": {
                            "from_user": "1000",
                            "to_user": "2000",
                            "status_code": 200,
                            "reason_phrase": "OK",
                            "duration_seconds": 11.3,
                            "timeline": [
                                {
                                    "frame": 1,
                                    "time": "2026-04-19 10:00:00",
                                    "event": "INVITE",
                                    "cseq_method": "INVITE",
                                    "src": "10.0.0.1",
                                    "src_port": 5060,
                                    "dst": "177.53.16.6",
                                    "dst_port": 5060,
                                },
                                {
                                    "frame": 10,
                                    "time": "2026-04-19 10:00:02",
                                    "event": "200 OK",
                                    "cseq_method": "INVITE",
                                    "src": "177.53.16.6",
                                    "src_port": 5060,
                                    "dst": "10.0.0.1",
                                    "dst_port": 5060,
                                },
                            ],
                            "responses": [
                                {
                                    "frame": 10,
                                    "time": "2026-04-19 10:00:00",
                                    "status_code": 200,
                                    "reason_phrase": "OK",
                                    "cseq_method": "INVITE",
                                    "src": "177.53.16.6",
                                    "dst": "10.0.0.1",
                                }
                            ],
                        },
                        "rtp": {
                            "total_packets": 42,
                            "streams": [
                                {
                                    "src_ip": "177.53.16.42",
                                    "src_port": 40000,
                                    "dst_ip": "10.0.0.1",
                                    "dst_port": 20000,
                                    "payload_type": "8",
                                    "payload_name": "PCMA",
                                    "packets": 42,
                                    "loss_percent_by_seq": 0,
                                    "jitter_max_ms": 2.5,
                                }
                            ],
                            "directions": [
                                {
                                    "src_ip": "177.53.16.42",
                                    "src_port": 40000,
                                    "dst_ip": "10.0.0.1",
                                    "dst_port": 20000,
                                    "packets": 42,
                                    "payload_types": ["8"],
                                    "payload_names": ["PCMA"],
                                    "ssrcs": ["0x1234"],
                                    "loss_percent_max": 0,
                                    "jitter_max_ms": 2.5,
                                    "delta_max_ms": 20,
                                    "has_rtcp": False,
                                    "rtcp_packets": 0,
                                }
                            ],
                            "warnings": [
                                {
                                    "severity": "baixa",
                                    "code": "missing_rtcp",
                                    "title": "RTCP ausente",
                                    "evidence": "Sem RTCP observado.",
                                }
                            ],
                        },
                        "verdict": {
                            "status": "completed_with_media",
                            "severity": "info",
                            "title": "Chamada completada com midia",
                            "summary": "SIP completou e ha RTP.",
                            "evidence": "RTP bidirecional observado.",
                        },
                    },
                    "diagnosis": {
                        "findings": [
                            {
                                "severity": "info",
                                "title": "SIP completou a sinalizacao da chamada",
                                "evidence": "Foi observada resposta 200 OK relacionada a chamada.",
                                "recommendation": "Correlacionar com RTP.",
                            }
                        ]
                    },
                },
                "rtp_filter": {"mode": "sdp", "endpoints": []},
                "notes": [],
            }
        )

        self.assertIn("Diagnostico", html)
        self.assertIn("Veredito Operacional", html)
        self.assertIn("Chamada completada com midia", html)
        self.assertIn("Timeline SIP", html)
        self.assertIn("RTP Por Direcao", html)
        self.assertIn("Avisos RTP", html)
        self.assertIn("SIP completou a sinalizacao da chamada", html)
        self.assertIn("Respostas SIP", html)
        self.assertIn("Streams RTP/RTCP", html)
        self.assertIn("PCMA", html)
        self.assertIn("Arquivos usados", html)


if __name__ == "__main__":
    unittest.main()
