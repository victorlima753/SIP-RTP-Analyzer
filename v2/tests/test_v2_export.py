from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import siprtp_v2_export as export
from app import siprtp_v2_performance as performance


class V2ExportTests(unittest.TestCase):
    def test_build_rtp_filter_from_sdp_audio_endpoints(self) -> None:
        endpoints = export.build_rtp_endpoints(
            [
                {
                    "media": "audio",
                    "ip": "177.53.16.42",
                    "port": 20000,
                    "payloads": ["0", "8"],
                    "attributes": ["rtpmap:0 PCMU/8000"],
                },
                {
                    "media": "audio",
                    "ip": "10.0.0.10",
                    "port": 30000,
                    "payloads": ["8"],
                    "attributes": ["rtcp:30005 IN IP4 10.0.0.10"],
                },
            ]
        )

        display_filter = export.build_rtp_display_filter(endpoints)

        self.assertIn("ip.addr == 177.53.16.42", display_filter)
        self.assertIn("udp.port == 20000", display_filter)
        self.assertIn("udp.port == 20001", display_filter)
        self.assertIn("ip.addr == 10.0.0.10", display_filter)
        self.assertIn("udp.port == 30000", display_filter)
        self.assertIn("udp.port == 30005", display_filter)

    def test_build_rtp_endpoints_prefers_audio_media(self) -> None:
        endpoints = export.build_rtp_endpoints(
            [
                {"media": "image", "ip": "177.53.16.42", "port": 40000, "payloads": [], "attributes": []},
                {"media": "audio", "ip": "177.53.16.42", "port": 20000, "payloads": ["0"], "attributes": []},
            ]
        )

        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0]["media"], "audio")
        self.assertEqual(endpoints[0]["rtp_port"], 20000)

    def test_display_string_escapes_call_id(self) -> None:
        self.assertEqual(export.display_string('a"b\\c'), '"a\\"b\\\\c"')

    def test_parallel_export_preserves_merge_order(self) -> None:
        tmp = ROOT / "tmp_export_order"
        tmp.mkdir(exist_ok=True)
        try:
            items = [
                export.ExportWorkItem(1, "sip", tmp / "sip.pcap", tmp / "1s.pcapng", tmp / "1f.pcapng", "sip"),
                export.ExportWorkItem(2, "rtp", tmp / "rtp2.pcap", tmp / "2s.pcapng", tmp / "2f.pcapng", "rtp"),
                export.ExportWorkItem(3, "rtp", tmp / "rtp3.pcap", tmp / "3s.pcapng", tmp / "3f.pcapng", "rtp"),
            ]
            plan = performance.WorkerPlan(
                profile="turbo",
                profile_label="Turbo",
                workers=3,
                auto_workers=True,
                cpu_count=8,
                candidate_count=3,
                memory_total_gb=16,
                memory_available_gb=8,
            )

            def fake_process(item, *_args, **_kwargs):
                return export.ExportWorkResult(item.index, item.role, item.src, item.filtered)

            with mock.patch.object(export, "process_export_item", side_effect=fake_process):
                produced = export.run_export_work_items(items, "editcap", "tshark", 1.0, 2.0, plan)

            self.assertEqual([path.name for path in produced], ["1f.pcapng", "2f.pcapng", "3f.pcapng"])
        finally:
            for child in tmp.glob("*"):
                child.unlink(missing_ok=True)
            tmp.rmdir()

    def test_export_worker_failure_has_clear_message(self) -> None:
        item = export.ExportWorkItem(1, "rtp", Path("bad.pcap"), Path("s.pcapng"), Path("f.pcapng"), "rtp")
        plan = performance.WorkerPlan("turbo", "Turbo", 2, True, 8, 1, 16, 8)

        with mock.patch.object(export, "process_export_item", side_effect=RuntimeError("boom")):
            with self.assertRaisesRegex(RuntimeError, "Falha ao exportar rtp"):
                export.run_export_work_items([item], "editcap", "tshark", 1.0, 2.0, plan)


if __name__ == "__main__":
    unittest.main()
