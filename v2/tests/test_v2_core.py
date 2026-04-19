from __future__ import annotations

import shutil
import unittest
import uuid
from pathlib import Path
from unittest import mock

import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import siprtp_v2_core as core


class V2CoreTests(unittest.TestCase):
    def test_iter_capture_files_accepts_tcpdump_rotation_names(self) -> None:
        tmp_path = ROOT / f"tmp_core_{uuid.uuid4().hex}"
        tmp_path.mkdir(parents=True)
        try:
            for name in ["base.pcap", "base.pcap1", "base.pcap27", "trace.cap3", "trace.pcapng2"]:
                (tmp_path / name).write_bytes(b"pcap")
            (tmp_path / "capturas.siprtp.v2.sqlite").write_bytes(b"sqlite")
            (tmp_path / "notes.txt").write_text("ignore", encoding="utf-8")

            names = [path.name for path in core.iter_capture_files(tmp_path)]

            self.assertEqual(names, ["base.pcap", "base.pcap1", "base.pcap27", "trace.cap3", "trace.pcapng2"])
        finally:
            shutil.rmtree(tmp_path, ignore_errors=True)

    def test_locate_fast_indexer_checks_executable_directory(self) -> None:
        tmp_path = ROOT / f"tmp_core_{uuid.uuid4().hex}"
        tmp_path.mkdir(parents=True)
        try:
            fake_gui = tmp_path / "SIPRTPAnalyzerV2.exe"
            fake_gui.write_bytes(b"gui")
            indexer = tmp_path / "siprtp_fast_indexer.exe"
            indexer.write_bytes(b"indexer")

            with mock.patch.object(core.sys, "executable", str(fake_gui)):
                self.assertEqual(core.locate_fast_indexer(), indexer)
        finally:
            shutil.rmtree(tmp_path, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
