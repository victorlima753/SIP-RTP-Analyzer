from __future__ import annotations

import json
import shutil
import sys
import unittest
import uuid
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import siprtp_v2_benchmark as benchmark


class V2BenchmarkTests(unittest.TestCase):
    def test_writes_json_and_csv_datalog(self) -> None:
        root = ROOT / f"tmp_benchmark_{uuid.uuid4().hex}"
        root.mkdir(parents=True)
        try:
            sip = root / "SIP"
            rtp = root / "RTP"
            sip.mkdir()
            rtp.mkdir()
            db_path = root / "capturas.sqlite"
            out_json = root / "bench.json"
            out_csv = root / "bench.csv"

            fake_result = {
                "db_path": str(db_path),
                "mode": "rust",
                "call_count": 12,
                "event_count": 120,
                "elapsed_seconds": 3.21,
                "workers": 2,
                "cpu_count": 4,
                "memory_total_gb": 8.0,
                "sip_file_count": 2,
                "rtp_file_count": 3,
                "sip_bytes": 1000,
                "rtp_bytes": 2000,
                "sip_scan_seconds": 2.0,
                "rtp_catalog_seconds": 0.5,
                "db_write_seconds": 0.2,
            }

            with mock.patch.object(benchmark.siprtp_v2_core, "index_folders", return_value=fake_result) as mocked:
                rows = benchmark.run_index_benchmark(
                    sip_dir=sip,
                    rtp_dir=rtp,
                    db_path=db_path,
                    performance_profile="balanced",
                    workers="auto",
                    out_json=out_json,
                    out_csv=out_csv,
                )

            mocked.assert_called_once()
            self.assertEqual(rows[0]["call_count"], 12)
            self.assertEqual(rows[0]["workers_used"], 2)
            self.assertTrue(out_json.exists())
            self.assertTrue(out_csv.exists())
            parsed = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(parsed[0]["event_count"], 120)
            self.assertIn("sip_scan_seconds", out_csv.read_text(encoding="utf-8"))
        finally:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
