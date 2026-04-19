from __future__ import annotations

import shutil
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace

import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import siprtp_v2_db as db


class V2DbTests(unittest.TestCase):
    def test_schema_insert_and_search(self) -> None:
        tmp_path = ROOT / f"tmp_test_{uuid.uuid4().hex}"
        tmp_path.mkdir(parents=True)
        try:
            tmp = str(tmp_path)
            db_path = Path(tmp) / "test.sqlite"
            with db.connect_db(db_path) as conn:
                db.init_db(conn)
                db.write_metadata(conn, {"engine": "test"})
                capture_set_id = db.create_capture_set(conn, Path(tmp) / "SIP", Path(tmp) / "RTP", {"test": True})
                pcap = Path(tmp) / "sip.pcap"
                pcap.write_bytes(b"pcap")
                file_id = db.insert_capture_file(conn, capture_set_id, "sip", pcap, 1770000000.0, 1770000030.0)
                summary = SimpleNamespace(
                    call_id="abc@1.2.3.4",
                    first_epoch=1770000001.0,
                    last_epoch=1770000025.0,
                    first_frame=1,
                    last_frame=9,
                    from_user="5511965116044",
                    to_user="5512988839274",
                    request_uri_user="",
                    contact_user="",
                    normalized_numbers="5511965116044 11965116044 5512988839274 12988839274",
                    methods=["INVITE", "ACK", "BYE"],
                    status_code=200,
                    reason_phrase="OK",
                    src_ips=["177.53.16.6"],
                    dst_ips=["10.0.0.1"],
                    sip_ports=[5060],
                    packet_count=9,
                    completed=True,
                    has_invite=True,
                    has_ack=True,
                    has_bye=True,
                    has_cancel=False,
                    sdp_media=[],
                )
                db.insert_call_summary(conn, summary)
                db.insert_call_file(conn, "abc@1.2.3.4", file_id, "sip", 1770000001.0, 1770000025.0)
                conn.commit()

            rows = db.find_calls(db_path, "11965116044", "1770000001", 10)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["call_id"], "abc@1.2.3.4")
            self.assertEqual(rows[0]["status_code"], 200)
        finally:
            shutil.rmtree(tmp_path, ignore_errors=True)

    def test_number_candidates(self) -> None:
        self.assertEqual(db.number_search_candidates("+55 (11) 96511-6044"), ["5511965116044", "11965116044", "1965116044"])


if __name__ == "__main__":
    unittest.main()
