from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import siprtp_ai


CALL_ID = "call@test"


def sip_event(
    frame: int,
    epoch: float,
    method: str = "",
    status_code: int | None = None,
    reason: str = "",
    cseq: str = "INVITE",
    sdp_ip: str = "177.53.16.42",
    sdp_payload: str = "8",
) -> siprtp_ai.SipEvent:
    sdp = []
    if status_code == 200 and cseq == "INVITE":
        sdp = [
            siprtp_ai.SdpMedia(
                ip=sdp_ip,
                port=40000,
                media="audio",
                payloads=[sdp_payload],
                attributes=[],
                frame_number=frame,
            )
        ]
    return siprtp_ai.SipEvent(
        call_id=CALL_ID,
        frame_number=frame,
        ts_epoch=epoch,
        src_ip="177.53.16.6" if status_code else "168.138.154.175",
        dst_ip="168.138.154.175" if status_code else "177.53.16.6",
        src_port=5060,
        dst_port=5060,
        method=method,
        status_code=status_code,
        reason_phrase=reason,
        cseq_method=cseq,
        from_user="1000",
        to_user="2000",
        request_uri_user="2000",
        contact_user="1000",
        raw_headers="",
        pai_user="",
        sdp_media=sdp,
    )


def rtp_packet(
    frame: int,
    epoch: float,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    seq: int,
    payload: str = "8",
    ssrc: str = "0x1111",
) -> siprtp_ai.RtpPacket:
    return siprtp_ai.RtpPacket(
        frame_number=frame,
        ts_epoch=epoch,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        ssrc=ssrc,
        seq=seq,
        payload_type=payload,
        jitter_ms=2.0,
        delta_ms=20.0,
        lost_segment="",
        is_rtcp=False,
    )


def completed_events(sdp_ip: str = "177.53.16.42", sdp_payload: str = "8") -> list[siprtp_ai.SipEvent]:
    return [
        sip_event(1, 1000.0, method="INVITE"),
        sip_event(2, 1001.0, status_code=200, reason="OK", cseq="INVITE", sdp_ip=sdp_ip, sdp_payload=sdp_payload),
        sip_event(3, 1001.2, method="ACK", cseq="ACK"),
    ]


def facts(events: list[siprtp_ai.SipEvent], packets: list[siprtp_ai.RtpPacket]) -> dict[str, object]:
    rtp_summary = siprtp_ai.summarize_rtp(packets)
    return siprtp_ai.facts_from_events_and_rtp(CALL_ID, events, rtp_summary)


class V2DiagnosticsTests(unittest.TestCase):
    def test_completed_with_bidirectional_media_verdict(self) -> None:
        packets = [
            rtp_packet(10, 1002.0, "177.53.16.42", 40000, "168.138.154.175", 20000, 1),
            rtp_packet(11, 1002.1, "168.138.154.175", 20000, "177.53.16.42", 40000, 1, ssrc="0x2222"),
        ]
        result = facts(completed_events(), packets)
        self.assertEqual(result["verdict"]["status"], "completed_with_media")
        self.assertEqual(len(result["sip"]["timeline"]), 3)
        self.assertEqual(len(result["rtp"]["directions"]), 2)

    def test_completed_without_rtp_verdict(self) -> None:
        result = facts(completed_events(), [])
        self.assertEqual(result["verdict"]["status"], "completed_no_media")
        self.assertEqual(result["rtp"]["warnings"][0]["code"], "no_rtp")

    def test_completed_with_one_way_audio_verdict(self) -> None:
        packets = [rtp_packet(10, 1002.0, "177.53.16.42", 40000, "168.138.154.175", 20000, 1)]
        result = facts(completed_events(), packets)
        self.assertEqual(result["verdict"]["status"], "one_way_audio")
        self.assertTrue(any(item["code"] == "one_way_audio" for item in result["rtp"]["warnings"]))

    def test_failed_sip_verdict(self) -> None:
        events = [
            sip_event(1, 1000.0, method="INVITE"),
            sip_event(2, 1001.0, status_code=486, reason="Busy Here", cseq="INVITE"),
        ]
        result = facts(events, [])
        self.assertEqual(result["verdict"]["status"], "failed")

    def test_private_sdp_verdict(self) -> None:
        packets = [
            rtp_packet(10, 1002.0, "10.0.0.85", 40000, "168.138.154.175", 20000, 1),
            rtp_packet(11, 1002.1, "168.138.154.175", 20000, "10.0.0.85", 40000, 1, ssrc="0x2222"),
        ]
        result = facts(completed_events(sdp_ip="10.0.0.85"), packets)
        self.assertEqual(result["verdict"]["status"], "possible_nat_sdp")

    def test_payload_mismatch_verdict(self) -> None:
        packets = [
            rtp_packet(10, 1002.0, "177.53.16.42", 40000, "168.138.154.175", 20000, 1, payload="0"),
            rtp_packet(11, 1002.1, "168.138.154.175", 20000, "177.53.16.42", 40000, 1, payload="0", ssrc="0x2222"),
        ]
        result = facts(completed_events(sdp_payload="8"), packets)
        self.assertEqual(result["verdict"]["status"], "media_mismatch")


if __name__ == "__main__":
    unittest.main()
