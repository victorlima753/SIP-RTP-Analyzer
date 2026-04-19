use crate::pcap_reader::{LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL, LINKTYPE_RAW};
use crate::types::{SdpMedia, SipEvent};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use std::collections::BTreeMap;

const SIP_PREFIXES: &[&[u8]] = &[
    b"INVITE ",
    b"ACK ",
    b"BYE ",
    b"CANCEL ",
    b"OPTIONS ",
    b"REGISTER ",
    b"PRACK ",
    b"UPDATE ",
    b"INFO ",
    b"MESSAGE ",
    b"REFER ",
    b"NOTIFY ",
    b"SUBSCRIBE ",
    b"SIP/2.0 ",
];

pub(crate) fn decode_sip_packet(
    data: &[u8],
    linktype: u32,
    ts_epoch: f64,
    frame_number: i64,
) -> Option<SipEvent> {
    let sliced = match linktype {
        LINKTYPE_ETHERNET => SlicedPacket::from_ethernet(data).ok()?,
        LINKTYPE_LINUX_SLL => {
            let ip_payload = linux_sll_ip_payload(data)?;
            SlicedPacket::from_ip(ip_payload).ok()?
        }
        LINKTYPE_RAW => SlicedPacket::from_ip(data).ok()?,
        _ => return None,
    };
    let (src_ip, dst_ip) = match sliced.net? {
        NetSlice::Ipv4(ipv4) => (
            ipv4.header().source_addr().to_string(),
            ipv4.header().destination_addr().to_string(),
        ),
        NetSlice::Ipv6(ipv6) => (
            ipv6.header().source_addr().to_string(),
            ipv6.header().destination_addr().to_string(),
        ),
    };
    let (src_port, dst_port, payload) = match sliced.transport? {
        TransportSlice::Udp(udp) => (
            Some(udp.source_port() as i64),
            Some(udp.destination_port() as i64),
            udp.payload(),
        ),
        TransportSlice::Tcp(tcp) => (
            Some(tcp.source_port() as i64),
            Some(tcp.destination_port() as i64),
            tcp.payload(),
        ),
        _ => return None,
    };
    if !looks_like_sip_bytes(payload) {
        return None;
    }
    let text = std::str::from_utf8(payload).ok()?;
    parse_sip(
        text,
        ts_epoch,
        frame_number,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
    )
}

fn linux_sll_ip_payload(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 16 {
        return None;
    }
    let protocol = u16::from_be_bytes([data[14], data[15]]);
    match protocol {
        0x0800 | 0x86dd => Some(&data[16..]),
        _ => None,
    }
}

pub(crate) fn looks_like_sip_bytes(payload: &[u8]) -> bool {
    SIP_PREFIXES
        .iter()
        .any(|prefix| payload.starts_with(prefix))
}

pub(crate) fn parse_sip(
    text: &str,
    ts_epoch: f64,
    frame_number: i64,
    src_ip: String,
    dst_ip: String,
    src_port: Option<i64>,
    dst_port: Option<i64>,
) -> Option<SipEvent> {
    let (head, body) = split_sip_head_body(text);
    let mut lines = head.lines();
    let first = lines.next()?.trim_end_matches('\r').trim().to_string();
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    for line in lines {
        let clean = line.trim_end_matches('\r');
        if let Some((name, value)) = clean.split_once(':') {
            headers.insert(header_name(name), value.trim().to_string());
        }
    }
    let call_id = header(&headers, "call-id")?;
    let mut method = String::new();
    let mut status_code = None;
    let mut reason_phrase = String::new();
    let mut request_uri_user = String::new();
    if first.starts_with("SIP/2.0") {
        let mut parts = first.splitn(3, ' ');
        let _ = parts.next();
        status_code = parts.next().and_then(|v| v.parse::<i64>().ok());
        reason_phrase = parts.next().unwrap_or("").trim().to_string();
    } else {
        let mut parts = first.split_whitespace();
        method = parts.next().unwrap_or("").to_ascii_uppercase();
        request_uri_user = extract_user(parts.next().unwrap_or(""));
    }
    let cseq_method = header(&headers, "cseq")
        .and_then(|value| {
            value
                .split_whitespace()
                .last()
                .map(|v| v.to_ascii_uppercase())
        })
        .unwrap_or_default();
    Some(SipEvent {
        call_id,
        frame_number,
        ts_epoch,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        method,
        status_code,
        reason_phrase,
        cseq_method,
        from_user: header(&headers, "from")
            .map(|v| extract_user(&v))
            .unwrap_or_default(),
        to_user: header(&headers, "to")
            .map(|v| extract_user(&v))
            .unwrap_or_default(),
        request_uri_user,
        contact_user: header(&headers, "contact")
            .map(|v| extract_user(&v))
            .unwrap_or_default(),
        pai_user: header(&headers, "p-asserted-identity")
            .map(|v| extract_user(&v))
            .unwrap_or_default(),
        sdp_media: parse_sdp(body, frame_number, ts_epoch),
    })
}

fn split_sip_head_body(text: &str) -> (&str, &str) {
    if let Some(pos) = text.find("\r\n\r\n") {
        return (&text[..pos], &text[pos + 4..]);
    }
    if let Some(pos) = text.find("\n\n") {
        return (&text[..pos], &text[pos + 2..]);
    }
    (text, "")
}

fn header_name(name: &str) -> String {
    match name.trim().to_ascii_lowercase().as_str() {
        "f" => "from".to_string(),
        "t" => "to".to_string(),
        "i" => "call-id".to_string(),
        "m" => "contact".to_string(),
        "l" => "content-length".to_string(),
        "c" => "content-type".to_string(),
        other => other.to_string(),
    }
}

fn header(headers: &BTreeMap<String, String>, name: &str) -> Option<String> {
    headers.get(name).cloned()
}

fn extract_user(value: &str) -> String {
    let target = value.split(';').next().unwrap_or(value);
    if let Some(pos) = target.find("sip:").or_else(|| target.find("sips:")) {
        let rest = &target[pos
            + if target[pos..].starts_with("sips:") {
                5
            } else {
                4
            }..];
        let user = rest.split('@').next().unwrap_or(rest);
        return user
            .trim_matches(|c: char| c == '<' || c == '>' || c == '"' || c.is_whitespace())
            .to_string();
    }
    normalize_number(target)
}

pub(crate) fn normalize_number(value: &str) -> String {
    value.chars().filter(|ch| ch.is_ascii_digit()).collect()
}

pub(crate) fn parse_sdp(body: &str, frame_number: i64, ts_epoch: f64) -> Vec<SdpMedia> {
    if body.is_empty() {
        return Vec::new();
    }
    let mut session_ip = String::new();
    let mut current: Option<SdpMedia> = None;
    let mut result = Vec::new();
    for line in body.lines().map(|v| v.trim_end_matches('\r').trim()) {
        if let Some(rest) = line.strip_prefix("c=") {
            if let Some(ip) = rest.split_whitespace().last() {
                if let Some(item) = current.as_mut() {
                    item.ip = ip.to_string();
                } else {
                    session_ip = ip.to_string();
                }
            }
        } else if let Some(rest) = line.strip_prefix("m=") {
            if let Some(item) = current.take() {
                result.push(item);
            }
            let parts: Vec<&str> = rest.split_whitespace().collect();
            current = Some(SdpMedia {
                frame_number,
                ts_epoch,
                media: parts.first().unwrap_or(&"").to_string(),
                port: parts.get(1).and_then(|v| v.parse::<i64>().ok()),
                payloads: parts.iter().skip(3).map(|v| v.to_string()).collect(),
                ip: session_ip.clone(),
                attributes: Vec::new(),
            });
        } else if let Some(rest) = line.strip_prefix("a=") {
            if let Some(item) = current.as_mut() {
                item.attributes.push(rest.to_string());
            }
        }
    }
    if let Some(item) = current.take() {
        result.push(item);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_brazilian_number() {
        assert_eq!(normalize_number("+55 (12) 98883-9274"), "5512988839274");
    }

    #[test]
    fn accepts_compact_sip_headers() {
        let text = concat!(
            "INVITE sip:2000@10.0.0.1 SIP/2.0\r\n",
            "i: abc@test\r\n",
            "f: <sip:1000@10.0.0.2>\r\n",
            "t: <sip:2000@10.0.0.1>\r\n",
            "m: <sip:1000@10.0.0.2>\r\n",
            "CSeq: 1 INVITE\r\n\r\n"
        );
        let event = parse_sip(
            text,
            1.0,
            10,
            "1.1.1.1".to_string(),
            "2.2.2.2".to_string(),
            Some(5060),
            Some(5060),
        )
        .unwrap();
        assert_eq!(event.call_id, "abc@test");
        assert_eq!(event.from_user, "1000");
        assert_eq!(event.to_user, "2000");
        assert_eq!(event.contact_user, "1000");
    }

    #[test]
    fn parses_sdp_audio_media() {
        let body = concat!(
            "v=0\r\n",
            "c=IN IP4 177.53.16.42\r\n",
            "m=audio 40000 RTP/AVP 0 8\r\n",
            "a=rtpmap:8 PCMA/8000\r\n"
        );
        let media = parse_sdp(body, 12, 123.0);
        assert_eq!(media.len(), 1);
        assert_eq!(media[0].ip, "177.53.16.42");
        assert_eq!(media[0].port, Some(40000));
        assert_eq!(media[0].payloads, vec!["0".to_string(), "8".to_string()]);
    }

    #[test]
    fn checks_sip_prefix_before_utf8() {
        assert!(looks_like_sip_bytes(b"SIP/2.0 200 OK\r\n"));
        assert!(!looks_like_sip_bytes(b"\xff\xff\xff"));
    }
}
