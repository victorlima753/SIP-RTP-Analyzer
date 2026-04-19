use crate::sip_parser::normalize_number;
use crate::types::{CallAcc, SipEvent};
use std::collections::BTreeMap;

pub(crate) fn merge_call(calls: &mut BTreeMap<String, CallAcc>, other: CallAcc) {
    let target = calls
        .entry(other.call_id.clone())
        .or_insert_with(|| CallAcc {
            call_id: other.call_id.clone(),
            ..CallAcc::default()
        });
    if let Some(value) = other.first_epoch {
        if target.first_epoch.map_or(true, |current| value < current) {
            target.first_epoch = Some(value);
            target.first_frame = other.first_frame;
        }
    }
    if let Some(value) = other.last_epoch {
        if target.last_epoch.map_or(true, |current| value > current) {
            target.last_epoch = Some(value);
            target.last_frame = other.last_frame;
        }
    }
    if target.from_user.is_empty() {
        target.from_user = other.from_user;
    }
    if target.to_user.is_empty() {
        target.to_user = other.to_user;
    }
    if target.request_uri_user.is_empty() {
        target.request_uri_user = other.request_uri_user;
    }
    if target.contact_user.is_empty() {
        target.contact_user = other.contact_user;
    }
    if target.pai_user.is_empty() {
        target.pai_user = other.pai_user;
    }
    target.normalized_numbers.extend(other.normalized_numbers);
    target.methods.extend(other.methods);
    if other.status_priority >= target.status_priority {
        target.status_priority = other.status_priority;
        target.status_code = other.status_code;
        target.reason_phrase = other.reason_phrase;
    }
    target.src_ips.extend(other.src_ips);
    target.dst_ips.extend(other.dst_ips);
    target.sip_ports.extend(other.sip_ports);
    target.packet_count += other.packet_count;
    target.completed |= other.completed;
    target.has_invite |= other.has_invite;
    target.has_ack |= other.has_ack;
    target.has_bye |= other.has_bye;
    target.has_cancel |= other.has_cancel;
    target.sdp_media.extend(other.sdp_media);
}

impl CallAcc {
    pub(crate) fn update(&mut self, event: SipEvent) {
        if self.first_epoch.map_or(true, |v| event.ts_epoch < v) {
            self.first_epoch = Some(event.ts_epoch);
            self.first_frame = event.frame_number;
        }
        if self.last_epoch.map_or(true, |v| event.ts_epoch > v) {
            self.last_epoch = Some(event.ts_epoch);
            self.last_frame = event.frame_number;
        }
        if self.from_user.is_empty() {
            self.from_user = event.from_user.clone();
        }
        if self.to_user.is_empty() {
            self.to_user = event.to_user.clone();
        }
        if self.request_uri_user.is_empty() {
            self.request_uri_user = event.request_uri_user.clone();
        }
        if self.contact_user.is_empty() {
            self.contact_user = event.contact_user.clone();
        }
        if self.pai_user.is_empty() {
            self.pai_user = event.pai_user.clone();
        }
        let method = if !event.method.is_empty() {
            event.method.clone()
        } else {
            event.cseq_method.clone()
        };
        if !method.is_empty() {
            self.methods.insert(method.clone());
        }
        self.has_invite |= method == "INVITE" || event.cseq_method == "INVITE";
        self.has_ack |= method == "ACK" || event.cseq_method == "ACK";
        self.has_bye |= method == "BYE" || event.cseq_method == "BYE";
        self.has_cancel |= method == "CANCEL" || event.cseq_method == "CANCEL";
        self.completed |= event.status_code == Some(200) && event.cseq_method == "INVITE";
        for value in [
            &event.from_user,
            &event.to_user,
            &event.request_uri_user,
            &event.contact_user,
            &event.pai_user,
        ] {
            let n = normalize_number(value);
            if !n.is_empty() {
                self.normalized_numbers.insert(n);
            }
        }
        if let Some(status) = event.status_code {
            let priority = if status >= 200 && event.cseq_method == "INVITE" {
                3
            } else if status >= 200 {
                2
            } else {
                1
            };
            let key = (priority, (event.ts_epoch * 1000.0) as i64);
            if key >= self.status_priority {
                self.status_priority = key;
                self.status_code = Some(status);
                self.reason_phrase = event.reason_phrase.clone();
            }
        }
        if !event.src_ip.is_empty() {
            self.src_ips.insert(event.src_ip);
        }
        if !event.dst_ip.is_empty() {
            self.dst_ips.insert(event.dst_ip);
        }
        if let Some(port) = event.src_port {
            self.sip_ports.insert(port);
        }
        if let Some(port) = event.dst_port {
            self.sip_ports.insert(port);
        }
        self.packet_count += 1;
        self.sdp_media.extend(event.sdp_media);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(call_id: &str, frame: i64, epoch: f64, status: Option<i64>) -> SipEvent {
        SipEvent {
            call_id: call_id.to_string(),
            frame_number: frame,
            ts_epoch: epoch,
            src_ip: "1.1.1.1".to_string(),
            dst_ip: "2.2.2.2".to_string(),
            src_port: Some(5060),
            dst_port: Some(5060),
            method: if status.is_some() {
                String::new()
            } else {
                "INVITE".to_string()
            },
            status_code: status,
            reason_phrase: if status == Some(200) {
                "OK".to_string()
            } else {
                String::new()
            },
            cseq_method: "INVITE".to_string(),
            from_user: "5511999999999".to_string(),
            to_user: "2000".to_string(),
            request_uri_user: "2000".to_string(),
            contact_user: String::new(),
            pai_user: String::new(),
            sdp_media: Vec::new(),
        }
    }

    #[test]
    fn aggregates_by_call_id() {
        let mut calls = BTreeMap::new();
        let mut first = CallAcc {
            call_id: "call-a".to_string(),
            ..CallAcc::default()
        };
        first.update(event("call-a", 1, 10.0, None));
        let mut second = CallAcc {
            call_id: "call-a".to_string(),
            ..CallAcc::default()
        };
        second.update(event("call-a", 2, 11.0, Some(200)));
        merge_call(&mut calls, first);
        merge_call(&mut calls, second);
        let acc = calls.get("call-a").unwrap();
        assert_eq!(acc.first_frame, 1);
        assert_eq!(acc.last_frame, 2);
        assert_eq!(acc.status_code, Some(200));
        assert!(acc.normalized_numbers.contains("5511999999999"));
    }
}
