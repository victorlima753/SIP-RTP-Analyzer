use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

#[derive(Default, Clone, Debug, PartialEq)]
pub(crate) struct SdpMedia {
    pub(crate) frame_number: i64,
    pub(crate) ts_epoch: f64,
    pub(crate) media: String,
    pub(crate) ip: String,
    pub(crate) port: Option<i64>,
    pub(crate) payloads: Vec<String>,
    pub(crate) attributes: Vec<String>,
}

#[derive(Default, Clone, Debug)]
pub(crate) struct CallAcc {
    pub(crate) call_id: String,
    pub(crate) first_epoch: Option<f64>,
    pub(crate) last_epoch: Option<f64>,
    pub(crate) first_frame: i64,
    pub(crate) last_frame: i64,
    pub(crate) from_user: String,
    pub(crate) to_user: String,
    pub(crate) request_uri_user: String,
    pub(crate) contact_user: String,
    pub(crate) pai_user: String,
    pub(crate) normalized_numbers: BTreeSet<String>,
    pub(crate) methods: BTreeSet<String>,
    pub(crate) status_code: Option<i64>,
    pub(crate) reason_phrase: String,
    pub(crate) status_priority: (i64, i64),
    pub(crate) src_ips: BTreeSet<String>,
    pub(crate) dst_ips: BTreeSet<String>,
    pub(crate) sip_ports: BTreeSet<i64>,
    pub(crate) packet_count: i64,
    pub(crate) completed: bool,
    pub(crate) has_invite: bool,
    pub(crate) has_ack: bool,
    pub(crate) has_bye: bool,
    pub(crate) has_cancel: bool,
    pub(crate) sdp_media: Vec<SdpMedia>,
}

#[derive(Debug)]
pub(crate) struct SipEvent {
    pub(crate) call_id: String,
    pub(crate) frame_number: i64,
    pub(crate) ts_epoch: f64,
    pub(crate) src_ip: String,
    pub(crate) dst_ip: String,
    pub(crate) src_port: Option<i64>,
    pub(crate) dst_port: Option<i64>,
    pub(crate) method: String,
    pub(crate) status_code: Option<i64>,
    pub(crate) reason_phrase: String,
    pub(crate) cseq_method: String,
    pub(crate) from_user: String,
    pub(crate) to_user: String,
    pub(crate) request_uri_user: String,
    pub(crate) contact_user: String,
    pub(crate) pai_user: String,
    pub(crate) sdp_media: Vec<SdpMedia>,
}

#[derive(Default, Clone, Debug)]
pub(crate) struct CaptureStats {
    pub(crate) first_epoch: Option<f64>,
    pub(crate) last_epoch: Option<f64>,
    pub(crate) packet_count: u64,
    pub(crate) sip_events: u64,
    pub(crate) file_calls: BTreeSet<String>,
}

#[derive(Debug)]
pub(crate) struct WorkerPlan {
    pub(crate) profile: String,
    pub(crate) workers: usize,
    pub(crate) cpu_count: usize,
    pub(crate) memory_total_gb: Option<f64>,
}

#[derive(Debug)]
pub(crate) struct FileScanResult {
    pub(crate) index: usize,
    pub(crate) path: PathBuf,
    pub(crate) stats: CaptureStats,
    pub(crate) calls: BTreeMap<String, CallAcc>,
}
