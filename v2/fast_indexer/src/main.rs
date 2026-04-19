use clap::{Parser, Subcommand};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use rusqlite::{params, Connection};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Instant;

const SCHEMA_VERSION: i64 = 2;
const LINKTYPE_ETHERNET: u32 = 1;
const LINKTYPE_LINUX_SLL: u32 = 113;
const LINKTYPE_RAW: u32 = 101;

#[derive(Parser)]
#[command(name = "siprtp_fast_indexer")]
#[command(about = "Fast SIP/RTP folder indexer for SIP/RTP Analyzer V2")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    IndexFolders {
        #[arg(long)]
        sip_dir: PathBuf,
        #[arg(long)]
        rtp_dir: PathBuf,
        #[arg(long)]
        db: PathBuf,
        #[arg(long, default_value = "177.53.16.6,177.53.16.41")]
        sip_servers: String,
        #[arg(long, default_value = "177.53.16.42,177.53.16.43,177.53.16.45")]
        rtp_servers: String,
        #[arg(long)]
        force: bool,
        #[arg(long, default_value = "balanced")]
        performance: String,
        #[arg(long, default_value = "auto")]
        workers: String,
    },
}

#[derive(Serialize)]
struct Progress<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sip_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rtp_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    packets: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sip_events: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    calls: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    call_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    elapsed_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    db_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workers: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    active_workers: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    performance_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    memory_total_gb: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Default, Clone)]
struct SdpMedia {
    frame_number: i64,
    ts_epoch: f64,
    media: String,
    ip: String,
    port: Option<i64>,
    payloads: Vec<String>,
    attributes: Vec<String>,
}

#[derive(Default)]
struct CallAcc {
    call_id: String,
    first_epoch: Option<f64>,
    last_epoch: Option<f64>,
    first_frame: i64,
    last_frame: i64,
    from_user: String,
    to_user: String,
    request_uri_user: String,
    contact_user: String,
    pai_user: String,
    normalized_numbers: BTreeSet<String>,
    methods: BTreeSet<String>,
    status_code: Option<i64>,
    reason_phrase: String,
    status_priority: (i64, i64),
    src_ips: BTreeSet<String>,
    dst_ips: BTreeSet<String>,
    sip_ports: BTreeSet<i64>,
    packet_count: i64,
    completed: bool,
    has_invite: bool,
    has_ack: bool,
    has_bye: bool,
    has_cancel: bool,
    sdp_media: Vec<SdpMedia>,
}

struct SipEvent {
    call_id: String,
    frame_number: i64,
    ts_epoch: f64,
    src_ip: String,
    dst_ip: String,
    src_port: Option<i64>,
    dst_port: Option<i64>,
    method: String,
    status_code: Option<i64>,
    reason_phrase: String,
    cseq_method: String,
    from_user: String,
    to_user: String,
    request_uri_user: String,
    contact_user: String,
    pai_user: String,
    sdp_media: Vec<SdpMedia>,
}

struct CaptureStats {
    first_epoch: Option<f64>,
    last_epoch: Option<f64>,
    packet_count: u64,
    sip_events: u64,
    file_calls: BTreeSet<String>,
}

struct WorkerPlan {
    profile: String,
    workers: usize,
    cpu_count: usize,
    memory_total_gb: Option<f64>,
}

struct FileScanResult {
    index: usize,
    path: PathBuf,
    stats: CaptureStats,
    calls: BTreeMap<String, CallAcc>,
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::IndexFolders {
            sip_dir,
            rtp_dir,
            db,
            sip_servers,
            rtp_servers,
            force,
            performance,
            workers,
        } => index_folders(
            sip_dir,
            rtp_dir,
            db,
            split_servers(&sip_servers),
            split_servers(&rtp_servers),
            force,
            performance,
            workers,
        ),
    };
    if let Err(err) = result {
        emit(&Progress {
            kind: "error",
            code: Some("fatal"),
            message: Some(err.to_string()),
            ..empty_progress()
        });
        std::process::exit(1);
    }
}

fn empty_progress<'a>() -> Progress<'a> {
    Progress {
        kind: "log",
        role: None,
        index: None,
        total: None,
        path: None,
        sip_dir: None,
        rtp_dir: None,
        packets: None,
        sip_events: None,
        calls: None,
        call_count: None,
        elapsed_seconds: None,
        db_path: None,
        workers: None,
        active_workers: None,
        performance_profile: None,
        memory_total_gb: None,
        code: None,
        message: None,
    }
}

fn emit(payload: &Progress) {
    println!("{}", serde_json::to_string(payload).unwrap());
}

fn split_servers(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

fn normalize_profile(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "safe" | "seguro" => "safe".to_string(),
        "turbo" => "turbo".to_string(),
        _ => "balanced".to_string(),
    }
}

fn profile_factor(profile: &str) -> f64 {
    match profile {
        "safe" => 0.25,
        "turbo" => 0.70,
        _ => 0.45,
    }
}

fn memory_cap(profile: &str, total_gb: Option<f64>) -> Option<usize> {
    let total = total_gb?;
    let caps = match profile {
        "safe" => [1, 2, 4, 6],
        "turbo" => [3, 8, 12, 18],
        _ => [2, 5, 8, 12],
    };
    Some(if total <= 8.0 {
        caps[0]
    } else if total <= 16.0 {
        caps[1]
    } else if total <= 32.0 {
        caps[2]
    } else {
        caps[3]
    })
}

fn parse_worker_override(value: &str) -> Option<usize> {
    let clean = value.trim();
    if clean.is_empty() || clean.eq_ignore_ascii_case("auto") {
        return None;
    }
    clean.parse::<usize>().ok().filter(|value| *value > 0)
}

fn calculate_worker_plan(profile_value: &str, workers_value: &str, candidate_count: usize) -> WorkerPlan {
    let profile = normalize_profile(profile_value);
    let cpus = thread::available_parallelism().map(|value| value.get()).unwrap_or(4).max(1);
    let memory_total_gb = total_memory_gb();
    let candidates = candidate_count.max(1);
    let mut workers = if let Some(manual) = parse_worker_override(workers_value) {
        manual
    } else {
        let mut value = ((cpus as f64) * profile_factor(&profile)).round() as usize;
        value = value.max(1);
        if cpus > 1 {
            value = value.min(cpus - 1);
        }
        if let Some(cap) = memory_cap(&profile, memory_total_gb) {
            value = value.min(cap);
        }
        value
    };
    workers = workers.max(1).min(candidates);
    WorkerPlan {
        profile,
        workers,
        cpu_count: cpus,
        memory_total_gb,
    }
}

#[cfg(windows)]
#[repr(C)]
struct MemoryStatusEx {
    dw_length: u32,
    dw_memory_load: u32,
    ull_total_phys: u64,
    ull_avail_phys: u64,
    ull_total_page_file: u64,
    ull_avail_page_file: u64,
    ull_total_virtual: u64,
    ull_avail_virtual: u64,
    ull_avail_extended_virtual: u64,
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn GlobalMemoryStatusEx(buffer: *mut MemoryStatusEx) -> i32;
}

#[cfg(windows)]
fn total_memory_gb() -> Option<f64> {
    let mut status = MemoryStatusEx {
        dw_length: std::mem::size_of::<MemoryStatusEx>() as u32,
        dw_memory_load: 0,
        ull_total_phys: 0,
        ull_avail_phys: 0,
        ull_total_page_file: 0,
        ull_avail_page_file: 0,
        ull_total_virtual: 0,
        ull_avail_virtual: 0,
        ull_avail_extended_virtual: 0,
    };
    let ok = unsafe { GlobalMemoryStatusEx(&mut status as *mut MemoryStatusEx) };
    if ok == 0 {
        None
    } else {
        Some(((status.ull_total_phys as f64) / 1024.0 / 1024.0 / 1024.0 * 100.0).round() / 100.0)
    }
}

#[cfg(not(windows))]
fn total_memory_gb() -> Option<f64> {
    None
}

fn index_folders(
    sip_dir: PathBuf,
    rtp_dir: PathBuf,
    db_path: PathBuf,
    sip_servers: Vec<String>,
    rtp_servers: Vec<String>,
    force: bool,
    performance: String,
    workers: String,
) -> Result<(), Box<dyn std::error::Error>> {
    if db_path.exists() {
        if force {
            fs::remove_file(&db_path)?;
        } else {
            return Err(format!("Indice ja existe: {}", db_path.display()).into());
        }
    }
    let start = Instant::now();
    let sip_files = capture_files(&sip_dir)?;
    let rtp_files = capture_files(&rtp_dir)?;
    let worker_plan = calculate_worker_plan(&performance, &workers, (sip_files.len() + rtp_files.len()).max(1));
    emit(&Progress {
        kind: "start",
        sip_dir: Some(sip_dir.display().to_string()),
        rtp_dir: Some(rtp_dir.display().to_string()),
        workers: Some(worker_plan.workers),
        active_workers: Some(worker_plan.workers),
        performance_profile: Some(worker_plan.profile.clone()),
        memory_total_gb: worker_plan.memory_total_gb,
        ..empty_progress()
    });

    let conn = Connection::open(&db_path)?;
    init_db(&conn)?;
    let config = serde_json::json!({
        "sip_servers": sip_servers.clone(),
        "rtp_servers": rtp_servers.clone(),
        "engine": "rust",
        "performance": worker_plan.profile.clone(),
        "workers": worker_plan.workers,
        "cpu_count": worker_plan.cpu_count,
        "memory_total_gb": worker_plan.memory_total_gb
    });
    conn.execute(
        "INSERT INTO capture_sets(created_at, sip_dir, rtp_dir, config_json, schema_version) VALUES(datetime('now'), ?, ?, ?, ?)",
        params![sip_dir.display().to_string(), rtp_dir.display().to_string(), config.to_string(), SCHEMA_VERSION],
    )?;
    let capture_set_id = conn.last_insert_rowid();

    let mut calls: BTreeMap<String, CallAcc> = BTreeMap::new();
    let mut call_files: Vec<(String, i64, f64, f64)> = Vec::new();
    let mut total_sip_events = 0_u64;

    let sip_results = scan_files_parallel(&sip_files, "sip", true, worker_plan.workers, start)?;
    for result in sip_results {
        total_sip_events += result.stats.sip_events;
        for (_, acc) in result.calls {
            merge_call(&mut calls, acc);
        }
        let file_id = insert_capture_file(&conn, capture_set_id, "sip", &result.path, &result.stats, detect_server(&result.path, &sip_servers))?;
        for call_id in result.stats.file_calls {
            if let (Some(first), Some(last)) = (result.stats.first_epoch, result.stats.last_epoch) {
                call_files.push((call_id, file_id, first, last));
            }
        }
    }

    let rtp_results = scan_files_parallel(&rtp_files, "rtp", false, worker_plan.workers, start)?;
    for result in rtp_results {
        insert_capture_file(&conn, capture_set_id, "rtp", &result.path, &result.stats, detect_server(&result.path, &rtp_servers))?;
    }

    conn.execute_batch("BEGIN IMMEDIATE TRANSACTION")?;
    for acc in calls.values() {
        insert_call(&conn, acc)?;
        for item in &acc.sdp_media {
            insert_sdp_media(&conn, &acc.call_id, item)?;
        }
    }
    for (call_id, file_id, first, last) in call_files {
        conn.execute(
            "INSERT INTO call_files(call_id, file_id, role, first_epoch, last_epoch) VALUES(?, ?, 'sip', ?, ?)",
            params![call_id, file_id, first, last],
        )?;
    }
    conn.execute("INSERT OR REPLACE INTO metadata(key, value) VALUES('schema_version', ?)", params![SCHEMA_VERSION.to_string()])?;
    conn.execute("INSERT OR REPLACE INTO metadata(key, value) VALUES('engine', 'rust')", [])?;
    conn.execute_batch("COMMIT")?;

    emit(&Progress {
        kind: "done",
        call_count: Some(calls.len()),
        sip_events: Some(total_sip_events),
        elapsed_seconds: Some(start.elapsed().as_secs_f64()),
        db_path: Some(db_path.display().to_string()),
        workers: Some(worker_plan.workers),
        active_workers: Some(worker_plan.workers),
        performance_profile: Some(worker_plan.profile.clone()),
        memory_total_gb: worker_plan.memory_total_gb,
        ..empty_progress()
    });
    Ok(())
}

fn capture_files(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    visit(dir, &mut files)?;
    files.sort();
    Ok(files)
}

fn visit(dir: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            visit(&path, files)?;
        } else if is_capture_file(&path) {
            files.push(path);
        }
    }
    Ok(())
}

fn is_capture_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|v| v.to_str()).unwrap_or("").to_ascii_lowercase();
    name.contains(".pcap") || name.contains(".pcapng") || name.contains(".cap")
}

fn scan_files_parallel(
    files: &[PathBuf],
    role: &'static str,
    parse_sip: bool,
    workers: usize,
    started: Instant,
) -> Result<Vec<FileScanResult>, Box<dyn std::error::Error>> {
    if files.is_empty() {
        return Ok(Vec::new());
    }
    let worker_count = workers.max(1).min(files.len());
    let tasks = Arc::new(Mutex::new(
        files
            .iter()
            .cloned()
            .enumerate()
            .collect::<Vec<(usize, PathBuf)>>(),
    ));
    let (tx, rx) = mpsc::channel::<Result<FileScanResult, String>>();
    let total = files.len();
    let mut handles = Vec::new();
    for _ in 0..worker_count {
        let tasks = Arc::clone(&tasks);
        let tx = tx.clone();
        let handle = thread::spawn(move || loop {
            let next = {
                let mut guard = tasks.lock().unwrap();
                guard.pop()
            };
            let Some((idx, file)) = next else {
                break;
            };
            emit(&Progress {
                kind: "file_start",
                role: Some(role),
                index: Some(idx + 1),
                total: Some(total),
                path: Some(file.display().to_string()),
                active_workers: Some(worker_count),
                ..empty_progress()
            });
            let mut local_calls: BTreeMap<String, CallAcc> = BTreeMap::new();
            let mut local_sip_events = 0_u64;
            let result = scan_file(&file, parse_sip, &mut local_calls, &mut local_sip_events, started)
                .map(|stats| FileScanResult {
                    index: idx,
                    path: file.clone(),
                    stats,
                    calls: local_calls,
                })
                .map_err(|err| format!("{}: {}", file.display(), err));
            if let Ok(item) = &result {
                emit(&Progress {
                    kind: "file_done",
                    role: Some(role),
                    index: Some(idx + 1),
                    total: Some(total),
                    path: Some(file.display().to_string()),
                    packets: Some(item.stats.packet_count),
                    sip_events: if parse_sip { Some(item.stats.sip_events) } else { None },
                    calls: if parse_sip { Some(item.calls.len()) } else { None },
                    active_workers: Some(worker_count),
                    elapsed_seconds: Some(started.elapsed().as_secs_f64()),
                    ..empty_progress()
                });
            }
            if tx.send(result).is_err() {
                break;
            }
        });
        handles.push(handle);
    }
    drop(tx);
    let mut results = Vec::new();
    let mut first_error: Option<String> = None;
    for received in rx {
        match received {
            Ok(result) => results.push(result),
            Err(err) if first_error.is_none() => first_error = Some(err),
            Err(_) => {}
        }
    }
    for handle in handles {
        let _ = handle.join();
    }
    if let Some(err) = first_error {
        return Err(err.into());
    }
    results.sort_by_key(|item| item.index);
    Ok(results)
}

fn scan_file(
    path: &Path,
    parse_sip: bool,
    calls: &mut BTreeMap<String, CallAcc>,
    total_sip_events: &mut u64,
    started: Instant,
) -> Result<CaptureStats, Box<dyn std::error::Error>> {
    if path.extension().and_then(|v| v.to_str()).map(|v| v.eq_ignore_ascii_case("pcapng")).unwrap_or(false) {
        emit(&Progress {
            kind: "warning",
            path: Some(path.display().to_string()),
            code: Some("pcapng_initial_support"),
            message: Some("Esta versao inicial do motor Rust prioriza PCAP classico; use fallback TShark para PCAPNG se necessario.".to_string()),
            ..empty_progress()
        });
    }
    let mut reader = PcapReader::open(path)?;
    if !matches!(reader.linktype, LINKTYPE_ETHERNET | LINKTYPE_LINUX_SLL | LINKTYPE_RAW) {
        emit(&Progress {
            kind: "warning",
            path: Some(path.display().to_string()),
            code: Some("unsupported_linktype"),
            message: Some(format!("Linktype {} ainda nao tem decoder dedicado no motor Rust.", reader.linktype)),
            ..empty_progress()
        });
    }
    let mut stats = CaptureStats { first_epoch: None, last_epoch: None, packet_count: 0, sip_events: 0, file_calls: BTreeSet::new() };
    let mut frame_number = 0_i64;
    while let Some(packet) = reader.next_packet(parse_sip)? {
        frame_number += 1;
        stats.packet_count += 1;
        stats.first_epoch = Some(stats.first_epoch.map_or(packet.ts_epoch, |v| v.min(packet.ts_epoch)));
        stats.last_epoch = Some(stats.last_epoch.map_or(packet.ts_epoch, |v| v.max(packet.ts_epoch)));
        if parse_sip {
            if let Some(event) = decode_sip_packet(&packet.data, reader.linktype, packet.ts_epoch, frame_number) {
                stats.sip_events += 1;
                *total_sip_events += 1;
                stats.file_calls.insert(event.call_id.clone());
                let acc = calls.entry(event.call_id.clone()).or_insert_with(|| CallAcc { call_id: event.call_id.clone(), ..CallAcc::default() });
                acc.update(event);
                if *total_sip_events % 50000 == 0 {
                    emit(&Progress {
                        kind: "progress",
                        role: Some("sip"),
                        packets: Some(stats.packet_count),
                        sip_events: Some(*total_sip_events),
                        calls: Some(calls.len()),
                        elapsed_seconds: Some(started.elapsed().as_secs_f64()),
                        path: Some(path.display().to_string()),
                        ..empty_progress()
                    });
                }
            }
        }
    }
    Ok(stats)
}

struct PcapPacket {
    ts_epoch: f64,
    data: Vec<u8>,
}

struct PcapReader {
    file: File,
    swapped: bool,
    ns_resolution: bool,
    linktype: u32,
}

impl PcapReader {
    fn open(path: &Path) -> io::Result<Self> {
        let mut file = File::open(path)?;
        let mut header = [0_u8; 24];
        file.read_exact(&mut header)?;
        let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let (swapped, ns_resolution) = match magic {
            0xa1b2c3d4 => (false, false),
            0xd4c3b2a1 => (true, false),
            0xa1b23c4d => (false, true),
            0x4d3cb2a1 => (true, true),
            _ => (false, false),
        };
        let linktype = read_u32_with_order([header[20], header[21], header[22], header[23]], swapped);
        Ok(Self { file, swapped, ns_resolution, linktype })
    }

    fn read_u32(&self, bytes: [u8; 4]) -> u32 {
        if self.swapped { u32::from_be_bytes(bytes) } else { u32::from_le_bytes(bytes) }
    }

    fn next_packet(&mut self, read_payload: bool) -> io::Result<Option<PcapPacket>> {
        let mut header = [0_u8; 16];
        match self.file.read_exact(&mut header) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(err) => return Err(err),
        }
        let ts_sec = self.read_u32([header[0], header[1], header[2], header[3]]);
        let ts_frac = self.read_u32([header[4], header[5], header[6], header[7]]);
        let incl_len = self.read_u32([header[8], header[9], header[10], header[11]]) as usize;
        let mut data = Vec::new();
        if read_payload {
            data.resize(incl_len, 0_u8);
            self.file.read_exact(&mut data)?;
        } else {
            self.file.seek(SeekFrom::Current(incl_len as i64))?;
        }
        let divisor = if self.ns_resolution { 1_000_000_000.0 } else { 1_000_000.0 };
        Ok(Some(PcapPacket { ts_epoch: ts_sec as f64 + ts_frac as f64 / divisor, data }))
    }
}

fn read_u32_with_order(bytes: [u8; 4], swapped: bool) -> u32 {
    if swapped { u32::from_be_bytes(bytes) } else { u32::from_le_bytes(bytes) }
}

fn merge_call(calls: &mut BTreeMap<String, CallAcc>, other: CallAcc) {
    let target = calls
        .entry(other.call_id.clone())
        .or_insert_with(|| CallAcc { call_id: other.call_id.clone(), ..CallAcc::default() });
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
    if target.from_user.is_empty() { target.from_user = other.from_user; }
    if target.to_user.is_empty() { target.to_user = other.to_user; }
    if target.request_uri_user.is_empty() { target.request_uri_user = other.request_uri_user; }
    if target.contact_user.is_empty() { target.contact_user = other.contact_user; }
    if target.pai_user.is_empty() { target.pai_user = other.pai_user; }
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
    fn update(&mut self, event: SipEvent) {
        if self.first_epoch.map_or(true, |v| event.ts_epoch < v) {
            self.first_epoch = Some(event.ts_epoch);
            self.first_frame = event.frame_number;
        }
        if self.last_epoch.map_or(true, |v| event.ts_epoch > v) {
            self.last_epoch = Some(event.ts_epoch);
            self.last_frame = event.frame_number;
        }
        if self.from_user.is_empty() { self.from_user = event.from_user.clone(); }
        if self.to_user.is_empty() { self.to_user = event.to_user.clone(); }
        if self.request_uri_user.is_empty() { self.request_uri_user = event.request_uri_user.clone(); }
        if self.contact_user.is_empty() { self.contact_user = event.contact_user.clone(); }
        if self.pai_user.is_empty() { self.pai_user = event.pai_user.clone(); }
        let method = if !event.method.is_empty() { event.method.clone() } else { event.cseq_method.clone() };
        if !method.is_empty() { self.methods.insert(method.clone()); }
        self.has_invite |= method == "INVITE" || event.cseq_method == "INVITE";
        self.has_ack |= method == "ACK" || event.cseq_method == "ACK";
        self.has_bye |= method == "BYE" || event.cseq_method == "BYE";
        self.has_cancel |= method == "CANCEL" || event.cseq_method == "CANCEL";
        self.completed |= event.status_code == Some(200) && event.cseq_method == "INVITE";
        for value in [&event.from_user, &event.to_user, &event.request_uri_user, &event.contact_user, &event.pai_user] {
            let n = normalize_number(value);
            if !n.is_empty() { self.normalized_numbers.insert(n); }
        }
        if let Some(status) = event.status_code {
            let priority = if status >= 200 && event.cseq_method == "INVITE" { 3 } else if status >= 200 { 2 } else { 1 };
            let key = (priority, (event.ts_epoch * 1000.0) as i64);
            if key >= self.status_priority {
                self.status_priority = key;
                self.status_code = Some(status);
                self.reason_phrase = event.reason_phrase.clone();
            }
        }
        if !event.src_ip.is_empty() { self.src_ips.insert(event.src_ip); }
        if !event.dst_ip.is_empty() { self.dst_ips.insert(event.dst_ip); }
        if let Some(port) = event.src_port { self.sip_ports.insert(port); }
        if let Some(port) = event.dst_port { self.sip_ports.insert(port); }
        self.packet_count += 1;
        self.sdp_media.extend(event.sdp_media);
    }
}

fn decode_sip_packet(data: &[u8], linktype: u32, ts_epoch: f64, frame_number: i64) -> Option<SipEvent> {
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
        TransportSlice::Udp(udp) => (Some(udp.source_port() as i64), Some(udp.destination_port() as i64), udp.payload()),
        TransportSlice::Tcp(tcp) => (Some(tcp.source_port() as i64), Some(tcp.destination_port() as i64), tcp.payload()),
        _ => return None,
    };
    let text = std::str::from_utf8(payload).ok()?;
    if !looks_like_sip(text) { return None; }
    parse_sip(text, ts_epoch, frame_number, src_ip, dst_ip, src_port, dst_port)
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

fn looks_like_sip(text: &str) -> bool {
    ["INVITE ", "ACK ", "BYE ", "CANCEL ", "OPTIONS ", "REGISTER ", "PRACK ", "UPDATE ", "INFO ", "MESSAGE ", "REFER ", "NOTIFY ", "SUBSCRIBE ", "SIP/2.0 "]
        .iter()
        .any(|prefix| text.starts_with(prefix))
}

fn parse_sip(text: &str, ts_epoch: f64, frame_number: i64, src_ip: String, dst_ip: String, src_port: Option<i64>, dst_port: Option<i64>) -> Option<SipEvent> {
    let normalized = text.replace("\r\n", "\n");
    let mut lines = normalized.lines();
    let first = lines.next()?.trim().to_string();
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    let mut body_lines = Vec::new();
    let mut in_body = false;
    for line in lines {
        if line.trim().is_empty() {
            in_body = true;
            continue;
        }
        if in_body {
            body_lines.push(line.to_string());
        } else if let Some((name, value)) = line.split_once(':') {
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
        .and_then(|value| value.split_whitespace().last().map(|v| v.to_ascii_uppercase()))
        .unwrap_or_default();
    let body = body_lines.join("\n");
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
        from_user: header(&headers, "from").map(|v| extract_user(&v)).unwrap_or_default(),
        to_user: header(&headers, "to").map(|v| extract_user(&v)).unwrap_or_default(),
        request_uri_user,
        contact_user: header(&headers, "contact").map(|v| extract_user(&v)).unwrap_or_default(),
        pai_user: header(&headers, "p-asserted-identity").map(|v| extract_user(&v)).unwrap_or_default(),
        sdp_media: parse_sdp(&body, frame_number, ts_epoch),
    })
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
        let rest = &target[pos + if target[pos..].starts_with("sips:") { 5 } else { 4 }..];
        let user = rest.split('@').next().unwrap_or(rest);
        return user.trim_matches(|c: char| c == '<' || c == '>' || c == '"' || c.is_whitespace()).to_string();
    }
    normalize_number(target)
}

fn normalize_number(value: &str) -> String {
    value.chars().filter(|ch| ch.is_ascii_digit()).collect()
}

fn parse_sdp(body: &str, frame_number: i64, ts_epoch: f64) -> Vec<SdpMedia> {
    if body.is_empty() { return Vec::new(); }
    let mut session_ip = String::new();
    let mut current: Option<SdpMedia> = None;
    let mut result = Vec::new();
    for line in body.lines().map(|v| v.trim()) {
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
                media: parts.get(0).unwrap_or(&"").to_string(),
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

fn init_db(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE capture_sets(id INTEGER PRIMARY KEY, created_at TEXT, sip_dir TEXT, rtp_dir TEXT, config_json TEXT, schema_version INTEGER);
        CREATE TABLE capture_files(id INTEGER PRIMARY KEY, capture_set_id INTEGER, role TEXT, path TEXT, file_name TEXT, size_bytes INTEGER, first_epoch REAL, last_epoch REAL, server_ip TEXT, packet_count INTEGER, parse_status TEXT, warning_count INTEGER);
        CREATE TABLE calls(call_id TEXT PRIMARY KEY, first_epoch REAL, last_epoch REAL, first_frame INTEGER, last_frame INTEGER, from_user TEXT, to_user TEXT, request_uri_user TEXT, contact_user TEXT, pai_user TEXT, normalized_numbers TEXT, methods_json TEXT, status_code INTEGER, reason_phrase TEXT, src_ips_json TEXT, dst_ips_json TEXT, sip_ports_json TEXT, packet_count INTEGER, completed INTEGER, has_invite INTEGER, has_ack INTEGER, has_bye INTEGER, has_cancel INTEGER);
        CREATE TABLE call_files(call_id TEXT, file_id INTEGER, role TEXT, first_epoch REAL, last_epoch REAL);
        CREATE TABLE sdp_media(id INTEGER PRIMARY KEY, call_id TEXT, frame_number INTEGER, ts_epoch REAL, media TEXT, ip TEXT, port INTEGER, payloads_json TEXT, attributes_json TEXT);
        CREATE TABLE index_warnings(id INTEGER PRIMARY KEY, file_id INTEGER, ts_epoch REAL, severity TEXT, code TEXT, message TEXT);
        CREATE INDEX idx_capture_files_role_time ON capture_files(role, first_epoch, last_epoch);
        CREATE INDEX idx_calls_time ON calls(first_epoch, last_epoch);
        CREATE INDEX idx_calls_status ON calls(status_code);
        CREATE INDEX idx_calls_numbers ON calls(normalized_numbers);
        CREATE INDEX idx_call_files_call ON call_files(call_id);
        CREATE INDEX idx_sdp_media_call ON sdp_media(call_id);
        ",
    )
}

fn insert_capture_file(conn: &Connection, capture_set_id: i64, role: &str, path: &Path, stats: &CaptureStats, server_ip: String) -> rusqlite::Result<i64> {
    let size = fs::metadata(path).map(|m| m.len() as i64).unwrap_or(0);
    conn.execute(
        "INSERT INTO capture_files(capture_set_id, role, path, file_name, size_bytes, first_epoch, last_epoch, server_ip, packet_count, parse_status, warning_count) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 'ok', 0)",
        params![capture_set_id, role, path.display().to_string(), path.file_name().and_then(|v| v.to_str()).unwrap_or(""), size, stats.first_epoch, stats.last_epoch, server_ip, stats.packet_count as i64],
    )?;
    Ok(conn.last_insert_rowid())
}

fn insert_call(conn: &Connection, acc: &CallAcc) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO calls(call_id, first_epoch, last_epoch, first_frame, last_frame, from_user, to_user, request_uri_user, contact_user, pai_user, normalized_numbers, methods_json, status_code, reason_phrase, src_ips_json, dst_ips_json, sip_ports_json, packet_count, completed, has_invite, has_ack, has_bye, has_cancel) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        params![
            acc.call_id,
            acc.first_epoch,
            acc.last_epoch,
            acc.first_frame,
            acc.last_frame,
            acc.from_user,
            acc.to_user,
            acc.request_uri_user,
            acc.contact_user,
            acc.pai_user,
            acc.normalized_numbers.iter().cloned().collect::<Vec<_>>().join(" "),
            serde_json::to_string(&acc.methods.iter().cloned().collect::<Vec<_>>()).unwrap(),
            acc.status_code,
            acc.reason_phrase,
            serde_json::to_string(&acc.src_ips.iter().cloned().collect::<Vec<_>>()).unwrap(),
            serde_json::to_string(&acc.dst_ips.iter().cloned().collect::<Vec<_>>()).unwrap(),
            serde_json::to_string(&acc.sip_ports.iter().cloned().collect::<Vec<_>>()).unwrap(),
            acc.packet_count,
            acc.completed as i64,
            acc.has_invite as i64,
            acc.has_ack as i64,
            acc.has_bye as i64,
            acc.has_cancel as i64,
        ],
    )?;
    Ok(())
}

fn insert_sdp_media(conn: &Connection, call_id: &str, item: &SdpMedia) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO sdp_media(call_id, frame_number, ts_epoch, media, ip, port, payloads_json, attributes_json) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
        params![call_id, item.frame_number, item.ts_epoch, item.media, item.ip, item.port, serde_json::to_string(&item.payloads).unwrap(), serde_json::to_string(&item.attributes).unwrap()],
    )?;
    Ok(())
}

fn detect_server(path: &Path, servers: &[String]) -> String {
    let name = path.file_name().and_then(|v| v.to_str()).unwrap_or("");
    for server in servers {
        if name.contains(server) || name.contains(&server.replace('.', "_")) {
            return server.clone();
        }
    }
    String::new()
}
