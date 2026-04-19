use clap::{Parser, Subcommand};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Instant;

mod aggregator;
mod db_writer;
mod pcap_reader;
mod sip_parser;
mod types;

use aggregator::merge_call;
use pcap_reader::{is_supported_linktype, PcapReader};
use sip_parser::decode_sip_packet;
use types::{CallAcc, CaptureStats, FileScanResult, WorkerPlan};

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
    cpu_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sip_file_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rtp_file_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sip_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rtp_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sip_scan_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rtp_catalog_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    db_write_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
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
        cpu_count: None,
        sip_file_count: None,
        rtp_file_count: None,
        sip_bytes: None,
        rtp_bytes: None,
        sip_scan_seconds: None,
        rtp_catalog_seconds: None,
        db_write_seconds: None,
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

fn calculate_worker_plan(
    profile_value: &str,
    workers_value: &str,
    candidate_count: usize,
) -> WorkerPlan {
    let profile = normalize_profile(profile_value);
    let cpus = thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(4)
        .max(1);
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
    preflight_fast_path(&sip_files)?;
    preflight_fast_path(&rtp_files)?;
    let sip_bytes = total_size(&sip_files);
    let rtp_bytes = total_size(&rtp_files);
    let worker_plan = calculate_worker_plan(
        &performance,
        &workers,
        (sip_files.len() + rtp_files.len()).max(1),
    );
    emit(&Progress {
        kind: "start",
        sip_dir: Some(sip_dir.display().to_string()),
        rtp_dir: Some(rtp_dir.display().to_string()),
        workers: Some(worker_plan.workers),
        active_workers: Some(worker_plan.workers),
        performance_profile: Some(worker_plan.profile.clone()),
        memory_total_gb: worker_plan.memory_total_gb,
        cpu_count: Some(worker_plan.cpu_count),
        sip_file_count: Some(sip_files.len()),
        rtp_file_count: Some(rtp_files.len()),
        sip_bytes: Some(sip_bytes),
        rtp_bytes: Some(rtp_bytes),
        ..empty_progress()
    });

    let mut calls: BTreeMap<String, CallAcc> = BTreeMap::new();
    let mut total_sip_events = 0_u64;

    let sip_started = Instant::now();
    let sip_results = scan_files_parallel(&sip_files, "sip", true, worker_plan.workers, start)?;
    let sip_scan_seconds = sip_started.elapsed().as_secs_f64();
    for result in &sip_results {
        total_sip_events += result.stats.sip_events;
        for (_, acc) in &result.calls {
            merge_call(&mut calls, acc.clone());
        }
    }

    let rtp_started = Instant::now();
    let rtp_results = scan_files_parallel(&rtp_files, "rtp", false, worker_plan.workers, start)?;
    let rtp_catalog_seconds = rtp_started.elapsed().as_secs_f64();

    let db_started = Instant::now();
    db_writer::write_index(db_writer::IndexWritePlan {
        db_path: &db_path,
        sip_dir: &sip_dir,
        rtp_dir: &rtp_dir,
        sip_servers: &sip_servers,
        rtp_servers: &rtp_servers,
        worker_plan: &worker_plan,
        sip_results: &sip_results,
        rtp_results: &rtp_results,
        calls: &calls,
    })?;
    let db_write_seconds = db_started.elapsed().as_secs_f64();

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
        cpu_count: Some(worker_plan.cpu_count),
        sip_file_count: Some(sip_files.len()),
        rtp_file_count: Some(rtp_files.len()),
        sip_bytes: Some(sip_bytes),
        rtp_bytes: Some(rtp_bytes),
        sip_scan_seconds: Some(sip_scan_seconds),
        rtp_catalog_seconds: Some(rtp_catalog_seconds),
        db_write_seconds: Some(db_write_seconds),
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
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    name.contains(".pcap") || name.contains(".pcapng") || name.contains(".cap")
}

fn total_size(files: &[PathBuf]) -> u64 {
    files
        .iter()
        .filter_map(|path| fs::metadata(path).ok().map(|item| item.len()))
        .sum()
}

fn preflight_fast_path(files: &[PathBuf]) -> Result<(), Box<dyn std::error::Error>> {
    for path in files {
        let info = PcapReader::header_info(path)?;
        if info.is_pcapng {
            emit(&Progress {
                kind: "warning",
                path: Some(path.display().to_string()),
                code: Some("rust_fast_path_pcapng"),
                message: Some(
                    "PCAPNG detectado antes da indexacao Rust; usando fallback TShark para evitar processamento tardio."
                        .to_string(),
                ),
                ..empty_progress()
            });
            return Err(format!(
                "Formato PCAPNG nao suportado pelo caminho rapido Rust: {}",
                path.display()
            )
            .into());
        }
        if !is_supported_linktype(info.linktype) {
            emit(&Progress {
                kind: "warning",
                path: Some(path.display().to_string()),
                code: Some("rust_fast_path_linktype"),
                message: Some(format!(
                    "Linktype {} nao suportado pelo caminho rapido Rust; usando fallback TShark antes de processar a pasta.",
                    info.linktype
                )),
                ..empty_progress()
            });
            return Err(format!(
                "Linktype {} nao suportado pelo caminho rapido Rust: {}",
                info.linktype,
                path.display()
            )
            .into());
        }
    }
    Ok(())
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
            let result = scan_file(
                &file,
                parse_sip,
                &mut local_calls,
                &mut local_sip_events,
                started,
            )
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
                    sip_events: if parse_sip {
                        Some(item.stats.sip_events)
                    } else {
                        None
                    },
                    calls: if parse_sip {
                        Some(item.calls.len())
                    } else {
                        None
                    },
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
    let mut reader = PcapReader::open(path)?;
    let linktype = reader.linktype();
    let mut stats = CaptureStats::default();
    let mut frame_number = 0_i64;
    while let Some(packet) = reader.next_packet(parse_sip)? {
        frame_number += 1;
        stats.packet_count += 1;
        stats.first_epoch = Some(
            stats
                .first_epoch
                .map_or(packet.ts_epoch, |v| v.min(packet.ts_epoch)),
        );
        stats.last_epoch = Some(
            stats
                .last_epoch
                .map_or(packet.ts_epoch, |v| v.max(packet.ts_epoch)),
        );
        if parse_sip {
            if let Some(event) =
                decode_sip_packet(packet.data, linktype, packet.ts_epoch, frame_number)
            {
                stats.sip_events += 1;
                *total_sip_events += 1;
                stats.file_calls.insert(event.call_id.clone());
                let acc = calls
                    .entry(event.call_id.clone())
                    .or_insert_with(|| CallAcc {
                        call_id: event.call_id.clone(),
                        ..CallAcc::default()
                    });
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
