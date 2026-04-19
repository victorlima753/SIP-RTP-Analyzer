use crate::types::{CallAcc, FileScanResult, WorkerPlan};
use rusqlite::{params, Connection, Transaction};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub(crate) const SCHEMA_VERSION: i64 = 2;

pub(crate) struct IndexWritePlan<'a> {
    pub(crate) db_path: &'a Path,
    pub(crate) sip_dir: &'a Path,
    pub(crate) rtp_dir: &'a Path,
    pub(crate) sip_servers: &'a [String],
    pub(crate) rtp_servers: &'a [String],
    pub(crate) worker_plan: &'a WorkerPlan,
    pub(crate) sip_results: &'a [FileScanResult],
    pub(crate) rtp_results: &'a [FileScanResult],
    pub(crate) calls: &'a BTreeMap<String, CallAcc>,
}

pub(crate) fn write_index(plan: IndexWritePlan<'_>) -> Result<(), Box<dyn std::error::Error>> {
    let mut conn = Connection::open(plan.db_path)?;
    conn.execute_batch(
        "
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
        PRAGMA temp_store=MEMORY;
        ",
    )?;
    let tx = conn.transaction()?;
    init_db(&tx)?;
    let config = serde_json::json!({
        "sip_servers": plan.sip_servers,
        "rtp_servers": plan.rtp_servers,
        "engine": "rust",
        "performance": plan.worker_plan.profile,
        "workers": plan.worker_plan.workers,
        "cpu_count": plan.worker_plan.cpu_count,
        "memory_total_gb": plan.worker_plan.memory_total_gb
    });
    tx.execute(
        "INSERT INTO capture_sets(created_at, sip_dir, rtp_dir, config_json, schema_version) VALUES(datetime('now'), ?, ?, ?, ?)",
        params![
            plan.sip_dir.display().to_string(),
            plan.rtp_dir.display().to_string(),
            config.to_string(),
            SCHEMA_VERSION
        ],
    )?;
    let capture_set_id = tx.last_insert_rowid();
    let mut call_files: Vec<(String, i64, f64, f64)> = Vec::new();

    insert_capture_results(
        &tx,
        capture_set_id,
        "sip",
        plan.sip_results,
        plan.sip_servers,
        &mut call_files,
    )?;
    insert_capture_results(
        &tx,
        capture_set_id,
        "rtp",
        plan.rtp_results,
        plan.rtp_servers,
        &mut call_files,
    )?;
    insert_calls(&tx, plan.calls)?;
    insert_call_files(&tx, &call_files)?;
    tx.execute(
        "INSERT OR REPLACE INTO metadata(key, value) VALUES('schema_version', ?)",
        params![SCHEMA_VERSION.to_string()],
    )?;
    tx.execute(
        "INSERT OR REPLACE INTO metadata(key, value) VALUES('engine', 'rust')",
        [],
    )?;
    tx.commit()?;
    Ok(())
}

fn init_db(tx: &Transaction<'_>) -> rusqlite::Result<()> {
    tx.execute_batch(
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

fn insert_capture_results(
    tx: &Transaction<'_>,
    capture_set_id: i64,
    role: &str,
    results: &[FileScanResult],
    servers: &[String],
    call_files: &mut Vec<(String, i64, f64, f64)>,
) -> rusqlite::Result<()> {
    let mut stmt = tx.prepare(
        "INSERT INTO capture_files(capture_set_id, role, path, file_name, size_bytes, first_epoch, last_epoch, server_ip, packet_count, parse_status, warning_count) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 'ok', 0)",
    )?;
    for result in results {
        let size = fs::metadata(&result.path)
            .map(|m| m.len() as i64)
            .unwrap_or(0);
        stmt.execute(params![
            capture_set_id,
            role,
            result.path.display().to_string(),
            result
                .path
                .file_name()
                .and_then(|v| v.to_str())
                .unwrap_or(""),
            size,
            result.stats.first_epoch,
            result.stats.last_epoch,
            detect_server(&result.path, servers),
            result.stats.packet_count as i64
        ])?;
        let file_id = tx.last_insert_rowid();
        if role == "sip" {
            for call_id in &result.stats.file_calls {
                if let (Some(first), Some(last)) =
                    (result.stats.first_epoch, result.stats.last_epoch)
                {
                    call_files.push((call_id.clone(), file_id, first, last));
                }
            }
        }
    }
    Ok(())
}

fn insert_calls(tx: &Transaction<'_>, calls: &BTreeMap<String, CallAcc>) -> rusqlite::Result<()> {
    let mut call_stmt = tx.prepare(
        "INSERT OR REPLACE INTO calls(call_id, first_epoch, last_epoch, first_frame, last_frame, from_user, to_user, request_uri_user, contact_user, pai_user, normalized_numbers, methods_json, status_code, reason_phrase, src_ips_json, dst_ips_json, sip_ports_json, packet_count, completed, has_invite, has_ack, has_bye, has_cancel) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )?;
    let mut sdp_stmt = tx.prepare(
        "INSERT INTO sdp_media(call_id, frame_number, ts_epoch, media, ip, port, payloads_json, attributes_json) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
    )?;
    for acc in calls.values() {
        call_stmt.execute(params![
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
            acc.normalized_numbers
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(" "),
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
        ])?;
        for item in &acc.sdp_media {
            sdp_stmt.execute(params![
                acc.call_id,
                item.frame_number,
                item.ts_epoch,
                item.media,
                item.ip,
                item.port,
                serde_json::to_string(&item.payloads).unwrap(),
                serde_json::to_string(&item.attributes).unwrap()
            ])?;
        }
    }
    Ok(())
}

fn insert_call_files(
    tx: &Transaction<'_>,
    call_files: &[(String, i64, f64, f64)],
) -> rusqlite::Result<()> {
    let mut stmt = tx.prepare(
        "INSERT INTO call_files(call_id, file_id, role, first_epoch, last_epoch) VALUES(?, ?, 'sip', ?, ?)",
    )?;
    for (call_id, file_id, first, last) in call_files {
        stmt.execute(params![call_id, file_id, first, last])?;
    }
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
