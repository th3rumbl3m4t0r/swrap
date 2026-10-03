//! Retention (spec 15) and compression (spec 8.7). Disk-based only: no time-based deletion.

use crate::daemon::Daemon;
use anyhow::Result;
use jiff::Timestamp;
use serde_json::json;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use swrap_core::time::now;

#[derive(Debug)]
struct Item {
    path: PathBuf,
    start: Timestamp,
    bytes: u64,
    kind: String,
    user: String,
    is_audit: bool,
}

fn parse_basic(s: &str) -> Option<Timestamp> {
    // 20260923T081402Z
    if s.len() < 16 {
        return None;
    }
    let iso = format!("{}-{}-{}T{}:{}:{}Z", &s[0..4], &s[4..6], &s[6..8], &s[9..11], &s[11..13], &s[13..15]);
    iso.parse().ok()
}

fn dir_size(p: &Path) -> u64 {
    let Ok(md) = std::fs::symlink_metadata(p) else { return 0 };
    if md.is_file() {
        return md.len();
    }
    std::fs::read_dir(p).map(|rd| rd.flatten().map(|e| dir_size(&e.path())).sum()).unwrap_or(0)
}

fn files_under(p: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(p) else { return };
    for e in rd.flatten() {
        let path = e.path();
        if path.is_dir() {
            files_under(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn live_paths(d: &Daemon) -> HashSet<PathBuf> {
    crate::session::live_sessions(d).iter().filter_map(|j| j["rec"].as_str().map(PathBuf::from)).collect()
}

fn collect(d: &Daemon) -> Vec<Item> {
    let live = live_paths(d);
    let mut items = vec![];
    // rec/<user>/<kind>/YYYY/MM/DD/<ts>_<ulid>_….swrec[.gz]
    if let Ok(us) = std::fs::read_dir(d.paths.rec()) {
        for u in us.flatten() {
            let user = u.file_name().to_string_lossy().to_string();
            for kind in ["sw", "shell", "sftp", "ai"] {
                let mut fs = vec![];
                files_under(&u.path().join(kind), &mut fs);
                for f in fs {
                    let name = f.file_name().unwrap().to_string_lossy().to_string();
                    if live.contains(&f) || !(name.ends_with(".swrec") || name.ends_with(".swrec.gz")) {
                        continue;
                    }
                    let Some(start) = parse_basic(&name) else { continue };
                    let bytes = std::fs::metadata(&f).map(|m| m.len()).unwrap_or(0);
                    items.push(Item { path: f, start, bytes, kind: kind.into(), user: user.clone(), is_audit: false });
                }
            }
        }
    }
    // runs/YYYY/MM/DD/<ts>_<ulid>_<kind>/
    for dd in date_dirs(&d.paths.runs()) {
        if let Ok(rd) = std::fs::read_dir(&dd) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                let Some(start) = parse_basic(&name) else { continue };
                items.push(Item { bytes: dir_size(&e.path()), path: e.path(), start, kind: "run".into(), user: String::new(), is_audit: false });
            }
        }
    }
    // logs/edge/YYYY/MM/DD.swrec[.gz] and audit/YYYY/MM/DD.swrec[.gz]
    let today = swrap_core::time::date_dir(now());
    for (base, is_audit) in [(d.paths.logs().join("edge"), false), (d.paths.audit(), true)] {
        let mut fs = vec![];
        files_under(&base, &mut fs);
        for f in fs {
            let rel = f.strip_prefix(&base).unwrap().to_string_lossy().to_string();
            let day = rel.split('.').next().unwrap_or("").to_string();
            if day == today {
                continue; // current daily file is live
            }
            let Ok(start) = format!("{}T00:00:00Z", day.replace('/', "-")).parse::<Timestamp>() else { continue };
            let bytes = std::fs::metadata(&f).map(|m| m.len()).unwrap_or(0);
            items.push(Item { path: f, start, bytes, kind: if is_audit { "audit".into() } else { "edgelog".into() }, user: String::new(), is_audit });
        }
    }
    items
}

fn date_dirs(base: &Path) -> Vec<PathBuf> {
    let mut out = vec![];
    for y in std::fs::read_dir(base).into_iter().flatten().flatten() {
        for m in std::fs::read_dir(y.path()).into_iter().flatten().flatten() {
            for dd in std::fs::read_dir(m.path()).into_iter().flatten().flatten() {
                out.push(dd.path());
            }
        }
    }
    out
}

pub struct Usage {
    pub total: u64,
    pub used: u64,
}

pub fn usage(p: &Path) -> Result<Usage> {
    let s = nix::sys::statvfs::statvfs(p)?;
    let bs = s.fragment_size() as u64;
    let total = s.blocks() as u64 * bs;
    let avail_root = s.blocks_free() as u64 * bs;
    Ok(Usage { total, used: total - avail_root })
}

fn pct(u: &Usage) -> f64 {
    if u.total == 0 { 0.0 } else { u.used as f64 * 100.0 / u.total as f64 }
}

/// Compress closed files older than `compress_after` (runs before eviction is considered).
pub fn compress_pass(d: &Daemon) -> Vec<String> {
    let cfg = d.cfg();
    let cutoff = cfg.retention.compress_after.before(now());
    let live = live_paths(d);
    let mut done = vec![];
    let mut fs = vec![];
    files_under(&d.paths.rec(), &mut fs);
    files_under(&d.paths.runs(), &mut fs);
    files_under(&d.paths.logs(), &mut fs);
    files_under(&d.paths.audit(), &mut fs);
    let today = swrap_core::time::date_dir(now());
    for f in fs {
        let name = f.to_string_lossy().to_string();
        if !name.ends_with(".swrec") || live.contains(&f) {
            continue;
        }
        if (name.contains("/audit/") || name.contains("/logs/")) && name.contains(&format!("{today}.")) {
            continue;
        }
        let (_, last, end) = swrec::reader::header_and_last_ts(&f);
        let t = end
            .as_ref()
            .and_then(|e| e.get("ts").and_then(|v| v.as_str()).and_then(|s| s.parse::<Timestamp>().ok()))
            .or_else(|| {
                // incomplete: use mtime
                std::fs::metadata(&f).ok().and_then(|m| m.modified().ok()).and_then(|m| Timestamp::try_from(m).ok())
            })
            .or_else(|| last.and_then(|s| s.parse().ok()));
        let Some(t) = t else { continue };
        if t >= cutoff {
            continue;
        }
        match swrec::compress::compress_file(&f, cfg.retention.gzip_member_bytes, None) {
            Ok(p) => done.push(p.to_string_lossy().into_owned()),
            Err(e) => d.audit_event("", "compress", &name, "", "error", json!({"error": e.to_string()}), ""),
        }
    }
    done
}

/// One retention check. Returns evicted paths.
pub fn evict_pass(d: &Daemon) -> Result<Vec<String>> {
    let cfg = d.cfg().retention;
    let mut u = usage(&d.paths.root)?;
    if pct(&u) < cfg.high_watermark_pct as f64 {
        return Ok(vec![]);
    }
    let low = cfg.low_watermark_pct.min(cfg.high_watermark_pct) as f64;
    let target_used = (u.total as f64 * low / 100.0) as u64;
    let mut items = collect(d);
    let deletable: u64 = items.iter().map(|i| i.bytes).sum();
    if u.used.saturating_sub(deletable) >= target_used {
        static LAST: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);
        let mut last = LAST.lock().unwrap();
        if last.map(|t| t.elapsed() < std::time::Duration::from_secs(3600)).unwrap_or(false) {
            return Ok(vec![]);
        }
        *last = Some(std::time::Instant::now());
        crate::motd::alert(d, "retention", json!({"msg": "disk above watermark and deleting every deletable record would not get below it (non-swrap data?) — nothing evicted", "used_pct": format!("{:.1}", pct(&u))}));
        return Ok(vec![]);
    }
    // Oldest first; audit only when nothing else remains.
    items.sort_by(|a, b| a.is_audit.cmp(&b.is_audit).then(a.start.cmp(&b.start)));
    let young = cfg.alert_if_evicting_younger_than.before(now());
    let mut evicted = vec![];
    for it in items {
        if u.used < target_used {
            break;
        }
        let r = if it.path.is_dir() { std::fs::remove_dir_all(&it.path) } else { std::fs::remove_file(&it.path) };
        if r.is_err() {
            continue;
        }
        if let Some(p) = it.path.parent() {
            let _ = swrap_core::atomic::fsync_dir(p);
        }
        let id = it.path.file_name().unwrap().to_string_lossy().to_string();
        d.audit_event("", "retention.evict", &it.kind, "", "ok",
            json!({"id": id, "kind": it.kind, "user": it.user, "start": swrap_core::time::fmt_utc_secs(it.start), "bytes": it.bytes}), "");
        if it.start > young {
            crate::motd::alert(d, "retention", json!({"msg": "evicting a record younger than alert_if_evicting_younger_than (output flooding?)", "id": id}));
        }
        evicted.push(it.path.to_string_lossy().into_owned());
        u = usage(&d.paths.root)?;
    }
    Ok(evicted)
}

pub async fn run_loop(d: std::sync::Arc<Daemon>) {
    let mut last_compress = std::time::Instant::now() - std::time::Duration::from_secs(3600);
    loop {
        let interval = d.cfg().retention.check_interval.exact().unwrap_or(std::time::Duration::from_secs(60));
        let d2 = d.clone();
        let do_compress = last_compress.elapsed() > std::time::Duration::from_secs(3600);
        if do_compress {
            last_compress = std::time::Instant::now();
        }
        let _ = tokio::task::spawn_blocking(move || {
            if do_compress {
                compress_pass(&d2);
            }
            if let Err(e) = evict_pass(&d2) {
                eprintln!("swrapd: retention: {e:#}");
            }
        })
        .await;
        tokio::time::sleep(interval).await;
    }
}
