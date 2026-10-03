//! Record queries: swls, swlog, find (for swcat/swplay), swsearch.

use crate::daemon::{Caller, Console, Daemon};
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::atomic::AtomicBool;
use swrap_core::api::Resp;
use swrap_core::config::Host;
use swrap_core::frame::{kind, Frame};
use swrap_core::rbac;
use swrap_core::time::{fmt_display, now, Interval};
use swrec::search::{self, Query, SearchOpts};

pub fn ls(d: &Daemon, c: &Caller) -> Result<Resp> {
    let user = c.aaa()?;
    let t = now();
    let mut rows = vec![];
    let mut text = String::from("LABEL\tROUTE\tADDRESS\tACCOUNTS (default first)\n");
    for h in Host::all(&d.paths)? {
        if !rbac::host_visible(user, &h, c.origin, t) {
            continue;
        }
        let accts = rbac::granted_accounts(user, &h, c.origin, t);
        if accts.is_empty() {
            continue;
        }
        let shown: Vec<String> = accts.iter().enumerate().map(|(i, a)| if i == 0 { format!("*{a}") } else { a.clone() }).collect();
        text += &format!("{}\t{}\t{}:{}\t{}\n", h.label, match h.route { swrap_core::config::Route::Core => "core", _ => "edge" }, h.address, h.port, shown.join(","));
        rows.push(json!({"label": h.label, "route": h.route, "address": h.address, "port": h.port, "accounts": accts, "tags": h.tags}));
    }
    Ok(Resp { ok: true, data: json!(rows), text, ..Default::default() })
}

/// Users whose records the caller may see.
fn visible_users(d: &Daemon, c: &Caller, all: bool) -> Option<Vec<String>> {
    if c.admin && all {
        None
    } else if c.admin && c.user.is_none() {
        None
    } else {
        let _ = d;
        Some(vec![c.name.clone()])
    }
}

pub fn log(d: &Daemon, c: &Caller, window: &str, kind_f: Option<&str>, all: bool) -> Result<Resp> {
    if !c.admin {
        c.aaa()?;
    }
    if all && !c.admin {
        bail!("--all is for admins");
    }
    let iv = Interval::parse(window)?;
    let kinds: Vec<String> = kind_f.map(|k| vec![k.to_string()]).unwrap_or_default();
    let users = visible_users(d, c, all);
    let mut cands = search::candidates(&d.paths.root, users.as_deref(), &kinds, &iv);
    cands.sort_by(|a, b| a.path.file_name().cmp(&b.path.file_name()));
    let tz = d.tz();
    let live: Vec<String> = crate::session::live_sessions(d).iter().filter_map(|j| j["id"].as_str().map(String::from)).collect();
    let mut rows = vec![];
    let mut text = String::new();
    for cand in cands {
        let (h, last, end) = swrec::reader::header_and_last_ts(&cand.path);
        let Some(h) = h else { continue };
        let start = h.get("start").and_then(Value::as_str).unwrap_or("");
        let Ok(st) = start.parse::<jiff::Timestamp>() else { continue };
        let lt = last.as_deref().and_then(|t| t.parse().ok()).unwrap_or(st);
        if !iv.overlaps(st, lt) {
            continue;
        }
        let id = h.get("id").and_then(Value::as_str).unwrap_or("").to_string();
        let kind = h.get("kind").and_then(Value::as_str).unwrap_or(&cand.kind).to_string();
        let target = match kind.as_str() {
            "sw" => format!("{}@{}", h.get("ruser").and_then(Value::as_str).unwrap_or(""), h.get("label").and_then(Value::as_str).unwrap_or("")),
            _ => h.get("exec").and_then(Value::as_str).unwrap_or("").to_string(),
        };
        let status = if live.contains(&id) {
            "live".to_string()
        } else if let Some(e) = &end {
            format!("{} {}", e.get("reason").and_then(Value::as_str).unwrap_or(""), e.get("duration").and_then(Value::as_str).unwrap_or(""))
        } else {
            "incomplete".into()
        };
        let user = h.get("aaa_user").and_then(Value::as_str).unwrap_or(&cand.user).to_string();
        text += &format!("{}  {}  {:<5} {:<10} {:<24} {}\n", fmt_display(st, &tz, false), id, kind, user, target, status);
        rows.push(json!({"id": id, "kind": kind, "user": user, "target": target, "start": start, "status": status, "path": cand.path}));
    }
    if rows.is_empty() {
        text = format!("no records in {iv}\n");
    }
    Ok(Resp { ok: true, data: json!(rows), text, ..Default::default() })
}

pub fn find(d: &Daemon, c: &Caller, id: &str) -> Result<Resp> {
    if id.len() < 26 || !swrap_core::paths::safe_component(id) {
        bail!("give the full record id (26 characters), e.g. from swlog");
    }
    if !c.admin {
        c.aaa()?;
    }
    let users = if c.admin { None } else { Some(vec![c.name.clone()]) };
    let p = swrec::search::find_record(&d.paths.root, users.as_deref(), id).ok_or_else(|| anyhow::anyhow!("no record {id} visible to you"))?;
    let live = crate::session::live_sessions(d).iter().any(|j| j["id"] == id);
    Ok(Resp::ok(json!({"path": p, "live": live, "tz": d.tz()})))
}

pub fn search(d: &Daemon, c: &Caller, query: &str, con: &Console) -> Result<Resp> {
    if !c.admin {
        c.aaa()?;
    }
    let cfg = d.cfg();
    let mut q = Query::parse(query)?;
    if q.window.is_none() {
        q.window = Some(Interval::parse(&cfg.web.search_default_window)?);
    }
    if !c.admin && q.terms.iter().any(|t| t.field == search::Field::User) {
        bail!("user: is for admins");
    }
    let cancel = AtomicBool::new(false);
    let opts = SearchOpts {
        root: d.paths.root.clone(),
        users: if c.admin { None } else { Some(vec![c.name.clone()]) },
        max_results: cfg.web.search_max_results,
        cancel: &cancel,
        kinds: vec![],
    };
    let tz = d.tz();
    let on_hit = |h: &search::Hit| {
        let ts = h.ts.parse::<jiff::Timestamp>().map(|t| fmt_display(t, &tz, false)).unwrap_or_default();
        let target = if h.kind == "sw" { format!("{}@{}", h.ruser, h.label) } else { h.exec.clone() };
        con.frame(Frame::new(kind::STDOUT, format!("{ts}  {}  {:<5} {:<10} {:<20} {:<6} {:>10}  {}", h.id, h.kind, h.user, target, h.field, h.bytes, h.snippet).into_bytes()));
        con.frame(Frame::json(kind::EVENT, &json!({"hit": h})));
    };
    let on_progress = |p: &search::Progress| {
        con.frame(Frame::json(kind::EVENT, &json!({"progress": p})));
    };
    let p = search::run(&q, &opts, &on_hit, &on_progress)?;
    Ok(Resp {
        ok: true,
        data: json!(p),
        text: format!("{} hits; {} of {} files, {} bytes scanned in {}", p.hits, p.files_scanned, p.files_total, p.bytes_scanned, q.window.unwrap()),
        ..Default::default()
    })
}

/// Stream a record file (as stored, possibly gzip) in DATA frames.
pub fn fetch(d: &Daemon, c: &Caller, id: &str, con: &Console) -> Result<Resp> {
    let r = find(d, c, id)?;
    let path = std::path::PathBuf::from(r.data["path"].as_str().unwrap_or(""));
    if path.is_dir() {
        bail!("{id} is a run directory; fetch one host's record from it on core");
    }
    use std::io::Read;
    let mut f = std::fs::File::open(&path)?;
    let mut buf = vec![0u8; 256 << 10];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        con.frame(Frame::new(kind::DATA, buf[..n].to_vec()));
    }
    Ok(Resp::ok(json!({"name": path.file_name().map(|x| x.to_string_lossy().to_string()), "live": r.data["live"], "tz": d.tz()})))
}
