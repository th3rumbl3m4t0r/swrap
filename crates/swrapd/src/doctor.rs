//! `swrap doctor [--scrub] [--rebuild]` (spec 12.6). Daily run (recent files) and weekly scrub
//! (everything, including gzip members). Findings go to the audit log and the admin MOTD.

use crate::daemon::{Caller, Console, Daemon};
use anyhow::Result;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use swrap_core::api::Resp;

fn files(p: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(p) else { return };
    for e in rd.flatten() {
        let path = e.path();
        if path.is_dir() {
            files(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn dirs(p: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(p) else { return };
    out.push(p.to_path_buf());
    for e in rd.flatten() {
        if e.path().is_dir() {
            dirs(&e.path(), out);
        }
    }
}

pub fn check(d: &Daemon, scrub: bool, rebuild: bool, con: &Console) -> Vec<String> {
    let mut f: Vec<String> = vec![];
    let git_owner = (d.swrap_uid, d.swrap_gid);
    // 1. git repos
    for (name, p) in [("config", d.paths.config()), ("state", d.paths.state())] {
        let repo = swrap_core::git::Repo::new(&p).run_as(git_owner.0, git_owner.1);
        match repo.check() {
            Ok(v) => f.extend(v.into_iter().map(|x| format!("{name}: {x}"))),
            Err(e) => f.push(format!("{name}: git check failed: {e}")),
        }
    }
    con.out("git repositories checked");
    // 2. vault manifest
    match swrap_vault::Vault::new(&d.paths, d.owner()).manifest_verify() {
        Ok(v) => f.extend(v),
        Err(e) => f.push(format!("vault manifest: {e}")),
    }
    con.out("vault manifest checked");
    // 3. crash leftovers of compression
    let mut ds = vec![];
    for base in [d.paths.rec(), d.paths.runs(), d.paths.logs(), d.paths.audit()] {
        dirs(&base, &mut ds);
    }
    for dir in &ds {
        if let Ok(acts) = swrec::compress::recover_dir(dir) {
            for a in acts {
                f.push(format!("compression recovery: {a}"));
            }
        }
    }
    // 4. record verification (daily: modified in the last P1D; scrub: all)
    let v = swrec::RecVerifier::for_core(&d.paths);
    let live: Vec<String> = crate::session::live_sessions(d).iter().filter_map(|j| j["rec"].as_str().map(String::from)).collect();
    let mut all = vec![];
    for base in [d.paths.rec(), d.paths.runs(), d.paths.logs(), d.paths.audit()] {
        files(&base, &mut all);
    }
    let cutoff = SystemTime::now() - Duration::from_secs(86400);
    let mut n = 0;
    for p in all {
        let s = p.to_string_lossy();
        if !(s.ends_with(".swrec") || s.ends_with(".swrec.gz")) {
            continue;
        }
        if !scrub && std::fs::metadata(&p).and_then(|m| m.modified()).map(|t| t < cutoff).unwrap_or(false) {
            continue;
        }
        let is_live = live.iter().any(|l| l.as_str() == s) || (s.contains("/audit/") && s.contains(&swrap_core::time::date_dir(swrap_core::time::now())));
        match swrec::scan(&p, swrec::ScanOpts { verifier: Some(&v), keep_records: false, live: is_live }) {
            Ok(r) => {
                n += 1;
                if matches!(r.report.status, swrec::Status::Damaged | swrec::Status::Tampered) {
                    f.push(format!("{}: {} {:?} {:?}", s, r.report.status.as_str(), r.report.damaged, r.report.notes));
                }
            }
            Err(e) => f.push(format!("{s}: unreadable: {e}")),
        }
    }
    con.out(format!("{n} record files verified{}", if scrub { " (scrub)" } else { " (modified in the last P1D)" }));
    // 5. stale runtime state (session dirs of dead workers)
    let live_ids: Vec<String> = crate::session::live_sessions(d).iter().filter_map(|j| j["id"].as_str().map(String::from)).collect();
    if let Ok(rd) = std::fs::read_dir(d.paths.sessions()) {
        for e in rd.flatten() {
            let id = e.file_name().to_string_lossy().to_string();
            let age = e.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).unwrap_or_default();
            if !live_ids.contains(&id) && age > Duration::from_secs(600) {
                let _ = std::fs::remove_dir_all(e.path());
                f.push(format!("removed stale session dir {id}"));
            }
        }
    }
    // 6. package integrity of OpenSSH (swrap itself is not packaged yet: compare with the rebuild kit)
    let o = Command::new("rpm").args(["-Va", "openssh", "openssh-clients", "openssh-server"]).output();
    if let Ok(o) = o {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            if !l.contains(" c /") {
                f.push(format!("rpm -Va: {l}"));
            }
        }
    }
    for b in ["swrapd", "swrap", "swrap-shell", "swrap-pam-unlock", "swrec", "swrap-web"] {
        let a = PathBuf::from("/usr/libexec/swrap").join(b);
        for kit in ["/srv/rebuild/bin", "/home/rebuild/bin"] {
            let k = Path::new(kit).join(b);
            if let (Ok(x), Ok(y)) = (std::fs::read(&a), std::fs::read(&k)) {
                if blake3::hash(&x) != blake3::hash(&y) {
                    f.push(format!("{} differs from {} (run `swrap replica sync` after upgrades)", a.display(), k.display()));
                }
            }
        }
    }
    // 7. SELinux readiness (information, not a finding: confinement is being prepared).
    for l in selinux_report(false) {
        con.out(l);
    }
    // 8. rebuild derived caches
    if rebuild {
        let _ = std::fs::remove_dir_all(d.paths.run.join("caps"));
        let _ = std::fs::create_dir_all(d.paths.run.join("caps"));
        f.push("derived caches rebuilt".into());
    }
    f
}

/// swrap's SELinux domains and what enforcing them would block today: the denials the
/// permissive domains logged in the last week, grouped; with `detail`, a draft policy.
pub fn selinux_report(detail: bool) -> Vec<String> {
    let out = |cmd: &str, args: &[&str]| Command::new(cmd).args(args).output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
    let mode = out("getenforce", &[]).trim().to_string();
    if mode.is_empty() || mode == "Disabled" {
        return vec!["selinux: disabled".into()];
    }
    let domains = ["swrapd_t", "swrap_web_t"];
    let perm = out("semanage", &["permissive", "-l"]);
    let running: Vec<String> = out("ps", &["-eo", "label="]).lines().filter_map(|l| l.split(':').nth(2).map(String::from)).collect();
    let state: Vec<String> = domains
        .iter()
        .map(|t| {
            let p = if perm.lines().any(|l| l.trim() == *t) { "permissive" } else { "enforced" };
            let n = running.iter().filter(|r| r == t).count();
            format!("{t} {p}, {n} process{}", if n == 1 { "" } else { "es" })
        })
        .collect();
    let raw = out("ausearch", &["-m", "AVC,USER_AVC", "-ts", "week-ago", "--raw"]);
    let mine: Vec<&str> = raw.lines().filter(|l| l.contains("avc:  denied") && domains.iter().any(|t| l.contains(&format!(":{t}:")))).collect();
    let mut groups: std::collections::BTreeMap<String, u64> = Default::default();
    for l in &mine {
        let field = |k: &str| l.split_whitespace().find_map(|w| w.strip_prefix(k)).unwrap_or("").to_string();
        let ty = |c: String| c.split(':').nth(2).unwrap_or("").to_string();
        let perms = l.split_once("{ ").and_then(|(_, r)| r.split_once(" }")).map(|(p, _)| p.to_string()).unwrap_or_default();
        *groups.entry(format!("{} -> {}:{} {{ {perms} }}", ty(field("scontext=")), ty(field("tcontext=")), field("tclass="))).or_default() += 1;
    }
    let mut v = vec![format!("selinux: {mode}; {}; {} denial{} logged for them in the last P7D ({} kinds)", state.join(", "), mine.len(), if mine.len() == 1 { "" } else { "s" }, groups.len())];
    if detail {
        for (k, n) in &groups {
            v.push(format!("  {n:>5}  {k}"));
        }
        if !mine.is_empty() {
            let mut child = match Command::new("audit2allow").args(["-m", "swrap_confine"]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn() {
                Ok(c) => c,
                Err(_) => return v,
            };
            if let Some(mut i) = child.stdin.take() {
                use std::io::Write;
                let _ = i.write_all((mine.join("\n") + "\n").as_bytes());
            }
            if let Ok(o) = child.wait_with_output() {
                v.push("draft policy (audit2allow; review before use):".into());
                v.extend(String::from_utf8_lossy(&o.stdout).lines().map(|l| format!("  {l}")));
            }
        }
    }
    v
}

pub fn run(d: &Arc<Daemon>, c: &Caller, args: &[String], con: &Console) -> Result<Resp> {
    c.require_admin()?;
    if args.iter().any(|a| a == "--selinux") {
        return Ok(Resp::text(selinux_report(true).join("\n") + "\n"));
    }
    let scrub = args.iter().any(|a| a == "--scrub");
    let rebuild = args.iter().any(|a| a == "--rebuild");
    let findings = check(d, scrub, rebuild, con);
    record(d, &findings, scrub);
    let mut t = String::new();
    if findings.is_empty() {
        t += "doctor: no findings\n";
    } else {
        for x in &findings {
            t += &format!("finding: {x}\n");
        }
    }
    Ok(Resp { ok: true, text: t, exit: if findings.iter().any(|x| !x.starts_with("removed stale") && !x.starts_with("derived")) { 1 } else { 0 }, ..Default::default() })
}

fn record(d: &Daemon, findings: &[String], scrub: bool) {
    d.audit_event("", if scrub { "doctor.scrub" } else { "doctor.run" }, "core", "", if findings.is_empty() { "ok" } else { "findings" }, json!({"findings": findings}), "");
    let serious: Vec<&String> = findings.iter().filter(|x| !x.starts_with("removed stale") && !x.starts_with("derived")).collect();
    if !serious.is_empty() {
        crate::motd::alert(d, "doctor", json!({"findings": serious.len(), "first": serious[0]}));
    }
}

/// Scheduler: daily run, weekly scrub (state in index/doctor.json).
pub async fn run_loop(d: Arc<Daemon>) {
    loop {
        tokio::time::sleep(Duration::from_secs(300)).await;
        let state_p = d.paths.index().join("doctor.json");
        let st: serde_json::Value = std::fs::read_to_string(&state_p).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(json!({}));
        let now = swrap_core::time::now().as_second();
        let last_run = st["run"].as_i64().unwrap_or(0);
        let last_scrub = st["scrub"].as_i64().unwrap_or(0);
        let scrub = now - last_scrub > 7 * 86400;
        if !scrub && now - last_run < 86400 {
            continue;
        }
        let d2 = d.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let f = check(&d2, scrub, false, &Console::null());
            record(&d2, &f, scrub);
        })
        .await;
        let new = json!({"run": now, "scrub": if scrub { now } else { last_scrub }});
        let _ = std::fs::create_dir_all(d.paths.index());
        let _ = std::fs::write(&state_p, new.to_string());
    }
}
