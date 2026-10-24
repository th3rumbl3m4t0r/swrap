//! Core side of the link (spec 4.5): `edge-api.sock` and `edge-pty.sock`, reached from edge
//! through ssh reverse unix-socket forwards. Core treats edge as partially trusted: identity of
//! logged-in users is believed, everything else is decided here. Inputs are schema-validated
//! (serde), size-limited (frame cap) and rate-limited (per-request concurrency).

use crate::daemon::{Console, Daemon};
use anyhow::{bail, Context, Result};
use jiff::Timestamp;
use serde_json::{json, Value};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use swrap_core::api::{EdgePty, EdgeReq, Req, Resp};
use swrap_core::frame::{aio, kind, Frame};
use swrap_core::paths::safe_component;
use swrap_core::time::fmt_utc_secs;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

static INFLIGHT: AtomicUsize = AtomicUsize::new(0);
const MAX_INFLIGHT: usize = 64;

/// Hellos (every PT30S) in a row that showed the edge clock more than PT1S off.
struct ClockOff {
    since: Timestamp,
    last: Timestamp,
    max_ms: i64,
    alerted: bool,
}
static CLOCK: Mutex<Option<ClockOff>> = Mutex::new(None);
const CLOCK_MAX_MS: i64 = 1000;
/// How long every Hello must be off before it is the clock, not a Hello that arrived late (a core
/// busy just after boot, a congested link): one is, and the next one PT30S later is on time.
const CLOCK_FOR_SECS: i64 = 300;
/// A longer silence (link down) starts the count again.
const CLOCK_GAP_SECS: i64 = 120;

/// The alert for a Hello at `t` whose time was `off_ms` (edge minus core) off: once, when every
/// Hello for PT5M was more than PT1S off; a Hello within PT1S ends it.
fn clock_check(st: &mut Option<ClockOff>, t: Timestamp, off_ms: Option<i64>) -> Option<Value> {
    let Some(off) = off_ms.filter(|o| o.abs() > CLOCK_MAX_MS) else {
        *st = None;
        return None;
    };
    if st.as_ref().is_some_and(|c| t.as_second() - c.last.as_second() > CLOCK_GAP_SECS) {
        *st = None;
    }
    let c = st.get_or_insert(ClockOff { since: t, last: t, max_ms: 0, alerted: false });
    c.last = t;
    c.max_ms = c.max_ms.max(off.abs());
    if c.alerted || t.as_second() - c.since.as_second() < CLOCK_FOR_SECS {
        return None;
    }
    c.alerted = true;
    Some(json!({"msg": "edge clock offset above PT1S", "offset_ms": off.abs(), "max_offset_ms": c.max_ms, "since": fmt_utc_secs(c.since), "edge": if off > 0 { "ahead of core" } else { "behind core" }, "check": "chronyc tracking on the core and on edge"}))
}

pub fn link_state_path(d: &Daemon) -> std::path::PathBuf {
    d.paths.run.join("link.json")
}

fn bind(d: &Daemon, p: &std::path::Path) -> Result<UnixListener> {
    let _ = std::fs::remove_file(p);
    let l = UnixListener::bind(p).with_context(|| format!("bind {}", p.display()))?;
    // Only the link's ssh client (running as swrap) may connect.
    std::os::unix::fs::chown(p, Some(d.swrap_uid), Some(d.swrap_gid))?;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))?;
    Ok(l)
}

pub async fn serve(d: Arc<Daemon>) -> Result<()> {
    let api = bind(&d, &d.paths.edge_api_sock())?;
    let pty = bind(&d, &d.paths.edge_pty_sock())?;
    let d2 = d.clone();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = pty.accept().await else { continue };
            let d = d2.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_pty(d.clone(), s).await {
                    d.audit_event("", "edge.pty", "edge", "", "error", json!({"error": format!("{e:#}")}), "");
                }
            });
        }
    });
    loop {
        let (s, _) = api.accept().await?;
        if INFLIGHT.load(Ordering::SeqCst) >= MAX_INFLIGHT {
            continue; // drop: edge is flooding
        }
        let d = d.clone();
        tokio::spawn(async move {
            INFLIGHT.fetch_add(1, Ordering::SeqCst);
            if let Err(e) = handle_api(d.clone(), s).await {
                eprintln!("swrapd: edge api: {e:#}");
            }
            INFLIGHT.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

async fn resp(s: &mut UnixStream, r: &Resp) -> Result<()> {
    aio::write_frame(s, &Frame::json(kind::RESP, r)).await?;
    Ok(())
}

async fn handle_api(d: Arc<Daemon>, mut s: UnixStream) -> Result<()> {
    let Some(f) = aio::read_frame(&mut s).await? else { return Ok(()) };
    let req: EdgeReq = match f.parse() {
        Ok(r) => r,
        Err(e) => {
            d.audit_event("", "edge.bad-request", "edge", "", "refused", json!({"error": e.to_string()}), "");
            return resp(&mut s, &Resp::err(format!("bad request: {e}"))).await;
        }
    };
    match req {
        EdgeReq::Hello { node, version, now, addrs } => {
            let edge_t = swrap_core::time::parse_datetime(&now).ok();
            let core_t = swrap_core::time::now();
            // Edge minus core, and also the time this Hello took to arrive: a late one looks like an edge clock behind.
            let off_ms = edge_t.map(|t| t.as_millisecond() - core_t.as_millisecond());
            let offset_ms = off_ms.map(i64::abs).unwrap_or(0);
            let addrs: Vec<String> = addrs.into_iter().filter(|a| a.parse::<std::net::IpAddr>().is_ok()).take(32).collect();
            let st = json!({"up_since": swrap_core::time::fmt_utc_secs(core_t), "edge_node": node, "edge_version": version, "clock_offset_ms": offset_ms, "edge_addrs": addrs});
            let _ = std::fs::write(link_state_path(&d), st.to_string());
            let alert = clock_check(&mut CLOCK.lock().unwrap_or_else(|p| p.into_inner()), core_t, off_ms);
            if let Some(detail) = alert {
                crate::motd::alert(&d, "clock", detail);
            }
            resp(&mut s, &Resp::ok(json!({"now": swrap_core::time::fmt_utc(core_t)}))).await
        }
        EdgeReq::Jobs => {
            for _ in 0..125 {
                if let Some(j) = crate::edge_jobs::next() {
                    return resp(&mut s, &Resp::ok(serde_json::to_value(j)?)).await;
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
            resp(&mut s, &Resp::ok(json!({}))).await
        }
        EdgeReq::JobResult { id, result } => {
            crate::edge_jobs::result(&id, result);
            resp(&mut s, &Resp::ok(json!({}))).await
        }
        EdgeReq::Attach { id } => {
            let Some(client) = crate::edge_jobs::take(&id) else { bail!("no session {id} waiting") };
            client.set_nonblocking(true)?;
            let mut client = UnixStream::from_std(client)?;
            let _ = tokio::io::copy_bidirectional(&mut s, &mut client).await;
            let _ = std::fs::remove_file(d.paths.live().join(&id));
            Ok(())
        }
        EdgeReq::State { have } => {
            // Long-poll like Snapshot: the committed tree as soon as state/ moved past `have`
            // (it moves every PT6H; checked every 5 s).
            for _ in 0..5 {
                let d2 = d.clone();
                let head = tokio::task::spawn_blocking(move || {
                    swrap_core::git::Repo::new(d2.paths.state()).run_as(d2.swrap_uid, d2.swrap_gid).git(&["rev-parse", "HEAD"]).map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                })
                .await??;
                if head != have {
                    let d2 = d.clone();
                    let h2 = head.clone();
                    let tree = tokio::task::spawn_blocking(move || {
                        swrap_core::git::Repo::new(d2.paths.state()).run_as(d2.swrap_uid, d2.swrap_gid).git(&["archive", "--format=tar.gz", &h2, ":(exclude)ai-usage.json"]).map(|o| o.stdout)
                    })
                    .await??;
                    for chunk in tree.chunks(512 << 10) {
                        aio::write_frame(&mut s, &Frame::new(kind::DATA, chunk.to_vec())).await?;
                    }
                    return resp(&mut s, &Resp::ok(json!({"head": head, "bytes": tree.len()}))).await;
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
            resp(&mut s, &Resp::ok(json!({"head": have}))).await
        }
        EdgeReq::Snapshot { have } => {
            // Long-poll: answer as soon as a newer signed snapshot exists, else after ~PT25S.
            for _ in 0..25 {
                let d2 = d.clone();
                let cur = tokio::task::spawn_blocking(move || crate::snapshot::current(&d2)).await??;
                if let Some((v, text, sig)) = cur {
                    if v > have {
                        return resp(&mut s, &Resp::ok(json!({"version": v, "snapshot": text, "sig": sig}))).await;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            resp(&mut s, &Resp::ok(json!({"version": have}))).await
        }
        EdgeReq::Api { user, client_addr, req } => {
            let c = d.edge_caller(&user)?;
            // Session requests from edge use Authorize / core-pty; the rest runs as usual.
            if matches!(req, Req::Sw { .. } | Req::Shell { .. } | Req::AiStart { .. } | Req::AiAttach { .. } | Req::AiWorker { .. } | Req::Sftp { .. } | Req::SftpBackend { .. } | Req::EdgeTunnel { .. }) {
                return resp(&mut s, &Resp::err("use authorize/core-pty for sessions")).await;
            }
            let _ = client_addr;
            let (tx, mut rx) = mpsc::unbounded_channel::<Frame>();
            let con = Console { tx };
            let d2 = d.clone();
            let task = tokio::task::spawn_blocking(move || {
                let r = crate::daemon::dispatch(&d2, &c, req, &con).unwrap_or_else(|e| Resp::err(format!("{e:#}")));
                con.frame(Frame::json(kind::RESP, &r));
            });
            while let Some(f) = rx.recv().await {
                if aio::write_frame(&mut s, &f).await.is_err() {
                    break;
                }
            }
            task.await?;
            Ok(())
        }
        EdgeReq::Authorize { user, client_addr, conn, target, cmd, cols, rows, term, tty } => {
            let c = d.edge_caller(&user)?;
            let req = Req::Sw { target: target.clone(), cmd, cols, rows, term, client_addr, conn, tty };
            let d2 = d.clone();
            let r = tokio::task::spawn_blocking(move || crate::session::plan_sw(&d2, &c, &req, swrap_core::rbac::Node::Edge, false, None)).await?;
            match r {
                Ok(Some(plan)) => resp(&mut s, &Resp::ok(serde_json::to_value(plan)?)).await,
                Ok(None) => resp(&mut s, &Resp::err("no plan")).await,
                Err(e) => {
                    let msg = format!("{e:#}");
                    d.audit_event(&user, "session.refused", &target, "", "refused", json!({"error": msg, "origin": "edge"}), "");
                    resp(&mut s, &Resp::err(if msg.starts_with("swrap:") { msg } else { format!("swrap: {msg}") })).await
                }
            }
        }
        EdgeReq::Agent { id } => {
            if !safe_component(&id) {
                bail!("bad id");
            }
            let p = d.paths.session_dir(&id).join("agent.sock");
            let mut up = UnixStream::connect(&p).await.context("session agent gone")?;
            // The frame protocol ends here: raw ssh-agent bytes both ways.
            tokio::io::copy_bidirectional(&mut s, &mut up).await?;
            Ok(())
        }
        EdgeReq::Authenticated { id } => {
            if safe_component(&id) {
                let _ = std::fs::write(d.paths.session_dir(&id).join("authed"), b"1");
            }
            resp(&mut s, &Resp::ok(json!({}))).await
        }
        EdgeReq::Ingest { header, offset } => ingest(d, s, header, offset).await,
        EdgeReq::Unlock { user, password, rhost } => {
            let d2 = d.clone();
            let u = user.clone();
            let ok = tokio::task::spawn_blocking(move || -> Result<bool> {
                let pw = zeroize::Zeroizing::new(password);
                let c = d2.edge_caller(&u)?;
                if !c.admin {
                    return Ok(false);
                }
                let v = swrap_vault::Vault::new(&d2.paths, d2.owner());
                match v.unwrap_password(&u, pw.as_bytes()) {
                    Ok(dek) => {
                        let _ = d2.unseal(dek, &u, "ssh-edge");
                        Ok(true)
                    }
                    Err(_) => Ok(false),
                }
            })
            .await??;
            d.audit_event(&user, "auth.admin-password", "edge", "", if ok { "ok" } else { "fail" }, json!({"rhost": rhost, "via": "ssh-edge"}), "");
            resp(&mut s, &Resp { ok, ..Default::default() }).await
        }
        EdgeReq::Log { lines } => {
            let d2 = d.clone();
            tokio::task::spawn_blocking(move || edge_log(&d2, &lines)).await??;
            resp(&mut s, &Resp::ok(json!({}))).await
        }
    }
}

/// Delegated sessions: the first frame names the user; the stream then belongs to a core worker.
async fn handle_pty(d: Arc<Daemon>, mut s: UnixStream) -> Result<()> {
    let Some(f) = aio::read_frame(&mut s).await? else { return Ok(()) };
    let ep: EdgePty = f.parse()?;
    let c = d.edge_caller(&ep.user)?;
    if !matches!(ep.req, Req::Sw { .. } | Req::AiStart { .. } | Req::AiAttach { .. } | Req::Sftp { .. }) {
        bail!("only sw, swai and SFTP sessions are delegated");
    }
    let std = s.into_std()?;
    std.set_nonblocking(false)?;
    if matches!(ep.req, Req::Sftp { .. }) {
        // SFTP from edge logins runs on core (spec 11.3 delegated): worker, recording, grants.
        tokio::task::spawn_blocking(move || crate::sftp::start(d, c, ep.req, std)).await??;
        return Ok(());
    }
    if matches!(ep.req, Req::AiStart { .. }) {
        // swai always runs on core (opencode, the vault and the backends live here).
        tokio::task::spawn_blocking(move || crate::ai::start(d, c, ep.req, std, swrap_core::rbac::Node::Edge, true)).await??;
        return Ok(());
    }
    if matches!(ep.req, Req::AiAttach { .. }) {
        tokio::task::spawn_blocking(move || crate::ai::attach(d, c, ep.req, std, swrap_core::rbac::Node::Edge)).await??;
        return Ok(());
    }
    tokio::task::spawn_blocking(move || {
        let mut std = std;
        if let Err(e) = crate::session::plan_sw(&d, &c, &ep.req, swrap_core::rbac::Node::Edge, true, Some(&std)) {
            let msg = format!("{e:#}");
            let msg = if msg.starts_with("swrap:") { msg } else { format!("swrap: {msg}") };
            d.audit_event(&c.name, "session.refused", "", "", "refused", json!({"error": msg, "origin": "edge", "delegated": true}), "");
            let _ = swrap_core::frame::write_frame(&mut std, &Frame::json(kind::RESP, &Resp::err(msg)));
        }
    })
    .await?;
    Ok(())
}

// ---------------------------------------------------------------- record ingest (spec 8.8)

/// Destination under rec/ derived from the (validated) header — never from an edge-supplied path.
fn ingest_path(d: &Daemon, h: &serde_json::Map<String, Value>) -> Result<std::path::PathBuf> {
    let g = |k: &str| h.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let (kind, user, id, start) = (g("kind"), g("aaa_user"), g("id"), g("start"));
    if !["sw", "shell", "sftp"].contains(&kind.as_str()) || !safe_component(&user) || !safe_component(&id) || id.len() != 26 {
        bail!("bad header");
    }
    if swrap_core::config::User::load(&d.paths, &user).is_err() {
        bail!("unknown user {user}");
    }
    let t: jiff::Timestamp = start.parse().context("bad start")?;
    let name = match kind.as_str() {
        "sw" => {
            let (label, ruser) = (g("label"), g("ruser"));
            if !safe_component(&label) || !safe_component(&ruser) {
                bail!("bad label/ruser");
            }
            format!("{}_{}_{}_{}.swrec", swrap_core::time::fmt_basic(t), id, label, ruser)
        }
        _ => format!("{}_{}_edge.swrec", swrap_core::time::fmt_basic(t), id),
    };
    let dir = crate::session::ensure_rec_dir(d, &user)?.join(&kind).join(swrap_core::time::date_dir(t));
    swrap_core::atomic::mkdirs(&dir, 0o2750, swrap_core::atomic::Owner::new(d.swrap_uid, d.admin_gid))?;
    Ok(dir.join(name))
}

async fn ingest(d: Arc<Daemon>, mut s: UnixStream, header: String, _offset: u64) -> Result<()> {
    let h = swrec::format::decode_line(header.trim_end_matches('\n').as_bytes()).map_err(|e| anyhow::anyhow!("bad header line: {e}"))?;
    if h.get("k").and_then(Value::as_str) != Some("h") {
        bail!("first line is not a header");
    }
    let path = ingest_path(&d, &h)?;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).mode(0o640).open(&path)?;
    let _ = std::os::unix::fs::fchown(&f, Some(d.swrap_uid), Some(d.admin_gid));
    let mut size = f.metadata()?.len();
    // Tell edge where to resume.
    resp(&mut s, &Resp::ok(json!({"size": size}))).await?;
    while let Some(fr) = aio::read_frame(&mut s).await? {
        if fr.kind != kind::DATA {
            break;
        }
        let data = fr.payload;
        // Only whole lines, each with a valid CRC; the very first line must be this header.
        if !data.ends_with(b"\n") {
            bail!("partial line in ingest");
        }
        for (i, line) in data[..data.len() - 1].split(|&b| b == b'\n').enumerate() {
            if swrec::format::decode_line(line).is_err() {
                bail!("line with bad CRC/JSON in ingest");
            }
            if size == 0 && i == 0 && line != header.trim_end_matches('\n').as_bytes() {
                bail!("stream does not start with its header");
            }
        }
        // Identical bytes, one write, then fdatasync before the ack.
        f.write_all(&data)?;
        f.sync_data()?;
        if size == 0 {
            swrap_core::atomic::fsync_dir(path.parent().unwrap())?;
        }
        size += data.len() as u64;
        resp(&mut s, &Resp::ok(json!({"size": size}))).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------- edge log shipping

fn edge_log(d: &Daemon, lines: &[String]) -> Result<()> {
    use swrec::{Writer, WriterOpts};
    if lines.len() > 5000 {
        bail!("too many lines");
    }
    let day = swrap_core::time::date_dir(swrap_core::time::now());
    let path = d.paths.logs().join("edge").join(format!("{day}.swrec"));
    swrap_core::atomic::mkdirs(path.parent().unwrap(), 0o2750, swrap_core::atomic::Owner::new(d.swrap_uid, d.admin_gid))?;
    let mut w = if path.exists() {
        match Writer::resume(&path, WriterOpts::default())? {
            Some(w) => w,
            None => return Ok(()),
        }
    } else {
        let h = json!({"kind": "edgelog", "origin": "edge", "exec": "edge"}).as_object().unwrap().clone();
        Writer::create(&path, &swrap_core::new_id(), h, WriterOpts::default())?
    };
    for l in lines {
        let l: String = l.chars().take(4096).collect();
        w.record_json("g", json!({"src": "edge", "msg": l}))?;
    }
    w.sync()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: i64) -> Timestamp {
        Timestamp::from_second(1_791_000_000 + s).unwrap()
    }

    #[test]
    fn one_late_hello_is_not_the_clock() {
        let mut st = None;
        // 2026-10-11T07:41:05Z: the first Hello after a boot, then on time again.
        assert!(clock_check(&mut st, at(0), Some(-13_068)).is_none());
        assert!(clock_check(&mut st, at(30), Some(-27)).is_none());
        assert!(st.is_none());
        assert!(clock_check(&mut st, at(60), None).is_none());
    }

    #[test]
    fn a_clock_off_for_five_minutes_alerts_once() {
        let mut st = None;
        let alerts: Vec<(i64, Value)> = (0..=20).filter_map(|i| clock_check(&mut st, at(30 * i), Some(2_500 + i)).map(|a| (i, a))).collect();
        assert_eq!(alerts.len(), 1);
        let (i, a) = &alerts[0];
        assert_eq!(*i, 10);
        assert_eq!(a["since"], fmt_utc_secs(at(0)));
        assert_eq!(a["max_offset_ms"], 2_510);
        assert_eq!(a["edge"], "ahead of core");
        // Back within PT1S, then off again: a new count.
        assert!(clock_check(&mut st, at(660), Some(400)).is_none());
        assert!((0..10).all(|i| clock_check(&mut st, at(690 + 30 * i), Some(-1_500)).is_none()));
        assert_eq!(clock_check(&mut st, at(990), Some(-1_500)).unwrap()["edge"], "behind core");
    }

    #[test]
    fn a_link_outage_starts_the_count_again() {
        let mut st = None;
        assert!(clock_check(&mut st, at(0), Some(-9_000)).is_none());
        // The link was down for an hour: the next late Hello is a new count, not PT1H of it.
        assert!(clock_check(&mut st, at(3_600), Some(-9_000)).is_none());
        assert!(clock_check(&mut st, at(3_630), Some(-200)).is_none());
    }
}
