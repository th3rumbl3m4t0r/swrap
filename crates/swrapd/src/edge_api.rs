//! Core side of the link (spec 4.5): `edge-api.sock` and `edge-pty.sock`, reached from edge
//! through ssh reverse unix-socket forwards. Core treats edge as partially trusted: identity of
//! logged-in users is believed, everything else is decided here. Inputs are schema-validated
//! (serde), size-limited (frame cap) and rate-limited (per-request concurrency).

use crate::daemon::{Console, Daemon};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use swrap_core::api::{EdgePty, EdgeReq, Req, Resp};
use swrap_core::frame::{aio, kind, Frame};
use swrap_core::paths::safe_component;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

static INFLIGHT: AtomicUsize = AtomicUsize::new(0);
const MAX_INFLIGHT: usize = 64;

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
            let offset_ms = edge_t.map(|t| (t.as_millisecond() - core_t.as_millisecond()).abs()).unwrap_or(0);
            let addrs: Vec<String> = addrs.into_iter().filter(|a| a.parse::<std::net::IpAddr>().is_ok()).take(32).collect();
            let st = json!({"up_since": swrap_core::time::fmt_utc_secs(core_t), "edge_node": node, "edge_version": version, "clock_offset_ms": offset_ms, "edge_addrs": addrs});
            let _ = std::fs::write(link_state_path(&d), st.to_string());
            if offset_ms > 1000 {
                crate::motd::alert(&d, "clock", json!({"msg": "edge clock offset above PT1S", "offset_ms": offset_ms}));
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
