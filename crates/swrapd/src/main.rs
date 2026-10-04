//! swrapd: the core daemon (vault, RBAC, sessions, agent proxy, records, retention).

mod accounts;
mod admin;
mod agent;
mod ai;
mod ai_reset;
mod ai_worker;
mod audit;
mod crypto;
mod doctor;
mod edge_admin;
mod edge_api;
mod edge_jobs;
mod edged;
mod eagent;
mod fleet;
mod link;
mod snapshot;
mod fw;
mod daemon;
mod hosts;
mod inventory;
mod motd;
mod records;
mod retention;
mod session;
mod sftp;
mod table;
mod unseal;
mod util;
mod worker;

use anyhow::{Context, Result};
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;
use swrap_core::Paths;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("worker") => worker::main(),
        Some("edge") => edged::main(),
        Some("tunnel") => tunnel(args.get(2).map(String::as_str).unwrap_or("")),
        Some("profile-snippet") => {
            print!("{}", hosts::profile_snippet());
            Ok(())
        }
        None | Some("run") => run(),
        Some(o) => anyhow::bail!("unknown mode {o}; usage: swrapd [run]"),
    }
}

/// `swrapd tunnel <id>`: ssh's ProxyCommand for hosts only edge reaches (SFTP backends). Asks
/// swrapd for the tunnel, then relays stdin/stdout to it.
fn tunnel(id: &str) -> Result<()> {
    use std::io::{Read, Write};
    use swrap_core::frame::{kind, read_frame, write_frame, Frame};
    let mut s = std::os::unix::net::UnixStream::connect(Paths::from_env().api_sock()).context("swrapd")?;
    write_frame(&mut s, &Frame::json(kind::REQ, &swrap_core::api::Req::EdgeTunnel { id: id.to_string() }))?;
    let r: swrap_core::api::Resp = read_frame(&mut s)?.context("swrapd closed")?.parse()?;
    if !r.ok {
        anyhow::bail!("swrap tunnel: {}", r.error.unwrap_or_default());
    }
    let mut up = s.try_clone()?;
    let t = std::thread::spawn(move || {
        let mut buf = [0u8; 64 << 10];
        let mut stdin = std::io::stdin().lock();
        while let Ok(n) = stdin.read(&mut buf) {
            if n == 0 || up.write_all(&buf[..n]).is_err() {
                break;
            }
        }
        let _ = up.shutdown(std::net::Shutdown::Write);
    });
    let mut out = std::io::stdout().lock();
    let mut buf = [0u8; 64 << 10];
    while let Ok(n) = s.read(&mut buf) {
        if n == 0 || out.write_all(&buf[..n]).and_then(|_| out.flush()).is_err() {
            break;
        }
    }
    drop(t);
    Ok(())
}

fn prepare_run_dirs(p: &Paths, uid: u32, gid: u32) -> Result<()> {
    for (dir, mode, own) in [
        (p.run.clone(), 0o755, false),
        (p.sessions(), 0o711, false),
        (p.live(), 0o755, true),
        (p.run.join("agents"), 0o700, false),
        (p.run.join("keygen"), 0o700, false),
        (p.run.join("caps"), 0o700, false),
        (p.run.join("ai-slots"), 0o700, true),
    ] {
        std::fs::create_dir_all(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode))?;
        if own {
            std::os::unix::fs::chown(&dir, Some(uid), Some(gid))?;
        }
    }
    Ok(())
}

fn run() -> Result<()> {
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }
    let paths = Paths::from_env();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().worker_threads(4).build()?;
    rt.block_on(async move {
        let d = daemon::Daemon::new(paths).context("init")?;
        prepare_run_dirs(&d.paths, d.swrap_uid, d.swrap_gid)?;
        d.audit_event("", "daemon.start", "core", "", "ok", serde_json::json!({"sealed": d.is_sealed(), "version": env!("CARGO_PKG_VERSION")}), "");
        motd::update(&d);
        // Every AAA user gets ~/swrap-docs (also for accounts created before this existed).
        for u in swrap_core::config::User::all(&d.paths).unwrap_or_default() {
            if let Some(pw) = swrap_core::sys::user_by_name(&u.name) {
                swrap_core::paths::ensure_docs_link(&pw.dir, pw.uid.as_raw(), pw.gid.as_raw());
            }
        }
        if let Err(e) = fw::apply(&d) {
            eprintln!("swrapd: nftables: {e:#}");
        }
        eprintln!("swrapd: started ({})", if d.is_sealed() { "vault sealed" } else { "vault unsealed from keyring" });
        let api = tokio::spawn(daemon::serve_api(d.clone()));
        let uns = tokio::spawn(unseal::serve(d.clone()));
        tokio::spawn(retention::run_loop(d.clone()));
        tokio::spawn(doctor::run_loop(d.clone()));
        tokio::spawn(inventory::run_loop(d.clone()));
        tokio::spawn(table::run_loop(d.clone()));
        let d_e = d.clone();
        tokio::spawn(async move {
            if let Err(e) = edge_api::serve(d_e).await {
                eprintln!("swrapd: edge api: {e:#}");
            }
        });
        tokio::spawn(link::supervise(d.clone()));
        let d2 = d.clone();
        tokio::spawn(async move {
            let mut n = 0u64;
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                d2.audit.lock().unwrap().tick();
                n += 1;
                if n % 3600 == 0 {
                    swrap_vault::keyring::touch();
                }
                if n % 60 == 0 {
                    motd::update(&d2);
                    // Entries become active/expire over time (not_before/not_after).
                    let d3 = d2.clone();
                    tokio::task::spawn_blocking(move || {
                        let _g = d3.config_lock.lock().unwrap();
                        let _ = fw::apply(&d3);
                    });
                }
            }
        });
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            r = api => { r??; }
            r = uns => { r??; }
            _ = term.recv() => { d.audit_event("", "daemon.stop", "core", "", "ok", serde_json::json!({}), ""); }
        }
        Ok::<(), anyhow::Error>(())
    })
}
