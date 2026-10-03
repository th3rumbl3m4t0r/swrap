//! Session start (spec 9.1, 9.2, 9.5): authorize on core, prepare the tmpfs session directory,
//! start the per-session agent, and hand the client connection to a worker process that owns
//! the PTY, the `ssh` child and the recording. Workers survive swrapd restarts.

use crate::agent::{self, Policy, SessionAgent};
use crate::daemon::{Caller, Daemon};
use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use swrap_core::api::{Req, Resp, WorkerSpec};
use swrap_core::config::{Host, Profile};
use swrap_core::frame::{kind, write_frame, Frame};
use swrap_core::rbac::{self, Node};
use swrap_core::time::{date_dir, fmt_basic, fmt_display, now};

pub fn start(d: Arc<Daemon>, c: Caller, req: Req, mut s: UnixStream) -> Result<()> {
    let r = match &req {
        Req::Sw { .. } => start_sw(&d, &c, &req, &s),
        Req::Shell { .. } => start_shell(&d, &c, &req, &s),
        _ => bail!("not a session request"),
    };
    if let Err(e) = r {
        let msg = format!("{e:#}");
        let msg = if msg.starts_with("swrap:") { msg } else { format!("swrap: {msg}") };
        d.audit_event(&c.name, if matches!(req, Req::Sw { .. }) { "session.refused" } else { "shell.refused" }, &target_of(&req), "", "refused", json!({"error": msg}), "");
        let _ = write_frame(&mut s, &Frame::json(kind::RESP, &Resp::err(msg)));
    }
    Ok(())
}

fn target_of(r: &Req) -> String {
    match r {
        Req::Sw { target, .. } => target.clone(),
        _ => String::new(),
    }
}

/// Live-session markers: `/run/swrap/live/<id>` = JSON {user, kind, pid, rec}.
pub fn live_sessions(d: &Daemon) -> Vec<Value> {
    let mut v = vec![];
    if let Ok(rd) = std::fs::read_dir(d.paths.live()) {
        for e in rd.flatten() {
            if let Ok(s) = std::fs::read_to_string(e.path()) {
                if let Ok(j) = serde_json::from_str::<Value>(&s) {
                    let pid = j.get("pid").and_then(Value::as_i64).unwrap_or(0) as i32;
                    if crate::util::process_alive(pid) {
                        v.push(j);
                    } else {
                        let _ = std::fs::remove_file(e.path());
                    }
                }
            }
        }
    }
    v
}

pub fn check_live(d: &Daemon, c: &Caller, id: &str) -> Result<Resp> {
    if !swrap_core::paths::safe_component(id) {
        bail!("bad id");
    }
    let ok = live_sessions(d).iter().any(|j| j["id"] == id && j["user"] == c.name.as_str() && (j["kind"] == "sw" || j["kind"] == "ai"));
    Ok(Resp::ok(json!({ "live": ok })))
}

/// Ensure `rec/<user>/` exists with ACLs: the user reads their own records, admins read all.
pub fn ensure_rec_dir(d: &Daemon, user: &str) -> Result<PathBuf> {
    let dir = d.paths.rec().join(user);
    if !dir.exists() {
        swrap_core::atomic::mkdirs(&dir, 0o2750, swrap_core::atomic::Owner::new(d.swrap_uid, d.admin_gid))?;
        let acl = format!("u:{user}:rx,g:swrap-admin:rx");
        crate::util::setfacl(&["-m", &acl], &dir)?;
        crate::util::setfacl(&["-d", "-m", &format!("{acl},u::rwx,g::rx,o::-")], &dir)?;
    }
    Ok(dir)
}

fn parse_target(t: &str) -> (Option<&str>, &str) {
    match t.split_once('@') {
        Some((u, l)) => (Some(u), l),
        None => (None, t),
    }
}

/// Find the credential for (label, ruser): (enc path, pub path).
pub fn credential(d: &Daemon, label: &str, ruser: &str) -> Option<(PathBuf, PathBuf)> {
    let dir = d.paths.vault_keys().join("hosts").join(label).join(ruser);
    let rd = std::fs::read_dir(&dir).ok()?;
    let mut encs: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.to_string_lossy().ends_with(".enc")).collect();
    encs.sort();
    let enc = encs.into_iter().next()?;
    let pubp = PathBuf::from(enc.to_string_lossy().replace(".enc", ".pub"));
    pubp.exists().then_some((enc, pubp))
}

pub(crate) fn new_session_dir(d: &Daemon, id: &str) -> Result<PathBuf> {
    let dir = d.paths.session_dir(id);
    std::fs::create_dir_all(d.paths.sessions())?;
    std::fs::create_dir(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    std::os::unix::fs::chown(&dir, Some(d.swrap_uid), Some(d.swrap_gid))?;
    Ok(dir)
}

pub(crate) fn write_owned(d: &Daemon, p: &Path, data: &[u8], mode: u32) -> Result<()> {
    swrap_core::atomic::write(p, data, mode, d.owner())
}

fn limits(d: &Daemon, user: &str) -> Result<()> {
    let cfg = d.cfg();
    let live = live_sessions(d);
    let sw: Vec<&Value> = live.iter().filter(|j| j["kind"] == "sw").collect();
    if sw.len() >= cfg.limits.sessions_core {
        bail!("session limit reached on core ({})", cfg.limits.sessions_core);
    }
    if sw.iter().filter(|j| j["user"] == user).count() >= cfg.limits.sessions_per_user {
        bail!("per-user session limit reached ({})", cfg.limits.sessions_per_user);
    }
    Ok(())
}

fn start_sw(d: &Arc<Daemon>, c: &Caller, req: &Req, s: &UnixStream) -> Result<()> {
    plan_sw(d, c, req, Node::Core, false, Some(s)).map(|_| ())
}

/// Authorize and start an `sw` session.
/// * origin core, or origin edge with a `route = core` host (`delegated`): core runs ssh and the
///   worker talks to `client` (for delegated sessions, a core-pty.sock stream relayed by edge).
/// * origin edge with a `route = edge` host: edge runs ssh. Core starts the filtering agent and
///   returns the plan; edge relays agent connections back over the link (`client` is None).
pub fn plan_sw(d: &Arc<Daemon>, c: &Caller, req: &Req, origin: Node, delegated: bool, client: Option<&UnixStream>) -> Result<Option<swrap_core::api::EdgeSession>> {
    let Req::Sw { target, cmd, cols, rows, term, client_addr, conn, tty } = req else { unreachable!() };
    let user = c.aaa()?;
    let (ruser_opt, label) = parse_target(target);
    let host = Host::load(&d.paths, label).map_err(|_| anyhow::anyhow!("unknown host {label:?} (or no grant)"))?;
    let t = now();
    let ruser = match ruser_opt {
        Some(r) => {
            if !rbac::allowed(user, &host, r, origin, t) {
                bail!("no grant for {r}@{label}");
            }
            if host.account(r).is_none() {
                bail!("no credential for {r}@{label}");
            }
            r.to_string()
        }
        None => rbac::granted_accounts(user, &host, origin, t)
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("unknown host {label:?} (or no grant)"))?,
    };
    // Exec node (spec 4.2): origin core → core for every route; origin edge → the host's route.
    // Hosts in edge's network are only reachable from edge, whatever the origin.
    let exec = if host.network == swrap_core::config::Route::Edge || (origin == Node::Edge && host.route == swrap_core::config::Route::Edge) { Node::Edge } else { Node::Core };
    if origin == Node::Edge && exec == Node::Core && client.is_none() {
        // Edge asked for a plan but this host is internal (grant already checked): delegate.
        return Ok(Some(swrap_core::api::EdgeSession { delegate: true, ..Default::default() }));
    }
    let (enc, pubp) = credential(d, label, &ruser).ok_or_else(|| anyhow::anyhow!("no credential for {ruser}@{label}"))?;
    if d.is_sealed() {
        bail!("swrap: vault sealed since {} — an admin must log in with password", d.disp(*d.sealed_since.lock().unwrap()));
    }
    limits(d, &c.name)?;
    let cfg = d.cfg();
    let profile = Profile::load(&d.paths, &host.profile)?;
    // Edge capability reports arrive with link Hello; until then validate against core's build.
    let caps = crate::crypto::validate(&d.paths.run.join("caps"), &profile, "core")?;
    let known = std::fs::read_to_string(d.paths.known_hosts(label)).context("host keys not pinned (run swenroll)")?;
    let pinned = agent::pinned_blobs(&known);
    if pinned.is_empty() {
        bail!("no pinned host keys for {label}");
    }
    let pub_line = std::fs::read_to_string(&pubp)?;
    let key_blob = agent::pub_blob(&pub_line).context("bad public key file")?;

    let id = swrap_core::new_id();
    let nonce = crate::util::random_hex(16);
    let sdir = new_session_dir(d, &id)?;
    let ssh_config = profile.ssh_config();
    write_owned(d, &sdir.join("ssh_config"), ssh_config.as_bytes(), 0o600)?;
    // known_hosts keyed by label (used with HostKeyAlias) so address changes can't bypass pinning.
    write_owned(d, &sdir.join("known_hosts"), known.as_bytes(), 0o600)?;
    write_owned(d, &sdir.join("id.pub"), pub_line.as_bytes(), 0o600)?;

    let private = d.with_dek(|dek| swrap_vault::Vault::new(&d.paths, d.owner()).get(dek, &enc))?;
    let sa = SessionAgent::start(
        d.clone(),
        Policy {
            session_id: id.clone(),
            aaa_user: c.name.clone(),
            label: label.to_string(),
            ruser: ruser.clone(),
            key_blob,
            pinned,
            max_sigs: cfg.signing.max_signatures_per_session,
            window: cfg.signing.window.exact().unwrap_or(Duration::from_secs(120)),
            require_hostbound: cfg.signing.require_hostbound,
        },
        private,
        &sdir,
    )?;

    let ssh_bin = profile.ssh_bin_for(exec.as_str()).to_string();
    let mut argv = ssh_argv(&ssh_bin, &sdir, label);
    argv.extend(["-o".into(), format!("SetEnv=SWRAP_SESSION={id}:{nonce}"), "-p".into(), host.port.to_string()]);
    argv.push("-tt".into());
    argv.push(format!("{ruser}@{}", host.address));
    if !cmd.is_empty() {
        argv.push("--".into());
        argv.extend(cmd.iter().cloned());
    }

    let rec_dir = ensure_rec_dir(d, &c.name)?;
    let rec_path = rec_dir.join("sw").join(date_dir(t)).join(format!("{}_{}_{}_{}.swrec", fmt_basic(t), id, label, ruser));
    let hostkey_fp = host.hostkey_fingerprints.join(",");
    let mut header = Map::new();
    header.insert("kind".into(), "sw".into());
    for (k, v) in [
        ("origin", json!(origin.as_str())),
        ("exec", json!(exec.as_str())),
        ("delegated", json!(delegated)),
        ("aaa_user", json!(c.name)),
        ("client_addr", json!(client_addr)),
        ("conn", json!(conn)),
        ("label", json!(label)),
        ("addr", json!(host.address)),
        ("port", json!(host.port)),
        ("ruser", json!(ruser)),
        ("cols", json!(cols)),
        ("rows", json!(rows)),
        ("term", json!(term)),
        ("ssh_bin", json!(ssh_bin)),
        ("ssh_version", json!(caps.version)),
        ("profile", json!(profile.name)),
        ("config_rev", json!(d.config_rev())),
        ("hostkey_fp", json!(hostkey_fp)),
        ("hostbound", json!(ssh_supports_bind(&caps.version))),
        ("cmd", json!(cmd.join(" "))),
        ("record_input", json!(true)),
        ("tty", json!(tty)),
    ] {
        header.insert(k.into(), v);
    }
    let via = match (origin, exec) {
        (Node::Edge, Node::Core) => "edge→core",
        (Node::Core, Node::Edge) => "core→edge",
        (_, Node::Edge) => "edge",
        _ => "core",
    };
    let mut banner = format!(
        "swrap: recording {} {}@{} via {} {} (keystrokes recorded)",
        id, ruser, label, via, fmt_display(t, cfg.tz(), false)
    );
    if profile.warn {
        banner.push_str(&format!("\r\nswrap: WARNING: {label} uses the {} crypto profile", profile.name));
    }
    if let Some(u) = view_url(d, origin, &id) {
        banner.push_str(&format!("\r\nswrap: view {u}"));
    }
    if exec == Node::Edge {
        // Edge runs ssh; hand back the plan. The agent stays on core behind the proxy.
        let mut tail: Vec<String> = vec!["-o".into(), format!("HostKeyAlias={label}"), "-o".into(), format!("SetEnv=SWRAP_SESSION={id}:{nonce}"), "-p".into(), host.port.to_string(), "-tt".into(), format!("{ruser}@{}", host.address)];
        if !cmd.is_empty() {
            tail.push("--".into());
            tail.extend(cmd.iter().cloned());
        }
        d.audit_event(&c.name, "session.start", label, &ruser, "ok", json!({"exec": "edge", "origin": origin.as_str(), "client_addr": client_addr}), &id);
        supervise_agent(d.clone(), sa, sdir.clone(), cfg.signing.window.exact().unwrap_or(Duration::from_secs(120)), None);
        let plan = swrap_core::api::EdgeSession {
            delegate: false,
            id: id.clone(),
            nonce,
            banner,
            header,
            argv_tail: tail,
            ssh_config,
            known_hosts: known,
            pub_key: pub_line,
            label: label.to_string(),
            ssh_bin,
        };
        let Some(client) = client else { return Ok(Some(plan)) };
        // Core-origin session on an edge-network host: edge runs and records it, then attaches
        // back to this client over the link. A core live marker keeps nested-shell pauses working.
        let _ = std::fs::write(d.paths.live().join(&id), json!({"id": id, "user": c.name, "kind": "sw", "pid": std::process::id(), "via": "edge"}).to_string());
        crate::edge_jobs::park(&id, client.try_clone()?);
        crate::edge_jobs::enqueue(swrap_core::api::EdgeJob::Session { id: id.clone(), user: c.name.clone(), plan, cols: *cols, rows: *rows, term: term.clone() });
        let d2 = d.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(20));
            if let Some(mut s) = crate::edge_jobs::take(&id) {
                let _ = std::fs::remove_file(d2.paths.live().join(&id));
                let _ = write_frame(&mut s, &Frame::json(kind::RESP, &Resp::err("swrap: edge did not pick up the session (link down?)")));
            }
        });
        return Ok(None);
    }
    let spec = WorkerSpec {
        mode: "sw".into(),
        id: id.clone(),
        aaa_user: c.name.clone(),
        uid: c.uid,
        rec_path: rec_path.to_string_lossy().into(),
        session_dir: sdir.to_string_lossy().into(),
        header,
        argv,
        cols: *cols,
        rows: *rows,
        term: term.clone(),
        nonce,
        record_input: true,
        signer: "core".into(),
        recsign_key: d.paths.recsign().join("ed25519.key").to_string_lossy().into(),
        rec_cfg: cfg.rec.clone(),
        live_marker: d.paths.live().join(&id).to_string_lossy().into(),
        banner,
        sshd_pid: 0,
        ai: None,
        sftp: None,
    };
    let pid = spawn_worker(d, &spec, client.expect("local client"))?;
    d.audit_event(&c.name, "session.start", label, &ruser, "ok", json!({"exec": exec.as_str(), "origin": origin.as_str(), "delegated": delegated, "client_addr": client_addr, "worker_pid": pid}), &id);
    supervise_agent(d.clone(), sa, sdir, cfg.signing.window.exact().unwrap_or(Duration::from_secs(120)), Some(pid));
    Ok(None)
}

/// The ssh options every swrap connection uses: the session's config, log, vault-backed agent
/// and pinned host keys, no forwarding, no passwords. Callers add port, destination, command.
pub(crate) fn ssh_argv(ssh_bin: &str, sdir: &Path, label: &str) -> Vec<String> {
    vec![
        ssh_bin.to_string(),
        "-F".into(), sdir.join("ssh_config").to_string_lossy().into(),
        "-E".into(), sdir.join("ssh.log").to_string_lossy().into(),
        // DEBUG1 (not just VERBOSE) so the negotiated kex/cipher/mac lines reach ssh.log;
        // -E keeps all of it out of the terminal.
        "-o".into(), "LogLevel=DEBUG1".into(),
        "-o".into(), format!("IdentityAgent={}", sdir.join("agent.sock").display()),
        "-o".into(), "IdentitiesOnly=yes".into(),
        "-i".into(), sdir.join("id.pub").to_string_lossy().into(),
        "-o".into(), format!("UserKnownHostsFile={}", sdir.join("known_hosts").display()),
        "-o".into(), "GlobalKnownHostsFile=/dev/null".into(),
        "-o".into(), format!("HostKeyAlias={label}"),
        "-o".into(), "StrictHostKeyChecking=yes".into(),
        "-o".into(), "UpdateHostKeys=no".into(),
        "-o".into(), "ForwardAgent=no".into(),
        "-o".into(), "ForwardX11=no".into(),
        "-o".into(), "ClearAllForwardings=yes".into(),
        "-o".into(), "ControlMaster=no".into(),
        "-o".into(), "ControlPath=none".into(),
        "-o".into(), "PasswordAuthentication=no".into(),
        "-o".into(), "KbdInteractiveAuthentication=no".into(),
        "-o".into(), "BatchMode=yes".into(),
    ]
}

/// Kill the per-session agent right after authentication, on timeout, or when the worker ends.
/// Core-run sessions signal authentication through ssh.log; edge-run ones through an `authed`
/// marker written when edge reports it.
pub(crate) fn supervise_agent(d: Arc<Daemon>, sa: Arc<SessionAgent>, sdir: PathBuf, window: Duration, pid: Option<u32>) {
    std::thread::spawn(move || {
        let t0 = Instant::now();
        let log = sdir.join("ssh.log");
        loop {
            std::thread::sleep(Duration::from_millis(50));
            let authed = sdir.join("authed").exists() || std::fs::read_to_string(&log).map(|s| s.contains("Authenticated to ")).unwrap_or(false);
            let gone = pid.map(|p| !crate::util::process_alive(p as i32)).unwrap_or(false);
            if authed || t0.elapsed() > window || gone {
                break;
            }
        }
        let info = json!({"hostbound": sa.hostbound.load(std::sync::atomic::Ordering::SeqCst), "signatures": sa.signatures.load(std::sync::atomic::Ordering::SeqCst)});
        sa.shutdown();
        let _ = swrap_core::atomic::write(&sdir.join("agent.json"), info.to_string().as_bytes(), 0o600, d.owner());
        if pid.is_none() {
            // Edge-run session: nothing else lives in the core-side session dir.
            std::thread::sleep(Duration::from_secs(10));
            let _ = std::fs::remove_dir_all(&sdir);
        }
    });
}

/// Web GUI link to a recording, for the node the user is logged into: the LAN GUI on core,
/// the edge relay (`https://<public name>:<web_port>`) on edge. `web.public_url` overrides core's.
pub fn view_url(d: &Daemon, origin: Node, id: &str) -> Option<String> {
    let base = match origin {
        Node::Edge => {
            let e = crate::snapshot::edge_toml(d);
            let host = e.get("address").and_then(|v| v.as_str())?.to_string();
            let port = e.get("web_port").and_then(|v| v.as_integer()).unwrap_or(8443);
            format!("https://{host}:{port}")
        }
        Node::Core => {
            let raw = std::fs::read_to_string(d.paths.swrap_toml()).ok().and_then(|s| toml::from_str::<toml::Value>(&s).ok());
            match raw.as_ref().and_then(|v| v.get("web")).and_then(|w| w.get("public_url")).and_then(|v| v.as_str()) {
                Some(u) => u.trim_end_matches('/').to_string(),
                None => {
                    let b = d.cfg().web.bind.into_iter().find(|b| !b.starts_with("unix:"))?;
                    let (h, p) = b.rsplit_once(':')?;
                    if p == "443" { format!("https://{h}") } else { format!("https://{h}:{p}") }
                }
            }
        }
    };
    Some(format!("{base}/play/{id}"))
}

fn ssh_supports_bind(version: &str) -> bool {
    // "OpenSSH_9.9p1, …" → ≥ 8.9
    let v = version.strip_prefix("OpenSSH_").unwrap_or("");
    let mut it = v.split(|c: char| !c.is_ascii_digit()).filter(|s| !s.is_empty()).map(|s| s.parse::<u32>().unwrap_or(0));
    let (a, b) = (it.next().unwrap_or(0), it.next().unwrap_or(0));
    (a, b) >= (8, 9)
}

fn start_shell(d: &Arc<Daemon>, c: &Caller, req: &Req, s: &UnixStream) -> Result<()> {
    let Req::Shell { cols, rows, term, client_addr, conn, nonce, sshd_pid } = req else { unreachable!() };
    c.aaa()?;
    if nonce.len() < 16 || !nonce.bytes().all(|b| b.is_ascii_alphanumeric()) {
        bail!("bad nonce");
    }
    let cfg = d.cfg();
    let t = now();
    let id = swrap_core::new_id();
    let rec_dir = ensure_rec_dir(d, &c.name)?;
    let rec_path = rec_dir.join("shell").join(date_dir(t)).join(format!("{}_{}_core.swrec", fmt_basic(t), id));
    let mut header = Map::new();
    header.insert("kind".into(), "shell".into());
    for (k, v) in [
        ("origin", json!("core")),
        ("exec", json!("core")),
        ("delegated", json!(false)),
        ("aaa_user", json!(c.name)),
        ("client_addr", json!(client_addr)),
        ("conn", json!(conn)),
        ("cols", json!(cols)),
        ("rows", json!(rows)),
        ("term", json!(term)),
        ("config_rev", json!(d.config_rev())),
        ("record_input", json!(false)),
    ] {
        header.insert(k.into(), v);
    }
    let spec = WorkerSpec {
        mode: "shell".into(),
        id: id.clone(),
        aaa_user: c.name.clone(),
        uid: c.uid,
        rec_path: rec_path.to_string_lossy().into(),
        session_dir: String::new(),
        header,
        argv: vec![],
        cols: *cols,
        rows: *rows,
        term: term.clone(),
        nonce: nonce.clone(),
        record_input: false,
        signer: "core".into(),
        recsign_key: d.paths.recsign().join("ed25519.key").to_string_lossy().into(),
        rec_cfg: cfg.rec.clone(),
        live_marker: d.paths.live().join(&id).to_string_lossy().into(),
        banner: view_url(d, Node::Core, &id).map(|u| format!("swrap: view {u}")).unwrap_or_default(),
        sshd_pid: *sshd_pid,
        ai: None,
        sftp: None,
    };
    let pid = spawn_worker(d, &spec, s)?;
    d.audit_event(&c.name, "shell.start", "core", "", "ok", json!({"client_addr": client_addr, "worker_pid": pid}), &id);
    Ok(())
}

/// Spawn `swrapd worker` as the swrap user, in its own session, with the client connection on fd 3.
pub(crate) fn spawn_worker(d: &Daemon, spec: &WorkerSpec, s: &UnixStream) -> Result<u32> {
    spawn_worker_ex(d, spec, s, false)
}

/// `start_privileged`: swai workers start as root to set up the sandbox (a separate uid) and
/// drop to swrap themselves before reading anything from the client.
pub fn spawn_worker_ex(d: &Daemon, spec: &WorkerSpec, s: &UnixStream, start_privileged: bool) -> Result<u32> {
    std::fs::create_dir_all(d.paths.live())?;
    let exe = std::env::current_exe()?;
    let fd = s.as_raw_fd();
    let (uid, gid) = (d.swrap_uid, d.swrap_gid);
    let admin_gid = d.admin_gid;
    let mut cmd = Command::new(exe);
    cmd.arg("worker")
        .env_clear()
        .env("PATH", "/usr/bin:/usr/sbin")
        .env("SWRAP_ROOT", &d.paths.root)
        .env("SWRAP_RUN", &d.paths.run)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let fl = libc::fcntl(3, libc::F_GETFD);
            libc::fcntl(3, libc::F_SETFD, fl & !libc::FD_CLOEXEC);
            libc::setsid();
            if start_privileged {
                return Ok(());
            }
            let groups = [gid, admin_gid];
            if libc::setgroups(2, groups.as_ptr()) != 0 || libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().context("spawn worker")?;
    child.stdin.take().unwrap().write_all(&serde_json::to_vec(spec)?)?;
    let pid = child.id();
    // Reap in the background (workers normally outlive this thread only across restarts).
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(pid)
}
