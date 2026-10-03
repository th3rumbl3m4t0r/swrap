//! Host lifecycle (spec 10.2–10.4): swadd, swenroll, swdel. Everything runs on core.
//! Remote commands go through the same per-session filtering agent as interactive sessions,
//! run as the `swrap` user, and are recorded as runs under `runs/`.

use crate::agent::{self, Policy, SessionAgent};
use crate::daemon::{Caller, Console, Daemon};
use anyhow::{bail, Context, Result};
use clap::Parser;
use serde_json::{json, Map};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use swrap_core::api::Resp;
use swrap_core::config::{Account, Host, HostState, Profile, Route};
use swrap_core::paths::safe_component;
use swrap_core::time::{date_dir, fmt_basic, fmt_utc_secs, now};
use swrap_vault::{Dek, Vault};

pub fn run(d: &Arc<Daemon>, c: &Caller, cmd: &str, argv: Vec<String>, con: &Console) -> Result<Resp> {
    let fixed: Vec<String> = argv
        .iter()
        .map(|a| if a.len() > 2 && a.starts_with('-') && !a.starts_with("--") && a[1..].chars().all(|c| c.is_ascii_lowercase() || c == '-') { format!("-{a}") } else { a.clone() })
        .collect();
    match cmd {
        "swadd" => swadd(d, c, Swadd::try_parse_from(fixed)?, con),
        "swenroll" => swenroll(d, c, Swenroll::try_parse_from(fixed)?, con),
        "swdel" => swdel(d, c, Swdel::try_parse_from(fixed)?, con),
        _ => bail!("unknown"),
    }
}

// ---------------------------------------------------------------- vault key generation

/// Generate a key with the profile's ssh-keygen in a private tmpfs dir, verify `ssh-keygen -y`
/// reproduces the .pub, encrypt into the vault, unlink the plaintext. Returns the .pub line.
pub fn gen_vault_key(d: &Daemon, dek: &Dek, enc_path: &Path, algo: &str, comment: &str) -> Result<String> {
    gen_vault_key_with(d, dek, enc_path, algo, comment, "/usr/bin/ssh-keygen", 4096)
}

pub fn gen_vault_key_with(d: &Daemon, dek: &Dek, enc_path: &Path, algo: &str, comment: &str, keygen: &str, rsa_bits: u32) -> Result<String> {
    let tmp = d.paths.run.join("keygen").join(swrap_core::new_id());
    std::fs::create_dir_all(&tmp)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700))?;
    let key = tmp.join("k");
    let res = (|| -> Result<String> {
        let (t, extra): (&str, Vec<String>) = match algo {
            "ssh-ed25519" => ("ed25519", vec![]),
            "ecdsa-sha2-nistp256" => ("ecdsa", vec!["-b".into(), "256".into()]),
            "rsa-sha2-512" | "rsa-sha2-256" | "ssh-rsa" => ("rsa", vec!["-b".into(), rsa_bits.to_string()]),
            other => bail!("unsupported key algorithm {other}"),
        };
        let mut c = Command::new(keygen);
        c.args(["-q", "-t", t]).args(&extra).args(["-N", "", "-C", comment, "-f"]).arg(&key);
        let o = c.output()?;
        if !o.status.success() {
            bail!("ssh-keygen: {}", String::from_utf8_lossy(&o.stderr));
        }
        let pubtxt = std::fs::read_to_string(tmp.join("k.pub"))?;
        let y = Command::new(keygen).arg("-y").arg("-f").arg(&key).output()?;
        let derived = String::from_utf8_lossy(&y.stdout);
        let norm = |s: &str| s.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
        if norm(&derived) != norm(&pubtxt) {
            bail!("ssh-keygen -y does not reproduce the public key");
        }
        let private = zeroize::Zeroizing::new(std::fs::read(&key)?);
        let fp = agent::fingerprint_of_pub_line(&pubtxt).unwrap_or_default();
        let v = Vault::new(&d.paths, d.owner());
        v.put(dek, enc_path, &fp, &private)?;
        let pub_path = PathBuf::from(enc_path.to_string_lossy().replace(".enc", ".pub"));
        swrap_core::atomic::write(&pub_path, pubtxt.as_bytes(), 0o640, d.owner())?;
        v.manifest_update()?;
        Ok(pubtxt.trim().to_string())
    })();
    // Unlink plaintext whatever happened (tmpfs).
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&key) {
        let len = f.metadata().map(|m| m.len()).unwrap_or(0) as usize;
        let _ = f.write_all(&vec![0u8; len]);
    }
    let _ = std::fs::remove_dir_all(&tmp);
    res
}

const ENROLL_ALGOS: [(&str, &str); 3] = [("ssh-ed25519", "ed25519"), ("ecdsa-sha2-nistp256", "ecdsa"), ("rsa-sha2-512", "rsa")];

fn enroll_key_path(d: &Daemon, short: &str) -> PathBuf {
    d.paths.vault_keys().join("enroll").join(format!("id_{short}.enc"))
}

fn ensure_enroll_keys(d: &Daemon) -> Result<Vec<String>> {
    let mut out = vec![];
    for (algo, short) in ENROLL_ALGOS {
        let enc = enroll_key_path(d, short);
        let pubp = PathBuf::from(enc.to_string_lossy().replace(".enc", ".pub"));
        if !pubp.exists() {
            d.with_dek(|dek| gen_vault_key(d, dek, &enc, algo, &format!("swrap-enroll-{short}")))?;
        }
        out.push(std::fs::read_to_string(&pubp)?.trim().to_string());
    }
    Ok(out)
}

// ---------------------------------------------------------------- remote execution

pub struct RemoteOut {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
    pub ssh_log: String,
    /// Raw bytes (capped by `RemoteOpts::cap`); `stdout`/`stderr` are their lossy UTF-8 views.
    pub raw_out: Vec<u8>,
    pub raw_err: Vec<u8>,
    /// Bytes beyond the cap that were read and dropped.
    pub dropped: u64,
    pub timed_out: bool,
}

/// Limits for one remote command (swai tool calls). Defaults: no timeout, no cap.
#[derive(Clone, Copy, Default)]
pub struct RemoteOpts {
    pub timeout: Option<Duration>,
    /// Max bytes kept per stream (0 = unlimited).
    pub cap: usize,
}

impl RemoteOut {
    /// Short diagnosis: stderr, else the last meaningful ssh.log lines.
    pub fn why(&self) -> String {
        let e = self.stderr.trim();
        if !e.is_empty() {
            return e.lines().last().unwrap_or(e).to_string();
        }
        let lines: Vec<&str> = self
            .ssh_log
            .lines()
            .filter(|l| !l.contains("debug1: channel") && !l.trim().is_empty())
            .collect();
        lines.iter().rev().take(4).rev().cloned().collect::<Vec<_>>().join(" | ")
    }
}

/// Run a command on a host as `ruser` using the vault key at `enc` through a filtering agent.
/// The output is also recorded into `rec` (a run swrec) when given.
#[allow(clippy::too_many_arguments)]
pub fn remote(d: &Arc<Daemon>, who: &str, host: &Host, ruser: &str, enc: &Path, profile: &Profile, known_hosts: &str, remote_cmd: &str, stdin: &[u8], rec: Option<&mut swrec::Writer>) -> Result<RemoteOut> {
    remote_ex(d, who, host, ruser, enc, profile, known_hosts, remote_cmd, stdin, rec, RemoteOpts::default())
}

/// `remote` with a timeout (ssh is killed; the remote side should also bound itself) and caps.
#[allow(clippy::too_many_arguments)]
pub fn remote_ex(d: &Arc<Daemon>, who: &str, host: &Host, ruser: &str, enc: &Path, profile: &Profile, known_hosts: &str, remote_cmd: &str, stdin: &[u8], rec: Option<&mut swrec::Writer>, opts: RemoteOpts) -> Result<RemoteOut> {
    remote_stream(d, who, host, ruser, enc, profile, known_hosts, remote_cmd, stdin, rec, opts, &mut |_, _| {})
}

/// `remote_ex` that also hands output to `on(fd, bytes)` as it arrives (fleet jobs show it live)
/// and records it as it arrives. Edge-network hosts run through edge, which returns the output
/// when the command ends: there `on` is called once per stream.
#[allow(clippy::too_many_arguments)]
pub fn remote_stream(d: &Arc<Daemon>, who: &str, host: &Host, ruser: &str, enc: &Path, profile: &Profile, known_hosts: &str, remote_cmd: &str, stdin: &[u8], rec: Option<&mut swrec::Writer>, opts: RemoteOpts, on: &mut dyn FnMut(u8, &[u8])) -> Result<RemoteOut> {
    let id = swrap_core::new_id();
    let sdir = d.paths.session_dir(&id);
    std::fs::create_dir_all(d.paths.sessions())?;
    std::fs::create_dir(&sdir)?;
    std::fs::set_permissions(&sdir, std::fs::Permissions::from_mode(0o700))?;
    std::os::unix::fs::chown(&sdir, Some(d.swrap_uid), Some(d.swrap_gid))?;
    let cleanup = scopeguard(sdir.clone());
    let pubp = PathBuf::from(enc.to_string_lossy().replace(".enc", ".pub"));
    let pub_line = std::fs::read_to_string(&pubp)?;
    let w = |p: &str, data: &str| swrap_core::atomic::write(&sdir.join(p), data.as_bytes(), 0o600, d.owner());
    w("ssh_config", &profile.ssh_config())?;
    w("known_hosts", known_hosts)?;
    w("id.pub", &pub_line)?;
    let private = d.with_dek(|dek| Vault::new(&d.paths, d.owner()).get(dek, enc))?;
    let cfg = d.cfg();
    let sa = SessionAgent::start(
        d.clone(),
        Policy {
            session_id: id.clone(),
            aaa_user: who.to_string(),
            label: host.label.clone(),
            ruser: ruser.to_string(),
            key_blob: agent::pub_blob(&pub_line).context("bad pub key")?,
            pinned: agent::pinned_blobs(known_hosts),
            max_sigs: cfg.signing.max_signatures_per_session,
            window: cfg.signing.window.exact().unwrap_or(Duration::from_secs(120)),
            require_hostbound: cfg.signing.require_hostbound,
        },
        private,
        &sdir,
    )?;
    if host.network == Route::Edge {
        // Only edge can reach this host: edge runs ssh, signing through this very agent.
        use base64::Engine;
        let plan = swrap_core::api::EdgeSession {
            id: id.clone(),
            ssh_config: profile.ssh_config(),
            known_hosts: known_hosts.to_string(),
            pub_key: pub_line.clone(),
            label: host.label.clone(),
            ssh_bin: profile.ssh_bin_for("edge").to_string(),
            argv_tail: vec![
                "-o".into(), format!("HostKeyAlias={}", host.label), "-o".into(), "ConnectTimeout=15".into(),
                "-T".into(), "-p".into(), host.port.to_string(), format!("{ruser}@{}", host.address), "--".into(), remote_cmd.to_string(),
            ],
            ..Default::default()
        };
        let secs = opts.timeout.map(|t| t.as_secs().max(1)).unwrap_or(600);
        let job = swrap_core::api::EdgeJob::Exec { id: id.clone(), plan, stdin_b64: base64::engine::general_purpose::STANDARD.encode(stdin), timeout_secs: secs };
        let res = crate::edge_jobs::submit(job, Duration::from_secs(secs + 20));
        sa.shutdown();
        drop(cleanup);
        let v = res?;
        let stdout = base64::engine::general_purpose::STANDARD.decode(v["stdout_b64"].as_str().unwrap_or("")).unwrap_or_default();
        let stderr = v["stderr"].as_str().unwrap_or("").to_string();
        on(1, &stdout);
        on(2, stderr.as_bytes());
        if let Some(r) = rec {
            r.output_fd(1, &stdout)?;
            r.output_fd(2, stderr.as_bytes())?;
            r.flush_pending()?;
        }
        let mut stdout = stdout;
        let mut dropped = 0u64;
        if opts.cap > 0 && stdout.len() > opts.cap {
            dropped = (stdout.len() - opts.cap) as u64;
            stdout.truncate(opts.cap);
        }
        let code = v["code"].as_i64().unwrap_or(255) as i32;
        return Ok(RemoteOut {
            code,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            raw_err: stderr.as_bytes().to_vec(),
            stderr,
            ssh_log: v["ssh_log"].as_str().unwrap_or("").to_string(),
            raw_out: stdout,
            dropped,
            timed_out: v["timed_out"].as_bool().unwrap_or(false),
        });
    }
    let log = sdir.join("ssh.log");
    let mut c = Command::new(profile.ssh_bin_for("core"));
    c.arg("-F").arg(sdir.join("ssh_config"))
        .arg("-E").arg(&log)
        .args(["-o", "LogLevel=DEBUG1"])
        .arg("-o").arg(format!("IdentityAgent={}", sdir.join("agent.sock").display()))
        .args(["-o", "IdentitiesOnly=yes"])
        .arg("-i").arg(sdir.join("id.pub"))
        .arg("-o").arg(format!("UserKnownHostsFile={}", sdir.join("known_hosts").display()))
        .args(["-o", "GlobalKnownHostsFile=/dev/null"])
        .arg("-o").arg(format!("HostKeyAlias={}", host.label))
        .args(["-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no", "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
            "-o", "ClearAllForwardings=yes", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-T"])
        .arg("-p").arg(host.port.to_string())
        .arg(format!("{ruser}@{}", host.address))
        .arg("--")
        .arg(remote_cmd)
        .env_clear()
        .env("PATH", "/usr/bin:/usr/sbin")
        .env("HOME", &sdir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let (uid, gid) = (d.swrap_uid, d.swrap_gid);
    unsafe {
        c.pre_exec(move || {
            libc::setgroups(0, std::ptr::null());
            if libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = c.spawn().context("spawn ssh")?;
    let mut sin = child.stdin.take().unwrap();
    let data = stdin.to_vec();
    let wt = std::thread::spawn(move || {
        let _ = sin.write_all(&data);
    });
    // Both streams arrive over one channel in the order they were read.
    let (tx, rx) = std::sync::mpsc::channel::<(u8, Vec<u8>)>();
    let pump = |fd: u8, mut r: Box<dyn Read + Send>, tx: std::sync::mpsc::Sender<(u8, Vec<u8>)>| {
        std::thread::spawn(move || {
            let mut buf = [0u8; 65536];
            while let Ok(n) = r.read(&mut buf) {
                if n == 0 || tx.send((fd, buf[..n].to_vec())).is_err() {
                    break;
                }
            }
        })
    };
    let t_out = pump(1, Box::new(child.stdout.take().unwrap()), tx.clone());
    let t_err = pump(2, Box::new(child.stderr.take().unwrap()), tx);
    let cap = opts.cap;
    let (mut out_b, mut err_b, mut dropped) = (Vec::new(), Vec::new(), 0u64);
    let mut rec = rec;
    let deadline = opts.timeout.map(|t| Instant::now() + t);
    let mut timed_out = false;
    let mut status = None;
    loop {
        match rx.recv_timeout(Duration::from_millis(20)) {
            Ok((fd, chunk)) => {
                on(fd, &chunk);
                if let Some(r) = rec.as_deref_mut() {
                    r.output_fd(fd, &chunk)?;
                }
                let keep = if fd == 1 { &mut out_b } else { &mut err_b };
                let room = if cap == 0 { chunk.len() } else { cap.saturating_sub(keep.len()).min(chunk.len()) };
                keep.extend_from_slice(&chunk[..room]);
                dropped += (chunk.len() - room) as u64;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break, // both streams closed
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
        }
        if let Some(r) = rec.as_deref_mut() {
            r.tick()?;
        }
        if status.is_none() {
            status = child.try_wait()?;
        }
        if status.is_none() && !timed_out && deadline.map(|dl| Instant::now() >= dl).unwrap_or(false) {
            timed_out = true;
            let _ = child.kill();
        }
    }
    let status = match status {
        Some(s) => s,
        None => child.wait()?,
    };
    let _ = (t_out.join(), t_err.join(), wt.join());
    sa.shutdown();
    let ssh_log = std::fs::read_to_string(&log).unwrap_or_default();
    drop(cleanup);
    if let Some(r) = rec {
        r.flush_pending()?;
    }
    Ok(RemoteOut {
        code: status.code().unwrap_or(255),
        stdout: String::from_utf8_lossy(&out_b).into_owned(),
        stderr: String::from_utf8_lossy(&err_b).into_owned(),
        ssh_log,
        raw_out: out_b,
        raw_err: err_b,
        dropped,
        timed_out,
    })
}

struct DirGuard(PathBuf);
impl Drop for DirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn scopeguard(p: PathBuf) -> DirGuard {
    DirGuard(p)
}

/// A run recording: `runs/YYYY/MM/DD/<ts>_<ulid>_<kind>/` with meta.toml and per-host swrec.
pub struct Run {
    pub dir: PathBuf,
    pub id: String,
}

impl Run {
    pub fn new(d: &Daemon, kind: &str, who: &str, targets: &str, extra: serde_json::Value) -> Result<Self> {
        let t = now();
        let id = swrap_core::new_id();
        let dir = d.paths.runs().join(date_dir(t)).join(format!("{}_{}_{}", fmt_basic(t), id, kind));
        swrap_core::atomic::mkdirs(&dir, 0o2750, swrap_core::atomic::Owner::new(d.swrap_uid, d.admin_gid))?;
        // TOML has no null: drop them.
        let mut extra = extra;
        if let Some(o) = extra.as_object_mut() {
            o.retain(|_, v| !v.is_null());
        }
        let meta = json!({"id": id, "kind": kind, "who": who, "targets": targets, "start": swrap_core::time::fmt_utc(t), "extra": extra});
        let tv: toml::Value = serde_json::from_value(meta)?;
        swrap_core::atomic::write(&dir.join("meta.toml"), toml::to_string_pretty(&tv)?.as_bytes(), 0o640, swrap_core::atomic::Owner::new(d.swrap_uid, d.admin_gid))?;
        Ok(Run { dir, id })
    }

    pub fn host_writer(&self, d: &Daemon, host: &Host, ruser: &str, who: &str, cmd: &str) -> Result<swrec::Writer> {
        let mut h = Map::new();
        for (k, v) in [
            ("kind", json!("run")), ("origin", json!("core")), ("exec", json!("core")), ("delegated", json!(false)),
            ("aaa_user", json!(who)), ("label", json!(host.label)), ("addr", json!(host.address)), ("port", json!(host.port)),
            ("ruser", json!(ruser)), ("run", json!(self.id)), ("cmd", json!(cmd)), ("config_rev", json!(d.config_rev())),
        ] {
            h.insert(k.into(), v);
        }
        let p = self.dir.join(format!("{}.swrec", host.label));
        let w = swrec::Writer::create(&p, &format!("{}-{}", self.id, host.label), h, swrec::WriterOpts::default())?;
        let _ = std::os::unix::fs::chown(&p, Some(d.swrap_uid), Some(d.admin_gid));
        Ok(w)
    }
}

/// Source addresses for `from=` on a managed host (IP literals only: sshd matches hostnames in
/// `from=` only with UseDNS, which is off by default). Core connects from its own interface
/// addresses (LAN hosts) or its configured egress addresses (public hosts); edge only ever
/// connects to `route = edge` hosts.
pub fn from_addrs(d: &Daemon, host: &Host) -> Vec<String> {
    let route = host.route;
    use std::net::ToSocketAddrs;
    let cfg = d.cfg();
    let mut v: Vec<String> = vec![];
    if let Ok(o) = Command::new("ip").args(["-o", "addr", "show", "scope", "global"]).output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            // Skip container/virtual bridges (podman, docker, libvirt, veth pairs).
            let ifname = l.split_whitespace().nth(1).unwrap_or("");
            if ["podman", "cni", "docker", "virbr", "veth", "br-"].iter().any(|p| ifname.starts_with(p)) {
                continue;
            }
            let mut it = l.split_whitespace();
            while let Some(t) = it.next() {
                if t == "inet" || t == "inet6" {
                    if let Some(a) = it.next().and_then(|a| a.split('/').next()) {
                        v.push(a.to_string());
                    }
                }
            }
        }
    }
    if host.network == Route::Edge {
        v.clear(); // core never connects to edge-network hosts
    }
    for e in cfg.network.core_egress_addresses.iter().filter(|_| host.network == Route::Core) {
        if e.parse::<std::net::IpAddr>().is_ok() {
            v.push(e.clone());
        }
    }
    if route == Route::Edge || host.network == Route::Edge {
        // Addresses edge reported (private ones for its own networks) + its public name.
        if let Ok(st) = std::fs::read_to_string(crate::edge_api::link_state_path(d)) {
            if let Ok(j) = serde_json::from_str::<serde_json::Value>(&st) {
                for a in j["edge_addrs"].as_array().into_iter().flatten().filter_map(|x| x.as_str()) {
                    v.push(a.to_string());
                }
            }
        }
        let e = crate::snapshot::edge_toml(d);
        for k in ["link_address", "address"] {
            if let Some(a) = e.get(k).and_then(|x| x.as_str()) {
                if let Ok(it) = (a, 22).to_socket_addrs() {
                    for sa in it {
                        // NAT64-synthesised addresses (64:ff9b::/96) are not what the host sees.
                        let ip = sa.ip();
                        if let std::net::IpAddr::V6(v6) = ip {
                            if v6.segments()[0] == 0x64 && v6.segments()[1] == 0xff9b {
                                continue;
                            }
                        }
                        v.push(ip.to_string());
                    }
                }
            }
        }
    }
    v.sort();
    v.dedup();
    if !cfg.network.from_restriction {
        v.clear();
    }
    v
}

// ---------------------------------------------------------------- swadd

#[derive(Parser, Debug)]
#[command(name = "swadd", about = "Add a host (state pending) and print the enrollment snippet")]
struct Swadd {
    #[arg(long)]
    host: String,
    #[arg(long)]
    label: String,
    #[arg(long, default_value_t = 22)]
    port: u16,
    #[arg(long)]
    tag: Vec<String>,
    #[arg(long)]
    profile: Option<String>,
    #[arg(long)]
    route: Option<String>,
    /// Which node's network the host is in: core or edge. Default for private addresses:
    /// the node you are logged into.
    #[arg(long)]
    network: Option<String>,
    /// Poll every PT10S and run swenroll when the key is installed (needs --fingerprint or --yes).
    #[arg(long)]
    wait: bool,
    #[arg(long)]
    fingerprint: Option<String>,
    #[arg(long)]
    yes: bool,
}

fn enroll_snippet(d: &Daemon, h: &Host) -> Result<String> {
    let cfg = d.cfg();
    let keys = ensure_enroll_keys(d)?;
    let expiry = cfg.general.enroll_key_ttl.after(now()).strftime("%Y%m%d").to_string();
    let from = from_addrs(d, h);
    let opts = if !from.is_empty() { format!("from=\"{}\",expiry-time=\"{expiry}\",restrict", from.join(",")) } else { format!("expiry-time=\"{expiry}\",restrict") };
    let mut t = format!("host {} (route {}, state pending). Paste on the target as root:\n\n", h.label, if h.route == Route::Core { "core" } else { "edge" });
    t += "install -d -m 700 /root/.ssh && sed -i '/ swrap-enroll-/d' /root/.ssh/authorized_keys 2>/dev/null; cat >> /root/.ssh/authorized_keys <<'EOF'\n";
    for k in &keys {
        t += &format!("{opts} {k}\n");
    }
    t += "EOF\nchmod 600 /root/.ssh/authorized_keys; restorecon -R /root/.ssh 2>/dev/null || true\n\n";
    if from.is_empty() && cfg.network.from_restriction {
        t += "note: no source addresses known, so no from= restriction was added\n";
    }
    t += &format!("then run: swenroll {}\n", h.label);
    Ok(t)
}

fn swadd(d: &Arc<Daemon>, c: &Caller, a: Swadd, con: &Console) -> Result<Resp> {
    if !safe_component(&a.label) || a.label.contains('.') && a.label.len() < 2 {
        bail!("bad label {:?}", a.label);
    }
    if a.host.is_empty() || a.host.contains(char::is_whitespace) || a.host.starts_with('-') {
        bail!("bad host address");
    }
    let cfg = d.cfg();
    let profile = a.profile.clone().unwrap_or(cfg.general.default_profile.clone());
    Profile::load(&d.paths, &profile)?;
    let internal = swrap_core::net::address_is_internal(&a.host, &cfg.network.internal_networks);
    let network = match a.network.as_deref() {
        Some("core") => Route::Core,
        Some("edge") => Route::Edge,
        Some(o) => bail!("--network takes core or edge, not {o}"),
        // A private address belongs to the network of the node you are logged into.
        None if internal && c.origin == swrap_core::rbac::Node::Edge => Route::Edge,
        None => Route::Core,
    };
    let route = match a.route.as_deref() {
        Some("core") => Route::Core,
        Some("edge") => Route::Edge,
        Some(o) => bail!("--route takes core or edge, not {o}"),
        None if network == Route::Edge => Route::Edge,
        None => {
            if internal { Route::Core } else { Route::Edge }
        }
    };
    if network == Route::Edge && route == Route::Core {
        bail!("a host in edge's network can only be routed via edge");
    }
    let keys = ensure_enroll_keys(d)?;
    {
        let _g = d.config_lock.lock().unwrap();
        if let Ok(h) = Host::load(&d.paths, &a.label) {
            if h.state == HostState::Pending && h.address == a.host && h.port == a.port {
                // Same pending host: just print a fresh snippet.
                drop(_g);
                return Ok(Resp::text(enroll_snippet(d, &h)?));
            }
            if h.state != HostState::Removed {
                bail!("host {} already exists ({:?})", a.label, h.state);
            }
        }
        let h = Host {
            label: a.label.clone(),
            address: a.host.clone(),
            port: a.port,
            route,
            edge_allowed: true,
            tags: a.tag.clone(),
            profile,
            default_user: "root".into(),
            state: HostState::Pending,
            enrolled: String::new(),
            created: fmt_utc_secs(now()),
            hostkey_fingerprints: vec![],
            accounts: vec![],
            enroll_progress: vec![],
            network,
            ai_allowed: false,
        };
        d.write_config(&format!("hosts/{}.toml", a.label), &h.to_toml())?;
        d.commit(&format!("swadd {} {} by {}", a.label, a.host, c.name))?;
    }
    d.audit_event(&c.name, "host.add", &a.label, "", "ok", json!({"address": a.host, "route": route}), "");
    let h = Host::load(&d.paths, &a.label)?;
    let t = enroll_snippet(d, &h)?;
    let _ = keys;
    if a.wait {
        con.out(t.clone());
        con.out("waiting for the enrollment key (polling every PT10S)…");
        let ttl = cfg.general.enroll_key_ttl.exact().unwrap_or(Duration::from_secs(14 * 86400));
        let t0 = std::time::Instant::now();
        loop {
            let hs = keyscan(&a.host, a.port, network).unwrap_or_default();
            if !hs.is_empty() {
                let r = swenroll(d, c, Swenroll { label: a.label.clone(), fingerprint: a.fingerprint.clone(), yes: a.yes, allow_legacy: false, probe_only: true }, &Console::null());
                if r.map(|r| r.ok).unwrap_or(false) {
                    return swenroll(d, c, Swenroll { label: a.label, fingerprint: a.fingerprint, yes: a.yes, allow_legacy: false, probe_only: false }, con);
                }
            }
            if t0.elapsed() > ttl {
                bail!("enrollment key expired before it was installed");
            }
            std::thread::sleep(Duration::from_secs(10));
        }
    }
    Ok(Resp::text(t))
}

// ---------------------------------------------------------------- swenroll

#[derive(Parser, Debug)]
#[command(name = "swenroll", about = "Enroll a pending host (runs on core)")]
struct Swenroll {
    label: String,
    /// Expected host key fingerprint (SHA256:…). Without it (or --yes) the fingerprints are shown.
    #[arg(long)]
    fingerprint: Option<String>,
    #[arg(long)]
    yes: bool,
    #[arg(long)]
    allow_legacy: bool,
    #[arg(long, hide = true)]
    probe_only: bool,
}

fn keyscan(addr: &str, port: u16, network: Route) -> Result<Vec<(String, String)>> {
    let text = if network == Route::Edge {
        let v = crate::edge_jobs::submit(swrap_core::api::EdgeJob::Keyscan { id: swrap_core::new_id(), addr: addr.into(), port }, Duration::from_secs(45))?;
        v["stdout"].as_str().unwrap_or("").to_string()
    } else {
        let o = Command::new("ssh-keyscan").args(["-T", "10", "-p", &port.to_string(), "-t", "ed25519,ecdsa,rsa", addr]).output()?;
        String::from_utf8_lossy(&o.stdout).into_owned()
    };
    let mut v = vec![];
    for l in text.lines() {
        if l.starts_with('#') || l.trim().is_empty() {
            continue;
        }
        let mut it = l.split_whitespace();
        let (_h, Some(t), Some(b)) = (it.next(), it.next(), it.next()) else { continue };
        v.push((t.to_string(), b.to_string()));
    }
    Ok(v)
}

const PROBE: &str = r#"set +e
echo "== os-release"; cat /etc/os-release 2>/dev/null
echo "== uname"; uname -r; uname -m
echo "== sshd"; sshd -T 2>/dev/null | grep -Ei '^(pubkeyacceptedalgorithms|kexalgorithms|ciphers|permitrootlogin|acceptenv) '
echo "== rpm"; rpm -q openssh-server 2>/dev/null
echo "== dnf"; if command -v dnf5 >/dev/null 2>&1; then echo dnf5; elif command -v dnf >/dev/null 2>&1; then echo dnf4; else echo none; fi
echo "== selinux"; getenforce 2>/dev/null || echo unknown
echo "== end"
"#;

fn section<'a>(out: &'a str, name: &str) -> Vec<&'a str> {
    let mut on = false;
    let mut v = vec![];
    for l in out.lines() {
        if let Some(n) = l.strip_prefix("== ") {
            on = n == name;
            continue;
        }
        if on {
            v.push(l);
        }
    }
    v
}

const PROFILE_SH: &str = r#"# swrap shell integration (installed by swenroll). Emits command records for recorded sessions.
if [ -n "${SWRAP_SESSION:-}" ] && [ -n "${BASH_VERSION:-}" ] && [[ $- == *i* ]]; then
  __swrap_nonce="${SWRAP_SESSION#*:}"
  __swrap_pc() {
    local ec=$? c
    c="$(HISTTIMEFORMAT= history 1)"
    if [ -n "$c" ] && [ "$c" != "${__swrap_last:-}" ]; then
      __swrap_last="$c"
      printf '\033]7719;%s;%s\a' "$__swrap_nonce" "$(printf '{"cmd":%s,"cwd":%s,"exit":%d}' "$(__swrap_json "$c")" "$(__swrap_json "$PWD")" "$ec" | base64 -w0)"
    fi
    return $ec
  }
  __swrap_json() { local s=${1//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}; s=${s//$'\t'/\\t}; s=${s//$'\r'/\\r}; printf '"%s"' "$s"; }
  __swrap_last="$(HISTTIMEFORMAT= history 1)"
  PROMPT_COMMAND="__swrap_pc${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
fi
"#;

pub fn profile_snippet() -> &'static str {
    PROFILE_SH
}

fn swenroll(d: &Arc<Daemon>, c: &Caller, a: Swenroll, con: &Console) -> Result<Resp> {
    let mut host = Host::load(&d.paths, &a.label)?;
    if host.state == HostState::Active && !a.probe_only {
        bail!("{} is already enrolled", a.label);
    }
    if d.is_sealed() {
        bail!("swrap: vault sealed since {} — an admin must log in with password", d.disp(*d.sealed_since.lock().unwrap()));
    }
    // 1. Pin host keys.
    let scanned = keyscan(&host.address, host.port, host.network)?;
    if scanned.is_empty() {
        bail!("no host keys from {}:{} (unreachable?)", host.address, host.port);
    }
    let fps: Vec<(String, String, String)> = scanned
        .iter()
        .map(|(t, b)| (t.clone(), b.clone(), agent::fingerprint_of_pub_line(&format!("{t} {b}")).unwrap_or_default()))
        .collect();
    let listing: String = fps.iter().map(|(t, _, f)| format!("  {t:<22} {f}\n")).collect();
    let accepted = match (&a.fingerprint, a.yes) {
        (Some(f), _) => fps.iter().any(|(_, _, x)| x == f),
        (None, true) => true,
        (None, false) => {
            return Ok(Resp {
                ok: false,
                exit: 3,
                data: json!({"fingerprints": fps.iter().map(|x| &x.2).collect::<Vec<_>>()}),
                text: format!("host keys offered by {}:{}:\n{listing}confirm with: swenroll {} --fingerprint SHA256:…  (or --yes)\n", host.address, host.port, a.label),
                ..Default::default()
            })
        }
    };
    if !accepted {
        bail!("fingerprint mismatch; offered:\n{listing}");
    }
    let known: String = fps.iter().map(|(t, b, _)| format!("{} {t} {b}\n", a.label)).collect();
    if fps.iter().all(|(t, _, _)| t == "ssh-rsa") {
        con.out("WARNING: the host offers only RSA host keys");
    }
    // 2. Connect with the enrollment keys (ed25519, ecdsa, rsa) and probe.
    let mut profile_names = vec![host.profile.clone()];
    for p in ["compat", "legacy"] {
        if !profile_names.iter().any(|x| x == p) && (p != "legacy" || a.allow_legacy) {
            profile_names.push(p.into());
        }
    }
    let mut connected: Option<(Profile, PathBuf, String, RemoteOut)> = None;
    let mut errors = vec![];
    'outer: for pn in &profile_names {
        let Ok(profile) = Profile::load(&d.paths, pn) else { continue };
        if crate::crypto::validate(&d.paths.run.join("caps"), &profile, "core").is_err() {
            continue;
        }
        for (_, short) in ENROLL_ALGOS {
            let enc = enroll_key_path(d, short);
            if !enc.exists() {
                continue;
            }
            let r = remote(d, &c.name, &host, "root", &enc, &profile, &known, PROBE, b"", None)?;
            if r.code == 0 && r.stdout.contains("== end") {
                connected = Some((profile, enc, short.to_string(), r));
                break 'outer;
            }
            let why = r.why();
            let log = format!("{} {}", r.stderr, r.ssh_log);
            errors.push(format!("{pn}/{short}: exit {} {}", r.code, why));
            if log.contains("Not allowed at this time") || log.contains("Connection reset") || log.contains("Too many authentication failures") {
                bail!(
                    "{}: the target refuses connections now (sshd PerSourcePenalties / MaxStartups after failed attempts). \
                     Wait a minute and run swenroll again; check the snippet's from= addresses first.\n{}",
                    a.label,
                    errors.join("\n")
                );
            }
        }
        // Another crypto profile only helps if negotiation failed, not if the key was refused.
        let negotiation = errors.iter().any(|e| e.contains("no matching") || e.contains("Unable to negotiate"));
        if !negotiation {
            break;
        }
    }
    let Some((profile, enroll_enc, enroll_short, probe)) = connected else {
        bail!("could not log in with any enrollment key: {}", errors.join("; "));
    };
    if a.probe_only {
        return Ok(Resp::text("enrollment key works\n"));
    }
    if profile.name == "legacy" {
        con.out(format!("WARNING: {} needs the legacy crypto profile", a.label));
    }
    con.out(format!("connected with enrollment key {enroll_short} (profile {})", profile.name));
    let run = Run::new(d, "enroll", &c.name, &a.label, json!({"profile": profile.name}))?;
    let mut rec = run.host_writer(d, &host, "root", &c.name, "swenroll")?;
    rec.output_fd(1, probe.stdout.as_bytes())?;
    let accepted_algs: Vec<String> = section(&probe.stdout, "sshd")
        .iter()
        .find_map(|l| l.strip_prefix("pubkeyacceptedalgorithms "))
        .map(|s| s.split(',').map(String::from).collect())
        .unwrap_or_default();
    // 4. Choose the key algorithm.
    let algo = profile
        .key_preference
        .iter()
        .find(|k| accepted_algs.is_empty() || accepted_algs.iter().any(|x| x == *k))
        .cloned()
        .context("no key algorithm acceptable to both the profile and the target")?;
    let short = match algo.as_str() {
        "ssh-ed25519" => "ed25519",
        "ecdsa-sha2-nistp256" => "ecdsa",
        _ => "rsa",
    };
    // 5. Generate the credential for (label, root).
    let enc = d.paths.host_key(&a.label, "root", &format!("id_{short}"));
    if enc.exists() {
        // Partial earlier attempt: keep the existing credential (idempotent).
        con.out("reusing credential from an earlier attempt");
    } else {
        d.with_dek(|dek| gen_vault_key_with(d, dek, &enc, &algo, &format!("swrap:{}:root", a.label), profile.keygen_bin_for("core"), profile.rsa_bits))?;
    }
    let pub_line = std::fs::read_to_string(PathBuf::from(enc.to_string_lossy().replace(".enc", ".pub")))?.trim().to_string();
    let pub_two: String = pub_line.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
    let from = from_addrs(d, &host);
    let from_opt = if !from.is_empty() { format!("from=\"{}\",", from.join(",")) } else { String::new() };
    let date = now().strftime("%Y-%m-%d").to_string();
    let line = format!("{from_opt}no-agent-forwarding,no-X11-forwarding {pub_two} swrap:{}:root:{date}", a.label);
    // 6. Install atomically (temp, fsync, rename, restorecon).
    let install = format!(
        r#"set -e; umask 077; f=/root/.ssh/authorized_keys; t=/root/.ssh/.authorized_keys.swrap.$$
install -d -m 700 /root/.ssh
{{ [ -f "$f" ] && grep -v ' swrap:{label}:root:' "$f" || true; cat; }} > "$t"
sync "$t" 2>/dev/null || sync; mv -f "$t" "$f"; restorecon "$f" 2>/dev/null || true; echo installed"#,
        label = a.label
    );
    let r = remote(d, &c.name, &host, "root", &enroll_enc, &profile, &known, &install, format!("{line}\n").as_bytes(), Some(&mut rec))?;
    if r.code != 0 {
        progress(d, &mut host, "key install failed")?;
        bail!("installing the key failed: {}", r.stderr.trim());
    }
    con.out("credential installed");
    // 7. Verify the new key in a fresh connection.
    let r = remote(d, &c.name, &host, "root", &enc, &profile, &known, "echo swrap-ok", b"", Some(&mut rec))?;
    if r.code != 0 || !r.stdout.contains("swrap-ok") {
        progress(d, &mut host, "credential installed but verification failed")?;
        bail!("new credential does not work: {}", r.stderr.trim());
    }
    con.out("credential verified");
    // 8. Remove enrollment keys and verify an enrollment-key login now fails.
    let rm = r#"set -e; f=/root/.ssh/authorized_keys; t=/root/.ssh/.authorized_keys.swrap.$$; umask 077
grep -v ' swrap-enroll-' "$f" > "$t" || true; sync; mv -f "$t" "$f"; restorecon "$f" 2>/dev/null || true; echo removed"#;
    let r = remote(d, &c.name, &host, "root", &enc, &profile, &known, rm, b"", Some(&mut rec))?;
    if r.code != 0 {
        bail!("removing the enrollment keys failed: {}", r.stderr.trim());
    }
    let r = remote(d, &c.name, &host, "root", &enroll_enc, &profile, &known, "true", b"", None)?;
    if r.code == 0 {
        progress(d, &mut host, "enrollment key still accepted after removal")?;
        bail!("enrollment key still works after removal; check {}:/root/.ssh/authorized_keys and other AuthorizedKeysFile locations", a.label);
    }
    con.out("enrollment keys removed (verified)");
    // 9. Extras: shell integration snippet + sshd drop-in (dead-man's switch rollback).
    let nonce = crate::util::random_hex(8);
    let extras = format!(
        r#"set -e
umask 022
cat > /etc/profile.d/swrap.sh.tmp <<'SWRAPEOF'
{profile_sh}SWRAPEOF
mv -f /etc/profile.d/swrap.sh.tmp /etc/profile.d/swrap.sh; restorecon /etc/profile.d/swrap.sh 2>/dev/null || true
d=/etc/ssh/sshd_config.d/05-swrap.conf
if grep -qs 'AcceptEnv SWRAP_SESSION' "$d"; then echo dropin-present; exit 0; fi
[ -f "$d" ] && cp -p "$d" "$d.swrap-prev"
printf '# managed by swrap\nAcceptEnv SWRAP_SESSION\n' > "$d.tmp"; mv -f "$d.tmp" "$d"; restorecon "$d" 2>/dev/null || true
if ! sshd -t; then rm -f "$d"; [ -f "$d.swrap-prev" ] && mv -f "$d.swrap-prev" "$d"; echo sshd-t-failed; exit 1; fi
systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || kill -HUP "$(cat /run/sshd.pid 2>/dev/null)" 2>/dev/null || true
# dead man's switch: roll back unless core confirms with a fresh connection
( for i in $(seq 1 60); do [ -f /run/swrap-confirm-{nonce} ] && {{ rm -f /run/swrap-confirm-{nonce} "$d.swrap-prev"; exit 0; }}; sleep 1; done
  rm -f "$d"; [ -f "$d.swrap-prev" ] && mv -f "$d.swrap-prev" "$d"; systemctl reload sshd 2>/dev/null || true ) </dev/null >/dev/null 2>&1 &
echo dropin-pending
"#,
        profile_sh = PROFILE_SH
    );
    let r = remote(d, &c.name, &host, "root", &enc, &profile, &known, &extras, b"", Some(&mut rec))?;
    if r.code != 0 {
        con.out(format!("WARNING: installing shell integration/sshd drop-in failed: {}", r.stdout.trim()));
    } else if r.stdout.contains("dropin-pending") {
        std::thread::sleep(Duration::from_secs(1));
        let r2 = remote(d, &c.name, &host, "root", &enc, &profile, &known, &format!("touch /run/swrap-confirm-{nonce} && echo confirmed"), b"", Some(&mut rec))?;
        if r2.code == 0 {
            con.out("sshd drop-in applied and verified with a new connection");
        } else {
            con.out("WARNING: new connection after sshd reload failed; the host rolls the drop-in back within PT60S");
        }
    }
    let integration = r.code == 0;
    // 10. Activate.
    let os = section(&probe.stdout, "os-release").iter().find_map(|l| l.strip_prefix("PRETTY_NAME=")).map(|s| s.trim_matches('"').to_string()).unwrap_or_default();
    {
        let _g = d.config_lock.lock().unwrap();
        let mut h = Host::load(&d.paths, &a.label)?;
        h.state = HostState::Active;
        h.enrolled = fmt_utc_secs(now());
        h.profile = profile.name.clone();
        h.hostkey_fingerprints = fps.iter().map(|x| x.2.clone()).collect();
        h.accounts.retain(|x| x.name != "root");
        h.accounts.push(Account {
            name: "root".into(),
            key_algo: algo.clone(),
            key_fingerprint: agent::fingerprint_of_pub_line(&pub_line).unwrap_or_default(),
            created: fmt_utc_secs(now()),
            sudo: "n/a".into(),
            managed_by_swrap: false,
            integration,
        });
        h.enroll_progress.clear();
        d.write_config(&format!("known_hosts/{}", a.label), &known)?;
        d.write_config(&format!("hosts/{}.toml", a.label), &h.to_toml())?;
        d.commit(&format!("swenroll {} ({os}) by {}", a.label, c.name))?;
    }
    rec.end("exit", Some(0), None)?;
    d.audit_event(&c.name, "host.enroll", &a.label, "root", "ok", json!({"algo": algo, "profile": profile.name, "os": os, "run": run.id}), &run.id);
    Ok(Resp::text(format!("{} enrolled: {os}, root key {algo}, profile {}\n", a.label, profile.name)))
}

fn progress(d: &Daemon, host: &mut Host, what: &str) -> Result<()> {
    let _g = d.config_lock.lock().unwrap();
    host.enroll_progress.push(format!("{} {what}", fmt_utc_secs(now())));
    d.write_config(&format!("hosts/{}.toml", host.label), &host.to_toml())?;
    d.commit(&format!("swenroll {} progress: {what}", host.label))?;
    Ok(())
}

// ---------------------------------------------------------------- swdel

#[derive(Parser, Debug)]
#[command(name = "swdel", about = "Remove a host (recordings are never deleted)")]
struct Swdel {
    label: String,
    #[arg(long)]
    keep_keys_on_host: bool,
    /// Also delete the host's config entry and pinned keys so the label can be reused cleanly
    /// (recordings and archived credentials are kept).
    #[arg(long)]
    purge: bool,
}

fn swdel(d: &Arc<Daemon>, c: &Caller, a: Swdel, con: &Console) -> Result<Resp> {
    let host = Host::load(&d.paths, &a.label)?;
    if !a.keep_keys_on_host && host.state == HostState::Active {
        let profile = Profile::load(&d.paths, &host.profile)?;
        let known = std::fs::read_to_string(d.paths.known_hosts(&a.label)).unwrap_or_default();
        for acct in &host.accounts {
            let Some((enc, _)) = crate::session::credential(d, &a.label, &acct.name) else { continue };
            let home = if acct.name == "root" { "/root".to_string() } else { format!("~{}", acct.name) };
            let cmd = format!(
                r#"f={home}/.ssh/authorized_keys; t=$f.swrap.$$; grep -v ' swrap:{label}:{u}:' "$f" > "$t"; mv -f "$t" "$f"; restorecon "$f" 2>/dev/null; echo removed"#,
                label = a.label,
                u = acct.name
            );
            match remote(d, &c.name, &host, &acct.name, &enc, &profile, &known, &cmd, b"", None) {
                Ok(r) if r.code == 0 => con.out(format!("removed swrap key for {} on {}", acct.name, a.label)),
                Ok(r) => con.out(format!("WARNING: could not remove key for {}: {}", acct.name, r.stderr.trim())),
                Err(e) => con.out(format!("WARNING: could not remove key for {}: {e}", acct.name)),
            }
        }
    }
    // Archive credentials.
    let src = d.paths.vault_keys().join("hosts").join(&a.label);
    if src.exists() {
        let dst = d.paths.vault_keys().join("retired").join(format!("{}_{}", a.label, fmt_basic(now())));
        std::fs::create_dir_all(dst.parent().unwrap())?;
        // Re-encrypt under the new path (AAD binds the path).
        d.with_dek(|dek| {
            let v = Vault::new(&d.paths, d.owner());
            for e in walk(&src) {
                let rel = e.strip_prefix(&src).unwrap().to_path_buf();
                let to = dst.join(&rel);
                if e.to_string_lossy().ends_with(".enc") {
                    let pt = v.get(dek, &e)?;
                    v.put(dek, &to, "retired", &pt)?;
                } else {
                    std::fs::create_dir_all(to.parent().unwrap())?;
                    std::fs::copy(&e, &to)?;
                }
            }
            Ok(())
        })?;
        std::fs::remove_dir_all(&src)?;
        Vault::new(&d.paths, d.owner()).manifest_update()?;
    }
    {
        let _g = d.config_lock.lock().unwrap();
        let mut h = Host::load(&d.paths, &a.label)?;
        h.state = HostState::Removed;
        h.accounts.clear();
        if a.purge {
            let _ = std::fs::remove_file(d.paths.host(&a.label));
            let _ = std::fs::remove_file(d.paths.known_hosts(&a.label));
        } else {
            d.write_config(&format!("hosts/{}.toml", a.label), &h.to_toml())?;
        }
        d.commit(&format!("swdel {}{} by {}", a.label, if a.purge { " --purge" } else { "" }, c.name))?;
    }
    d.audit_event(&c.name, "host.del", &a.label, "", "ok", json!({"keep_keys_on_host": a.keep_keys_on_host}), "");
    Ok(Resp::text(format!("{} removed; credentials archived; recordings kept\n", a.label)))
}

fn walk(p: &Path) -> Vec<PathBuf> {
    let mut v = vec![];
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            if e.path().is_dir() {
                v.extend(walk(&e.path()));
            } else {
                v.push(e.path());
            }
        }
    }
    v
}
