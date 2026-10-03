//! SFTP virtual filesystem (spec 11). A non-admin login sees one directory per granted host
//! account (`web1/`, `deploy@web1/`). A worker, running as swrap like the `sw` workers, speaks
//! SFTP v3 to the client, opens `ssh -s … sftp` to a host the first time its directory is used,
//! rewrites paths and handles between the two, and records every operation as an `f` record.
//! The user's own process only relays bytes, so it never holds a host connection it could use
//! unrecorded.

use crate::agent::{self, Policy, SessionAgent};
use crate::daemon::{Caller, Daemon};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};
use swrap_core::api::{Req, Resp, SftpEntry, SftpSpec, WorkerSpec};
use swrap_core::config::{Host, Profile, Route, User};
use swrap_core::frame::{kind, read_frame, write_frame, Frame};
use swrap_core::rbac::{self, Node};
use swrap_core::time::{date_dir, fmt_basic, fmt_utc, now};
use swrec::{RecSigner, Writer};

// ---------------------------------------------------------------- daemon side

fn reg_dir(d: &Daemon) -> PathBuf {
    d.paths.run.join("sftp")
}

/// The virtual root for `user`: every host account granted from `origin` that has a
/// credential, the most privileged one under the bare label.
pub fn entries(d: &Daemon, user: &User, origin: Node) -> Vec<SftpEntry> {
    let t = now();
    let mut out = vec![];
    for h in Host::all(&d.paths).unwrap_or_default() {
        let accts: Vec<String> = rbac::granted_accounts(user, &h, origin, t).into_iter().filter(|a| crate::session::credential(d, &h.label, a).is_some()).collect();
        for (i, a) in accts.iter().enumerate() {
            let name = if i == 0 { h.label.clone() } else { format!("{a}@{}", h.label) };
            out.push(SftpEntry { name, label: h.label.clone(), ruser: a.clone() });
        }
    }
    out
}

/// `Req::Sftp`: start a worker for this connection (it answers the client itself).
pub fn start(d: Arc<Daemon>, c: Caller, req: Req, mut s: UnixStream) -> Result<()> {
    if let Err(e) = start_inner(&d, &c, &req, &s) {
        let msg = format!("{e:#}");
        let msg = if msg.starts_with("swrap:") { msg } else { format!("swrap: {msg}") };
        d.audit_event(&c.name, "sftp.refused", "core", "", "refused", json!({"error": msg}), "");
        let _ = write_frame(&mut s, &Frame::json(kind::RESP, &Resp::err(msg)));
    }
    Ok(())
}

fn start_inner(d: &Arc<Daemon>, c: &Caller, req: &Req, s: &UnixStream) -> Result<()> {
    let Req::Sftp { client_addr, conn } = req else { unreachable!() };
    let user = c.aaa()?;
    if c.origin != Node::Core {
        bail!("SFTP through the edge is not available yet; connect to the AAA core");
    }
    let cfg = d.cfg();
    let live = crate::session::live_sessions(d);
    if live.iter().filter(|j| j["kind"] == "sftp" && j["user"] == c.name.as_str()).count() >= cfg.limits.sessions_per_user {
        bail!("per-user SFTP session limit reached ({})", cfg.limits.sessions_per_user);
    }
    // Registrations of workers that are gone.
    std::fs::create_dir_all(reg_dir(d))?;
    std::fs::set_permissions(reg_dir(d), std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    if let Ok(rd) = std::fs::read_dir(reg_dir(d)) {
        for e in rd.flatten() {
            let pid = std::fs::read_to_string(e.path()).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok()).and_then(|j| j["worker_pid"].as_i64()).unwrap_or(0);
            if pid > 0 && !crate::util::process_alive(pid as i32) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    let ents = entries(d, user, Node::Core);
    let t = now();
    let id = swrap_core::new_id();
    let token = crate::util::random_hex(32);
    let rec_dir = crate::session::ensure_rec_dir(d, &c.name)?;
    let rec_path = rec_dir.join("sftp").join(date_dir(t)).join(format!("{}_{}_core.swrec", fmt_basic(t), id));
    let mut header = Map::new();
    header.insert("kind".into(), "sftp".into());
    for (k, v) in [
        ("origin", json!("core")),
        ("exec", json!("core")),
        ("delegated", json!(false)),
        ("aaa_user", json!(c.name)),
        ("client_addr", json!(client_addr)),
        ("conn", json!(conn)),
        ("config_rev", json!(d.config_rev())),
        ("entries", json!(ents.iter().map(|e| e.name.clone()).collect::<Vec<_>>())),
    ] {
        header.insert(k.into(), v);
    }
    let spec = WorkerSpec {
        mode: "sftp".into(),
        id: id.clone(),
        aaa_user: c.name.clone(),
        uid: c.uid,
        rec_path: rec_path.to_string_lossy().into(),
        session_dir: String::new(),
        header,
        argv: vec![],
        cols: 0,
        rows: 0,
        term: String::new(),
        nonce: String::new(),
        record_input: false,
        signer: "core".into(),
        recsign_key: d.paths.recsign().join("ed25519.key").to_string_lossy().into(),
        rec_cfg: cfg.rec.clone(),
        live_marker: d.paths.live().join(&id).to_string_lossy().into(),
        banner: String::new(),
        sshd_pid: 0,
        ai: None,
        sftp: Some(SftpSpec { token: token.clone(), entries: ents.clone(), idle_secs: 300 }),
    };
    let reg = |pid: u32| json!({"user": c.name, "token_b3": blake3::hash(token.as_bytes()).to_hex().to_string(), "worker_pid": pid, "started": fmt_utc(t)});
    let rp = reg_dir(d).join(&id);
    swrap_core::atomic::write(&rp, reg(0).to_string().as_bytes(), 0o600, swrap_core::atomic::Owner::new(0, 0))?;
    let pid = crate::session::spawn_worker(d, &spec, s)?;
    swrap_core::atomic::write(&rp, reg(pid).to_string().as_bytes(), 0o600, swrap_core::atomic::Owner::new(0, 0))?;
    d.audit_event(&c.name, "sftp.start", "core", "", "ok", json!({"client_addr": client_addr, "entries": ents.iter().map(|e| e.name.clone()).collect::<Vec<_>>(), "worker_pid": pid}), &id);
    Ok(())
}

/// `Req::SftpBackend`: a worker needs a connection for one entry. Grants are checked again
/// now (a revoked grant stops new connections at once); the per-connection signing agent
/// lives until ssh has authenticated, like an `sw` session's.
pub fn backend(d: &Arc<Daemon>, c: &Caller, session: &str, token: &str, entry: &str) -> Result<Resp> {
    if c.uid != d.swrap_uid || !swrap_core::paths::safe_component(session) {
        bail!("permission denied");
    }
    let reg: Value = serde_json::from_str(&std::fs::read_to_string(reg_dir(d).join(session)).map_err(|_| anyhow!("unknown SFTP session"))?)?;
    if reg["token_b3"].as_str() != Some(blake3::hash(token.as_bytes()).to_hex().as_str()) {
        bail!("permission denied");
    }
    let who = reg["user"].as_str().unwrap_or("").to_string();
    let user = User::load(&d.paths, &who)?;
    if user.disabled {
        bail!("{who} is disabled");
    }
    let (want, label) = match entry.split_once('@') {
        Some((u, l)) => (Some(u.to_string()), l),
        None => (None, entry),
    };
    let host = Host::load(&d.paths, label).map_err(|_| anyhow!("unknown host {label}"))?;
    let t = now();
    let ruser = match want {
        Some(r) => r,
        None => rbac::granted_accounts(&user, &host, Node::Core, t)
            .into_iter()
            .find(|a| crate::session::credential(d, label, a).is_some())
            .ok_or_else(|| anyhow!("no grant for {label} any more"))?,
    };
    if !rbac::allowed(&user, &host, &ruser, Node::Core, t) {
        bail!("no grant for {ruser}@{label} any more");
    }
    if host.network == Route::Edge {
        bail!("{label} is reachable only through edge; SFTP to it is not available yet");
    }
    if d.is_sealed() {
        bail!("the swrap vault is sealed; an admin must log in first");
    }
    let (enc, pubp) = crate::session::credential(d, label, &ruser).ok_or_else(|| anyhow!("no credential for {ruser}@{label}"))?;
    let profile = Profile::load(&d.paths, &host.profile)?;
    let known = std::fs::read_to_string(d.paths.known_hosts(label)).context("host keys not pinned")?;
    let pinned = agent::pinned_blobs(&known);
    if pinned.is_empty() {
        bail!("no pinned host keys for {label}");
    }
    let pub_line = std::fs::read_to_string(&pubp)?;
    let key_blob = agent::pub_blob(&pub_line).context("bad public key file")?;
    let bid = swrap_core::new_id();
    let sdir = crate::session::new_session_dir(d, &bid)?;
    crate::session::write_owned(d, &sdir.join("ssh_config"), profile.ssh_config().as_bytes(), 0o600)?;
    crate::session::write_owned(d, &sdir.join("known_hosts"), known.as_bytes(), 0o600)?;
    crate::session::write_owned(d, &sdir.join("id.pub"), pub_line.as_bytes(), 0o600)?;
    let private = d.with_dek(|dek| swrap_vault::Vault::new(&d.paths, d.owner()).get(dek, &enc))?;
    let cfg = d.cfg();
    let window = cfg.signing.window.exact().unwrap_or(Duration::from_secs(120));
    let sa = SessionAgent::start(
        d.clone(),
        Policy {
            session_id: bid.clone(),
            aaa_user: who.clone(),
            label: label.to_string(),
            ruser: ruser.clone(),
            key_blob,
            pinned,
            max_sigs: cfg.signing.max_signatures_per_session,
            window,
            require_hostbound: cfg.signing.require_hostbound,
        },
        private,
        &sdir,
    )?;
    let worker = reg["worker_pid"].as_u64().filter(|p| *p > 0).map(|p| p as u32);
    crate::session::supervise_agent(d.clone(), sa, sdir.clone(), window, worker);
    let mut argv = crate::session::ssh_argv(profile.ssh_bin_for("core"), &sdir, label);
    argv.extend(["-o".into(), "ServerAliveInterval=30".into(), "-o".into(), "ServerAliveCountMax=4".into(), "-p".into(), host.port.to_string()]);
    argv.extend(["-s".into(), format!("{ruser}@{}", host.address), "sftp".into()]);
    d.audit_event(&who, "sftp.connect", label, &ruser, "ok", json!({"session": session}), &bid);
    Ok(Resp::ok(json!({"argv": argv, "session_dir": sdir, "label": label, "ruser": ruser})))
}

// ---------------------------------------------------------------- protocol (SFTP v3)

const INIT: u8 = 1;
const VERSION: u8 = 2;
const OPEN: u8 = 3;
const CLOSE: u8 = 4;
const READ: u8 = 5;
const WRITE: u8 = 6;
const LSTAT: u8 = 7;
const FSTAT: u8 = 8;
const SETSTAT: u8 = 9;
const FSETSTAT: u8 = 10;
const OPENDIR: u8 = 11;
const READDIR: u8 = 12;
const REMOVE: u8 = 13;
const MKDIR: u8 = 14;
const RMDIR: u8 = 15;
const REALPATH: u8 = 16;
const STAT: u8 = 17;
const RENAME: u8 = 18;
const READLINK: u8 = 19;
const SYMLINK: u8 = 20;
const STATUS: u8 = 101;
const HANDLE: u8 = 102;
const DATA: u8 = 103;
const NAME: u8 = 104;
const ATTRS: u8 = 105;
const EXTENDED: u8 = 200;
const EXTENDED_REPLY: u8 = 201;

const FX_OK: u32 = 0;
const FX_EOF: u32 = 1;
const FX_NO_SUCH_FILE: u32 = 2;
const FX_PERMISSION_DENIED: u32 = 3;
const FX_FAILURE: u32 = 4;
const FX_BAD_MESSAGE: u32 = 5;
const FX_NO_CONNECTION: u32 = 6;
const FX_CONNECTION_LOST: u32 = 7;
const FX_OP_UNSUPPORTED: u32 = 8;

const PF_WRITE: u32 = 0x02;
const PF_CREAT: u32 = 0x08;
const PF_TRUNC: u32 = 0x10;
const PF_EXCL: u32 = 0x20;

/// Largest packet accepted from either side (OpenSSH uses 256 KiB).
const MAX_PACKET: usize = 1 << 20;

/// Extensions offered to clients; each is handled below (forwarded, or answered here).
const EXTENSIONS: &[(&str, &str)] = &[
    ("posix-rename@openssh.com", "1"),
    ("statvfs@openssh.com", "2"),
    ("fstatvfs@openssh.com", "2"),
    ("hardlink@openssh.com", "1"),
    ("fsync@openssh.com", "1"),
    ("lsetstat@openssh.com", "1"),
    ("limits@openssh.com", "1"),
    ("expand-path@openssh.com", "1"),
    ("copy-data", "1"),
    ("home-directory", "1"),
];

fn read_packet(r: &mut impl Read) -> std::io::Result<Option<Vec<u8>>> {
    let mut l = [0u8; 4];
    match r.read_exact(&mut l) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_be_bytes(l) as usize;
    if n == 0 || n > MAX_PACKET {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("bad SFTP packet length {n}")));
    }
    let mut b = vec![0u8; n];
    r.read_exact(&mut b)?;
    Ok(Some(b))
}

struct Rd<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Rd<'a> {
    fn new(b: &'a [u8]) -> Self {
        Rd { b, p: 0 }
    }
    fn u32(&mut self) -> Option<u32> {
        let v = self.b.get(self.p..self.p + 4)?;
        self.p += 4;
        Some(u32::from_be_bytes(v.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        let v = self.b.get(self.p..self.p + 8)?;
        self.p += 8;
        Some(u64::from_be_bytes(v.try_into().ok()?))
    }
    fn str(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        let v = self.b.get(self.p..self.p.checked_add(n)?)?;
        self.p += n;
        Some(v)
    }
    fn rest(&self) -> &'a [u8] {
        &self.b[self.p.min(self.b.len())..]
    }
}

/// A packet body under construction (type first); `done` adds the length.
struct Pk(Vec<u8>);

impl Pk {
    fn new(t: u8) -> Self {
        Pk(vec![t])
    }
    fn u32(mut self, v: u32) -> Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn u64(mut self, v: u64) -> Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn str(mut self, s: &[u8]) -> Self {
        self.0.extend_from_slice(&(s.len() as u32).to_be_bytes());
        self.0.extend_from_slice(s);
        self
    }
    fn raw(mut self, b: &[u8]) -> Self {
        self.0.extend_from_slice(b);
        self
    }
    fn done(self) -> Vec<u8> {
        let mut v = (self.0.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(&self.0);
        v
    }
}

fn status_name(code: u32) -> &'static str {
    match code {
        FX_OK => "ok",
        FX_EOF => "eof",
        FX_NO_SUCH_FILE => "no-such-file",
        FX_PERMISSION_DENIED => "permission-denied",
        FX_FAILURE => "failure",
        FX_BAD_MESSAGE => "bad-message",
        FX_NO_CONNECTION => "no-connection",
        FX_CONNECTION_LOST => "connection-lost",
        FX_OP_UNSUPPORTED => "unsupported",
        _ => "error",
    }
}

/// SFTP attributes as JSON for records (size, owner, mode, times).
fn attrs_json(b: &[u8]) -> Value {
    let mut r = Rd::new(b);
    let Some(fl) = r.u32() else { return Value::Null };
    let mut m = Map::new();
    if fl & 0x1 != 0 {
        m.insert("size".into(), r.u64().unwrap_or(0).into());
    }
    if fl & 0x2 != 0 {
        m.insert("uid".into(), r.u32().unwrap_or(0).into());
        m.insert("gid".into(), r.u32().unwrap_or(0).into());
    }
    if fl & 0x4 != 0 {
        m.insert("mode".into(), format!("{:o}", r.u32().unwrap_or(0) & 0o7777).into());
    }
    if fl & 0x8 != 0 {
        m.insert("atime".into(), r.u32().unwrap_or(0).into());
        m.insert("mtime".into(), r.u32().unwrap_or(0).into());
    }
    Value::Object(m)
}

/// Attributes of a directory of the virtual root.
fn dir_attrs(mode: u32, t: u32) -> Vec<u8> {
    Pk(vec![]).u32(0x1 | 0x4 | 0x8).u64(0).u32(0o040000 | mode).u32(t).u32(t).0
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// Where a client path points.
enum Loc {
    /// The virtual root.
    Root,
    /// A top-level name that is no entry.
    Missing,
    /// Entry index and the path on that host.
    In(usize, Vec<u8>),
}

/// Lexical normalisation (spec 11.2): `.` and `..` resolve here, clamped at the virtual root,
/// so no path can leave its entry. Relative paths are relative to the virtual root.
fn normalize(path: &[u8]) -> Vec<&[u8]> {
    let mut comps: Vec<&[u8]> = vec![];
    for c in path.split(|&b| b == b'/') {
        match c {
            b"" | b"." => {}
            b".." => {
                comps.pop();
            }
            c => comps.push(c),
        }
    }
    comps
}

// ---------------------------------------------------------------- worker side

enum Ev {
    Client(Vec<u8>),
    ClientGone,
    Back(usize, Vec<u8>),
    BackGone(usize),
}

struct Backend {
    entry: usize,
    stdin: ChildStdin,
    child: Child,
    sdir: PathBuf,
    alive: bool,
    busy: usize,
    handles: usize,
    last: Instant,
    exts: Vec<String>,
}

#[derive(Default)]
struct Handle {
    back: Option<usize>,
    bh: Vec<u8>,
    dir: bool,
    entry: Option<usize>,
    path: String,
    pflags: u32,
    read: u64,
    written: u64,
    next: u64,
    seq: bool,
    hash: Option<blake3::Hasher>,
    eof: bool,
    listed: u64,
    root_done: bool,
}

struct Pend {
    t: u8,
    ext: String,
    back: usize,
    entry: usize,
    path: String,
    path2: String,
    handle: Option<u32>,
    off: u64,
    extra: Map<String, Value>,
}

struct Proxy<'a> {
    spec: &'a WorkerSpec,
    sftp: &'a SftpSpec,
    out: UnixStream,
    w: &'a mut Writer,
    tx: mpsc::Sender<Ev>,
    backs: Vec<Backend>,
    slot: Vec<Option<usize>>,
    handles: HashMap<u32, Handle>,
    next_h: u32,
    pend: HashMap<u32, Pend>,
    started: u32,
    ops: u64,
    bytes_read: u64,
    bytes_written: u64,
}

/// The SFTP session worker: `client` is the relayed SFTP stream (after the RESP frame).
pub fn run_worker(spec: &WorkerSpec, mut client: UnixStream, w: &mut Writer, signer: &RecSigner) -> Result<()> {
    let sftp = spec.sftp.as_ref().context("no sftp spec")?;
    write_frame(&mut client, &Frame::json(kind::RESP, &Resp::ok(json!({"id": spec.id}))))?;
    w.note(&format!("sftp: {} directories: {}", sftp.entries.len(), sftp.entries.iter().map(|e| e.name.as_str()).collect::<Vec<_>>().join(" ")))?;
    let (tx, rx) = mpsc::channel::<Ev>();
    let mut rd = client.try_clone()?;
    let ctx = tx.clone();
    std::thread::spawn(move || loop {
        match read_packet(&mut rd) {
            Ok(Some(p)) => {
                if ctx.send(Ev::Client(p)).is_err() {
                    break;
                }
            }
            _ => {
                let _ = ctx.send(Ev::ClientGone);
                break;
            }
        }
    });
    let mut px = Proxy {
        spec,
        sftp,
        out: client,
        w,
        tx,
        backs: vec![],
        slot: vec![None; sftp.entries.len()],
        handles: HashMap::new(),
        next_h: 1,
        pend: HashMap::new(),
        started: now().as_second() as u32,
        ops: 0,
        bytes_read: 0,
        bytes_written: 0,
    };
    let mut inited = false;
    let mut last_idle = Instant::now();
    let reason = loop {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(Ev::Client(p)) => {
                if !inited {
                    if p.first() != Some(&INIT) {
                        break "protocol error: no INIT";
                    }
                    inited = true;
                    px.version()?;
                    continue;
                }
                if let Err(e) = px.request(&p) {
                    px.w.note(&format!("sftp: {e:#}"))?;
                    break "error";
                }
            }
            Ok(Ev::ClientGone) | Err(mpsc::RecvTimeoutError::Disconnected) => break "exit",
            Ok(Ev::Back(i, p)) => px.response(i, &p)?,
            Ok(Ev::BackGone(i)) => px.lost(i)?,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        px.w.tick()?;
        if last_idle.elapsed() > Duration::from_secs(10) {
            last_idle = Instant::now();
            px.close_idle()?;
        }
    };
    px.finish(reason, signer)
}

impl<'a> Proxy<'a> {
    fn send(&mut self, pkt: &[u8]) -> Result<()> {
        self.out.write_all(pkt).context("client gone")
    }

    fn status(&mut self, id: u32, code: u32, msg: &str) -> Result<()> {
        self.send(&Pk::new(STATUS).u32(id).u32(code).str(msg.as_bytes()).str(b"").done())
    }

    fn record(&mut self, op: &str, entry: Option<usize>, path: &str, result: &str, extra: Map<String, Value>) -> Result<()> {
        self.ops += 1;
        let (label, ruser) = match entry.and_then(|i| self.sftp.entries.get(i)) {
            Some(e) => (e.label.clone(), e.ruser.clone()),
            None => (String::new(), String::new()),
        };
        let mut m = Map::new();
        m.insert("op".into(), op.into());
        m.insert("label".into(), label.into());
        m.insert("ruser".into(), ruser.into());
        m.insert("path".into(), path.into());
        m.extend(extra);
        m.insert("result".into(), result.into());
        self.w.record("f", m)?;
        Ok(())
    }

    fn version(&mut self) -> Result<()> {
        let mut p = Pk::new(VERSION).u32(3);
        for (n, v) in EXTENSIONS {
            p = p.str(n.as_bytes()).str(v.as_bytes());
        }
        self.send(&p.done())
    }

    fn locate(&self, path: &[u8]) -> Loc {
        let comps = normalize(path);
        let Some(first) = comps.first() else { return Loc::Root };
        let Some(i) = self.sftp.entries.iter().position(|e| e.name.as_bytes() == *first) else { return Loc::Missing };
        let mut hp = vec![];
        for c in &comps[1..] {
            hp.push(b'/');
            hp.extend_from_slice(c);
        }
        if hp.is_empty() {
            hp.push(b'/');
        }
        Loc::In(i, hp)
    }

    /// The virtual path of a path on entry `i`'s host.
    fn vpath(&self, i: usize, hp: &[u8]) -> Vec<u8> {
        let mut v = b"/".to_vec();
        v.extend_from_slice(self.sftp.entries[i].name.as_bytes());
        if hp != b"/" {
            if !hp.starts_with(b"/") {
                v.push(b'/');
            }
            v.extend_from_slice(hp);
        }
        v
    }

    fn name_reply(&mut self, id: u32, path: &[u8], attrs: &[u8]) -> Result<()> {
        self.send(&Pk::new(NAME).u32(id).u32(1).str(path).str(path).raw(attrs).done())
    }

    /// The backend for entry `i`, connecting on first use.
    fn backend(&mut self, i: usize) -> Result<usize, String> {
        if let Some(b) = self.slot[i] {
            if self.backs[b].alive {
                return Ok(b);
            }
        }
        let e = self.sftp.entries[i].clone();
        let resp = daemon_call(&Req::SftpBackend { session: self.spec.id.clone(), token: self.sftp.token.clone(), entry: e.name.clone() }).map_err(|x| format!("{x:#}"))?;
        if !resp.ok {
            return Err(resp.error.unwrap_or_default());
        }
        let argv: Vec<String> = resp.data["argv"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(String::from)).collect();
        let sdir = PathBuf::from(resp.data["session_dir"].as_str().unwrap_or(""));
        let fail = |why: String, sdir: &PathBuf| {
            let log = std::fs::read_to_string(sdir.join("ssh.log")).unwrap_or_default();
            let tail: Vec<&str> = log.lines().filter(|l| !l.contains("debug1:") && !l.trim().is_empty()).collect();
            let _ = std::fs::remove_dir_all(sdir);
            match tail.last() {
                Some(l) => format!("{why}: {l}"),
                None => why,
            }
        };
        let mut child = Command::new(argv.first().ok_or("no ssh command")?)
            .args(&argv[1..])
            .env_clear()
            .env("PATH", "/usr/bin:/usr/sbin")
            .env("HOME", &sdir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|x| fail(format!("start ssh: {x}"), &sdir))?;
        let mut stdin = child.stdin.take().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let bi = self.backs.len();
        let (first_tx, first_rx) = mpsc::channel::<Vec<u8>>();
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let mut first = Some(first_tx);
            loop {
                match read_packet(&mut stdout) {
                    Ok(Some(p)) => {
                        if let Some(f) = first.take() {
                            let _ = f.send(p);
                        } else if tx.send(Ev::Back(bi, p)).is_err() {
                            break;
                        }
                    }
                    _ => {
                        let _ = tx.send(Ev::BackGone(bi));
                        break;
                    }
                }
            }
        });
        let _ = stdin.write_all(&Pk::new(INIT).u32(3).done());
        let v = match first_rx.recv_timeout(Duration::from_secs(60)) {
            Ok(v) if v.first() == Some(&VERSION) => v,
            Ok(_) => {
                let _ = child.kill();
                return Err(fail("unexpected answer from the host's sftp server".into(), &sdir));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(fail(format!("could not open SFTP on {}@{}", e.ruser, e.label), &sdir));
            }
        };
        let mut r = Rd::new(&v[1..]);
        let _ver = r.u32();
        let mut exts = vec![];
        while let Some(n) = r.str() {
            exts.push(lossy(n));
            let _ = r.str();
        }
        self.backs.push(Backend { entry: i, stdin, child, sdir, alive: true, busy: 0, handles: 0, last: Instant::now(), exts });
        self.slot[i] = Some(bi);
        let _ = self.w.note(&format!("sftp: connected to {}@{}", e.ruser, e.label));
        Ok(bi)
    }

    /// Forward a request for entry `i` (connecting if needed).
    #[allow(clippy::too_many_arguments)]
    fn forward(&mut self, i: usize, t: u8, id: u32, body: Pk, op: &str, path: &str, p: Pend) -> Result<()> {
        let b = match self.backend(i) {
            Ok(b) => b,
            Err(why) => {
                self.record(op, Some(i), path, &format!("no-connection: {why}"), p.extra)?;
                return self.status(id, FX_NO_CONNECTION, &why);
            }
        };
        if t == EXTENDED && !self.backs[b].exts.contains(&p.ext) {
            let why = format!("the host's sftp server does not support {}", p.ext);
            self.record(op, Some(i), path, "unsupported", p.extra)?;
            return self.status(id, FX_OP_UNSUPPORTED, &why);
        }
        let mut pkt = Pk::new(t).u32(id);
        pkt.0.extend_from_slice(&body.0);
        let pkt = pkt.done();
        let be = &mut self.backs[b];
        if be.stdin.write_all(&pkt).is_err() {
            be.alive = false;
            self.record(op, Some(i), path, "connection-lost", p.extra)?;
            return self.status(id, FX_CONNECTION_LOST, "connection to the host lost");
        }
        be.busy += 1;
        be.last = Instant::now();
        self.pend.insert(id, Pend { back: b, entry: i, ..p });
        Ok(())
    }

    fn new_handle(&mut self, h: Handle) -> Vec<u8> {
        let n = self.next_h;
        self.next_h = self.next_h.wrapping_add(1).max(1);
        self.handles.insert(n, h);
        n.to_be_bytes().to_vec()
    }

    fn handle_of(b: &[u8]) -> Option<u32> {
        (b.len() == 4).then(|| u32::from_be_bytes(b.try_into().unwrap()))
    }

    /// One client request.
    fn request(&mut self, p: &[u8]) -> Result<()> {
        let t = p[0];
        let mut r = Rd::new(&p[1..]);
        let Some(id) = r.u32() else { bail!("short packet") };
        let bad = |s: &mut Self| s.status(id, FX_BAD_MESSAGE, "malformed request");
        match t {
            REALPATH | STAT | LSTAT | OPENDIR | REMOVE | RMDIR | READLINK | MKDIR | SETSTAT | OPEN => {
                let Some(path) = r.str() else { return bad(self) };
                let op = match t {
                    REALPATH => "realpath",
                    STAT => "stat",
                    LSTAT => "lstat",
                    OPENDIR => "list",
                    REMOVE => "remove",
                    RMDIR => "rmdir",
                    READLINK => "readlink",
                    MKDIR => "mkdir",
                    SETSTAT => "setstat",
                    _ => "open",
                };
                match self.locate(path) {
                    Loc::Root => match t {
                        REALPATH => {
                            self.record(op, None, "/", "ok", Map::new())?;
                            let a = dir_attrs(0o555, self.started);
                            self.name_reply(id, b"/", &a)
                        }
                        STAT | LSTAT => {
                            self.record(op, None, "/", "ok", Map::new())?;
                            let a = dir_attrs(0o555, self.started);
                            self.send(&Pk::new(ATTRS).u32(id).raw(&a).done())
                        }
                        OPENDIR => {
                            let h = self.new_handle(Handle { dir: true, path: "/".into(), ..Default::default() });
                            self.send(&Pk::new(HANDLE).u32(id).str(&h).done())
                        }
                        _ => {
                            self.record(op, None, "/", "permission-denied", Map::new())?;
                            self.status(id, FX_PERMISSION_DENIED, "the top level lists hosts and is read-only")
                        }
                    },
                    Loc::Missing => {
                        let writes = match t {
                            OPEN => r.u32().unwrap_or(0) & (PF_WRITE | PF_CREAT) != 0,
                            MKDIR | SETSTAT | REMOVE | RMDIR => true,
                            _ => false,
                        };
                        let (code, msg) = if writes { (FX_PERMISSION_DENIED, "the top level lists hosts and is read-only") } else { (FX_NO_SUCH_FILE, "no such host directory") };
                        self.record(op, None, &lossy(path), status_name(code), Map::new())?;
                        self.status(id, code, msg)
                    }
                    Loc::In(i, hp) => {
                        // The entry itself is a directory of the virtual root: answered here.
                        if hp == b"/" && matches!(t, STAT | LSTAT) {
                            let a = dir_attrs(0o755, self.started);
                            self.record(op, Some(i), "/", "ok", Map::new())?;
                            return self.send(&Pk::new(ATTRS).u32(id).raw(&a).done());
                        }
                        if hp == b"/" && t == REALPATH {
                            let v = self.vpath(i, b"/");
                            self.record(op, Some(i), "/", "ok", Map::new())?;
                            let a = dir_attrs(0o755, self.started);
                            return self.name_reply(id, &v, &a);
                        }
                        let rest = r.rest();
                        let mut pd = new_pend(t, lossy(&hp));
                        let body = match t {
                            OPEN => {
                                let mut rr = Rd::new(rest);
                                let fl = rr.u32().unwrap_or(0);
                                pd.extra.insert("flags".into(), open_flags(fl).into());
                                pd.off = fl as u64; // the open flags, for the handle
                                Pk(vec![]).str(&hp).raw(rest)
                            }
                            MKDIR | SETSTAT => {
                                pd.extra.insert("attrs".into(), attrs_json(rest));
                                Pk(vec![]).str(&hp).raw(rest)
                            }
                            _ => Pk(vec![]).str(&hp),
                        };
                        let pth = pd.path.clone();
                        self.forward(i, t, id, body, op, &pth, pd)
                    }
                }
            }
            RENAME => {
                let (Some(a), Some(b)) = (r.str(), r.str()) else { return bad(self) };
                self.two_paths(id, t, "", "rename", a, b)
            }
            SYMLINK => {
                // OpenSSH order: target first, then the link to create.
                let (Some(target), Some(link)) = (r.str(), r.str()) else { return bad(self) };
                let Loc::In(i, lp) = self.locate(link) else {
                    self.record("symlink", None, &lossy(link), "permission-denied", Map::new())?;
                    return self.status(id, FX_PERMISSION_DENIED, "the top level lists hosts and is read-only");
                };
                let target = if target.starts_with(b"/") {
                    match self.locate(target) {
                        Loc::In(j, tp) if j == i => tp,
                        _ => {
                            self.record("symlink", Some(i), &lossy(&lp), "permission-denied", Map::new())?;
                            return self.status(id, FX_PERMISSION_DENIED, "a link must point into the same host");
                        }
                    }
                } else {
                    target.to_vec()
                };
                let mut pd = new_pend(t, lossy(&lp));
                pd.path2 = lossy(&target);
                let pth = pd.path.clone();
                self.forward(i, t, id, Pk(vec![]).str(&target).str(&lp), "symlink", &pth, pd)
            }
            CLOSE | READ | WRITE | FSTAT | FSETSTAT | READDIR => {
                let Some(hb) = r.str() else { return bad(self) };
                let Some(hn) = Self::handle_of(hb) else { return self.status(id, FX_FAILURE, "invalid handle") };
                let rest = r.rest().to_vec();
                self.on_handle(id, t, hn, &rest)
            }
            EXTENDED => {
                let Some(name) = r.str() else { return bad(self) };
                let name = lossy(name);
                self.extended(id, &name, r)
            }
            _ => self.status(id, FX_OP_UNSUPPORTED, "not supported"),
        }
    }

    /// RENAME and the two-path extensions: both paths must be on the same host.
    fn two_paths(&mut self, id: u32, t: u8, ext: &str, op: &str, a: &[u8], b: &[u8]) -> Result<()> {
        match (self.locate(a), self.locate(b)) {
            (Loc::In(i, pa), Loc::In(j, pb)) if i == j && pa != b"/" && pb != b"/" => {
                let mut pd = new_pend(t, lossy(&pa));
                pd.path2 = lossy(&pb);
                pd.ext = ext.to_string();
                let body = if ext.is_empty() { Pk(vec![]).str(&pa).str(&pb) } else { Pk(vec![]).str(ext.as_bytes()).str(&pa).str(&pb) };
                let pth = pd.path.clone();
                self.forward(i, t, id, body, op, &pth, pd)
            }
            (Loc::In(i, _), Loc::In(j, _)) if i != j => {
                let mut x = Map::new();
                x.insert("path2".into(), lossy(b).into());
                self.record(op, None, &lossy(a), "failure", x)?;
                self.status(id, FX_FAILURE, "cannot move or link between hosts (copy instead)")
            }
            _ => {
                let mut x = Map::new();
                x.insert("path2".into(), lossy(b).into());
                self.record(op, None, &lossy(a), "permission-denied", x)?;
                self.status(id, FX_PERMISSION_DENIED, "the top level lists hosts and is read-only")
            }
        }
    }

    fn on_handle(&mut self, id: u32, t: u8, hn: u32, rest: &[u8]) -> Result<()> {
        let Some(h) = self.handles.get_mut(&hn) else { return self.status(id, FX_FAILURE, "invalid handle") };
        let Some(b) = h.back else {
            // The virtual root's directory handle.
            return match t {
                READDIR if !h.root_done => {
                    h.root_done = true;
                    let mut p = Pk::new(NAME).u32(id).u32(self.sftp.entries.len() as u32 + 2);
                    let a = dir_attrs(0o755, self.started);
                    let ra = dir_attrs(0o555, self.started);
                    let date = jiff::Timestamp::from_second(self.started as i64).map(|t| t.to_zoned(jiff::tz::TimeZone::system()).strftime("%b %e %H:%M").to_string()).unwrap_or_default();
                    for (n, attrs, mode) in [(".", &ra, "dr-xr-xr-x"), ("..", &ra, "dr-xr-xr-x")] {
                        p = p.str(n.as_bytes()).str(format!("{mode}    2 swrap    swrap           0 {date} {n}").as_bytes()).raw(attrs);
                    }
                    let names: Vec<String> = self.sftp.entries.iter().map(|e| e.name.clone()).collect();
                    for n in &names {
                        p = p.str(n.as_bytes()).str(format!("drwxr-xr-x    2 swrap    swrap           0 {date} {n}").as_bytes()).raw(&a);
                    }
                    self.send(&p.done())
                }
                READDIR => self.status(id, FX_EOF, "end of directory"),
                FSTAT => {
                    let a = dir_attrs(0o555, self.started);
                    self.send(&Pk::new(ATTRS).u32(id).raw(&a).done())
                }
                CLOSE => {
                    self.handles.remove(&hn);
                    let mut x = Map::new();
                    x.insert("entries".into(), self.sftp.entries.len().into());
                    self.record("list", None, "/", "ok", x)?;
                    self.status(id, FX_OK, "")
                }
                _ => self.status(id, FX_PERMISSION_DENIED, "the top level lists hosts and is read-only"),
            };
        };
        if !self.backs[b].alive {
            return self.status(id, FX_CONNECTION_LOST, "connection to the host lost");
        }
        let (entry, path, bh) = (h.entry.unwrap_or(0), h.path.clone(), h.bh.clone());
        let mut pd = new_pend(t, path.clone());
        pd.handle = Some(hn);
        match t {
            READ => {
                let mut rr = Rd::new(rest);
                pd.off = rr.u64().unwrap_or(u64::MAX);
            }
            WRITE => {
                let mut rr = Rd::new(rest);
                let off = rr.u64().unwrap_or(u64::MAX);
                let data = rr.str().unwrap_or_default();
                h.written += data.len() as u64;
                if h.seq && off == h.next {
                    if let Some(x) = h.hash.as_mut() {
                        x.update(data);
                    }
                    h.next += data.len() as u64;
                } else {
                    h.seq = false;
                }
            }
            FSETSTAT => {
                pd.extra.insert("attrs".into(), attrs_json(rest));
            }
            _ => {}
        }
        let op = match t {
            CLOSE => "close",
            READ => "read",
            WRITE => "write",
            FSTAT => "fstat",
            FSETSTAT => "fsetstat",
            _ => "readdir",
        };
        self.forward(entry, t, id, Pk(vec![]).str(&bh).raw(rest), op, &path, pd)
    }

    fn extended(&mut self, id: u32, name: &str, mut r: Rd) -> Result<()> {
        match name {
            "posix-rename@openssh.com" | "hardlink@openssh.com" => {
                let (Some(a), Some(b)) = (r.str(), r.str()) else { return self.status(id, FX_BAD_MESSAGE, "malformed request") };
                let op = if name.starts_with("posix") { "rename" } else { "hardlink" };
                self.two_paths(id, EXTENDED, name, op, a, b)
            }
            "statvfs@openssh.com" | "lsetstat@openssh.com" => {
                let Some(path) = r.str() else { return self.status(id, FX_BAD_MESSAGE, "malformed request") };
                let op = if name.starts_with("statvfs") { "statvfs" } else { "lsetstat" };
                match self.locate(path) {
                    Loc::In(i, hp) => {
                        let rest = r.rest();
                        let mut pd = new_pend(EXTENDED, lossy(&hp));
                        pd.ext = name.to_string();
                        if op == "lsetstat" {
                            pd.extra.insert("attrs".into(), attrs_json(rest));
                        }
                        let pth = pd.path.clone();
                        self.forward(i, EXTENDED, id, Pk(vec![]).str(name.as_bytes()).str(&hp).raw(rest), op, &pth, pd)
                    }
                    _ => self.status(id, if op == "statvfs" { FX_OP_UNSUPPORTED } else { FX_PERMISSION_DENIED }, "not on the top level"),
                }
            }
            "fstatvfs@openssh.com" | "fsync@openssh.com" => {
                let Some(hb) = r.str() else { return self.status(id, FX_BAD_MESSAGE, "malformed request") };
                let Some(h) = Self::handle_of(hb).and_then(|n| self.handles.get(&n)) else { return self.status(id, FX_FAILURE, "invalid handle") };
                let (Some(b), entry, path, bh) = (h.back, h.entry.unwrap_or(0), h.path.clone(), h.bh.clone()) else { return self.status(id, FX_OP_UNSUPPORTED, "not on the top level") };
                if !self.backs[b].alive {
                    return self.status(id, FX_CONNECTION_LOST, "connection to the host lost");
                }
                let mut pd = new_pend(EXTENDED, path.clone());
                pd.ext = name.to_string();
                let op = if name.starts_with("fsync") { "fsync" } else { "fstatvfs" };
                self.forward(entry, EXTENDED, id, Pk(vec![]).str(name.as_bytes()).str(&bh), op, &path, pd)
            }
            "copy-data" => {
                let (Some(rh), Some(roff), Some(len), Some(wh), Some(woff)) = (r.str(), r.u64(), r.u64(), r.str(), r.u64()) else { return self.status(id, FX_BAD_MESSAGE, "malformed request") };
                let get = |s: &Self, b: &[u8]| Self::handle_of(b).and_then(|n| s.handles.get(&n)).and_then(|h| h.back.map(|b| (b, h.entry.unwrap_or(0), h.path.clone(), h.bh.clone())));
                match (get(self, rh), get(self, wh)) {
                    (Some((b1, e1, p1, bh1)), Some((b2, _, p2, bh2))) if b1 == b2 && self.backs[b1].alive => {
                        let mut pd = new_pend(EXTENDED, p1.clone());
                        pd.ext = name.to_string();
                        pd.path2 = p2;
                        pd.extra.insert("bytes".into(), len.into());
                        self.forward(e1, EXTENDED, id, Pk(vec![]).str(name.as_bytes()).str(&bh1).u64(roff).u64(len).str(&bh2).u64(woff), "copy", &p1, pd)
                    }
                    _ => self.status(id, FX_OP_UNSUPPORTED, "server-side copy only works within one host"),
                }
            }
            "limits@openssh.com" => {
                let v = MAX_PACKET as u64 / 4;
                self.send(&Pk::new(EXTENDED_REPLY).u32(id).u64(v).u64(v - 1024).u64(v - 1024).u64(0).done())
            }
            "expand-path@openssh.com" => {
                let Some(path) = r.str() else { return self.status(id, FX_BAD_MESSAGE, "malformed request") };
                // `~` is the virtual root: it is the directory a login starts in.
                let p = if path == b"~" { b"/".to_vec() } else if let Some(x) = path.strip_prefix(b"~/") { [b"/".as_slice(), x].concat() } else { path.to_vec() };
                let comps = normalize(&p);
                let mut v = vec![];
                for c in comps {
                    v.push(b'/');
                    v.extend_from_slice(c);
                }
                if v.is_empty() {
                    v.push(b'/');
                }
                self.send(&Pk::new(NAME).u32(id).u32(1).str(&v).str(b"").u32(0).done())
            }
            "home-directory" => self.send(&Pk::new(NAME).u32(id).u32(1).str(b"/").str(b"").u32(0).done()),
            _ => self.status(id, FX_OP_UNSUPPORTED, "not supported"),
        }
    }

    /// One answer from backend `b`.
    fn response(&mut self, b: usize, p: &[u8]) -> Result<()> {
        if p.len() < 5 {
            return Ok(());
        }
        let t = p[0];
        let id = u32::from_be_bytes(p[1..5].try_into().unwrap());
        let Some(pd) = self.pend.remove(&id) else { return Ok(()) };
        {
            let be = &mut self.backs[b];
            be.busy = be.busy.saturating_sub(1);
            be.last = Instant::now();
        }
        let mut r = Rd::new(&p[5..]);
        let op = op_name(pd.t, &pd.ext);
        let mut extra = pd.extra.clone();
        if !pd.path2.is_empty() {
            extra.insert("path2".into(), pd.path2.clone().into());
        }
        match t {
            HANDLE => {
                let bh = r.str().unwrap_or_default().to_vec();
                let h = Handle {
                    back: Some(b),
                    bh,
                    dir: pd.t == OPENDIR,
                    entry: Some(pd.entry),
                    path: pd.path.clone(),
                    pflags: pd.off as u32,
                    seq: true,
                    hash: Some(blake3::Hasher::new()),
                    ..Default::default()
                };
                self.backs[b].handles += 1;
                let our = self.new_handle(h);
                self.send(&Pk::new(HANDLE).u32(id).str(&our).done())
            }
            NAME if matches!(pd.t, REALPATH | READLINK) => {
                let count = r.u32().unwrap_or(0);
                let name = r.str().unwrap_or_default().to_vec();
                let long = r.str().unwrap_or_default().to_vec();
                let rest = r.rest().to_vec();
                // Host paths come back under the entry's directory; relative link targets stay.
                let shown = if pd.t == REALPATH || name.starts_with(b"/") { self.vpath(pd.entry, &name) } else { name.clone() };
                extra.insert("to".into(), lossy(&name).into());
                self.record(op, Some(pd.entry), &pd.path, "ok", extra)?;
                self.send(&Pk::new(NAME).u32(id).u32(count).str(&shown).str(&long).raw(&rest).done())
            }
            NAME => {
                if let Some(h) = pd.handle.and_then(|n| self.handles.get_mut(&n)) {
                    h.listed += r.u32().unwrap_or(0) as u64;
                }
                self.send(p_with_len(p).as_slice())
            }
            DATA => {
                let data = r.str().unwrap_or_default();
                self.bytes_read += data.len() as u64;
                if let Some(h) = pd.handle.and_then(|n| self.handles.get_mut(&n)) {
                    h.read += data.len() as u64;
                    if h.seq && pd.off == h.next {
                        if let Some(x) = h.hash.as_mut() {
                            x.update(data);
                        }
                        h.next += data.len() as u64;
                    } else {
                        h.seq = false;
                    }
                }
                self.send(p_with_len(p).as_slice())
            }
            STATUS => {
                let code = r.u32().unwrap_or(FX_FAILURE);
                let msg = lossy(r.str().unwrap_or_default());
                let result = if code == FX_OK || (code == FX_EOF && matches!(pd.t, READ | READDIR)) { "ok".to_string() } else if msg.is_empty() { status_name(code).to_string() } else { format!("{}: {msg}", status_name(code)) };
                match pd.t {
                    READ => {
                        if code == FX_EOF {
                            if let Some(h) = pd.handle.and_then(|n| self.handles.get_mut(&n)) {
                                if pd.off == h.next {
                                    h.eof = true;
                                }
                            }
                        }
                    }
                    READDIR => {}
                    WRITE => {
                        if code != FX_OK {
                            if let Some(h) = pd.handle.and_then(|n| self.handles.get_mut(&n)) {
                                h.seq = false;
                            }
                            self.record("write", Some(pd.entry), &pd.path, &result, extra)?;
                        }
                    }
                    CLOSE => {
                        if let Some(n) = pd.handle {
                            if let Some(h) = self.handles.remove(&n) {
                                self.backs[b].handles = self.backs[b].handles.saturating_sub(1);
                                self.close_record(h, &result)?;
                            }
                        }
                    }
                    _ => self.record(op, Some(pd.entry), &pd.path, &result, extra)?,
                }
                self.send(p_with_len(p).as_slice())
            }
            ATTRS | EXTENDED_REPLY => {
                if t == ATTRS && matches!(pd.t, STAT | LSTAT | FSTAT) {
                    extra.insert("attrs".into(), attrs_json(r.rest()));
                }
                self.record(op, Some(pd.entry), &pd.path, "ok", extra)?;
                self.send(p_with_len(p).as_slice())
            }
            _ => self.send(p_with_len(p).as_slice()),
        }
    }

    /// The `f` record for a closed handle: what was read or written, and the content's
    /// blake3 when the whole file went through in order (spec 11.4).
    fn close_record(&mut self, h: Handle, result: &str) -> Result<()> {
        let mut x = Map::new();
        if h.dir {
            x.insert("entries".into(), h.listed.into());
            return self.record("list", h.entry, &h.path, result, x);
        }
        x.insert("flags".into(), open_flags(h.pflags).into());
        self.bytes_written += h.written;
        let op = match (h.read > 0, h.written > 0) {
            (true, false) => "get",
            (false, true) => "put",
            (true, true) => "read+write",
            _ => "open",
        };
        if h.read > 0 {
            x.insert("bytes_read".into(), h.read.into());
        }
        if h.written > 0 {
            x.insert("bytes_written".into(), h.written.into());
        }
        let whole = h.seq && ((op == "get" && h.eof) || (op == "put" && h.pflags & (PF_TRUNC | PF_EXCL) != 0));
        if whole {
            if let Some(hs) = h.hash {
                x.insert("b3".into(), hs.finalize().to_hex().to_string().into());
            }
        } else if op != "open" {
            x.insert("partial".into(), true.into());
        }
        self.record(op, h.entry, &h.path, result, x)
    }

    /// A backend's connection ended: fail what was waiting on it.
    fn lost(&mut self, b: usize) -> Result<()> {
        if b >= self.backs.len() {
            return Ok(());
        }
        let e = self.backs[b].entry;
        let was_alive = self.backs[b].alive;
        self.backs[b].alive = false;
        let ids: Vec<u32> = self.pend.iter().filter(|(_, p)| p.back == b).map(|(id, _)| *id).collect();
        for id in ids {
            if let Some(p) = self.pend.remove(&id) {
                self.record(op_name(p.t, &p.ext), Some(p.entry), &p.path, "connection-lost", p.extra)?;
                self.status(id, FX_CONNECTION_LOST, "connection to the host lost")?;
            }
        }
        if was_alive {
            let ent = &self.sftp.entries[e];
            let note = format!("sftp: connection to {}@{} closed", ent.ruser, ent.label);
            self.w.note(&note)?;
        }
        self.shut(b);
        Ok(())
    }

    fn shut(&mut self, b: usize) {
        let be = &mut self.backs[b];
        be.alive = false;
        let _ = be.child.kill();
        let _ = be.child.wait();
        let _ = std::fs::remove_dir_all(&be.sdir);
        if self.slot[be.entry] == Some(b) {
            self.slot[be.entry] = None;
        }
    }

    /// Close host connections unused for `idle_secs` (spec 11.3).
    fn close_idle(&mut self) -> Result<()> {
        let idle = Duration::from_secs(self.sftp.idle_secs.max(30));
        for b in 0..self.backs.len() {
            let be = &self.backs[b];
            if be.alive && be.busy == 0 && be.handles == 0 && be.last.elapsed() > idle {
                let ent = &self.sftp.entries[be.entry];
                let note = format!("sftp: closed idle connection to {}@{}", ent.ruser, ent.label);
                self.shut(b);
                self.w.note(&note)?;
            }
        }
        Ok(())
    }

    fn finish(mut self, reason: &str, signer: &RecSigner) -> Result<()> {
        let open: Vec<u32> = self.handles.keys().copied().collect();
        for n in open {
            if let Some(h) = self.handles.remove(&n) {
                if h.back.is_some() {
                    self.close_record(h, "not-closed")?;
                }
            }
        }
        for b in 0..self.backs.len() {
            if self.backs[b].alive {
                self.shut(b);
            }
        }
        let used: Vec<String> = self.backs.iter().map(|b| self.sftp.entries[b.entry].name.clone()).collect();
        self.w.record_json("n", json!({"msg": "sftp session totals", "stats": {"operations": self.ops, "bytes_read": self.bytes_read, "bytes_written": self.bytes_written, "hosts": used}}))?;
        self.w.end(reason, Some(0), Some(signer))?;
        Ok(())
    }
}

fn new_pend(t: u8, path: String) -> Pend {
    Pend { t, ext: String::new(), back: 0, entry: 0, path, path2: String::new(), handle: None, off: 0, extra: Map::new() }
}

/// The packet with its length prefix again (responses are forwarded unchanged).
fn p_with_len(p: &[u8]) -> Vec<u8> {
    let mut v = (p.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(p);
    v
}

fn open_flags(fl: u32) -> String {
    let mut s = String::new();
    for (bit, c) in [(0x01, 'r'), (PF_WRITE, 'w'), (0x04, 'a'), (PF_CREAT, 'c'), (PF_TRUNC, 't'), (PF_EXCL, 'x')] {
        if fl & bit != 0 {
            s.push(c);
        }
    }
    s
}

fn op_name(t: u8, ext: &str) -> &'static str {
    match t {
        OPEN => "open",
        CLOSE => "close",
        READ => "read",
        WRITE => "write",
        LSTAT => "lstat",
        FSTAT => "fstat",
        SETSTAT => "setstat",
        FSETSTAT => "fsetstat",
        OPENDIR => "list",
        READDIR => "readdir",
        REMOVE => "remove",
        MKDIR => "mkdir",
        RMDIR => "rmdir",
        REALPATH => "realpath",
        STAT => "stat",
        RENAME => "rename",
        READLINK => "readlink",
        SYMLINK => "symlink",
        EXTENDED => match ext {
            "posix-rename@openssh.com" => "rename",
            "hardlink@openssh.com" => "hardlink",
            "statvfs@openssh.com" => "statvfs",
            "fstatvfs@openssh.com" => "fstatvfs",
            "fsync@openssh.com" => "fsync",
            "lsetstat@openssh.com" => "lsetstat",
            "copy-data" => "copy",
            _ => "extended",
        },
        _ => "unknown",
    }
}

fn daemon_call(req: &Req) -> Result<Resp> {
    let mut s = UnixStream::connect(swrap_core::Paths::from_env().api_sock()).context("swrapd unreachable")?;
    write_frame(&mut s, &Frame::json(kind::REQ, req))?;
    loop {
        let Some(f) = read_frame(&mut s)? else { bail!("swrapd closed the connection") };
        if f.kind == kind::RESP {
            return f.parse();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalisation_cannot_leave_the_root() {
        let n = |p: &str| normalize(p.as_bytes()).iter().map(|c| lossy(c)).collect::<Vec<_>>().join("/");
        assert_eq!(n("/web1/etc/../../../.."), "");
        assert_eq!(n("/web1/./etc//passwd"), "web1/etc/passwd");
        assert_eq!(n("../../web1/x"), "web1/x");
        assert_eq!(n("/a/b/../../c"), "c");
    }

    #[test]
    fn packets_roundtrip() {
        let p = Pk::new(STATUS).u32(7).u32(FX_EOF).str(b"end").str(b"").done();
        let body = read_packet(&mut &p[..]).unwrap().unwrap();
        assert_eq!(body[0], STATUS);
        let mut r = Rd::new(&body[1..]);
        assert_eq!((r.u32(), r.u32(), r.str()), (Some(7), Some(FX_EOF), Some(&b"end"[..])));
        assert!(read_packet(&mut &[0u8, 0x20, 0, 0][..]).is_err(), "oversized length refused");
    }

    #[test]
    fn attrs_decode() {
        let a = Pk(vec![]).u32(0x1 | 0x4).u64(42).u32(0o100644).0;
        assert_eq!(attrs_json(&a), json!({"size": 42, "mode": "644"}));
    }
}
