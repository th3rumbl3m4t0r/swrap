//! swai (spec 24, terminal edition) — daemon side.
//!
//! A swai session is opencode (pinned) in a bubblewrap sandbox on core, owned by a session
//! worker like `sw`: the worker records the TUI and serves two unix sockets the sandbox can
//! reach — an inference proxy (records m/q/a, adds the API key, applies effort) and an MCP tool
//! server. Tool calls come back here (`Req::AiWorker`) and run under AI grants only (spec 24.5):
//! the host opts in (`ai_allowed`) and the user holds an explicit `[[ai_grant]]`; admins are
//! refused. Nothing in the sandbox can reach the network, the vault or swrap's files.

use crate::daemon::{Caller, Console, Daemon};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, VecDeque};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use swrap_core::api::{AiSpec, Req, Resp, WorkerSpec};
use swrap_core::config::{AiApi, AiBackend, AiConfig, Host, HostState, Profile, Route, User};
use swrap_core::frame::{kind, write_frame, Frame};
use swrap_core::paths::safe_component;
use swrap_core::rbac::{self, Node};
use swrap_core::time::{date_dir, fmt_basic, fmt_display, fmt_duration_ms, fmt_utc, fmt_utc_secs, now, IsoDuration};

pub const EFFORTS: [&str; 5] = ["low", "medium", "high", "xhigh", "max"];
/// Pinned opencode lives here (`opencode` + `VERSION`), installed by `swrap install`.
pub const OPENCODE_DIR: &str = "/usr/libexec/swrap/opencode";
/// Pinned Claude Code (`claude` + `VERSION`): the harness for `claude-code` backends.
pub const CLAUDE_DIR: &str = "/usr/libexec/swrap/claude-code";
/// Kept per stream from a tool's output (the model sees head + tail of it).
const TOOL_CAP: usize = 8 << 20;
/// Ports tried when "add new IP" gets no port: llama.cpp, vLLM, Ollama, LM Studio, others.
const PROBE_PORTS: [u16; 7] = [8080, 8000, 11434, 1234, 5000, 8001, 30000];

pub fn http(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(false)
        .user_agent(concat!("swrap-swai/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

fn key_path(d: &Daemon, backend: &str) -> PathBuf {
    d.paths.vault_keys().join("ai").join(format!("{backend}.enc"))
}

fn opencode_version() -> String {
    std::fs::read_to_string(Path::new(OPENCODE_DIR).join("VERSION")).map(|s| s.trim().to_string()).unwrap_or_default()
}

fn claude_version() -> String {
    std::fs::read_to_string(Path::new(CLAUDE_DIR).join("VERSION")).map(|s| s.trim().to_string()).unwrap_or_default()
}

fn swai_ids() -> Option<(u32, u32)> {
    swrap_core::sys::user_by_name("swai").map(|u| (u.uid.as_raw(), u.gid.as_raw()))
}

/// The AAA user behind a request, refusing admins (spec 24.4: separation of duties).
fn ai_user(c: &Caller) -> Result<&User> {
    let u = c.aaa()?;
    if u.is_admin() {
        bail!("swai is for normal users; admins are refused (use your non-admin account)");
    }
    Ok(u)
}

// ---------------------------------------------------------------- usage index (last P30D)

fn usage_path(d: &Daemon) -> PathBuf {
    d.paths.state().join("ai-usage.json")
}

fn usage_lock() -> &'static Mutex<()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
}

fn note_usage(d: &Daemon, backend: &str, model: &str) {
    if model.is_empty() || model.len() > 200 {
        return;
    }
    let _g = usage_lock().lock().unwrap();
    let p = usage_path(d);
    let mut v: Value = std::fs::read_to_string(&p).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_else(|| json!({}));
    let e = &mut v[backend][model];
    let n = e["n"].as_u64().unwrap_or(0) + 1;
    *e = json!({"last": fmt_utc_secs(now()), "n": n});
    let _ = swrap_core::atomic::mkdirs(&d.paths.state(), 0o750, d.owner());
    if swrap_core::atomic::write(&p, v.to_string().as_bytes(), 0o640, d.owner()).is_err() {
        return;
    }
    // Versioned like the rest of state/: commit just this file (an inventory may be writing
    // other files of the repository at the same time). Best effort: a busy index retries next time.
    let repo = swrap_core::git::Repo::new(d.paths.state()).run_as(d.swrap_uid, d.swrap_gid);
    if swrap_core::git::is_repo(&d.paths.state()) {
        let f = "ai-usage.json";
        if repo.git(&["add", "--", f]).is_ok() && !repo.git_ok(&["diff", "--cached", "--quiet", "--", f]).unwrap_or(true) {
            let _ = repo.git(&["commit", "-q", "-m", &format!("{} ai usage: {backend} {model}", fmt_utc_secs(now())), "--", f]);
        }
    }
}

/// Models used with `backend` within P30D, most recent first.
fn recent_models(d: &Daemon, backend: &str) -> Vec<Value> {
    let v: Value = std::fs::read_to_string(usage_path(d)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    let cutoff = now() - jiff::SignedDuration::from_hours(30 * 24);
    let mut out: Vec<(String, String, u64)> = v[backend]
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(k, e)| {
                    let last = e["last"].as_str()?.to_string();
                    let t: jiff::Timestamp = last.parse().ok()?;
                    (t >= cutoff).then(|| (k.clone(), last, e["n"].as_u64().unwrap_or(0)))
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort_by(|a, b| b.1.cmp(&a.1));
    out.into_iter().map(|(m, last, n)| json!({"model": m, "last": last, "n": n})).collect()
}

// ---------------------------------------------------------------- wizard data

fn backend_state(d: &Daemon, b: &AiBackend) -> (bool, String) {
    if b.api == AiApi::ClaudeCode && !Path::new(CLAUDE_DIR).join("claude").exists() {
        return (false, "Claude Code is not installed (run swrap install)".into());
    }
    if b.needs_key && !key_path(d, &b.name).exists() {
        return (false, format!("no API key yet (admin: swai backend key {})", b.name));
    }
    if b.needs_key && d.is_sealed() {
        return (false, "vault sealed (an admin must log in)".into());
    }
    (true, String::new())
}

pub fn options(d: &Arc<Daemon>, c: &Caller) -> Result<Resp> {
    let user = ai_user(c)?;
    let t = now();
    let mut hosts = vec![];
    let mut others = vec![];
    for h in Host::all(&d.paths)? {
        if h.state != HostState::Active {
            continue;
        }
        let accts = rbac::ai_accounts(user, &h, t);
        if !accts.is_empty() {
            hosts.push(json!({"label": h.label, "accounts": accts, "address": h.address, "network": h.network, "tags": h.tags}));
        } else if rbac::host_visible(user, &h, Node::Core, t) || rbac::host_visible(user, &h, Node::Edge, t) {
            let why = if !h.ai_allowed { "not enabled for AI" } else { "no AI grant" };
            others.push(json!({"label": h.label, "why": why}));
        }
    }
    let ai = AiConfig::load(&d.paths)?;
    let backends: Vec<Value> = ai
        .backends
        .iter()
        .map(|b| {
            let (ready, why) = backend_state(d, b);
            json!({"name": b.name, "api": b.api.as_str(), "base_url": b.base_url, "ready": ready, "why": why, "recent": recent_models(d, &b.name), "models": b.models, "harness": if b.api == AiApi::ClaudeCode { format!("Claude Code {}", claude_version()) } else { format!("opencode {}", opencode_version()) }})
        })
        .collect();
    Ok(Resp::ok(json!({
        "user": c.name, "hosts": hosts, "others": others, "backends": backends,
        "efforts": EFFORTS, "can_add": !user.ai_grants.is_empty(), "opencode": opencode_version(),
    })))
}

/// Live model list of a backend (`GET /v1/models`).
pub fn models(d: &Arc<Daemon>, c: &Caller, backend: &str) -> Result<Resp> {
    ai_user(c)?;
    let ai = AiConfig::load(&d.paths)?;
    let b = ai.backend(backend).ok_or_else(|| anyhow!("unknown backend {backend:?}"))?;
    let key = backend_key(d, b)?;
    let list = list_models(b, key.as_deref().map(|k| k.as_str()))?;
    let list: Vec<Value> = if b.models.is_empty() { list } else { list.into_iter().filter(|m| b.models.iter().any(|x| Some(x.as_str()) == m["id"].as_str())).collect() };
    Ok(Resp::ok(json!({"models": list})))
}

fn backend_key(d: &Daemon, b: &AiBackend) -> Result<Option<zeroize::Zeroizing<String>>> {
    if !b.needs_key {
        return Ok(None);
    }
    let p = key_path(d, &b.name);
    if !p.exists() {
        bail!("backend {} has no API key yet (admin: swai backend key {})", b.name, b.name);
    }
    let raw = d.with_dek(|dek| swrap_vault::Vault::new(&d.paths, d.owner()).get(dek, &p))?;
    Ok(Some(zeroize::Zeroizing::new(String::from_utf8_lossy(&raw).trim().to_string())))
}

fn get_json(agent: &ureq::Agent, url: &str, b: &AiBackend, key: Option<&str>) -> Result<(u16, Value)> {
    let mut r = agent.get(url);
    match (&b.api, key) {
        (AiApi::Anthropic, Some(k)) => r = r.header("x-api-key", k).header("anthropic-version", "2023-06-01"),
        (AiApi::Anthropic | AiApi::ClaudeCode, _) => r = r.header("anthropic-version", "2023-06-01"),
        (AiApi::Openai, Some(k)) => r = r.header("authorization", &format!("Bearer {k}")),
        (AiApi::Openai, None) => {}
    }
    let mut resp = r.call().map_err(|e| anyhow!("{url}: {e}"))?;
    let status = resp.status().as_u16();
    let body = resp.body_mut().with_config().limit(8 << 20).read_to_string().unwrap_or_default();
    Ok((status, serde_json::from_str(&body).unwrap_or(Value::Null)))
}

fn api_error(v: &Value) -> String {
    v["error"]["message"].as_str().or(v["error"].as_str()).or(v["message"].as_str()).unwrap_or("").to_string()
}

/// Claude Code resolves the aliases to the newest model of the family your plan allows; after
/// them, the specific models the installed Claude Code knows (`MODELS`, written by install and
/// the nightly update: `id<TAB>name`).
fn claude_code_models() -> Vec<Value> {
    let mut v = vec![
        json!({"id": "opus", "name": "latest Opus"}),
        json!({"id": "sonnet", "name": "latest Sonnet"}),
        json!({"id": "haiku", "name": "latest Haiku (fastest)"}),
        json!({"id": "fable", "name": "latest Fable, if your plan includes it"}),
    ];
    for l in std::fs::read_to_string(Path::new(CLAUDE_DIR).join("MODELS")).unwrap_or_default().lines() {
        if let Some((id, name)) = l.split_once('\t') {
            v.push(json!({"id": id, "name": name}));
        }
    }
    v
}

fn list_models(b: &AiBackend, key: Option<&str>) -> Result<Vec<Value>> {
    if b.api == AiApi::ClaudeCode {
        return Ok(claude_code_models());
    }
    let agent = http(Duration::from_secs(8));
    let base = b.base_url.trim_end_matches('/');
    let mut out = vec![];
    let mut url = format!("{base}/v1/models?limit=1000");
    for _ in 0..10 {
        let (st, v) = get_json(&agent, &url, b, key)?;
        if st != 200 {
            bail!("{} answered HTTP {st} for /v1/models {}", b.name, api_error(&v));
        }
        for m in v["data"].as_array().cloned().unwrap_or_default() {
            let id = m["id"].as_str().unwrap_or("").to_string();
            if id.is_empty() {
                continue;
            }
            let ctx = m["max_input_tokens"].as_u64().or(m["max_model_len"].as_u64()).or(m["meta"]["n_ctx_train"].as_u64()).or(m["context_length"].as_u64());
            out.push(json!({"id": id, "name": m["display_name"].as_str().unwrap_or(""), "context": ctx}));
        }
        // Anthropic paginates with has_more/last_id.
        match (v["has_more"].as_bool(), v["last_id"].as_str()) {
            (Some(true), Some(last)) => url = format!("{base}/v1/models?limit=1000&after_id={last}"),
            _ => break,
        }
    }
    // LM Studio says more: model type (drop embedding models), loaded state and context.
    if b.api == AiApi::Openai {
        if let Ok((200, v)) = get_json(&agent, &format!("{base}/api/v0/models"), b, key) {
            let info: std::collections::HashMap<String, Value> = v["data"].as_array().into_iter().flatten().filter_map(|m| Some((m["id"].as_str()?.to_string(), m.clone()))).collect();
            out.retain(|m| info.get(m["id"].as_str().unwrap_or("")).map(|i| i["type"] != "embeddings").unwrap_or(true));
            for m in out.iter_mut() {
                if let Some(i) = info.get(m["id"].as_str().unwrap_or("")) {
                    let loaded = i["state"] == "loaded";
                    m["context"] = json!(i["loaded_context_length"].as_u64().or(i["max_context_length"].as_u64()));
                    m["name"] = json!(if loaded { "loaded" } else { "" });
                }
            }
            // Loaded models first: they answer without a load delay.
            out.sort_by_key(|m| m["name"] != "loaded");
        }
    }
    Ok(out)
}

pub struct ModelInfo {
    pub context: u64,
    pub max_output: u64,
    pub efforts: Vec<String>,
    pub adaptive: bool,
}

/// Limits and capabilities of a model; conservative fallbacks when the backend can't say.
fn model_info(b: &AiBackend, key: Option<&str>, model: &str) -> ModelInfo {
    let agent = http(Duration::from_secs(5));
    let base = b.base_url.trim_end_matches('/');
    match b.api {
        // Claude Code manages context, output and effort itself (`--effort`).
        AiApi::ClaudeCode => ModelInfo { context: 0, max_output: 0, efforts: EFFORTS.iter().map(|e| e.to_string()).collect(), adaptive: true },
        AiApi::Anthropic => {
            if let Ok((200, m)) = get_json(&agent, &format!("{base}/v1/models/{model}"), b, key) {
                let caps = &m["capabilities"];
                let efforts: Vec<String> = if caps["effort"]["supported"].as_bool() == Some(true) {
                    EFFORTS.iter().filter(|l| caps["effort"][**l]["supported"].as_bool() == Some(true)).map(|l| l.to_string()).collect()
                } else {
                    vec![]
                };
                return ModelInfo {
                    context: m["max_input_tokens"].as_u64().unwrap_or(200_000),
                    max_output: m["max_tokens"].as_u64().unwrap_or(32_000),
                    adaptive: caps["thinking"]["types"]["adaptive"]["supported"].as_bool() == Some(true),
                    efforts,
                };
            }
            // Offline table (claude-api model catalog): effort is refused by Haiku 4.5 / Sonnet 4.5.
            let old = ["claude-haiku-4-5", "claude-sonnet-4-5", "claude-opus-4-1", "claude-opus-4-0", "claude-sonnet-4-0", "claude-3"].iter().any(|p| model.starts_with(p));
            if old {
                ModelInfo { context: 200_000, max_output: 64_000, efforts: vec![], adaptive: false }
            } else {
                // Unknown but current: assume the full ladder; a 400 turns effort off for the session.
                ModelInfo { context: 1_000_000, max_output: 128_000, efforts: EFFORTS.iter().map(|e| e.to_string()).collect(), adaptive: true }
            }
        }
        AiApi::Openai => {
            let mut ctx = None;
            if let Ok((200, v)) = get_json(&agent, &format!("{base}/v1/models"), b, key) {
                if let Some(m) = v["data"].as_array().and_then(|a| a.iter().find(|m| m["id"] == model)) {
                    ctx = m["max_model_len"].as_u64().or(m["meta"]["n_ctx_train"].as_u64()).or(m["context_length"].as_u64());
                }
            }
            // LM Studio: the context a loaded model runs with (or its maximum).
            if let Ok((200, m)) = get_json(&agent, &format!("{base}/api/v0/models/{model}"), b, key) {
                if let Some(n) = m["loaded_context_length"].as_u64().or(m["max_context_length"].as_u64()).filter(|n| *n > 0) {
                    ctx = Some(n);
                }
            }
            // llama.cpp reports the context it actually runs with on /props.
            if let Ok((200, p)) = get_json(&agent, &format!("{base}/props"), b, key) {
                if let Some(n) = p["default_generation_settings"]["n_ctx"].as_u64().filter(|n| *n > 0) {
                    ctx = Some(ctx.map(|c| c.min(n)).unwrap_or(n));
                }
            }
            let context = ctx.unwrap_or(32_768);
            ModelInfo { context, max_output: (context / 4).clamp(1024, 32_768), efforts: vec![], adaptive: false }
        }
    }
}

// ---------------------------------------------------------------- add a backend by IP

fn core_addrs() -> Vec<std::net::IpAddr> {
    let mut v = vec![];
    if let Ok(o) = std::process::Command::new("ip").args(["-o", "addr", "show"]).output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() > 3 {
                if let Some(ip) = f[3].split('/').next().and_then(|a| a.parse().ok()) {
                    v.push(ip);
                }
            }
        }
    }
    v
}

fn parse_addr(addr: &str) -> Result<(std::net::IpAddr, Option<u16>)> {
    let a = addr.trim().trim_start_matches("http://").trim_end_matches('/').trim_end_matches("/v1");
    if let Ok(sa) = a.parse::<std::net::SocketAddr>() {
        return Ok((sa.ip(), Some(sa.port())));
    }
    if let Ok(ip) = a.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
        return Ok((ip, None));
    }
    if let Some((h, p)) = a.rsplit_once(':') {
        if let (Ok(ip), Ok(port)) = (h.parse::<std::net::IpAddr>(), p.parse::<u16>()) {
            return Ok((ip, Some(port)));
        }
    }
    bail!("give an IP address, optionally with :port (e.g. 10.0.0.20 or 10.0.0.20:8080)")
}

pub fn add_backend(d: &Arc<Daemon>, c: &Caller, addr: &str, con: &Console) -> Result<Resp> {
    let user = if c.admin { None } else { Some(ai_user(c)?) };
    if let Some(u) = user {
        if u.ai_grants.is_empty() {
            bail!("adding inference servers needs an AI grant");
        }
    }
    let (ip, port) = parse_addr(addr)?;
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || core_addrs().contains(&ip) {
        bail!("{ip} is not usable as an inference server (loopback, unspecified, multicast or this host)");
    }
    if let std::net::IpAddr::V4(v4) = ip {
        if v4.is_link_local() || v4.is_broadcast() {
            bail!("{ip} is not usable as an inference server");
        }
    }
    let host = if ip.is_ipv6() { format!("[{ip}]") } else { ip.to_string() };
    let ports: Vec<u16> = match port {
        Some(p) => vec![p],
        None => PROBE_PORTS.to_vec(),
    };
    let agent = http(Duration::from_millis(1500));
    let mut found = None;
    for p in &ports {
        let base = format!("http://{host}:{p}");
        con.out(format!("probing {base}/v1/models …"));
        let probe = AiBackend { name: String::new(), api: AiApi::Openai, base_url: base.clone(), models: vec![], needs_key: false, timeout: "PT1H".into(), max_concurrent: 0, added_by: String::new(), created: String::new() };
        if let Ok((200, v)) = get_json(&agent, &format!("{base}/v1/models"), &probe, None) {
            if let Some(a) = v["data"].as_array() {
                let names: Vec<String> = a.iter().filter_map(|m| m["id"].as_str().map(String::from)).collect();
                found = Some((base, *p, names));
                break;
            }
        }
    }
    let Some((base, p, names)) = found else {
        bail!("no OpenAI-compatible server answered on {host} (ports tried: {}); llama.cpp, vLLM, Ollama and LM Studio serve /v1/models", ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "))
    };
    let name = format!("{ip}:{p}");
    {
        let _g = d.config_lock.lock().unwrap();
        let mut ai = AiConfig::load(&d.paths)?;
        if ai.backend(&name).is_none() && !ai.backends.iter().any(|b| b.base_url == base) {
            ai.backends.push(AiBackend { name: name.clone(), api: AiApi::Openai, base_url: base.clone(), models: vec![], needs_key: false, timeout: "PT1H".into(), max_concurrent: 0, added_by: c.name.clone(), created: fmt_utc_secs(now()) });
            d.write_config("ai.toml", &ai.to_toml())?;
            d.commit(&format!("swai backend {name} added by {}", c.name))?;
        }
    }
    d.audit_event(&c.name, "ai.backend.add", &name, "", "ok", json!({"base_url": base, "models": names}), "");
    Ok(Resp { ok: true, data: json!({"name": name, "models": names}), text: format!("added {name} ({} models)\n", names.len()), ..Default::default() })
}

// ---------------------------------------------------------------- sessions

struct Session {
    id: String,
    user: String,
    token_hash: blake3::Hash,
    mode: String,
    label: String,
    ruser: String,
    backend: String,
    max_calls: usize,
    calls: AtomicUsize,
    /// What a handoff successor starts with (the same as this session).
    model: String,
    effort: String,
    loose: bool,
    /// Place in a handoff chain (0 = started by the user).
    chain: usize,
}

/// A successor started by `handoff`: its first prompt, its predecessor, its place in the chain.
struct Handoff {
    prompt: String,
    continues: String,
    chain: usize,
}

fn sessions() -> &'static Mutex<HashMap<String, Arc<Session>>> {
    static S: OnceLock<Mutex<HashMap<String, Arc<Session>>>> = OnceLock::new();
    S.get_or_init(Default::default)
}

fn session_file(d: &Daemon, id: &str) -> PathBuf {
    d.paths.ai_run().join(id).join("session.json")
}

/// Registered sessions survive daemon restarts through a root-only file next to the sockets.
fn lookup(d: &Daemon, id: &str) -> Option<Arc<Session>> {
    if !safe_component(id) {
        return None;
    }
    if let Some(s) = sessions().lock().unwrap().get(id) {
        return Some(s.clone());
    }
    let v: Value = serde_json::from_str(&std::fs::read_to_string(session_file(d, id)).ok()?).ok()?;
    let s = Arc::new(Session {
        id: id.to_string(),
        user: v["user"].as_str()?.to_string(),
        token_hash: blake3::Hash::from_hex(v["token_b3"].as_str()?).ok()?,
        mode: v["mode"].as_str()?.to_string(),
        label: v["label"].as_str().unwrap_or("").to_string(),
        ruser: v["ruser"].as_str().unwrap_or("").to_string(),
        backend: v["backend"].as_str().unwrap_or("").to_string(),
        max_calls: v["max_calls"].as_u64().unwrap_or(500) as usize,
        calls: AtomicUsize::new(v["calls"].as_u64().unwrap_or(0) as usize),
        model: v["model"].as_str().unwrap_or("").to_string(),
        effort: v["effort"].as_str().unwrap_or("").to_string(),
        loose: v["loose"].as_bool().unwrap_or(false),
        chain: v["chain"].as_u64().unwrap_or(0) as usize,
    });
    sessions().lock().unwrap().insert(id.to_string(), s.clone());
    Some(s)
}

/// Runtime dirs of sessions whose worker is gone (killed, crashed) are removed.
fn sweep(d: &Daemon) {
    let live: Vec<String> = crate::session::live_sessions(d).iter().filter(|j| j["kind"] == "ai").filter_map(|j| j["id"].as_str().map(String::from)).collect();
    if let Ok(rd) = std::fs::read_dir(d.paths.ai_run()) {
        for e in rd.flatten() {
            let id = e.file_name().to_string_lossy().to_string();
            let young = e.metadata().and_then(|m| m.modified()).map(|t| t.elapsed().map(|x| x < Duration::from_secs(60)).unwrap_or(true)).unwrap_or(true);
            if !live.contains(&id) && !young {
                let _ = std::fs::remove_dir_all(e.path());
                sessions().lock().unwrap().remove(&id);
            }
        }
    }
}

fn live_ai(d: &Daemon, user: &str) -> usize {
    crate::session::live_sessions(d).iter().filter(|j| j["kind"] == "ai" && j["user"] == user).count()
}

pub fn start(d: Arc<Daemon>, c: Caller, req: Req, mut s: UnixStream, origin: Node, delegated: bool) -> Result<()> {
    if let Err(e) = start_inner(&d, &c, &req, &s, origin, delegated, None) {
        let msg = format!("{e:#}");
        let msg = if msg.starts_with("swai:") || msg.starts_with("swrap:") { msg } else { format!("swai: {msg}") };
        let target = match &req {
            Req::AiStart { target, .. } => target.clone(),
            _ => String::new(),
        };
        d.audit_event(&c.name, "ai.refused", &target, "", "refused", json!({"error": msg, "origin": origin.as_str()}), "");
        let _ = write_frame(&mut s, &Frame::json(kind::RESP, &Resp::err(msg)));
    }
    Ok(())
}

// ---------------------------------------------------------------- tmux-like: list / attach / kill

/// The caller's running sessions (live markers written by the workers), newest first.
fn my_sessions(d: &Daemon, user: &str) -> Vec<Value> {
    let mut v: Vec<Value> = crate::session::live_sessions(d).into_iter().filter(|j| j["kind"] == "ai" && j["user"] == user).collect();
    v.sort_by(|a, b| b["started"].as_str().unwrap_or("").cmp(a["started"].as_str().unwrap_or("")));
    v
}

fn ago(ts: &str) -> String {
    ts.parse::<jiff::Timestamp>()
        .ok()
        .map(|t| {
            let secs = (now().as_second() - t.as_second()).max(0) as u64;
            let d = Duration::from_secs(secs);
            if secs < 60 { "PT0M".into() } else { swrap_core::time::fmt_duration(Duration::from_secs(d.as_secs() / 60 * 60)) }
        })
        .unwrap_or_default()
}

pub fn list(d: &Arc<Daemon>, c: &Caller) -> Result<Resp> {
    ai_user(c)?;
    let rows = my_sessions(d, &c.name);
    let tz = d.tz();
    let mut text = String::new();
    for j in &rows {
        let started = j["started"].as_str().and_then(|t| t.parse::<jiff::Timestamp>().ok()).map(|t| fmt_display(t, &tz, false)).unwrap_or_default();
        let state = if j["attached"] == true {
            format!("attached from {}", j["client_addr"].as_str().filter(|x| !x.is_empty()).unwrap_or("?"))
        } else {
            format!("detached for {}", ago(j["since"].as_str().unwrap_or("")))
        };
        text += &format!("{}  {:<20} {} {}{}  started {started}  {state}
", j["id"].as_str().unwrap_or(""), j["target"].as_str().unwrap_or(""), j["backend"].as_str().unwrap_or(""), j["model"].as_str().unwrap_or(""), j["effort"].as_str().filter(|e| !e.is_empty()).map(|e| format!(" ({e})")).unwrap_or_default());
    }
    if rows.is_empty() {
        text = "no running swai sessions\n".into();
    }
    Ok(Resp { ok: true, data: json!(rows), text, ..Default::default() })
}

/// Resolve `id` (full, unique prefix, or "" = the latest detached) among the caller's sessions.
fn pick_session(d: &Daemon, user: &str, id: &str) -> Result<Value> {
    let mine = my_sessions(d, user);
    if id.is_empty() {
        return mine.iter().find(|j| j["attached"] != true).or(mine.first()).cloned().ok_or_else(|| anyhow!("no running swai sessions (start one with swai)"));
    }
    // Full id, or its start, or (more distinctive for ULIDs started close together) its end.
    let want = id.to_lowercase();
    let m: Vec<&Value> = mine.iter().filter(|j| j["id"].as_str().map(|x| { let x = x.to_lowercase(); x == want || x.starts_with(&want) || x.ends_with(&want) }).unwrap_or(false)).collect();
    match m.len() {
        1 => Ok(m[0].clone()),
        0 => bail!("no running swai session {id} of yours (see swai ls)"),
        _ => bail!("{id} matches {} sessions; give more of the id", m.len()),
    }
}

pub fn attach(d: Arc<Daemon>, c: Caller, req: Req, mut s: UnixStream, origin: Node) -> Result<()> {
    let r = (|| -> Result<String> {
        let Req::AiAttach { id, cols, rows, term, client_addr } = &req else { bail!("not an attach request") };
        ai_user(&c)?;
        let j = pick_session(&d, &c.name, id)?;
        let id = j["id"].as_str().unwrap_or("").to_string();
        if !safe_component(&id) {
            bail!("bad session id");
        }
        let ctl = d.paths.ai_run().join(&id).join("ctl").join("ctl.sock");
        let conn = UnixStream::connect(&ctl).context("the session does not accept attaches (ended?)")?;
        conn.set_read_timeout(Some(Duration::from_secs(5)))?;
        let hdr = json!({"cols": cols, "rows": rows, "term": term, "client_addr": client_addr, "origin": origin.as_str(), "user": c.name}).to_string();
        use std::os::fd::AsRawFd;
        let fds = [s.as_raw_fd()];
        nix::sys::socket::sendmsg::<()>(conn.as_raw_fd(), &[std::io::IoSlice::new(hdr.as_bytes())], &[nix::sys::socket::ControlMessage::ScmRights(&fds)], nix::sys::socket::MsgFlags::empty(), None)?;
        let mut ack = [0u8; 1];
        use std::io::Read;
        if (&conn).read(&mut ack).ok() != Some(1) {
            bail!("the session did not take the connection");
        }
        Ok(id)
    })();
    match r {
        Ok(id) => d.audit_event(&c.name, "ai.attach", "", "", "ok", json!({"origin": origin.as_str()}), &id),
        Err(e) => {
            let msg = format!("swai: {e:#}");
            let _ = write_frame(&mut s, &Frame::json(kind::RESP, &Resp::err(msg)));
        }
    }
    Ok(())
}

fn kill(d: &Daemon, c: &Caller, id: &str) -> Result<Resp> {
    let j = if c.admin {
        let want = id.to_lowercase();
        let all: Vec<Value> = crate::session::live_sessions(d).into_iter().filter(|j| j["kind"] == "ai" && !want.is_empty() && j["id"].as_str().map(|x| { let x = x.to_lowercase(); x.starts_with(&want) || x.ends_with(&want) }).unwrap_or(false)).collect();
        match all.len() {
            1 => all[0].clone(),
            0 => bail!("no running swai session {id}"),
            _ => bail!("{id} matches several sessions"),
        }
    } else {
        ai_user(c)?;
        if id.is_empty() {
            bail!("which session? (swai ls)");
        }
        pick_session(d, &c.name, id)?
    };
    let pid = j["pid"].as_i64().unwrap_or(0) as i32;
    if pid <= 1 {
        bail!("no worker for that session");
    }
    unsafe { libc::kill(pid, libc::SIGTERM) };
    d.audit_event(&c.name, "ai.kill", j["target"].as_str().unwrap_or(""), "", "ok", json!({"owner": j["user"]}), j["id"].as_str().unwrap_or(""));
    Ok(Resp::text(format!("swai session {} ended\n", j["id"].as_str().unwrap_or(""))))
}

fn valid_model(m: &str) -> bool {
    !m.is_empty() && m.len() <= 200 && m.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:/@+-".contains(&b))
}

/// MemAvailable of /proc/meminfo in MiB.
fn mem_available_mb() -> Option<u64> {
    let m = std::fs::read_to_string("/proc/meminfo").ok()?;
    let kb: u64 = m.lines().find_map(|l| l.strip_prefix("MemAvailable:"))?.trim().trim_end_matches("kB").trim().parse().ok()?;
    Some(kb / 1024)
}

/// Starts a session for `c` (`s`: the client's connection). A handoff successor has no client
/// yet (it runs detached until one attaches) and starts from its predecessor's briefing.
fn start_inner(d: &Arc<Daemon>, c: &Caller, req: &Req, s: &UnixStream, origin: Node, delegated: bool, handoff: Option<&Handoff>) -> Result<String> {
    let Req::AiStart { target, backend, model, effort, cols, rows, term, client_addr, conn, resume, loose } = req else { bail!("not an AI session request") };
    let loose = *loose;
    let resume_ok = resume.is_empty()
        || resume == "last"
        || (resume.starts_with("ses_") && resume.len() <= 64 && resume.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        || (resume.len() == 36 && resume.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'));
    if !resume_ok {
        bail!("bad session to continue {resume:?}");
    }
    let user = ai_user(c)?.clone();
    let t = now();
    let ai = AiConfig::load(&d.paths)?;
    let b = ai.backend(backend).ok_or_else(|| anyhow!("unknown inference backend {backend:?}"))?.clone();
    if !valid_model(model) {
        bail!("bad model name {model:?}");
    }
    if !b.models.is_empty() && !b.models.iter().any(|m| m == model) {
        bail!("model {model} is not allowed on {backend} (allowed: {})", b.models.join(", "));
    }
    let effort = match effort.as_str() {
        "" | "default" => String::new(),
        e if EFFORTS.contains(&e) => e.to_string(),
        e => bail!("effort must be one of {} (got {e:?})", EFFORTS.join(", ")),
    };
    let (swai_uid, swai_gid) = swai_ids().context("the swai system user is missing (run swrap install)")?;
    let claude = b.api == AiApi::ClaudeCode;
    let oc = Path::new(OPENCODE_DIR).join("opencode");
    let cc = Path::new(CLAUDE_DIR).join("claude");
    if claude && !cc.exists() {
        bail!("Claude Code is not installed ({}); run swrap install", cc.display());
    }
    if !claude && !oc.exists() {
        bail!("opencode is not installed ({}); run swrap install", oc.display());
    }
    // Target: one host (lean tools, capped context) or the AAA (all AI hosts + swrap records).
    let (mode, label, ruser, host) = if target == "aaa" {
        ("aaa".to_string(), String::new(), String::new(), None)
    } else {
        let (ru, label) = match target.split_once('@') {
            Some((u, l)) => (Some(u.to_string()), l.to_string()),
            None => (None, target.clone()),
        };
        let host = Host::load(&d.paths, &label).map_err(|_| anyhow!("unknown host {label:?}"))?;
        let accts = rbac::ai_accounts(&user, &host, t);
        if accts.is_empty() {
            bail!("no AI access to {label} ({}; an admin grants it with: swai host {label} on; swai grant {} {label} <accounts>)", if host.ai_allowed { "no AI grant" } else { "host not enabled for AI" }, user.name);
        }
        let ruser = match ru {
            Some(r) if accts.contains(&r) => r,
            Some(r) => bail!("no AI grant for {r}@{label}"),
            None => accts[0].clone(),
        };
        ("host".to_string(), label, ruser, Some(host))
    };
    if loose && mode != "host" {
        bail!("letting the AI loose (no permission prompts) is for one host, not the whole AAA");
    }
    sweep(d);
    // A successor replaces its predecessor, which ends seconds later: no limit checks.
    if handoff.is_none() {
        if let Some(avail) = mem_available_mb() {
            if avail < ai.limits.min_available_mb {
                bail!("core is low on memory ({avail} MiB available, a new swai session needs {} MiB); end a session first (swai ls, swai kill <id>)", ai.limits.min_available_mb);
            }
        }
    }
    if handoff.is_none() && live_ai(d, &c.name) >= ai.limits.sessions_per_user {
        bail!("you already run {} swai sessions (the limit); see them with swai ls, reattach with swai attach, end one with swai kill <id>", ai.limits.sessions_per_user);
    }
    let key = backend_key(d, &b)?;
    let info = model_info(&b, key.as_deref().map(|k| k.as_str()), model);
    drop(key);
    let context = if mode == "host" && ai.limits.host_context > 0 { info.context.min(ai.limits.host_context) } else { info.context };

    let id = swrap_core::new_id();
    let token = crate::util::random_hex(32);
    // Runtime dir: session.json (root only) + sock/ (swrap:swai 0750, bound into the sandbox).
    let run_dir = d.paths.ai_run().join(&id);
    std::fs::create_dir_all(d.paths.ai_run())?;
    std::fs::set_permissions(d.paths.ai_run(), std::fs::Permissions::from_mode(0o711))?;
    std::fs::create_dir(&run_dir)?;
    std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o711))?;
    let sock_dir = run_dir.join("sock");
    std::fs::create_dir(&sock_dir)?;
    std::fs::set_permissions(&sock_dir, std::fs::Permissions::from_mode(0o750))?;
    std::os::unix::fs::chown(&sock_dir, Some(d.swrap_uid), Some(swai_gid))?;
    let chain = handoff.map(|h| h.chain).unwrap_or(0);
    let reg = json!({"user": c.name, "token_b3": blake3::hash(token.as_bytes()).to_hex().to_string(), "mode": mode, "label": label, "ruser": ruser, "backend": b.name, "max_calls": ai.limits.max_tool_calls, "started": fmt_utc(t),
                     "model": model, "effort": effort, "loose": loose, "chain": chain});
    swrap_core::atomic::write(&session_file(d, &id), reg.to_string().as_bytes(), 0o600, swrap_core::atomic::Owner::new(0, 0))?;
    // Persistent homes: opencode per (user, target); Claude Code one per user (it holds the
    // Claude login) with a working directory per target, which keys its conversation history.
    let tgt_dir = if mode == "aaa" { "aaa".to_string() } else { label.clone() };
    let home = if claude { d.paths.ai_homes().join(&c.name).join("claude") } else { d.paths.ai_homes().join(&c.name).join(&tgt_dir) };
    for (p, mode_bits, own) in [
        (d.paths.root.join("ai"), 0o711, (0, 0)),
        (d.paths.ai_homes(), 0o711, (0, 0)),
        (d.paths.ai_homes().join(&c.name), 0o700, (swai_uid, swai_gid)),
        (home.clone(), 0o700, (swai_uid, swai_gid)),
    ] {
        if !p.exists() {
            std::fs::create_dir(&p)?;
        }
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode_bits))?;
        std::os::unix::fs::chown(&p, Some(own.0), Some(own.1))?;
    }
    let workdir = format!("/{tgt_dir}");
    if claude {
        trust_workdir(&home, &workdir, swai_uid, swai_gid);
    }

    let rec_dir = crate::session::ensure_rec_dir(d, &c.name)?;
    let rec_path = rec_dir.join("ai").join(date_dir(t)).join(format!("{}_{}_{}.swrec", fmt_basic(t), id, tgt_dir));
    let ocv = opencode_version();
    let mut header = Map::new();
    header.insert("kind".into(), "ai".into());
    for (k, v) in [
        ("origin", json!(origin.as_str())),
        ("exec", json!("core")),
        ("delegated", json!(delegated)),
        ("aaa_user", json!(c.name)),
        ("client_addr", json!(client_addr)),
        ("conn", json!(conn)),
        ("target", json!(target)),
        ("mode", json!(mode)),
        ("label", json!(label)),
        ("ruser", json!(ruser)),
        ("backend", json!(b.name)),
        ("api", json!(b.api.as_str())),
        ("model", json!(model)),
        ("effort", json!(effort)),
        ("cols", json!(cols)),
        ("rows", json!(rows)),
        ("term", json!(term)),
        ("config_rev", json!(d.config_rev())),
        ("record_input", json!(true)),
        ("harness", json!(if claude { format!("claude-code {}", claude_version()) } else { format!("opencode {ocv}") })),
        ("loose", json!(loose)),
        ("attribution", json!("session")),
    ] {
        header.insert(k.into(), v);
    }
    if let Some(h) = handoff {
        header.insert("continues".into(), json!(h.continues));
        header.insert("chain".into(), json!(h.chain));
    }
    let cfg = d.cfg();
    let what = if mode == "aaa" { "aaa".to_string() } else { format!("{ruser}@{label}") };
    let mut banner = format!(
        "swai: recording {id} · {what} · {} {model}{} · {} (keystrokes recorded)",
        b.name,
        if effort.is_empty() { String::new() } else { format!(" · effort {effort}") },
        fmt_display(t, cfg.tz(), false)
    );
    if let Some(h) = handoff {
        banner.push_str(&format!("\r\nswai: handoff {}/{}: continues session {} with a fresh budget of {} tool calls", h.chain, ai.limits.max_handoffs, h.continues, ai.limits.max_tool_calls));
    }
    if loose {
        banner.push_str(&format!("\r\nswai: LOOSE: no permission prompts{} on {what}; every action is still recorded", if claude { " (--dangerously-skip-permissions)" } else { "" }));
    }
    if let Some(u) = crate::session::view_url(d, origin, &id) {
        banner.push_str(&format!("\r\nswrap: view {u}"));
    }
    let hosts_list = if mode == "aaa" { ai_hosts_text(d, &user) } else { String::new() };
    let spec = WorkerSpec {
        mode: "ai".into(),
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
        nonce: String::new(),
        record_input: true,
        signer: "core".into(),
        recsign_key: d.paths.recsign().join("ed25519.key").to_string_lossy().into(),
        rec_cfg: cfg.rec.clone(),
        live_marker: d.paths.live().join(&id).to_string_lossy().into(),
        banner,
        sshd_pid: 0,
        ai: Some(AiSpec {
            token,
            mode: mode.clone(),
            label: label.clone(),
            ruser: ruser.clone(),
            backend: b.name.clone(),
            api: b.api.as_str().into(),
            base_url: b.base_url.trim_end_matches('/').to_string(),
            needs_key: b.needs_key,
            model: model.clone(),
            effort: effort.clone(),
            effort_levels: info.efforts.clone(),
            adaptive: info.adaptive,
            context,
            max_output: info.max_output,
            timeout_secs: IsoDuration::parse(&b.timeout).ok().and_then(|x| x.exact()).map(|x| x.as_secs()).unwrap_or(600),
            run_dir: run_dir.to_string_lossy().into(),
            home: home.to_string_lossy().into(),
            swai_uid,
            swai_gid,
            swrap_uid: d.swrap_uid,
            swrap_gid: d.swrap_gid,
            admin_gid: d.admin_gid,
            opencode: oc.to_string_lossy().into(),
            opencode_version: ocv,
            helper: swrap_core::paths::libexec("swrap").to_string_lossy().into(),
            system_prompt: system_prompt(&mode, &user.name, host.as_ref(), &ruser, &hosts_list, cfg.tz()),
            tools: tool_defs(&mode),
            max_tool_calls: ai.limits.max_tool_calls,
            tz: cfg.tz().to_string(),
            approval: if loose || ai.limits.approval == "allow" { "allow".into() } else { "ask".into() },
            loose,
            first_prompt: handoff.map(|h| h.prompt.clone()).unwrap_or_default(),
            handoff_warn: ai.limits.handoff_warn,
            chain,
            max_handoffs: ai.limits.max_handoffs,
            resume: resume.clone(),
            detached_secs: IsoDuration::parse(&ai.limits.detached_timeout).ok().and_then(|x| x.exact()).map(|x| x.as_secs()).unwrap_or(7 * 86400),
            harness: if claude { "claude".into() } else { "opencode".into() },
            // The version current now (`claude` links into `v/<version>/`): the sandbox mounts
            // that version's directory, so a nightly update never changes it under the session.
            claude: std::fs::canonicalize(&cc).unwrap_or(cc.clone()).to_string_lossy().into(),
            workdir: workdir.clone(),
        }),
        sftp: None,
    };
    let pid = crate::session::spawn_worker_ex(d, &spec, s, true)?;
    note_usage(d, &b.name, model);
    d.audit_event(&c.name, "ai.start", if mode == "aaa" { "aaa" } else { &label }, &ruser, "ok", json!({"backend": b.name, "model": model, "effort": effort, "loose": loose, "continues": handoff.map(|h| h.continues.as_str()), "chain": chain, "origin": origin.as_str(), "delegated": delegated, "client_addr": client_addr, "worker_pid": pid}), &id);
    Ok(id)
}

/// Claude Code asks whether to trust a new working directory; ours are empty per-target
/// directories, so answer it once (merged into its config; it owns the rest of that file).
fn trust_workdir(home: &Path, workdir: &str, uid: u32, gid: u32) {
    let p = home.join(".claude.json");
    let mut v: Value = std::fs::read_to_string(&p).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_else(|| json!({}));
    if v["projects"][workdir]["hasTrustDialogAccepted"] == true {
        return;
    }
    if !v["projects"].is_object() {
        v["projects"] = json!({});
    }
    if !v["projects"][workdir].is_object() {
        v["projects"][workdir] = json!({});
    }
    v["projects"][workdir]["hasTrustDialogAccepted"] = json!(true);
    let _ = swrap_core::atomic::write(&p, serde_json::to_string_pretty(&v).unwrap_or_default().as_bytes(), 0o600, swrap_core::atomic::Owner::new(uid, gid));
}

fn ai_hosts_text(d: &Daemon, user: &User) -> String {
    let t = now();
    let mut s = String::new();
    for h in Host::all(&d.paths).unwrap_or_default() {
        let accts = rbac::ai_accounts(user, &h, t);
        if accts.is_empty() {
            continue;
        }
        let tags = if h.tags.is_empty() { String::new() } else { format!("; tags {}", h.tags.join(",")) };
        s += &format!("- {}: {}; {}; network {}{tags}\n", h.label, accts.join(","), h.address, if h.network == Route::Edge { "edge" } else { "core" });
    }
    s
}

const GUIDANCE: &str = "Work in small, verifiable steps and check results. Before anything destructive or disruptive \
(deleting data, stopping or restarting services, upgrades, firewall or network changes, reboots) state exactly what \
you will do and wait for the user's go-ahead. exec is non-interactive (no TTY): avoid prompts, pagers and editors \
(use -y, --no-pager, sed or write_file instead). Be concise. Tool calls per session are limited: when a tool result \
says few are left (or none), call handoff with a complete briefing. A new session with a fresh budget continues the work \
from that briefing alone, so put everything in it: the goal, what is done and verified, the current state, what is left, \
the exact next step, and the paths, commands and findings it needs.";

fn system_prompt(mode: &str, user: &str, host: Option<&Host>, ruser: &str, hosts_list: &str, tz: &str) -> String {
    match host {
        Some(h) => {
            let tags = if h.tags.is_empty() { String::new() } else { format!(", tags {}", h.tags.join(",")) };
            format!(
                "You are swai, an assistant operating one server through swrap, an audited SSH jump host. Every tool call and its complete output is recorded.\n\n\
                 Target: {ruser}@{} ({}{tags}). The tools act on the target as {ruser}: exec, read_file, write_file, edit_file; paths are on the target.\n\n\
                 {GUIDANCE} Times are ISO 8601 (display zone {tz}).",
                h.label, h.address
            )
        }
        None => {
            let _ = mode;
            let list = if hosts_list.is_empty() { "(none: only swrap records are available)\n".to_string() } else { hosts_list.to_string() };
            format!(
                "You are swai, an assistant for {user} on swrap, an audited SSH jump host (AAA). Every tool call and its complete output is recorded.\n\n\
                 Hosts you may act on (label: accounts, first is the default; address; network; tags):\n{list}\n\
                 Host tools take target = \"label\" or \"account@label\": exec, read_file, write_file, edit_file.\n\
                 swrap tools read {user}'s own records: sessions (recordings in a time window), search (full text across recordings), transcript (text of one recording by id). Use them to answer questions about past work.\n\n\
                 {GUIDANCE} Times are ISO 8601 (display zone {tz})."
            )
        }
    }
}

fn tool_defs(mode: &str) -> Value {
    let aaa = mode == "aaa";
    let with_target = |mut props: Value, required: &[&str]| -> Value {
        let mut req: Vec<Value> = required.iter().map(|r| json!(r)).collect();
        if aaa {
            props["target"] = json!({"type": "string", "description": "Host label or account@label."});
            req.insert(0, json!("target"));
        }
        json!({"type": "object", "properties": props, "required": req})
    };
    let mut tools = vec![
        json!({"name": "exec", "description": "Run a non-interactive shell command on the host (bash -lc; no TTY). Returns exit code, stdout and stderr; long output keeps its head and tail.",
            "inputSchema": with_target(json!({
                "command": {"type": "string"},
                "cwd": {"type": "string", "description": "Working directory (default: the account's home)."},
                "timeout": {"type": "string", "description": "ISO 8601 duration; default PT10M, max PT1H."},
                "stdin": {"type": "string"}
            }), &["command"])}),
        json!({"name": "read_file", "description": "Read a text file with line numbers.",
            "inputSchema": with_target(json!({
                "path": {"type": "string", "description": "Absolute path."},
                "offset": {"type": "integer", "description": "First line (1-based)."},
                "limit": {"type": "integer", "description": "Number of lines (default 2000)."}
            }), &["path"])}),
        json!({"name": "write_file", "description": "Create or replace a file atomically; an existing file keeps its mode and owner.",
            "inputSchema": with_target(json!({
                "path": {"type": "string", "description": "Absolute path."},
                "content": {"type": "string"},
                "mode": {"type": "string", "description": "Octal mode for a new file, e.g. 0644."}
            }), &["path", "content"])}),
        json!({"name": "edit_file", "description": "Replace an exact string in a file. old_string must occur exactly once unless replace_all is true.",
            "inputSchema": with_target(json!({
                "path": {"type": "string", "description": "Absolute path."},
                "old_string": {"type": "string"},
                "new_string": {"type": "string"},
                "replace_all": {"type": "boolean"}
            }), &["path", "old_string", "new_string"])}),
    ];
    tools.push(json!({"name": "handoff", "description": "Continue in a new swai session with a fresh tool budget, from a briefing you write. Call it when a tool result says the budget is running out or exhausted (it costs no budget). The new session starts with only this briefing and a list of your last tool calls, not this conversation: include the goal, what is done and verified, the current state, what is left, the exact next step, and every path, command, finding and decision it needs. This session ends right after.",
        "inputSchema": {"type": "object", "properties": {"briefing": {"type": "string", "description": "Everything the next session needs to carry on (plain text or Markdown)."}}, "required": ["briefing"]}}));
    if aaa {
        tools.push(json!({"name": "hosts", "description": "List the hosts and accounts you may act on.", "inputSchema": {"type": "object", "properties": {}}}));
        tools.push(json!({"name": "sessions", "description": "List the user's recordings (kinds sw, shell, ai, sftp) that overlap a time window: start, id, kind, target, status.",
            "inputSchema": {"type": "object", "properties": {"window": {"type": "string", "description": "ISO 8601 interval, default P7D/now (e.g. 2026-09-01/P2D)."}}}}));
        tools.push(json!({"name": "search", "description": "Search the user's recordings. Terms: host:, ruser:, kind:, node:, cmd:, out:, keys:, file:, free text; \"quoted phrase\", /regex/, -term excludes; window:P7D/now (default P7D/now).",
            "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}}));
        tools.push(json!({"name": "transcript", "description": "Text of one recording by id: terminal output (ANSI stripped) with ISO timestamps, plus commands. Page with offset/limit (characters).",
            "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}, "offset": {"type": "integer"}, "limit": {"type": "integer", "description": "Default 20000."}}, "required": ["id"]}}));
    }
    json!(tools)
}

// ---------------------------------------------------------------- worker calls

#[derive(Default)]
struct UserCalls {
    in_flight: usize,
    recent: VecDeque<Instant>,
}

fn user_calls() -> &'static Mutex<HashMap<String, UserCalls>> {
    static U: OnceLock<Mutex<HashMap<String, UserCalls>>> = OnceLock::new();
    U.get_or_init(Default::default)
}

struct InFlight(String);
impl Drop for InFlight {
    fn drop(&mut self) {
        if let Some(u) = user_calls().lock().unwrap().get_mut(&self.0) {
            u.in_flight = u.in_flight.saturating_sub(1);
        }
    }
}

/// Requests from a session worker. The caller must be the swrap user and hold the session token.
pub fn worker_call(d: &Arc<Daemon>, c: &Caller, session: &str, token: &str, op: &str, args: &Value, con: &Console) -> Result<Resp> {
    if c.uid != d.swrap_uid {
        bail!("permission denied");
    }
    let s = lookup(d, session).ok_or_else(|| anyhow!("unknown swai session"))?;
    if blake3::hash(token.as_bytes()) != s.token_hash {
        bail!("permission denied");
    }
    let user = User::load(&d.paths, &s.user)?;
    if user.disabled || user.is_admin() {
        bail!("AI access for {} is revoked", s.user);
    }
    match op {
        "key" => {
            let ai = AiConfig::load(&d.paths)?;
            let b = ai.backend(&s.backend).ok_or_else(|| anyhow!("backend {} was removed", s.backend))?;
            let k = backend_key(d, b)?;
            Ok(Resp::ok(json!({"key": k.as_deref().map(|k| k.as_str()).unwrap_or("")})))
        }
        "usage" => {
            note_usage(d, &s.backend, args["model"].as_str().unwrap_or(""));
            Ok(Resp::ok(json!({})))
        }
        "end" => {
            sessions().lock().unwrap().remove(&s.id);
            let _ = std::fs::remove_dir_all(d.paths.ai_run().join(&s.id));
            d.audit_event(&s.user, "ai.end", if s.mode == "aaa" { "aaa" } else { &s.label }, &s.ruser, args["reason"].as_str().unwrap_or("exit"), args.clone(), &s.id);
            Ok(Resp::ok(json!({})))
        }
        "tool" => tool_call(d, &s, &user, args, con),
        "handoff" => handoff(d, &s, &user, args),
        _ => bail!("unknown op {op}"),
    }
}

fn tool_call(d: &Arc<Daemon>, s: &Session, user: &User, args: &Value, con: &Console) -> Result<Resp> {
    let name = args["name"].as_str().unwrap_or("");
    let a = &args["arguments"];
    let limits = AiConfig::load(&d.paths).map(|c| c.limits).unwrap_or_default();
    // Limits (spec 24.7): per session, per user per hour, per user in flight.
    let n = s.calls.fetch_add(1, Ordering::SeqCst) + 1;
    if n > s.max_calls {
        return Ok(tool_err(format!("tool budget of this swai session is exhausted ({} calls): call handoff with a complete briefing; a new session continues with a fresh budget", s.max_calls)));
    }
    let _guard = {
        let mut m = user_calls().lock().unwrap();
        let u = m.entry(s.user.clone()).or_default();
        while u.recent.front().map(|t| t.elapsed() > Duration::from_secs(3600)).unwrap_or(false) {
            u.recent.pop_front();
        }
        if u.recent.len() >= limits.calls_per_hour {
            return Ok(tool_err(format!("rate limit: {} tool calls per PT1H reached; wait a bit", limits.calls_per_hour)));
        }
        if u.in_flight >= limits.concurrent_calls {
            return Ok(tool_err(format!("at most {} tool calls may run at once; retry when one finishes", limits.concurrent_calls)));
        }
        u.recent.push_back(Instant::now());
        u.in_flight += 1;
        InFlight(s.user.clone())
    };
    let t0 = Instant::now();
    let r = match name {
        "exec" | "read_file" | "write_file" | "edit_file" => host_tool(d, s, user, name, a),
        "hosts" if s.mode == "aaa" => Ok(ToolOut::text(ai_hosts_text(d, user))),
        "sessions" | "search" | "transcript" if s.mode == "aaa" => records_tool(d, user, name, a),
        _ => Err(anyhow!("unknown tool {name}")),
    };
    let dur = t0.elapsed();
    let out = r.unwrap_or_else(|e| ToolOut { text: format!("error: {e:#}"), is_error: true, ..Default::default() });
    let detail = json!({"tool": name, "exit": out.exit, "error": out.is_error, "duration": fmt_duration_ms(dur), "summary": summarize(name, a)});
    d.audit_event(&s.user, "ai.tool", &out.target, &out.ruser, if out.is_error { "error" } else { "ok" }, detail, &s.id);
    // Full output travels in STDOUT/STDERR frames (a RESP frame is capped at 1 MiB).
    for (k, data) in [(kind::STDOUT, &out.out), (kind::STDERR, &out.err)] {
        for chunk in data.chunks(512 << 10) {
            con.frame(Frame::new(k, chunk.to_vec()));
        }
    }
    Ok(Resp::ok(json!({"text": out.text, "is_error": out.is_error, "target": out.target, "ruser": out.ruser, "exit": out.exit, "dropped": out.dropped, "duration": fmt_duration_ms(dur)})))
}

/// `handoff` from a session's AI: start its successor (same user, target, account, backend,
/// model, effort, permissions; fresh budget and conversation) with the briefing and the digest of
/// its last tool calls as the first prompt. It runs detached; an attached client follows it.
fn handoff(d: &Arc<Daemon>, s: &Session, user: &User, args: &Value) -> Result<Resp> {
    let ai = AiConfig::load(&d.paths)?;
    if s.chain >= ai.limits.max_handoffs {
        bail!("no further handoff: this session is number {} of at most {} in a row; stop and tell the user where things stand", s.chain, ai.limits.max_handoffs);
    }
    let briefing = args["briefing"].as_str().unwrap_or("").trim();
    if briefing.len() < 200 {
        bail!("the briefing is too short: the next session gets nothing else, so write the goal, what is done and verified, the current state, what is left, the exact next step, and the paths and commands it needs");
    }
    let briefing: String = briefing.chars().take(60_000).collect();
    let digest: String = args["digest"].as_str().unwrap_or("").chars().take(12_000).collect();
    let what = if s.mode == "aaa" { "aaa".to_string() } else { format!("{}@{}", s.ruser, s.label) };
    let chain = s.chain + 1;
    let prompt = format!(
        "swai handoff {chain}/{max}: you continue the work of swai session {prev} ({what}), which used up its budget of {calls} tool calls. \
         You start with a fresh budget and only what follows; that conversation is not available.\n\n\
         ## Briefing from the previous session\n\n{briefing}\n\n\
         ## Its last tool calls (from its recording)\n\n{digest}\n\n\
         Continue the work from here. Where the briefing leaves something essential unclear, check on the host before acting.",
        max = ai.limits.max_handoffs, prev = s.id, calls = s.max_calls,
        digest = if digest.trim().is_empty() { "(none recorded)" } else { digest.trim() },
    );
    let req = Req::AiStart {
        target: what.clone(),
        backend: s.backend.clone(),
        model: s.model.clone(),
        effort: s.effort.clone(),
        cols: args["cols"].as_u64().unwrap_or(120).clamp(20, 1000) as u16,
        rows: args["rows"].as_u64().unwrap_or(40).clamp(5, 1000) as u16,
        term: args["term"].as_str().filter(|t| !t.is_empty() && t.len() < 64).unwrap_or("xterm-256color").to_string(),
        client_addr: "handoff".into(),
        conn: String::new(),
        resume: String::new(),
        loose: s.loose,
    };
    let uid = nix::unistd::User::from_name(&s.user).ok().flatten().map(|u| u.uid.as_raw()).unwrap_or(0);
    let caller = Caller { uid, pid: 0, name: s.user.clone(), user: Some(user.clone()), admin: false, origin: Node::Core };
    // No client yet: the worker gets one end of a pair whose other end is closed, so it starts
    // detached (as after ctrl-\) until someone attaches.
    let (ours, theirs) = UnixStream::pair()?;
    drop(theirs);
    let ho = Handoff { prompt, continues: s.id.clone(), chain };
    let id = start_inner(d, &caller, &req, &ours, Node::Core, false, Some(&ho))?;
    drop(ours);
    d.audit_event(&s.user, "ai.handoff", if s.mode == "aaa" { "aaa" } else { &s.label }, &s.ruser, "ok", json!({"from": s.id, "to": id, "chain": chain, "briefing_bytes": briefing.len()}), &s.id);
    Ok(Resp::ok(json!({"id": id, "chain": chain, "max_handoffs": ai.limits.max_handoffs, "max_calls": ai.limits.max_tool_calls})))
}

fn summarize(name: &str, a: &Value) -> String {
    let s = match name {
        "exec" => a["command"].as_str().unwrap_or("").to_string(),
        "read_file" | "write_file" | "edit_file" => a["path"].as_str().unwrap_or("").to_string(),
        "search" => a["query"].as_str().unwrap_or("").to_string(),
        "transcript" => a["id"].as_str().unwrap_or("").to_string(),
        "sessions" => a["window"].as_str().unwrap_or("").to_string(),
        _ => String::new(),
    };
    s.chars().take(300).collect()
}

#[derive(Default)]
struct ToolOut {
    text: String,
    is_error: bool,
    target: String,
    ruser: String,
    exit: Option<i32>,
    out: Vec<u8>,
    err: Vec<u8>,
    dropped: u64,
}

impl ToolOut {
    fn text(t: impl Into<String>) -> Self {
        ToolOut { text: t.into(), ..Default::default() }
    }
}

fn tool_err(msg: String) -> Resp {
    Resp::ok(json!({"text": msg, "is_error": true}))
}

/// Single-quote for a POSIX shell.
pub fn q(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn str_arg<'a>(a: &'a Value, k: &str) -> Result<&'a str> {
    a[k].as_str().ok_or_else(|| anyhow!("{k} is required"))
}

fn abs_path(a: &Value) -> Result<String> {
    let p = str_arg(a, "path")?;
    if !p.starts_with('/') || p.contains('\0') || p.len() > 4096 {
        bail!("path must be absolute");
    }
    Ok(p.to_string())
}

/// Head and tail of `b` within `budget` bytes, as text.
fn clip(b: &[u8], budget: usize) -> String {
    let s = String::from_utf8_lossy(b).replace('\0', "\u{fffd}");
    if s.len() <= budget {
        return s;
    }
    let mut h = budget * 2 / 3;
    while !s.is_char_boundary(h) {
        h -= 1;
    }
    let mut t = s.len() - (budget - h);
    while !s.is_char_boundary(t) {
        t += 1;
    }
    format!("{}\n… [{} bytes omitted; the full output is recorded] …\n{}", &s[..h], t - h, &s[t..])
}

struct Target {
    host: Host,
    ruser: String,
    enc: PathBuf,
    profile: Profile,
    known: String,
}

fn resolve(d: &Daemon, s: &Session, user: &User, a: &Value) -> Result<Target> {
    let spec = if s.mode == "host" {
        match a["target"].as_str() {
            Some(t) if !t.is_empty() && t != s.label && !t.ends_with(&format!("@{}", s.label)) => bail!("this session works on {} only", s.label),
            Some(t) if t.contains('@') => t.to_string(),
            _ => format!("{}@{}", s.ruser, s.label),
        }
    } else {
        str_arg(a, "target")?.to_string()
    };
    let (ru, label) = match spec.split_once('@') {
        Some((u, l)) => (Some(u.to_string()), l.to_string()),
        None => (None, spec.clone()),
    };
    let host = Host::load(&d.paths, &label).map_err(|_| anyhow!("unknown host {label:?}"))?;
    // Re-checked on every call: revoking a grant or disabling AI on a host takes effect at once.
    let accts = rbac::ai_accounts(user, &host, now());
    let ruser = match ru {
        Some(r) if accts.contains(&r) => r,
        Some(r) => bail!("no AI grant for {r}@{label}"),
        None => accts.first().cloned().ok_or_else(|| anyhow!("no AI grant for {label}"))?,
    };
    let (enc, _) = crate::session::credential(d, &label, &ruser).ok_or_else(|| anyhow!("no credential for {ruser}@{label}"))?;
    let profile = Profile::load(&d.paths, &host.profile)?;
    let known = std::fs::read_to_string(d.paths.known_hosts(&label)).context("host keys not pinned")?;
    Ok(Target { host, ruser, enc, profile, known })
}

fn run_on(d: &Arc<Daemon>, s: &Session, t: &Target, script: &str, stdin: &[u8], timeout: Duration) -> Result<crate::hosts::RemoteOut> {
    crate::hosts::remote_ex(d, &s.user, &t.host, &t.ruser, &t.enc, &t.profile, &t.known, script, stdin, None, crate::hosts::RemoteOpts { timeout: Some(timeout), cap: TOOL_CAP })
}

fn parse_timeout(v: &Value) -> Result<u64> {
    let secs = match v {
        Value::Null => 600,
        Value::Number(n) => n.as_u64().unwrap_or(600),
        Value::String(s) if s.is_empty() => 600,
        Value::String(s) => IsoDuration::parse(s).ok().and_then(|x| x.exact()).map(|x| x.as_secs()).ok_or_else(|| anyhow!("timeout must be an ISO 8601 duration such as PT5M"))?,
        _ => bail!("timeout must be an ISO 8601 duration such as PT5M"),
    };
    Ok(secs.clamp(1, 3600))
}

const READ_CAP: usize = 4 << 20;

/// `stat` line + up to READ_CAP bytes of a regular file.
fn read_remote(d: &Arc<Daemon>, s: &Session, t: &Target, path: &str) -> Result<(String, Vec<u8>, bool)> {
    let script = format!(
        "f={}; if [ ! -e \"$f\" ]; then echo \"no such file: $f\" >&2; exit 2; fi; if [ -d \"$f\" ]; then echo \"is a directory: $f\" >&2; exit 2; fi; \
         stat -L -c '%s %Y %a %U:%G' -- \"$f\" || exit 2; head -c {} -- \"$f\"",
        q(path),
        READ_CAP + 1
    );
    let r = run_on(d, s, t, &script, b"", Duration::from_secs(120))?;
    if r.code != 0 {
        bail!("{}", if r.stderr.trim().is_empty() { format!("exit {}: {}", r.code, r.why()) } else { r.stderr.trim().to_string() });
    }
    let nl = r.raw_out.iter().position(|&b| b == b'\n').ok_or_else(|| anyhow!("stat failed"))?;
    let stat = String::from_utf8_lossy(&r.raw_out[..nl]).to_string();
    let mut body = r.raw_out[nl + 1..].to_vec();
    let cut = body.len() > READ_CAP;
    body.truncate(READ_CAP);
    Ok((stat, body, cut))
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::Digest;
    crate::daemon::hex(&sha2::Sha256::digest(b))
}

/// Atomic replace on the host; `expect` guards against concurrent changes (edit_file).
fn write_remote(d: &Arc<Daemon>, s: &Session, t: &Target, path: &str, content: &[u8], mode: Option<&str>, expect: Option<&str>) -> Result<String> {
    let guard = match expect {
        Some(h) => format!(
            "h=$( (sha256sum -- \"$f\" 2>/dev/null || echo skip) | cut -c1-64); [ \"$h\" = skip ] || [ \"$h\" = {h} ] || {{ rm -f -- \"$t\"; echo 'the file changed since it was read; read it again' >&2; exit 3; }}; "
        ),
        None => String::new(),
    };
    let script = format!(
        "f={}; if [ -L \"$f\" ]; then f=$(readlink -f -- \"$f\") || exit 2; fi; d=$(dirname -- \"$f\"); [ -d \"$d\" ] || mkdir -p -- \"$d\" || exit 2; t=$(mktemp \"$d/.swai.XXXXXX\") || exit 2; \
         cat > \"$t\" || {{ rm -f -- \"$t\"; exit 2; }}; \
         if [ -e \"$f\" ]; then chmod \"$(stat -c %a -- \"$f\")\" \"$t\"; chown \"$(stat -c %u:%g -- \"$f\")\" \"$t\" 2>/dev/null; else chmod {} \"$t\"; fi; \
         {guard}mv -f -- \"$t\" \"$f\" || {{ rm -f -- \"$t\"; exit 2; }}; wc -c < \"$f\"",
        q(path),
        mode.unwrap_or("0644")
    );
    let r = run_on(d, s, t, &script, content, Duration::from_secs(300))?;
    if r.code != 0 {
        bail!("{}", if r.stderr.trim().is_empty() { format!("exit {}: {}", r.code, r.why()) } else { r.stderr.trim().to_string() });
    }
    Ok(r.stdout.trim().to_string())
}

fn numbered(text: &str, from: usize, count: usize) -> (String, usize) {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let total = lines.len();
    let mut out = String::new();
    for (i, l) in lines.iter().enumerate().skip(from.saturating_sub(1)).take(count) {
        let l = l.trim_end_matches('\n');
        let l: String = if l.chars().count() > 2000 { l.chars().take(2000).collect::<String>() + " …" } else { l.to_string() };
        out += &format!("{:>6}\t{l}\n", i + 1);
    }
    (out, total)
}

fn host_tool(d: &Arc<Daemon>, s: &Session, user: &User, name: &str, a: &Value) -> Result<ToolOut> {
    if d.is_sealed() {
        bail!("the swrap vault is sealed; host tools are unavailable until an admin logs in");
    }
    let t = resolve(d, s, user, a)?;
    let mut out = ToolOut { target: t.host.label.clone(), ruser: t.ruser.clone(), ..Default::default() };
    match name {
        "exec" => {
            let cmd = str_arg(a, "command")?;
            if cmd.len() > 256 << 10 {
                bail!("command too long");
            }
            let secs = parse_timeout(&a["timeout"])?;
            let cd = match a["cwd"].as_str().filter(|c| !c.is_empty()) {
                Some(c) => format!("cd -- {} || exit 2; ", q(c)),
                None => String::new(),
            };
            let script = format!(
                "S=$(command -v bash 2>/dev/null || echo sh); {cd}if command -v timeout >/dev/null 2>&1; then exec timeout -k 10 {secs} \"$S\" -lc {c}; else exec \"$S\" -lc {c}; fi",
                c = q(cmd)
            );
            let stdin = a["stdin"].as_str().unwrap_or("").as_bytes().to_vec();
            let t0 = Instant::now();
            let r = run_on(d, s, &t, &script, &stdin, Duration::from_secs(secs + 30))?;
            let timed_out = r.timed_out || r.code == 124;
            out.exit = Some(r.code);
            let mut head = format!("exit {} · {}", r.code, fmt_duration_ms(t0.elapsed()));
            if timed_out {
                head += &format!(" · timed out after {}", fmt_duration_ms(Duration::from_secs(secs)));
            }
            if r.dropped > 0 {
                head += &format!(" · {} bytes of output beyond 8 MiB were dropped", r.dropped);
            }
            if r.code == 255 && r.raw_out.is_empty() && !r.ssh_log.is_empty() && r.raw_err.is_empty() {
                head += &format!(" · ssh: {}", r.why());
            }
            let mut text = head + "\n";
            if !r.raw_out.is_empty() {
                text += &format!("stdout:\n{}\n", clip(&r.raw_out, 24 << 10).trim_end());
            }
            if !r.raw_err.is_empty() {
                text += &format!("stderr:\n{}\n", clip(&r.raw_err, 8 << 10).trim_end());
            }
            if r.raw_out.is_empty() && r.raw_err.is_empty() {
                text += "(no output)\n";
            }
            out.is_error = r.code != 0;
            out.text = text;
            out.out = r.raw_out;
            out.err = r.raw_err;
            out.dropped = r.dropped;
        }
        "read_file" => {
            let path = abs_path(a)?;
            let (stat, body, cut) = read_remote(d, s, &t, &path)?;
            let f: Vec<&str> = stat.split_whitespace().collect();
            let mtime = f.get(1).and_then(|x| x.parse::<i64>().ok()).and_then(|x| jiff::Timestamp::from_second(x).ok()).map(fmt_utc_secs).unwrap_or_default();
            let desc = format!("{path} · {} bytes · modified {mtime} · mode {} {}", f.first().unwrap_or(&"?"), f.get(2).unwrap_or(&"?"), f.get(3).unwrap_or(&"?"));
            if body.iter().take(8192).any(|&b| b == 0) || std::str::from_utf8(&body).is_err() && String::from_utf8_lossy(&body).matches('\u{fffd}').count() > 16 {
                out.text = format!("{desc}\nbinary file; inspect it with exec (file, xxd, base64, strings)\n");
            } else {
                let text = String::from_utf8_lossy(&body);
                let from = a["offset"].as_u64().unwrap_or(1).max(1) as usize;
                let count = a["limit"].as_u64().unwrap_or(2000).clamp(1, 20_000) as usize;
                let (lines, total) = numbered(&text, from, count);
                let last = (from + count - 1).min(total);
                out.text = format!("{desc} · lines {from}-{last} of {total}{}\n{lines}", if cut { " (file cut at 4 MiB)" } else { "" });
                if lines.len() > 256 << 10 {
                    out.text = clip(out.text.as_bytes(), 256 << 10);
                }
            }
            out.out = body;
        }
        "write_file" => {
            let path = abs_path(a)?;
            let content = str_arg(a, "content")?;
            if content.len() > 8 << 20 {
                bail!("content larger than 8 MiB");
            }
            let mode = match a["mode"].as_str().filter(|m| !m.is_empty()) {
                Some(m) if m.len() <= 4 && m.bytes().all(|b| (b'0'..=b'7').contains(&b)) => Some(m),
                Some(m) => bail!("mode must be octal like 0644 (got {m:?})"),
                None => None,
            };
            let n = write_remote(d, s, &t, &path, content.as_bytes(), mode, None)?;
            out.text = format!("wrote {n} bytes to {path}\n");
            out.out = content.as_bytes().to_vec();
        }
        "edit_file" => {
            let path = abs_path(a)?;
            let old = str_arg(a, "old_string")?;
            let new = str_arg(a, "new_string")?;
            let all = a["replace_all"].as_bool().unwrap_or(false);
            if old.is_empty() {
                bail!("old_string is empty; use write_file to create a file");
            }
            if old == new {
                bail!("old_string and new_string are identical");
            }
            let (_stat, body, cut) = read_remote(d, s, &t, &path)?;
            if cut {
                bail!("file larger than 4 MiB; edit it with exec (sed) instead");
            }
            let text = String::from_utf8(body.clone()).map_err(|_| anyhow!("not a UTF-8 text file"))?;
            let count = text.matches(old).count();
            if count == 0 {
                bail!("old_string not found in {path} (it must match exactly, including whitespace)");
            }
            if count > 1 && !all {
                bail!("old_string occurs {count} times in {path}; include more context or set replace_all");
            }
            let first = text.find(old).unwrap_or(0);
            let updated = if all { text.replace(old, new) } else { text.replacen(old, new, 1) };
            write_remote(d, s, &t, &path, updated.as_bytes(), None, Some(&sha256_hex(&body)))?;
            let line = text[..first].matches('\n').count() + 1;
            let span = new.matches('\n').count() + 1;
            let (snip, _) = numbered(&updated, line.saturating_sub(3).max(1), span + 6);
            out.text = format!("edited {path}: {} replacement{}\n{snip}", if all { count } else { 1 }, if all && count != 1 { "s" } else { "" });
            out.out = updated.into_bytes();
        }
        _ => unreachable!(),
    }
    Ok(out)
}

/// swrap's own records, with the user's rights (never admin): sessions, search, transcript.
fn records_tool(d: &Arc<Daemon>, user: &User, name: &str, a: &Value) -> Result<ToolOut> {
    let c = Caller { uid: u32::MAX, pid: 0, name: user.name.clone(), user: Some(user.clone()), admin: false, origin: Node::Core };
    let text = match name {
        "sessions" => {
            let w = a["window"].as_str().filter(|w| !w.is_empty()).unwrap_or("P7D/now");
            crate::records::log(d, &c, w, None, false)?.text
        }
        "search" => {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let con = Console { tx };
            let r = crate::records::search(d, &c, str_arg(a, "query")?, &con)?;
            drop(con);
            let mut lines = vec![];
            while let Ok(f) = rx.try_recv() {
                if f.kind == kind::STDOUT && lines.len() < 200 {
                    lines.push(String::from_utf8_lossy(&f.payload).to_string());
                }
            }
            format!("{}\n{}\n", lines.join("\n"), r.text)
        }
        "transcript" => {
            let id = str_arg(a, "id")?;
            let r = crate::records::find(d, &c, id)?;
            let path = PathBuf::from(r.data["path"].as_str().unwrap_or(""));
            if path.is_dir() {
                bail!("{id} is a run directory");
            }
            let sc = swrec::reader::scan(&path, swrec::reader::ScanOpts { verifier: None, keep_records: true, live: r.data["live"].as_bool().unwrap_or(false) })?;
            let tz = d.tz();
            let o = swrec::text::CatOpts { tz: &tz, utc: false, keys: false, cmds: true, raw: false };
            let mut buf = vec![];
            swrec::text::cat(sc.header.as_ref(), &sc.records, &o, &mut buf)?;
            let all = String::from_utf8_lossy(&buf).to_string();
            let off = a["offset"].as_u64().unwrap_or(0) as usize;
            let lim = a["limit"].as_u64().unwrap_or(20_000).clamp(1000, 200_000) as usize;
            let chars: Vec<char> = all.chars().collect();
            let end = (off + lim).min(chars.len());
            let part: String = chars[off.min(chars.len())..end].iter().collect();
            format!("[characters {off}-{end} of {}]\n{part}", chars.len())
        }
        _ => unreachable!(),
    };
    Ok(ToolOut::text(clip(text.as_bytes(), 64 << 10)))
}

// ---------------------------------------------------------------- admin: `swai …`

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "swai", about = "swai: AI harness (opencode) on swrap — run `swai` without arguments to start")]
struct Swai {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Hosts and accounts the AI may use for you.
    Targets,
    /// Roll an AI test VM back to its Proxmox snapshot (needs an AI grant; the host must allow it).
    Reset {
        label: String,
        /// Also while swai sessions work on it.
        #[arg(long)]
        force: bool,
    },
    /// Allow swai reset for a host: Proxmox API server, node, VM id, snapshot (admin).
    ResetSetup {
        label: String,
        #[arg(long)]
        api: Option<String>,
        #[arg(long)]
        node: Option<String>,
        #[arg(long)]
        vmid: Option<u32>,
        #[arg(long)]
        snapshot: Option<String>,
        /// Turn swai reset off for the host.
        #[arg(long)]
        off: bool,
    },
    /// The host's Proxmox API token into the vault, from stdin: user@realm!tokenid=secret (admin).
    ResetToken { label: String },
    /// The Proxmox CA certificate (/etc/pve/pve-root-ca.pem) from stdin (admin).
    ResetCa,
    /// Inference backends (admin: add, del, key, test).
    Backend {
        #[command(subcommand)]
        cmd: BackendCmd,
    },
    /// Grant AI access: swai grant <aaa_user> <hosts> <remote_users> [--until ISO] (admin).
    Grant {
        user: String,
        hosts: String,
        remote_users: String,
        #[arg(long)]
        until: Option<String>,
    },
    /// Remove an AI grant by id (admin).
    RevokeGrant { user: String, id: String },
    /// Let the AI act on a host at all (`on`) or never (`off`) (admin; spec 24.5 host opt-in).
    Host { label: String, state: String },
    /// Grants, backends, sessions and the pinned opencode version.
    Status,
    /// End one of your running sessions (admins: anyone's).
    Kill { id: String },
    /// Tool approval for exec/write_file/edit_file in new sessions: ask (default) or allow (admin).
    Approval { mode: String },
    /// Show the limits, or set one: swai limits [<key> <value>] (admin).
    Limits { key: Option<String>, value: Option<String> },
}

#[derive(Subcommand, Debug)]
enum BackendCmd {
    List,
    /// Add a backend: swai backend add <name> <base_url> [--api openai|anthropic|claude-code] [--key] (admin).
    Add {
        name: String,
        base_url: String,
        #[arg(long, default_value = "openai")]
        api: String,
        /// Needs an API key (then: swai backend key <name>).
        #[arg(long)]
        key: bool,
        /// Model allow-list (comma separated).
        #[arg(long)]
        models: Option<String>,
        /// How long the server may stay silent (plain HTTP) or answer (HTTPS), ISO 8601.
        #[arg(long, default_value = "PT1H")]
        timeout: String,
        /// Requests at once over all sessions (default: no limit); more wait their turn.
        #[arg(long)]
        max_concurrent: Option<u32>,
    },
    /// Change a backend: swai backend set <name> [--timeout PT1H] [--models a,b] (admin).
    Set {
        name: String,
        #[arg(long)]
        timeout: Option<String>,
        /// Model allow-list (comma separated; "" clears it).
        #[arg(long)]
        models: Option<String>,
        /// Requests at once over all sessions (0 = no limit); applies at once.
        #[arg(long)]
        max_concurrent: Option<u32>,
    },
    Del { name: String },
    /// Store the backend's API key in the vault (read from stdin) (admin).
    Key { name: String },
    /// Reachability, model list, latency.
    Test { name: String },
}

pub fn admin(d: &Arc<Daemon>, c: &Caller, argv: &[String], stdin: Option<zeroize::Zeroizing<String>>, con: &Console) -> Result<Resp> {
    let a = Swai::try_parse_from(argv)?;
    match a.cmd {
        Cmd::Reset { label, force } => crate::ai_reset::reset(d, c, &label, force, con),
        Cmd::ResetSetup { label, api, node, vmid, snapshot, off } => {
            let p = if off {
                None
            } else {
                Some(swrap_core::config::ProxmoxVm {
                    api: api.ok_or_else(|| anyhow!("--api https://<server>:8006 (or --off)"))?.trim_end_matches('/').to_string(),
                    node: node.ok_or_else(|| anyhow!("--node <proxmox node>"))?,
                    vmid: vmid.ok_or_else(|| anyhow!("--vmid <id>"))?,
                    snapshot: snapshot.ok_or_else(|| anyhow!("--snapshot <name>"))?,
                })
            };
            crate::ai_reset::setup(d, c, &label, p)
        }
        Cmd::ResetToken { label } => crate::ai_reset::set_token(d, c, &label, stdin),
        Cmd::ResetCa => crate::ai_reset::set_ca(d, c, stdin),
        Cmd::Targets => {
            let user = ai_user(c)?;
            let t = ai_hosts_text(d, user);
            Ok(Resp::text(if t.is_empty() { "no hosts are enabled for AI for you (an admin runs: swai host <label> on; swai grant <you> <hosts> <accounts>)\n".into() } else { t }))
        }
        Cmd::Backend { cmd: BackendCmd::List } => {
            let ai = AiConfig::load(&d.paths)?;
            let mut s = String::from("NAME\tAPI\tURL\tSTATE\n");
            for b in &ai.backends {
                let (ready, why) = backend_state(d, b);
                s += &format!("{}\t{}\t{}\t{}\n", b.name, b.api.as_str(), b.base_url, if ready { "ready".to_string() } else { why });
            }
            Ok(Resp::text(s))
        }
        Cmd::Backend { cmd: BackendCmd::Test { name } } => {
            let ai = AiConfig::load(&d.paths)?;
            let b = ai.backend(&name).ok_or_else(|| anyhow!("unknown backend {name}"))?;
            if !c.admin {
                ai_user(c)?;
            }
            let key = backend_key(d, b)?;
            let t0 = Instant::now();
            let list = list_models(b, key.as_deref().map(|k| k.as_str()))?;
            Ok(Resp::text(format!("{name}: /v1/models answered in {} with {} models\n{}\n", fmt_duration_ms(t0.elapsed()), list.len(), list.iter().filter_map(|m| m["id"].as_str()).collect::<Vec<_>>().join("\n"))))
        }
        Cmd::Kill { id } => kill(d, c, &id),
        other => {
            c.require_admin()?;
            admin_write(d, c, other, stdin, con)
        }
    }
}

fn admin_write(d: &Arc<Daemon>, c: &Caller, cmd: Cmd, stdin: Option<zeroize::Zeroizing<String>>, _con: &Console) -> Result<Resp> {
    let _g = d.config_lock.lock().unwrap();
    match cmd {
        Cmd::Backend { cmd: BackendCmd::Add { name, base_url, api, key, models, timeout, max_concurrent } } => {
            IsoDuration::parse(&timeout).map_err(|e| anyhow!("--timeout: {e}"))?;
            if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b)) || name.is_empty() {
                bail!("bad backend name");
            }
            let api = match api.as_str() {
                "openai" => AiApi::Openai,
                "anthropic" => AiApi::Anthropic,
                "claude-code" => AiApi::ClaudeCode,
                o => bail!("api must be openai, anthropic or claude-code (got {o})"),
            };
            if !(base_url.starts_with("http://") || base_url.starts_with("https://")) {
                bail!("base_url must start with http:// or https://");
            }
            let mut ai = AiConfig::load(&d.paths)?;
            if ai.backend(&name).is_some() {
                bail!("backend {name} exists");
            }
            let base = base_url.trim_end_matches('/').trim_end_matches("/v1").to_string();
            ai.backends.push(AiBackend { name: name.clone(), api, base_url: base, models: models.map(|m| m.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()).unwrap_or_default(), needs_key: key, timeout, max_concurrent: max_concurrent.unwrap_or(0), added_by: c.name.clone(), created: fmt_utc_secs(now()) });
            d.write_config("ai.toml", &ai.to_toml())?;
            d.commit(&format!("swai backend add {name} by {}", c.name))?;
            d.audit_event(&c.name, "ai.backend.add", &name, "", "ok", json!({"base_url": base_url}), "");
            Ok(Resp::text(format!("backend {name} added{}\n", if key { format!("; now store its key: swai backend key {name}") } else { String::new() })))
        }
        Cmd::Backend { cmd: BackendCmd::Set { name, timeout, models, max_concurrent } } => {
            let mut ai = AiConfig::load(&d.paths)?;
            let b = ai.backends.iter_mut().find(|b| b.name == name).ok_or_else(|| anyhow!("unknown backend {name}"))?;
            if let Some(t) = timeout {
                IsoDuration::parse(&t).map_err(|e| anyhow!("--timeout: {e}"))?;
                b.timeout = t;
            }
            if let Some(m) = models {
                b.models = m.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
            }
            if let Some(n) = max_concurrent {
                b.max_concurrent = n;
            }
            let summary = format!(
                "{name}: timeout {} (new sessions), models {} (new sessions), at once {} (now)",
                b.timeout,
                if b.models.is_empty() { "any".to_string() } else { b.models.join(",") },
                if b.max_concurrent == 0 { "unlimited".to_string() } else { b.max_concurrent.to_string() }
            );
            d.write_config("ai.toml", &ai.to_toml())?;
            d.commit(&format!("swai backend set {name} by {}", c.name))?;
            d.audit_event(&c.name, "ai.backend.set", &name, "", "ok", json!({}), "");
            Ok(Resp::text(format!("{summary}\n")))
        }
        Cmd::Backend { cmd: BackendCmd::Del { name } } => {
            let mut ai = AiConfig::load(&d.paths)?;
            let n = ai.backends.len();
            ai.backends.retain(|b| b.name != name);
            if ai.backends.len() == n {
                bail!("unknown backend {name}");
            }
            d.write_config("ai.toml", &ai.to_toml())?;
            d.commit(&format!("swai backend del {name} by {}", c.name))?;
            let _ = std::fs::remove_file(key_path(d, &name));
            d.audit_event(&c.name, "ai.backend.del", &name, "", "ok", json!({}), "");
            Ok(Resp::text(format!("backend {name} removed\n")))
        }
        Cmd::Backend { cmd: BackendCmd::Key { name } } => {
            let ai = AiConfig::load(&d.paths)?;
            let b = ai.backend(&name).ok_or_else(|| anyhow!("unknown backend {name}"))?;
            let key = stdin.ok_or_else(|| anyhow!("the key is read from stdin"))?;
            let key = key.trim();
            if key.len() < 8 || key.contains(char::is_whitespace) {
                bail!("that does not look like an API key");
            }
            let p = key_path(d, &b.name);
            d.with_dek(|dek| swrap_vault::Vault::new(&d.paths, d.owner()).put(dek, &p, &format!("ai-{}", b.name), key.as_bytes()))?;
            // Check it right away (models list needs a valid key).
            let check = list_models(b, Some(key)).map(|l| format!("key works ({} models visible)", l.len())).unwrap_or_else(|e| format!("stored, but the check failed: {e:#}"));
            d.audit_event(&c.name, "ai.backend.key", &name, "", "ok", json!({}), "");
            Ok(Resp::text(format!("API key for {name} stored in the vault; {check}\n")))
        }
        Cmd::Grant { user, hosts, remote_users, until } => {
            let mut u = User::load(&d.paths, &user)?;
            if u.is_admin() {
                bail!("{user} is an admin; admins cannot use swai");
            }
            rbac::Targets::parse(&hosts)?;
            if let Some(x) = &until {
                swrap_core::time::parse_datetime(x)?;
            }
            let id = format!("ai{}", &swrap_core::new_id()[20..].to_lowercase());
            u.ai_grants.push(swrap_core::config::AiGrant { id: id.clone(), hosts: hosts.clone(), remote_users: remote_users.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(), until, created: fmt_utc_secs(now()) });
            d.write_config(&format!("users/{user}.toml"), &u.to_toml())?;
            d.commit(&format!("swai grant {user} {hosts} {remote_users} by {}", c.name))?;
            d.audit_event(&c.name, "ai.grant", &hosts, &remote_users, "ok", json!({"user": user, "id": id}), "");
            let off: Vec<String> = Host::all(&d.paths)?.into_iter().filter(|h| !h.ai_allowed && rbac::Targets::parse(&hosts).map(|t| t.matches(h)).unwrap_or(false)).map(|h| h.label).collect();
            let hint = if off.is_empty() { String::new() } else { format!("note: not enabled for AI yet: {} (swai host <label> on)\n", off.join(", ")) };
            Ok(Resp::text(format!("AI grant {id} for {user}: {hosts} as {remote_users}\n{hint}")))
        }
        Cmd::RevokeGrant { user, id } => {
            let mut u = User::load(&d.paths, &user)?;
            let n = u.ai_grants.len();
            u.ai_grants.retain(|g| g.id != id);
            if n == u.ai_grants.len() {
                bail!("no AI grant {id} for {user}");
            }
            d.write_config(&format!("users/{user}.toml"), &u.to_toml())?;
            d.commit(&format!("swai revoke-grant {user} {id} by {}", c.name))?;
            d.audit_event(&c.name, "ai.revoke", &user, "", "ok", json!({"id": id}), "");
            Ok(Resp::text(format!("AI grant {id} of {user} revoked\n")))
        }
        Cmd::Host { label, state } => {
            let on = match state.as_str() {
                "on" | "yes" | "true" => true,
                "off" | "no" | "false" => false,
                _ => bail!("state is on or off"),
            };
            let mut h = Host::load(&d.paths, &label)?;
            h.ai_allowed = on;
            d.write_config(&format!("hosts/{label}.toml"), &h.to_toml())?;
            d.commit(&format!("swai host {label} {state} by {}", c.name))?;
            d.audit_event(&c.name, "ai.host", &label, "", "ok", json!({"ai_allowed": on}), "");
            Ok(Resp::text(format!("{label}: AI {}\n", if on { "enabled (users still need an AI grant)" } else { "disabled" })))
        }
        Cmd::Limits { key: None, .. } => {
            let l = AiConfig::load(&d.paths)?.limits;
            Ok(Resp::text(format!(
                "max_tool_calls    {:>8}  tool calls per session\n\
                 handoff_warn      {:>8}  tool results remind the AI to hand off when this few are left\n\
                 max_handoffs      {:>8}  handoffs in a row (each successor gets a fresh max_tool_calls)\n\
                 calls_per_hour    {:>8}  tool calls per user per PT1H\n\
                 concurrent_calls  {:>8}  tool calls per user at once\n\
                 sessions_per_user {:>8}  running sessions per user\n\
                 min_available_mb  {:>8}  a new session needs this much available memory on core (MiB)\n\
                 host_context      {:>8}  context cap (tokens) for one-host sessions\n\
                 detached_timeout  {:>8}  a session without a client ends after this\n",
                l.max_tool_calls, l.handoff_warn, l.max_handoffs, l.calls_per_hour, l.concurrent_calls, l.sessions_per_user, l.min_available_mb, l.host_context, l.detached_timeout
            )))
        }
        Cmd::Limits { key: Some(key), value } => {
            let value = value.ok_or_else(|| anyhow!("usage: swai limits <key> <value>"))?;
            let mut ai = AiConfig::load(&d.paths)?;
            let l = &mut ai.limits;
            let num = || value.parse::<u64>().map_err(|_| anyhow!("{key} takes a whole number"));
            match key.as_str() {
                "max_tool_calls" => l.max_tool_calls = (num()? as usize).max(1),
                "handoff_warn" => l.handoff_warn = num()? as usize,
                "max_handoffs" => l.max_handoffs = num()? as usize,
                "calls_per_hour" => l.calls_per_hour = (num()? as usize).max(1),
                "concurrent_calls" => l.concurrent_calls = (num()? as usize).max(1),
                "sessions_per_user" => l.sessions_per_user = (num()? as usize).max(1),
                "host_context" => l.host_context = num()?,
                "min_available_mb" => l.min_available_mb = num()?,
                "detached_timeout" => {
                    IsoDuration::parse(&value).ok().and_then(|x| x.exact()).ok_or_else(|| anyhow!("detached_timeout is an ISO 8601 duration, e.g. P7D"))?;
                    l.detached_timeout = value.clone();
                }
                k => bail!("unknown limit {k} (see swai limits)"),
            }
            d.write_config("ai.toml", &ai.to_toml())?;
            d.commit(&format!("swai limits {key} {value} by {}", c.name))?;
            d.audit_event(&c.name, "ai.limits", &key, "", "ok", json!({"value": value}), "");
            // Read on every tool call or start: running sessions get it now. The others are part of
            // a session's spec from its start.
            let now = matches!(key.as_str(), "concurrent_calls" | "calls_per_hour" | "max_handoffs" | "sessions_per_user" | "min_available_mb");
            Ok(Resp::text(format!("{key} = {value} ({})\n", if now { "in effect now, also for running sessions" } else { "for new sessions" })))
        }
        Cmd::Approval { mode } => {
            if mode != "ask" && mode != "allow" {
                bail!("approval is ask or allow");
            }
            let mut ai = AiConfig::load(&d.paths)?;
            ai.limits.approval = mode.clone();
            d.write_config("ai.toml", &ai.to_toml())?;
            d.commit(&format!("swai approval {mode} by {}", c.name))?;
            d.audit_event(&c.name, "ai.approval", &mode, "", "ok", json!({}), "");
            Ok(Resp::text(if mode == "allow" {
                "new swai sessions run exec, write_file and edit_file without asking (AI grants still apply; everything is recorded)\n".to_string()
            } else {
                "new swai sessions ask before exec, write_file and edit_file\n".to_string()
            }))
        }
        Cmd::Status => {
            let ai = AiConfig::load(&d.paths)?;
            let mut s = format!("opencode {} · Claude Code {}\n\nbackends:\n", opencode_version(), claude_version());
            for b in &ai.backends {
                let (ready, why) = backend_state(d, b);
                s += &format!("  {} ({}, {}) {}\n", b.name, b.api.as_str(), b.base_url, if ready { "ready" } else { &why });
            }
            s += &format!("\ntool approval: {}\nhosts enabled for AI: ", ai.limits.approval);
            let on: Vec<String> = Host::all(&d.paths)?.into_iter().filter(|h| h.ai_allowed).map(|h| h.label).collect();
            s += &(if on.is_empty() { "(none)".to_string() } else { on.join(", ") } + "\n\nAI grants:\n");
            for u in User::all(&d.paths)? {
                for g in &u.ai_grants {
                    s += &format!("  {} {}: {} as {}{}\n", u.name, g.id, g.hosts, g.remote_users.join(","), g.until.as_ref().map(|x| format!(" until {x}")).unwrap_or_default());
                }
            }
            let live: Vec<Value> = crate::session::live_sessions(d).into_iter().filter(|j| j["kind"] == "ai").collect();
            s += &format!("\nlive swai sessions: {}\n", live.len());
            for j in live {
                s += &format!("  {} {}\n", j["id"].as_str().unwrap_or(""), j["user"].as_str().unwrap_or(""));
            }
            Ok(Resp::text(s))
        }
        Cmd::Targets | Cmd::Reset { .. } | Cmd::ResetSetup { .. } | Cmd::ResetToken { .. } | Cmd::ResetCa | Cmd::Kill { .. } | Cmd::Backend { cmd: BackendCmd::List } | Cmd::Backend { cmd: BackendCmd::Test { .. } } => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handoff_is_offered_in_both_modes_and_explained() {
        for mode in ["host", "aaa"] {
            let defs = tool_defs(mode);
            let h = defs.as_array().unwrap().iter().find(|t| t["name"] == "handoff").expect("handoff tool");
            assert_eq!(h["inputSchema"]["required"], json!(["briefing"]));
            assert!(h["description"].as_str().unwrap().contains("costs no budget"));
        }
        assert!(GUIDANCE.contains("call handoff with a complete briefing"));
    }
}
