//! Client ↔ daemon API (JSON inside REQ/RESP frames). Identity comes from SO_PEERCRED.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum Req {
    Whoami,
    /// Start a recorded session. The connection then carries DATA/RESIZE/SIGNAL/EXIT frames.
    Sw {
        target: String,
        #[serde(default)]
        cmd: Vec<String>,
        cols: u16,
        rows: u16,
        term: String,
        #[serde(default)]
        client_addr: String,
        #[serde(default)]
        conn: String,
        #[serde(default)]
        tty: bool,
    },
    /// Record an AAA login shell. The connection then carries recorder frames.
    Shell {
        cols: u16,
        rows: u16,
        term: String,
        #[serde(default)]
        client_addr: String,
        #[serde(default)]
        conn: String,
        nonce: String,
        #[serde(default)]
        sshd_pid: i32,
    },
    Ls,
    Log {
        window: String,
        #[serde(default)]
        kind: Option<String>,
        #[serde(default)]
        all: bool,
    },
    /// Resolve a record id (or prefix) to a path the caller may read.
    Find { id: String },
    /// Stream a record's bytes (for nodes without local access, i.e. edge).
    Fetch { id: String },
    Search { query: String },
    /// SFTP session (spec 11): the connection becomes the SFTP stream once the worker answers.
    Sftp { client_addr: String, #[serde(default)] conn: String },
    /// An SFTP worker asks for a host connection for one namespace entry (worker token).
    SftpBackend { session: String, token: String, entry: String },
    /// swrapd's own `tunnel` helper (ssh ProxyCommand, swrap uid): the connection becomes the TCP
    /// stream edge opened to a host only it can reach (one use, set up by `SftpBackend`).
    EdgeTunnel { id: String },
    /// Inventory (spec 10.7): `swinv [targets]` (empty = every host the caller may use).
    Inventory { #[serde(default)] targets: String },
    /// Fleet script (`swr`) or command (`swx`) (spec 10.9). `script` is base64. Secret values
    /// travel in memory only and are redacted from output and recordings.
    Run {
        targets: String,
        #[serde(default)]
        ruser: Option<String>,
        /// `swr`: the script's file name; `swx`: empty (the script is the command).
        #[serde(default)]
        script_name: String,
        script_b64: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        secrets: Vec<SecretEnv>,
    },
    /// Fleet dnf upgrade (spec 10.10): `swupdate <targets> [--app <pkg>]`.
    Update { targets: String, #[serde(default)] app: Option<String> },
    /// Audit event from swrap-shell / workers.
    Audit { action: String, #[serde(default)] target: String, #[serde(default)] result: String, #[serde(default)] detail: serde_json::Value },
    /// Is session `id` live and owned by the caller? (nested `sw` pause check)
    SessionCheck { id: String },
    Passwd { password: String },
    Status,
    /// Admin command: argv as typed (`swadm user add x`), executed by the daemon.
    Admin { cmd: String, args: Vec<String>, #[serde(default)] stdin: Option<String> },
    /// swai wizard data: AI-enabled hosts, inference backends, models used in the last P30D.
    AiOptions,
    /// Models a backend serves right now (its `/v1/models`).
    AiModels { backend: String },
    /// Add an OpenAI-compatible inference server at `addr` (`IP[:port]`; common ports probed).
    AiAddBackend { addr: String },
    /// Start a swai session (`target` = `aaa` or a host label). The connection then carries
    /// DATA/RESIZE/SIGNAL/EXIT frames, like `Sw`.
    AiStart {
        target: String,
        backend: String,
        model: String,
        #[serde(default)]
        effort: String,
        cols: u16,
        rows: u16,
        term: String,
        #[serde(default)]
        client_addr: String,
        #[serde(default)]
        conn: String,
        /// "" = new conversation, "last" = continue the latest, or an opencode session id.
        #[serde(default)]
        resume: String,
        /// One host only: no permission prompts (Claude Code --dangerously-skip-permissions,
        /// opencode: every tool allowed). Still only that host, under its AI grant, recorded.
        #[serde(default)]
        loose: bool,
    },
    /// Reattach to a running swai session (`id`: full id, unique prefix, or "" for the latest
    /// detached one). The connection then carries DATA/RESIZE/SIGNAL/EXIT frames.
    AiAttach {
        #[serde(default)]
        id: String,
        cols: u16,
        rows: u16,
        term: String,
        #[serde(default)]
        client_addr: String,
    },
    /// The caller's running swai sessions.
    AiList,
    /// From a swai session worker (uid swrap), authenticated by the per-session token:
    /// `key` (backend API key), `tool` (run an MCP tool call), `usage` (model used), `end`.
    AiWorker { session: String, token: String, call: String, #[serde(default)] args: serde_json::Value },
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Resp {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub data: serde_json::Value,
    /// Human-readable output (already formatted with ISO times).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub text: String,
    #[serde(default)]
    pub exit: i32,
}

impl Resp {
    pub fn ok(data: serde_json::Value) -> Self {
        Resp { ok: true, data, ..Default::default() }
    }
    pub fn text(t: impl Into<String>) -> Self {
        Resp { ok: true, text: t.into(), ..Default::default() }
    }
    pub fn err(e: impl std::fmt::Display) -> Self {
        Resp { ok: false, error: Some(e.to_string()), exit: 1, ..Default::default() }
    }
}

/// Unseal socket protocol (root-only): swrap-pam-unlock → swrapd.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum UnsealReq {
    /// DEK after successful verification (base64). `user` is the admin.
    Unseal { user: String, dek: String, via: String, rhost: String },
    /// Report an attempt (success or failure) for the audit log.
    Attempt { user: String, result: String, via: String, rhost: String, detail: String },
}

/// Per-session spec handed from swrapd to a worker (via stdin).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WorkerSpec {
    pub mode: String, // "sw" | "shell"
    pub id: String,
    pub aaa_user: String,
    pub uid: u32,
    pub rec_path: String,
    pub session_dir: String,
    pub header: serde_json::Map<String, serde_json::Value>,
    pub argv: Vec<String>,
    pub cols: u16,
    pub rows: u16,
    pub term: String,
    pub nonce: String,
    pub record_input: bool,
    pub signer: String,
    pub recsign_key: String,
    pub rec_cfg: crate::config::RecCfg,
    pub live_marker: String,
    pub banner: String,
    #[serde(default)]
    pub sshd_pid: i32,
    /// swai sessions only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai: Option<AiSpec>,
    /// SFTP sessions only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sftp: Option<SftpSpec>,
}

/// Everything an SFTP session worker needs (spec 11).
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SftpSpec {
    /// Per-session secret for `Req::SftpBackend`.
    pub token: String,
    /// The virtual root, in listing order.
    pub entries: Vec<SftpEntry>,
    /// Idle host connections close after this long.
    pub idle_secs: u64,
}

/// One directory of the virtual root: `label` (default account) or `ruser@label`.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SftpEntry {
    pub name: String,
    pub label: String,
    pub ruser: String,
}

/// Everything a swai session worker needs (spec 24, terminal edition).
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AiSpec {
    /// Per-session secret for `Req::AiWorker` calls.
    pub token: String,
    /// `host` (one host, lean tool set) or `aaa` (all AI-granted hosts + swrap records).
    pub mode: String,
    pub label: String,
    pub ruser: String,
    pub backend: String,
    /// `anthropic` | `openai`
    pub api: String,
    pub base_url: String,
    pub needs_key: bool,
    pub model: String,
    /// `low|medium|high|xhigh|max`, or empty for the model's default.
    pub effort: String,
    /// Effort levels the model is known to accept (empty = unknown: try, fall back on 400).
    pub effort_levels: Vec<String>,
    /// Model supports `thinking: {type: "adaptive"}` (Anthropic).
    pub adaptive: bool,
    pub context: u64,
    pub max_output: u64,
    pub timeout_secs: u64,
    /// `/run/swrap/ai/<id>`: proxy + MCP sockets (swrap:swai 0750).
    pub run_dir: String,
    /// Persistent opencode home for (user, target) (swai 0700).
    pub home: String,
    pub swai_uid: u32,
    pub swai_gid: u32,
    pub swrap_uid: u32,
    pub swrap_gid: u32,
    pub admin_gid: u32,
    pub opencode: String,
    pub opencode_version: String,
    /// The `swrap` multi-call binary (sandbox helpers `swai-sandbox`, `swai-mcp`).
    pub helper: String,
    pub system_prompt: String,
    /// MCP tool definitions (`tools/list` result entries).
    pub tools: serde_json::Value,
    pub max_tool_calls: usize,
    pub tz: String,
    /// opencode permission for exec/write_file/edit_file: `ask` (default) or `allow`.
    #[serde(default)]
    pub approval: String,
    /// No permission prompts at all (one host): Claude Code runs with
    /// --dangerously-skip-permissions, opencode allows every tool.
    #[serde(default)]
    pub loose: bool,
    /// A handoff successor's first prompt: the predecessor's briefing (empty otherwise).
    #[serde(default)]
    pub first_prompt: String,
    /// Tool results remind the AI to hand off when this few calls are left.
    #[serde(default)]
    pub handoff_warn: usize,
    /// Place in a handoff chain (0 = started by a user) and its limit.
    #[serde(default)]
    pub chain: usize,
    #[serde(default)]
    pub max_handoffs: usize,
    /// "" | "last" | an opencode session id (`ses_…`).
    #[serde(default)]
    pub resume: String,
    /// A session left without a client ends after this long.
    #[serde(default)]
    pub detached_secs: u64,
    /// `opencode` (default) or `claude` (Claude Code with the user's plan).
    #[serde(default)]
    pub harness: String,
    /// Claude Code: the binary, and the working directory in the sandbox (`/<target>`), which
    /// keys its per-target conversation history.
    #[serde(default)]
    pub claude: String,
    #[serde(default)]
    pub workdir: String,
}

// ---------------------------------------------------------------- core ↔ edge (over the link)

/// Requests edge sends to core over `core-api.sock`. Core treats edge as partially trusted:
/// it believes edge about *who* logged in, and decides everything else itself.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum EdgeReq {
    Hello { node: String, version: String, now: String, #[serde(default)] addrs: Vec<String> },
    /// Long-poll for work core needs done from edge's network (hosts with `network = "edge"`).
    Jobs,
    JobResult { id: String, result: serde_json::Value },
    /// Stream for a core-origin session that edge runs: bridges to the waiting core client.
    Attach { id: String },
    /// Long-poll for a signed snapshot newer than `have`.
    Snapshot { have: u64 },
    /// A client request from an AAA user logged in on edge.
    Api { user: String, client_addr: String, req: Req },
    /// `sw` from edge: core authorizes and decides the exec node.
    Authorize { user: String, client_addr: String, conn: String, target: String, cmd: Vec<String>, cols: u16, rows: u16, term: String, tty: bool },
    /// Relay an ssh-agent connection for an edge-run session to core's filtering proxy.
    Agent { id: String },
    /// Edge-run session reached "authenticated" (core kills the per-session agent).
    Authenticated { id: String },
    /// Append record bytes produced on edge. Followed by DATA frames; core acks with offsets.
    Ingest { header: String, offset: u64 },
    /// Admin password from edge's pam_exec helper: verify (and unseal) on core.
    Unlock { user: String, password: String, rhost: String },
    /// Edge log lines (journald of swrap units + sshd).
    Log { lines: Vec<String> },
    /// Long-poll for the inventory tree (`state/`, spec 10.7) newer than commit `have`: DATA
    /// frames carry its `git archive` (tar.gz), then RESP {head}.
    State { have: String },
}

/// Core's answer to `Authorize`.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct EdgeSession {
    /// true: exec node is core; edge relays the PTY stream over core-pty.sock.
    pub delegate: bool,
    pub id: String,
    pub nonce: String,
    pub banner: String,
    pub header: serde_json::Map<String, serde_json::Value>,
    pub argv_tail: Vec<String>,
    pub ssh_config: String,
    pub known_hosts: String,
    pub pub_key: String,
    pub label: String,
    pub ssh_bin: String,
}

/// First frame on `core-pty.sock`: a delegated session for a user logged in on edge.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EdgePty {
    pub user: String,
    pub client_addr: String,
    pub req: Req,
}

/// Work core hands to edge (hosts only edge can reach).
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum EdgeJob {
    Keyscan { id: String, addr: String, port: u16 },
    /// Non-interactive ssh through core's filtering agent (enrollment, admin commands).
    Exec { id: String, plan: EdgeSession, stdin_b64: String, timeout_secs: u64 },
    /// Interactive session started on core for an edge-network host: edge runs and records it.
    Session { id: String, user: String, plan: EdgeSession, cols: u16, rows: u16, term: String },
    /// A TCP connection to `addr:port` that edge attaches to core with `Attach { id }`: core's own
    /// ssh runs through it, so edge relays only ciphertext (SFTP to edge-network hosts).
    Connect { id: String, addr: String, port: u16 },
}

/// A `--secret-env` value: never shown by `Debug`, so it cannot reach a log by accident.
#[derive(Serialize, Deserialize, Clone)]
pub struct SecretEnv {
    pub name: String,
    pub value: String,
}

impl std::fmt::Debug for SecretEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretEnv({}=<redacted>)", self.name)
    }
}
