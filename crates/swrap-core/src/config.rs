//! Config models for the `config/` git repo (spec sections 9.3, 10.1, 13.1, 17, 23).
//! Config is re-read on every request (spec 12.3); nothing here caches.

use crate::paths::{safe_component, Paths};
use crate::time::IsoDuration;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

fn read_toml<T: serde::de::DeserializeOwned>(p: &Path) -> Result<T> {
    let s = std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
    toml::from_str(&s).with_context(|| format!("parse {}", p.display()))
}

fn dur(s: &str) -> IsoDuration {
    IsoDuration::parse(s).expect("valid default")
}

// ---------------------------------------------------------------- swrap.toml

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct SwrapConfig {
    pub general: General,
    pub network: Network,
    pub rec: RecCfg,
    pub retention: Retention,
    pub limits: Limits,
    pub inventory: InventoryCfg,
    pub fleet: FleetCfg,
    pub signing: SigningCfg,
    pub web: WebCfg,
    pub vault: VaultCfg,
    pub node: NodeCfg,
}

impl Default for SwrapConfig {
    fn default() -> Self {
        SwrapConfig {
            general: General::default(),
            network: Network::default(),
            rec: RecCfg::default(),
            retention: Retention::default(),
            limits: Limits::default(),
            inventory: InventoryCfg::default(),
            fleet: FleetCfg::default(),
            signing: SigningCfg::default(),
            web: WebCfg::default(),
            vault: VaultCfg::default(),
            node: NodeCfg::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct General {
    pub display_timezone: String,
    pub default_profile: String,
    pub enroll_key_ttl: IsoDuration,
}
impl Default for General {
    fn default() -> Self {
        General { display_timezone: "UTC".into(), default_profile: "modern".into(), enroll_key_ttl: dur("P14D") }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Network {
    pub internal_networks: Vec<String>,
    pub core_egress_addresses: Vec<String>,
    pub from_restriction: bool,
    pub lan_cidrs: Vec<String>,
    pub managed_ports: Vec<u16>,
}
impl Default for Network {
    fn default() -> Self {
        Network {
            internal_networks: vec!["10.0.0.0/8".into(), "172.16.0.0/12".into(), "192.168.0.0/16".into(), "fd00::/8".into()],
            core_egress_addresses: vec![],
            from_restriction: true,
            lan_cidrs: vec![],
            managed_ports: vec![22],
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct RecCfg {
    pub coalesce: IsoDuration,
    pub coalesce_max_bytes: usize,
    pub sync_interval: IsoDuration,
    pub checkpoint_interval: IsoDuration,
    pub checkpoint_bytes: u64,
    /// Store output that repeats recent output (spinners, animations) as `p` records.
    pub fold_repeats: bool,
}
impl Default for RecCfg {
    fn default() -> Self {
        RecCfg {
            coalesce: dur("PT0.005S"),
            coalesce_max_bytes: 16384,
            sync_interval: dur("PT1S"),
            checkpoint_interval: dur("PT10S"),
            checkpoint_bytes: 262144,
            fold_repeats: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Retention {
    pub high_watermark_pct: u8,
    pub low_watermark_pct: u8,
    pub check_interval: IsoDuration,
    pub compress_after: IsoDuration,
    pub gzip_member_bytes: usize,
    pub alert_if_evicting_younger_than: IsoDuration,
}
impl Default for Retention {
    fn default() -> Self {
        Retention {
            high_watermark_pct: 90,
            low_watermark_pct: 90,
            check_interval: dur("PT1M"),
            compress_after: dur("P7D"),
            gzip_member_bytes: 262144,
            alert_if_evicting_younger_than: dur("P30D"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Limits {
    pub sessions_per_user: usize,
    pub sessions_core: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Limits { sessions_per_user: 10, sessions_core: 100 }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct InventoryCfg {
    pub interval: IsoDuration,
    pub host_timeout: IsoDuration,
    pub parallel: usize,
}
impl Default for InventoryCfg {
    fn default() -> Self {
        InventoryCfg { interval: dur("PT6H"), host_timeout: dur("PT2M"), parallel: 8 }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct FleetCfg {
    pub parallel: usize,
    pub default_timeout: IsoDuration,
}
impl Default for FleetCfg {
    fn default() -> Self {
        FleetCfg { parallel: 8, default_timeout: dur("PT10M") }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct SigningCfg {
    pub max_signatures_per_session: u32,
    pub window: IsoDuration,
    pub require_hostbound: bool,
}
impl Default for SigningCfg {
    fn default() -> Self {
        SigningCfg { max_signatures_per_session: 4, window: dur("PT2M"), require_hostbound: false }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct WebCfg {
    pub bind: Vec<String>,
    pub tls_cert: String,
    pub tls_key: String,
    pub session_lifetime: IsoDuration,
    pub search_default_window: String,
    pub search_max_results: usize,
}
impl Default for WebCfg {
    fn default() -> Self {
        WebCfg {
            bind: vec!["unix:/run/swrap/web.sock".into(), "0.0.0.0:443".into()],
            tls_cert: "/etc/swrap/tls/cert.pem".into(),
            tls_key: "/etc/swrap/tls/key.pem".into(),
            session_lifetime: dur("PT12H"),
            search_default_window: "P1D/now".into(),
            search_max_results: 1000,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct VaultCfg {
    pub argon2_m_kib: u32,
    pub argon2_t: u32,
    pub argon2_p: u32,
}
impl Default for VaultCfg {
    fn default() -> Self {
        VaultCfg { argon2_m_kib: 262144, argon2_t: 3, argon2_p: 1 }
    }
}

/// Identity of this node (not in the spec's example, but needed; defaults to core).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeCfg {
    pub name: String,
}
impl Default for NodeCfg {
    fn default() -> Self {
        NodeCfg { name: "core".into() }
    }
}

impl SwrapConfig {
    pub fn load(p: &Paths) -> Result<Self> {
        let f = p.swrap_toml();
        if !f.exists() {
            return Ok(Self::default());
        }
        read_toml(&f)
    }
    pub fn tz(&self) -> &str {
        &self.general.display_timezone
    }
}

// ---------------------------------------------------------------- profiles

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NodeOverride {
    pub ssh_bin: Option<String>,
    pub ssh_keygen_bin: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    #[serde(default = "default_ssh")]
    pub ssh_bin: String,
    #[serde(default = "default_keygen")]
    pub ssh_keygen_bin: String,
    #[serde(default)]
    pub kex: Vec<String>,
    #[serde(default)]
    pub ciphers: Vec<String>,
    #[serde(default)]
    pub macs: Vec<String>,
    #[serde(default)]
    pub host_key_algorithms: Vec<String>,
    #[serde(default)]
    pub key_preference: Vec<String>,
    #[serde(default)]
    pub pubkey_accepted_algorithms: Vec<String>,
    #[serde(default = "default_rsa_bits")]
    pub rsa_bits: u32,
    #[serde(default)]
    pub extra_options: BTreeMap<String, String>,
    #[serde(default)]
    pub warn: bool,
    #[serde(default)]
    pub node: BTreeMap<String, NodeOverride>,
}

fn default_ssh() -> String { "/usr/bin/ssh".into() }
fn default_keygen() -> String { "/usr/bin/ssh-keygen".into() }
fn default_rsa_bits() -> u32 { 4096 }

impl Profile {
    pub fn load(p: &Paths, name: &str) -> Result<Self> {
        if !safe_component(name) {
            bail!("bad profile name {name:?}");
        }
        read_toml(&p.profile(name))
    }
    pub fn ssh_bin_for(&self, node: &str) -> &str {
        self.node.get(node).and_then(|o| o.ssh_bin.as_deref()).unwrap_or(&self.ssh_bin)
    }
    pub fn keygen_bin_for(&self, node: &str) -> &str {
        self.node.get(node).and_then(|o| o.ssh_keygen_bin.as_deref()).unwrap_or(&self.ssh_keygen_bin)
    }
    /// Render the `ssh_config` used with `-F` (spec 9.2).
    pub fn ssh_config(&self) -> String {
        let mut s = String::from("# generated by swrap from profile ");
        s += &self.name;
        s += "\nHost *\n";
        let mut kv = |k: &str, v: &[String]| {
            if !v.is_empty() {
                s += &format!("  {} {}\n", k, v.join(","));
            }
        };
        kv("KexAlgorithms", &self.kex);
        kv("Ciphers", &self.ciphers);
        kv("MACs", &self.macs);
        kv("HostKeyAlgorithms", &self.host_key_algorithms);
        let pk = if self.pubkey_accepted_algorithms.is_empty() { &self.key_preference } else { &self.pubkey_accepted_algorithms };
        kv("PubkeyAcceptedAlgorithms", pk);
        for (k, v) in &self.extra_options {
            if k.bytes().all(|b| b.is_ascii_alphanumeric()) && !v.contains('\n') {
                s += &format!("  {k} {v}\n");
            }
        }
        s
    }
}

// ---------------------------------------------------------------- hosts

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Route {
    Core,
    Edge,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HostState {
    Pending,
    Active,
    Disabled,
    Removed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    pub name: String,
    pub key_algo: String,
    #[serde(default)]
    pub key_fingerprint: String,
    #[serde(default)]
    pub created: String,
    /// `n/a` (root), `nopasswd`, `none`.
    #[serde(default = "sudo_none")]
    pub sudo: String,
    #[serde(default)]
    pub managed_by_swrap: bool,
    #[serde(default)]
    pub integration: bool,
    /// Locked by `swuser lock` (the account has expired: no login, not even with its key).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub locked: bool,
}

/// `/etc/sudoers.d/swrap-<ruser>` exactly as `swuser` writes it (inventory compares the hash).
pub fn swrap_sudoers(ruser: &str) -> String {
    format!("# managed by swrap (swuser): edits are reported as drift\n{ruser} ALL=(ALL) NOPASSWD: ALL\n")
}

/// A remote user name swuser accepts: a portable lower-case login name, never root.
pub fn valid_ruser(n: &str) -> bool {
    n != "root"
        && !n.is_empty()
        && n.len() <= 32
        && n.bytes().next().is_some_and(|b| b.is_ascii_lowercase() || b == b'_')
        && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}
fn sudo_none() -> String { "none".into() }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Host {
    pub label: String,
    pub address: String,
    #[serde(default = "port22")]
    pub port: u16,
    pub route: Route,
    #[serde(default = "yes")]
    pub edge_allowed: bool,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "modern")]
    pub profile: String,
    #[serde(default = "root")]
    pub default_user: String,
    pub state: HostState,
    #[serde(default)]
    pub enrolled: String,
    #[serde(default)]
    pub created: String,
    #[serde(default)]
    pub hostkey_fingerprints: Vec<String>,
    /// Which node's network the host lives in (who can reach it): `core` (default; also any
    /// public host) or `edge` (private network behind the edge, e.g. cloud VMs next to mail).
    /// Edge-network hosts are enrolled, administered and run from edge.
    #[serde(default = "net_core")]
    pub network: Route,
    #[serde(default, rename = "account")]
    pub accounts: Vec<Account>,
    /// swai may act on this host (spec 24.5: the host must opt in; default false).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ai_allowed: bool,
    /// `swai reset` may roll this VM back to its Proxmox snapshot (spec 24.5).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ai_reset: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxmox: Option<ProxmoxVm>,
    /// Free-form progress notes for failed/partial enrollments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enroll_progress: Vec<String>,
}
/// Where `swai reset` rolls a host back: Proxmox API server, node, VM id and snapshot name.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProxmoxVm {
    pub api: String,
    pub node: String,
    pub vmid: u32,
    pub snapshot: String,
}

fn port22() -> u16 { 22 }
fn net_core() -> Route { Route::Core }
fn yes() -> bool { true }
fn modern() -> String { "modern".into() }
fn root() -> String { "root".into() }

impl Host {
    pub fn load(p: &Paths, label: &str) -> Result<Self> {
        if !safe_component(label) {
            bail!("bad host label {label:?}");
        }
        let f = p.host(label);
        if !f.exists() {
            bail!("unknown host {label:?}");
        }
        read_toml(&f)
    }
    pub fn all(p: &Paths) -> Result<Vec<Self>> {
        let mut v = vec![];
        let d = p.hosts();
        if !d.exists() {
            return Ok(v);
        }
        for e in std::fs::read_dir(d)? {
            let e = e?;
            let n = e.file_name().to_string_lossy().to_string();
            if let Some(l) = n.strip_suffix(".toml") {
                if safe_component(l) {
                    v.push(read_toml::<Host>(&e.path())?);
                }
            }
        }
        v.sort_by(|a, b| a.label.cmp(&b.label));
        Ok(v)
    }
    pub fn account(&self, name: &str) -> Option<&Account> {
        self.accounts.iter().find(|a| a.name == name)
    }
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("serialize host")
    }
}

// ---------------------------------------------------------------- users

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    User,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Grant {
    pub id: String,
    /// Targets expression (section 10.6), e.g. `*`, `web*`, `@lab,!db-1`.
    pub hosts: String,
    pub remote_users: Vec<String>,
    #[serde(default = "via_both")]
    pub via: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
    #[serde(default)]
    pub created: String,
}
fn via_both() -> Vec<String> { vec!["core".into(), "edge".into()] }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    pub name: String,
    pub role: Role,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub keys: Vec<String>,
    #[serde(default)]
    pub created: String,
    #[serde(default, rename = "grant")]
    pub grants: Vec<Grant>,
    /// AI grants (spec 24.5): separate from human grants, never inherited from them.
    #[serde(default, rename = "ai_grant", skip_serializing_if = "Vec::is_empty")]
    pub ai_grants: Vec<AiGrant>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AiGrant {
    pub id: String,
    /// Targets expression; only hosts with `ai_allowed = true` ever match.
    pub hosts: String,
    pub remote_users: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
    #[serde(default)]
    pub created: String,
}

impl User {
    pub fn load(p: &Paths, name: &str) -> Result<Self> {
        if !safe_component(name) {
            bail!("bad user name {name:?}");
        }
        let f = p.user(name);
        if !f.exists() {
            bail!("{name} is not an AAA user");
        }
        read_toml(&f)
    }
    pub fn all(p: &Paths) -> Result<Vec<Self>> {
        let mut v = vec![];
        let d = p.users();
        if !d.exists() {
            return Ok(v);
        }
        for e in std::fs::read_dir(d)? {
            let e = e?;
            if e.file_name().to_string_lossy().ends_with(".toml") {
                v.push(read_toml::<User>(&e.path())?);
            }
        }
        v.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(v)
    }
    pub fn is_admin(&self) -> bool {
        self.role == Role::Admin && !self.disabled
    }
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("serialize user")
    }
}

// ---------------------------------------------------------------- firewall / edge

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct FwEntry {
    pub id: String,
    pub cidr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(default)]
    pub comment: String,
    #[serde(default)]
    pub created_by: String,
    #[serde(default)]
    pub created: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Firewall {
    #[serde(default)]
    pub web_allow: Vec<FwEntry>,
    #[serde(default)]
    pub ssh_block: Vec<FwEntry>,
}

impl Firewall {
    pub fn load(p: &Paths) -> Result<Self> {
        let f = p.firewall_toml();
        if !f.exists() {
            return Ok(Self::default());
        }
        read_toml(&f)
    }
}

// ---------------------------------------------------------------- ai.toml (swai)

/// `config/ai.toml`: inference backends and AI limits.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct AiConfig {
    #[serde(default, rename = "backend")]
    pub backends: Vec<AiBackend>,
    #[serde(default)]
    pub limits: AiLimits,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AiApi {
    /// Anthropic Messages API (`/v1/messages`) with an API key from the vault (opencode).
    Anthropic,
    /// OpenAI-compatible chat completions (`/v1/chat/completions`): llama.cpp, vLLM, Ollama, …
    Openai,
    /// Claude Code itself as the harness, signed in with the user's Claude plan (Pro/Max).
    #[serde(rename = "claude-code")]
    ClaudeCode,
}

impl AiApi {
    pub fn as_str(&self) -> &'static str {
        match self {
            AiApi::Anthropic => "anthropic",
            AiApi::Openai => "openai",
            AiApi::ClaudeCode => "claude-code",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AiBackend {
    pub name: String,
    pub api: AiApi,
    /// Scheme, host and port only (`https://api.anthropic.com`, `http://10.0.0.20:8080`);
    /// the proxy appends `/v1/…`.
    pub base_url: String,
    /// Optional allow-list; empty = any model the backend serves.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<String>,
    /// The API key lives in the vault (`keys/ai/<name>.enc`); this only says one is needed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub needs_key: bool,
    /// How long the inference server may stay silent (plain HTTP; total time for HTTPS). Local
    /// models at high effort can think for many minutes before the first visible output.
    #[serde(default = "ai_timeout")]
    pub timeout: String,
    /// Requests to this backend at once, over all sessions (0 = no limit); more wait their turn.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_concurrent: u32,
    #[serde(default)]
    pub added_by: String,
    #[serde(default)]
    pub created: String,
}
fn ai_timeout() -> String { "PT1H".into() }
fn is_zero_u32(n: &u32) -> bool { *n == 0 }

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct AiLimits {
    /// Tool calls per user in flight at once.
    pub concurrent_calls: usize,
    /// Tool calls per user per hour.
    pub calls_per_hour: usize,
    /// Tool calls per swai session.
    pub max_tool_calls: usize,
    /// swai sessions per user at once.
    pub sessions_per_user: usize,
    /// Tool approval in the TUI for exec/write_file/edit_file: `ask` (spec 24.13: on at first)
    /// or `allow`.
    pub approval: String,
    /// Context cap (tokens) for one-host sessions, so they compact earlier and stay cheap.
    pub host_context: u64,
    /// A detached session (no client attached) ends after this long.
    pub detached_timeout: String,
    /// A session that runs out of tool calls hands off to a successor (fresh budget, its
    /// briefing as the first prompt) at most this many times in a row.
    pub max_handoffs: usize,
    /// Tool results remind the AI to hand off when this few calls are left.
    pub handoff_warn: usize,
    /// A new session needs this much available memory on core (MiB): each one runs a Claude
    /// Code or opencode process of several hundred MiB, and core has no swap.
    pub min_available_mb: u64,
}

impl Default for AiLimits {
    fn default() -> Self {
        AiLimits { concurrent_calls: 16, calls_per_hour: 600, max_tool_calls: 500, sessions_per_user: 12, approval: "ask".into(), host_context: 200_000, detached_timeout: "P7D".into(), max_handoffs: 10, handoff_warn: 25, min_available_mb: 1024 }
    }
}

impl AiConfig {
    pub fn load(p: &Paths) -> Result<Self> {
        let f = p.ai_toml();
        if !f.exists() {
            return Ok(Self::default());
        }
        read_toml(&f)
    }
    pub fn backend(&self, name: &str) -> Option<&AiBackend> {
        self.backends.iter().find(|b| b.name == name)
    }
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("serialize ai.toml")
    }
}

// ---------------------------------------------------------------- helpers

pub fn load_all_profiles(p: &Paths) -> Result<Vec<Profile>> {
    let mut v = vec![];
    if let Ok(rd) = std::fs::read_dir(p.profiles()) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().ends_with(".toml") {
                v.push(read_toml::<Profile>(&e.path())?);
            }
        }
    }
    v.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(v)
}

pub fn parse_toml<T: serde::de::DeserializeOwned>(s: &str) -> Result<T> {
    Ok(toml::from_str(s)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_with_proxmox_and_accounts_round_trips() {
        let mut h: Host = toml::from_str("label = \"lab\"\naddress = \"10.0.0.9\"\nport = 22\nroute = \"core\"\nprofile = \"modern\"\ndefault_user = \"root\"\nstate = \"active\"\nai_allowed = true\n").unwrap();
        h.ai_reset = true;
        h.proxmox = Some(ProxmoxVm { api: "https://pve.lan:8006".into(), node: "pve".into(), vmid: 120, snapshot: "clean".into() });
        h.accounts.push(Account { name: "root".into(), key_algo: "ssh-ed25519".into(), key_fingerprint: "SHA256:x".into(), created: "2026-10-03T00:00:00Z".into(), sudo: "none".into(), managed_by_swrap: false, integration: true, locked: false });
        h.enroll_progress = vec!["step".into()];
        let back: Host = toml::from_str(&h.to_toml()).unwrap();
        assert_eq!(back.proxmox, h.proxmox);
        assert!(back.ai_reset && back.accounts.len() == 1 && back.enroll_progress.len() == 1);
    }
}
