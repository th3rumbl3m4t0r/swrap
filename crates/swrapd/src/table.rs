//! The `table` asset database as swrap's ticket sink and asset record.
//!
//! * **Tickets** only for actionable conditions, through a create-only form: per host, one
//!   ticket when conditions appear (unreachable, reboot needed, security updates, unexpected
//!   sudoers files, no asset record), nothing while they persist, a new one only after they
//!   cleared and came back; other alerts (doctor, retention, clock) at most once per P7D each.
//!   Tickets wait in a queue while table or the vault is unavailable.
//! * **Assets**: after each inventory, every enrolled host's asset gets `aaa_label`,
//!   `aaa_asimilated` and `aaa_running_projects` (active git repositories found on the host,
//!   merged with hand-written lines, which are never changed). Hosts without one get one
//!   through a create-only form.
//! * **Endpoint agent**: a host without it gets it (its per-host forms made with the table admin
//!   login, see `eagent`), when that login is in the vault.
//!
//! Form tokens and the admin password live in the vault (`keys/table/<name>.enc`), settings in
//! `config/table.toml`.

use crate::daemon::{Caller, Console, Daemon};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use swrap_core::api::Resp;
use swrap_core::config::{Host, HostState};
use swrap_core::time::{fmt_utc_secs, now};

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct TableCfg {
    /// Base URL of table.
    pub endpoint: String,
    pub ticket_form: String,
    pub asset_read_form: String,
    pub asset_update_form: String,
    /// Create-only form for new assets (enrolled hosts table does not know yet).
    pub asset_create_form: String,
    /// cgit index: repositories cloned from `git_hosts` (host names, SSH aliases or path
    /// fragments of the git server) link here as `<git_web><name>/`.
    pub git_web: String,
    pub git_hosts: Vec<String>,
    /// A repository counts as active when used by a process or unit, or changed within this.
    pub active_days: u64,
    /// The table admin account swrap creates the endpoint agent's per-host forms with (its
    /// password: `swrap table admin-password`, in the vault).
    pub admin_user: String,
    /// Deploy the endpoint agent by itself to hosts found without it (at most once a day each).
    pub agent_auto: bool,
    /// The agent that is installed, and that makes the forms (`--provision-env`).
    pub agent_script: String,
    /// How hosts reach table (TABLE_ENDPOINT in their env): empty = `endpoint`; edge hosts use
    /// `agent_endpoint_edge`, and get no agent while it is empty.
    pub agent_endpoint: String,
    pub agent_endpoint_edge: String,
}

impl Default for TableCfg {
    fn default() -> Self {
        TableCfg {
            endpoint: String::new(),
            ticket_form: "aaa_create_ticket".into(),
            asset_read_form: "aaa_asset_read".into(),
            asset_update_form: "aaa_asset_update".into(),
            asset_create_form: "aaa_create_asset".into(),
            git_web: String::new(),
            git_hosts: vec![],
            active_days: 30,
            admin_user: "aaa_adm".into(),
            agent_auto: true,
            agent_script: "/usr/local/sbin/endpoint-agent.py".into(),
            agent_endpoint: String::new(),
            agent_endpoint_edge: String::new(),
        }
    }
}

const TOKENS: [&str; 4] = ["ticket", "asset-read", "asset-update", "asset-create"];
const REPEAT: i64 = 7 * 86400;

fn cfg_path(d: &Daemon) -> PathBuf {
    d.paths.config().join("table.toml")
}

pub fn cfg(d: &Daemon) -> TableCfg {
    std::fs::read_to_string(cfg_path(d)).ok().and_then(|s| toml::from_str(&s).ok()).unwrap_or_default()
}

fn token_path(d: &Daemon, which: &str) -> PathBuf {
    d.paths.vault_keys().join("table").join(format!("{which}.enc"))
}

/// A form token from the vault; `None` if never set, an error while sealed.
fn token(d: &Daemon, which: &str) -> Result<Option<zeroize::Zeroizing<String>>> {
    let p = token_path(d, which);
    if !p.exists() {
        return Ok(None);
    }
    let raw = d.with_dek(|dek| swrap_vault::Vault::new(&d.paths, d.owner()).get(dek, &p))?;
    Ok(Some(zeroize::Zeroizing::new(String::from_utf8_lossy(&raw).trim().to_string())))
}

/// The table admin login (user, password) from the vault; `None` if never set.
pub fn admin_login(d: &Daemon) -> Result<Option<(String, zeroize::Zeroizing<String>)>> {
    let p = token_path(d, "admin");
    if !p.exists() {
        return Ok(None);
    }
    let raw = zeroize::Zeroizing::new(d.with_dek(|dek| swrap_vault::Vault::new(&d.paths, d.owner()).get(dek, &p))?);
    Ok(Some((cfg(d).admin_user, zeroize::Zeroizing::new(String::from_utf8_lossy(&raw).to_string()))))
}

/// Log in to table as `user` (sha256 of `user:password`, as table's own login page sends it),
/// confirm the account is an admin, log out again.
fn check_admin(c: &TableCfg, user: &str, pass: &str) -> Result<()> {
    use sha2::Digest;
    let base = c.endpoint.trim_end_matches('/');
    let http = crate::ai::http(Duration::from_secs(20));
    let auth = format!("{:x}", sha2::Sha256::digest(format!("{user}:{pass}").as_bytes()));
    let mut r = http.post(&format!("{base}/api/login")).header("Content-Type", "application/json").send(&serde_json::to_vec(&json!({"username": user, "auth": auth}))?[..])?;
    let st = r.status().as_u16();
    let cookie = r.headers().get("set-cookie").and_then(|v| v.to_str().ok()).and_then(|v| v.split(';').next()).unwrap_or("").to_string();
    let body = r.body_mut().read_to_string().unwrap_or_default();
    if st != 200 || cookie.is_empty() {
        bail!("table refused the login of {user} ({st}): {}", cut(&body, 200));
    }
    let mut me = http.get(&format!("{base}/api/me")).header("Cookie", &cookie).call()?;
    let me: Value = serde_json::from_str(&me.body_mut().read_to_string().unwrap_or_default()).unwrap_or_default();
    let _ = http.post(&format!("{base}/api/logout")).header("Cookie", &cookie).send(&b""[..]);
    if me["admin"] != json!(true) {
        bail!("{user} logs in, but is not a table admin");
    }
    Ok(())
}

// ---------------------------------------------------------------- state

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct State {
    /// `<label>|<kind>` → since (ISO): host conditions already ticketed.
    open: BTreeMap<String, String>,
    /// Other alerts: key → last ticket (unix seconds).
    sent: BTreeMap<String, i64>,
    queue: Vec<Ticket>,
    /// label → asset id (from the last sync; `core` is this node).
    assets: BTreeMap<String, i64>,
    /// label → project lines swrap added (removed again when the repository goes).
    auto_projects: BTreeMap<String, Vec<String>>,
    /// label → last automatic endpoint agent deployment (unix seconds).
    agent_tries: BTreeMap<String, i64>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Ticket {
    short: String,
    description: String,
    worknotes: String,
    #[serde(default)]
    label: String,
}

static STATE: Mutex<()> = Mutex::new(());

fn state_path(d: &Daemon) -> PathBuf {
    d.paths.index().join("table.json")
}

fn load_state(d: &Daemon) -> State {
    std::fs::read_to_string(state_path(d)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn save_state(d: &Daemon, st: &State) {
    let _ = swrap_core::atomic::write(&state_path(d), serde_json::to_string_pretty(st).unwrap_or_default().as_bytes(), 0o600, d.owner());
}

/// One actionable condition of a host.
pub struct Condition {
    pub kind: &'static str,
    pub summary: String,
    pub detail: String,
}

/// The host's actionable conditions now (inventory + asset sync). New ones → one ticket.
pub fn host_conditions(d: &Daemon, label: &str, conds: Vec<Condition>) {
    let _g = STATE.lock().unwrap_or_else(|p| p.into_inner());
    let mut st = load_state(d);
    let keys: BTreeSet<String> = conds.iter().map(|c| format!("{label}|{}", c.kind)).collect();
    let prefix = format!("{label}|");
    let cleared: Vec<String> = st.open.keys().filter(|k| k.starts_with(&prefix) && !keys.contains(*k)).cloned().collect();
    for k in cleared {
        st.open.remove(&k);
        d.audit_event("", "ticket.cleared", label, "", "ok", json!({"condition": k}), "");
    }
    let fresh: Vec<&Condition> = conds.iter().filter(|c| !st.open.contains_key(&format!("{label}|{}", c.kind))).collect();
    if !fresh.is_empty() {
        let when = fmt_utc_secs(now());
        for c in &fresh {
            st.open.insert(format!("{label}|{}", c.kind), when.clone());
        }
        let short = format!("{label}: {}", fresh.iter().map(|c| c.summary.as_str()).collect::<Vec<_>>().join("; "));
        let description = fresh.iter().map(|c| c.detail.as_str()).collect::<Vec<_>>().join("\n\n");
        st.queue.push(Ticket {
            short,
            description,
            worknotes: format!("Raised by swrap on the AAA core at {when} from its host inventory. swrap raises this again only after the condition has cleared and come back."),
            label: label.to_string(),
        });
    }
    save_state(d, &st);
}

/// Alerts that are not per host (doctor, retention, clock): at most once per P7D each.
pub fn alert(d: &Daemon, what: &str, detail: &Value) {
    if what.starts_with("host.") {
        return; // tickets come from host_conditions
    }
    let summary = match what {
        "doctor" => format!("integrity check: {}", detail["first"].as_str().unwrap_or("findings")),
        "retention" => detail["msg"].as_str().map(String::from).unwrap_or_else(|| "recording retention problem".into()),
        "clock" => "edge clock offset above PT1S".into(),
        other => other.to_string(),
    };
    let key = format!("{what}|{summary}");
    let _g = STATE.lock().unwrap_or_else(|p| p.into_inner());
    let mut st = load_state(d);
    let t = now().as_second();
    if st.sent.get(&key).is_some_and(|last| t - last < REPEAT) {
        return;
    }
    st.sent.insert(key, t);
    st.queue.push(Ticket {
        short: format!("AAA: {}", cut(&summary, 180)),
        description: format!("swrap on the AAA core raised a `{what}` alert:\n\n{}\n\nSee `swrap status` and the audit log on the core.", serde_json::to_string_pretty(detail).unwrap_or_default()),
        worknotes: format!("Raised by swrap at {}. The same alert does not raise another ticket within P7D.", fmt_utc_secs(now())),
        label: "core".into(),
    });
    save_state(d, &st);
}

fn cut(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() } else { s.chars().take(n - 1).collect::<String>() + "…" }
}

fn post(d: &Daemon, path: &str, bearer: &str, body: &Value) -> Result<(u16, String)> {
    let c = cfg(d);
    let url = format!("{}{path}", c.endpoint.trim_end_matches('/'));
    let mut r = crate::ai::http(Duration::from_secs(20)).post(&url).header("Authorization", &format!("Bearer {bearer}")).header("Content-Type", "application/json").send(&serde_json::to_vec(body)?[..])?;
    let st = r.status().as_u16();
    Ok((st, r.body_mut().read_to_string().unwrap_or_default()))
}

fn get(d: &Daemon, path: &str, bearer: &str) -> Result<Value> {
    let c = cfg(d);
    let url = format!("{}{path}", c.endpoint.trim_end_matches('/'));
    let mut r = crate::ai::http(Duration::from_secs(20)).get(&url).header("Authorization", &format!("Bearer {bearer}")).call()?;
    let st = r.status().as_u16();
    let body = r.body_mut().read_to_string().unwrap_or_default();
    if st != 200 {
        bail!("table answered {st}: {}", cut(&body, 200));
    }
    Ok(serde_json::from_str(&body)?)
}

/// Send queued tickets (in order; stops at the first failure and tries again later).
pub fn flush(d: &Daemon) -> Result<usize> {
    let _g = STATE.lock().unwrap_or_else(|p| p.into_inner());
    let mut st = load_state(d);
    if st.queue.is_empty() || d.is_sealed() {
        return Ok(0);
    }
    let Some(tok) = token(d, "ticket")? else { return Ok(0) };
    let form = cfg(d).ticket_form;
    let mut sent = 0;
    while let Some(t) = st.queue.first().cloned() {
        let mut body = json!({"short_description": cut(&t.short, 200), "description": t.description, "status": "created", "worknotes": t.worknotes});
        if let Some(id) = st.assets.get(&t.label) {
            body["affected_asset"] = json!(id);
        }
        match post(d, &format!("/api/form/{form}"), &tok, &body) {
            Ok((200, resp)) => {
                let number = serde_json::from_str::<Value>(&resp).ok().and_then(|v| v.get("entry_id").cloned()).unwrap_or(Value::Null);
                d.audit_event("", "ticket.created", &t.label, "", "ok", json!({"short": t.short, "entry": number}), "");
                st.queue.remove(0);
                sent += 1;
            }
            Ok((code, resp)) => {
                d.audit_event("", "ticket.created", &t.label, "", "failed", json!({"short": t.short, "status": code, "error": cut(&resp, 300)}), "");
                // A request table refuses (4xx) would fail forever: drop it, keep the rest.
                if (400..500).contains(&code) {
                    st.queue.remove(0);
                    continue;
                }
                break;
            }
            Err(_) => break,
        }
    }
    st.queue.truncate(500);
    save_state(d, &st);
    Ok(sent)
}

/// Every five minutes: send what is queued.
pub async fn run_loop(d: Arc<Daemon>) {
    loop {
        tokio::time::sleep(Duration::from_secs(300)).await;
        let d2 = d.clone();
        let _ = tokio::task::spawn_blocking(move || flush(&d2)).await;
    }
}

// ---------------------------------------------------------------- assets

/// One git working tree from the inventory's `gitrepos.tsv`.
struct Repo {
    path: String,
    origin: String,
    last_commit: i64,
    in_use: bool,
    recent: bool,
    units: String,
}

fn repos_of(tsv: &str) -> Vec<Repo> {
    tsv.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (f.len() >= 5).then(|| Repo {
                path: f[0].to_string(),
                origin: if f[1] == "-" { String::new() } else { f[1].to_string() },
                last_commit: f[2].parse().unwrap_or(0),
                in_use: f[3] == "yes",
                recent: f[4] == "yes",
                units: f.get(5).unwrap_or(&"").to_string(),
            })
        })
        .collect()
}

/// `git@git.example.com:/srv/git/x.git`, `ssh://…/x.git`, `http://git.example.com/git/x/` → `x` if
/// the host is one of `git_hosts`.
fn git_name(origin: &str, hosts: &[String]) -> Option<String> {
    if !hosts.iter().any(|h| origin.contains(h.as_str())) {
        return None;
    }
    let tail = origin.trim_end_matches('/').rsplit(['/', ':']).next()?;
    let name = tail.strip_suffix(".git").unwrap_or(tail);
    (!name.is_empty()).then(|| name.to_string())
}

/// A clone URL as a link for people: `git@github.com:a/b.git` → `https://github.com/a/b`.
fn web_link(origin: &str) -> String {
    if let Some(rest) = origin.strip_prefix("git@") {
        if let Some((host, path)) = rest.split_once(':') {
            return format!("https://{host}/{}", path.trim_start_matches('/').trim_end_matches(".git"));
        }
    }
    origin.trim_end_matches(".git").to_string()
}

/// A repository's description from its cgit summary page (the index truncates them).
fn cgit_description(web: &str, name: &str) -> Option<String> {
    let mut r = crate::ai::http(Duration::from_secs(10)).get(&format!("{web}{name}/")).call().ok()?;
    let html = r.body_mut().read_to_string().ok()?;
    let i = html.find("<td class='sub'>")? + "<td class='sub'>".len();
    let d = &html[i..i + html[i..].find("</td>")?];
    let d = d.replace("&amp;", "&").replace("&#39;", "'").replace("&quot;", "\"").replace("&lt;", "<").replace("&gt;", ">");
    let d = d.trim();
    (!d.is_empty() && d != name && !d.starts_with("Unnamed repository")).then(|| d.to_string())
}

/// The active repositories of a host as project lines (sorted, one per repository).
fn project_lines(c: &TableCfg, repos: &[Repo], desc: &mut dyn FnMut(&str) -> Option<String>) -> Vec<(String, String)> {
    let recent = now().as_second() - (c.active_days as i64) * 86400;
    let mut out: BTreeMap<String, (String, String)> = BTreeMap::new();
    for r in repos {
        if !(r.in_use || !r.units.is_empty() || r.recent || r.last_commit >= recent) {
            continue;
        }
        let base = r.path.rsplit('/').next().unwrap_or(&r.path).to_string();
        let (key, line) = match git_name(&r.origin, &c.git_hosts) {
            Some(name) => {
                let link = format!("{}{name}/", c.git_web);
                let d = desc(&name).map(|d| format!(" ({d})")).unwrap_or_default();
                (link.clone(), format!("{name}{d} - {link}"))
            }
            None if !r.origin.is_empty() => {
                let link = web_link(&r.origin);
                (link.clone(), format!("{base} - {link}"))
            }
            None => (r.path.clone(), format!("{base} (local repository {})", r.path)),
        };
        out.entry(key.clone()).or_insert((key, line));
    }
    out.into_values().collect()
}

/// Hand-written lines stay as they are; lines swrap added before are replaced by what is active
/// now; a repository a hand-written line already links to is not added again.
fn merge_projects(existing: &str, auto_prev: &[String], detected: &[(String, String)]) -> (String, Vec<String>) {
    let manual: Vec<&str> = existing.lines().map(str::trim_end).filter(|l| !l.trim().is_empty() && !auto_prev.iter().any(|a| a == l)).collect();
    let auto: Vec<String> = detected.iter().filter(|(key, _)| !manual.iter().any(|m| m.contains(key.as_str()))).map(|(_, line)| line.clone()).collect();
    let mut all: Vec<String> = manual.iter().map(|s| s.to_string()).collect();
    all.extend(auto.iter().cloned());
    (all.join("\n"), auto)
}

/// Bring the `aaa_*` columns of every enrolled host's asset up to date. Returns a report and
/// the hosts without an asset record.
pub fn sync_assets(d: &Daemon) -> Result<(String, Vec<String>)> {
    if d.is_sealed() {
        bail!("the vault is sealed");
    }
    let (Some(rtok), Some(utok)) = (token(d, "asset-read")?, token(d, "asset-update")?) else {
        bail!("asset form tokens not set (swrap table token asset-read / asset-update)");
    };
    let c = cfg(d);
    let v = get(d, &format!("/api/form-read/{}?limit=1000", c.asset_read_form), &rtok)?;
    let rows: Vec<Map<String, Value>> = v["rows"].as_array().into_iter().flatten().filter_map(|r| r.as_object().cloned()).collect();
    let s = |r: &Map<String, Value>, k: &str| r.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let hosts: Vec<Host> = Host::all(&d.paths)?.into_iter().filter(|h| h.state == HostState::Active).collect();
    let mut descs: BTreeMap<String, Option<String>> = BTreeMap::new();
    let web = c.git_web.clone();
    let mut desc = |name: &str| descs.entry(name.to_string()).or_insert_with(|| cgit_description(&web, name)).clone();
    let _g = STATE.lock().unwrap_or_else(|p| p.into_inner());
    let mut st = load_state(d);
    let mut report = vec![];
    let mut missing = vec![];
    let mut updates: Vec<(i64, Map<String, Value>, String)> = vec![];
    // Enrolled hosts; `core` is this node itself (its asset has no label).
    let mut targets: Vec<(String, Option<Host>)> = hosts.iter().map(|h| (h.label.clone(), Some(h.clone()))).collect();
    targets.push(("core".into(), None));
    for (label, host) in &targets {
        let found = match host {
            Some(h) => {
                let facts_host = std::fs::read_to_string(d.paths.state().join("hosts").join(label).join("facts.toml")).ok().and_then(|t| toml::from_str::<toml::Value>(&t).ok()).and_then(|t| t.get("hostname").and_then(|v| v.as_str()).map(String::from)).unwrap_or_default();
                let by_label: Vec<&Map<String, Value>> = rows.iter().filter(|r| s(r, "aaa_label") == *label).collect();
                let by_ip: Vec<&Map<String, Value>> = rows.iter().filter(|r| format!("{}, {}", s(r, "aaa_ipv4"), s(r, "aaa_ipv6")).split(", ").any(|a| a == h.address)).collect();
                let by_name: Vec<&Map<String, Value>> = rows.iter().filter(|r| !facts_host.is_empty() && facts_host != "localhost" && s(r, "hostname") == facts_host).collect();
                [by_label, by_ip, by_name].into_iter().find(|v| v.len() == 1).map(|v| v[0])
            }
            None => {
                let me = swrap_core::sys::hostname();
                let v: Vec<&Map<String, Value>> = rows.iter().filter(|r| s(r, "hostname") == me || s(r, "name") == me).collect();
                (v.len() == 1).then(|| v[0])
            }
        };
        let Some(row) = found else {
            if let Some(h) = host {
                match create_asset(d, &c, h, &mut desc) {
                    Ok(Some((id, auto))) => {
                        st.assets.insert(label.clone(), id);
                        st.auto_projects.insert(label.clone(), auto);
                        report.push(format!("{label}: created asset {id}"));
                        d.audit_event("", "table.asset_created", label, "", "ok", json!({"asset": id}), "");
                    }
                    Ok(None) => {
                        missing.push(label.clone());
                        report.push(format!("{label}: no asset in table (not created: no good inventory yet, or no asset-create token)"));
                    }
                    Err(e) => {
                        missing.push(label.clone());
                        report.push(format!("{label}: no asset in table; creating it failed: {e:#}"));
                    }
                }
            }
            continue;
        };
        let id = row.get("_id").and_then(Value::as_i64).ok_or_else(|| anyhow!("asset row without _id"))?;
        st.assets.insert(label.clone(), id);
        let repos = if host.is_some() {
            repos_of(&std::fs::read_to_string(d.paths.state().join("hosts").join(label).join("gitrepos.tsv")).unwrap_or_default())
        } else {
            repos_of(&local_git_scan())
        };
        let detected = project_lines(&c, &repos, &mut desc);
        let prev = st.auto_projects.get(label).cloned().unwrap_or_default();
        let (projects, auto) = merge_projects(&s(row, "aaa_running_projects"), &prev, &detected);
        let mut want = Map::new();
        if host.is_some() && s(row, "aaa_label") != *label {
            want.insert("aaa_label".into(), json!(label));
        }
        if row.get("aaa_asimilated").and_then(Value::as_bool) != Some(true) {
            want.insert("aaa_asimilated".into(), json!(true));
        }
        if projects.trim() != s(row, "aaa_running_projects").trim() {
            want.insert("aaa_running_projects".into(), json!(projects));
        }
        st.auto_projects.insert(label.clone(), auto);
        if !want.is_empty() {
            updates.push((id, want, label.clone()));
        }
    }
    // Assets of hosts that left swrap are no longer assimilated.
    let labels: BTreeSet<&str> = hosts.iter().map(|h| h.label.as_str()).collect();
    for r in &rows {
        let l = s(r, "aaa_label");
        if !l.is_empty() && !labels.contains(l.as_str()) && r.get("aaa_asimilated").and_then(Value::as_bool) == Some(true) {
            if let Some(id) = r.get("_id").and_then(Value::as_i64) {
                let mut m = Map::new();
                m.insert("aaa_asimilated".into(), json!(false));
                updates.push((id, m, l.clone()));
            }
        }
    }
    save_state(d, &st);
    drop(_g);
    for (id, mut fields, label) in updates {
        let names: Vec<String> = fields.keys().cloned().collect();
        fields.insert("id".into(), json!(id));
        match post(d, &format!("/api/form-update/{}", c.asset_update_form), &utok, &Value::Object(fields))? {
            (200, _) => report.push(format!("{label} (asset {id}): updated {}", names.join(", "))),
            (code, body) => report.push(format!("{label} (asset {id}): update refused ({code}): {}", cut(&body, 160))),
        }
    }
    d.audit_event("", "table.sync", "assets", "", "ok", json!({"report": report}), "");
    Ok((report.join("\n"), missing))
}

/// A new asset for an enrolled host table does not know, from its inventory (`None` until
/// there is a good inventory, or without the asset-create token).
fn create_asset(d: &Daemon, c: &TableCfg, h: &Host, desc: &mut dyn FnMut(&str) -> Option<String>) -> Result<Option<(i64, Vec<String>)>> {
    let Some(tok) = token(d, "asset-create")? else { return Ok(None) };
    let dir = d.paths.state().join("hosts").join(&h.label);
    let f: toml::Value = match std::fs::read_to_string(dir.join("facts.toml")).ok().and_then(|t| toml::from_str(&t).ok()) {
        Some(f) => f,
        None => return Ok(None),
    };
    let g = |k: &str| f.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    if !g("inventory_status").starts_with("ok") {
        return Ok(None);
    }
    let repos = repos_of(&std::fs::read_to_string(dir.join("gitrepos.tsv")).unwrap_or_default());
    let auto: Vec<String> = project_lines(c, &repos, desc).into_iter().map(|(_, l)| l).collect();
    let hostname = Some(g("hostname")).filter(|n| !n.is_empty() && n != "localhost").unwrap_or_else(|| h.address.clone());
    let enrolled = h.enrolled.get(..10).unwrap_or(&h.enrolled).to_string();
    let mut body = json!({
        "name": h.label,
        "hostname": hostname,
        "description": format!("Enrolled in swrap (AAA) as {} ({}, {} network){}. Created by swrap from its inventory.", h.label, h.address, match h.network { swrap_core::config::Route::Edge => "edge", _ => "core" }, if enrolled.is_empty() { String::new() } else { format!(" on {enrolled}") }),
        "os": g("os"),
        "status": "running",
        "type": if g("virt").is_empty() || g("virt") == "none" { "server" } else { "virtualServer" },
        "health": "healthy",
        "aaa_label": h.label,
        "aaa_asimilated": true,
        "aaa_ipv4": g("ipv4"),
        "aaa_ipv6": g("ipv6"),
        "aaa_running_projects": auto.join("\n"),
    });
    if let Ok(t) = g("installed").parse::<jiff::Timestamp>() {
        body["running_since"] = json!(t.as_second());
    }
    let (code, resp) = post(d, &format!("/api/form/{}", c.asset_create_form), &tok, &body)?;
    if code != 200 {
        bail!("table answered {code}: {}", cut(&resp, 200));
    }
    let id = serde_json::from_str::<Value>(&resp).ok().and_then(|v| v["entry_id"].as_i64()).ok_or_else(|| anyhow!("no entry id in table's answer"))?;
    Ok(Some((id, auto)))
}

/// The inventory's git scan, run on this node (the core is no inventory target).
fn local_git_scan() -> String {
    std::process::Command::new("bash").arg("-c").arg(crate::inventory::GIT_SCAN).output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default()
}

/// The asset id of `label` and whether swrap may deploy the endpoint agent there by itself now
/// (on, admin login stored, not tried within a day); marks the attempt.
fn agent_turn(d: &Daemon, label: &str) -> Option<i64> {
    let c = cfg(d);
    if !c.agent_auto || !token_path(d, "admin").exists() {
        return None;
    }
    let _g = STATE.lock().unwrap_or_else(|p| p.into_inner());
    let mut st = load_state(d);
    let aid = *st.assets.get(label)?;
    let t = now().as_second();
    if st.agent_tries.get(label).is_some_and(|l| t - l < 86400) {
        return None;
    }
    st.agent_tries.insert(label.to_string(), t);
    save_state(d, &st);
    Some(aid)
}

/// After an inventory: assets, then the hosts' actionable conditions, then send tickets. Hosts
/// without the endpoint agent get it first, on a thread of their own (the inventory does not
/// wait); their conditions follow when that is done.
pub fn after_inventory(d: &Arc<Daemon>) {
    let missing = match sync_assets(d) {
        Ok((_, m)) => Some(m),
        Err(e) => {
            eprintln!("swrapd: table sync: {e:#}");
            None
        }
    };
    let mut later: Vec<(Host, i64, Vec<Condition>)> = vec![];
    for h in Host::all(&d.paths).unwrap_or_default().into_iter().filter(|h| h.state == HostState::Active) {
        let mut conds = crate::inventory::conditions(d, &h.label);
        if conds.iter().any(|c| c.kind == "agent") {
            if let Some(aid) = agent_turn(d, &h.label) {
                later.push((h, aid, conds));
                continue;
            }
        }
        if missing.as_ref().is_some_and(|m| m.contains(&h.label)) {
            conds.push(Condition {
                kind: "no-asset",
                summary: "no asset record in table".into(),
                detail: format!("{} is enrolled in swrap ({}), but table has no asset for it (matched by aaa_label, IP address or hostname), and swrap could not create one (see `swrap table sync`). Create it, or set the asset-create token (`swrap table token asset-create`); the next inventory links them.", h.label, h.address),
            });
        }
        host_conditions(d, &h.label, conds);
    }
    let _ = flush(d);
    if later.is_empty() {
        return;
    }
    let d = d.clone();
    let rt = tokio::runtime::Handle::try_current().ok();
    std::thread::spawn(move || {
        let _e = rt.as_ref().map(|r| r.enter());
        for (h, aid, mut conds) in later {
            match crate::eagent::deploy(&d, "swrap", &h, aid, &Console::null()) {
                Ok(_) => conds.retain(|c| c.kind != "agent"),
                Err(e) => {
                    eprintln!("swrapd: endpoint agent on {}: {e:#}", h.label);
                    if let Some(c) = conds.iter_mut().find(|c| c.kind == "agent") {
                        c.detail += &format!("\n\nswrap tried to deploy it and failed: {e:#}");
                    }
                }
            }
            host_conditions(&d, &h.label, conds);
        }
        let _ = flush(&d);
    });
}

// ---------------------------------------------------------------- admin

/// `swrap table status | token <name> | admin-password | agent <label> | sync | test-ticket | set <key> <value>`
pub fn admin(d: &Arc<Daemon>, c: &Caller, argv: &[String], stdin: Option<zeroize::Zeroizing<String>>, con: &Console) -> Result<Resp> {
    c.require_admin()?;
    let a: Vec<&str> = argv.iter().skip(1).map(String::as_str).collect();
    match a.as_slice() {
        [] | ["status"] => {
            let c2 = cfg(d);
            let st = load_state(d);
            let mut t = format!("table {} · ticket form {} · asset forms {} / {} / {}\n", c2.endpoint, c2.ticket_form, c2.asset_read_form, c2.asset_update_form, c2.asset_create_form);
            for w in TOKENS {
                t += &format!("  token {w}: {}\n", if token_path(d, w).exists() { "set (vault)" } else { "NOT SET" });
            }
            t += &format!("  admin login {}: {}\n", c2.admin_user, if token_path(d, "admin").exists() { "password set (vault)" } else { "NOT SET" });
            t += &format!(
                "  endpoint agent: {} · hosts reach table at {} · edge hosts at {}\n",
                if c2.agent_auto { "deployed by swrap where missing" } else { "automatic deployment off" },
                if c2.agent_endpoint.is_empty() { &c2.endpoint } else { &c2.agent_endpoint },
                if c2.agent_endpoint_edge.is_empty() { "(not set: no automatic agent)" } else { &c2.agent_endpoint_edge }
            );
            t += &format!("  queued tickets: {} · open host conditions: {} · assets known: {}\n", st.queue.len(), st.open.len(), st.assets.len());
            for (k, since) in &st.open {
                t += &format!("    {k} since {since}\n");
            }
            Ok(Resp::text(t))
        }
        ["token", which] if TOKENS.contains(which) => {
            let v = stdin.ok_or_else(|| anyhow!("the token is read from stdin"))?;
            let v = v.trim();
            if v.len() < 16 || v.contains(char::is_whitespace) {
                bail!("that does not look like a form token");
            }
            let p = token_path(d, which);
            d.with_dek(|dek| swrap_vault::Vault::new(&d.paths, d.owner()).put(dek, &p, &format!("table-{which}"), v.as_bytes()))?;
            d.audit_event(&c.name, "table.token", which, "", "ok", json!({}), "");
            Ok(Resp::text(format!("{which} token stored in the vault\n")))
        }
        ["admin-password"] => {
            let v = stdin.ok_or_else(|| anyhow!("the password is read from stdin"))?;
            let v = v.trim_end_matches(['\r', '\n']);
            if v.is_empty() || v.contains('\n') {
                bail!("give the password on one line");
            }
            let c2 = cfg(d);
            check_admin(&c2, &c2.admin_user, v).context("not stored")?;
            let p = token_path(d, "admin");
            d.with_dek(|dek| swrap_vault::Vault::new(&d.paths, d.owner()).put(dek, &p, "table-admin", v.as_bytes()))?;
            d.audit_event(&c.name, "table.admin_password", &c2.admin_user, "", "ok", json!({}), "");
            Ok(Resp::text(format!("{} is a table admin; its password is stored in the vault\n", c2.admin_user)))
        }
        ["agent", label] => {
            let h = Host::all(&d.paths)?.into_iter().find(|h| h.label == *label && h.state == HostState::Active).ok_or_else(|| anyhow!("no active host {label}"))?;
            let known = load_state(d).assets.get(*label).copied();
            let aid = match known {
                Some(id) => id,
                None => {
                    sync_assets(d)?;
                    load_state(d).assets.get(*label).copied().ok_or_else(|| anyhow!("{label} has no asset in table yet (see `swrap table sync`)"))?
                }
            };
            Ok(Resp::text(crate::eagent::deploy(d, &c.name, &h, aid, con)?))
        }
        ["sync"] => {
            let (r, _) = sync_assets(d)?;
            Ok(Resp::text(if r.is_empty() { "assets up to date\n".to_string() } else { r + "\n" }))
        }
        ["test-ticket"] => {
            {
                let _g = STATE.lock().unwrap_or_else(|p| p.into_inner());
                let mut st = load_state(d);
                st.queue.push(Ticket {
                    short: "AAA: test ticket from swrap (can be closed)".into(),
                    description: "swrap on the AAA core can create tickets. This one tests the connection; nothing needs doing.".into(),
                    worknotes: format!("Sent by {} at {}", c.name, fmt_utc_secs(now())),
                    label: "core".into(),
                });
                save_state(d, &st);
            }
            let n = flush(d)?;
            Ok(Resp::text(if n > 0 { "test ticket created\n" } else { "not sent yet (see `swrap table status` and the audit log)\n" }))
        }
        ["set", key, value] => {
            let _g = d.config_lock.lock().unwrap();
            let mut v = serde_json::to_value(cfg(d))?;
            let cur = v.get(*key).ok_or_else(|| anyhow!("unknown setting {key}"))?;
            v[*key] = match cur {
                Value::Number(_) => json!(value.parse::<u64>().context("a number")?),
                Value::Bool(_) => json!(match *value { "true" | "on" | "yes" => true, "false" | "off" | "no" => false, _ => bail!("{key} is on or off") }),
                Value::Array(_) => json!(value.split(',').map(str::trim).filter(|s| !s.is_empty()).collect::<Vec<_>>()),
                _ => json!(value),
            };
            let tc: TableCfg = serde_json::from_value(v)?;
            swrap_core::atomic::write(&cfg_path(d), toml::to_string_pretty(&tc)?.as_bytes(), 0o640, d.owner())?;
            d.commit(&format!("table: {key} = {value} ({})", c.name))?;
            Ok(Resp::text(format!("{key} set\n")))
        }
        _ => bail!("usage: swrap table status | token <ticket|asset-read|asset-update|asset-create> (stdin) | admin-password (stdin) | agent <label> | sync | test-ticket | set <key> <value>"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_names_and_links() {
        let h = vec!["git.example.com".to_string()];
        assert_eq!(git_name("git@git.example.com:/srv/git/newsagent.git", &h).as_deref(), Some("newsagent"));
        assert_eq!(git_name("http://git.example.com/git/table/", &h).as_deref(), Some("table"));
        assert_eq!(git_name("ssh://root@git.example.com/srv/git/x.git", &h).as_deref(), Some("x"));
        assert_eq!(git_name("https://github.com/a/b.git", &h), None);
        let h2 = vec!["swrap-git".to_string()];
        assert_eq!(git_name("swrap-git:/srv/git/swrap.git", &h2).as_deref(), Some("swrap"));
        assert_eq!(git_name("swrap-git:/srv/git/swrap.git", &TableCfg::default().git_hosts), None);
        assert_eq!(web_link("git@github.com:anomalyco/opencode.git"), "https://github.com/anomalyco/opencode");
    }

    #[test]
    fn projects_merge_keeps_hand_written_lines() {
        let existing = "table production (:88) - http://git.example.com/git/table/\nSamba shares\nold - http://git.example.com/git/old/";
        let prev = vec!["old - http://git.example.com/git/old/".to_string()];
        let detected = vec![
            ("http://git.example.com/git/table/".to_string(), "table (source) - http://git.example.com/git/table/".to_string()),
            ("http://git.example.com/git/new/".to_string(), "new - http://git.example.com/git/new/".to_string()),
        ];
        let (text, auto) = merge_projects(existing, &prev, &detected);
        assert_eq!(text, "table production (:88) - http://git.example.com/git/table/\nSamba shares\nnew - http://git.example.com/git/new/");
        assert_eq!(auto, vec!["new - http://git.example.com/git/new/".to_string()]);
    }
}
