//! The ticket worker: tickets in table assigned to `claude` are worked by swai, one recorded,
//! unattended session per ticket (the configured user's AI grants and Claude login). It
//! replaces an older ticket worker, whose forms it can retire.
//!
//! * **Scope**: a ticket whose affected asset is a swrap host gets a session on that host alone
//!   (with the user's recordings); any other ticket an aaa session (all the user's AI hosts). A
//!   host the user has no AI access to gets no session: the ticket goes to the human, with the
//!   grant it needs.
//! * **When**: a ticket a person assigns to claude is worked within a minute or two (swrapd
//!   looks every minute, `assigned_now`); swrap's own new tickets, assigned to claude when they
//!   are raised, wait for the night.
//!
//! * **Setup** (`swai tickets setup`, admin) uses the table admin login from the vault: swrap's
//!   own read and update forms for tickets (secrets into the vault), the table user ids of
//!   `claude` and the human, the ticket statuses, `assignee` on swrap's create form (so its own
//!   tickets go to claude), and the old worker's forms (`retire_forms`) deactivated.
//! * **Nightly** at `at` (display zone): the pending tickets assigned to claude, oldest first, up
//!   to `max_tickets`, one session after the other. A session ends itself after its
//!   `ticket_result` (else swrapd ends it 30 s later); one that stops without a result is reminded
//!   twice, and swrapd ends it after `session_limit` or `idle_limit` (no tool call in flight,
//!   nothing recorded).
//! * **Tickets** are fixes (diagnose, then the smallest allowed change, verified) or
//!   investigations (discovery only, anywhere the user's AI grants reach, findings reported).
//! * **Outcomes**: resolved (status `resolved_status`, with a solution), report (an
//!   investigation's findings, to the human), assign (to the human: anything that needs more
//!   access or a decision), retry (stays with claude). Nights without a result count as tries;
//!   after `retries` the ticket goes to the human. Worknotes are appended, never replaced.

use crate::daemon::{Caller, Console, Daemon};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use swrap_core::api::Resp;
use swrap_core::config::{Host, User};
use swrap_core::time::{fmt_utc_secs, now, IsoDuration};

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct TicketsCfg {
    /// The worker: the nightly run and `assigned_now` (manual `swai tickets run` works either way).
    pub enabled: bool,
    /// Tickets a person assigns to claude are worked at once, not at night.
    pub assigned_now: bool,
    /// The AAA user whose AI grants and Claude login the sessions run with.
    pub user: String,
    pub backend: String,
    pub model: String,
    pub effort: String,
    /// Local time (display zone) of the nightly start, HH:MM; it may start up to `window` later
    /// (the vault was sealed, swrapd restarted).
    pub at: String,
    pub window: String,
    pub max_tickets: usize,
    /// One ticket's sessions (handoffs included) end after this, and after this long without
    /// any activity.
    pub session_limit: String,
    pub idle_limit: String,
    /// Nights without a result (or with `retry`) before the ticket goes to the human.
    pub retries: u32,
    /// Hosts the worker may reboot (the `reboot` tool); none by default.
    pub reboot: Vec<String>,
    /// swrap's own new tickets are assigned to claude (set by setup once the create form allows it).
    pub assign_new: bool,
    /// table usernames and their ids (ids filled in by setup).
    pub claude_name: String,
    pub human_name: String,
    pub claude_id: i64,
    pub human_id: i64,
    /// Ticket statuses that mean "waiting for claude".
    pub pending: Vec<String>,
    pub assigned_status: String,
    pub resolved_status: String,
    /// All statuses table offers (from setup, for reference).
    pub statuses: Vec<String>,
    pub read_form: String,
    pub update_form: String,
    /// Forms of the previous worker, deactivated by setup.
    pub retire_forms: Vec<String>,
}

impl Default for TicketsCfg {
    fn default() -> Self {
        TicketsCfg {
            enabled: false,
            assigned_now: true,
            user: "admin".into(),
            backend: "claude".into(),
            model: "claude-opus-5-5".into(),
            effort: "high".into(),
            at: "02:30".into(),
            window: "PT4H".into(),
            max_tickets: 10,
            session_limit: "PT2H".into(),
            idle_limit: "PT20M".into(),
            retries: 3,
            reboot: vec![],
            assign_new: false,
            claude_name: "claude".into(),
            human_name: "admin".into(),
            claude_id: 0,
            human_id: 0,
            pending: vec!["created".into(), "assigned".into(), "in-progress".into()],
            assigned_status: "assigned".into(),
            resolved_status: String::new(),
            statuses: vec![],
            read_form: "aaa_read_tickets".into(),
            update_form: "aaa_update_tickets".into(),
            retire_forms: vec!["claude_read_tickets".into(), "claude_update_tickets".into()],
        }
    }
}

fn cfg_path(d: &Daemon) -> PathBuf {
    d.paths.config().join("tickets.toml")
}

pub fn cfg(d: &Daemon) -> TicketsCfg {
    std::fs::read_to_string(cfg_path(d)).ok().and_then(|s| toml::from_str(&s).ok()).unwrap_or_default()
}

fn save_cfg(d: &Daemon, c: &TicketsCfg, msg: &str) -> Result<()> {
    swrap_core::atomic::write(&cfg_path(d), toml::to_string_pretty(c)?.as_bytes(), 0o640, d.owner())?;
    d.commit(msg)?;
    Ok(())
}

fn secs(iso: &str, default: u64) -> i64 {
    IsoDuration::parse(iso).ok().and_then(|x| x.exact()).map(|x| x.as_secs()).unwrap_or(default) as i64
}

// ---------------------------------------------------------------- state

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct State {
    /// The night (local date of its start) last run by the schedule.
    night: String,
    /// Tickets (table entry ids) still to work in this run, and until when new ones may start
    /// (unix seconds: the night's window; a manual run gets as long).
    queue: Vec<i64>,
    deadline: i64,
    /// After a session failed to start: not before this (unix seconds).
    retry_at: i64,
    current: Option<Current>,
    /// Ticket id → nights without a result (or `retry`).
    tries: BTreeMap<String, u32>,
    /// The tickets waiting for claude at the last look (None: never looked); one that is new
    /// since then was assigned by a person, unless it is in `nightly`.
    seen: Option<Vec<i64>>,
    /// swrap's own new tickets: they wait for the night while they stay with claude.
    nightly: Vec<i64>,
    /// The last results, newest last.
    log: Vec<Value>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(default)]
struct Current {
    id: i64,
    number: String,
    short: String,
    /// The session working on it now (a handoff successor replaces it), and all of them.
    session: String,
    sessions: Vec<String>,
    started: i64,
    /// Set by `ticket_result`.
    outcome: String,
    done_at: i64,
    /// Why swrap ended the session (time limit, idle).
    ended: String,
}

static STATE: Mutex<()> = Mutex::new(());
/// Tool calls of ticket sessions: in flight, and when the last one ended (unix seconds). A long
/// update or a reboot is not idleness.
static TOOLS: Mutex<BTreeMap<String, (usize, i64)>> = Mutex::new(BTreeMap::new());

/// Marks a ticket session's tool call in flight while it lives.
pub struct ToolGuard(String);

impl ToolGuard {
    pub fn new(session: &str) -> Self {
        TOOLS.lock().unwrap_or_else(|p| p.into_inner()).entry(session.to_string()).or_default().0 += 1;
        ToolGuard(session.to_string())
    }
}

impl Drop for ToolGuard {
    fn drop(&mut self) {
        if let Some(e) = TOOLS.lock().unwrap_or_else(|p| p.into_inner()).get_mut(&self.0) {
            e.0 = e.0.saturating_sub(1);
            e.1 = now().as_second();
        }
    }
}

/// Whether a tool call of `session` runs now, and when the last one ended (0: none yet).
fn tool_state(session: &str) -> (bool, i64) {
    TOOLS.lock().unwrap_or_else(|p| p.into_inner()).get(session).map(|e| (e.0 > 0, e.1)).unwrap_or((false, 0))
}
/// One step of the runner at a time (the loop, `swai tickets run`).
static RUN: Mutex<()> = Mutex::new(());

fn state_path(d: &Daemon) -> PathBuf {
    d.paths.index().join("tickets.json")
}

fn load_state(d: &Daemon) -> State {
    std::fs::read_to_string(state_path(d)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn save_state(d: &Daemon, st: &State) {
    let _ = swrap_core::atomic::write(&state_path(d), serde_json::to_string_pretty(st).unwrap_or_default().as_bytes(), 0o600, d.owner());
}

fn with_state<T>(d: &Daemon, f: impl FnOnce(&mut State) -> T) -> T {
    let _g = STATE.lock().unwrap_or_else(|p| p.into_inner());
    let mut st = load_state(d);
    let r = f(&mut st);
    save_state(d, &st);
    r
}

fn log_result(st: &mut State, cur: &Current, outcome: &str, note: &str) {
    st.log.push(json!({"at": fmt_utc_secs(now()), "ticket": cur.id, "number": cur.number, "short": cur.short, "outcome": outcome, "sessions": cur.sessions, "note": note}));
    let n = st.log.len();
    if n > 200 {
        st.log.drain(..n - 200);
    }
}

// ---------------------------------------------------------------- tickets in table

#[derive(Clone, Default, Debug)]
pub struct Ticket {
    pub id: i64,
    pub number: String,
    pub short: String,
    pub description: String,
    pub status: String,
    pub assignee: i64,
    pub worknotes: String,
    pub solution: String,
    pub asset: Option<i64>,
    pub due: String,
    current: bool,
}

/// A ref column's value: an id, `{"id": …}`, or its text.
fn ref_id(v: &Value) -> Option<i64> {
    v.as_i64().or_else(|| v["id"].as_i64()).or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

fn text(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        o => o.to_string(),
    }
}

fn parse_ticket(r: &Value) -> Ticket {
    Ticket {
        id: r["_id"].as_i64().or_else(|| r["entry_id"].as_i64()).unwrap_or(0),
        number: text(&r["number"]),
        short: text(&r["short_description"]),
        description: text(&r["description"]),
        status: text(&r["status"]),
        assignee: ref_id(&r["assignee"]).unwrap_or(0),
        worknotes: text(&r["worknotes"]),
        solution: text(&r["solution"]),
        asset: ref_id(&r["affected_asset"]),
        due: r["due_by_date"].as_i64().filter(|t| *t > 0).and_then(|t| jiff::Timestamp::from_second(t).ok()).map(fmt_utc_secs).unwrap_or_default(),
        current: r["_cur"].as_bool().unwrap_or(true) && r["_act"].as_bool().unwrap_or(true),
    }
}

impl Ticket {
    fn name(&self) -> String {
        if self.number.is_empty() { format!("#{}", self.id) } else { self.number.clone() }
    }
}

fn read_token(d: &Daemon) -> Result<zeroize::Zeroizing<String>> {
    crate::table::token(d, "ticket-read")?.ok_or_else(|| anyhow!("the ticket forms are not set up (swai tickets setup)"))
}

/// Tickets assigned to claude that wait for it, oldest first.
pub fn pending(d: &Daemon, c: &TicketsCfg) -> Result<Vec<Ticket>> {
    if c.claude_id <= 0 {
        bail!("claude's table user id is unknown (swai tickets setup)");
    }
    let tok = read_token(d)?;
    let v = crate::table::get(d, &format!("/api/form-read/{}?q={}&limit=500", c.read_form, c.claude_id), &tok)?;
    let mut out: Vec<Ticket> = v["rows"].as_array().into_iter().flatten().map(parse_ticket).filter(|t| t.current && t.assignee == c.claude_id && c.pending.contains(&t.status)).collect();
    out.sort_by_key(|t| t.id);
    Ok(out)
}

fn read_one(d: &Daemon, c: &TicketsCfg, id: i64) -> Result<Ticket> {
    let tok = read_token(d)?;
    let v = crate::table::get(d, &format!("/api/form-read/{}?id={id}", c.read_form), &tok)?;
    Ok(parse_ticket(&v["row"]))
}

/// All current tickets (newest 1000), for `adopt` and `run <number>`.
fn read_all(d: &Daemon, c: &TicketsCfg) -> Result<Vec<Ticket>> {
    let tok = read_token(d)?;
    let v = crate::table::get(d, &format!("/api/form-read/{}?limit=1000", c.read_form), &tok)?;
    Ok(v["rows"].as_array().into_iter().flatten().map(parse_ticket).filter(|t| t.current).collect())
}

fn update(d: &Daemon, c: &TicketsCfg, id: i64, fields: Map<String, Value>) -> Result<()> {
    let tok = crate::table::token(d, "ticket-update")?.ok_or_else(|| anyhow!("the ticket forms are not set up (swai tickets setup)"))?;
    let mut body = Value::Object(fields);
    body["id"] = json!(id);
    let (st, resp) = crate::table::post(d, &format!("/api/form-update/{}", c.update_form), &tok, &body)?;
    if st != 200 {
        bail!("table refused the ticket update ({st}): {}", resp.chars().take(300).collect::<String>());
    }
    Ok(())
}

/// Worknotes belong to people too: entries are appended, the text above stays as it is.
fn appended(old: &str, entry: &str) -> String {
    let old = old.trim_end();
    if old.is_empty() { entry.to_string() } else { format!("{old}\n\n{entry}") }
}

fn note_ticket(d: &Daemon, c: &TicketsCfg, id: i64, entry: &str, extra: Map<String, Value>) -> Result<()> {
    let t = read_one(d, c, id)?;
    let mut f = extra;
    f.insert("worknotes".into(), json!(appended(&t.worknotes, entry)));
    update(d, c, id, f)
}

// ---------------------------------------------------------------- setup (table admin login)

fn lookup_user(s: &crate::table::AdminSession, name: &str) -> Result<i64> {
    let v = s.get(&format!("/api/lookup/users?q={}", urlencode(name)))?;
    let rows = v.as_array().cloned().or_else(|| v["rows"].as_array().cloned()).unwrap_or_default();
    rows.iter()
        .find(|r| r["label"].as_str().is_some_and(|l| l.eq_ignore_ascii_case(name)))
        .and_then(|r| r["id"].as_i64())
        .ok_or_else(|| anyhow!("table has no user {name:?}"))
}

fn urlencode(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

/// Create the form, or align an existing one (fields, search field, active) and regenerate its
/// secret. Returns the secret.
fn ensure_form(s: &crate::table::AdminSession, forms: &[Value], spec: &Value) -> Result<String> {
    let name = spec["name"].as_str().unwrap_or("");
    let secret = |b: &str| serde_json::from_str::<Value>(b).ok().and_then(|v| v["secret"].as_str().map(String::from)).ok_or_else(|| anyhow!("no secret in table's answer for {name}"));
    let Some(f) = forms.iter().find(|f| f["name"] == spec["name"]) else {
        let (st, b) = s.send("POST", "/api/admin/forms", spec)?;
        if st != 200 {
            bail!("creating form {name} failed ({st}): {}", b.chars().take(300).collect::<String>());
        }
        return secret(&b);
    };
    if f["ftype"] != spec["ftype"] || f["table"] != spec["table"] || !f["bound_id"].is_null() {
        bail!("form {name} exists as {} on {} (record {}), not what swrap needs; rename or fix it in table", f["ftype"], f["table"], f["bound_id"]);
    }
    let id = f["id"].as_i64().unwrap_or(0);
    let mut upd = json!({"fields": spec["fields"], "active": true});
    if spec["ftype"] == "api_read" {
        upd["search_col"] = spec["search_col"].clone();
    }
    let (st, b) = s.send("PUT", &format!("/api/admin/form/{id}"), &upd)?;
    if st != 200 {
        bail!("aligning form {name} failed ({st}): {}", b.chars().take(300).collect::<String>());
    }
    let (st, b) = s.send("POST", &format!("/api/admin/form/{id}/secret"), &json!({}))?;
    if st != 200 {
        bail!("regenerating the secret of {name} failed ({st}): {}", b.chars().take(300).collect::<String>());
    }
    secret(&b)
}

fn setup(d: &Arc<Daemon>, who: &str) -> Result<String> {
    if d.is_sealed() {
        bail!("the vault is sealed");
    }
    let mut c = cfg(d);
    let tcfg = crate::table::cfg(d);
    let s = crate::table::AdminSession::open(d)?;
    let mut out = String::new();

    // The tickets table: columns and statuses.
    let meta = s.get("/api/meta/tickets").context("the tickets table")?;
    let cols: Vec<Value> = meta["cols"].as_array().cloned().unwrap_or_default();
    let has = |n: &str| cols.iter().any(|x| x["name"] == n);
    for need in ["short_description", "description", "status", "assignee", "worknotes", "solution"] {
        if !has(need) {
            bail!("the tickets table has no column {need}");
        }
    }
    let statuses: Vec<String> = cols.iter().find(|x| x["name"] == "status").and_then(|x| x["options"].as_array()).map(|a| a.iter().filter_map(|o| o.as_str().map(String::from)).collect()).unwrap_or_default();
    if !statuses.is_empty() {
        if !statuses.contains(&c.resolved_status) {
            c.resolved_status = ["resolved", "closed", "done", "solved"].iter().find(|s| statuses.iter().any(|x| x == *s)).map(|s| s.to_string()).unwrap_or_default();
        }
        if !statuses.contains(&c.assigned_status) {
            c.assigned_status = statuses.iter().find(|s| s.contains("assign")).cloned().unwrap_or_else(|| c.assigned_status.clone());
        }
        c.pending.retain(|p| statuses.contains(p));
    }
    if c.resolved_status.is_empty() {
        bail!("no status for resolved tickets among {statuses:?}; set it: swai tickets set resolved_status <status>");
    }
    c.statuses = statuses.clone();
    let rules: Vec<String> = meta["req_rules"].as_array().into_iter().flatten().map(|r| format!("{}={} needs {}", r["col"].as_str().unwrap_or(""), r["value"].as_str().unwrap_or(""), r["require"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(",")).unwrap_or_default())).collect();
    out += &format!("tickets: statuses {} · pending {} · resolved → {:?} · to a person → {:?}{}\n", statuses.join(", "), c.pending.join(","), c.resolved_status, c.assigned_status, if rules.is_empty() { String::new() } else { format!(" · rules: {}", rules.join("; ")) });

    // The two people.
    c.claude_id = lookup_user(&s, &c.claude_name)?;
    c.human_id = lookup_user(&s, &c.human_name)?;
    out += &format!("table users: {} #{} (works the tickets), {} #{} (gets what needs a person)\n", c.claude_name, c.claude_id, c.human_name, c.human_id);

    // swrap's forms.
    let forms: Vec<Value> = s.get("/api/admin/forms")?["forms"].as_array().cloned().unwrap_or_default();
    let mut read_cols = vec!["number", "short_description", "description", "status", "assignee", "due_by_date", "worknotes", "solution", "affected_asset"];
    read_cols.retain(|x| has(x));
    let read = json!({"name": c.read_form, "ftype": "api_read", "table": "tickets", "search_col": "assignee", "fields": read_cols.iter().map(|x| json!({"column": x})).collect::<Vec<_>>()});
    let upd_fields: Vec<Value> = ["status", "assignee", "worknotes", "solution"].iter().map(|x| json!({"column": x})).collect();
    let upd = json!({"name": c.update_form, "ftype": "api_update", "table": "tickets", "fields": upd_fields});
    let rs = zeroize::Zeroizing::new(ensure_form(&s, &forms, &read)?);
    crate::table::store_token(d, "ticket-read", &rs)?;
    let us = zeroize::Zeroizing::new(ensure_form(&s, &forms, &upd)?);
    crate::table::store_token(d, "ticket-update", &us)?;
    out += &format!("forms: {} (read, by assignee) and {} (status, assignee, worknotes, solution); secrets in the vault\n", c.read_form, c.update_form);

    // swrap's own tickets go to claude: the create form must take an assignee.
    match forms.iter().find(|f| f["name"] == json!(tcfg.ticket_form)) {
        Some(f) => {
            let mut fields = f["fields"].as_array().cloned().unwrap_or_default();
            if !fields.iter().any(|x| x["column"] == "assignee") {
                fields.push(json!({"column": "assignee"}));
                let (st, b) = s.send("PUT", &format!("/api/admin/form/{}", f["id"].as_i64().unwrap_or(0)), &json!({"fields": fields}))?;
                if st != 200 {
                    bail!("adding assignee to {} failed ({st}): {}", tcfg.ticket_form, b.chars().take(300).collect::<String>());
                }
            }
            c.assign_new = true;
            out += &format!("swrap's new tickets ({}) are assigned to {}\n", tcfg.ticket_form, c.claude_name);
        }
        None => out += &format!("note: swrap's ticket form {} is not in table; its tickets stay unassigned\n", tcfg.ticket_form),
    }

    // The previous worker loses its forms.
    for name in &c.retire_forms {
        match forms.iter().find(|f| f["name"] == json!(name)) {
            Some(f) if f["active"] == true => {
                let (st, b) = s.send("PUT", &format!("/api/admin/form/{}", f["id"].as_i64().unwrap_or(0)), &json!({"active": false}))?;
                if st != 200 {
                    bail!("deactivating {name} failed ({st}): {}", b.chars().take(300).collect::<String>());
                }
                out += &format!("deactivated {name} (the old worker's form)\n");
            }
            Some(_) => out += &format!("{name}: already inactive\n"),
            None => {}
        }
    }
    drop(s);
    save_cfg(d, &c, &format!("swai tickets setup by {who}"))?;
    d.audit_event(who, "tickets.setup", "table", "", "ok", json!({"claude": c.claude_id, "human": c.human_id, "resolved": c.resolved_status, "forms": [c.read_form, c.update_form], "retired": c.retire_forms}), "");
    Ok(out)
}

/// Open tickets swrap raised that nobody took: to claude.
fn adopt(d: &Daemon, who: &str) -> Result<String> {
    let c = cfg(d);
    if c.claude_id <= 0 {
        bail!("run swai tickets setup first");
    }
    let mut out = String::new();
    let mut n = 0;
    for t in read_all(d, &c)? {
        let swraps = t.worknotes.contains("Raised by swrap");
        if !swraps || t.assignee != 0 || !c.pending.contains(&t.status) {
            continue;
        }
        let mut f = Map::new();
        f.insert("assignee".into(), json!(c.claude_id));
        if t.status == "created" && c.statuses.contains(&c.assigned_status) {
            f.insert("status".into(), json!(c.assigned_status));
        }
        update(d, &c, t.id, f)?;
        out += &format!("  {} {}\n", t.name(), t.short);
        n += 1;
    }
    d.audit_event(who, "tickets.adopt", "table", "", "ok", json!({"tickets": n}), "");
    Ok(format!("{n} open swrap ticket(s) assigned to {}\n{out}", c.claude_name))
}

// ---------------------------------------------------------------- prompts

/// The system prompt of a ticket session: on one `host` (the ticket's affected asset) or the
/// aaa target (`hosts`: the user's AI hosts, one per line).
pub fn system_prompt(d: &Daemon, user: &str, host: Option<&str>, hosts: &str, tz: &str) -> String {
    let c = cfg(d);
    let human = &c.human_name;
    let list = if hosts.is_empty() { "(none)\n".to_string() } else { hosts.to_string() };
    let (only, which, targets) = match host {
        Some(l) => (
            format!(" This session is for {l} alone, the ticket's affected asset."),
            "The host you may act on",
            format!("Host tools act on {l}; target is optional (\"account@{l}\" for another of your accounts there)"),
        ),
        None => (String::new(), "Hosts you may act on", "Host tools take target = \"label\" or \"account@label\"".to_string()),
    };
    let reboot = if c.reboot.is_empty() {
        format!("not allowed in this run: no host is on the reboot list, so a ticket that needs a reboot goes to {human}")
    } else {
        format!("only {}; it waits until the host is back and re-inventories it", c.reboot.join(", "))
    };
    format!(
        "You are swai, the ticket worker of swrap, an audited SSH jump host (AAA). You work one ticket from table (the asset and ticket database) that is assigned to claude, with {user}'s AI access.{only} \
         The run is unattended: nobody watches and nobody can answer questions. Every tool call and its complete output is recorded, and {human} reads your worknotes later.\n\n\
         {which} (label: accounts, first is the default; address; network; tags):\n{list}\n\
         {targets}: exec, read_file, write_file, edit_file; update (dnf upgrade --refresh of all packages or one, like swupdate, then a fresh inventory); \
         inventory (refresh swrap's inventory of a host and list its open conditions); reboot ({reboot}).\n\
         Records: sessions, search, transcript ({user}'s recordings). The ticket: ticket (as it is in table now) and ticket_result (how the ticket ends).\n\n\
         Two kinds of tickets:\n\
         - Fixes (most of them, e.g. the conditions swrap raises): diagnose first, read-only. Then fix with the smallest change that solves the ticket. Allowed changes: package updates with update; restarting or re-enabling a failed service; freeing disk space from caches, old journals and package caches; fixing a configuration file you understand, after a backup copy next to it.\n\
         - Investigations (the ticket asks you to check, find out or explain something: what causes a bug, why a service fails or is slow, whether something is set up right): discovery only, wherever the answer may be, on any host listed. \
         Logs (journalctl --no-pager, /var/log, application logs), service and process state, configuration, package versions and recent changes (rpm -qa --last, dnf history), disk and memory, network state and listening ports, timers and cron jobs, and {user}'s recordings (search, transcript) for what was done before. \
         Reproduce a problem only with commands that change nothing. Change nothing unless the ticket also asks for a fix and it is one of the allowed changes. \
         End with report: what you checked, the likely cause with its evidence (commands, log lines with their times), what you would do about it, and what you could not check and why.\n\n\
         Rules:\n\
         - Not yours: anything that needs an account, host, key or password not listed above; the AAA core itself (swrap's configuration, vault, grants, this run); firewalls and networks; starting, stopping or changing VMs and hardware; deleting user data; anything only a person can decide. \
         Do not look for a way around a missing permission. Assign the ticket to {human} (ticket_result outcome assign) and say exactly what is needed (the grant, the command to run, or the decision) and what you found.\n\
         - Reboots only with the reboot tool, never with exec.\n\
         - Never copy secrets (keys, passwords, tokens, private data) into worknotes; name the file or setting instead.\n\
         - Verify before you call a ticket resolved: re-check what the ticket describes; for conditions swrap raised (security fixes, reboot needed, unreachable, sudoers files, endpoint agent, no asset record) run inventory and confirm the condition is gone.\n\
         - End with exactly one ticket_result: resolved (solution: what you did and how you verified it), report (an investigation's findings, back to {human}), assign (to {human}: what is needed and why), or retry (only if a later night should work without anyone doing anything, e.g. the host was down for maintenance; say what to check then). \
         Its worknotes are appended to the ticket: findings, actions with swrap run ids, what is left. The session ends after ticket_result.\n\
         - exec is non-interactive (no TTY): no prompts, pagers or editors (-y, --no-pager). Few, purposeful tool calls. If a tool result says the budget is running out, call handoff with a complete briefing (the ticket number included).\n\
         Times are ISO 8601; write them in UTC (Z) in worknotes. Display zone {tz}."
    )
}

/// Other tickets waiting for claude on the same asset (a condition swrap raised again, older
/// tickets about it): one result can settle them too.
fn same_asset(c: &TicketsCfg, t: &Ticket, pending: &[Ticket]) -> Vec<Ticket> {
    match t.asset {
        Some(a) => pending.iter().filter(|x| x.id != t.id && x.asset == Some(a) && x.assignee == c.claude_id && c.pending.contains(&x.status)).cloned().collect(),
        None => vec![],
    }
}

fn first_prompt(d: &Daemon, c: &TicketsCfg, user: &User, t: &Ticket, tries: u32, others: &[Ticket]) -> String {
    let asset = match t.asset {
        None => "none".to_string(),
        Some(a) => match crate::table::label_of_asset(d, a) {
            Some(l) if l == "core" => format!("asset #{a}: the AAA core itself (swrap's node; not yours to change)"),
            Some(l) => match Host::load(&d.paths, &l) {
                Ok(h) => {
                    let accts = swrap_core::rbac::ai_accounts(user, &h, now());
                    if accts.is_empty() {
                        format!("asset #{a}: swrap host {l}, but you have no AI access to it")
                    } else {
                        format!("asset #{a}: swrap host {l} (you may act on it as {})", accts.join(", "))
                    }
                }
                Err(_) => format!("asset #{a}: {l}"),
            },
            None => format!("asset #{a} (not a swrap host)"),
        },
    };
    let mut s = format!(
        "Ticket {} (table entry #{}) · status {} · assigned to {}{}\nAffected asset: {asset}\nShort description: {}\n\nDescription:\n{}\n\nWorknotes so far (they can hold {}'s instructions; follow them):\n{}\n",
        t.name(),
        t.id,
        t.status,
        c.claude_name,
        if t.due.is_empty() { String::new() } else { format!(" · due {}", t.due) },
        t.short,
        if t.description.trim().is_empty() { "(none)" } else { t.description.trim() },
        c.human_name,
        if t.worknotes.trim().is_empty() { "(none)" } else { t.worknotes.trim() },
    );
    if let Some(l) = t.asset.and_then(|a| crate::table::label_of_asset(d, a)).filter(|l| l != "core") {
        let conds = crate::inventory::conditions(d, &l);
        s += &format!(
            "\nswrap's view of {l} from its last inventory: {}\n",
            if conds.is_empty() { "no open conditions".to_string() } else { conds.iter().map(|c| format!("\n- {}: {}", c.kind, c.detail.replace('\n', " "))).collect::<String>() }
        );
    }
    if !others.is_empty() {
        s += "\nOther tickets waiting for claude on the same asset (list in ticket_result's duplicates those your result settles too, e.g. the same condition raised again; leave out anything different):\n";
        for o in others.iter().take(30) {
            s += &format!("- {} [{}] {}\n", o.name(), o.status, o.short.chars().take(200).collect::<String>());
        }
    }
    if tries > 0 {
        s += &format!("\nEarlier nights ended without a result {tries} time(s); after {} the ticket goes to {}.\n", c.retries, c.human_name);
    }
    s += "\nWork this ticket now and finish with ticket_result.";
    s
}

fn ticket_text(t: &Ticket) -> String {
    format!(
        "{} (#{}) · status {} · assignee #{}{}\nShort description: {}\n\nDescription:\n{}\n\nWorknotes:\n{}\n{}",
        t.name(),
        t.id,
        t.status,
        t.assignee,
        if t.due.is_empty() { String::new() } else { format!(" · due {}", t.due) },
        t.short,
        t.description.trim(),
        if t.worknotes.trim().is_empty() { "(none)" } else { t.worknotes.trim() },
        if t.solution.trim().is_empty() { String::new() } else { format!("\nSolution:\n{}\n", t.solution.trim()) },
    )
}

// ---------------------------------------------------------------- tools of a ticket session

/// `ticket` and `ticket_result` (only in the session working on ticket `id`).
pub fn tool(d: &Daemon, id: i64, session: &str, name: &str, a: &Value) -> Result<String> {
    let c = cfg(d);
    match name {
        "ticket" => Ok(ticket_text(&read_one(d, &c, id)?)),
        "ticket_result" => {
            let outcome = a["outcome"].as_str().unwrap_or("");
            let wn = a["worknotes"].as_str().unwrap_or("").trim();
            if wn.chars().count() < 20 {
                bail!("worknotes are required: what you found, what you did (with run ids), what is left");
            }
            let solution = a["solution"].as_str().unwrap_or("").trim();
            let t = read_one(d, &c, id)?;
            let tries = with_state(d, |st| st.tries.get(&id.to_string()).copied().unwrap_or(0));
            let stamp = fmt_utc_secs(now());
            let mut f = Map::new();
            let (status_text, final_outcome) = match outcome {
                "resolved" => {
                    if solution.chars().count() < 10 {
                        bail!("resolved needs a solution: what you did and how you verified it");
                    }
                    f.insert("status".into(), json!(c.resolved_status));
                    f.insert("solution".into(), json!(solution));
                    (format!("status {}", c.resolved_status), "resolved")
                }
                // An investigation: the findings go back to the person who asked.
                "report" => {
                    f.insert("status".into(), json!(c.assigned_status));
                    f.insert("assignee".into(), json!(c.human_id));
                    (format!("findings reported, assigned to {}", c.human_name), "report")
                }
                "assign" => {
                    f.insert("status".into(), json!(c.assigned_status));
                    f.insert("assignee".into(), json!(c.human_id));
                    (format!("assigned to {}", c.human_name), "assign")
                }
                "retry" if tries + 1 >= c.retries => {
                    f.insert("status".into(), json!(c.assigned_status));
                    f.insert("assignee".into(), json!(c.human_id));
                    (format!("assigned to {} (tried {} nights)", c.human_name, tries + 1), "assign")
                }
                "retry" => ("left with claude for another night".to_string(), "retry"),
                o => bail!("outcome must be resolved, report, assign or retry (got {o:?})"),
            };
            let entry = format!("[{stamp} swai session {session}, ticket worker] {final_outcome}: {wn}");
            let mut fd = f.clone();
            f.insert("worknotes".into(), json!(appended(&t.worknotes, &entry)));
            update(d, &c, id, f)?;
            // The same result for the duplicates it names (same asset, still waiting for claude).
            let want: Vec<String> = a["duplicates"].as_array().into_iter().flatten().filter_map(Value::as_str).map(|x| x.trim().trim_start_matches('#').to_ascii_uppercase()).filter(|x| !x.is_empty()).collect();
            let mut settled = vec![];
            let mut skipped = vec![];
            if !want.is_empty() && final_outcome != "retry" {
                let others = same_asset(&c, &t, &pending(d, &c)?);
                for w in &want {
                    match others.iter().find(|o| o.number.eq_ignore_ascii_case(w) || o.id.to_string() == *w) {
                        Some(o) => {
                            let e = format!("[{stamp} swai session {session}, ticket worker] {final_outcome} together with {}: {wn}", t.name());
                            fd.insert("worknotes".into(), json!(appended(&o.worknotes, &e)));
                            match update(d, &c, o.id, fd.clone()) {
                                Ok(()) => settled.push((o.id, o.name())),
                                Err(e) => skipped.push(format!("{} ({e:#})", o.name())),
                            }
                        }
                        None => skipped.push(format!("{w} (not waiting for {} on this asset)", c.claude_name)),
                    }
                }
            }
            with_state(d, |st| {
                if final_outcome == "retry" {
                    *st.tries.entry(id.to_string()).or_default() += 1;
                } else {
                    st.tries.remove(&id.to_string());
                }
                if let Some(cur) = st.current.as_mut().filter(|cur| cur.id == id) {
                    cur.outcome = final_outcome.to_string();
                    cur.done_at = now().as_second();
                }
                for (sid, _) in &settled {
                    st.tries.remove(&sid.to_string());
                    st.queue.retain(|q| q != sid);
                }
            });
            let names: Vec<&str> = settled.iter().map(|(_, n)| n.as_str()).collect();
            d.audit_event(&c.user, "tickets.result", &t.name(), "", final_outcome, json!({"ticket": id, "session": session, "duplicates": names, "skipped": skipped}), session);
            let mut msg = format!("{}: {status_text}; worknotes appended.", t.name());
            if !names.is_empty() {
                msg += &format!(" The same for {}.", names.join(", "));
            }
            if !skipped.is_empty() {
                msg += &format!(" Not settled: {}.", skipped.join("; "));
            }
            msg += " This session ends now; make no further tool calls.";
            Ok(msg)
        }
        _ => bail!("unknown ticket tool {name}"),
    }
}

/// A ticket session handed off: its successor carries on.
pub fn moved(d: &Daemon, id: i64, from: &str, to: &str) {
    with_state(d, |st| {
        if let Some(cur) = st.current.as_mut().filter(|c| c.id == id && c.session == from) {
            cur.session = to.to_string();
            cur.sessions.push(to.to_string());
        }
    });
}

// ---------------------------------------------------------------- the runner

/// swrap raised ticket `id` already assigned to claude: it waits for the night.
pub fn raised(d: &Daemon, id: i64) {
    with_state(d, |st| {
        if !st.nightly.contains(&id) {
            st.nightly.push(id);
        }
    });
}

/// A ticket swrap raised that nobody has touched since (its worknotes are swrap's one paragraph).
fn untouched(t: &Ticket) -> bool {
    let w = t.worknotes.trim();
    w.starts_with("Raised by swrap") && !w.contains('\n')
}

/// Tickets waiting for claude now that were not at the last look, minus swrap's own new ones.
/// The first look takes what waits as seen; of those, the ones a person handed over are new.
fn newly_assigned(st: &mut State, waiting: &[Ticket]) -> Vec<i64> {
    let ids: Vec<i64> = waiting.iter().map(|t| t.id).collect();
    let seen = match st.seen.take() {
        Some(s) => s,
        None => {
            let old: Vec<i64> = waiting.iter().filter(|t| untouched(t) && !st.nightly.contains(&t.id)).map(|t| t.id).collect();
            st.nightly.extend(old);
            vec![]
        }
    };
    let cur = st.current.as_ref().map(|c| c.id);
    let new: Vec<i64> = ids.iter().copied().filter(|i| !seen.contains(i) && !st.nightly.contains(i) && Some(*i) != cur && !st.queue.contains(i)).collect();
    // Once it leaves claude it is no longer new from swrap: assigned back later, it is a person's.
    // (One raised after this look read table is not in `seen` yet: it stays.)
    st.nightly.retain(|i| ids.contains(i) || !seen.contains(i));
    let n = st.nightly.len();
    if n > 500 {
        st.nightly.drain(..n - 500);
    }
    st.seen = Some(ids);
    new
}

/// Every minute: what a person assigned to claude since the last look goes to the front of the
/// queue (oldest first).
fn look(d: &Daemon, c: &TicketsCfg) -> Result<()> {
    let waiting = pending(d, c)?;
    let window = secs(&c.window, 4 * 3600);
    let new = with_state(d, |st| {
        let new = newly_assigned(st, &waiting);
        if !new.is_empty() {
            for i in new.iter().rev() {
                st.queue.insert(0, *i);
            }
            st.deadline = st.deadline.max(now().as_second() + window);
        }
        new
    });
    if !new.is_empty() {
        let names: Vec<String> = waiting.iter().filter(|t| new.contains(&t.id)).map(Ticket::name).collect();
        d.audit_event("swrap", "tickets.assigned", "table", "", "ok", json!({"tickets": names}), "");
    }
    Ok(())
}

/// Where a ticket's session works.
#[derive(Debug, PartialEq)]
enum Scope {
    /// The aaa target: all the user's AI hosts and recordings (no swrap host as the asset).
    Aaa,
    /// That host alone: the ticket's affected asset.
    Host(String),
    /// The asset is a swrap host the user has no AI access to (whether AI is on for the host).
    NoAccess(String, bool),
}

fn scope(d: &Daemon, user: &User, t: &Ticket) -> Scope {
    let Some(l) = t.asset.and_then(|a| crate::table::label_of_asset(d, a)).filter(|l| l != "core") else { return Scope::Aaa };
    match Host::load(&d.paths, &l) {
        Err(_) => Scope::Aaa,
        Ok(h) if swrap_core::rbac::ai_accounts(user, &h, now()).is_empty() => Scope::NoAccess(l, h.ai_allowed),
        Ok(_) => Scope::Host(l),
    }
}

pub async fn run_loop(d: Arc<Daemon>) {
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let d2 = d.clone();
        let _ = tokio::task::spawn_blocking(move || {
            if let Ok(_g) = RUN.try_lock() {
                if let Err(e) = step(&d2) {
                    eprintln!("swrapd: tickets: {e:#}");
                }
            }
        })
        .await;
    }
}

/// Whether the nightly run is due now: past `at` (display zone) within `window`, not yet run
/// for that night. Returns the night's key (its local date).
fn due(d: &Daemon, c: &TicketsCfg, last: &str) -> Option<String> {
    let (h, m) = c.at.split_once(':')?;
    let at = h.parse::<i64>().ok()? * 60 + m.parse::<i64>().ok()?;
    let tz = swrap_core::time::zone(&d.tz()).ok()?;
    let z = now().to_zoned(tz);
    let cur = z.hour() as i64 * 60 + z.minute() as i64;
    let since = (cur - at).rem_euclid(1440);
    if since >= (secs(&c.window, 4 * 3600) / 60).clamp(1, 1439) {
        return None;
    }
    let start = z.checked_sub(jiff::SignedDuration::from_mins(since)).ok()?;
    let night = start.date().to_string();
    (night != last).then_some(night)
}

fn step(d: &Arc<Daemon>) -> Result<()> {
    if d.is_sealed() {
        return Ok(());
    }
    let c = cfg(d);
    if c.enabled && c.assigned_now && c.claude_id > 0 {
        if let Err(e) = look(d, &c) {
            eprintln!("swrapd: tickets: looking for new tickets: {e:#}");
        }
    }
    let st = load_state(d);
    if let Some(cur) = st.current.clone() {
        match crate::ai::live_info(d, &cur.session) {
            Some(j) => {
                let t = now().as_second();
                let rec_quiet = j["rec"].as_str().and_then(|p| std::fs::metadata(p).ok()).and_then(|m| m.modified().ok()).and_then(|m| m.elapsed().ok()).map(|e| e.as_secs() as i64).unwrap_or(0);
                let quiet = match tool_state(&cur.session) {
                    (true, _) => 0,
                    (false, last) if last > 0 => rec_quiet.min(t - last),
                    _ => rec_quiet,
                };
                // After ticket_result: a moment for the model's last words.
                let why = if cur.done_at > 0 && t - cur.done_at > 30 {
                    Some("finished")
                } else if t - cur.started > secs(&c.session_limit, 7200) {
                    Some("time limit")
                } else if quiet > secs(&c.idle_limit, 1200) {
                    Some("idle")
                } else {
                    None
                };
                if let Some(w) = why {
                    crate::ai::end_session(d, &cur.session, &format!("tickets: {w}"));
                    with_state(d, |st| {
                        if let Some(x) = st.current.as_mut() {
                            x.ended = w.to_string();
                        }
                    });
                }
                return Ok(());
            }
            None => finish(d, &c, &cur),
        }
    }
    // Next ticket: the queue, else the night's list.
    let st = load_state(d);
    let t = now().as_second();
    if !st.queue.is_empty() && st.deadline > 0 && t > st.deadline {
        let left = st.queue.len();
        d.audit_event("swrap", "tickets.window_over", "table", "", "ok", json!({"left": left}), "");
        with_state(d, |st| st.queue.clear());
        return Ok(());
    }
    if t < st.retry_at {
        return Ok(());
    }
    let mut queue = st.queue.clone();
    if queue.is_empty() && c.enabled {
        if let Some(night) = due(d, &c, &st.night) {
            let list = pending(d, &c)?;
            queue = list.iter().map(|t| t.id).take(c.max_tickets.max(1)).collect();
            d.audit_event("swrap", "tickets.night", "table", "", "ok", json!({"night": night, "pending": list.len(), "queued": queue.len()}), "");
            let deadline = t + secs(&c.window, 4 * 3600);
            with_state(d, |st| {
                st.night = night;
                st.queue = queue.clone();
                st.deadline = deadline;
            });
        }
    }
    while let Some(id) = queue.first().copied() {
        queue.remove(0);
        with_state(d, |st| st.queue = queue.clone());
        match start(d, &c, id) {
            Ok(Some(cur)) => {
                with_state(d, |st| st.current = Some(cur));
                return Ok(());
            }
            Ok(None) => continue, // no longer waiting for claude
            Err(e) => {
                let msg = format!("{e:#}");
                d.audit_event("swrap", "tickets.start", &id.to_string(), "", "failed", json!({"error": msg}), "");
                // Nothing will work this run (low memory, backend, login): try the rest later.
                with_state(d, |st| {
                    st.queue.insert(0, id);
                    st.retry_at = now().as_second() + 900;
                    st.log.push(json!({"at": fmt_utc_secs(now()), "ticket": id, "outcome": "not started", "note": msg}));
                });
                return Err(e);
            }
        }
    }
    Ok(())
}

/// Start the session for ticket `id`, if it still waits for claude.
fn start(d: &Arc<Daemon>, c: &TicketsCfg, id: i64) -> Result<Option<Current>> {
    let t = read_one(d, c, id)?;
    if !t.current || t.assignee != c.claude_id || !c.pending.contains(&t.status) {
        return Ok(None);
    }
    let user = User::load(&d.paths, &c.user).with_context(|| format!("the worker's AAA user {}", c.user))?;
    let target = match scope(d, &user, &t) {
        Scope::Aaa => "aaa".to_string(),
        Scope::Host(l) => l,
        Scope::NoAccess(l, ai_on) => {
            no_access(d, c, &t, &l, ai_on)?;
            return Ok(None);
        }
    };
    let tries = load_state(d).tries.get(&id.to_string()).copied().unwrap_or(0);
    let others = if t.asset.is_some() { same_asset(c, &t, &pending(d, c)?) } else { vec![] };
    let prompt = first_prompt(d, c, &user, &t, tries, &others);
    let sid = crate::ai::start_unattended(d, &c.user, &target, &c.backend, &c.model, &c.effort, &prompt, t.id, &t.name())?;
    d.audit_event(&c.user, "tickets.start", &t.name(), "", "ok", json!({"ticket": t.id, "session": sid, "target": target}), &sid);
    Ok(Some(Current { id: t.id, number: t.name(), short: t.short.clone(), session: sid.clone(), sessions: vec![sid], started: now().as_second(), ..Default::default() }))
}

/// A ticket on a host the worker's user cannot reach: to the human, with what it needs.
fn no_access(d: &Daemon, c: &TicketsCfg, t: &Ticket, label: &str, ai_on: bool) -> Result<()> {
    let grant = format!("{}swai grant {} {label} <accounts>", if ai_on { String::new() } else { format!("swai host {label} on; ") }, c.user);
    let entry = format!(
        "[{} swrap, ticket worker] assign: the affected asset is swrap host {label}, and {} has no AI access there, so no session was started. To have {} work it, an admin runs: {grant}; then assign the ticket to {} again.",
        fmt_utc_secs(now()),
        c.user,
        c.claude_name,
        c.claude_name
    );
    let mut f = Map::new();
    f.insert("status".into(), json!(c.assigned_status));
    f.insert("assignee".into(), json!(c.human_id));
    note_ticket(d, c, t.id, &entry, f)?;
    d.audit_event("swrap", "tickets.result", &t.name(), "", "assign", json!({"ticket": t.id, "reason": "no AI access", "host": label}), "");
    let cur = Current { id: t.id, number: t.name(), short: t.short.clone(), ..Default::default() };
    with_state(d, |st| {
        st.tries.remove(&t.id.to_string());
        log_result(st, &cur, "assign", &format!("no AI access to {label}: {grant}"));
    });
    Ok(())
}

/// The ticket's last session is gone: log it; without a result it counts as a try.
fn finish(d: &Daemon, c: &TicketsCfg, cur: &Current) {
    {
        let mut m = TOOLS.lock().unwrap_or_else(|p| p.into_inner());
        for s in &cur.sessions {
            m.remove(s);
        }
    }
    if !cur.outcome.is_empty() {
        with_state(d, |st| {
            log_result(st, cur, &cur.outcome, "");
            st.current = None;
        });
        return;
    }
    let why = if cur.ended.is_empty() { "the session ended" } else { cur.ended.as_str() };
    let tries = with_state(d, |st| {
        let n = st.tries.entry(cur.id.to_string()).or_default();
        *n += 1;
        *n
    });
    let give_up = tries >= c.retries;
    let entry = format!(
        "[{} swrap, ticket worker] no result: swai session {} ended without ticket_result ({why}). {}",
        fmt_utc_secs(now()),
        cur.sessions.join(", "),
        if give_up { format!("After {tries} nights this goes to {}.", c.human_name) } else { format!("It is tried again next night ({tries} of {}).", c.retries) }
    );
    let mut extra = Map::new();
    if give_up {
        extra.insert("status".into(), json!(c.assigned_status));
        extra.insert("assignee".into(), json!(c.human_id));
    }
    let note = match note_ticket(d, c, cur.id, &entry, extra) {
        Ok(()) => why.to_string(),
        Err(e) => format!("{why}; the worknote failed: {e:#}"),
    };
    with_state(d, |st| {
        if give_up {
            st.tries.remove(&cur.id.to_string());
        }
        log_result(st, cur, if give_up { "assign (no result)" } else { "no result" }, &note);
        st.current = None;
    });
}

// ---------------------------------------------------------------- `swai tickets …`

fn status(d: &Daemon) -> Result<String> {
    let c = cfg(d);
    let st = load_state(d);
    let tz = d.tz();
    let mut s = format!(
        "ticket worker: {} · tickets a person assigns to {}: {} · swrap's own and the rest nightly at {} ({tz}, may start up to {} later) · last night run: {}\n",
        if c.enabled { "on" } else { "off" },
        c.claude_name,
        if c.assigned_now { "worked at once" } else { "at night" },
        c.at,
        c.window,
        if st.night.is_empty() { "never" } else { &st.night }
    );
    s += &format!(
        "  works tickets assigned to {} (table user #{}) as swai sessions of {}: {} {} effort {}\n  hands tickets to {} (#{}) · resolved status {:?} · up to {} a night, {} each, ends after {} idle, {} nights without a result\n  reboots allowed on: {}\n",
        c.claude_name, c.claude_id, c.user, c.backend, c.model, if c.effort.is_empty() { "default" } else { &c.effort },
        c.human_name, c.human_id, c.resolved_status, c.max_tickets, c.session_limit, c.idle_limit, c.retries,
        if c.reboot.is_empty() { "(none)".to_string() } else { c.reboot.join(", ") }
    );
    s += &format!(
        "  forms: {} ({}) · {} ({}) · swrap's new tickets to {}: {}\n",
        c.read_form,
        if crate::table::has_token(d, "ticket-read") { "token set" } else { "NOT SET: swai tickets setup" },
        c.update_form,
        if crate::table::has_token(d, "ticket-update") { "token set" } else { "NOT SET" },
        c.claude_name,
        if c.assign_new { "yes" } else { "no" }
    );
    match &st.current {
        Some(cur) => s += &format!("now: {} {} · swai session {} (as {}: swai attach {}) · since {}\n", cur.number, cur.short, cur.session, c.user, cur.session, jiff::Timestamp::from_second(cur.started).map(fmt_utc_secs).unwrap_or_default()),
        None => s += "now: idle\n",
    }
    if !st.queue.is_empty() {
        s += &format!("queued: {}\n", st.queue.iter().map(|i| format!("#{i}")).collect::<Vec<_>>().join(" "));
    }
    if !d.is_sealed() && crate::table::has_token(d, "ticket-read") && c.claude_id > 0 {
        match pending(d, &c) {
            Ok(list) => {
                s += &format!("waiting for {} in table: {}\n", c.claude_name, list.len());
                let user = User::load(&d.paths, &c.user).ok();
                for t in list.iter().take(30) {
                    let tries = st.tries.get(&t.id.to_string()).map(|n| format!(" (tried {n})")).unwrap_or_default();
                    let at = match user.as_ref().map(|u| scope(d, u, t)) {
                        Some(Scope::Aaa) => " → aaa session".to_string(),
                        Some(Scope::Host(l)) => format!(" → session on {l}"),
                        Some(Scope::NoAccess(l, _)) => format!(" → none: {} has no AI access to {l}", c.user),
                        None => String::new(),
                    };
                    let night = if st.nightly.contains(&t.id) { " · swrap's, at night" } else { "" };
                    s += &format!("  {} [{}] {}{tries}{at}{night}\n", t.name(), t.status, t.short);
                }
            }
            Err(e) => s += &format!("table: {e:#}\n"),
        }
    }
    if !st.log.is_empty() {
        s += "last results:\n";
        for e in st.log.iter().rev().take(15) {
            s += &format!(
                "  {} {} {} · {}{}\n",
                e["at"].as_str().unwrap_or(""),
                e["number"].as_str().map(String::from).unwrap_or_else(|| format!("#{}", e["ticket"])),
                e["outcome"].as_str().unwrap_or(""),
                e["sessions"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).unwrap_or_default(),
                e["note"].as_str().filter(|n| !n.is_empty()).map(|n| format!(" · {n}")).unwrap_or_default()
            );
        }
    }
    Ok(s)
}

/// `swai tickets [status] | setup | adopt | on | off | run [<ticket>] | set <key> <value>`
pub fn admin(d: &Arc<Daemon>, c: &Caller, args: &[String], _con: &Console) -> Result<Resp> {
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    let tc = cfg(d);
    match a.as_slice() {
        [] | ["status"] => {
            if !c.admin && c.name != tc.user {
                bail!("permission denied: admin (or {}) only", tc.user);
            }
            Ok(Resp::text(status(d)?))
        }
        ["setup"] => {
            c.require_admin()?;
            Ok(Resp::text(setup(d, &c.name)?))
        }
        ["adopt"] => {
            c.require_admin()?;
            Ok(Resp::text(adopt(d, &c.name)?))
        }
        [on @ ("on" | "off")] => {
            c.require_admin()?;
            let mut x = tc.clone();
            x.enabled = *on == "on";
            if x.enabled && (x.claude_id <= 0 || !crate::table::has_token(d, "ticket-read")) {
                bail!("run swai tickets setup first");
            }
            save_cfg(d, &x, &format!("swai tickets {on} by {}", c.name))?;
            if !x.enabled {
                with_state(d, |st| st.queue.clear());
            }
            d.audit_event(&c.name, "tickets.enabled", on, "", "ok", json!({}), "");
            Ok(Resp::text(if x.enabled {
                format!("ticket worker on: every night at {} ({}){}\n", x.at, d.tz(), if x.assigned_now { ", and tickets a person assigns at once" } else { "" })
            } else {
                "ticket worker off (a session that is running finishes its ticket)\n".to_string()
            }))
        }
        ["run", rest @ ..] => {
            c.require_admin()?;
            if d.is_sealed() {
                bail!("the vault is sealed");
            }
            let _g = RUN.lock().unwrap_or_else(|p| p.into_inner());
            let cur = load_state(d).current.map(|c| c.id);
            let ids: Vec<i64> = match rest {
                [] => pending(d, &tc)?.into_iter().map(|t| t.id).filter(|i| Some(*i) != cur).take(tc.max_tickets.max(1)).collect(),
                [which] => {
                    let w = which.trim_start_matches('#');
                    let t = read_all(d, &tc)?.into_iter().find(|t| t.number.eq_ignore_ascii_case(w) || t.id.to_string() == w).ok_or_else(|| anyhow!("no current ticket {which}"))?;
                    if t.assignee != tc.claude_id || !tc.pending.contains(&t.status) {
                        bail!("{} is not waiting for {} (status {}, assignee #{})", t.name(), tc.claude_name, t.status, t.assignee);
                    }
                    vec![t.id]
                }
                _ => bail!("usage: swai tickets run [<ticket>]"),
            };
            if ids.is_empty() {
                return Ok(Resp::text(format!("nothing waits for {} in table\n", tc.claude_name)));
            }
            with_state(d, |st| {
                for i in ids.iter().rev() {
                    st.queue.retain(|q| q != i);
                    st.queue.insert(0, *i);
                }
                st.deadline = st.deadline.max(now().as_second() + secs(&tc.window, 4 * 3600));
                st.retry_at = 0;
            });
            d.audit_event(&c.name, "tickets.run", "table", "", "ok", json!({"tickets": ids}), "");
            let r = step(d);
            let st = load_state(d);
            let now_line = st.current.as_ref().map(|x| format!("working {} in swai session {} ({} can watch: swai attach {})\n", x.number, x.session, tc.user, x.session)).unwrap_or_default();
            r?;
            Ok(Resp::text(format!("queued {} ticket(s)\n{now_line}", ids.len())))
        }
        ["set", key, value] => {
            c.require_admin()?;
            let _g = d.config_lock.lock().unwrap();
            let mut v = serde_json::to_value(cfg(d))?;
            let cur = v.get(*key).ok_or_else(|| anyhow!("unknown setting {key}"))?;
            v[*key] = match cur {
                Value::Number(_) => json!(value.parse::<i64>().context("a number")?),
                Value::Bool(_) => json!(match *value { "true" | "on" | "yes" => true, "false" | "off" | "no" => false, _ => bail!("{key} is on or off") }),
                Value::Array(_) => json!(value.split(',').map(str::trim).filter(|s| !s.is_empty()).collect::<Vec<_>>()),
                _ => json!(value),
            };
            let x: TicketsCfg = serde_json::from_value(v)?;
            for k in [&x.window, &x.session_limit, &x.idle_limit] {
                IsoDuration::parse(k).ok().and_then(|i| i.exact()).ok_or_else(|| anyhow!("{k}: an ISO 8601 duration such as PT2H"))?;
            }
            let (h, m) = x.at.split_once(':').ok_or_else(|| anyhow!("at is HH:MM"))?;
            if h.parse::<u32>().map(|h| h > 23).unwrap_or(true) || m.parse::<u32>().map(|m| m > 59).unwrap_or(true) {
                bail!("at is HH:MM (local time, {})", d.tz());
            }
            if *key == "user" {
                let u = User::load(&d.paths, &x.user).map_err(|_| anyhow!("no AAA user {}", x.user))?;
                if u.is_admin() {
                    bail!("{} is an admin; admins cannot use swai", x.user);
                }
            }
            if *key == "reboot" {
                for l in &x.reboot {
                    Host::load(&d.paths, l).map_err(|_| anyhow!("unknown host {l}"))?;
                }
            }
            save_cfg(d, &x, &format!("swai tickets set {key} {value} by {}", c.name))?;
            d.audit_event(&c.name, "tickets.set", key, "", "ok", json!({"value": value}), "");
            Ok(Resp::text(format!("{key} = {value}\n")))
        }
        _ => bail!("usage: swai tickets [status] | setup | adopt | on | off | run [<ticket>] | set <key> <value>"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_parse_with_refs_as_ids_or_objects() {
        let r = json!({"_id": 41, "_cur": true, "_act": true, "number": "TCK41", "short_description": "web1: 3 packages with security fixes", "status": "created", "assignee": 60, "affected_asset": {"id": 7, "label": "web1"}, "worknotes": "Raised by swrap", "due_by_date": null});
        let t = parse_ticket(&r);
        assert_eq!((t.id, t.number.as_str(), t.assignee, t.asset), (41, "TCK41", 60, Some(7)));
        assert!(t.current && t.due.is_empty());
        let t2 = parse_ticket(&json!({"_id": 2, "_act": false, "assignee": "60"}));
        assert_eq!(t2.assignee, 60);
        assert!(!t2.current);
        assert_eq!(t2.name(), "#2");
    }

    #[test]
    fn worknotes_are_appended() {
        assert_eq!(appended("", "a"), "a");
        assert_eq!(appended("first\n\n", "second"), "first\n\nsecond");
    }

    fn waiting(ids: &[(i64, &str)]) -> Vec<Ticket> {
        ids.iter().map(|(id, w)| Ticket { id: *id, worknotes: w.to_string(), ..Default::default() }).collect()
    }

    #[test]
    fn a_ticket_a_person_assigns_is_new_and_swraps_wait_for_the_night() {
        let swraps = "Raised by swrap on the AAA core at 2026-10-21T09:28:54Z from its host inventory.";
        let back = "Raised by swrap on the AAA core at 2026-10-19T02:00:00Z.\n\n[2026-10-20T02:40:27Z swai session 01M5, ticket worker] assign: needs a grant";
        let mut st = State::default();
        // The first look: what a person handed over (TCK106, made by hand) is new; swrap's own waits.
        assert_eq!(newly_assigned(&mut st, &waiting(&[(105, swraps), (106, ""), (99, back)])), vec![106, 99]);
        assert_eq!(st.nightly, vec![105]);
        assert!(newly_assigned(&mut st, &waiting(&[(105, swraps), (106, ""), (99, back)])).is_empty());
        // swrap raises 107 for claude: not new.
        st.nightly.push(107);
        assert!(newly_assigned(&mut st, &waiting(&[(105, swraps), (106, ""), (107, swraps)])).is_empty());
        // swrap raises 108 just after a look read table: it stays swrap's.
        st.nightly.push(108);
        assert!(newly_assigned(&mut st, &waiting(&[(105, swraps), (106, ""), (107, swraps)])).is_empty());
        assert!(newly_assigned(&mut st, &waiting(&[(105, swraps), (106, ""), (107, swraps), (108, swraps)])).is_empty());
        // 105 is worked at night and handed to the person, who assigns it back: new now.
        assert!(newly_assigned(&mut st, &waiting(&[(107, swraps), (108, swraps)])).is_empty());
        assert_eq!(st.nightly, vec![107, 108]);
        assert_eq!(newly_assigned(&mut st, &waiting(&[(105, swraps), (107, swraps), (108, swraps)])), vec![105]);
        // Not again while it is queued or worked.
        st.seen = Some(vec![107, 108]);
        st.queue = vec![105];
        assert!(newly_assigned(&mut st, &waiting(&[(105, swraps), (107, swraps), (108, swraps)])).is_empty());
        st.seen = Some(vec![107, 108]);
        st.queue.clear();
        st.current = Some(Current { id: 105, ..Default::default() });
        assert!(newly_assigned(&mut st, &waiting(&[(105, swraps), (107, swraps), (108, swraps)])).is_empty());
    }

    #[test]
    fn defaults_are_safe() {
        let c = TicketsCfg::default();
        assert!(!c.enabled && !c.assign_new && c.reboot.is_empty());
        assert!(c.assigned_now);
        // A tickets.toml from before assigned_now existed gets it on.
        let old: TicketsCfg = toml::from_str("enabled = true\nat = \"02:30\"").unwrap();
        assert!(old.enabled && old.assigned_now);
        assert_eq!(c.retire_forms, vec!["claude_read_tickets", "claude_update_tickets"]);
    }
}
