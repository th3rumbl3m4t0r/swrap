//! Targets syntax (spec 10.6) and RBAC evaluation (spec 9.1, 17).

use crate::config::{Grant, Host, HostState, User};
use crate::time;
use anyhow::{bail, Result};
use globset::{Glob, GlobMatcher};
use jiff::Timestamp;

#[derive(Debug)]
enum Term {
    All,
    Tag(String),
    Glob(GlobMatcher, bool /* literal */, String),
}

impl Term {
    fn matches(&self, h: &Host) -> bool {
        match self {
            Term::All => true,
            Term::Tag(t) => h.tags.iter().any(|x| x == t),
            Term::Glob(g, _, _) => g.is_match(&h.label),
        }
    }
}

/// A parsed targets expression: `web*,@lab,!db-1`, `@all`, `web1`.
#[derive(Debug)]
pub struct Targets {
    include: Vec<Term>,
    exclude: Vec<Term>,
}

fn is_glob(s: &str) -> bool {
    s.contains(['*', '?', '['])
}

impl Targets {
    pub fn parse(expr: &str) -> Result<Self> {
        let mut include = vec![];
        let mut exclude = vec![];
        for raw in expr.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let (neg, t) = match raw.strip_prefix('!') {
                Some(r) => (true, r),
                None => (false, raw),
            };
            let term = if t == "@all" || t == "*" {
                Term::All
            } else if let Some(tag) = t.strip_prefix('@') {
                Term::Tag(tag.to_string())
            } else {
                if !t.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.*?[]!".contains(&b)) {
                    bail!("bad target {t:?}");
                }
                Term::Glob(Glob::new(t)?.compile_matcher(), !is_glob(t), t.to_string())
            };
            if neg { exclude.push(term) } else { include.push(term) }
        }
        if include.is_empty() {
            if exclude.is_empty() {
                bail!("empty targets expression");
            }
            include.push(Term::All);
        }
        Ok(Targets { include, exclude })
    }

    pub fn matches(&self, h: &Host) -> bool {
        self.include.iter().any(|t| t.matches(h)) && !self.exclude.iter().any(|t| t.matches(h))
    }

    /// Literal labels named explicitly (they must exist and be granted, else error).
    pub fn explicit_labels(&self) -> Vec<&str> {
        self.include
            .iter()
            .filter_map(|t| match t {
                Term::Glob(_, true, s) => Some(s.as_str()),
                _ => None,
            })
            .collect()
    }
}

/// Where the request originates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Node {
    Core,
    Edge,
}

impl Node {
    pub fn as_str(&self) -> &'static str {
        match self {
            Node::Core => "core",
            Node::Edge => "edge",
        }
    }
}

fn grant_active(g: &Grant, origin: Node, now: Timestamp) -> bool {
    if !g.via.iter().any(|v| v == origin.as_str()) {
        return false;
    }
    if let Some(u) = &g.until {
        match time::parse_datetime(u) {
            Ok(t) if now < t => {}
            _ => return false,
        }
    }
    true
}

fn ruser_matches(g: &Grant, ruser: &str) -> bool {
    g.remote_users.iter().any(|p| Glob::new(p).map(|g| g.compile_matcher().is_match(ruser)).unwrap_or(false))
}

fn grant_hosts(g: &Grant, h: &Host) -> bool {
    Targets::parse(&g.hosts).map(|t| t.matches(h)).unwrap_or(false)
}

/// Is `user` allowed to use `ruser@host` from `origin`?
pub fn allowed(user: &User, host: &Host, ruser: &str, origin: Node, now: Timestamp) -> bool {
    if user.disabled || host.state != HostState::Active {
        return false;
    }
    if origin == Node::Edge && !host.edge_allowed {
        return false;
    }
    user.grants.iter().any(|g| grant_active(g, origin, now) && grant_hosts(g, host) && ruser_matches(g, ruser))
}

/// Does the user have any grant covering the host (regardless of account)?
pub fn host_visible(user: &User, host: &Host, origin: Node, now: Timestamp) -> bool {
    if user.disabled || host.state != HostState::Active || (origin == Node::Edge && !host.edge_allowed) {
        return false;
    }
    user.grants.iter().any(|g| grant_active(g, origin, now) && grant_hosts(g, host))
}

// ---------------------------------------------------------------- AI grants (spec 24.5)

fn ai_grant_active(g: &crate::config::AiGrant, now: Timestamp) -> bool {
    match &g.until {
        Some(u) => matches!(time::parse_datetime(u), Ok(t) if now < t),
        None => true,
    }
}

/// May the AI act as `ruser` on `host` for `user`? Needs both keys: the host opted in
/// (`ai_allowed`) and an explicit, active AI grant. Human grants never count; admins never qualify.
pub fn ai_allowed(user: &User, host: &Host, ruser: &str, now: Timestamp) -> bool {
    if user.disabled || user.is_admin() || host.state != HostState::Active || !host.ai_allowed || host.account(ruser).is_none() {
        return false;
    }
    user.ai_grants.iter().any(|g| {
        ai_grant_active(g, now)
            && Targets::parse(&g.hosts).map(|t| t.matches(host)).unwrap_or(false)
            && g.remote_users.iter().any(|p| Glob::new(p).map(|m| m.compile_matcher().is_match(ruser)).unwrap_or(false))
    })
}

/// AI-granted accounts on `host`, most privileged first (the same ranking as `sw`).
pub fn ai_accounts(user: &User, host: &Host, now: Timestamp) -> Vec<String> {
    let mut v: Vec<String> = host.accounts.iter().filter(|a| ai_allowed(user, host, &a.name, now)).map(|a| a.name.clone()).collect();
    v.sort_by(|a, b| {
        rank(host, a)
            .cmp(&rank(host, b))
            .then_with(|| (b == &host.default_user).cmp(&(a == &host.default_user)))
            .then_with(|| a.cmp(b))
    });
    v
}

/// Privilege rank: lower is more privileged.
fn rank(host: &Host, name: &str) -> u8 {
    if name == "root" {
        return 0;
    }
    match host.account(name) {
        Some(a) if a.sudo == "nopasswd" && a.managed_by_swrap => 1,
        _ => 2,
    }
}

/// Granted accounts (with credentials) on `host`, most privileged first (spec 9.1).
pub fn granted_accounts(user: &User, host: &Host, origin: Node, now: Timestamp) -> Vec<String> {
    let mut v: Vec<String> = host
        .accounts
        .iter()
        .filter(|a| allowed(user, host, &a.name, origin, now))
        .map(|a| a.name.clone())
        .collect();
    v.sort_by(|a, b| {
        rank(host, a)
            .cmp(&rank(host, b))
            .then_with(|| (b == &host.default_user).cmp(&(a == &host.default_user)))
            .then_with(|| a.cmp(b))
    });
    v
}

/// Can `user` act as root on host (directly or via swrap NOPASSWD sudo)? Returns the account to use.
pub fn root_capable_account(user: &User, host: &Host, origin: Node, now: Timestamp) -> Option<(String, bool)> {
    for a in granted_accounts(user, host, origin, now) {
        match rank(host, &a) {
            0 => return Some((a, false)),
            1 => return Some((a, true)),
            _ => {}
        }
    }
    None
}

/// Expand targets against all hosts, only covering hosts the caller has grants for.
/// An explicit label without a grant is an error.
pub fn expand<'a>(
    expr: &str,
    hosts: &'a [Host],
    visible: impl Fn(&Host) -> bool,
) -> Result<Vec<&'a Host>> {
    let t = Targets::parse(expr)?;
    for l in t.explicit_labels() {
        match hosts.iter().find(|h| h.label == l) {
            None => bail!("unknown host {l:?}"),
            Some(h) if !visible(h) => bail!("no grant for host {l:?}"),
            _ => {}
        }
    }
    Ok(hosts.iter().filter(|h| t.matches(h) && visible(h)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    fn host(label: &str, tags: &[&str], accts: &[(&str, &str, bool)]) -> Host {
        Host {
            label: label.into(),
            address: "10.0.0.1".into(),
            port: 22,
            route: Route::Core,
            edge_allowed: true,
            tags: tags.iter().map(|s| s.to_string()).collect(),
            profile: "modern".into(),
            default_user: "root".into(),
            state: HostState::Active,
            enrolled: String::new(),
            created: String::new(),
            hostkey_fingerprints: vec![],
            accounts: accts
                .iter()
                .map(|(n, sudo, m)| Account {
                    name: n.to_string(),
                    key_algo: "ssh-ed25519".into(),
                    key_fingerprint: String::new(),
                    created: String::new(),
                    sudo: sudo.to_string(),
                    managed_by_swrap: *m,
                    integration: true,
                })
                .collect(),
            enroll_progress: vec![],
            network: Route::Core,
            ai_allowed: false,
        }
    }

    fn user(grants: Vec<Grant>) -> User {
        User { name: "u".into(), role: Role::User, disabled: false, keys: vec![], created: String::new(), grants, ai_grants: vec![] }
    }

    fn grant(hosts: &str, rusers: &[&str], via: &[&str]) -> Grant {
        Grant {
            id: "g".into(),
            hosts: hosts.into(),
            remote_users: rusers.iter().map(|s| s.to_string()).collect(),
            via: via.iter().map(|s| s.to_string()).collect(),
            until: None,
            created: String::new(),
        }
    }

    #[test]
    fn targets() {
        let hs = vec![host("web1", &["lab"], &[]), host("web2", &[], &[]), host("db-1", &["lab"], &[])];
        let names = |e: &str| expand(e, &hs, |_| true).unwrap().iter().map(|h| h.label.clone()).collect::<Vec<_>>();
        assert_eq!(names("web*"), ["web1", "web2"]);
        assert_eq!(names("@lab"), ["web1", "db-1"]);
        assert_eq!(names("@all,!web2"), ["web1", "db-1"]);
        assert_eq!(names("!db-1"), ["web1", "web2"]);
        assert_eq!(names("db-?"), ["db-1"]);
        assert!(expand("nope", &hs, |_| true).is_err());
        assert!(expand("web1", &hs, |h| h.label != "web1").is_err());
        assert!(expand("web*", &hs, |h| h.label != "web1").unwrap().len() == 1);
    }

    #[test]
    fn most_privileged() {
        let h = host("m", &[], &[("deploy", "nopasswd", true), ("app", "none", false), ("root", "n/a", false)]);
        let u = user(vec![grant("*", &["*"], &["core", "edge"])]);
        let now = time::now();
        assert_eq!(granted_accounts(&u, &h, Node::Core, now), ["root", "deploy", "app"]);
        let u2 = user(vec![grant("*", &["deploy", "app"], &["core"])]);
        assert_eq!(granted_accounts(&u2, &h, Node::Core, now), ["deploy", "app"]);
        assert!(granted_accounts(&u2, &h, Node::Edge, now).is_empty());
        assert_eq!(root_capable_account(&u2, &h, Node::Core, now), Some(("deploy".into(), true)));
    }

    #[test]
    fn ai_grants_need_both_keys() {
        let mut h = host("lab", &["ai"], &[("root", "n/a", false), ("app", "none", false)]);
        let mut u = user(vec![grant("*", &["*"], &["core", "edge"])]);
        let now = time::now();
        // Human grants never count.
        assert!(ai_accounts(&u, &h, now).is_empty());
        u.ai_grants.push(AiGrant { id: "a".into(), hosts: "@ai".into(), remote_users: vec!["*".into()], until: None, created: String::new() });
        // The host has not opted in.
        assert!(ai_accounts(&u, &h, now).is_empty());
        h.ai_allowed = true;
        assert_eq!(ai_accounts(&u, &h, now), ["root", "app"]);
        u.ai_grants[0].until = Some("2000-01-01T00:00:00Z".into());
        assert!(ai_accounts(&u, &h, now).is_empty());
        u.ai_grants[0].until = None;
        u.role = Role::Admin;
        assert!(ai_accounts(&u, &h, now).is_empty(), "admins are refused");
    }

    #[test]
    fn until_and_edge_flag() {
        let mut h = host("m", &[], &[("root", "n/a", false)]);
        let mut g = grant("m", &["root"], &["core", "edge"]);
        g.until = Some("2000-01-01T00:00:00Z".into());
        let u = user(vec![g]);
        assert!(!allowed(&u, &h, "root", Node::Core, time::now()));
        let u = user(vec![grant("m", &["root"], &["core", "edge"])]);
        assert!(allowed(&u, &h, "root", Node::Edge, time::now()));
        h.edge_allowed = false;
        assert!(!allowed(&u, &h, "root", Node::Edge, time::now()));
        assert!(allowed(&u, &h, "root", Node::Core, time::now()));
    }
}
