//! Filesystem layout (spec section 7). `SWRAP_ROOT`/`SWRAP_RUN` override the roots for tests.

use std::path::{Path, PathBuf};

pub const LIBEXEC: &str = "/usr/libexec/swrap";

#[derive(Clone, Debug)]
pub struct Paths {
    pub root: PathBuf,
    pub run: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Self::from_env()
    }
}

impl Paths {
    pub fn from_env() -> Self {
        let edge = is_edge();
        let (root, run) = if edge { ("/var/lib/swrap-edge", "/run/swrap-edge") } else { ("/var/lib/swrap", "/run/swrap") };
        Paths {
            root: std::env::var_os("SWRAP_ROOT").map(PathBuf::from).unwrap_or_else(|| root.into()),
            run: std::env::var_os("SWRAP_RUN").map(PathBuf::from).unwrap_or_else(|| run.into()),
        }
    }
    pub fn at(root: impl Into<PathBuf>, run: impl Into<PathBuf>) -> Self {
        Paths { root: root.into(), run: run.into() }
    }

    pub fn config(&self) -> PathBuf { self.root.join("config") }
    pub fn swrap_toml(&self) -> PathBuf { self.config().join("swrap.toml") }
    pub fn profiles(&self) -> PathBuf { self.config().join("profiles") }
    pub fn profile(&self, name: &str) -> PathBuf { self.profiles().join(format!("{name}.toml")) }
    pub fn hosts(&self) -> PathBuf { self.config().join("hosts") }
    pub fn host(&self, label: &str) -> PathBuf { self.hosts().join(format!("{label}.toml")) }
    pub fn users(&self) -> PathBuf { self.config().join("users") }
    pub fn user(&self, name: &str) -> PathBuf { self.users().join(format!("{name}.toml")) }
    pub fn firewall_toml(&self) -> PathBuf { self.config().join("firewall.toml") }
    pub fn edge_toml(&self) -> PathBuf { self.config().join("edge.toml") }
    pub fn ai_toml(&self) -> PathBuf { self.config().join("ai.toml") }
    /// Per-(user, target) opencode homes of swai sessions (owned by the `swai` user).
    pub fn ai_homes(&self) -> PathBuf { self.root.join("ai").join("home") }
    /// Runtime dirs of swai sessions (proxy + MCP sockets, shared with the sandbox).
    pub fn ai_run(&self) -> PathBuf { self.run.join("ai") }
    pub fn known_hosts(&self, label: &str) -> PathBuf { self.config().join("known_hosts").join(label) }

    pub fn vault(&self) -> PathBuf { self.root.join("vault") }
    pub fn wraps(&self) -> PathBuf { self.vault().join("wraps") }
    pub fn vault_keys(&self) -> PathBuf { self.vault().join("keys") }
    pub fn host_key(&self, label: &str, ruser: &str, algo_file: &str) -> PathBuf {
        self.vault_keys().join("hosts").join(label).join(ruser).join(format!("{algo_file}.enc"))
    }
    pub fn manifest(&self) -> PathBuf { self.vault().join("MANIFEST.b3") }

    pub fn link(&self) -> PathBuf { self.root.join("link") }
    pub fn recsign(&self) -> PathBuf { self.root.join("recsign") }
    pub fn trust(&self) -> PathBuf { self.root.join("trust") }
    pub fn webpw(&self, user: &str) -> PathBuf { self.root.join("secrets").join("webpw").join(user) }
    pub fn state(&self) -> PathBuf { self.root.join("state") }
    pub fn rec(&self) -> PathBuf { self.root.join("rec") }
    pub fn runs(&self) -> PathBuf { self.root.join("runs") }
    pub fn logs(&self) -> PathBuf { self.root.join("logs") }
    pub fn audit(&self) -> PathBuf { self.root.join("audit") }
    pub fn index(&self) -> PathBuf { self.root.join("index") }
    pub fn alerts(&self) -> PathBuf { self.root.join("index").join("alerts.tsv") }

    pub fn api_sock(&self) -> PathBuf { self.run.join("api.sock") }
    pub fn unseal_sock(&self) -> PathBuf { self.run.join("unseal.sock") }
    pub fn sessions(&self) -> PathBuf { self.run.join("sessions") }
    pub fn session_dir(&self, id: &str) -> PathBuf { self.sessions().join(id) }
    pub fn live(&self) -> PathBuf { self.run.join("live") }
    pub fn motd(&self) -> PathBuf { self.run.join("motd") }
}

pub fn libexec(name: &str) -> PathBuf {
    std::env::var_os("SWRAP_LIBEXEC").map(PathBuf::from).unwrap_or_else(|| LIBEXEC.into()).join(name)
}

/// Reject anything that is not a plain, safe path component (labels, user names, ids).
pub fn safe_component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s != "."
        && s != ".."
        && !s.starts_with('-')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

pub fn exists(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok()
}

/// Node role from `/etc/swrap/role` (`edge` on the public node; absent or `core` on core).
pub fn is_edge() -> bool {
    std::env::var("SWRAP_ROLE").map(|r| r == "edge").unwrap_or_else(|_| {
        std::fs::read_to_string("/etc/swrap/role").map(|s| s.trim() == "edge").unwrap_or(false)
    })
}

/// Edge-side paths (spec 7.2).
impl Paths {
    pub fn spool(&self) -> PathBuf { self.root.join("spool") }
    pub fn snapshot_dir(&self) -> PathBuf { self.root.join("snapshot") }
    /// Created by sshd as `swrap-link`, so they live in a directory that user owns.
    pub fn link_dir(&self) -> PathBuf { self.run.join("link") }
    pub fn core_api(&self) -> PathBuf { self.link_dir().join("core-api.sock") }
    pub fn core_pty(&self) -> PathBuf { self.link_dir().join("core-pty.sock") }
    pub fn core_web(&self) -> PathBuf { self.link_dir().join("core-web.sock") }
    /// Core-side sockets the link forwards to.
    pub fn edge_api_sock(&self) -> PathBuf { self.run.join("edge-api.sock") }
    pub fn edge_pty_sock(&self) -> PathBuf { self.run.join("edge-pty.sock") }
    /// Owned by swrap-web (runs as `swrap`), hence its own directory.
    pub fn ingress_web_sock(&self) -> PathBuf { self.run.join("web").join("ingress-web.sock") }
}

/// Where the documentation (README quickstart + spec) is installed on every node.
pub const DOC_DIR: &str = "/usr/share/doc/swrap";

/// Give an AAA user `~/swrap-docs` → the installed docs (always current after upgrades).
/// Never replaces anything the user created under that name.
pub fn ensure_docs_link(home: &Path, uid: u32, gid: u32) {
    let l = home.join("swrap-docs");
    if std::fs::symlink_metadata(&l).is_err() && home.is_dir() {
        if std::os::unix::fs::symlink(DOC_DIR, &l).is_ok() {
            let _ = std::os::unix::fs::lchown(&l, Some(uid), Some(gid));
        }
    }
}
