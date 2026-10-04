//! `swrap-install core`: idempotent installer for the core node (spec 5.1, 7.1, 12, 14, 17).
//!
//! Deliberate deviations for a machine that is also administered as root over SSH with a password:
//! * sshd `AllowGroups` also admits group `root`, and the PAM change only diverts members of
//!   `swrap-admin` to swrap-pam-unlock; every other account keeps the system `password-auth`.

use anyhow::{bail, Context, Result};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use swrap_core::atomic::{self, Owner};
use swrap_core::Paths;

const LIBEXEC: &str = "/usr/libexec/swrap";
const BINARIES: &[&str] = &["swrapd", "swrap", "swrap-shell", "swrap-pam-unlock", "swrec", "swrap-web"];
const LINKS: &[&str] = &[
    "swrap", "sw", "swai", "swls", "swlog", "swcat", "swplay", "swsearch", "swupdate", "swinv", "swr", "swx", "swpasswd", "swunlock", "swadm", "swadd", "swenroll", "swdel", "swuser", "swrotate", "swcrypto", "swfw", "swedge", "swrap-install",
];

/// Documentation shipped inside the binary, so every node (and every edge deploy) has it.
pub(crate) const DOC_README: &str = include_str!("../../../README.md");
pub(crate) const DOC_SPEC: &str = include_str!("../../../docs/aaa.md");

pub(crate) fn install_docs() -> Result<()> {
    let dir = Path::new(swrap_core::paths::DOC_DIR);
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
    atomic::write(&dir.join("README.md"), DOC_README.as_bytes(), 0o644, Owner::NONE)?;
    atomic::write(&dir.join("aaa.md"), DOC_SPEC.as_bytes(), 0o644, Owner::NONE)?;
    let _ = Command::new("restorecon").arg("-R").arg(dir).output();
    Ok(())
}

fn sh(cmd: &str, args: &[&str]) -> Result<String> {
    let o = Command::new(cmd).args(args).output().with_context(|| format!("spawn {cmd}"))?;
    if !o.status.success() {
        bail!("{cmd} {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

fn ok(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd).args(args).output().map(|o| o.status.success()).unwrap_or(false)
}

fn step(s: &str) {
    println!("==> {s}");
}

pub const PROFILES: &[(&str, &str)] = &[
    ("modern", r#"name = "modern"
ssh_bin = "/usr/bin/ssh"
ssh_keygen_bin = "/usr/bin/ssh-keygen"
kex = ["mlkem768x25519-sha256", "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com", "curve25519-sha256"]
ciphers = ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com"]
macs = ["hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com"]
host_key_algorithms = ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256"]
key_preference = ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512"]
rsa_bits = 4096
extra_options = { ServerAliveInterval = "30", ServerAliveCountMax = "4" }
"#),
    ("compat", r#"name = "compat"
ssh_bin = "/usr/bin/ssh"
ssh_keygen_bin = "/usr/bin/ssh-keygen"
kex = ["mlkem768x25519-sha256", "sntrup761x25519-sha512@openssh.com", "curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "diffie-hellman-group16-sha512"]
ciphers = ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr"]
macs = ["hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512", "hmac-sha2-256"]
host_key_algorithms = ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256"]
key_preference = ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512"]
rsa_bits = 4096
extra_options = { ServerAliveInterval = "30", ServerAliveCountMax = "4" }
"#),
    ("legacy", r#"name = "legacy"
ssh_bin = "/usr/bin/ssh"
ssh_keygen_bin = "/usr/bin/ssh-keygen"
warn = true
kex = ["curve25519-sha256", "ecdh-sha2-nistp256", "diffie-hellman-group16-sha512", "diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1"]
ciphers = ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr", "aes128-ctr"]
macs = ["hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512", "hmac-sha2-256", "hmac-sha1"]
host_key_algorithms = ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]
key_preference = ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "ssh-rsa"]
rsa_bits = 4096
extra_options = { ServerAliveInterval = "30", ServerAliveCountMax = "4" }
"#),
    ("inbound", r#"name = "inbound"
ssh_bin = "/usr/bin/ssh"
ssh_keygen_bin = "/usr/bin/ssh-keygen"
kex = ["mlkem768x25519-sha256", "sntrup761x25519-sha512@openssh.com", "curve25519-sha256"]
ciphers = ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com"]
macs = ["hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com"]
host_key_algorithms = ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256"]
key_preference = ["ssh-ed25519", "sk-ssh-ed25519@openssh.com", "ecdsa-sha2-nistp256", "sk-ecdsa-sha2-nistp256@openssh.com", "rsa-sha2-512", "rsa-sha2-256"]
rsa_bits = 4096
"#),
    ("link", r#"name = "link"
ssh_bin = "/usr/bin/ssh"
ssh_keygen_bin = "/usr/bin/ssh-keygen"
kex = ["mlkem768x25519-sha256", "sntrup761x25519-sha512@openssh.com", "curve25519-sha256"]
ciphers = ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"]
macs = ["hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com"]
host_key_algorithms = ["ssh-ed25519"]
key_preference = ["ssh-ed25519"]
rsa_bits = 4096
extra_options = { ServerAliveInterval = "15", ExitOnForwardFailure = "yes" }
"#),
];

fn swrap_toml(lan: &str, egress: &str, tls_bind: &str) -> String {
    format!(
        r#"# swrap core configuration (spec section 23). All times ISO 8601.
[general]
display_timezone = "UTC"
default_profile = "modern"
enroll_key_ttl = "P14D"

[network]
internal_networks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"]
core_egress_addresses = [{egress}]
from_restriction = true
lan_cidrs = ["{lan}"]
managed_ports = [22]

[rec]
coalesce = "PT0.005S"
coalesce_max_bytes = 16384
sync_interval = "PT1S"
checkpoint_interval = "PT10S"
checkpoint_bytes = 262144

[retention]
high_watermark_pct = 90
low_watermark_pct = 85
check_interval = "PT1M"
compress_after = "P7D"
gzip_member_bytes = 262144
alert_if_evicting_younger_than = "P30D"

[limits]
sessions_per_user = 10
sessions_core = 100

[inventory]
interval = "PT6H"
host_timeout = "PT2M"
parallel = 8

[fleet]
parallel = 8
default_timeout = "PT10M"

[signing]
max_signatures_per_session = 4
window = "PT2M"
require_hostbound = false

[web]
bind = ["unix:/run/swrap/web.sock", "{tls_bind}"]
tls_cert = "/etc/swrap/tls/cert.pem"
tls_key = "/etc/swrap/tls/key.pem"
session_lifetime = "PT12H"
search_default_window = "P1D/now"
search_max_results = 1000

[vault]
argon2_m_kib = 262144
argon2_t = 3
argon2_p = 1
"#
    )
}

const UNIT: &str = r#"[Unit]
Description=swrap core daemon (vault, RBAC, sessions, records)
After=network-online.target
Wants=network-online.target
RequiresMountsFor=/var/lib/swrap

[Service]
ExecStart=/usr/libexec/swrap/swrapd
# Live session workers survive a daemon restart (spec 9.1).
KillMode=process
Restart=on-failure
RestartSec=2
LimitCORE=0
UMask=0027
Slice=swrap.slice

[Install]
WantedBy=multi-user.target
"#;

const REPLICA_SERVICE: &str = r#"[Unit]
Description=swrap: keep the rebuild kit and a data backup on both disks
After=swrapd.service

[Service]
Type=oneshot
ExecStart=/usr/libexec/swrap/swrap replica sync
Nice=10
IOSchedulingClass=idle
"#;

const REPLICA_TIMER: &str = r#"[Unit]
Description=swrap replica sync every PT15M

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
"#;

const WEB_SERVICE: &str = r#"[Unit]
Description=swrap web GUI (playback and search)
After=swrapd.service network-online.target
RequiresMountsFor=/var/lib/swrap

[Service]
ExecStart=/usr/libexec/swrap/swrap-web
User=swrap
Group=swrap
SupplementaryGroups=swrap-admin
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadOnlyPaths=/var/lib/swrap
ReadWritePaths=/run/swrap
Restart=on-failure
LimitCORE=0
Slice=swrap.slice

[Install]
WantedBy=multi-user.target
"#;

const SLICE: &str = r#"[Unit]
Description=swrap services and sessions

[Slice]
CPUWeight=100
"#;

const TMPFILES: &str = "d /run/swrap 0755 root root -\nd /run/swrap/web 0750 swrap swrap -\nd /run/motd.d 0755 root root -\nL+ /run/motd.d/50-swrap - - - - /run/swrap/motd\n";

const SYSCTL: &str = "# swrap: spec 5.1 hardening\nkernel.yama.ptrace_scope = 2\n";

const SSHD_GLOBAL: &str = r#"# managed by swrap-install (spec 17). Global options; first value wins.
PerSourcePenalties yes
LogLevel VERBOSE
MaxStartups 10:30:60
MaxSessions 10
PermitTunnel no
# swrap AAA users and the link user; `root` stays admitted so this VM's console-style root login keeps working.
AllowGroups swrap-users swrap-link root
# SFTP (spec 11): admins and non-swrap accounts get sftp-server, AAA users the host directories.
Subsystem sftp /usr/libexec/swrap/sftp-dispatch
"#;

const SSHD_MATCH: &str = r#"# managed by swrap-install (spec 14.2, 17). Kept last so the Match blocks cannot capture other files' options.
Match Group swrap-admin
    AuthenticationMethods publickey,keyboard-interactive:pam
    KbdInteractiveAuthentication yes
    AuthorizedKeysFile /etc/ssh/authorized_keys/%u
    AllowTcpForwarding no
    AllowAgentForwarding no
    AllowStreamLocalForwarding no
    X11Forwarding no
    PermitTunnel no
    PermitUserRC no
Match Group swrap-users
    AuthenticationMethods publickey
    AuthorizedKeysFile /etc/ssh/authorized_keys/%u
    AllowTcpForwarding no
    AllowAgentForwarding no
    AllowStreamLocalForwarding no
    X11Forwarding no
    PermitTunnel no
    PermitUserRC no
"#;

pub(crate) const PAM_MARK: &str = "# swrap: admins";

// Layout found empirically with libpam (see git history). Constraints:
// * sshd runs keyboard-interactive auth in a forked helper and pam_setcred on a *fresh* handle in
//   the parent; there pam_succeed_if and pam_exec return PAM_IGNORE, and libpam mishandles
//   jumps taken on PAM_IGNORE, so no line may jump on `ignore`.
// * pam_faillock only persists an `authfail` record when that line ends the stack with `die`.
// * `authfail` returns success in the setcred phase: that success skips the safety pam_deny.
// * The leading optional pam_permit gives the setcred phase a success base; it cannot grant
//   authentication by itself because every path ends in `done`/`die` or in password-auth.
pub(crate) fn pam_sshd(orig: &str) -> String {
    let block = format!(
        "{PAM_MARK} (group swrap-admin) authenticate the second factor against the vault; everyone else keeps password-auth\n\
auth       optional     pam_permit.so\n\
auth       [success=5 default=ignore] pam_succeed_if.so quiet user notingroup swrap-admin\n\
auth       required     pam_faillock.so preauth silent\n\
auth       [success=2 ignore=ignore default=bad] pam_exec.so type=auth expose_authtok quiet {LIBEXEC}/swrap-pam-unlock\n\
auth       [success=1 default=die] pam_faillock.so authfail\n\
auth       requisite    pam_deny.so\n\
auth       [success=done ignore=ignore default=die] pam_faillock.so authsucc\n"
    );
    let mut out = String::new();
    let mut inserted = false;
    for l in orig.lines() {
        if !inserted && l.trim_start().starts_with("auth") {
            out.push_str(&block);
            inserted = true;
        }
        out.push_str(l);
        out.push('\n');
    }
    out
}

fn random_password() -> String {
    use rand::Rng;
    let mut r = rand::thread_rng();
    let a = b"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    (0..4).map(|_| (0..5).map(|_| a[r.gen_range(0..a.len())] as char).collect::<String>()).collect::<Vec<_>>().join("-")
}

fn daemon_admin(args: &[&str], stdin: Option<&str>) -> Result<swrap_core::api::Resp> {
    let req = swrap_core::api::Req::Admin { cmd: args[0].into(), args: args[1..].iter().map(|s| s.to_string()).collect(), stdin: stdin.map(String::from) };
    crate::client::call(&req)
}

const AI_TOML: &str = r#"# swai: inference backends and limits (spec 24.6, 24.7).
# API keys are never stored here: swai backend key <name> puts them in the vault
# (only for api = "anthropic" backends; "claude" uses your Claude plan's login).
# Users add OpenAI-compatible servers by IP from the swai menu ("add new IP").

# Claude Code signed in with your Claude plan (Pro/Max): log in once inside swai.
[[backend]]
name = "claude"
api = "claude-code"
base_url = "https://api.anthropic.com"
timeout = "PT30M"

[limits]
concurrent_calls = 4     # tool calls per user in flight
calls_per_hour = 600     # tool calls per user per PT1H
max_tool_calls = 500     # tool calls per swai session
sessions_per_user = 4
approval = "ask"         # exec/write_file/edit_file need a yes in the TUI; "allow" to skip
host_context = 200000    # context cap for one-host sessions (they compact earlier)
detached_timeout = "P7D" # a session nobody is attached to ends after this
"#;

/// Pinned opencode (the swai TUI). Verified by sha256 when downloaded; the rebuild kits carry
/// the installed copy (`bin/opencode/`), so a rebuild needs no network.
const OPENCODE_VERSION: &str = "1.18.32";
const OPENCODE_URL: &str = "https://github.com/anomalyco/opencode/releases/download/v1.18.32/opencode-linux-x64.tar.gz";
const OPENCODE_TGZ_SHA256: &str = "3046e0404fdc60fb80307e7a47824ba07477364178a4d09baa8548496dd6d43b";

/// Claude Code, the swai harness for `claude-code` backends (signed in with a Claude plan).
/// Install pins a known version; `swrap claude-code-update` (nightly timer) then follows
/// Anthropic's "latest" channel. Each version lives in `v/<version>/`; `claude` links to the
/// current one, and a session mounts the version it started with, so an update never swaps
/// the binary under a running session.
const CLAUDE_VERSION: &str = "2.1.274";
const CLAUDE_SHA256: &str = "15e2d05148f801b5774032faad87e624ecd172e9903288bda448b892eb58fa07";
const CLAUDE_RELEASES: &str = "https://downloads.claude.ai/claude-code-releases";
/// "Anthropic Claude Code Release Signing <security@anthropic.com>", from
/// https://downloads.claude.ai/keys/claude-code.asc; it signs each release's manifest.
const CLAUDE_SIGNING_FPR: &str = "31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE";
const CLAUDE_SIGNING_KEY: &str = include_str!("../assets/claude-code-release.asc");
/// A superseded version is removed this long after the update (swai's detached sessions end
/// after P7D, so no session still runs it).
const CLAUDE_KEEP_DAYS: u64 = 8;

const CLAUDE_UPDATE_SERVICE: &str = r#"[Unit]
Description=swrap: update Claude Code (the swai harness) from Anthropic's latest channel
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/libexec/swrap/swrap claude-code-update
Nice=10
"#;

const CLAUDE_UPDATE_TIMER: &str = r#"[Unit]
Description=swrap: nightly Claude Code update

[Timer]
OnCalendar=*-*-* 03:30:00
RandomizedDelaySec=45min
Persistent=true

[Install]
WantedBy=timers.target
"#;

fn ver_key(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.trim().split('.').map(|x| x.parse::<u64>().ok());
    let k = (it.next()??, it.next()??, it.next()??);
    it.next().is_none().then_some(k)
}

fn claude_installed(dir: &Path) -> Option<String> {
    let v = std::fs::read_to_string(dir.join("VERSION")).ok()?.trim().to_string();
    (dir.join("claude").exists() && ver_key(&v).is_some()).then_some(v)
}

fn sha256_of(p: &Path) -> Result<String> {
    Ok(sh("sha256sum", &[&p.to_string_lossy()])?.split_whitespace().next().unwrap_or("").to_string())
}

/// The newest models (two per family) a Claude Code binary knows, as `id\tname` lines, so
/// swai can offer them next to the aliases.
fn claude_models(bin: &Path) -> String {
    let Ok(data) = std::fs::read(bin) else { return String::new() };
    let mut found: std::collections::BTreeMap<&str, std::collections::BTreeSet<(u64, u64)>> = Default::default();
    let fams: [&str; 4] = ["opus", "sonnet", "fable", "haiku"];
    let num = |d: &[u8], i: &mut usize| -> Option<u64> {
        let st = *i;
        while *i < d.len() && d[*i].is_ascii_digit() {
            *i += 1;
        }
        (*i > st && *i - st <= 3).then(|| std::str::from_utf8(&d[st..*i]).ok()?.parse().ok()).flatten()
    };
    let mut at = 0;
    while let Some(off) = data[at..].windows(7).position(|w| w == b"claude-") {
        let mut i = at + off + 7;
        at = i;
        let Some(fam) = fams.iter().find(|f| data[i..].starts_with(f.as_bytes()) && data.get(i + f.len()) == Some(&b'-')) else { continue };
        i += fam.len() + 1;
        let Some(major) = num(&data, &mut i) else { continue };
        let mut minor = 0;
        if data.get(i) == Some(&b'-') && data.get(i + 1).is_some_and(u8::is_ascii_digit) {
            let mut j = i + 1;
            match num(&data, &mut j) {
                Some(m) if m < 10 => { minor = m; i = j; }
                _ => continue, // a dated snapshot id, or not a model
            }
        }
        if data.get(i).is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'.') {
            continue;
        }
        found.entry(fam).or_default().insert((major, minor));
    }
    let mut out = String::new();
    for fam in fams {
        let Some(vs) = found.get(fam) else { continue };
        for &(ma, mi) in vs.iter().rev().take(2) {
            let (id, v) = if mi == 0 { (format!("claude-{fam}-{ma}"), format!("{ma}")) } else { (format!("claude-{fam}-{ma}-{mi}"), format!("{ma}.{mi}")) };
            let name = format!("{}{} {v}", fam[..1].to_uppercase(), &fam[1..]);
            out += &format!("{id}\t{name}\n");
        }
    }
    out
}

/// Put a verified binary in place as the current version (atomic switch of the `claude` link).
fn place_claude(dst: &Path, ver: &str, bin: &Path, sha: &str) -> Result<()> {
    let vdir = dst.join("v").join(ver);
    std::fs::create_dir_all(&vdir)?;
    for d in [dst.to_path_buf(), dst.join("v"), vdir.clone()] {
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755))?;
    }
    let new = vdir.join(".claude.new");
    std::fs::copy(bin, &new)?;
    std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755))?;
    std::fs::File::open(&new)?.sync_all()?;
    std::fs::rename(&new, vdir.join("claude"))?;
    atomic::write(&vdir.join("SHA256"), format!("{sha}\n").as_bytes(), 0o644, Owner::NONE)?;
    let models = claude_models(&vdir.join("claude"));
    atomic::write(&vdir.join("MODELS"), models.as_bytes(), 0o644, Owner::NONE)?;
    // The version it replaces starts its grace period.
    if let Some(old) = claude_installed(dst).filter(|o| o != ver) {
        let od = dst.join("v").join(&old);
        if od.is_dir() {
            let _ = std::fs::write(od.join(".superseded"), "");
        }
    }
    let lnk = dst.join(".claude.lnk");
    let _ = std::fs::remove_file(&lnk);
    std::os::unix::fs::symlink(format!("v/{ver}/claude"), &lnk)?;
    std::fs::rename(&lnk, dst.join("claude"))?;
    atomic::write(&dst.join("MODELS"), models.as_bytes(), 0o644, Owner::NONE)?;
    atomic::write(&dst.join("VERSION"), format!("{ver}\n").as_bytes(), 0o644, Owner::NONE)?;
    swrap_core::atomic::fsync_dir(dst)?;
    let _ = sh("restorecon", &["-R", &dst.to_string_lossy()]);
    // Remove versions superseded long enough ago that no session can still run them.
    if let Ok(rd) = std::fs::read_dir(dst.join("v")) {
        for e in rd.flatten() {
            let mark = e.path().join(".superseded");
            let old = std::fs::metadata(&mark).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).map(|a| a.as_secs() > CLAUDE_KEEP_DAYS * 86400).unwrap_or(false);
            if old && e.file_name() != std::ffi::OsStr::new(ver) {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
    Ok(())
}

fn install_claude_code(from: &Path) -> Result<()> {
    let dst = Path::new(LIBEXEC).join("claude-code");
    let pinned = ver_key(CLAUDE_VERSION);
    // A newer version from the nightly update stays: install never downgrades it.
    if let Some(v) = claude_installed(&dst).filter(|v| ver_key(v) >= pinned) {
        println!("    Claude Code {v} present");
        return Ok(());
    }
    // A rebuild kit carries what the nightly update installed, with its checksum.
    let kit = from.join("claude-code");
    if kit != dst {
        if let Some(v) = claude_installed(&kit).filter(|v| ver_key(v) >= pinned) {
            let want = std::fs::read_to_string(kit.join("v").join(&v).join("SHA256")).map(|s| s.trim().to_string()).unwrap_or_else(|_| if v == CLAUDE_VERSION { CLAUDE_SHA256.into() } else { String::new() });
            let bin = kit.join("claude");
            if !want.is_empty() && sha256_of(&bin)? == want {
                place_claude(&dst, &v, &bin, &want)?;
                println!("    Claude Code {v} from {}", kit.display());
                return Ok(());
            }
            println!("    Claude Code in {} does not match its checksum; downloading", kit.display());
        }
    }
    let tmp = PathBuf::from(format!("/var/tmp/swrap-claude.{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    let res = (|| -> Result<()> {
        let bin = tmp.join("claude");
        let url = format!("{CLAUDE_RELEASES}/{CLAUDE_VERSION}/linux-x64/claude");
        sh("curl", &["-fsSL", "--retry", "3", "-o", &bin.to_string_lossy(), &url]).context("download Claude Code")?;
        let sum = sha256_of(&bin)?;
        if sum != CLAUDE_SHA256 {
            bail!("Claude Code binary failed verification (sha256 {sum})");
        }
        place_claude(&dst, CLAUDE_VERSION, &bin, CLAUDE_SHA256)?;
        println!("    Claude Code {CLAUDE_VERSION} downloaded, sha256 verified");
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    res
}

fn claude_update_timer() -> Result<()> {
    atomic::write(Path::new("/etc/systemd/system/swrap-claude-update.service"), CLAUDE_UPDATE_SERVICE.as_bytes(), 0o644, Owner::NONE)?;
    atomic::write(Path::new("/etc/systemd/system/swrap-claude-update.timer"), CLAUDE_UPDATE_TIMER.as_bytes(), 0o644, Owner::NONE)?;
    let _ = sh("restorecon", &["/etc/systemd/system/swrap-claude-update.service", "/etc/systemd/system/swrap-claude-update.timer"]);
    sh("systemctl", &["daemon-reload"])?;
    sh("systemctl", &["enable", "--now", "swrap-claude-update.timer"])?;
    Ok(())
}

/// `swrap claude-code-update [--check] [--install-timer]`: follow Anthropic's latest channel.
/// A new version is installed only if its manifest carries a valid signature by Anthropic's
/// release key (pinned fingerprint), the binary matches the manifest's sha256 and size, and it
/// starts and reports that version.
pub fn claude_update(args: Vec<String>) -> Result<i32> {
    if !nix::unistd::Uid::effective().is_root() {
        bail!("claude-code-update must run as root");
    }
    let check = args.iter().any(|a| a == "--check");
    if args.iter().any(|a| a == "--install-timer") {
        claude_update_timer()?;
        println!("swrap-claude-update.timer enabled (nightly, 03:30 + up to 45 min)");
        return Ok(0);
    }
    if let Some(a) = args.iter().find(|a| !matches!(a.as_str(), "--check")) {
        bail!("unknown argument {a} (usage: swrap claude-code-update [--check] [--install-timer])");
    }
    let dst = Path::new(LIBEXEC).join("claude-code");
    let installed = claude_installed(&dst);
    let latest = sh("curl", &["-fsSL", "--retry", "3", "-m", "60", &format!("{CLAUDE_RELEASES}/latest")]).context("ask for the latest Claude Code version")?.trim().to_string();
    if ver_key(&latest).is_none() {
        bail!("unexpected latest version {latest:?}");
    }
    if installed.as_deref().and_then(ver_key) >= ver_key(&latest) {
        println!("Claude Code {} is current (latest {latest})", installed.unwrap_or_default());
        return Ok(0);
    }
    if check {
        println!("Claude Code {} installed; {latest} available", installed.as_deref().unwrap_or("none"));
        return Ok(0);
    }
    let tmp = PathBuf::from(format!("/var/tmp/swrap-claude-update.{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("gnupg"))?;
    std::fs::create_dir_all(tmp.join("home"))?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700))?;
    std::fs::set_permissions(tmp.join("gnupg"), std::fs::Permissions::from_mode(0o700))?;
    let res = (|| -> Result<()> {
        let t = |f: &str| tmp.join(f).to_string_lossy().to_string();
        let get = |url: String, to: String| sh("curl", &["-fsSL", "--retry", "3", "-m", "900", "-o", &to, &url]);
        get(format!("{CLAUDE_RELEASES}/{latest}/manifest.json"), t("manifest.json"))?;
        get(format!("{CLAUDE_RELEASES}/{latest}/manifest.json.sig"), t("manifest.json.sig"))?;
        std::fs::write(tmp.join("key.asc"), CLAUDE_SIGNING_KEY)?;
        let home = t("gnupg");
        sh("gpg", &["--homedir", &home, "--batch", "--quiet", "--import", &t("key.asc")])?;
        let st = Command::new("gpg").args(["--homedir", &home, "--batch", "--status-fd", "1", "--verify", &t("manifest.json.sig"), &t("manifest.json")]).output()?;
        let _ = Command::new("gpgconf").args(["--homedir", &home, "--kill", "all"]).output();
        let status = String::from_utf8_lossy(&st.stdout);
        let signed = st.status.success() && status.lines().any(|l| l.starts_with("[GNUPG:] VALIDSIG ") && l.split_whitespace().last() == Some(CLAUDE_SIGNING_FPR));
        if !signed {
            bail!("the {latest} manifest is not signed by Anthropic's Claude Code release key");
        }
        let m: serde_json::Value = serde_json::from_slice(&std::fs::read(tmp.join("manifest.json"))?)?;
        let plat = &m["platforms"]["linux-x64"];
        let (sha, size) = (plat["checksum"].as_str().unwrap_or(""), plat["size"].as_u64().unwrap_or(0));
        if m["version"].as_str() != Some(latest.as_str()) || sha.len() != 64 || size == 0 {
            bail!("the {latest} manifest does not describe a linux-x64 build of {latest}");
        }
        get(format!("{CLAUDE_RELEASES}/{latest}/linux-x64/claude"), t("claude"))?;
        let bin = tmp.join("claude");
        if std::fs::metadata(&bin)?.len() != size || sha256_of(&bin)? != sha {
            bail!("the downloaded Claude Code {latest} does not match its signed manifest");
        }
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))?;
        let out = Command::new("timeout").args(["60", &t("claude"), "--version"]).env_clear().env("HOME", t("home")).env("PATH", "/usr/bin:/bin").env("DISABLE_AUTOUPDATER", "1").output()?;
        if !String::from_utf8_lossy(&out.stdout).contains(latest.as_str()) {
            bail!("Claude Code {latest} did not start: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        place_claude(&dst, &latest, &bin, sha)?;
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    res?;
    println!("Claude Code {} -> {latest} (signature, sha256 and a test run verified); running sessions keep their version", installed.as_deref().unwrap_or("none"));
    Ok(0)
}

fn install_opencode(from: &Path) -> Result<()> {
    let dst = Path::new(LIBEXEC).join("opencode");
    let current = |d: &Path| d.join("opencode").exists() && std::fs::read_to_string(d.join("VERSION")).map(|v| v.trim() == OPENCODE_VERSION).unwrap_or(false);
    if current(&dst) {
        println!("    opencode {OPENCODE_VERSION} present");
        return Ok(());
    }
    let tmp = PathBuf::from(format!("/var/tmp/swrap-opencode.{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    let res = (|| -> Result<()> {
        let kit = from.join("opencode");
        if current(&kit) && kit != dst {
            std::fs::copy(kit.join("opencode"), tmp.join("opencode"))?;
            println!("    opencode {OPENCODE_VERSION} from {}", kit.display());
        } else {
            let tgz = tmp.join("opencode.tar.gz");
            sh("curl", &["-fsSL", "--retry", "3", "-o", &tgz.to_string_lossy(), OPENCODE_URL]).context("download opencode")?;
            let sum = sh("sha256sum", &[&tgz.to_string_lossy()])?;
            if sum.split_whitespace().next() != Some(OPENCODE_TGZ_SHA256) {
                bail!("opencode download failed verification (sha256 {})", sum.split_whitespace().next().unwrap_or("?"));
            }
            sh("tar", &["-xzf", &tgz.to_string_lossy(), "-C", &tmp.to_string_lossy(), "opencode"])?;
            println!("    opencode {OPENCODE_VERSION} downloaded, sha256 verified");
        }
        std::fs::create_dir_all(&dst)?;
        std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755))?;
        let new = dst.join(".opencode.new");
        std::fs::copy(tmp.join("opencode"), &new)?;
        std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755))?;
        std::fs::rename(&new, dst.join("opencode"))?;
        std::fs::write(dst.join("VERSION"), format!("{OPENCODE_VERSION}\n"))?;
        let _ = sh("restorecon", &["-R", &dst.to_string_lossy()]);
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    res
}

pub fn main(args: Vec<String>) -> Result<i32> {
    if args.first().map(String::as_str) == Some("edge") {
        return crate::install_edge::main(args[1..].to_vec());
    }
    if args.first().map(String::as_str) == Some("selinux") {
        // Only the policy module: `--enforce` drops the `swrap:permissive` lines, `--permissive`
        // (the default) keeps them.
        if !nix::unistd::geteuid().is_root() {
            bail!("run as root");
        }
        let enforce = match args.get(1).map(String::as_str) {
            Some("--enforce") => true,
            None | Some("--permissive") => false,
            Some(o) => bail!("usage: swrap install selinux [--enforce|--permissive] (got {o})"),
        };
        crate::install_selinux::install(enforce)?;
        return Ok(0);
    }
    let mut role = None;
    let mut from = None;
    let mut admin_key = None;
    let mut egress = String::new();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "core" => role = Some("core"),
            "edge" => bail!("edge installation comes with the edge node (not built yet)"),
            "--from" => from = it.next(),
            "--admin-key" => admin_key = it.next(),
            "--egress" => egress = it.next().unwrap_or_default(),
            "-h" | "--help" => {
                println!("usage: swrap-install core [--from <dir with built binaries>] [--admin-key '<ssh pubkey>'] [--egress <public IP>]");
                return Ok(0);
            }
            o => bail!("unknown argument {o}"),
        }
    }
    if role.is_none() {
        bail!("usage: swrap-install core …");
    }
    if !nix::unistd::geteuid().is_root() {
        bail!("run as root");
    }
    let paths = Paths::from_env();
    let from = PathBuf::from(from.unwrap_or_else(|| std::env::current_exe().unwrap().parent().unwrap().to_string_lossy().into()));

    step("groups and service account");
    for g in ["swrap-users", "swrap-admin", "swrap-link"] {
        if swrap_core::sys::gid_of_group(g).is_none() {
            sh("groupadd", &["-r", g])?;
        }
    }
    if swrap_core::sys::user_by_name("swrap").is_none() {
        sh("useradd", &["-r", "-U", "-d", "/var/lib/swrap", "-M", "-s", "/sbin/nologin", "-c", "swrap service", "swrap"])?;
    }
    let (uid, gid) = swrap_core::sys::swrap_ids().context("swrap user")?;
    let admin_gid = swrap_core::sys::gid_of_group("swrap-admin").unwrap();
    let own = Owner::new(uid, gid);
    let own_adm = Owner::new(uid, admin_gid);

    step("binaries");
    std::fs::create_dir_all(LIBEXEC)?;
    for b in BINARIES {
        let src = from.join(b);
        if !src.exists() {
            if *b == "swrap-web" {
                continue;
            }
            bail!("missing binary {}", src.display());
        }
        let dst = Path::new(LIBEXEC).join(b);
        let tmp = Path::new(LIBEXEC).join(format!(".{b}.new"));
        std::fs::copy(&src, &tmp)?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
        std::fs::rename(&tmp, &dst)?;
    }
    for l in LINKS {
        let p = Path::new("/usr/bin").join(l);
        let _ = std::fs::remove_file(&p);
        std::os::unix::fs::symlink(Path::new(LIBEXEC).join("swrap"), &p)?;
    }
    let _ = std::fs::remove_file("/usr/bin/swrec");
    std::os::unix::fs::symlink(Path::new(LIBEXEC).join("swrec"), "/usr/bin/swrec")?;
    // sshd's sftp subsystem (06-swrap.conf).
    let _ = std::fs::remove_file(Path::new(LIBEXEC).join("sftp-dispatch"));
    std::os::unix::fs::symlink("swrap", Path::new(LIBEXEC).join("sftp-dispatch"))?;
    let _ = sh("restorecon", &["-R", LIBEXEC]);
    if let Some(sh_path) = std::path::Path::new(LIBEXEC).join("swrap-shell").to_str() {
        let shells = std::fs::read_to_string("/etc/shells").unwrap_or_default();
        if !shells.lines().any(|l| l == sh_path) {
            std::fs::write("/etc/shells", format!("{shells}{sh_path}\n"))?;
        }
    }

    install_docs()?;
    println!("    documentation in {} (users get ~/swrap-docs)", swrap_core::paths::DOC_DIR);

    step("swai: sandbox user, bubblewrap, pinned opencode and Claude Code");
    if swrap_core::sys::user_by_name("swai").is_none() {
        sh("useradd", &["-r", "-U", "-d", "/nonexistent", "-M", "-s", "/sbin/nologin", "-c", "swai sandbox (opencode)", "swai"])?;
    }
    if !Path::new("/usr/bin/bwrap").exists() {
        sh("dnf", &["-y", "-q", "install", "bubblewrap"]).context("install bubblewrap")?;
    }
    install_opencode(&from)?;
    install_claude_code(&from)?;

    step("data layout on /var/lib/swrap");
    let mounted = sh("findmnt", &["-n", "-o", "SOURCE", "--target", &paths.root.to_string_lossy()]).unwrap_or_default();
    if !ok("mountpoint", &["-q", &paths.root.to_string_lossy()]) {
        println!("    WARNING: {} is not a dedicated mount (retention watermarks would measure the OS disk)", paths.root.display());
    } else {
        println!("    {} on {}", paths.root.display(), mounted.trim());
    }
    atomic::mkdirs(&paths.root, 0o750, own)?;
    std::os::unix::fs::chown(&paths.root, Some(uid), Some(gid))?;
    std::fs::set_permissions(&paths.root, std::fs::Permissions::from_mode(0o750))?;
    for (d, mode, o) in [
        (paths.config(), 0o750, own),
        (paths.config().join("profiles"), 0o750, own),
        (paths.config().join("hosts"), 0o750, own),
        (paths.config().join("users"), 0o750, own),
        (paths.config().join("known_hosts"), 0o750, own),
        (paths.vault(), 0o700, own),
        (paths.link(), 0o700, own),
        (paths.recsign(), 0o700, own),
        (paths.trust(), 0o750, own),
        (paths.root.join("secrets"), 0o700, own),
        (paths.root.join("secrets/webpw"), 0o700, own),
        (paths.state(), 0o750, own),
        (paths.rec(), 0o2750, own_adm),
        (paths.runs(), 0o2750, own_adm),
        (paths.logs(), 0o2750, own_adm),
        (paths.audit(), 0o2750, own_adm),
        (paths.index(), 0o750, own),
    ] {
        atomic::mkdirs(&d, mode, o)?;
    }
    for d in [paths.root.clone(), paths.rec(), paths.runs(), paths.logs(), paths.audit(), paths.state()] {
        let _ = sh("setfacl", &["-m", "g:swrap-admin:rx", &d.to_string_lossy()]);
    }
    let _ = sh("setfacl", &["-R", "-m", "g:swrap-users:rX,g:swrap-admin:rX", &paths.state().to_string_lossy()]);
    let _ = sh("setfacl", &["-R", "-d", "-m", "g:swrap-users:rX,g:swrap-admin:rX", &paths.state().to_string_lossy()]);
    let _ = sh("setfacl", &["-m", "g:swrap-users:x", &paths.root.to_string_lossy()]);
    // The swai sandbox user only traverses to its opencode homes (ai/home/<user>/<target>).
    let _ = sh("setfacl", &["-m", "u:swai:x", &paths.root.to_string_lossy()]);
    for d in [paths.runs(), paths.logs(), paths.audit()] {
        let _ = sh("setfacl", &["-d", "-m", "g:swrap-admin:rX", &d.to_string_lossy()]);
    }

    step("config repository (the database)");
    let repo = swrap_core::git::Repo::new(paths.config()).run_as(uid, gid);
    repo.init()?;
    let wcfg = |rel: &str, data: &str| -> Result<()> {
        let p = paths.config().join(rel);
        if !p.exists() {
            atomic::write(&p, data.as_bytes(), 0o640, own)?;
        }
        Ok(())
    };
    let lan = sh("ip", &["-4", "-o", "route", "show", "scope", "link"]).unwrap_or_default().split_whitespace().next().unwrap_or("192.168.1.0/24").to_string();
    let lan_ip = sh("ip", &["-4", "-o", "addr", "show", "scope", "global"]).unwrap_or_default().split_whitespace().nth(3).and_then(|s| s.split('/').next()).unwrap_or("0.0.0.0").to_string();
    let egress_list = if egress.is_empty() { String::new() } else { format!("\"{egress}\"") };
    wcfg("swrap.toml", &swrap_toml(&lan, &egress_list, &format!("{lan_ip}:443")))?;
    for (n, p) in PROFILES {
        wcfg(&format!("profiles/{n}.toml"), p)?;
    }
    wcfg("firewall.toml", "# web_allow / ssh_block entries are managed with swfw\n")?;
    wcfg("ai.toml", AI_TOML)?;
    for d in ["hosts", "users", "known_hosts"] {
        wcfg(&format!("{d}/.keep"), "")?;
    }
    repo.commit_all(&format!("{} swrap-install core", swrap_core::time::fmt_utc_secs(swrap_core::time::now())))?;
    let srepo = swrap_core::git::Repo::new(paths.state()).run_as(uid, gid);
    srepo.init()?;
    if !paths.state().join("summary.tsv").exists() {
        atomic::write(&paths.state().join("summary.tsv"), b"label\troute\tos\tkernel\tupdates\tsecurity\treboot\tlast_seen\tstatus\n", 0o644, own)?;
        srepo.commit_all(&format!("{} init", swrap_core::time::fmt_utc_secs(swrap_core::time::now())))?;
    }

    step("recording signing key");
    let kp = paths.recsign().join("ed25519.key");
    if !kp.exists() {
        let s = swrec::RecSigner::generate("core");
        atomic::write(&kp, s.private_text().as_bytes(), 0o600, own)?;
        atomic::write(&paths.recsign().join("ed25519.pub"), s.public_text().as_bytes(), 0o644, own)?;
    }
    let _ = sh("setfacl", &["-m", "g:swrap-users:x,g:swrap-admin:x", &paths.recsign().to_string_lossy()]);

    step("system integration (systemd, tmpfiles, sysctl, profile.d)");
    std::fs::create_dir_all("/etc/swrap")?;
    atomic::write(Path::new("/etc/systemd/system/swrapd.service"), UNIT.as_bytes(), 0o644, Owner::NONE)?;
    atomic::write(Path::new("/etc/systemd/system/swrap.slice"), SLICE.as_bytes(), 0o644, Owner::NONE)?;
    atomic::write(Path::new("/etc/systemd/system/swrap-replica.service"), REPLICA_SERVICE.as_bytes(), 0o644, Owner::NONE)?;
    atomic::write(Path::new("/etc/systemd/system/swrap-replica.timer"), REPLICA_TIMER.as_bytes(), 0o644, Owner::NONE)?;
    atomic::write(Path::new("/etc/tmpfiles.d/swrap.conf"), TMPFILES.as_bytes(), 0o644, Owner::NONE)?;
    atomic::write(Path::new("/etc/sysctl.d/90-swrap.conf"), SYSCTL.as_bytes(), 0o644, Owner::NONE)?;
    let snippet = sh(&format!("{LIBEXEC}/swrapd"), &["profile-snippet"])?;
    atomic::write(Path::new("/etc/profile.d/swrap.sh"), snippet.as_bytes(), 0o644, Owner::NONE)?;
    let _ = sh("restorecon", &["-R", "/etc/systemd/system/swrapd.service", "/etc/systemd/system/swrap.slice", "/etc/profile.d/swrap.sh", "/etc/sysctl.d/90-swrap.conf"]);
    sh("systemd-tmpfiles", &["--create", "/etc/tmpfiles.d/swrap.conf"])?;
    let _ = sh("sysctl", &["-q", "-p", "/etc/sysctl.d/90-swrap.conf"]);
    sh("systemctl", &["daemon-reload"])?;
    sh("systemctl", &["enable", "swrapd.service"])?;
    claude_update_timer()?;
    if Path::new("/usr/local/bin/rustic").exists() {
        sh("systemctl", &["enable", "--now", "swrap-replica.timer"])?;
    } else {
        println!("    WARNING: /usr/local/bin/rustic missing; replica timer not enabled");
    }
    let _ = std::fs::remove_file(paths.api_sock());
    sh("systemctl", &["restart", "swrapd.service"])?;
    let mut up = false;
    for _ in 0..100 {
        if std::os::unix::net::UnixStream::connect(paths.api_sock()).is_ok() {
            up = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if !up {
        bail!("swrapd did not come up; see journalctl -u swrapd");
    }

    step("vault");
    let secrets_file = PathBuf::from("/root/swrap-initial-secrets.txt");
    let st = daemon_admin(&["swadm", "vault", "status"], None)?;
    if st.text.contains("initialized: false") {
        let pw = std::env::var("SWRAP_ADMIN_PASSWORD").unwrap_or_else(|_| random_password());
        let r = daemon_admin(&["swadm", "vault", "init", "admin"], Some(&pw))?;
        if !r.ok {
            bail!("vault init: {}", r.error.unwrap_or_default());
        }
        let rec = r.text.lines().map(str::trim).find(|l| l.len() > 40 && l.contains('-')).unwrap_or("").to_string();
        let body = format!(
            "swrap initial secrets — generated {}\n\n\
             admin vault password (= SSH password of AAA user 'admin'):\n    {pw}\n\n\
             vault RECOVERY KEY (store offline, then delete this file):\n    {rec}\n\n\
             change the password with: swadm vault passwd   (logged in as admin)\n",
            swrap_core::time::fmt_display(swrap_core::time::now(), "UTC", false)
        );
        atomic::write(&secrets_file, body.as_bytes(), 0o600, Owner::new(0, 0))?;
        println!("    vault initialised; admin password and recovery key written to {} (0600)", secrets_file.display());
    } else {
        println!("    vault already initialised");
    }

    step("default AAA user (admin)");
    let users = daemon_admin(&["swadm", "user", "list"], None)?;
    if !users.text.lines().any(|l| l.starts_with("admin\t")) {
        let mut a = vec!["swadm", "user", "add", "admin", "--admin"];
        if let Some(k) = &admin_key {
            a.push("--key");
            a.push(k);
        }
        let r = daemon_admin(&a, None)?;
        println!("    {}", r.text.trim().lines().next().unwrap_or(r.error.as_deref().unwrap_or("")));
    }

    step("sshd and PAM (admins: key + vault password; users: key only; root unchanged)");
    atomic::write(Path::new("/etc/ssh/sshd_config.d/06-swrap.conf"), SSHD_GLOBAL.as_bytes(), 0o600, Owner::NONE)?;
    atomic::write(Path::new("/etc/ssh/sshd_config.d/99-swrap-match.conf"), SSHD_MATCH.as_bytes(), 0o600, Owner::NONE)?;
    let pam = std::fs::read_to_string("/etc/pam.d/sshd")?;
    if !pam.contains(PAM_MARK) && !Path::new("/etc/pam.d/sshd.swrap-orig").exists() {
        std::fs::write("/etc/pam.d/sshd.swrap-orig", &pam)?;
    }
    // Always regenerate from the pristine original so fixes to the swrap block apply on reinstall.
    let orig = std::fs::read_to_string("/etc/pam.d/sshd.swrap-orig")?;
    let want = pam_sshd(&orig);
    if want != pam {
        atomic::write(Path::new("/etc/pam.d/sshd"), want.as_bytes(), 0o644, Owner::NONE)?;
    }
    atomic::mkdirs(Path::new("/etc/ssh/authorized_keys"), 0o755, Owner::new(0, 0))?;
    let _ = sh("restorecon", &["-R", "/etc/ssh", "/etc/pam.d/sshd"]);
    match sh("sshd", &["-t"]) {
        Ok(_) => {
            // Effective config sanity: root keeps password auth, admins need key+password.
            let root = sh("sshd", &["-T", "-C", "user=root,host=x,addr=192.0.2.1"]).unwrap_or_default();
            if !root.lines().any(|l| l == "usepam yes") || !root.lines().any(|l| l == "authenticationmethods any") {
                bail!("sshd effective config for root changed unexpectedly; not reloading");
            }
            sh("systemctl", &["reload", "sshd"])?;
        }
        Err(e) => {
            let _ = std::fs::remove_file("/etc/ssh/sshd_config.d/06-swrap.conf");
            let _ = std::fs::remove_file("/etc/ssh/sshd_config.d/99-swrap-match.conf");
            bail!("sshd -t failed, drop-ins removed: {e}");
        }
    }

    step("web GUI (TLS, service, firewalld https)");
    std::fs::create_dir_all("/etc/swrap/tls")?;
    if !Path::new("/etc/swrap/tls/cert.pem").exists() {
        let host = swrap_core::sys::hostname();
        let mut sans = vec![host.clone()];
        if lan_ip != "0.0.0.0" {
            sans.push(lan_ip.clone());
        }
        let ck = rcgen::generate_simple_self_signed(sans).context("generate TLS certificate")?;
        atomic::write(Path::new("/etc/swrap/tls/cert.pem"), ck.cert.pem().as_bytes(), 0o644, Owner::NONE)?;
        atomic::write(Path::new("/etc/swrap/tls/key.pem"), ck.key_pair.serialize_pem().as_bytes(), 0o640, Owner::new(0, gid))?;
        println!("    self-signed certificate for {host} / {lan_ip} (replace /etc/swrap/tls/*.pem with your own)");
    }
    std::os::unix::fs::chown("/etc/swrap/tls/key.pem", Some(0), Some(gid))?;
    std::fs::set_permissions("/etc/swrap/tls/key.pem", std::fs::Permissions::from_mode(0o640))?;
    atomic::write(Path::new("/etc/systemd/system/swrap-web.service"), WEB_SERVICE.as_bytes(), 0o644, Owner::NONE)?;
    let _ = sh("restorecon", &["-R", "/etc/swrap", "/etc/systemd/system/swrap-web.service"]);
    if ok("systemctl", &["is-active", "-q", "firewalld"]) {
        let _ = sh("firewall-cmd", &["-q", "--permanent", "--add-service=https"]);
        let _ = sh("firewall-cmd", &["-q", "--reload"]);
    }
    sh("systemctl", &["daemon-reload"])?;
    sh("systemctl", &["enable", "swrap-web.service"])?;
    sh("systemctl", &["restart", "swrap-web.service"])?;
    println!("    https://{lan_ip}/ — allow your address first: swfw web allow <ip> --for PT8H");

    step("SELinux policy for swrap-pam-unlock");
    crate::install_selinux::install(crate::install_selinux::installed_mode().as_deref() == Some("enforcing"))?;

    step("rebuild kit on both disks (swrap replica sync)");
    match Command::new(format!("{LIBEXEC}/swrap")).args(["replica", "sync"]).status() {
        Ok(s) if s.success() => {}
        _ => println!("    WARNING: replica sync reported problems (see swrap replica status)"),
    }

    println!("\nswrap core installed. Next steps:");
    println!("  * add inbound keys:   swadm key add admin 'ssh-ed25519 AAAA…'");
    println!("  * log in as admin with key + vault password to unseal after a reboot");
    println!("  * add hosts:          swadd --host <addr> --label <label>  then  swenroll <label>");
    Ok(0)
}
