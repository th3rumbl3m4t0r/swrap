//! `swrap install edge`: installer for the public node (spec 5.2, 5.3, 7.2), run on the edge host
//! by `swedge deploy` from core. Idempotent.
//!
//! Co-location rules (spec 5.3): Stalwart's ports, units, files and firewall are never touched;
//! swrap only adds its own users/units/drop-ins and its own nftables table (applied by the daemon).
//! sshd/PAM changes are guarded by a dead-man's switch: they roll back automatically unless core
//! confirms with a fresh login within PT120S.

use anyhow::{bail, Context, Result};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use swrap_core::atomic::{self, Owner};

const LIBEXEC: &str = "/usr/libexec/swrap";
const BINARIES: &[&str] = &["swrapd", "swrap", "swrap-shell", "swrap-pam-unlock", "swrec"];
const LINKS: &[&str] = &["swrap", "sw", "swls", "swlog", "swcat", "swplay", "swsearch", "swupdate", "swinv", "swr", "swx", "swpasswd", "swunlock", "swadm", "swadd", "swenroll", "swdel", "swcrypto", "swfw"];
const EDGE_ROOT: &str = "/var/lib/swrap-edge";

fn sh(cmd: &str, args: &[&str]) -> Result<String> {
    let o = Command::new(cmd).args(args).output().with_context(|| format!("spawn {cmd}"))?;
    if !o.status.success() {
        bail!("{cmd} {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

fn step(s: &str) {
    println!("==> {s}");
}

const UNIT: &str = r#"[Unit]
Description=swrap edge daemon (public session node)
After=network-online.target sshd.service
Wants=network-online.target

[Service]
ExecStart=/usr/libexec/swrap/swrapd edge
Environment=SWRAP_ROLE=edge
# Live session workers survive a daemon restart.
KillMode=process
Restart=always
RestartSec=2
LimitCORE=0
UMask=0027
Slice=swrap.slice

[Install]
WantedBy=multi-user.target
"#;

/// Spec 5.3: swrap's budget next to Stalwart.
const SLICE: &str = r#"[Unit]
Description=swrap services and sessions (bounded so mail is never starved)

[Slice]
MemoryHigh=384M
MemoryMax=512M
CPUWeight=100
"#;

const TMPFILES: &str = "d /run/swrap-edge 0755 root root -\nd /run/swrap-edge/link 0750 swrap-link swrap-link -\n";

const SSHD_GLOBAL: &str = r#"# managed by swrap (edge). Global options; first value wins.
LogLevel VERBOSE
# swrap AAA users, the link user, and root (root keeps key-only login for maintenance and `sw mail`).
AllowGroups swrap-users swrap-link root
# SFTP (spec 11): AAA users get the host directories (their session runs on core); root,
# admins and every other account get sftp-server exactly as before.
Subsystem sftp /usr/libexec/swrap/sftp-dispatch
"#;

const SSHD_MATCH: &str = r#"# managed by swrap (edge). Kept last so the Match blocks cannot capture other files' options.
Match User swrap-link
    AuthorizedKeysFile /etc/ssh/authorized_keys/%u
    AuthenticationMethods publickey
    AllowStreamLocalForwarding remote
    # OpenSSH gates unix-socket -R on AllowTcpForwarding too (channels.c: no ACLs for
    # streamlocal), so allow "remote" and deny every TCP listen/open explicitly.
    AllowTcpForwarding remote
    PermitListen none
    PermitOpen none
    AllowAgentForwarding no
    X11Forwarding no
    PermitTTY no
    PermitTunnel no
    PermitUserRC no
    StreamLocalBindUnlink yes
    StreamLocalBindMask 0117
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

fn ensure_group(g: &str) -> Result<()> {
    if swrap_core::sys::gid_of_group(g).is_none() {
        sh("groupadd", &["-r", g])?;
    }
    Ok(())
}

pub fn main(args: Vec<String>) -> Result<i32> {
    let mut from = None;
    let mut snap_pub = None;
    let mut link_pub = None;
    let mut token = None;
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--from" => from = it.next(),
            "--snapshot-pub" => snap_pub = it.next(),
            "--link-pub" => link_pub = it.next(),
            "--confirm-token" => token = it.next(),
            o => bail!("unknown argument {o}"),
        }
    }
    let (Some(snap_pub), Some(link_pub), Some(token)) = (snap_pub, link_pub, token) else {
        bail!("usage: swrap install edge --snapshot-pub KEY --link-pub KEY --confirm-token T [--from DIR] (normally run by `swedge deploy` on core)");
    };
    if !token.bytes().all(|b| b.is_ascii_alphanumeric()) || token.len() < 8 {
        bail!("bad token");
    }
    if !nix::unistd::geteuid().is_root() {
        bail!("run as root");
    }
    let from = std::path::PathBuf::from(from.unwrap_or_else(|| LIBEXEC.into()));

    step("role, groups and service accounts");
    std::fs::create_dir_all("/etc/swrap")?;
    atomic::write(Path::new("/etc/swrap/role"), b"edge\n", 0o644, Owner::NONE)?;
    for g in ["swrap-users", "swrap-admin", "swrap-link"] {
        ensure_group(g)?;
    }
    if swrap_core::sys::user_by_name("swrap-edge").is_none() {
        sh("useradd", &["-r", "-U", "-d", EDGE_ROOT, "-M", "-s", "/sbin/nologin", "-c", "swrap edge sessions", "swrap-edge"])?;
    }
    if swrap_core::sys::user_by_name("swrap-link").is_none() {
        sh("useradd", &["-r", "-g", "swrap-link", "-d", "/var/empty", "-M", "-s", "/sbin/nologin", "-c", "swrap link from core", "swrap-link"])?;
    }
    let pw = swrap_core::sys::user_by_name("swrap-edge").unwrap();
    let (uid, gid) = (pw.uid.as_raw(), pw.gid.as_raw());

    step("binaries");
    std::fs::create_dir_all(LIBEXEC)?;
    for b in BINARIES {
        let src = from.join(b);
        if !src.exists() {
            bail!("missing binary {}", src.display());
        }
        let dst = Path::new(LIBEXEC).join(b);
        if src != dst {
            let tmp = Path::new(LIBEXEC).join(format!(".{b}.new"));
            std::fs::copy(&src, &tmp)?;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
            std::fs::rename(&tmp, &dst)?;
        }
    }
    for l in LINKS {
        let p = Path::new("/usr/bin").join(l);
        let _ = std::fs::remove_file(&p);
        std::os::unix::fs::symlink(Path::new(LIBEXEC).join("swrap"), &p)?;
    }
    let _ = std::fs::remove_file("/usr/bin/swrec");
    std::os::unix::fs::symlink(Path::new(LIBEXEC).join("swrec"), "/usr/bin/swrec")?;
    // sshd's sftp subsystem (06-swrap.conf), before sshd is pointed at it.
    let _ = std::fs::remove_file(Path::new(LIBEXEC).join("sftp-dispatch"));
    std::os::unix::fs::symlink("swrap", Path::new(LIBEXEC).join("sftp-dispatch"))?;
    let _ = sh("restorecon", &["-R", LIBEXEC]);
    let shell = format!("{LIBEXEC}/swrap-shell");
    let shells = std::fs::read_to_string("/etc/shells").unwrap_or_default();
    if !shells.lines().any(|l| l == shell) {
        std::fs::write("/etc/shells", format!("{shells}{shell}\n"))?;
    }
    let _ = sh("restorecon", &["-R", LIBEXEC]);

    crate::install::install_docs()?;

    step("state directories and keys");
    let root = Path::new(EDGE_ROOT);
    atomic::mkdirs(root, 0o755, Owner::NONE)?;
    atomic::mkdirs(&root.join("spool"), 0o750, Owner::new(uid, gid))?;
    atomic::mkdirs(&root.join("recsign"), 0o700, Owner::new(uid, gid))?;
    atomic::mkdirs(&root.join("trust"), 0o755, Owner::NONE)?;
    atomic::mkdirs(&root.join("snapshot"), 0o700, Owner::NONE)?;
    let kp = root.join("recsign/ed25519.key");
    if !kp.exists() {
        let s = swrec::RecSigner::generate("edge");
        atomic::write(&kp, s.private_text().as_bytes(), 0o600, Owner::new(uid, gid))?;
        atomic::write(&root.join("recsign/ed25519.pub"), s.public_text().as_bytes(), 0o644, Owner::new(uid, gid))?;
    }
    // Pinned core key for snapshot verification.
    if !snap_pub.starts_with("ssh-ed25519 ") || snap_pub.contains('\n') {
        bail!("bad snapshot public key");
    }
    atomic::write(&root.join("trust/allowed_signers"), format!("core namespaces=\"swrap-edge-config\" {snap_pub}\n").as_bytes(), 0o644, Owner::NONE)?;
    atomic::write(&root.join("trust/core-edge-config.pub"), format!("{snap_pub}\n").as_bytes(), 0o644, Owner::NONE)?;
    // The link key can do nothing but the reverse socket forwards.
    if !link_pub.starts_with("ssh-ed25519 ") || link_pub.contains('\n') {
        bail!("bad link public key");
    }
    atomic::mkdirs(Path::new("/etc/ssh/authorized_keys"), 0o755, Owner::new(0, 0))?;
    // Not `restrict,port-forwarding` (spec 4.5): `restrict` also disables unix-socket forwarding and
    // no key option re-enables it. Everything else is switched off explicitly; TCP forwarding and
    // TTYs are refused by sshd's `Match User swrap-link`, and any session gets /sbin/nologin.
    atomic::write(
        Path::new("/etc/ssh/authorized_keys/swrap-link"),
        format!("command=\"/sbin/nologin\",no-agent-forwarding,no-X11-forwarding,no-pty,no-user-rc {link_pub}\n").as_bytes(),
        0o644,
        Owner::new(0, 0),
    )?;

    step("systemd (swrap-edged in swrap.slice: MemoryHigh=384M MemoryMax=512M), tmpfiles, sysctl, profile.d");
    for d in ["/etc/systemd/system", "/etc/tmpfiles.d", "/etc/sysctl.d", "/etc/profile.d"] {
        std::fs::create_dir_all(d)?;
    }
    atomic::write(Path::new("/etc/systemd/system/swrap-edged.service"), UNIT.as_bytes(), 0o644, Owner::NONE)?;
    atomic::write(Path::new("/etc/systemd/system/swrap.slice"), SLICE.as_bytes(), 0o644, Owner::NONE)?;
    atomic::write(Path::new("/etc/tmpfiles.d/swrap-edge.conf"), TMPFILES.as_bytes(), 0o644, Owner::NONE)?;
    atomic::write(Path::new("/etc/sysctl.d/90-swrap.conf"), b"kernel.yama.ptrace_scope = 2\n", 0o644, Owner::NONE)?;
    let snippet = sh(&format!("{LIBEXEC}/swrapd"), &["profile-snippet"])?;
    atomic::write(Path::new("/etc/profile.d/swrap.sh"), snippet.as_bytes(), 0o644, Owner::NONE)?;
    let _ = sh("restorecon", &["-R", "/etc/systemd/system/swrap-edged.service", "/etc/systemd/system/swrap.slice", "/etc/profile.d/swrap.sh", "/etc/ssh/authorized_keys", EDGE_ROOT]);
    sh("systemd-tmpfiles", &["--create", "/etc/tmpfiles.d/swrap-edge.conf"])?;
    let _ = sh("sysctl", &["-q", "-p", "/etc/sysctl.d/90-swrap.conf"]);
    sh("systemctl", &["daemon-reload"])?;
    sh("systemctl", &["enable", "swrap-edged.service"])?;
    sh("systemctl", &["restart", "swrap-edged.service"])?;

    step("sshd and PAM (guarded: automatic rollback unless core confirms within PT120S)");
    let backup = root.join("sshd-backup");
    std::fs::create_dir_all(&backup)?;
    for f in ["/etc/pam.d/sshd", "/etc/ssh/sshd_config.d/06-swrap.conf", "/etc/ssh/sshd_config.d/99-swrap-match.conf"] {
        let b = backup.join(Path::new(f).file_name().unwrap());
        let _ = std::fs::remove_file(&b);
        if Path::new(f).exists() {
            std::fs::copy(f, &b)?;
        }
    }
    let pam = std::fs::read_to_string("/etc/pam.d/sshd")?;
    let orig_p = Path::new("/etc/pam.d/sshd.swrap-orig");
    if !pam.contains(crate::install::PAM_MARK) && !orig_p.exists() {
        std::fs::write(orig_p, &pam)?;
    }
    let orig = std::fs::read_to_string(orig_p)?;
    atomic::write(Path::new("/etc/pam.d/sshd"), crate::install::pam_sshd(&orig).as_bytes(), 0o644, Owner::NONE)?;
    atomic::write(Path::new("/etc/ssh/sshd_config.d/06-swrap.conf"), SSHD_GLOBAL.as_bytes(), 0o600, Owner::NONE)?;
    atomic::write(Path::new("/etc/ssh/sshd_config.d/99-swrap-match.conf"), SSHD_MATCH.as_bytes(), 0o600, Owner::NONE)?;
    let _ = sh("restorecon", &["-R", "/etc/ssh", "/etc/pam.d/sshd"]);
    let restore = format!(
        "for f in sshd:/etc/pam.d/sshd 06-swrap.conf:/etc/ssh/sshd_config.d/06-swrap.conf 99-swrap-match.conf:/etc/ssh/sshd_config.d/99-swrap-match.conf; do \
           b={bk}/${{f%%:*}}; t=${{f#*:}}; if [ -f \"$b\" ]; then cp -p \"$b\" \"$t\"; else rm -f \"$t\"; fi; done; systemctl reload sshd",
        bk = backup.display()
    );
    if let Err(e) = sh("sshd", &["-t"]) {
        let _ = sh("sh", &["-c", &restore]);
        bail!("sshd -t failed, restored previous config: {e}");
    }
    // Root must keep key login; check effective config before reloading.
    let root_cfg = sh("sshd", &["-T", "-C", "user=root,host=x,addr=192.0.2.1"]).unwrap_or_default();
    if !root_cfg.lines().any(|l| l == "pubkeyauthentication yes") {
        let _ = sh("sh", &["-c", &restore]);
        bail!("root would lose key login; restored previous config");
    }
    sh("systemctl", &["reload", "sshd"])?;
    let confirm = format!("/run/swrap-edge/sshd-confirm-{token}");
    let watcher = format!(
        "for i in $(seq 1 120); do [ -f {confirm} ] && {{ rm -f {confirm}; exit 0; }}; sleep 1; done; {restore}; echo swrap: sshd change rolled back | systemd-cat -t swrap-install"
    );
    sh("systemd-run", &["--unit", &format!("swrap-sshd-guard-{token}"), "--collect", "--quiet", "sh", "-c", &watcher])?;
    println!("    sshd reloaded; waiting for core to confirm with a fresh connection (token {token})");
    println!("EDGE-RECSIGN-PUB: {}", std::fs::read_to_string(root.join("recsign/ed25519.pub"))?.trim());
    Ok(0)
}
