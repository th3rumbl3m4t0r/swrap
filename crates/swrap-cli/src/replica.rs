//! `swrap replica sync|status|verify`: keep everything needed to rebuild core on BOTH disks,
//! without RAID mirroring.
//!
//! * Disk A (sda): `/var/lib/swrap` (the primary data) and the rebuild kit at `/srv/rebuild`.
//! * Disk B (sdb): the OS, the source tree, the rebuild kit at `/home/rebuild`, and a versioned,
//!   deduplicated rustic repository of `/var/lib/swrap` at `/home/rebuild/data`.
//!
//! The kit holds: a git mirror of the source, vendored crates (offline rebuild), release binaries
//! (including rustic), system configuration (sshd/PAM/systemd/SELinux/fstab, host keys), the spec,
//! the recording signing trust, and README-REBUILD.md.
//!
//! Safety: data is never backed up unless `/var/lib/swrap` is its own mount and holds the config
//! repo, so a dead data disk can't produce "empty" snapshots that would later prune the real ones.

use anyhow::{bail, Context, Result};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const KIT_A: &str = "/srv/rebuild";
const KIT_B: &str = "/home/rebuild";
const SRC: &str = "/root/swrap";
const DATA: &str = "/var/lib/swrap";
const RUSTIC: &str = "/usr/local/bin/rustic";

const SYSTEM_FILES: &[&str] = &[
    "/etc/fstab",
    "/etc/ssh/sshd_config",
    "/etc/ssh/sshd_config.d",
    "/etc/ssh/authorized_keys",
    "/etc/ssh/ssh_host_ed25519_key",
    "/etc/ssh/ssh_host_ed25519_key.pub",
    "/etc/ssh/ssh_host_ecdsa_key",
    "/etc/ssh/ssh_host_ecdsa_key.pub",
    "/etc/ssh/ssh_host_rsa_key",
    "/etc/ssh/ssh_host_rsa_key.pub",
    "/etc/pam.d/sshd",
    "/etc/pam.d/sshd.swrap-orig",
    "/etc/systemd/system/swrapd.service",
    "/etc/systemd/system/swrap.slice",
    "/etc/systemd/system/swrap-replica.service",
    "/etc/systemd/system/swrap-replica.timer",
    "/etc/systemd/system/swrap-web.service",
    "/etc/tmpfiles.d/swrap.conf",
    "/etc/sysctl.d/90-swrap.conf",
    "/etc/profile.d/swrap.sh",
    "/etc/swrap",
    "/etc/shells",
    "/root/aaa.md",
    "/root/anaconda-ks.cfg",
];

fn sh(cmd: &str, args: &[&str]) -> Result<String> {
    let o = Command::new(cmd).args(args).output().with_context(|| format!("spawn {cmd}"))?;
    if !o.status.success() {
        bail!("{cmd} {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

fn is_mount(p: &str) -> bool {
    Command::new("mountpoint").arg("-q").arg(p).status().map(|s| s.success()).unwrap_or(false)
}

fn mkdir0700(p: &Path) -> Result<()> {
    std::fs::create_dir_all(p)?;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn kits() -> Vec<(&'static str, bool)> {
    // (path, available). Kit A needs its own filesystem on sda; kit B lives on the OS disk.
    vec![(KIT_A, is_mount(KIT_A)), (KIT_B, Path::new("/home").is_dir())]
}

fn password_file(kit: &Path) -> Result<PathBuf> {
    let p = kit.join("rustic.key");
    if !p.exists() {
        // Same key in both kits so either disk alone can open the repository.
        let other = [KIT_A, KIT_B].iter().map(|k| Path::new(k).join("rustic.key")).find(|x| x.exists());
        let key = match other {
            Some(o) => std::fs::read_to_string(o)?,
            None => {
                use rand::Rng;
                let mut r = rand::thread_rng();
                (0..48).map(|_| char::from(b"abcdefghijklmnopqrstuvwxyz0123456789"[r.gen_range(0..36)])).collect::<String>() + "\n"
            }
        };
        std::fs::write(&p, key)?;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(p)
}

fn rsync(src: &str, dst: &Path) -> Result<()> {
    sh("rsync", &["-a", "--delete", "--relative", src, &format!("{}/", dst.display())]).map(|_| ())
}

fn sync_kit(kit: &Path, log: &mut Vec<String>) -> Result<()> {
    mkdir0700(kit)?;
    // 1. Source: bare git mirror (all branches/tags, full history).
    let git = kit.join("src/swrap.git");
    if !git.exists() {
        std::fs::create_dir_all(kit.join("src"))?;
        sh("git", &["init", "-q", "--bare", &git.to_string_lossy()])?;
    }
    sh("git", &["-C", SRC, "push", "-q", "--mirror", &git.to_string_lossy()])?;
    // push --mirror leaves HEAD as `git init` made it (master): point it at the source's branch,
    // or a clone of the mirror (README-REBUILD step 6) checks nothing out.
    if let Ok(branch) = sh("git", &["-C", SRC, "symbolic-ref", "-q", "HEAD"]) {
        sh("git", &["--git-dir", &git.to_string_lossy(), "symbolic-ref", "HEAD", branch.trim()])?;
    }
    // Uncommitted work is snapshotted too (as a patch), so nothing on the OS disk is lost.
    let diff = sh("git", &["-C", SRC, "diff", "HEAD"]).unwrap_or_default();
    std::fs::write(kit.join("src/uncommitted.patch"), diff)?;
    log.push(format!("{}: source mirror at {}", kit.display(), sh("git", &["-C", SRC, "rev-parse", "--short", "HEAD"])?.trim()));
    // 2. Vendored crates for an offline rebuild (only when Cargo.lock changed).
    let lock = std::fs::read(Path::new(SRC).join("Cargo.lock"))?;
    let lock_hash = blake3_hex(&lock);
    let stamp = kit.join("src/vendor.lock.b3");
    if std::fs::read_to_string(&stamp).ok().as_deref() != Some(lock_hash.as_str()) {
        let v = kit.join("src/vendor");
        let o = Command::new("cargo")
            .args(["vendor", "--locked", "--versioned-dirs", "-q"])
            .arg(&v)
            .current_dir(SRC)
            .env("PATH", format!("/root/.cargo/bin:{}", std::env::var("PATH").unwrap_or_default()))
            .output()?;
        if !o.status.success() {
            log.push(format!("{}: WARNING cargo vendor failed: {}", kit.display(), String::from_utf8_lossy(&o.stderr).trim()));
        } else {
            std::fs::write(&stamp, &lock_hash)?;
            log.push(format!("{}: vendored crates refreshed", kit.display()));
        }
    }
    // 3. Binaries.
    let bin = kit.join("bin");
    std::fs::create_dir_all(&bin)?;
    sh("rsync", &["-a", "--delete", "/usr/libexec/swrap/", &format!("{}/", bin.display())])?;
    sh("install", &["-m755", RUSTIC, &bin.join("rustic").to_string_lossy()])?;
    // 4. System configuration.
    let sys = kit.join("system");
    std::fs::create_dir_all(&sys)?;
    for f in SYSTEM_FILES {
        if Path::new(f).exists() {
            rsync(f, &sys)?;
        }
    }
    let _ = Command::new("sh").arg("-c").arg(format!(
        "rpm -qa --qf '%{{NAME}}\\n' | sort > {d}/packages.txt; lsblk -f > {d}/lsblk.txt; lvs > {d}/lvs.txt 2>/dev/null; \
         getent group swrap swrap-users swrap-admin swrap-link > {d}/groups.txt; getent passwd swrap > {d}/passwd-swrap.txt; \
         semodule -l | grep swrap > {d}/selinux-modules.txt",
        d = sys.display()
    )).status();
    // 5. Public trust material (recording signing public key; private keys live in the data backup).
    let _ = rsync(&format!("{DATA}/recsign/ed25519.pub"), &sys);
    let _ = password_file(kit);
    std::fs::write(kit.join("README-REBUILD.md"), README)?;
    std::fs::write(kit.join("LAST-SYNC"), format!("{}\n", swrap_core::time::fmt_utc_secs(swrap_core::time::now())))?;
    Ok(())
}

fn blake3_hex(b: &[u8]) -> String {
    blake3::hash(b).to_hex().to_string()
}

fn rustic(repo: &Path, pw: &Path, args: &[&str]) -> Result<String> {
    let mut a = vec!["--no-progress", "-r", repo.to_str().unwrap(), "--password-file", pw.to_str().unwrap()];
    a.extend_from_slice(args);
    sh(RUSTIC, &a)
}

fn sync_data(kit: &Path, log: &mut Vec<String>) -> Result<()> {
    if !is_mount(DATA) || !Path::new(DATA).join("config/.git").is_dir() {
        bail!("{DATA} is not mounted or has no config repo: refusing to back up (data disk failed?)");
    }
    let repo = kit.join("data");
    let pw = password_file(kit)?;
    if !repo.join("config").exists() {
        rustic(&repo, &pw, &["init"])?;
    }
    rustic(&repo, &pw, &["backup", DATA, "--tag", "swrap-data", "--glob", "!/var/lib/swrap/index/**"])?;
    // Snapshot thinning only (never touches live data): recent history dense, older sparse.
    rustic(&repo, &pw, &["forget", "--prune", "--keep-within", "2d", "--keep-hourly", "72", "--keep-daily", "60", "--keep-weekly", "26", "--keep-monthly", "24"])?;
    log.push(format!("{}: data snapshot of {DATA} written", repo.display()));
    Ok(())
}

pub fn main(args: Vec<String>) -> Result<i32> {
    if !nix::unistd::geteuid().is_root() {
        bail!("run as root");
    }
    match args.first().map(String::as_str) {
        Some("sync") => {
            // One sync at a time (the PT15M timer and a manual run would race on the mirrors).
            let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open("/run/swrap-replica.lock")?;
            if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                eprintln!("swrap replica: another sync is running; waiting for it");
                if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX) } != 0 {
                    bail!("lock /run/swrap-replica.lock: {}", std::io::Error::last_os_error());
                }
            }
            let only_data = args.iter().any(|a| a == "--data-only");
            let mut log = vec![];
            let mut errors = vec![];
            for (k, avail) in kits() {
                if !avail {
                    errors.push(format!("{k}: not available (disk missing?)"));
                    continue;
                }
                if !only_data {
                    if let Err(e) = sync_kit(Path::new(k), &mut log) {
                        errors.push(format!("{k}: {e:#}"));
                    }
                }
            }
            // Off-host source mirror (git server), if a remote `origin` is configured. Non-fatal when offline.
            if !only_data && sh("git", &["-C", SRC, "remote", "get-url", "origin"]).is_ok() {
                match sh("timeout", &["60", "git", "-C", SRC, "push", "-q", "--all", "origin"]).and_then(|_| sh("timeout", &["60", "git", "-C", SRC, "push", "-q", "--tags", "origin"])) {
                    Ok(_) => log.push(format!("origin: source pushed ({})", sh("git", &["-C", SRC, "remote", "get-url", "origin"]).unwrap_or_default().trim())),
                    Err(e) => log.push(format!("origin: WARNING push failed: {e:#}")),
                }
            }
            // The data copy must live on the OTHER disk than the data: kit B (sdb).
            if let Err(e) = sync_data(Path::new(KIT_B), &mut log) {
                errors.push(format!("data: {e:#}"));
            }
            for l in &log {
                println!("{l}");
            }
            let status = json!({"at": swrap_core::time::fmt_utc_secs(swrap_core::time::now()), "ok": errors.is_empty(), "errors": errors, "log": log});
            for k in [KIT_A, KIT_B] {
                if Path::new(k).is_dir() {
                    let _ = std::fs::write(Path::new(k).join("status.json"), status.to_string());
                }
            }
            let _ = crate::client::call(&swrap_core::api::Req::Audit {
                action: "replica.sync".into(),
                target: "both-disks".into(),
                result: if errors.is_empty() { "ok".into() } else { "error".into() },
                detail: json!({"errors": errors}),
            });
            if !errors.is_empty() {
                for e in &errors {
                    eprintln!("swrap replica: {e}");
                }
                return Ok(1);
            }
            Ok(0)
        }
        Some("status") => {
            for k in [KIT_A, KIT_B] {
                let s = std::fs::read_to_string(Path::new(k).join("status.json")).unwrap_or_else(|_| "never synced".into());
                println!("{k}: {s}");
            }
            let pw = Path::new(KIT_B).join("rustic.key");
            if pw.exists() {
                print!("{}", rustic(&Path::new(KIT_B).join("data"), &pw, &["snapshots"]).unwrap_or_default());
            }
            Ok(0)
        }
        Some("verify") => {
            let pw = password_file(Path::new(KIT_B))?;
            let repo = Path::new(KIT_B).join("data");
            let full = args.iter().any(|a| a == "--read-data");
            let mut a = vec!["check"];
            if full {
                a.push("--read-data");
            }
            println!("{}", rustic(&repo, &pw, &a)?);
            for (k, avail) in kits() {
                if avail {
                    let g = Path::new(k).join("src/swrap.git");
                    sh("git", &["-C", &g.to_string_lossy(), "fsck", "--no-progress"])?;
                    println!("{k}: source mirror ok ({})", sh("git", &["-C", &g.to_string_lossy(), "rev-parse", "--short", "HEAD"])?.trim());
                }
            }
            Ok(0)
        }
        _ => {
            println!("usage: swrap replica sync [--data-only] | status | verify [--read-data]");
            Ok(2)
        }
    }
}

const README: &str = r#"# swrap core — rebuild kit

This directory exists on BOTH disks of the core VM:

| Disk | Holds | Kit path |
|---|---|---|
| sda (VG `swrapdata`) | `/var/lib/swrap` (all swrap data: config git DB, vault, recordings, audit) | `/srv/rebuild` |
| sdb (VG `rl`, OS)    | the OS, source tree `/root/swrap`, and a rustic backup of `/var/lib/swrap` | `/home/rebuild` (+ `data/`) |

Contents of each kit: `src/swrap.git` (full git mirror), `src/vendor/` (all crates, offline build),
`src/uncommitted.patch`, `bin/` (release binaries + rustic), `system/` (sshd, PAM, systemd,
sysctl, tmpfiles, profile.d, fstab, SSH host keys, authorized_keys, package list, disk layout,
spec `aaa.md`), `rustic.key` (repository password; same in both kits).
The vault stays encrypted everywhere; you still need an admin vault password or the offline
recovery key to unseal after a rebuild.

## sdb (OS disk) died — data disk sda survives

1. Replace the disk, reinstall Rocky Linux 10 (see `system/anaconda-ks.cfg`, `system/lsblk.txt`).
2. `vgchange -ay swrapdata; mount /dev/swrapdata/rebuild /srv/rebuild; mount /dev/swrapdata/swrap /var/lib/swrap`
3. Restore mounts: copy the two `swrapdata` lines from `/srv/rebuild/system/etc/fstab` into `/etc/fstab`.
4. `dnf install git rsync acl policycoreutils-python-utils selinux-policy-devel make` and restore SSH host keys:
   `cp -a /srv/rebuild/system/etc/ssh/ssh_host_* /etc/ssh/ && restorecon -R /etc/ssh`
5. Reinstall: `/srv/rebuild/bin/swrap install core --from /srv/rebuild/bin`
   (existing data in /var/lib/swrap is kept; users/keys are re-rendered from config/).
6. Recreate the source tree: `git clone /srv/rebuild/src/swrap.git /root/swrap` (build offline:
   configure `.cargo/config.toml` source replacement to `/srv/rebuild/src/vendor`).
7. Recreate kit B: `swrap replica sync` (re-initialises `/home/rebuild`, new rustic repo).

## sda (data disk) died — OS disk sdb survives

1. Replace the disk; recreate LVM: `pvcreate /dev/sda; vgcreate swrapdata /dev/sda;
   lvcreate -n swrap -L 380G swrapdata; lvcreate -n rebuild -l 100%FREE swrapdata;
   mkfs.xfs -L swrap /dev/swrapdata/swrap; mkfs.xfs -L rebuild-a /dev/swrapdata/rebuild; mount -a`
2. `systemctl stop swrapd swrap-replica.timer`
3. Restore data: `rustic -r /home/rebuild/data --password-file /home/rebuild/rustic.key restore latest /`
   (restores `/var/lib/swrap` exactly as of the last snapshot; `rustic snapshots` lists all).
4. `restorecon -R /var/lib/swrap` then `swrap install core --from /usr/libexec/swrap` and `systemctl start swrapd`.
5. `swrap replica sync` to rebuild kit A on the new disk.

Recording signature verification after restore: `swrec verify /var/lib/swrap/rec/*/*/*/*/*/*.swrec`.
"#;
