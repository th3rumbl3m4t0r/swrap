//! SELinux policy module for swrap on core. sshd runs the pam_exec helper in `sshd_t`; it must
//! read the vault wraps and talk to swrapd's unseal socket. swrapd and swrap-web run in their
//! own domains, permissive while their policy is completed (`swrap doctor --selinux`). Built
//! with the policy devel Makefile.

use anyhow::{bail, Context, Result};
use std::process::Command;

pub const TE: &str = include_str!("../selinux/swrap.te");
pub const FC: &str = include_str!("../selinux/swrap.fc");

pub fn install() -> Result<()> {
    let enforcing = Command::new("getenforce").output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
    if enforcing == "Disabled" || enforcing.is_empty() {
        println!("    SELinux disabled; skipping");
        return Ok(());
    }
    let dir = std::env::temp_dir().join(format!("swrap-selinux-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("swrap.te"), TE)?;
    std::fs::write(dir.join("swrap.fc"), FC)?;
    let o = Command::new("make").arg("-f").arg("/usr/share/selinux/devel/Makefile").arg("swrap.pp").current_dir(&dir).output().context("make (selinux-policy-devel installed?)")?;
    if !o.status.success() {
        bail!("building SELinux module failed: {}", String::from_utf8_lossy(&o.stderr));
    }
    let o = Command::new("semodule").arg("-i").arg(dir.join("swrap.pp")).output()?;
    if !o.status.success() {
        bail!("semodule -i failed: {}", String::from_utf8_lossy(&o.stderr));
    }
    let _ = std::fs::remove_dir_all(&dir);
    // The data disk is a fresh filesystem: label everything (vault gets swrap_vault_t).
    for p in ["/var/lib/swrap", "/run/swrap", "/srv/rebuild", "/usr/libexec/swrap"] {
        let _ = Command::new("restorecon").arg("-R").arg(p).output();
    }
    println!("    module swrap loaded; /var/lib/swrap and /run/swrap relabelled");
    Ok(())
}
