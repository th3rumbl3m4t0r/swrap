//! SELinux policy module for swrap on core. sshd runs the pam_exec helper in `sshd_t`; it must
//! read the vault wraps and talk to swrapd's unseal socket. swrapd, swrap-web and the swai
//! harness (`swrap_ai_t`) run in their own domains, permissive while their policy is completed
//! (`swrap doctor --selinux`); `swrap install selinux --enforce` builds the module without the
//! `swrap:permissive` lines. The mode installed is kept in `/var/lib/swrap/selinux.mode`. Built
//! with the policy devel Makefile.

use anyhow::{bail, Context, Result};
use std::process::Command;

pub const TE: &str = include_str!("../selinux/swrap.te");
pub const FC: &str = include_str!("../selinux/swrap.fc");

const MODE_FILE: &str = "/var/lib/swrap/selinux.mode";

/// `permissive` or `enforcing`: what the last install loaded.
pub fn installed_mode() -> Option<String> {
    std::fs::read_to_string(MODE_FILE).ok().map(|s| s.trim().to_string())
}

/// The module source: as written, or with the `swrap:permissive` lines left out.
pub fn te(enforce: bool) -> String {
    if !enforce {
        return TE.to_string();
    }
    TE.lines().filter(|l| !l.contains("# swrap:permissive")).map(|l| format!("{l}\n")).collect()
}

pub fn install(enforce: bool) -> Result<()> {
    let enforcing = Command::new("getenforce").output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
    if enforcing == "Disabled" || enforcing.is_empty() {
        println!("    SELinux disabled; skipping");
        return Ok(());
    }
    let dir = std::env::temp_dir().join(format!("swrap-selinux-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("swrap.te"), te(enforce))?;
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
    let mode = if enforce { "enforcing" } else { "permissive" };
    std::fs::write(MODE_FILE, format!("{mode}\n"))?;
    println!("    module swrap loaded ({mode}: swrapd_t, swrap_web_t, swrap_ai_t); /var/lib/swrap and /run/swrap relabelled");
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn enforce_drops_only_the_permissive_lines() {
        let p = super::te(false);
        let e = super::te(true);
        assert_eq!(p.matches("permissive swrap").count(), 3);
        assert_eq!(e.matches("permissive swrap").count(), 0);
        assert_eq!(p.lines().count() - e.lines().count(), 3);
        assert!(e.contains("domain_auto_transition_pattern(swrapd_t, swrap_ai_exec_t, swrap_ai_t)"));
    }
}
