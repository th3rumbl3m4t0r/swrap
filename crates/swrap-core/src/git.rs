//! Minimal git wrapper for the two repos: `config/` (the database) and `state/` (inventory).

use anyhow::{bail, Context, Result};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[derive(Clone, Debug)]
pub struct Repo {
    pub path: PathBuf,
    /// Run git as this uid/gid (the `swrap` user) when set.
    pub run_as: Option<(u32, u32)>,
}

impl Repo {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Repo { path: path.into(), run_as: None }
    }

    pub fn run_as(mut self, uid: u32, gid: u32) -> Self {
        self.run_as = Some((uid, gid));
        self
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new("git");
        c.arg("-c").arg("safe.directory=*")
            .arg("-c").arg("user.name=swrap")
            .arg("-c").arg("user.email=swrap@localhost")
            .arg("-c").arg("commit.gpgsign=false")
            .arg("-C").arg(&self.path)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env("HOME", "/nonexistent");
        let drop_groups = matches!(self.run_as, Some(_)) && nix::unistd::geteuid().is_root();
        if let (Some((uid, gid)), true) = (self.run_as, drop_groups) {
            c.uid(uid).gid(gid);
        }
        unsafe {
            c.pre_exec(move || {
                if drop_groups {
                    libc::setgroups(0, std::ptr::null());
                }
                // Its own umask, whatever the calling process has at the moment: a repository
                // directory without x for its owner (umask 0177) breaks every later commit.
                libc::umask(0o027);
                Ok(())
            });
        }
        c
    }

    pub fn git(&self, args: &[&str]) -> Result<Output> {
        let out = self.cmd().args(args).output().context("spawn git")?;
        if !out.status.success() {
            bail!("git {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(out)
    }

    pub fn git_ok(&self, args: &[&str]) -> Result<bool> {
        Ok(self.cmd().args(args).output().context("spawn git")?.status.success())
    }

    pub fn init(&self) -> Result<()> {
        if self.path.join(".git").exists() {
            return Ok(());
        }
        self.git(&["init", "-q", "-b", "main"])?;
        Ok(())
    }

    /// Stage everything and commit if anything changed. Returns the new HEAD, if a commit was made.
    pub fn commit_all(&self, message: &str) -> Result<Option<String>> {
        self.git(&["add", "-A"])?;
        if self.git_ok(&["diff", "--cached", "--quiet"])? && self.head().is_ok() {
            return Ok(None);
        }
        self.git(&["commit", "-q", "--allow-empty-message", "-m", message])?;
        Ok(Some(self.head()?))
    }

    pub fn head(&self) -> Result<String> {
        let o = self.git(&["rev-parse", "HEAD"])?;
        Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
    }

    pub fn short_head(&self) -> String {
        self.git(&["rev-parse", "--short=12", "HEAD"])
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "none".into())
    }

    /// `git fsck --full` + refresh + porcelain status; returns findings.
    pub fn check(&self) -> Result<Vec<String>> {
        let mut findings = vec![];
        let o = self.cmd().args(["fsck", "--full", "--no-progress"]).output()?;
        if !o.status.success() {
            findings.push(format!("git fsck failed: {}", String::from_utf8_lossy(&o.stderr).trim()));
        }
        let _ = self.cmd().args(["update-index", "--really-refresh", "-q"]).output();
        let o = self.git(&["status", "--porcelain"])?;
        let s = String::from_utf8_lossy(&o.stdout);
        for l in s.lines() {
            findings.push(format!("uncommitted change in {}: {}", self.path.display(), l));
        }
        Ok(findings)
    }
}

pub fn is_repo(p: &Path) -> bool {
    p.join(".git").is_dir()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A narrow umask in the calling process (another thread binding a socket, say) must not
    /// leave repository directories without x for their owner.
    #[test]
    fn commits_ignore_the_callers_umask() {
        let dir = std::env::temp_dir().join(format!("swrap-git-umask-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let repo = Repo::new(&dir);
        repo.init().unwrap();
        let old = unsafe { libc::umask(0o177) };
        std::fs::write(dir.join("a.toml"), "a = 1\n").unwrap();
        let r = repo.commit_all("first");
        std::fs::write(dir.join("b.toml"), "b = 2\n").unwrap();
        let r2 = repo.commit_all("second");
        unsafe { libc::umask(old) };
        r.unwrap();
        r2.unwrap();
        for e in std::fs::read_dir(dir.join(".git/objects")).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                let mode = std::fs::metadata(&p).unwrap().permissions().mode();
                assert_eq!(mode & 0o700, 0o700, "{} has mode {:o}", p.display(), mode);
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
