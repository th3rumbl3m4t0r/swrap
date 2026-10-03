use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;

pub fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let o = Command::new(cmd).args(args).output().with_context(|| format!("spawn {cmd}"))?;
    if !o.status.success() {
        bail!("{} {}: {}", cmd, args.join(" "), String::from_utf8_lossy(&o.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

pub fn setfacl(args: &[&str], path: &Path) -> Result<()> {
    let p = path.to_string_lossy();
    let mut a: Vec<&str> = args.to_vec();
    a.push(&p);
    run("setfacl", &a).map(|_| ())
}

pub fn random_hex(n: usize) -> String {
    use rand::RngCore;
    let mut b = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut b);
    crate::daemon::hex(&b)
}

pub fn process_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    let r = unsafe { libc::kill(pid, 0) };
    r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}
