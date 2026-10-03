//! `sftp-dispatch`: sshd's sftp subsystem on core (spec 11.1).
//!
//! * swrap admins get OpenSSH's `sftp-server` on the real filesystem (audited);
//! * AAA users get the virtual filesystem: the connection goes to swrapd, whose worker speaks
//!   SFTP to the client; this process only relays bytes;
//! * everyone else (root, system accounts) gets `sftp-server`, as before swrap.

use crate::client;
use anyhow::{bail, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::process::CommandExt;
use swrap_core::api::Req;
use swrap_core::frame::{kind, read_frame, write_frame, Frame};

const SFTP_SERVER: &str = "/usr/libexec/openssh/sftp-server";

fn in_group(name: &str) -> bool {
    let Ok(Some(g)) = nix::unistd::Group::from_name(name) else { return false };
    nix::unistd::getgroups().map(|gs| gs.contains(&g.gid)).unwrap_or(false) || nix::unistd::getegid() == g.gid
}

pub fn dispatch() -> Result<i32> {
    let conn = std::env::var("SSH_CONNECTION").unwrap_or_default();
    let client_addr = conn.split_whitespace().next().unwrap_or("local").to_string();
    if in_group("swrap-admin") {
        let _ = client::call_with_quiet(&Req::Audit {
            action: "sftp.admin".into(),
            target: "core".into(),
            result: "ok".into(),
            detail: serde_json::json!({"client_addr": client_addr, "conn": conn, "server": SFTP_SERVER}),
        });
        let e = std::process::Command::new(SFTP_SERVER).args(["-l", "INFO"]).exec();
        bail!("exec {SFTP_SERVER}: {e}");
    }
    if !in_group("swrap-users") {
        let e = std::process::Command::new(SFTP_SERVER).exec();
        bail!("exec {SFTP_SERVER}: {e}");
    }
    let mut s = client::connect()?;
    write_frame(&mut s, &Frame::json(kind::REQ, &Req::Sftp { client_addr, conn }))?;
    loop {
        let Some(f) = read_frame(&mut s)? else { bail!("swrap: daemon closed the connection") };
        match f.kind {
            kind::STDERR => eprintln!("{}", String::from_utf8_lossy(&f.payload)),
            kind::RESP => {
                let r: swrap_core::api::Resp = f.parse()?;
                if !r.ok {
                    eprintln!("{}", r.error.unwrap_or_default());
                    return Ok(1);
                }
                break;
            }
            _ => {}
        }
    }
    // From here on the connection is the SFTP stream itself.
    let mut up = s.try_clone()?;
    std::thread::spawn(move || {
        let mut stdin = unsafe { File::from_raw_fd(0) };
        let mut buf = vec![0u8; 256 << 10];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if up.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = up.shutdown(std::net::Shutdown::Write);
    });
    let mut stdout = unsafe { File::from_raw_fd(1) };
    let mut buf = vec![0u8; 256 << 10];
    loop {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if stdout.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    Ok(0)
}
