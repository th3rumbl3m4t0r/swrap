//! swrap-pam-unlock (core mode): `pam_exec.so expose_authtok` helper for admins (spec 14.2).
//! Authentication succeeds iff the password unwraps the admin's DEK wrap and the commitment
//! matches. On success the DEK is handed to swrapd over the root-only unseal socket.

use base64::Engine;
use std::io::Read;
use std::os::unix::net::UnixStream;
use swrap_core::api::UnsealReq;
use swrap_core::frame::{kind, read_frame, write_frame, Frame};
use zeroize::Zeroizing;

fn send(req: &UnsealReq) {
    let p = swrap_core::Paths::from_env().unseal_sock();
    if let Ok(mut s) = UnixStream::connect(p) {
        let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let _ = write_frame(&mut s, &Frame::json(kind::REQ, req));
        let _ = read_frame(&mut s);
    }
}

fn main() {
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }
    let user = std::env::var("PAM_USER").unwrap_or_default();
    let rhost = std::env::var("PAM_RHOST").unwrap_or_default();
    let ty = std::env::var("PAM_TYPE").unwrap_or_default();
    if ty != "auth" {
        std::process::exit(0);
    }
    // pam_exec writes the token followed by a NUL and may keep the pipe open: stop at NUL/LF/EOF.
    let mut raw = Zeroizing::new(Vec::with_capacity(512));
    let mut stdin = std::io::stdin().lock();
    let mut b = [0u8; 1];
    while raw.len() < 4096 {
        match stdin.read(&mut b) {
            Ok(1) if b[0] != 0 && b[0] != b'\n' => raw.push(b[0]),
            _ => break,
        }
    }
    // pam_exec writes the token followed by a NUL.
    let end = raw.iter().position(|&b| b == 0 || b == b'\n').unwrap_or(raw.len());
    let pw = Zeroizing::new(raw[..end].to_vec());
    let paths = swrap_core::Paths::from_env();
    if swrap_core::paths::is_edge() {
        // Edge mode: core verifies (and unseals). Link down → fail closed.
        let ok = (|| -> Option<bool> {
            let mut s = UnixStream::connect(paths.core_api()).ok()?;
            s.set_read_timeout(Some(std::time::Duration::from_secs(20))).ok()?;
            let req = swrap_core::api::EdgeReq::Unlock { user, password: String::from_utf8_lossy(&pw).into_owned(), rhost };
            write_frame(&mut s, &Frame::json(kind::REQ, &req)).ok()?;
            let f = read_frame(&mut s).ok()??;
            let r: swrap_core::api::Resp = f.parse().ok()?;
            Some(r.ok)
        })()
        .unwrap_or(false);
        std::process::exit(if ok { 0 } else { 1 });
    }
    let v = swrap_vault::Vault::new(&paths, swrap_core::atomic::Owner::NONE);
    match v.unwrap_password(&user, &pw) {
        Ok(dek) => {
            let b64 = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(dek.bytes()));
            send(&UnsealReq::Unseal { user: user.clone(), dek: b64.to_string(), via: "ssh-core".into(), rhost: rhost.clone() });
            send(&UnsealReq::Attempt { user, result: "ok".into(), via: "ssh-core".into(), rhost, detail: String::new() });
            std::process::exit(0);
        }
        Err(e) => {
            send(&UnsealReq::Attempt { user, result: "fail".into(), via: "ssh-core".into(), rhost, detail: e.to_string() });
            std::process::exit(1);
        }
    }
}
