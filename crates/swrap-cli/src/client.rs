//! Talking to the local daemon.

use anyhow::{bail, Context, Result};
use std::io::Write;
use std::os::unix::net::UnixStream;
use swrap_core::api::{Req, Resp};
use swrap_core::frame::{kind, read_frame, write_frame, Frame};

pub fn connect() -> Result<UnixStream> {
    let p = swrap_core::Paths::from_env().api_sock();
    UnixStream::connect(&p).with_context(|| format!("swrap: cannot reach the swrap daemon at {} (is swrapd running?)", p.display()))
}

/// Send a request; stream STDOUT/STDERR frames; return the final response.
pub fn call(req: &Req) -> Result<Resp> {
    call_with(req, |_| {})
}

/// Like `call`, but hands DATA frames to `on_data`.
pub fn call_frames(req: &Req, mut on_data: impl FnMut(&Frame)) -> Result<Resp> {
    let mut s = connect()?;
    write_frame(&mut s, &Frame::json(kind::REQ, req))?;
    loop {
        let Some(f) = read_frame(&mut s)? else { bail!("swrap: daemon closed the connection") };
        match f.kind {
            kind::DATA => on_data(&f),
            kind::STDERR => eprintln!("{}", String::from_utf8_lossy(&f.payload)),
            kind::RESP => return Ok(f.parse()?),
            _ => {}
        }
    }
}

/// Like `call`, but swallows progress output (for full-screen/boxed UIs).
pub fn call_with_quiet(req: &Req) -> Result<Resp> {
    let mut s = connect()?;
    write_frame(&mut s, &Frame::json(kind::REQ, req))?;
    loop {
        let Some(f) = read_frame(&mut s)? else { bail!("swrap: daemon closed the connection") };
        if f.kind == kind::RESP {
            return Ok(f.parse()?);
        }
    }
}

pub fn call_with(req: &Req, mut on_event: impl FnMut(&serde_json::Value)) -> Result<Resp> {
    let mut s = connect()?;
    write_frame(&mut s, &Frame::json(kind::REQ, req))?;
    let stdout = std::io::stdout();
    loop {
        let Some(f) = read_frame(&mut s)? else { bail!("swrap: daemon closed the connection") };
        match f.kind {
            kind::STDOUT => {
                let mut o = stdout.lock();
                o.write_all(&f.payload)?;
                if !f.payload.ends_with(b"\n") {
                    o.write_all(b"\n")?;
                }
            }
            kind::STDERR => eprintln!("{}", String::from_utf8_lossy(&f.payload)),
            kind::EVENT => {
                if let Ok(v) = serde_json::from_slice(&f.payload) {
                    on_event(&v);
                }
            }
            kind::RESP => return Ok(f.parse()?),
            _ => {}
        }
    }
}

/// Print a response the standard way and return the exit code.
pub fn finish(r: &Resp) -> i32 {
    if !r.text.is_empty() {
        print!("{}", r.text);
        if !r.text.ends_with('\n') {
            println!();
        }
    }
    if let Some(e) = &r.error {
        let e = if e.starts_with("swrap:") { e.clone() } else { format!("swrap: {e}") };
        eprintln!("{e}");
    }
    if r.exit != 0 { r.exit } else if r.ok { 0 } else { 1 }
}
