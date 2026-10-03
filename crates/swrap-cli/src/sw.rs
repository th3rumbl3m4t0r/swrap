//! `sw [ruser@]label [-- cmd]`: recorded session client.

use crate::client;
use crate::term::{self, RawGuard};
use anyhow::{bail, Result};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use swrap_core::api::{Req, Resp};
use swrap_core::frame::{kind, read_frame, write_frame, Frame};

pub fn main(args: &[String]) -> Result<i32> {
    let mut target = None;
    let mut cmd = vec![];
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--" => {
                cmd.extend(it.by_ref().cloned());
                break;
            }
            "-h" | "--help" => {
                println!("usage: sw [ruser@]label [-- cmd…]\n\nEverything typed inside sw is recorded, including input at hidden prompts.\nFor secrets, stay in the AAA shell (read -rs X there is not recorded).");
                return Ok(0);
            }
            s if s.starts_with('-') => bail!("sw takes no ssh options; only a remote command after --"),
            s => {
                if target.is_some() {
                    bail!("usage: sw [ruser@]label [-- cmd…]");
                }
                target = Some(s.to_string());
            }
        }
    }
    let Some(target) = target else { bail!("usage: sw [ruser@]label [-- cmd…]") };
    let tty = term::isatty(0) && term::isatty(1);
    let (cols, rows) = term::winsize();
    let ssh_conn = std::env::var("SSH_CONNECTION").unwrap_or_default();
    let client_addr = ssh_conn.split_whitespace().next().unwrap_or("local").to_string();
    let req = Req::Sw {
        target,
        cmd,
        cols,
        rows,
        term: std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into()),
        client_addr,
        conn: ssh_conn,
        tty,
    };
    let mut s = client::connect()?;
    write_frame(&mut s, &Frame::json(kind::REQ, &req))?;
    let resp: Resp = loop {
        let Some(f) = read_frame(&mut s)? else { bail!("swrap: daemon closed the connection") };
        match f.kind {
            kind::RESP => break f.parse()?,
            kind::STDERR => eprintln!("{}", String::from_utf8_lossy(&f.payload)),
            _ => {}
        }
    };
    if !resp.ok {
        return Ok(client::finish(&resp));
    }
    let id = resp.data["id"].as_str().unwrap_or("").to_string();
    eprintln!("{}", resp.text);
    // Nested inside the recorded AAA shell: pause its recording for our span (spec 9.5).
    let shell_nonce = std::env::var("SWRAP_SHELL_NONCE").ok().filter(|n| !n.is_empty());
    let mut out = std::io::stdout();
    if let Some(n) = &shell_nonce {
        let _ = write!(out, "\x1b]7719;{n};sw-start:{id}\x07");
        let _ = out.flush();
    }
    let code = relay(&mut s, tty)?;
    if let Some(n) = &shell_nonce {
        let _ = write!(out, "\x1b]7719;{n};sw-end:{id}\x07");
        let _ = out.flush();
    }
    Ok(code)
}

pub fn relay(s: &mut std::os::unix::net::UnixStream, tty: bool) -> Result<i32> {
    let _raw = if tty { RawGuard::new() } else { None };
    let sigr = term::signal_pipe();
    let mut stdin_open = true;
    let mut buf = vec![0u8; 65536];
    let mut rbuf: Vec<u8> = vec![];
    let mut out = std::io::stdout();
    loop {
        let stdin_fd = unsafe { BorrowedFd::borrow_raw(0) };
        let sig_fd = unsafe { BorrowedFd::borrow_raw(sigr) };
        let mut fds = vec![PollFd::new(s.as_fd(), PollFlags::POLLIN), PollFd::new(sig_fd, PollFlags::POLLIN)];
        if stdin_open {
            fds.push(PollFd::new(stdin_fd, PollFlags::POLLIN));
        }
        match poll(&mut fds, PollTimeout::NONE) {
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        }
        let sock_ev = fds[0].revents().unwrap_or(PollFlags::empty());
        let sig_ev = fds[1].revents().unwrap_or(PollFlags::empty());
        let in_ev = if stdin_open { fds[2].revents().unwrap_or(PollFlags::empty()) } else { PollFlags::empty() };
        drop(fds);
        if sig_ev.contains(PollFlags::POLLIN) {
            let mut b = [0u8; 16];
            let n = unsafe { libc::read(sigr, b.as_mut_ptr() as *mut _, 16) };
            for &sig in &b[..n.max(0) as usize] {
                match sig as i32 {
                    libc::SIGWINCH => {
                        let (c, r) = term::winsize();
                        write_frame(s, &Frame::json(kind::RESIZE, &serde_json::json!({"cols": c, "rows": r})))?;
                    }
                    other => {
                        write_frame(s, &Frame::new(kind::SIGNAL, vec![other as u8]))?;
                    }
                }
            }
        }
        if in_ev.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR) {
            let n = std::io::stdin().lock().read(&mut buf).unwrap_or(0);
            if n == 0 && tty {
                // The terminal went away (EOF/EIO on a tty): hang up the session, don't linger.
                let _ = write_frame(s, &Frame::new(kind::SIGNAL, vec![libc::SIGHUP as u8]));
                return Ok(129);
            } else if n == 0 {
                stdin_open = false;
                write_frame(s, &Frame::new(kind::EOF, vec![]))?;
            } else {
                write_frame(s, &Frame::new(kind::DATA, buf[..n].to_vec()))?;
            }
        }
        if sock_ev.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR) {
            let n = s.read(&mut buf)?;
            if n == 0 {
                eprint!("\r\nswrap: connection to the session worker lost\r\n");
                return Ok(255);
            }
            rbuf.extend_from_slice(&buf[..n]);
            while rbuf.len() >= 4 {
                let len = u32::from_be_bytes(rbuf[..4].try_into().unwrap()) as usize;
                if rbuf.len() < 4 + len {
                    break;
                }
                let f = Frame { stream: 0, kind: rbuf[8], payload: rbuf[9..4 + len].to_vec() };
                rbuf.drain(..4 + len);
                match f.kind {
                    kind::DATA => {
                        out.write_all(&f.payload)?;
                        out.flush()?;
                    }
                    kind::STDERR => {
                        eprint!("{}\r\n", String::from_utf8_lossy(&f.payload));
                    }
                    kind::EXIT => {
                        let (code, reason) = f.exit_code();
                        drop(_raw);
                        if reason != "exit" {
                            eprintln!("swrap: session ended: {reason}");
                        }
                        return Ok(code);
                    }
                    _ => {}
                }
            }
        }
    }
}
