//! swrap-shell: login shell of every AAA user (spec 9.5).
//!
//! * Interactive PTY logins: spawn `bash -l` in a PTY and stream output, resizes and integration
//!   commands to a recorder worker via swrapd. Keystrokes are never recorded.
//! * Non-interactive (`-c cmd`, or no tty): run the command, proxy stdio, and send the command
//!   line, exit code, byte counts and client address to the audit log.
//! Fail-closed: if the recorder is unavailable, no interactive shell is started.

use anyhow::{bail, Context, Result};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::pty::{openpty, Winsize};
use nix::sys::termios::{self, SetArg};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::Arc;
use swrap_core::api::{Req, Resp};
use swrap_core::frame::{kind, read_frame, write_frame, Frame};

const BASH: &str = "/bin/bash";

fn main() {
    let code = match run() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("swrap-shell: {e:#}");
            1
        }
    };
    std::process::exit(code);
}

fn client_addr() -> (String, String) {
    let c = std::env::var("SSH_CONNECTION").unwrap_or_default();
    (c.split_whitespace().next().unwrap_or("local").to_string(), c)
}

fn audit(action: &str, result: &str, detail: serde_json::Value) {
    if let Ok(mut s) = UnixStream::connect(swrap_core::Paths::from_env().api_sock()) {
        let _ = write_frame(&mut s, &Frame::json(kind::REQ, &Req::Audit { action: action.into(), target: "core".into(), result: result.into(), detail }));
        let _ = read_frame(&mut s);
    }
}

const SFTP_DISPATCH: &str = "/usr/libexec/swrap/sftp-dispatch";

fn run() -> Result<i32> {
    let args: Vec<String> = std::env::args().collect();
    // sshd runs `shell -c "command"` for exec requests and subsystems.
    if let Some(pos) = args.iter().position(|a| a == "-c") {
        let cmd = args.get(pos + 1).cloned().unwrap_or_default();
        if cmd == SFTP_DISPATCH {
            // The sftp subsystem: it records itself, and its stream must not go through pipes here.
            let e = std::os::unix::process::CommandExt::exec(&mut Command::new(SFTP_DISPATCH));
            anyhow::bail!("exec {SFTP_DISPATCH}: {e}");
        }
        return noninteractive(Some(cmd));
    }
    if unsafe { libc::isatty(0) } != 1 {
        return noninteractive(None);
    }
    interactive()
}

fn noninteractive(cmd: Option<String>) -> Result<i32> {
    let (addr, conn) = client_addr();
    let started = std::time::Instant::now();
    let mut c = Command::new(BASH);
    match &cmd {
        Some(cmd) => {
            c.arg("-c").arg(cmd);
        }
        None => {
            c.arg("-l").arg("-s");
        }
    }
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().context("spawn bash")?;
    let bin = Arc::new(AtomicU64::new(0));
    let bout = Arc::new(AtomicU64::new(0));
    let berr = Arc::new(AtomicU64::new(0));
    let mut cin = child.stdin.take().unwrap();
    let mut cout = child.stdout.take().unwrap();
    let mut cerr = child.stderr.take().unwrap();
    let b1 = bin.clone();
    // stdin pump is detached: it may block forever on a client that never closes stdin.
    std::thread::spawn(move || {
        let mut buf = [0u8; 65536];
        let mut stdin = std::io::stdin();
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    b1.fetch_add(n as u64, Ordering::Relaxed);
                    if cin.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let b2 = bout.clone();
    let t_out = std::thread::spawn(move || {
        let mut buf = [0u8; 65536];
        let mut o = std::io::stdout();
        while let Ok(n) = cout.read(&mut buf) {
            if n == 0 || o.write_all(&buf[..n]).and_then(|_| o.flush()).is_err() {
                break;
            }
            b2.fetch_add(n as u64, Ordering::Relaxed);
        }
    });
    let b3 = berr.clone();
    let t_err = std::thread::spawn(move || {
        let mut buf = [0u8; 65536];
        let mut o = std::io::stderr();
        while let Ok(n) = cerr.read(&mut buf) {
            if n == 0 || o.write_all(&buf[..n]).is_err() {
                break;
            }
            b3.fetch_add(n as u64, Ordering::Relaxed);
        }
    });
    let st = child.wait()?;
    let _ = t_out.join();
    let _ = t_err.join();
    let code = st.code().unwrap_or_else(|| 128 + std::os::unix::process::ExitStatusExt::signal(&st).unwrap_or(0));
    audit(
        "shell.exec",
        "ok",
        serde_json::json!({
            "cmd": cmd.unwrap_or_else(|| "<stdin script>".into()), "exit_code": code,
            "bytes_in": bin.load(Ordering::Relaxed), "bytes_out": bout.load(Ordering::Relaxed), "bytes_err": berr.load(Ordering::Relaxed),
            "client_addr": addr, "conn": conn, "duration": swrap_core::time::fmt_duration_ms(started.elapsed()),
        }),
    );
    Ok(code)
}

fn winsize() -> (u16, u16) {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_col > 0 {
        (ws.ws_col, ws.ws_row)
    } else {
        (80, 24)
    }
}

static SIGPIPE_W: AtomicI32 = AtomicI32::new(-1);
extern "C" fn on_sig(sig: libc::c_int) {
    let fd = SIGPIPE_W.load(Ordering::SeqCst);
    if fd >= 0 {
        let b = sig as u8;
        unsafe { libc::write(fd, &b as *const u8 as *const _, 1) };
    }
}

fn interactive() -> Result<i32> {
    let nonce: String = {
        use rand::Rng;
        let mut r = rand::thread_rng();
        (0..24).map(|_| char::from(b"abcdefghijklmnopqrstuvwxyz0123456789"[r.gen_range(0..36)])).collect()
    };
    let (cols, rows) = winsize();
    let (addr, conn) = client_addr();
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());
    let mut s = UnixStream::connect(swrap_core::Paths::from_env().api_sock())
        .context("recording is unavailable (swrapd not reachable); refusing an unrecorded shell")?;
    let req = Req::Shell { cols, rows, term, client_addr: addr, conn, nonce: nonce.clone(), sshd_pid: nix::unistd::getppid().as_raw() };
    write_frame(&mut s, &Frame::json(kind::REQ, &req))?;
    let Some(f) = read_frame(&mut s)? else { bail!("recorder closed the connection") };
    let resp: Resp = f.parse()?;
    if !resp.ok {
        bail!("{}", resp.error.unwrap_or_default());
    }
    let id = resp.data["id"].as_str().unwrap_or("").to_string();
    if let Ok(m) = std::fs::read_to_string(swrap_core::Paths::from_env().motd()) {
        print!("{}", m.replace('\n', "\r\n"));
    }
    println!("swrap: this shell is recorded (output and commands; keystrokes are not) — {id}");
    if let Some(b) = resp.data["banner"].as_str().filter(|b| !b.is_empty()) {
        println!("{b}");
    }

    let ws = Winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
    let pty = openpty(Some(&ws), None)?;
    let master: OwnedFd = pty.master;
    let slave: OwnedFd = pty.slave;
    let sfd = slave.as_raw_fd();
    let mut cmd = Command::new(BASH);
    cmd.arg0("-bash")
        .env("SWRAP_SESSION", format!("{id}:{nonce}"))
        .env("SWRAP_SHELL_NONCE", &nonce)
        .env("SWRAP_SHELL_ID", &id)
        .env("SHELL", BASH)
        .stdin(unsafe { Stdio::from_raw_fd(libc::dup(sfd)) })
        .stdout(unsafe { Stdio::from_raw_fd(libc::dup(sfd)) })
        .stderr(unsafe { Stdio::from_raw_fd(libc::dup(sfd)) });
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            if libc::ioctl(0, libc::TIOCSCTTY as _, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.spawn().context("spawn bash")?;
    // Command owns the slave dups until dropped; the master only sees EIO once all are closed.
    drop(cmd);
    drop(slave);
    let pid = Pid::from_raw(child.id() as i32);
    std::mem::forget(child);

    // Raw mode on our terminal.
    let stdin_fd = unsafe { BorrowedFd::borrow_raw(0) };
    let orig = termios::tcgetattr(stdin_fd).ok();
    if let Some(o) = &orig {
        let mut raw = o.clone();
        termios::cfmakeraw(&mut raw);
        let _ = termios::tcsetattr(stdin_fd, SetArg::TCSADRAIN, &raw);
    }
    let mut fds = [0; 2];
    unsafe {
        libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK);
        SIGPIPE_W.store(fds[1], Ordering::SeqCst);
        libc::signal(libc::SIGWINCH, on_sig as *const () as usize);
        libc::signal(libc::SIGHUP, on_sig as *const () as usize);
        libc::signal(libc::SIGTERM, on_sig as *const () as usize);
    }
    let sigr = fds[0];
    let mut master_f = std::fs::File::from(master);
    let mut buf = vec![0u8; 65536];
    let mut out = std::io::stdout();
    let mut code = 0;
    let mut recorder_ok = true;
    loop {
        let sig_fd = unsafe { BorrowedFd::borrow_raw(sigr) };
        let mut pfds = [
            PollFd::new(master_f.as_fd(), PollFlags::POLLIN),
            PollFd::new(stdin_fd, PollFlags::POLLIN),
            PollFd::new(sig_fd, PollFlags::POLLIN),
            PollFd::new(s.as_fd(), PollFlags::POLLIN),
        ];
        match poll(&mut pfds, PollTimeout::NONE) {
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        }
        let ev: Vec<PollFlags> = pfds.iter().map(|p| p.revents().unwrap_or(PollFlags::empty())).collect();
        if ev[2].contains(PollFlags::POLLIN) {
            let mut b = [0u8; 16];
            let n = unsafe { libc::read(sigr, b.as_mut_ptr() as *mut _, 16) };
            for &sg in &b[..n.max(0) as usize] {
                if sg as i32 == libc::SIGWINCH {
                    let (c, r) = winsize();
                    let ws = libc::winsize { ws_row: r, ws_col: c, ws_xpixel: 0, ws_ypixel: 0 };
                    unsafe { libc::ioctl(master_f.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
                    let _ = write_frame(&mut s, &Frame::json(kind::RESIZE, &serde_json::json!({"cols": c, "rows": r})));
                } else {
                    let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGHUP);
                }
            }
        }
        if ev[0].intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR) {
            match master_f.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let _ = out.write_all(&buf[..n]);
                    let _ = out.flush();
                    if write_frame(&mut s, &Frame::new(kind::DATA, buf[..n].to_vec())).is_err() {
                        recorder_ok = false;
                        break;
                    }
                }
            }
        }
        if ev[1].intersects(PollFlags::POLLIN | PollFlags::POLLHUP) {
            let n = unsafe { libc::read(0, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n <= 0 {
                let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGHUP);
                break;
            }
            // Keystrokes go to the shell only; never to the recorder.
            master_f.write_all(&buf[..n as usize])?;
        }
        if ev[3].intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR) {
            // The recorder never sends data after the response; readable means it went away.
            let mut tmp = [0u8; 64];
            if matches!(s.read(&mut tmp), Ok(0) | Err(_)) {
                recorder_ok = false;
                break;
            }
        }
    }
    if !recorder_ok {
        let _ = out.write_all(b"\r\nswrap: recorder lost; terminating the shell (fail-closed)\r\n");
        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGHUP);
    }
    if let Ok(st) = waitpid(pid, None) {
        code = match st {
            WaitStatus::Exited(_, c) => c,
            WaitStatus::Signaled(_, sg, _) => 128 + sg as i32,
            _ => 0,
        };
    }
    if let Some(o) = &orig {
        let _ = termios::tcsetattr(stdin_fd, SetArg::TCSADRAIN, o);
    }
    let _ = write_frame(&mut s, &Frame::exit(code, "exit"));
    let _ = s.shutdown(std::net::Shutdown::Write);
    let _ = read_frame(&mut s);
    Ok(code)
}
