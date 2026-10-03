//! Terminal helpers: raw mode, window size, password prompts, self-pipe for signals.

use nix::sys::termios::{self, SetArg, Termios};
use std::io::{BufRead, Write};
use std::os::fd::{AsFd, BorrowedFd, RawFd};
use std::sync::atomic::{AtomicI32, Ordering};

pub fn isatty(fd: RawFd) -> bool {
    unsafe { libc::isatty(fd) == 1 }
}

pub fn winsize() -> (u16, u16) {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    for fd in [0, 1, 2] {
        if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_col > 0 {
            return (ws.ws_col, ws.ws_row);
        }
    }
    (80, 24)
}

pub struct RawGuard {
    orig: Termios,
}

impl RawGuard {
    pub fn new() -> Option<Self> {
        if !isatty(0) {
            return None;
        }
        let fd = unsafe { BorrowedFd::borrow_raw(0) };
        let orig = termios::tcgetattr(fd).ok()?;
        let mut raw = orig.clone();
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(fd, SetArg::TCSADRAIN, &raw).ok()?;
        Some(RawGuard { orig })
    }
}

impl Drop for RawGuard {
    fn drop(&mut self) {
        let fd = unsafe { BorrowedFd::borrow_raw(0) };
        let _ = termios::tcsetattr(fd, SetArg::TCSADRAIN, &self.orig);
    }
}

/// Read a secret from the terminal without echo (falls back to stdin when not a tty).
pub fn prompt_secret(prompt: &str) -> anyhow::Result<zeroize::Zeroizing<String>> {
    let tty = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty");
    match tty {
        Ok(mut t) => {
            write!(t, "{prompt}")?;
            t.flush()?;
            let fd = t.as_fd();
            let orig = termios::tcgetattr(fd)?;
            let mut noecho = orig.clone();
            noecho.local_flags.remove(termios::LocalFlags::ECHO);
            termios::tcsetattr(fd, SetArg::TCSANOW, &noecho)?;
            let mut line = String::new();
            let r = std::io::BufReader::new(&t).read_line(&mut line);
            termios::tcsetattr(t.as_fd(), SetArg::TCSANOW, &orig)?;
            writeln!(t)?;
            r?;
            Ok(zeroize::Zeroizing::new(line.trim_end_matches(['\n', '\r']).to_string()))
        }
        Err(_) => {
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            Ok(zeroize::Zeroizing::new(line.trim_end_matches(['\n', '\r']).to_string()))
        }
    }
}

pub fn prompt_line(prompt: &str) -> anyhow::Result<String> {
    eprint!("{prompt}");
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_string())
}

// Self-pipe for SIGWINCH / SIGINT forwarding.
static PIPE_W: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_sig(sig: libc::c_int) {
    let fd = PIPE_W.load(Ordering::SeqCst);
    if fd >= 0 {
        let b = sig as u8;
        unsafe { libc::write(fd, &b as *const u8 as *const _, 1) };
    }
}

/// Returns the read end of a pipe that receives one byte per SIGWINCH/SIGTERM/SIGHUP.
pub fn signal_pipe() -> RawFd {
    let mut fds = [0; 2];
    unsafe {
        libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    PIPE_W.store(fds[1], Ordering::SeqCst);
    for s in [libc::SIGWINCH, libc::SIGTERM, libc::SIGHUP] {
        unsafe { libc::signal(s, on_sig as *const () as usize) };
    }
    fds[0]
}
