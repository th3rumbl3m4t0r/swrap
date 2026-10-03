//! Small system helpers: user/group lookups, peer credentials.

use anyhow::{Context, Result};
use nix::unistd::{Gid, Group, Uid, User};
use std::os::fd::AsRawFd;

pub fn user_name(uid: u32) -> Option<String> {
    User::from_uid(Uid::from_raw(uid)).ok().flatten().map(|u| u.name)
}

pub fn user_by_name(name: &str) -> Option<User> {
    User::from_name(name).ok().flatten()
}

pub fn uid_of(name: &str) -> Option<u32> {
    user_by_name(name).map(|u| u.uid.as_raw())
}

pub fn gid_of_group(name: &str) -> Option<u32> {
    Group::from_name(name).ok().flatten().map(|g| g.gid.as_raw())
}

pub fn group_members(name: &str) -> Vec<String> {
    Group::from_name(name).ok().flatten().map(|g| g.mem).unwrap_or_default()
}

pub fn in_group(user: &str, group: &str) -> bool {
    let Some(g) = Group::from_name(group).ok().flatten() else { return false };
    if g.mem.iter().any(|m| m == user) {
        return true;
    }
    user_by_name(user).map(|u| u.gid == g.gid).unwrap_or(false)
}

/// The `swrap` service account (uid, gid).
pub fn swrap_ids() -> Option<(u32, u32)> {
    user_by_name("swrap").map(|u| (u.uid.as_raw(), u.gid.as_raw()))
}

pub fn gid_raw(g: Gid) -> u32 {
    g.as_raw()
}

#[derive(Clone, Copy, Debug)]
pub struct PeerCred {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

pub fn peer_cred(fd: &impl AsRawFd) -> Result<PeerCred> {
    let mut c = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, &mut c as *mut _ as *mut _, &mut len)
    };
    if r != 0 {
        return Err(std::io::Error::last_os_error()).context("SO_PEERCRED");
    }
    Ok(PeerCred { pid: c.pid, uid: c.uid, gid: c.gid })
}

pub fn hostname() -> String {
    nix::unistd::gethostname().map(|h| h.to_string_lossy().into_owned()).unwrap_or_else(|_| "localhost".into())
}
