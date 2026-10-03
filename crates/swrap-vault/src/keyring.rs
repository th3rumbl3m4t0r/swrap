//! Kernel keyring stash for the DEK (spec 14.2): a copy lives in the persistent keyring of the
//! daemon's uid, so restarting swrapd does not reseal; a reboot clears it.

use anyhow::{bail, Result};
use std::ffi::CString;

const KEYCTL_SETPERM: libc::c_long = 5;
const KEYCTL_UNLINK: libc::c_long = 9;
const KEYCTL_SEARCH: libc::c_long = 10;
const KEYCTL_READ: libc::c_long = 11;
const KEYCTL_INVALIDATE: libc::c_long = 21;
const KEYCTL_GET_PERSISTENT: libc::c_long = 22;
const KEY_SPEC_PROCESS_KEYRING: libc::c_long = -2;
const DESC: &str = "swrap:dek";

// possessor: view|read|write|search|link|setattr ; user: view
const PERM: libc::c_long = 0x3f01_0000 | 0x0000_0001;

fn persistent() -> Result<libc::c_long> {
    // uid -1 = own uid; link into the process keyring so we possess it.
    let r = unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_GET_PERSISTENT, -1 as libc::c_long, KEY_SPEC_PROCESS_KEYRING) };
    if r < 0 {
        bail!("keyctl get_persistent: {}", std::io::Error::last_os_error());
    }
    Ok(r)
}

/// Refresh the persistent keyring's expiry timer (call periodically).
pub fn touch() {
    let _ = persistent();
}

pub fn store(dek: &[u8; 32]) -> Result<()> {
    let ring = persistent()?;
    let ty = CString::new("user").unwrap();
    let desc = CString::new(DESC).unwrap();
    let id = unsafe {
        libc::syscall(libc::SYS_add_key, ty.as_ptr(), desc.as_ptr(), dek.as_ptr(), 32usize, ring)
    };
    if id < 0 {
        bail!("add_key: {}", std::io::Error::last_os_error());
    }
    unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_SETPERM, id, PERM) };
    Ok(())
}

fn find() -> Option<libc::c_long> {
    let ring = persistent().ok()?;
    let ty = CString::new("user").unwrap();
    let desc = CString::new(DESC).unwrap();
    let id = unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_SEARCH, ring, ty.as_ptr(), desc.as_ptr(), 0 as libc::c_long) };
    (id >= 0).then_some(id)
}

pub fn load() -> Option<super::Dek> {
    let id = find()?;
    let mut buf = zeroize::Zeroizing::new([0u8; 64]);
    let n = unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_READ, id, buf.as_mut_ptr(), 64usize) };
    if n != 32 {
        return None;
    }
    super::Dek::from_bytes(&buf[..32]).ok()
}

pub fn clear() {
    if let Some(id) = find() {
        unsafe {
            libc::syscall(libc::SYS_keyctl, KEYCTL_INVALIDATE, id);
            if let Ok(ring) = persistent() {
                libc::syscall(libc::SYS_keyctl, KEYCTL_UNLINK, id, ring);
            }
        }
    }
}
