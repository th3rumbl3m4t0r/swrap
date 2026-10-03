//! Address classification for the default `route` (spec 4.2).

use ipnet::IpNet;
use std::net::{IpAddr, ToSocketAddrs};

pub fn is_internal_ip(ip: IpAddr, extra: &[String]) -> bool {
    let builtin = match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_loopback(),
        IpAddr::V6(v6) => {
            let s = v6.segments()[0];
            (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80 || v6.is_loopback()
        }
    };
    builtin || extra.iter().filter_map(|c| c.parse::<IpNet>().ok()).any(|n| n.contains(&ip))
}

/// Resolve `addr` and decide: any internal address → internal.
pub fn address_is_internal(addr: &str, extra: &[String]) -> bool {
    if let Ok(ip) = addr.parse::<IpAddr>() {
        return is_internal_ip(ip, extra);
    }
    match (addr, 22).to_socket_addrs() {
        Ok(it) => it.map(|sa| sa.ip()).any(|ip| is_internal_ip(ip, extra)),
        // Unresolvable from here: treat as internal (core can decide later).
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classify() {
        assert!(address_is_internal("192.168.1.5", &[]));
        assert!(address_is_internal("fd12::1", &[]));
        assert!(address_is_internal("fe80::1", &[]));
        assert!(!address_is_internal("8.8.8.8", &[]));
        assert!(address_is_internal("100.64.1.1", &["100.64.0.0/10".into()]));
    }
}
