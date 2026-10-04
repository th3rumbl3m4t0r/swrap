# Edge co-located with Stalwart (mail)

A budget compromise (spec 5.3, 4.7): the edge VM also runs the mail server, which widens the
edge's attack surface. What swrap needs and does, and what the host should provide.

## What swrap takes and leaves alone

- **Ports.** swrap uses 22 (sshd: users, admins, the link) and 8443 (web relay, allow-listed).
  Stalwart keeps its own (25, 465, 587, 993, 4190, 443, 80 for HTTP-01 ACME). `web_mode = "sni"`
  (swrap-edged on 443, passing everything that is not `swrap.<domain>` to Stalwart with PROXY v2)
  exists in the spec but the default, `port` mode on 8443, touches nothing of Stalwart's.
- **Firewall.** swrap manages only `table inet swrap`. It never flushes the ruleset, never touches
  firewalld or Stalwart rules, and its chains only *drop* (blocked or non-allow-listed swrap
  ports, rate limits). Accepting stays with the host's firewall.
- **Outbound SSH.** Only the `swrap-edge` user may open TCP to managed hosts' SSH ports
  (`meta skuid`), so shell users cannot bypass recording with their own `ssh`.
- **Resources.** swrap's units run in `swrap.slice` (`MemoryHigh=384M`, `MemoryMax=512M`,
  `CPUWeight=100`; as configured). The spool is capped in software (spec 8.8).
- **Logs.** Only swrap units, sshd and audit/SELinux events are shipped to core, never mail logs.
- **sshd changes** (`swedge deploy`) are checked with `sshd -t`, must keep root's key login, and
  roll back by themselves within PT120S unless core confirms them over a fresh connection.

## What the host should provide

| Requirement | Why |
|---|---|
| Stalwart as its own unprivileged user | a mail-server bug is not root |
| Stalwart sandboxed: `ProtectSystem=strict`, `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectHome=yes`, `ReadWritePaths=` its data only (or rootless podman) | a mail-server bug cannot reach swrap's files or the spool |
| `MemoryLow=` on the Stalwart unit (its baseline) | a burst of sessions never starves mail |
| Stalwart data directories 0700 | other local users cannot read mail |
| SELinux enforcing | containment for both services |
| `/proc` mounted `hidepid=2,gid=swrap-admin` | AAA users with bash on edge cannot see other users' processes (Stalwart's, the link's) |
| Users not in any Stalwart group | no access to mail data (swrap creates its own groups) |
| Only the ports above reachable from the internet | Stalwart's admin listener (`8080` by default) should not be public: bind it to loopback or block it at the provider firewall |

Suggested drop-in for Stalwart, to try in a maintenance window (check mail flow, ACME renewal and
the admin UI afterwards; `/opt/stalwart` is the default install path, adjust to yours):

```ini
# /etc/systemd/system/stalwart.service.d/10-hardening.conf
[Service]
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/opt/stalwart
MemoryLow=256M
```

`/proc` with hidepid (fstab, then `mount -o remount /proc`):

```
proc /proc proc defaults,hidepid=2,gid=swrap-admin 0 0
```

Loopback access to Stalwart's ports stays possible for shell users; that is harmless for
authenticated mail and noted for completeness.
