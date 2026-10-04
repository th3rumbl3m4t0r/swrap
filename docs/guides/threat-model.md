# Threat model

What swrap protects, against whom, and what is left. Spec 4.7, 12, 14, 21; as built 2026-10-03.

## Assets

1. **Credentials to managed hosts**: private keys in the vault (core), used only through a
   per-session filtering ssh-agent; tokens and API keys (table, Proxmox, inference backends).
2. **The record**: recordings (keystrokes included), audit log, run logs; signed, crash-safe.
3. **Authority**: users, grants (human and AI), host settings, firewall allow-lists (config git).
4. **The managed hosts** themselves, reachable as root through swrap.

## Trust boundaries

```
internet ──> edge (sshd, swrap-edged, web relay; shared with Stalwart)
                │  one SSH link, opened by core (unix-socket forwards only)
LAN ─────────> core (vault, RBAC, recordings, web UI, swai)  ──ssh──> managed hosts
```

- **Core** is LAN-only, no inbound internet. It is the single writer and decides everything.
- **Edge** holds no keys and no RBAC: every session and request is a live question to core, and
  signatures are made on core, bound to the host's key (`session-bind`, hostbound).
- **Managed hosts** accept swrap's keys only from the nodes that connect (`from=`), no forwarding.

## Attackers and what they get

| Attacker | Can | Cannot |
|---|---|---|
| Internet, unauthenticated | brute-force sshd (PerSourcePenalties, fail2ban, `MaxStartups`), the web login if allow-listed (argon2 for every name, unknown ones too, so names cannot be told apart by timing; fail2ban jail; IOC reporting) | reach core |
| AAA user (non-admin) | sessions to granted host accounts, recorded; own recordings in the web UI | other users' recordings; keys (the agent signs only for their session, with a signature budget and window); un-recorded host access (outbound SSH on edge is only for `swrap-edge`; SFTP is proxied, not passed through) |
| AI (swai) | tool calls on hosts it has AI grants for, as the granted account, recorded, budgeted | the vault, other hosts, the network (sandbox loopback only), admin functions |
| Edge compromise (swrap-edged, sshd, or Stalwart + local root) | read live traffic of sessions running on edge; start sessions **as any user** to what that user may reach from edge; capture an admin password typed on edge while present | steal keys; keep access after a rebuild; change RBAC, users or firewall; read stored recordings; reach internal networks except through sessions core authorizes and records |
| Core compromise | everything | — (hence LAN-only, SELinux, minimal services, offline recovery key) |
| Disk theft (core) | recordings and config (stored in clear so search works, decision 21.2) | the vault (encrypted; DEK only in RAM/keyring, wrapped by admin passwords and the offline recovery key) |
| Malicious admin | most things; every action lands in the audit log (daily swrec files, signed at rollover) and sessions are recorded | alter a closed recording or audit day without `swrec verify` noticing (CRC, chain, signature); an admin with root on core can still delete them, which the replica's snapshot history keeps for a while |

## Mitigations to configure

- Per grant `via = ["core", "edge"]` (e.g. root on sensitive hosts LAN-only); per host
  `edge_allowed`.
- Isolate Stalwart on the edge ([stalwart](stalwart.md)): sandboxing, SELinux enforcing, hidepid.
- Keep the vault recovery key and break-glass key offline; at least two admins with vault
  passwords.
- Alerts on: unreachable hosts, new security updates, reboots needed, sudoers drift
  (`swrap-*` files unexpected, modified or missing), edge clock offset, doctor findings.

## Residual risks (as built)

- swrapd, swrap-web and the swai harness run in their own SELinux domains but still
  **permissive** (`swrap doctor --selinux`); until enforced, SELinux contains nothing there.
- An edge shared with a mail server is only as contained as that host is configured
  (Stalwart sandboxing, SELinux enforcing, hidepid); swrap does not set these up. See
  [stalwart](stalwart.md).
- Recordings at rest are not encrypted (searchable by design); VM disk encryption is the
  documented answer.
- No off-machine backup by default ([backup](backup.md)).
- Bit flips in RAM on non-ECC hardware (spec 12).
