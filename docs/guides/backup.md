# Backup and restore (core)

Edge needs no backup: it is rebuilt from core (`swedge deploy <label>`), then the link key is
re-authorized and its recording key re-pinned (spec 21.7). Everything else lives on core.

## What matters

| What | Where | Notes |
|---|---|---|
| Vault (host keys, tokens, API keys, wraps) | `/var/lib/swrap/vault` | encrypted at rest; useless without an admin vault password or the recovery key |
| Configuration (git) | `/var/lib/swrap/config` | users, hosts, grants, profiles, firewall, AI config; full history |
| Inventory (git) | `/var/lib/swrap/state` | host facts, packages, history |
| Recordings, audit, runs | `/var/lib/swrap/rec`, `audit`, `runs`, `logs` | signed; `swrec verify` checks them after a restore |
| Recording signing key, link key, trust | `/var/lib/swrap/recsign`, `link`, `trust` | the link key is deliberately outside the vault (the link comes up while sealed) |
| System configuration | sshd/PAM/systemd/SELinux/fstab, SSH host keys | copied into the rebuild kit |
| **Offline** | the vault recovery key, the break-glass private key, an admin vault password | never on core; without one of the first or third, a restored vault stays sealed |

The search index (`/var/lib/swrap/index`) is not backed up; it is rebuilt.

## How: `swrap replica`

Core has two disks and keeps everything needed to rebuild on **both** (no RAID mirror):

- Disk A (data): `/var/lib/swrap` and the rebuild kit at `/srv/rebuild`.
- Disk B (OS): the OS, the source tree, the rebuild kit at `/home/rebuild`, and a versioned,
  deduplicated rustic repository of `/var/lib/swrap` at `/home/rebuild/data`.
- The kits hold: a git mirror of the source, vendored crates (offline rebuild), release binaries
  (rustic included), system configuration and host keys, the spec, the recording signing trust,
  and `README-REBUILD.md` with the step-by-step restore for either disk dying.
- `swrap-replica.timer` runs `swrap replica sync` every PT15M (one at a time, flock); run it by
  hand after changes too. Snapshot thinning: everything within 2 days, then 72 hourly, 60 daily,
  26 weekly, 24 monthly.
- Safety: no data snapshot is taken unless `/var/lib/swrap` is its own mount and holds the config
  repository, so a dead data disk cannot produce empty snapshots that later prune the real ones.
- `swrap replica status` and `swrap replica verify`; `swrap doctor` reports kit binaries that
  differ from the installed ones (run `swrap replica sync` after upgrades).

## Restore

Follow `README-REBUILD.md` in either kit (`/srv/rebuild` or `/home/rebuild`): one procedure for the
OS disk dying, one for the data disk dying. Afterwards: `restorecon -R /var/lib/swrap`,
`swrap install core --from …`, unseal with an admin login (or the recovery key), and
`swrec verify` over the recordings.

## Not covered (recommended)

- **A copy off the machine.** Both disks sit in one VM on one host: fire, theft or a Proxmox
  storage failure takes both. Add an off-site rustic repository (e.g. `rustic copy` of
  `/home/rebuild/data` to a remote or removable repository, its password kept offline) or a
  Proxmox backup of the VM to another box.
- Test a restore on a scratch VM now and then; `README-REBUILD.md` is only as good as its last run.
