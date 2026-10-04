# Proxmox checklist (core VM)

Core holds the vault, every recording and the only writable configuration, so its VM is set up
for durability first. Spec 5.1, 12.

| Item | Setting | Why |
|---|---|---|
| CPU type | `host` or `x86-64-v3` | Rocky Linux 10 needs x86-64-v3 |
| OS disk | its own virtual disk | rebuild without touching data |
| Data disk | a **dedicated** virtual disk for `/var/lib/swrap` (XFS) | the 90 % retention watermark must measure swrap data only; `swrap replica` refuses to back up an unmounted or empty data disk |
| Disk cache | `none` or `writeback`, **never `unsafe`** | `unsafe` drops flushes: crash-safety of recordings (fsync, atomic renames) depends on them |
| Storage | ZFS mirror, monthly scrub | detects and repairs bit rot under the recordings' own CRC/blake3 checks |
| Power | UPS with NUT, clean shutdown | the recorder fsyncs at most once a second per session |
| SSDs | with power-loss protection if possible | acknowledged writes survive a power cut |
| RAM | ECC if at all possible | the only real fix for bit flips in RAM (spec 12) |
| Swap | none, or encrypted | the vault's DEK and session keys live in RAM |
| Network | LAN only; no port forward to core | core's only internet traffic is outbound (link to edge, sessions to public hosts) |
| Backups | `swrap replica` (two disks, see [backup](backup.md)); a Proxmox backup of the VM is an extra, not a replacement | the replica is consistent per snapshot; a block-level VM backup of a running vault/recorder may not be |
| Time | NTP (chrony) on the host and in the VM | every record is ISO 8601 UTC; the edge's clock is compared with core's (alert above PT1S) |

Inside the VM: SELinux enforcing, `kernel.yama.ptrace_scope = 2` (set by `swrap-install core`).

Check after install: `swrap doctor` (integrity, SELinux, disk, clock), `swrap replica status`.
