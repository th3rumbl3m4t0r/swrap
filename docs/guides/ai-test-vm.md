# AI test VM isolation (swai)

swai lets an AI act on hosts through swrap: every tool call runs as a remote account under an
AI grant, recorded. Root on the AI's machine should mean nothing outside that machine (spec
24.5). Set up a dedicated VM for it:

## The VM

- **Network.** Its own VLAN or Proxmox bridge, with internet egress (packages, git) but **no
  route to the LAN** or other managed hosts. On the Proxmox host or the router: drop
  `AI-VLAN → LAN` and `AI-VLAN → management`; allow `core → AI-VM:22` (core runs the ssh).
- **No credentials for anything else.** No SSH keys, tokens, cloud credentials, git deploy keys
  with write access to anything important, no mounted shares.
- **Snapshot.** Take a Proxmox snapshot of the clean state (e.g. `clean`) to roll back to.
- **Enrollment.** Enroll it like any host (`swadd`, `swenroll`), then `swai host <label> on`
  (`ai_allowed`) and `swai grant <user> <label> root [--until …]`.

## Resetting it: `swai reset <label>`

1. On Proxmox, a role with exactly `VM.Snapshot.Rollback` and `VM.PowerMgmt`, a user without
   a password, and an API token (privilege separation on) with that role on `/vms/<vmid>` only.
   A separated token gets the permissions that both it and its user hold, so both get the ACL:
   ```
   pveum role add SwaiReset --privs "VM.Snapshot.Rollback VM.PowerMgmt"
   pveum user add swai@pve --comment "swrap: swai reset"
   pveum acl modify /vms/<vmid> --users swai@pve --roles SwaiReset
   pveum user token add swai@pve reset-<vmid> --privsep 1
   pveum acl modify /vms/<vmid> --tokens 'swai@pve!reset-<vmid>' --roles SwaiReset
   ```
2. On core (admin):
   ```
   swai reset-setup <label> --api https://<pve>:8006 --node <node> --vmid <vmid> --snapshot clean
   swai reset-token <label>          # paste swai@pve!reset-<vmid>=<secret>
   swai reset-ca < pve-root-ca.pem   # /etc/pve/pve-root-ca.pem from the Proxmox host
   ```
3. Users with an AI grant on it: `swai reset <label>` (refused while swai sessions work on the
   host, unless `--force`). It rolls back, starts the VM, waits for ssh and checks the host keys
   are still the pinned ones: take the snapshot **after** enrollment, or the keys will differ.

## What swrap does on its side

- The harness (Claude Code, opencode) runs in a bwrap sandbox on core with its own network
  namespace (loopback only: the recording proxy), as the `swai` user, in SELinux domain
  `swrap_ai_t` (permissive for now: no network, vault or swrap data once enforced).
- Every model request and reply, every tool call and its full output, and the terminal are
  recorded; `--loose` (no permission prompts) is allowed for one host at a time only and is
  marked in the recording and the audit.
- Admins cannot use swai (separation of duties); AI grants are separate from human grants.
