# swrap

swrap is a self-hosted SSH jump host that puts **authentication, authorization and audit**
(AAA) in front of every Linux server you run. People log in to swrap with their SSH key,
then open a session to a host they have been granted (`sw web1`). They never hold a key for
that host, and every session is recorded, signed and searchable afterwards.

**Authenticate.** SSH keys only. Users log in with public-key authentication and nothing
else: no passwords to guess, phish or reuse. Admins need their key *and* their vault
password. Accounts on the managed hosts are password-locked; swrap reaches them with
per-host keys that it generates itself. Host keys are pinned at enrollment, so a
swapped or spoofed server is refused, not trusted on first use.

**Authorize.** Access is granted per user, per host and per remote account (`alice` may
be `root` on `web*` and `deploy` on `@lab`), optionally only for a while (`--for PT8H`) and
only from the LAN or also from the internet. The private keys never leave the core's
encrypted vault. For each session, a filtering agent signs exactly one login, for the
granted account on the pinned host, and refuses everything else. Revoking a grant or a
user takes effect for the next session at once; there are no copied keys to chase down.

**Audit.** Every session is recorded: terminal output, the commands run, the keystrokes
typed inside it, the negotiated crypto and the host's identity. Recordings are
hash-chained and signed, so tampering is detectable (`swrec verify`). You can replay them
in the terminal or the web player, read them as timestamped text, and search across all of
them (`swsearch 'host:web* cmd:/dnf .*install/ out:"permission denied"'`). Fleet commands,
file transfers (SFTP / scp), user and key changes, and every admin action land in the
record as well. Admin actions go to a daily, signed audit log.

**What it is for.** A team (or one person with many machines) that needs to answer *who
did what, on which host, when*, to give a contractor or a colleague time-limited
access without handing out keys, and to revoke it in one command. It also suits putting an
AI agent on your servers under the same rules as a person. swrap runs on one **core** VM
on your LAN (Rocky / RHEL 10, SELinux) and an optional internet-facing **edge** node that
holds no keys. It manages hosts that speak OpenSSH. Around that it covers host
enrollment, accounts on the hosts and key rotation, inventory and updates across the fleet,
an AI workbench (`swai`), firewall allow-listing and an off-disk replica for recovery.

**Log in:** LAN → `ssh you@<core>` · internet → `ssh you@<edge>` (optional edge node)

```
sw [ruser@]host [-- cmd]      open a recorded session (keystrokes recorded!)
swls                          hosts & accounts you may use  (* = default account)
swlog --since P1D             your recordings (ISO 8601 durations: PT1H, P1D, P7D)
swcat <id> [--cmds] [--keys]  recording as text with timestamps
swplay <id> [--speed 2]       replay in the terminal
swsearch 'host:web* cmd:/dnf .*install/ out:"denied"'   search (window:P7D/now …)
swpasswd                      set your web password
swrap status                  vault / alert status
swai                          AI (opencode / Claude Code) on one host or the whole AAA: quick questions, then chat
swai --loose …                one host, no permission prompts (Claude Code --dangerously-skip-permissions)
swai ls · swai attach [id]    AI sessions survive disconnects (like tmux); ctrl-\ detaches
swai -c  ·  swai kill <id>    continue the last AI conversation  ·  end a session
swupdate '<targets>' [--app p]  dnf upgrade where you are root ('web*', @tag, @all, a,b, !x): live output, recorded
swinv ['<targets>']           inventory: OS, kernel, updates, security fixes, reboot needed (also every PT6H)
swx '<targets>' -- <command>  run a command on hosts · swr <script> '<targets>' [-- args]: a script
  --secret-env NAME           pass $NAME without recording it (set it with: read -rs NAME; export NAME)
sftp you@<core>               one folder per host you may use (web1/, deploy@web1/ …); scp works too (not rsync)
```

Web GUI (search + player + transcript): **https://&lt;core&gt;/** from the LAN, **https://&lt;edge&gt;:8443/** from outside. Allow your IP first: `swfw web allow --my-ip --for PT8H`, run as an admin; the LAN is always allowed. Every login and every `sw` prints a direct `swrap: view https://…/play/<id>` link.

Admins, additionally:

```
swadd --host <addr> --label <l>    then paste the snippet on the host, then:  swenroll <l>
swdel <l> [--purge]                swcrypto test
swadm user add|del|list|disable|enable <u> [--admin] [--key '…']
swadm key add|del|list <u> …       swadm grant <u> <hosts> <rusers> [--via core,edge] [--for PT8H]
swadm revoke <u> <grant-id>        swadm show <u>
swadm vault status|seal|passwd|add-admin <u>|recover        swunlock
swuser add|del|lock|unlock|sudo|list|adopt <targets> <ruser>   accounts on hosts: vault key, no password, swrap sudo
swrotate <targets> [--user u] [--algo a]   rotate the vault-held keys: add, verify, remove old, verify refused, retire
swfw web allow|revoke …  ·  swfw ssh block|unblock …  ·  swfw list|status
swedge deploy <l> [--public-name …]  ·  swedge status  ·  swrap doctor [--scrub]
swai host <l> on|off  ·  swai grant <u> <hosts> <accounts> [--until ISO]  ·  swai revoke-grant <u> <id>  ·  swai approval ask|allow
swai backend add|del|list|test|key   (claude = Claude Code with your plan; local servers by IP)  ·  swai status
swai limits [<key> <value>]   tool budget per session, handoffs in a row, rates
swai reset <label> [--force]  roll an AI test VM back to its Proxmox snapshot (reset-setup, reset-token, reset-ca)
swrap table …                 optional ticketing / asset integration (see below)
```

## Quickstart

1. **An account.** An admin runs `swadm user add alice --key 'ssh-ed25519 AAAA…'` and `swadm grant alice 'web*,@lab' root`. Alice logs in with her key. Her shell on swrap is recorded too: output and commands, never keystrokes.
2. **A session.** `sw web1` connects to the most privileged account she is granted (`root` first), or `sw deploy@web1`. The banner shows the recording id and link. Everything typed inside `sw`, including passwords at prompts, is recorded. For secrets, stay in the swrap shell (`read -rs X`), which never records keystrokes.
3. **Look back.** `swlog --since P1D`, `swcat <id> --cmds`, `swplay <id>`, `swsearch 'window:P7D/now cmd:/rm -rf/'`, or the web GUI.
4. **Admins: add a host.**
   1. `swadd --host 10.0.0.7 --label db1` prints a snippet with time-limited enrollment keys; paste it on the host as root.
   2. `swenroll db1` pins the host key (you confirm its fingerprint) and creates a per-host key in the vault. It then removes the enrollment keys and checks that they no longer work.

   A private address belongs to the network of the node you are logged into. Hosts in a cloud network behind the edge are enrolled and reached via edge automatically.
5. **Admins: after a reboot** the vault is sealed and no sessions work until an admin logs in with key + vault password (on core or edge).

Times are ISO 8601 everywhere (`2026-09-25T10:00:00+02:00`, `P7D`, `P1D/now`); other formats are rejected. `--help` works on every command; the full design and every command's behaviour are in [docs/aaa.md](docs/aaa.md).

## How it works

- **Core and edge.** The core sits on the LAN and holds the vault, the recordings and all configuration (a git repository, so every change is committed). The optional edge sits on the internet. It gets a signed, rollback-protected snapshot of users, keys and firewall rules over a link that the core opens outbound, and it holds no host keys. When a session runs on the edge, its logins are signed remotely by the core's filtering agent, and its recording is streamed to the core and checked there. A compromised edge can neither steal keys nor change who may do what. Hosts that only the edge can reach (e.g. cloud VMs on a private network) are enrolled and used through it. Grants say whether they apply from core, from edge or both (`--via`).
- **Keys and vault.** Host keys are generated into the vault: XChaCha20-Poly1305 under a data key that is wrapped by each admin's password (argon2id) and by an offline recovery key. The vault is sealed after a reboot; an admin login unseals it. Each session gets its own `ssh-agent` behind a filtering proxy. It offers one key, allows only a `session-bind` to the pinned host key and a bounded number of userauth signatures for the expected remote user, and refuses and audits everything else. `swrotate` replaces keys and verifies that the old one is refused. Retired keys are destroyed after P30D.
- **Accounts on hosts.** `swuser` creates accounts with their own vault key and a locked password, with optional NOPASSWD sudo through `visudo`-checked `swrap-*` files. The inventory reports sudoers drift (unexpected, modified or missing files). The host's sshd drop-in is installed with a dead-man's-switch rollback.
- **Recordings.** Each session is one `swrec` file: coalesced output frames, keystrokes, commands (from the shell integration installed on enrolled hosts, else a heuristic), `fdatasync` checkpoints, a blake3 hash chain and an ed25519 end signature. A torn write damages only its own tail. Files are gzip-compressed after P7D (crash-safe) and evicted oldest first at a disk watermark, never live ones, audit last. `swrap doctor` checks integrity daily and scrubs weekly.
- **The swrap shell.** Users get `swrap-shell` on core and edge: output and commands are recorded, keystrokes never. A nested `sw` links the two recordings. Forged markers are ignored, and the shell fails closed.
- **SFTP and scp.** AAA users see one directory per host account they may use. The transfer is proxied and recorded by a worker on core, from LAN and edge logins alike.
- **Firewall.** swrap manages only its own nftables `table inet swrap`, which only drops: SSH blocks, a per-source rate limit and the web allow-list. Your firewall stays in charge of accepting.
- **Web GUI.** rustls, an IP allow-list, argon2 password checks (unknown names too, so they cannot be told apart by timing) with backoff. It offers search with live progress, an asciinema-based player with a command timeline, keystroke overlay, signature verification and live follow, plus a text transcript.
- **SELinux.** On core, swrapd runs as `swrapd_t`, swrap-web as `swrap_web_t` and the swai harness as `swrap_ai_t`, which has no network beyond its sandbox loopback and no access to the vault or other swrap data. The domains ship permissive. `swrap doctor --selinux` shows what enforcing would still deny, and once that stays empty `swrap install selinux --enforce` switches them over.

## swai: AI on your hosts, recorded

`swai` opens an AI coding agent against one host or the whole AAA. Five small "choose an option" screens come first: target (**one host** or **aaa**), host, inference (**claude**, a local server by IP, or **add new IP…**), model (those used with that backend in the last P30D, or everything it serves), and effort (low … max; ignored if the model has none). Your previous answers are preselected. The agent is **Claude Code** for **claude**, and [opencode](https://github.com/anomalyco/opencode) (pinned 1.18.32) for local servers. Claude Code follows Anthropic's latest channel: `swrap-claude-update.timer` runs `swrap claude-code-update` nightly (03:30 plus up to 45 min). It installs a new version only if the release manifest is signed by Anthropic's Claude Code release key (fingerprint pinned), the binary matches the manifest's sha256, and the binary starts. A session keeps the version it started with; superseded versions are removed after P8D.

- **AI access is separate from yours.** The AI may act only where two things hold: an admin enabled the host (`swai host <l> on`) *and* granted you AI access (`swai grant <you> <hosts> <accounts>`). Your human grants never count, and admins cannot use swai at all. `exec`, `write_file` and `edit_file` ask you in the TUI before running; for unattended runs an admin switches that off with `swai approval allow` (back with `swai approval ask`).
- **Two targets.** *One host*: four tools (`exec`, `read_file`, `write_file`, `edit_file`) on that host, a short prompt and a 200k-token context cap, so it stays cheap and compacts early. *aaa*: the same tools on every host you have AI access to, plus your swrap records (`sessions`, `search`, `transcript`), with the model's full context.
- **Claude with your plan (Pro/Max).** Pick **claude**. The first time, Claude Code asks you to log in: choose "Claude account with subscription", open the link it shows (press `c` to copy it), approve, and paste the code back. The login is kept for your AAA user and every later session starts signed in. Claude Code gets no tools of its own (no shell, files or web), only swrap's. Its model traffic goes through swrap's recording proxy unchanged (your sign-in token is passed through, never stored). Its sign-in and account calls may reach only Anthropic's own hosts, through a tunnel that is logged in the recording.
- **Contained.** The agent runs in a bubblewrap sandbox as the unprivileged `swai` user, with no network (only a loopback bridge to this session's proxy), no shell, and no view of the host. The proxy fetches any API key from the vault for every request, so a sealed vault stops keyed backends and all host tools.
- **Recorded.** Each session is one `ai` recording: the terminal (keystrokes included), every model request and reply (each message stored once and referenced by hash), and every tool call with its full output. The web player opens such sessions on a chat view (prompts, replies, expandable tool calls, tokens and latency per turn, links into the TUI replay). Search with `prompt:`, `reply:`, `tool:`, `args:`, `cmd:` and `out:`.
- **Limits and handoff.** Per user: concurrent calls, calls per hour and sessions. Per session: a tool budget; when it runs out the agent writes a briefing and continues in a fresh session. Per backend: `max_concurrent` requests. There is also a free-memory floor (`swai limits`).
- **Like tmux.** Closing the terminal, losing SSH or the edge link only *detaches*: the agent keeps working on core. `swai ls` lists your sessions, `swai attach [id]` (or plain `swai`) brings one back, **ctrl-\** detaches on purpose, `/exit` ends it. Detached sessions end after P7D.
- **Slow models are fine.** Local models at high effort may think silently for many minutes. swrap only cuts a request after the backend's `timeout` of silence (PT1H by default), and when you interrupt (Esc) it closes the connection so the server stops generating at once.
- **Test VMs.** `swai reset <label>` rolls a dedicated AI test VM back to its Proxmox snapshot, with a token that may do nothing else ([guide](docs/guides/ai-test-vm.md)).
- **Setup (admin).** Nothing for **claude**. A local server (LM Studio, llama.cpp, vLLM, Ollama) is added by any AI user through "add new IP…" (common ports are probed), or with `swai backend add <name> http://<ip>:<port>`. For a Claude API key instead of a plan (billed per token, runs opencode): `swai backend add anthropic https://api.anthropic.com --api anthropic --key`, then `swai backend key anthropic`.

## Overhead

| | |
|---|---|
| Keystroke latency added by `sw` (echo round-trip vs plain `ssh`) | +0.11 ms median, p99 under 1 ms |
| Memory per concurrent `sw` session on core | ~15 MiB (worker 6 + ssh 8 + client 3.4) |
| Edge, 20 concurrent sessions | ~55 MiB in total (`swrap.slice` is capped at 512 MiB) |
| swai session with Claude Code | 250–320 MiB, almost all of it Claude Code itself; swrap's worker 14–42 MiB |
| swai recording size | ~0.8 MiB per session-hour (gzip 4–9× after a week) |

Session limits by default: 10 per user and 100 on core; 10 per user and 20 in total on edge. OpenSSH ≥ 9.5 adds its own deliberate keystroke delay (`ObscureKeystrokeTiming`) with or without swrap; the latency figure was measured with it off on every hop.

## Backups: `swrap replica`

`swrap replica` keeps a second copy on a second disk: a rustic (deduplicated, versioned) backup of `/var/lib/swrap`, plus two rebuild kits. Each kit holds a git mirror of the source, vendored crates and release binaries, the system configuration (sshd, PAM, systemd, SSH host keys, disk layout) and a `README-REBUILD.md` for either disk failing. `swrap-replica.timer` syncs every PT15M; `swrap replica status` and `swrap replica verify [--read-data]` report on it. The disk layout and paths follow the reference deployment (see `crates/swrap-cli/src/replica.rs` and the [backup guide](docs/guides/backup.md)). A copy off the machine is still up to you.

## Install

```
cargo build --release
./target/release/swrap install core --from target/release --admin-key 'ssh-ed25519 …'
```

Target: Rocky / RHEL 10 with SELinux, on a VM of its own. The installer is idempotent. It sets up the users, vault, sshd and PAM, systemd units, SELinux module and firewall table. The edge is deployed from the core with `swedge deploy <label>`. An RPM spec is in `packaging/` (offline build from `packaging/make-sources.sh`; the package installs files only, the commands above do the setup).

Notes for operators:

- **Root keeps password SSH on the core.** The installer assumes the core may still be administered as root with a password, so `AllowGroups` also admits `root`. Only AAA users and admins are bound to the key-only rules above. Remove `root` from `/etc/ssh/sshd_config.d/06-swrap.conf` when you no longer need it.
- Session sshd drop-ins on core are `06-swrap.conf` (globals) and `99-swrap-match.conf` (Match blocks); managed hosts get `05-swrap.conf`.
- Guides: [Proxmox checklist](docs/guides/proxmox.md), [edge shared with a Stalwart mail server](docs/guides/stalwart.md), [backup and restore](docs/guides/backup.md), [threat model](docs/guides/threat-model.md), [AI test VM isolation](docs/guides/ai-test-vm.md).

## Layout

```
crates/swrap-core        ISO 8601, atomic writes, git, frames, config models, RBAC/targets, API types
crates/swrec             record format: writer, reader/verifier, gzip, renderers, search; `swrec` tool
crates/swrap-vault       data key, wraps, recovery key, key files, manifest, kernel keyring
crates/swrapd            core daemon, session worker (`swrapd worker`), edge daemon (`swrapd edge`)
crates/swrap-cli         `swrap` multi-call client (sw, swai, swls, swlog, swcat, swplay, swsearch, swadm,
                         swadd, swenroll, swdel, swfw, swuser, swrotate, swunlock, swpasswd, doctor, replica, install)
crates/swrap-shell       recorded login shell
crates/swrap-pam-unlock  pam_exec helper (admin login unseals the vault)
crates/swrap-web         web GUI
docs/aaa.md              the design document
```

## Tests

- `cargo test`: ISO parsing, RBAC and targets, framing, the swrec writer/reader including tamper and torn-write cases, crash-at-every-step compression, the vault (bit flips in wraps never yield a wrong key), agent filtering, the OSC filter and renderers, search.
- `swrec fuzz --iterations 10000`: plain and gzip files. No panics, and damage stays local.
- `tests/acceptance/acceptance.sh`: acceptance tests against a live installation. The safe ones run by default; destructive ones run only when named, with `SWRAP_ACCEPT_DESTRUCTIVE=yes`; `--list` shows them.

## Optional: table integration

swrap can raise tickets and keep host assets in a [table](https://github.com/th3rumbl3m4t0r/Table) server (inventory changes, new hosts). It is off until configured: set `endpoint` (and optionally `git_web` / `git_hosts` for linking git checkouts) in `config/table.toml`, then store the form tokens with `swrap table token …`.

## License

Copyright (C) 2026 th3rumbl3m4t0r

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. See [LICENSE](LICENSE).

`crates/swrap-web/assets/asciinema-player.*` is the vendored [asciinema-player](https://github.com/asciinema/asciinema-player) under the Apache License 2.0 (see `asciinema-player.LICENSE`). `crates/swrap-cli/assets/claude-code-release.asc` is Anthropic's public Claude Code release-signing key, used only to verify updates.
