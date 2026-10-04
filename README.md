# swrap

Recorded SSH access to your hosts. Log in to a swrap node, then `sw <host>`. Every session is recorded, signed, searchable and replayable. Private keys never leave the core's vault.

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
swai limits [<key> <value>]   tool budget per session, handoffs in a row, rates (admin); out of budget: the AI hands off
swai reset <label> [--force]  roll an AI test VM back to its Proxmox snapshot (admin sets it up: reset-setup, reset-token, reset-ca)
swuser add|del|lock|unlock|sudo|list|adopt <targets> <ruser>   accounts on hosts: vault key, no password, swrap sudo (admin)
swrotate <targets> [--user u] [--algo a]   rotate the vault-held keys: add, verify, remove old, verify refused, retire (admin)
swai ls · swai attach [id]    AI sessions survive disconnects (like tmux); ctrl-\ detaches
swai -c  ·  swai kill <id>    continue the last AI conversation  ·  end a session
swupdate '<targets>' [--app p]  dnf upgrade where you are root ('pm*', @tag, @all, a,b, !x): live output, table, recorded
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
swfw web allow|revoke …  ·  swfw ssh block|unblock …  ·  swfw list|status
swedge deploy <l> [--public-name …]  ·  swedge status  ·  swrap doctor [--scrub]
swrap table status|sync|test-ticket|token <ticket|asset-read|asset-update|asset-create>   (tickets, asset aaa_* fields, new assets in table)
swrap table admin-password | agent <label>   (aaa_adm login into the vault; endpoint agent + its forms, also automatic)
swai host <l> on|off  ·  swai grant <u> <hosts> <accounts> [--until ISO]  ·  swai revoke-grant <u> <id>  ·  swai approval ask|allow
swai backend add|del|list|test|key   (claude = Claude Code with your plan; local servers by IP)  ·  swai status
```

## Quickstart

1. **An account.** An admin runs `swadm user add alice --key 'ssh-ed25519 AAAA…'` and `swadm grant alice 'web*,@lab' root`. Alice logs in with her key. Her shell is recorded: output and commands, never keystrokes.
2. **A session.** `sw web1` connects to the most privileged account she is granted (`root` first), or `sw deploy@web1`. The banner shows the recording id and link. Everything typed inside `sw`, including passwords at prompts, is recorded. For secrets, stay in the swrap shell (`read -rs X`), which never records keystrokes.
3. **Look back.** `swlog --since P1D`, `swcat <id> --cmds`, `swplay <id>`, `swsearch 'window:P7D/now cmd:/rm -rf/'`, or the web GUI.
4. **Admins: add a host.**
   1. `swadd --host 10.0.0.7 --label db1` prints a snippet with time-limited enrollment keys; paste it on the host as root.
   2. `swenroll db1` pins the host key (you confirm its fingerprint) and creates a per-host key in the vault. It then removes the enrollment keys.

   A private address belongs to the network of the node you are logged into. Hosts in the cloud network behind the edge are enrolled and reached via edge automatically.
5. **Admins: after a reboot** the vault is sealed and no sessions work until an admin logs in with key + vault password (on core or edge).

Times are ISO 8601 everywhere (`2026-09-25T10:00:00+02:00`, `P7D`, `P1D/now`); other formats are rejected. More detail: the spec `aaa.md` (sections 9–17 describe every command), `--help` on any command, and the sections below.

## swai: AI on your hosts, recorded

`swai` opens an AI coding agent against one host or the whole AAA. Five small "choose an option" screens come first: target (**one host** or **aaa**), host, inference (**claude**, a local server by IP, or **add new IP…**), model (those used with that backend in the last P30D, or everything it serves), and effort (low … max; ignored if the model has none). Your previous answers are preselected. The agent is **Claude Code** for **claude**, and [opencode](https://github.com/anomalyco/opencode) (pinned 1.18.32) for local servers. Claude Code follows Anthropic's latest channel: `swrap-claude-update.timer` runs `swrap claude-code-update` nightly (03:30 plus up to 45 min) and installs a new version only if its release manifest is signed by Anthropic's Claude Code release key (fingerprint pinned), the binary matches the manifest's sha256, and it starts. Versions live in `/usr/libexec/swrap/claude-code/v/<version>/`; a session keeps the version it started with, and superseded versions are removed after P8D. The model screen offers the aliases (opus, sonnet, haiku, fable) and the newest specific models that version knows, e.g. `claude-opus-5-5`. `swrap claude-code-update --check` shows whether an update is waiting.

- **Two targets.** *One host*: four tools (`exec`, `read_file`, `write_file`, `edit_file`) on that host, a short prompt and a 200k-token context cap, so it stays cheap and compacts early. *aaa*: the same tools on every host you have AI access to, plus your swrap records (`sessions`, `search`, `transcript`), with the model's full context.
- **Claude with your plan (Pro/Max).** Pick **claude**. The first time, Claude Code asks you to log in: choose "Claude account with subscription", open the link it shows (press `c` to copy it), approve, and paste the code back. The login is kept for your AAA user (in your swai home on core, readable only by the sandbox user) and every later session starts signed in; `/login`, `/logout`, `/usage` (your plan limits), `/model` and `/effort` work as usual. Claude Code gets no tools of its own (no shell, files or web), only swrap's. Its model traffic goes through swrap's recording proxy unchanged (your sign-in token is passed through, never stored by swrap); its sign-in and account calls may reach only api.anthropic.com, platform.claude.com, claude.ai and claude.com, through a tunnel that is logged in the recording.
- **Slow models are fine.** Local models at high effort may think, or build a large tool call, silently for many minutes. swrap only cuts a request after the backend's `timeout` of silence (PT1H by default; `swai backend set <name> --timeout PT2H`), and when you interrupt (Esc), it closes the connection so the server stops generating at once.
- **Like tmux.** Closing the terminal, losing SSH or the edge link only *detaches*: opencode keeps working on core. `swai ls` lists your sessions, `swai attach [id]` (or plain `swai`) brings one back, **ctrl-\** detaches on purpose, `/exit` ends it. Detached sessions end after P7D. `swai -c` reopens your last conversation in a new session.
- **AI access is separate from yours.** The AI may act only where two things hold: an admin enabled the host (`swai host <l> on`) *and* granted you AI access (`swai grant <you> <hosts> <accounts>`). Your human grants never count, and admins cannot use swai at all. `exec`, `write_file` and `edit_file` ask you in the TUI before running; for unattended runs an admin switches that off with `swai approval allow` (back with `swai approval ask`).
- **Contained.** opencode runs in a bubblewrap sandbox as the unprivileged `swai` user. It has no network (only a loopback bridge to this session's proxy), no shell, and no view of the host. The proxy fetches the API key from the vault for every request (a sealed vault stops keyed backends and all host tools) and applies the chosen effort; if a model rejects effort, it retries without and notes it.
- **Recorded.** Each session is one `ai` recording: the terminal (keystrokes included), every model request and reply (each message stored once and referenced by hash), and every tool call with its full output. The web player opens such sessions on a chat view (prompts, replies, expandable tool calls with target, exit code, arguments and result, tokens and latency per turn, an ISO time scrubber, links into the TUI replay); the TUI player, the Transcript tab and `swcat` are there too. Search with `prompt:`, `reply:`, `tool:`, `args:`, `cmd:` and `out:`.
- **Setup (admin).** Nothing for **claude**. A local server (LM Studio, llama.cpp, vLLM, Ollama) is added by any AI user through "add new IP…" (common ports are probed), or with `swai backend add <name> http://<ip>:<port>`. A Claude API key instead of a plan (billed per token, runs opencode): `swai backend add anthropic https://api.anthropic.com --api anthropic --key`, then `swai backend key anthropic`.

## Performance (measured on the reference VM: 4 vCPU Ryzen 7 5700X, XFS on a virtual disk)

| Metric | Result | Spec target |
|---|---|---|
| Keystroke latency added by swrap (echo round-trip `sw` vs plain `ssh`, 3×300 samples) | +0.11 ms median; `sw` p99 0.39–0.76 ms, max 1.2 ms (plain ssh max 1.35 ms) | < 1 ms p99 |
| Recorder throughput, CPU-bound (tmpfs) | 687 MB/s of terminal output | ≥ 100 MB/s |
| Recorder throughput to this VM's disk | 68 MB/s (bounded by the disk's ~190 ms flush latency) | n/a |
| Memory per concurrent session on core | ~15 MiB (worker 6.1 + ssh 8.1 + client 3.4) | est. 20–30 MiB |
| 20 concurrent sessions on an edge co-located with a Stalwart mail server | `swrap.slice` peak 55 MiB of 512 MiB; Stalwart unaffected | fits in 512 MiB |
| Search, plain files | ~800–860 MiB/s (4 threads); command-only queries ~4 GB/s | n/a |
| Search, gzip files | ~680 MiB/s of decompressed data | n/a |
| Verify | ~670 MB/s | n/a |
| swai session memory (Claude Code; 2026-10-03, 4 live sessions) | 250–320 MiB each: the harness 230–275 MiB, swrap's worker 14–42 MiB, the MCP helper 2–3 MiB | n/a |
| swai capacity on the reference VM (7.5 GiB RAM, 4 sessions running) | 5.6 GiB available; with the 1 GiB `min_available_mb` floor, room for about 15 more Claude Code sessions | n/a |
| swai recording size | 0.8 MiB per session-hour on average (0.2–2.6 over 25 sessions, 414 h); gzip 4–9× | n/a |
| Web chat view of a 10 h swai session (8 k records, 67 requests, 66 tool calls) | built in ~0.3 s, 178 KiB of JSON | n/a |

Notes:
- **Keystroke timing obfuscation.** OpenSSH ≥ 9.5 deliberately delays keystrokes (`ObscureKeystrokeTiming`, ~14 ms here) to hide typing rhythm. That applies with or without swrap, so the latency row was measured with it off on every hop; normal use keeps it on.
- **Background I/O.** Session recorders write and `fdatasync` on a helper thread. Before this, a 190 ms disk flush caused 150–200 ms keystroke stalls once a second.
- **Session limits.** 10 per user and 100 on core; on edge, 10 per user and 20 total.
- **Reproducing.** `swrec bench --dir /dev/shm` (CPU-bound; the default directory measures the disk), `swrec search-bench`, `swrec fuzz`; swai figures from `ps` over the live sessions' process trees and the `ai` recordings' sizes and spans.

## Status (spec coverage)

| Spec area | State |
|---|---|
| 3 ISO 8601 policy | done: strict parser/formatter (date-times, durations, intervals, `now`); `--since 7d` is rejected with an example |
| 4.4 Remote signing, filtering agent | done: per-session `ssh-agent` holding one vault key behind a Rust proxy. It allows only identities, `session-bind` to pinned host keys, and userauth signatures for the expected remote user (≤ N within the window). Everything else is refused and audited. Edge-run sessions reach it through the link |
| 7 Layout | done: `/var/lib/swrap` is a dedicated LV on **sda** |
| 8 swrec v1.1 | done: writer (coalescing, O_APPEND, fdatasync policy, checkpoints, blake3 chain, ed25519 end signature), tolerant reader/verifier, multi-member gzip with crash-safe procedure, fuzz and bench |
| 9 Sessions (`sw`) | done on core: the worker owns the PTY, `ssh` and the recording, and survives daemon restarts. Records keystrokes, heuristic and integration commands, negotiated crypto, host binding |
| 9.5 AAA shell | done: `swrap-shell` records output and commands, never keystrokes. Nested `sw` pause/link markers, forged markers are ignored, fail-closed |
| 10 Hosts | partial: `swadd`, `swenroll` (pin, probe, key generation into the vault, install, verify, remove enrollment keys, integration + sshd drop-in with dead-man's-switch rollback), `swdel`. Done: `swinv` with the PT6H run, change alerts and table tickets/assets (10.7; new hosts get an asset automatically), `swr`/`swx` with `--secret-env` redaction (10.9), `swupdate` (10.10); see the as-built notes. `swuser` (10.5: accounts with their own vault key, password locked, NOPASSWD sudo through `visudo -cf`-checked `swrap-*` files, drift = unexpected/modified/missing) and `swrotate` (10.4: add, verify, remove, verify refused, retire; retired keys destroyed after P30D); `state/` is mirrored to edge (read-only tree, swapped atomically) |
| 11 SFTP | done on core (11.5): per-host directories for AAA users, proxied and recorded by a worker; admins get the real filesystem. Edge logins and edge-network hosts not yet |
| 12 Integrity | done: atomic writes with read-back, vault manifest, `swrap doctor` (daily run, weekly scrub) |
| 13 Firewall | core part done: `swfw web allow/revoke`, `ssh block/unblock`, `list`, `status`; nftables `table inet swrap` (drop-only). Edge: the same table from the signed snapshot (SSH blocks, per-source rate limit on :22, web allow-list on the relay port) |
| 14 Vault | done: XChaCha20-Poly1305 DEK, argon2id admin wraps, recovery key, blake3 commitment. Admin SSH login (key + vault password via PAM) unseals. Kernel keyring survives daemon restarts. `swadm vault …` |
| 15 Retention | done: watermark eviction (oldest first, audit last, never live), non-swrap-fill guard, young-eviction alert, compression after P7D |
| 16 Web GUI | done: rustls, allow-list, argon2 web passwords, backoff, SSE search with cancel/progress, vendored asciinema-player, command timeline, verification panel, nested-session links, keystroke overlay, live follow, UTC toggle |
| 17 AAA users | done: `swadm user/key/grant/revoke/show`, Linux accounts, `/etc/ssh/authorized_keys/%u`, sshd Match blocks, PAM |
| 4–5 Edge node | done: `swrapd edge` (swrap-edged); outbound link from core with three socket forwards; signed snapshots (accounts, keys, firewall; rollback-protected); edge-run sessions with remote signing through core's filtering agent (host-bound); delegated sessions; spool → core ingest (identical bytes, fsync before ack, delete after end-ack, fail-closed at the cap); admin password verified/unsealed on core; web relay :8443 → core; log shipping; `swedge deploy/status`. Rehearsed on a systemd container |
| Networks | each host has `network = core|edge`. `swadd` with a private address puts the host in the network of the node you are logged into (`--network` overrides). Edge-network hosts (e.g. cloud VMs sharing a private net with mail) are enrolled and administered through edge (core → edge jobs over the link), and `sw` to them from core is reverse-delegated: edge runs and records the session and streams it back (`via core→edge`). `from=` always lists IP addresses of the node(s) that actually connect |
| SFTP, fleet on edge | done: SFTP for edge logins (delegated to core, edge grants) and to edge-network hosts (core's ssh through a one-use TCP tunnel on edge: ciphertext only); fleet jobs from edge stream their output live |
| 24 AI workbench | done as **swai** (terminal edition, see Deviations): Claude Code (signed in with the user's Claude plan) or opencode (local/OpenAI-compatible, or an API key) in a bwrap sandbox on core, recording inference proxy (Anthropic Messages pass-through + OpenAI-compatible, streaming, vault-held keys, effort), MCP tools executed by swrapd under AI grants (`ai_allowed` + `[[ai_grant]]`, admins refused), limits (16 concurrent / 600 per PT1H per user, 500 per session, 12 sessions per user, a memory floor; `swai limits`), handoff to a fresh session, per-backend `max_concurrent`, deduplicated `m/q/a/t/o` records, search fields, chat view in the web player, tmux-like detach/attach, edge delegation, `swai reset` (Proxmox rollback; built and tested against a fake API, waits for a scoped token) |

## Deviations from the spec (deliberate)

- **Root access preserved.** The installer assumes the core may still be administered as root with a password over SSH. So `AllowGroups` also admits `root`, and the PAM change only sends members of `swrap-admin` to `swrap-pam-unlock`. Every other account keeps `password-auth`. Remove `root` from `/etc/ssh/sshd_config.d/06-swrap.conf` when you no longer need it.
- **`ssh -o LogLevel=DEBUG1`** instead of VERBOSE for session ssh processes. OpenSSH only logs the negotiated kex, cipher and MAC at DEBUG1. `-E` keeps the extra output out of the terminal.
- **`HostKeyAlias=<label>`**: known_hosts entries are keyed by label, so an address change can't bypass pinning.
- **fdatasync at byte-triggered checkpoints** is rate-limited to the sync interval. On this VM one flush takes about 190 ms; syncing every 256 KiB capped throughput at 1.2 MB/s. Time-triggered checkpoints and the end record always sync. Recorder CPU throughput is ~535 MB/s (target ≥ 100). On this disk the real rate is ~65 MB/s, limited by flush latency.
- **`/var/lib/swrap` traversal** uses per-user ACLs (`u:<user>:x`) rather than widening the 0750 mode.
- **Link user on edge**: `authorized_keys` uses `command="/sbin/nologin",no-agent-forwarding,no-X11-forwarding,no-pty,no-user-rc` instead of `restrict,port-forwarding`, and sshd has `AllowTcpForwarding remote` + `PermitListen none` + `PermitOpen none` for that user. OpenSSH 9.9 disables unix-socket `-R` both under `restrict` and under `AllowTcpForwarding no` (channels.c has no separate ACL for streamlocal); the replacement still refuses every TCP forward, PTY and command (verified).
- **Edge binaries**: swrap-edged is a mode of the `swrapd` binary (`swrapd edge`) so the session worker and recorder are shared.
- **Spec 24 as a terminal harness.** At the owner's request the AI workbench is `swai`, an opencode TUI reached over SSH like `sw`, instead of Turnstone behind a second web GUI. So there are no one-time web codes (SSH login is the authentication), no OIDC gate, and no extra edge port. What the spec requires is kept: AI grants separate from human grants, keys only in the vault, no egress from the harness except the recording proxy, every request, reply and tool call recorded, limits, admins refused. Backends: any AI user may add an OpenAI-compatible server by IP (loopback and this host's own addresses are refused); admins manage the rest. `max_concurrent` per backend caps requests over all sessions (flock slots; waits, then 503). With Claude Code the model traffic is recorded by the proxy, but its sign-in/account calls pass through a TLS tunnel to four Anthropic hosts, logged by host and byte count only.
- **Acceptance tests.** `tests/acceptance/acceptance.sh` (safe tests by default on the live system; destructive ones only when named with `SWRAP_ACCEPT_DESTRUCTIVE=yes`; `--list`).
- **Guides.** [Proxmox checklist](docs/guides/proxmox.md), [edge with Stalwart](docs/guides/stalwart.md), [backup and restore](docs/guides/backup.md), [threat model](docs/guides/threat-model.md), [AI test VM isolation](docs/guides/ai-test-vm.md). Packaging: `packaging/swrap.spec` (offline build from `packaging/make-sources.sh`; the package installs files only, `swrap-install core` / `swedge deploy` do the setup).
- **SELinux (core).** Enforcing. swrapd (daemon, session workers) runs as `swrapd_t`, swrap-web as `swrap_web_t`, and the swai harness (Claude Code, opencode) as `swrap_ai_t`, entered when bwrap executes it (no_new_privs, so `nnp_transition`), with its homes as `swrap_ai_home_t`. Policy 1.3.1 (2026-10-03) holds the rules drafted from a week of logged denials (36 833 denials in that week; 81 in the first PT20M after loading 1.3.0, now covered too); `swrap_ai_t` has no network but the sandbox's own loopback (the recording proxy's relay), no vault, keyring or other swrap data. All three are still **permissive** (lines marked `swrap:permissive`): `swrap doctor --selinux` shows what enforcing would still deny, counting from the last policy load. Once that stays empty over normal use, `swrap install selinux --enforce` rebuilds the module without those lines (`--permissive` goes back); the mode loaded is in `/var/lib/swrap/selinux.mode`. The doctor no longer runs `semanage` (it would need the policy store): it reads that file and the denials' `permissive=` field.
- **Session sshd drop-in names on core**: `06-swrap.conf` (globals) and `99-swrap-match.conf` (Match blocks last). `05-swrap.conf` is the name used on *managed* hosts, as specified.

## Two disks, no RAID: `swrap replica`

`swrap replica` expects the core VM to be laid out like the reference deployment (paths are fixed in `crates/swrap-cli/src/replica.rs`):

| Disk | Contents |
|---|---|
| sda (VG `swrapdata`) | `/var/lib/swrap` (380G, all swrap data) and `/srv/rebuild` (120G, rebuild kit A) |
| sdb (VG `rl`) | OS, source `/root/swrap`, `/home/rebuild` (kit B) and `/home/rebuild/data`, a rustic (deduplicated, versioned) backup of `/var/lib/swrap` |

Each kit contains:
- a full git mirror of the source tree at `/root/swrap`;
- vendored crates for an offline build;
- release binaries plus rustic;
- system config (sshd, PAM, systemd, sysctl, tmpfiles, fstab, **SSH host keys**, authorized_keys, package list, disk layout, the spec);
- `README-REBUILD.md` with step-by-step recovery for either disk failing.

`swrap-replica.timer` runs `swrap replica sync` every PT15M. `swrap replica status` and `swrap replica verify [--read-data]` report on it. The data backup refuses to run if `/var/lib/swrap` isn't mounted, so a dead sda can't create empty snapshots. The sda mounts are `nofail`, so the OS still boots if sda dies.

## Layout

```
crates/swrap-core      ISO 8601, atomic writes, git, frames, config models, RBAC/targets, API types
crates/swrec           record format: writer (repeat folding), reader/verifier, gzip, OSC 7719, renderers, search; `swrec` tool
crates/swrap-vault     DEK, wraps, recovery key, key files, manifest, kernel keyring
crates/swrapd          core daemon + session worker (`swrapd worker`)
crates/swrap-cli       `swrap` multi-call client (sw, swai, swls, swlog, swcat, swplay, swsearch, swadm, swadd,
                       swenroll, swdel, swfw, swcrypto, swunlock, swpasswd, doctor, replica, install)
crates/swrap-shell     recorded login shell
crates/swrap-pam-unlock  pam_exec helper
crates/swrap-web       web GUI
```

Build and (re)install: `cargo build --release && ./target/release/swrap install core --from target/release [--admin-key 'ssh-ed25519 …']`. Target: Rocky/RHEL 10 with SELinux.
The installer is idempotent.

## Tests

- `cargo test`: unit tests. They cover ISO parsing, RBAC and targets, framing, the swrec writer/reader including tamper and torn-write cases, the crash-at-every-step compression test, the vault (bit flips in wraps never yield a wrong key), agent filtering, the OSC filter and renderers.
- `swrec fuzz --iterations 10000`: plain and gzip files. No panics, and damage stays local.
- `swrec bench`: recorder throughput.

## Optional: table integration

swrap can raise tickets and keep host assets in a [table](https://github.com/th3rumbl3m4t0r/Table) server. It is off until configured: set `endpoint` (and optionally `git_web` / `git_hosts` for linking git checkouts) in `config/table.toml`, then store the form tokens with `swrap table token …`.

## License

Copyright (C) 2026 th3rumbl3m4t0r

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. See [LICENSE](LICENSE).

`crates/swrap-web/assets/asciinema-player.*` is the vendored [asciinema-player](https://github.com/asciinema/asciinema-player) under the Apache License 2.0 (see `asciinema-player.LICENSE`). `crates/swrap-cli/assets/claude-code-release.asc` is Anthropic's public Claude Code release-signing key, used only to verify updates.
