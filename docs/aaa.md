# swrap: Personal AAA / SSH Jump Host, Specification v0.4

This is the build spec for **swrap**, a personal AAA (Authentication, Authorization, Accounting) system, to be handed to Claude Code. The document is self-contained, so no earlier version is needed.

- **MUST** means a requirement.
- **SHOULD** means a strong default.
- **MAY** means optional.

Section 21 lists open decisions. Where one is unanswered, Claude Code uses the stated default and does not stall.

**Changes in v0.4:** adds **Stage 2: AI workbench** (section 24). Stage 2 is built only after Stage 1 (sections 1–23) passes all its acceptance tests. Nothing in Stage 1 depends on it.

**Changes from v0.2 (in v0.3):**
- **Edge is a full session node.** A user who logs in from the internet gets a shell on edge. Sessions to public destinations run on edge, so edge is the only hop, and all session data streams to core.
- **Internal destinations reached from edge** are delegated to core.
- **Private keys never leave core.** Edge gets per-session signatures through a filtering remote-signing agent.
- **Edge holds no database.** Every authorization is decided on core.
- **Edge shares its VM with a Stalwart mail server.** Section 5.3 covers ports, isolation and resources.
- **New section 19** on performance and sizing.

---

## 1. Goals and non-goals

### 1.1 Goals

1. **Two session nodes, one authority.**
   - **core** runs on-prem (Rocky VM on Proxmox). It is the only writer and holds the database, the key vault, all stored recordings and the web GUI.
   - **edge** is a small public VM shared with a Stalwart mail server. It is the only node reachable from the internet. It runs shells and sessions but keeps no keys, no database and no stored sessions.
2. **Session placement follows the traffic.** From the LAN you log into core and core runs every session. From the internet you log into edge; edge runs sessions to public hosts itself and delegates sessions to internal hosts to core.
3. **Accounting of everything, stored on core.**
   - `sw` sessions record output, keystrokes and commands.
   - AAA shell sessions record output and commands, but no keystrokes.
   - SFTP file operations are recorded.
   - Fleet runs are recorded.
   - All of it is crash-proof, corruption-tolerant, and searchable with grep or zgrep.
4. **Web GUI on core for playback and search only.** It is reachable only from source IPs an admin has allow-listed from the CLI.
5. **SSH is orchestrated, never implemented.** OpenSSH binaries and algorithm lists come from versioned crypto profiles, so OpenSSH can be upgraded or swapped and cipher suites changed without touching code.
6. **Host lifecycle.**
   - Enrollment with per-(host, user) key generation and removal of the enrollment key.
   - Package inventory presented as a folder tree.
   - Fleet scripts (`swr`) and fleet updates (`swupdate`).
   - Remote user management with swrap-managed NOPASSWD sudo.
   - A virtual SFTP filesystem across hosts.
7. **Everything built is Rust.** External runtime dependencies are OpenSSH, git, nftables and PAM (via `pam_exec`).
8. **Built for consumer hardware without ECC.** Every persistent artefact is checksummed, verifiable, and recoverable locally.
9. **ISO 8601 everywhere** (section 3).

### 1.2 Non-goals (v1)

- No SSH protocol implementation in Rust.
- No agent on managed hosts. The only thing installed there is an optional shell-integration snippet.
- No web-based administration.
- No multi-writer database and no automatic failover (section 4.3).
- No Windows targets. Debian/Ubuntu targets come later.
- No AI features in Stage 1. The AI workbench is Stage 2 (section 24).

---

## 2. Terminology

| Term | Meaning |
|---|---|
| core | On-prem node; the authority: DB, vault, stored records, web. Runs sessions for LAN logins and for delegated sessions. |
| edge | Public node, co-hosted with Stalwart. Runs shells and sessions for internet logins. It stores nothing permanently; its data streams to core. |
| link | Outbound SSH connection from core to edge that carries all core↔edge traffic. |
| origin node | The node the user is logged into (core or edge). |
| exec node | The node that runs the `ssh` client for a session. |
| route | Per-host setting (`core` or `edge`) that decides the exec node when the origin is edge. |
| delegated session | Origin is edge, exec node is core; edge relays the PTY stream. |
| remote signing | Edge's `ssh` authenticates using signatures produced on core by a filtering agent proxy. The key never leaves core. |
| AAA user | A swrap user account, which exists as a Linux account on both nodes. |
| Managed host | Enrolled target with a unique **label**. |
| Grant | RBAC entry: AAA user may use (hosts, remote users). |
| Crypto profile | Named set of OpenSSH binary paths and algorithm lists. |
| Vault | Encrypted keystore on core. It is *sealed* after boot and *unsealed* by an admin password login. |
| swrec | Recording and log file format (section 8). |

---

## 3. Time: ISO 8601 policy (MUST, everywhere)

- **Storage:** UTC in the RFC 3339 profile of ISO 8601, with microseconds and a `Z` suffix, e.g. `2026-09-23T08:14:02.113245Z`.
- **Display:** extended format with an explicit offset in the configured zone (default `UTC`), e.g. `2026-09-23T10:14:02+02:00`. A `--utc` flag and a web toggle switch to `Z`.
  - No locale formats.
  - No 12-hour clock.
  - No relative phrases such as "3 hours ago".
- **Durations** use ISO 8601 durations: `PT1H23M4.5S`, `P7D`.
- **Intervals** use ISO 8601 intervals: `2026-09-01T00:00:00Z/2026-09-02T00:00:00Z`, `2026-09-01T00:00Z/PT6H`, `P1D/now`. The literal `now` is the only extension allowed.
- **CLI input** accepts only ISO date-times, durations and intervals.
  - `--since P7D`
  - `--window <interval>`
  - `--for PT8H`
  - `--until <date-time>`
  - Anything else is rejected, and the error shows an example of the correct form.
- **Filenames** use the ISO 8601 basic format, e.g. `20260923T081402Z`. Date directories are `YYYY/MM/DD`.
- **Everything else** uses the same formats: git commit messages, TSV files, audit records and the web UI.
- **Clocks:** chrony is required on both nodes. Event times are the header wall time plus a `CLOCK_MONOTONIC` offset, so a clock step during a session cannot reorder events. Each node reports its clock offset to the other on link-up, and an offset above PT1S raises an alert.

---

## 4. Topology, routing, trust

### 4.1 Overview

```
   Internet user                                   LAN user
       │ ssh :22                                       │ ssh :22
       ▼                                               ▼
┌──────────── edge VM (shared with Stalwart) ──┐  ┌──────────── core VM (Proxmox) ─────────────┐
│ sshd → swrap-shell (edge shell, recorded)    │  │ sshd → swrap-shell (core shell, recorded)   │
│ swrap-edged:                                 │  │ swrapd: DB (git), vault, RBAC, records,     │
│  • edge-run sessions (route=edge hosts)      │  │  sessions, delegation endpoint, remote-     │
│    ssh ──────────────────────────────┐       │  │  signing agent proxy, enrollment, fleet,    │
│  • record spool → stream to core     │       │  │  retention, doctor, edge snapshot signer    │
│  • PTY relay for delegated sessions  │       │  │ swrap-web (TLS terminates here)             │
│  • web relay :8443 (or SNI on :443)  │       │  │ /var/lib/swrap (dedicated disk)             │
│  • nft table "swrap", rate limits    │       │  └───────┬───────────────────────┬─────────────┘
│ Stalwart (own user, own ports)       │       │          │ link (core dials out) │ ssh
└──────────────────▲───────────────────┼───────┘          │                        ▼
                   └───────────────────┼──────────────────┘            Internal hosts (route=core)
                                       ▼
                         Public hosts (route=edge), one hop from edge
```

### 4.2 Session placement

| Origin (where you logged in) | Host `route = edge` (public VMs) | Host `route = core` (internal) |
|---|---|---|
| core (LAN) | core runs `ssh` directly (core has internet egress) | core runs `ssh` |
| edge (internet) | **edge** runs `ssh`; records stream to core | **delegated**: core runs `ssh`; edge relays the PTY byte stream over the link |

- **Default `route`** is set by the address at `swadd` time:
  - RFC1918, ULA and link-local addresses, and anything inside `network.internal_networks`, get `core`.
  - Everything else gets `edge`.
  - An admin can override this per host.
- **Traffic path, edge-run session:** user → edge → public host. The only extra traffic is the recording stream from edge to core, which is small (section 19).
- **Traffic path, delegated session:** user → edge → core → internal host. This is unavoidable, because edge cannot reach internal hosts. The SSH encryption to the internal host is terminated on core.
- The same placement rules apply to SFTP entries (section 11).
- **Fleet jobs** (`swr`, `swx`, `swupdate`, `swinv`) always run on core in v1, whatever the origin. They are batch jobs where latency doesn't matter. Per-host fleet execution on edge is a phase-2 option (21.13).

### 4.3 Database: single writer, no split brain

With two nodes you cannot have both automatic failover and no split brain. swrap is therefore **single-writer**:

- **core owns the one database.** It is the `config/` git repo holding users, grants, hosts, profiles, firewall rules and edge settings. All writes happen on core.
- **edge holds no RBAC and no host database.** Every `sw`, SFTP entry, `swls` and completion request from edge is a live query to core. Core decides and returns only what that one operation needs:
  - the host's address and port;
  - the pinned host keys;
  - the crypto profile;
  - the remote user;
  - a remote-signing channel.
- **edge keeps one signed snapshot of public-only data** needed while the link is down. It is signed with core's `edge-config` key using `ssh-keygen -Y sign`, and edge verifies it against a pinned public key. The snapshot contains:
  - AAA user accounts with names, roles and inbound public keys, so edge `sshd` can still let people log in;
  - firewall allow-lists and blocks;
  - rate limits and edge settings.

  Edge rejects any snapshot whose version is not strictly greater than the one it has (rollback protection).
- **A write can never happen on edge.** Admin commands typed on edge are executed by core. So there is never anything to reconcile.

### 4.4 Remote signing: keys never leave core

Edge-run sessions still authenticate with credentials stored in core's vault. The mechanism:

1. Edge's session worker creates a local agent socket, `/run/swrap-edge/sessions/<id>/agent.sock`. It tunnels SSH-agent protocol messages over the link to core, tagged with the session id.
2. For that session, core starts a per-session `ssh-agent` holding exactly one key, decrypted in memory from the vault. Core fronts it with a **filtering proxy** written in Rust, in swrapd.
3. The proxy allows only the following:
   - `REQUEST_IDENTITIES`, which returns only this session's public key;
   - `session-bind@openssh.com`. OpenSSH ≥ 8.9 clients send this, and edge SHOULD run such a client (Rocky 10). The proxy verifies that the server host key in the bind matches the host key pinned for the label, then **binds the session to that host**.
   - `SIGN_REQUEST` for that key, and only when the signed data parses as an SSH userauth request for the expected remote user. At most 4 signatures are allowed, within PT2M of session authorization.
   - Everything else is refused: add, remove, lock and any other extension.
4. After authentication, or on timeout, the agent is killed and the decrypted key is zeroized.
5. Every signature is audited on core, with the session id, label, remote user and host-key fingerprint.

**Why this design:** since a compromised edge never holds a private key, rebuilding edge fully removes the attacker. No key rotation is needed afterwards. Delegated and core-run sessions use the same per-session agent locally without the tunnel.

Implementation note: confirm during phase 7 that the OpenSSH client on edge sends `session-bind@openssh.com` for agent-based user authentication. Without it the proxy still enforces the one-key, user-name, count and time limits, but not host binding. The session header records `hostbound: true/false`.

### 4.5 The link

- **Who dials.** core's swrapd supervises `ssh -N` to edge. Backoff is exponential from PT1S to PT1M, with a watchdog.
- **Settings.**
  - Crypto profile `link`.
  - Link key at `/var/lib/swrap/link/id_ed25519`.
  - Edge host key pinned in `link/known_hosts`.
  - `ServerAliveInterval=15` and `ExitOnForwardFailure=yes`.
- **Reverse unix-socket forwards (edge → core services):**

  | Edge socket | Core socket | Purpose |
  |---|---|---|
  | `/run/swrap-edge/core-api.sock` | `/run/swrap/edge-api.sock` | Authorize, query, admin commands, remote signing, record streaming, log shipping, snapshot fetch, password verification |
  | `/run/swrap-edge/core-pty.sock` | `/run/swrap/edge-pty.sock` | Delegated session PTY streams and delegated SFTP backends |
  | `/run/swrap-edge/core-web.sock` | `/run/swrap/ingress-web.sock` | Web GUI relay |

- **Edge sshd settings for the link user.**
  - `Match User swrap-link`: `AllowStreamLocalForwarding remote`, `AllowTcpForwarding no`, `PermitTTY no`, `X11Forwarding no`, `StreamLocalBindUnlink yes`, `StreamLocalBindMask 0117`.
  - The authorized key carries `restrict,port-forwarding`.
  - The sockets belong to group `swrap-edge`.
  - The link uses edge's normal sshd on :22. A separate port is optional via `edge.link_port`.
- **The link key is not in the vault.** After a reboot the vault is sealed, and unsealing from the internet needs the link to be up. The key can do nothing except open those three forwards.
- **The API is multiplexed.** Framed, length-prefixed messages carry a stream id and type, and every stream is scoped to a session or request.
- **Core treats edge as partially trusted.** Edge is trusted to authenticate AAA users who log into it; nothing else. All input from edge is schema-validated, size-limited and rate-limited.

### 4.6 Failure modes

| Situation | LAN (core) | Internet (edge) |
|---|---|---|
| All up | everything | everything |
| Link down or core down | LAN unaffected (if only link) | Edge login works (snapshot). **New `sw`, SFTP host entries, fleet and search are refused** ("core unreachable since …"). Running edge-run sessions continue and spool locally up to the cap (section 8.8); at the cap they are terminated (fail-closed accounting). Delegated sessions end (their transport is gone); core records `reason=link_lost`. |
| Edge down | everything | nothing (provider console only) |
| Vault sealed | shells and web work; no sessions anywhere | shells work; no sessions |

### 4.7 Trust and compromise analysis

- **Core compromise:** total. Core holds everything. It is protected by being LAN-only with no inbound internet exposure.
- **Edge compromise.** This could come through swrap-edged, sshd, or the co-hosted Stalwart plus a local privilege escalation. The attacker can:
  - read live traffic of sessions currently running on edge, including keystrokes;
  - start sessions **as any AAA user** to any host that user is granted. Core must believe edge's word about who logged in; this is the price of terminating user SSH on edge.
  - capture an admin's password if an admin logs in on edge while the attacker is present.

  The attacker **cannot**:
  - steal keys;
  - keep access after edge is rebuilt;
  - change RBAC, users or firewall rules;
  - read stored recordings;
  - reach internal hosts' networks except through delegated sessions that core authorizes and records.

  Every signature and session is logged on core, outside the attacker's reach.
- **Mitigations, configurable:**
  - Per grant, `via = ["core", "edge"]`. For example, root on the most sensitive internal hosts could be LAN-only.
  - Per host, `edge_allowed = true/false`.
  - Keep Stalwart isolated (section 5.3).
  - Core raises an alert on unusual edge behaviour: sessions for a user who has no active edge login reported, signature bursts, or snapshot version mismatch.

---

## 5. Platform and deployment

### 5.1 core

- **OS:** Rocky Linux 10 preferred; Rocky 9 supported.
  - Rocky 10 ships OpenSSH 9.9 at release. Verify with `ssh -V`. It supports `mlkem768x25519-sha256`, `sntrup761x25519-sha512`, `PerSourcePenalties` and `session-bind`.
  - Rocky 10 requires an **x86-64-v3** CPU type in Proxmox, i.e. `host` or `x86-64-v3`.
- **Disk:** a dedicated virtual disk for `/var/lib/swrap`. The 90 % retention watermark must measure only swrap data.
- **Swap:** none, or encrypted swap only.
- **Proxmox checklist:**
  - Disk cache `none` or `writeback`, **never `unsafe`**.
  - ZFS mirror with a monthly scrub.
  - UPS with NUT.
  - SSDs with power-loss protection if possible.
  - ECC RAM is the only real fix for bit flips in RAM (section 12).
- **Hardening:** SELinux enforcing, `kernel.yama.ptrace_scope = 2`.
- **Network exposure:** core listens on the LAN only. Its only internet-facing traffic is outbound: the link, and sessions to public hosts started from the LAN.

### 5.2 edge

- **OS:** Rocky Linux 10 preferred, because OpenSSH ≥ 8.9 gives host-bound remote signing. Rocky 9 is supported without host binding.
- **Public ports used by swrap:**
  - `22`: sshd, for users, admins and the link user.
  - `8443`: web relay, allow-listed. Default, see section 5.3.
- **Stored state:**
  - sshd host keys;
  - the edge recording signing key (`/var/lib/swrap-edge/recsign/`);
  - the pinned core `edge-config` public key;
  - the latest signed snapshot;
  - the spool (section 8.8).
  - No private keys for managed hosts and no stored sessions.
- **Edge as a managed host:** edge is enrolled on core with label `edge` and `route = core`. Admins maintain it with `sw edge` from core. That session is recorded on core and is independent of edge's own swrap services. The provider's console is the emergency path.

### 5.3 Co-location with Stalwart

This is a budget compromise. It works, but it raises edge's attack surface, and section 4.7 describes what an edge compromise means. Requirements:

- **Ports.**
  - Stalwart keeps its ports: 25, 465, 587, 993, 4190, 443, plus 80 if it uses HTTP-01 ACME.
  - swrap takes 22 and 8443 by default.
  - Alternatively, `edge.web_mode = "sni"`: swrap-edged listens on 443 and peeks at the TLS ClientHello SNI.
    - `swrap.<domain>` goes to core.
    - Everything else goes to Stalwart on a loopback port, prefixed with a PROXY protocol v2 header so Stalwart still sees real client IPs. This requires enabling PROXY-protocol for that listener in Stalwart and trusting 127.0.0.1; verify against Stalwart's current documentation.
    - Default: **`port`** mode on 8443, which touches nothing of Stalwart's.
- **Firewall coexistence.** swrap manages **only** its own nftables table (`table inet swrap`). It never flushes the ruleset and never touches firewalld or Stalwart rules.
  - Its chains only **drop** traffic, for swrap ports that are blocked or not allow-listed, and for rate-limit violations.
  - Accepting is left to the host's normal firewall: firewalld must open 22 and 8443.
- **Process isolation.**
  - Stalwart runs as its own unprivileged user, preferably in rootless podman or with strict systemd sandboxing (`ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp`, `ProtectHome`, and `ReadWritePaths` limited to its data directory).
  - SELinux enforcing. Stalwart's data directories are 0700.
- **Shell users vs the mail server.** AAA users get bash on edge, so:
  - mount `/proc` with `hidepid=2,gid=swrap-admin`;
  - users are not in any Stalwart group;
  - nftables `meta skuid` rules allow outbound TCP from edge to managed hosts' SSH ports only for the `swrap-edge` user, so users cannot bypass recording with their own `ssh`.
  - Loopback access to Stalwart's ports stays possible. It is harmless for authenticated mail, and noted here for completeness.
- **Resource isolation with systemd slices:**
  - `swrap.slice`: `MemoryHigh=384M`, `MemoryMax=512M`, `CPUWeight=100`.
  - The Stalwart unit gets `MemoryLow` set to its own baseline, so mail is never starved by a session burst.
  - The spool is capped in software (section 8.8). Optionally it can live on its own small filesystem image so it cannot fill the mail disk.
- **Logs.** Only swrap units, sshd and audit/SELinux events are shipped to core. Stalwart logs are not shipped (21.12).

---

## 6. Components (Cargo workspace)

| Crate / binary | Node | Purpose |
|---|---|---|
| `swrap-core` (lib) | both | Config models, ISO 8601 parse and format (date-times, durations, intervals), RBAC evaluation, profiles, atomic writes, git wrapper, framed link protocol, snapshot codec |
| `swrec` (lib + bin) | both | Record format: writer, tolerant reader, verifier, multi-member gzip, ANSI and keystroke renderers, asciicast v2 export, search engine |
| `swrapd` | core | Vault, RBAC decisions, session workers, delegation endpoint, remote-signing proxy, record ingest from edge, enrollment, inventory, fleet, link supervision, snapshot signing, retention, compression, doctor |
| `swrap-edged` | edge | Edge session workers, remote-signing socket, record spool and streaming, PTY relay for delegated sessions, web relay (port/SNI), nftables `swrap` table, rate limits, snapshot verification, account sync from snapshot, log shipping |
| `swrap` (multi-call) | both | Client commands (`sw`, `swr`, …); talks to the local daemon, which executes locally or forwards to core |
| `swrap-shell` | both | Login-shell wrapper that records the AAA shell |
| `swrap-sftp` | both | Virtual SFTP filesystem for non-admins |
| `swrap-pam-unlock` | both | `pam_exec` helper. On core it verifies the password and unseals locally. On edge it forwards the password over the link to core for verification and unsealing |
| `swrap-web` | core | Playback and search web server (axum + rustls), vendored asciinema-player |
| `swrap-ingress` | core | Terminates the web relay, maps the real client IP, forwards with PROXY v2 |

Suggested crates:

- **Runtime, CLI, config:** `tokio`, `clap`, `serde`, `serde_json`, `toml`.
- **Time and ids:** `jiff`, `ulid`.
- **System calls and ACLs:** `rustix`/`nix`, `exacl`.
- **Integrity:** `crc32c`, `blake3`.
- **Signing, encryption, key derivation:** `ed25519-dalek`, `chacha20poly1305`, `argon2`.
- **Secret handling:** `zeroize`, `secrecy`, `memsec`.
- **Compression and search:** `flate2`, `regex`, `rayon`.
- **Terminal parsing:** `vte`.
- **Web and TLS:** `axum`, `tower-http`, `rustls`, `tokio-rustls`.
- **PROXY protocol:** `ppp`.
- **SFTP packet types over stdio:** `russh-sftp`.
- **SSH agent wire format for the filtering proxy:** `ssh-key`/`ssh-encoding` (parse only).

Key generation always uses the profile's `ssh-keygen`.

---

## 7. Filesystem layout

### 7.1 core

```
/var/lib/swrap/                                  swrap:swrap 0750, dedicated disk
├── config/                    git #1 — THE database
│   ├── swrap.toml
│   ├── profiles/<name>.toml
│   ├── hosts/<label>.toml
│   ├── users/<aaa_user>.toml
│   ├── firewall.toml
│   ├── edge.toml
│   └── known_hosts/<label>
├── vault/                     0700
│   ├── wraps/<admin>.wrap, wraps/recovery.wrap
│   ├── keys/enroll/id_<algo>.enc
│   ├── keys/hosts/<label>/<ruser>/id_<algo>.enc  (+ .pub in clear)
│   ├── keys/edge-config/id_ed25519.enc
│   ├── keys/retired/…
│   └── MANIFEST.b3
├── link/                      0700, not encrypted (section 4.5)
├── recsign/                   0700, core recording signing key
├── trust/edge-recsign.pub     edge's recording signing public key (pinned)
├── secrets/webpw/<aaa_user>
├── state/                     git #2 — inventory view (section 10.7)
├── rec/<aaa_user>/sw/YYYY/MM/DD/<20260923T081402Z>_<ulid>_<label>_<ruser>.swrec[.gz]
├── rec/<aaa_user>/shell/YYYY/MM/DD/<ts>_<ulid>_<node>.swrec[.gz]
├── rec/<aaa_user>/sftp/YYYY/MM/DD/<ts>_<ulid>_<node>.swrec[.gz]
├── runs/YYYY/MM/DD/<ts>_<ulid>_<kind>/
├── logs/edge/YYYY/MM/DD.swrec[.gz]
├── audit/YYYY/MM/DD.swrec[.gz]
└── index/                     derived caches only
```

User views on core:

- `~/swrap/` links to `state/` (read-only).
- `~/recordings/` links to `rec/<user>/`.
- POSIX ACLs give each user read access to their own records. The `swrap-admin` group reads everything.

On edge, these views are not local. `swlog`, `swsearch`, `swcat` and `swplay` query core over the link. `~/swrap/` on edge is a read-only mirror of `state/`, pushed as part of the snapshot; it is public inventory data only.

Primary data is `config/`, `vault/`, `link/`, `recsign/`, `trust/`, `rec/`, `runs/`, `logs/` and `audit/`. Everything else can be rebuilt with `swrap doctor --rebuild`.

### 7.2 edge

```
/var/lib/swrap-edge/                             swrap-edge:swrap-edge 0750
├── snapshot/current.toml + current.sig          last verified snapshot
├── snapshot/state/                              inventory mirror (public data)
├── recsign/id_ed25519                           edge recording signing key (0600)
├── trust/core-edge-config.pub                   pinned
└── spool/<ulid>.swrec                           in-flight records, deleted after core ack
/run/swrap-edge/                                 sockets, per-session dirs (tmpfs)
```

---

## 8. Record format: swrec v1.1

### 8.1 Framing

Each line has the form `<crc32c, 8 lowercase hex> <SP> <compact JSON> <LF>`.

- The CRC covers only the JSON bytes.
- JSON escaping guarantees there is never a raw LF inside a record.
- A torn write or a flipped bit damages only the affected line(s), and readers resynchronise at the next LF.

### 8.2 Common fields

- Every record except the header has `s`, a sequence number that increases by exactly 1.
- Every record except the header has `ts`, an ISO 8601 UTC timestamp with microseconds, computed as header wall time plus the monotonic offset.
- There is no separate relative-time field. Players compute offsets from `ts`.
- Every line carries an absolute ISO time, so a raw `zgrep` hit already shows when it happened.

### 8.3 Record kinds

| k | Used in | Fields | Meaning |
|---|---|---|---|
| `h` | all | `v`:"1.2" (1.1 files have no `p` records and read unchanged); `kind` (`sw`, `shell`, `sftp`, `run`, `audit`, `edgelog`); `id`; `start`; `origin` (core\|edge); `exec` (core\|edge); `delegated` (bool); `aaa_user`; `client_addr`; `conn`; kind-specific: `label`, `addr`, `port`, `ruser`, `cols`, `rows`, `term`, `ssh_bin`, `ssh_version`, `profile`, `config_rev`, `hostkey_fp`, `hostbound`, `cmd`, `record_input` | Header. Always written and fdatasync'd first |
| `o` | sw, shell, run | `d` (UTF-8) or `b` (base64); run only: `fd` | Output |
| `p` | sw, shell, ai | `n`, `end`, `back`, `jit`?, `crc` | Repeated output (8.4): `n` output events, each a byte-for-byte copy of the event `back` places earlier in the output stream, first at `ts`, last at `end`, `jit` µs offsets from an even spread; expands to exactly the `o` records it replaces |
| `i` | sw only | `d` / `b` | Keystrokes. **Always on for `sw`; never in `shell`** |
| `r` | sw, shell | `cols`, `rows` | Resize |
| `x` | sw, shell | `cmd`, `src` (`integration`\|`heuristic`), `cwd`?, `exit`? | Command |
| `l` | shell | `sw` (session id), `phase` (`start`\|`end`) | Link to an `sw` recording covering a paused span |
| `f` | sftp | `op`, `label`, `ruser`, `path`, `path2`?, `bytes`?, `b3`?, `result` | File operation |
| `a` | audit | `node`, `action`, `target`, `ruser`, `result`, `detail`, `ref` | Audit event |
| `g` | edgelog | `src`, `msg`, `fields` | Edge log line |
| `n` | any | `msg` | Note: negotiated crypto, host key verified, redaction, link loss, spoofed marker, … |
| `c` | all | `seg`, `chain`, `first_s`, `last_s` | Checkpoint: blake3 of the line bytes since the previous checkpoint, chained |
| `e` | sessions | `reason` (`exit`, `client_disconnect`, `link_lost`, `spool_full`, `killed`, `timeout`, `error`), `exit_code`, `bytes_out`, `bytes_in`, `duration`, `seg`, `chain`, `sig`, `signer` (core\|edge) | End |

### 8.4 Writer

- **Coalescing.** Output within 5 ms and up to 16 KiB is merged into one record. Keystrokes are coalesced for at most 5 ms.
- **Write path.**
  - One `write(2)` per record, on an `O_APPEND` descriptor.
  - `fdatasync` at most once per PT1S, and always at a checkpoint or the end record.
  - A checkpoint every PT10S or 256 KiB, whichever comes first.
- **Integrity.** CRC and blake3 are computed from the exact buffer being written. The parent directory is fsynced when a file is created.
- **Encoding.** A UTF-8 sequence split across chunks is carried over to the next chunk. Invalid bytes go into `b`.
- **Repeated output (`p`, swrec 1.2).** A TUI that animates while it waits (a spinner, a scanner bar, a progress line drawn in place) repeats the same few writes for as long as it waits. An output record whose data equals one of the last 1024 output events (text, at most 4 KiB) is not written again; consecutive repeats are written as one `p` record instead.
  - **Lossless.** Readers expand a `p` record into exactly the records it replaces: the same bytes, the same microsecond timestamps. `crc` (crc32c of the expanded bytes) lets a reader that lost its place (after a damaged line) report the record as damaged instead of showing the wrong output.
  - **Output stream.** `back` counts events of the output stream: `o` records without `fd` or `call`, in file order, with each `p` record's events in its place. `back` and `jit` are run-length packed (`[value, count]` for a run, a bare number otherwise).
  - **Durability unchanged.** Folded events are written, as an ordinary appended line, before any other record (so the file stays in time order), at every checkpoint and end, and at the latest one sync interval (PT1S) after the first of them. A power loss therefore loses no more than without folding, and a file is never rewritten.
  - **Only when smaller.** A short, accidental repeat is written as plain `o` records.
  - **Switch.** `[rec] fold_repeats` (default `true`). `swrec refold <file>` shows what folding saves on an existing recording and checks the round trip, without changing the file.

### 8.5 Reader and verifier

The reader never refuses a file.

- A final line without LF is treated as a truncated tail and ignored.
- A line with a bad CRC or bad JSON is skipped and its span is reported.
- Sequence gaps are reported.
- Segments, the chain and the signature are verified.
- Every `p` record is expanded and checked against its `crc`; one that cannot be is reported as damaged.

Possible statuses: `ok`, `ok-incomplete`, `damaged` (with the damaged spans), `tampered`, and `live` (a worker is still writing).

### 8.6 Signing

- The end record is signed with ed25519 over `chain ‖ id` by the **exec node's** recording key.
  - Core sessions, including delegated ones, are signed by `recsign/`.
  - Edge-run sessions and edge shells are signed by edge's key, which is pinned on core.
- Recording keys live outside the vault, so recording works whatever the seal state.
- The signature gives tamper evidence against anyone without root on the signing node. It is not protection against that node's root.

### 8.7 Compression: gzip after P7D

- **When.** Closed files whose end `ts`, or mtime if the file is incomplete, is older than P7D.
- **Format.** Multi-member gzip, starting a new member every 256 KiB of input and always cutting at a line boundary.
  - `zcat`, `zgrep` and `gzip -t` work unchanged.
  - A corrupt member loses at most about 256 KiB. The reader resynchronises at the next `1f 8b 08` header.
- **Procedure.**
  1. Write `.swrec.gz.tmp` and fsync it.
  2. Decompress it and compare its blake3 with the original.
  3. Rename it to `.swrec.gz` and fsync the directory.
  4. Unlink the original and fsync the directory.
- **Crash recovery.** A crash at any step leaves either the original alone, or both files. Doctor resolves the second case.
- **Scope.** Audit and edge logs use daily files and follow the same rule.

### 8.8 Records produced on edge: spool and streaming

- **Writing.** Edge-run sessions, edge shell sessions and edge SFTP sessions are written by swrap-edged into `spool/<ulid>.swrec`, with identical format and the same fsync rules.
- **Streaming.** Records are sent to core over `core-api` as soon as they are written.
  - Core verifies each line's CRC and appends the **identical bytes** to the final file under `rec/`.
  - Core fdatasyncs, then acknowledges by sequence number.
- **Reconnect.** Edge resumes from the last acknowledged sequence number.
- **Cleanup.** Once the session has ended and the end record is acknowledged, the spool file is deleted.
- **What edge keeps.** Edge holds only records that core has not yet acknowledged. There is **no session storage on edge beyond in-flight data**.
- **Spool cap.** Default `edge.spool_max_bytes = 512 MiB`, shared by all sessions.
  - When the link is down, sessions continue as long as the spool has room.
  - At 100 % every active edge-run session is terminated with `reason=spool_full`. This is fail-closed accounting: no unrecorded activity.
- **Delegated sessions** are recorded by core directly; edge relays bytes only.
- **Edge logs.** Edge's own logs (journald for swrap units and sshd, plus the swrap-edged connection log) use a separate log spool, capped at 64 MiB with the oldest dropped first and a drop counter. They ship the same way into `logs/edge/`.
- **Retention on edge.** journald keeps `MaxRetentionSec=3day` and `SystemMaxUse=128M`.

---

## 9. Sessions

### 9.1 `sw [ruser@]label [-- cmd]`

The client talks to the local daemon: swrapd on core, swrap-edged on edge. Identity comes from `SO_PEERCRED`.

1. **Authorize (on core, always).**
   - Check grants, including `via` and `until`.
   - Check the host's `edge_allowed` flag if the origin is edge.
   - Check that a credential exists.
   - If `ruser` was given, it is honoured when granted.
   - Otherwise pick the most privileged granted account: `root` first, then accounts with swrap-managed NOPASSWD sudo, then others; ties are broken by `default_user`, then alphabetically. For `deploy` this is always `root`.
   - Choose the exec node (section 4.2).
   - A sealed vault fails with: `swrap: vault sealed since 2026-09-23T06:02:11+02:00 — an admin must log in with password`.
   - An unreachable core, when the origin is edge, fails with: `swrap: core unreachable since …; sessions unavailable`.
2. **Execute.**
   - **Core exec:** core forks a session worker that owns the PTY, the `ssh` child and the recording. The swrapd unit uses `KillMode=process`, so live sessions survive a daemon restart. If the origin is edge, the worker's PTY stream is relayed through `core-pty.sock` to swrap-edged and then to the user's `sw` client.
   - **Edge exec:** swrap-edged forks a worker with a local PTY and `ssh`. Remote signing goes through core (section 4.4). Recording goes to the spool, streamed to core.
3. **Frames.** Client, daemon and worker exchange length-prefixed frames: `DATA`, `RESIZE`, `SIGNAL`, `EXIT`.
4. **Recorded content:** `o`, `i` (always), `r`, `x`, and `n` for the negotiated crypto and host binding.
5. **Banner line** printed by the client:
   `swrap: recording 01J8Z… root@web1 via edge 2026-09-23T10:14:02+02:00 (keystrokes recorded)`
   (`via core` or `via edge→core` as applicable).

**Warning, shown in the docs and on that line:** everything typed inside `sw` is recorded, including input at hidden prompts. To handle secrets, use the AAA shell together with `swr --secret-env` (section 10.9).

### 9.2 How ssh is invoked (on the exec node)

```
<ssh_bin> -F <session dir>/ssh_config -E <session dir>/ssh.log -o LogLevel=VERBOSE
  -o IdentityAgent=<session dir>/agent.sock -o IdentitiesOnly=yes -i <session dir>/id.pub
  -o UserKnownHostsFile=<session dir>/known_hosts -o GlobalKnownHostsFile=/dev/null
  -o StrictHostKeyChecking=yes -o UpdateHostKeys=no -o ForwardAgent=no -o ForwardX11=no
  -o ClearAllForwardings=yes -o ControlMaster=no -o ControlPath=none
  -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no
  -o SetEnv=SWRAP_SESSION=<id>:<nonce>
  -p <port> <ruser>@<addr> [-- <cmd>]
```

- **Session directory contents.** The session directory is on tmpfs: `/run/swrap/sessions/<id>` on core, `/run/swrap-edge/sessions/<id>` on edge. It holds `ssh_config` generated from the profile, `known_hosts` with the pinned keys supplied by core, and the public key.
- **Agent socket.**
  - On core it is a local per-session `ssh-agent` behind the filtering proxy.
  - On edge it is the remote-signing tunnel.
- **No private key file ever exists** on any filesystem.
- **Crypto logging.** The negotiated algorithms are parsed from `ssh.log` into an `n` record and into the audit log.
- **Config isolation.** `-F` bypasses the system `ssh_config` and crypto-policies, so the profile is authoritative.
- **No user options.** Users cannot pass ssh options; only a remote command after `--`.

### 9.3 Crypto profiles

`config/profiles/<name>.toml`:

```toml
name = "modern"
ssh_bin = "/usr/bin/ssh"
ssh_keygen_bin = "/usr/bin/ssh-keygen"
kex = ["mlkem768x25519-sha256", "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com", "curve25519-sha256"]
ciphers = ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com"]
macs = ["hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com"]
host_key_algorithms = ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256"]
key_preference = ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512"]   # for new credentials
rsa_bits = 4096
extra_options = { ServerAliveInterval = "30", ServerAliveCountMax = "4" }
# optional per-node binary override:
# [node.edge]
# ssh_bin = "/opt/openssh-10.x/bin/ssh"
```

- **Shipped profiles:**
  - `modern` (default).
  - `compat`: adds `ecdh-sha2-nistp256`, `diffie-hellman-group16-sha512` and `aes256-ctr` for Rocky 8 and older Fedora.
  - `legacy`: adds SHA-1 `ssh-rsa` and `diffie-hellman-group14-sha1`. Opt-in per host, with a warning on every use.
  - `inbound`: for both nodes' sshd; includes `sk-ssh-ed25519@openssh.com` for FIDO2 user keys.
  - `link`: for the link.
- **Validation per node.**
  - On link-up, and whenever a binary changes (tracked by path, size, mtime and blake3), each node runs `ssh -Q kex|cipher|mac|key|HostKeyAlgorithms` and `ssh -V` and reports its capability set.
  - A profile is valid on a node only if every algorithm it lists exists in that node's binary.
  - A session is refused with a clear error if the host's profile is invalid on the chosen exec node.
  - `swcrypto test [profile] [--node core|edge]` shows the result.
- **Upgrading.**
  - Distro upgrades: `dnf upgrade openssh`, then `swcrypto test`, then add new algorithms to profiles.
  - Side-by-side builds go under `/opt/openssh-<ver>/`, referenced by a profile, per node if needed.
  - Rollback is a profile change.
- **McEliece** does not exist in upstream OpenSSH; it has only been available in the experimental Open Quantum Safe fork. Check that fork's maintenance status before relying on it. It plugs in like any other build.
- **Signature algorithms** are classical in OpenSSH today. When a post-quantum signature type appears, add it to `key_preference` and run `swrotate @all`.
- **`swcrypto apply <profile> <targets>`** pushes an `/etc/ssh/sshd_config.d/05-swrap.conf` drop-in to managed hosts. On Rocky and Fedora the first value read wins, so `05-` precedes `50-redhat.conf`. The procedure:
  1. Keep the current connection open.
  2. Write the drop-in and run `sshd -t`; on failure, remove it and abort.
  3. Reload sshd.
  4. Verify with a **new** connection; on failure, roll back through the connection that is still open.
  5. Commit.

### 9.4 Command capture (`x` records)

1. **Integration (exact).**
   - Enrollment installs `/etc/profile.d/swrap.sh` on managed hosts, together with `AcceptEnv SWRAP_SESSION` in the sshd drop-in. Both swrap nodes use the same snippet for their own shells.
   - When `SWRAP_SESSION` is set, bash's `PROMPT_COMMAND` emits `ESC ] 7719 ; <nonce> ; <base64 json {cmd, cwd, exit}> BEL`, using `history 1`.
   - The recorder strips these sequences from the terminal stream and from `o`, and emits `x` records.
   - A sequence with the wrong nonce stays in the output and is flagged with an `n` record.
2. **Heuristic (fallback, `sw` only).**
   - Lines are reconstructed from `i`, applying BS, ^U, ^W and ^C and dropping escape sequences, and emitted as `x` with `src: "heuristic"` on CR.
   - This misses history recall and tab completion.

### 9.5 AAA shell recording (`swrap-shell`, both nodes)

- **Login shell.** The login shell of every AAA user is `/usr/libexec/swrap/swrap-shell`.
- **Interactive PTY logins.**
  - The wrapper spawns `bash -l` in a PTY.
  - It streams output, resizes and integration commands to the local daemon. On core the daemon writes `rec/<user>/shell/…`. On edge it goes via the spool to core.
  - **Keystrokes are never recorded.** Input at hidden prompts (`read -rs SECRET`) leaves no trace. Anything echoed does, including commands.
- **Non-interactive exec.** The wrapper execs the command directly. The command line, exit code, byte counts and client address go to the audit log.
- **Nested `sw`.**
  1. `sw` gets a pause token from the daemon.
  2. `sw` emits `ESC ] 7719 ; <shell-nonce> ; sw-start:<id> BEL`.
  3. The shell recorder checks with the daemon (the session must be active and belong to this user). It then writes `l start` and stops recording until `sw-end` produces `l end`.
  4. The `sw` recording is the authoritative record of that span.
  5. A forged marker does not pause recording.
- **Tamper resistance.** The wrapper runs as the user, so it is best-effort. Mitigations:
  - `ptrace_scope=2`.
  - The daemon records in the audit log any shell whose recorder stream ended before sshd's session did.

  `sw` recordings are produced by daemon workers and are tamper-resistant against users.

---

## 10. Hosts, fleet, updates

### 10.1 Host file `config/hosts/<label>.toml`

```toml
label = "web1"
address = "web1.lan"
port = 22
route = "core"                 # core | edge (section 4.2)
edge_allowed = true            # may sessions be started from edge at all
tags = ["rocky", "lab"]
profile = "modern"
default_user = "root"
state = "active"               # pending | active | disabled | removed
enrolled = "2026-09-23T08:00:00Z"
hostkey_fingerprints = ["SHA256:…"]

[[account]]
name = "root"
key_algo = "ssh-ed25519"
key_fingerprint = "SHA256:…"
created = "2026-09-23T08:01:10Z"
sudo = "n/a"                   # root
managed_by_swrap = false
integration = true

[[account]]
name = "deploy"
key_algo = "ssh-ed25519"
key_fingerprint = "SHA256:…"
created = "2026-09-23T08:05:00Z"
sudo = "nopasswd"              # nopasswd | none
managed_by_swrap = true
integration = true
```

### 10.2 `swadd --host <addr> --label <label> [--port 22] [--tag …] [--profile modern] [--route core|edge] [--wait]`

- Admin only. It runs on core; from edge, the command is forwarded. Single-dash long forms (`-host`, `-label`) are also accepted.
- It creates the host with `state = "pending"`, commits, and prints the snippet to paste on the target:

```bash
install -d -m 700 /root/.ssh && cat >> /root/.ssh/authorized_keys <<'EOF'
from="<core egress>,<edge addr>",expiry-time="20261007",restrict ssh-ed25519 AAAA… swrap-enroll-ed25519
from="…",expiry-time="20261007",restrict ecdsa-sha2-nistp256 AAAA… swrap-enroll-ecdsa
from="…",expiry-time="20261007",restrict ssh-rsa AAAA… swrap-enroll-rsa
EOF
chmod 600 /root/.ssh/authorized_keys; restorecon -R /root/.ssh 2>/dev/null || true
```

- **`from=` addresses.** Enrollment always runs from core, so `from=` contains core's egress addresses plus edge's address. If core's public IP is dynamic, set `network.from_restriction = false` (decision 21.7).
- **`expiry-time`.** OpenSSH requires `YYYYMMDD` here. The expiry is `general.enroll_key_ttl` after creation, so a forgotten enrollment key dies by itself.
- **Enrollment keys.** They are ed25519, ecdsa-p256 and rsa-4096; the RSA one is used with `rsa-sha2-*`, and SHA-1 only via `legacy`. They are stored in the vault and rotated with `swcrypto rotate-enrollment`.
- **`--wait`** polls every PT10S and then runs `swenroll`. The vault must be unsealed.

### 10.3 `swenroll <label> [--fingerprint SHA256:…] [--yes]` (runs on core)

1. **Pin the host key.** Fetch host keys, show their fingerprints, and require either a `--fingerprint` match or interactive confirmation. Store them in `known_hosts/<label>`. Warn if the host offers only RSA host keys.
2. **Connect** with the enrollment keys, trying ed25519, then ecdsa, then rsa. Each key is served by a per-session agent.
3. **Probe** using a single embedded script. It collects:
   - `/etc/os-release` and `uname -r`;
   - `sshd -T` values: `pubkeyacceptedalgorithms`, `kexalgorithms`, `ciphers`, `permitrootlogin`;
   - the server version banner and `rpm -q openssh-server`;
   - which of dnf or dnf5 is installed;
   - the SELinux mode.
4. **Choose.**
   - The key algorithm is the first in the profile's `key_preference` that the target also accepts.
   - The profile falls back `modern` → `compat` → `legacy`. `legacy` requires `--allow-legacy`.
   - If `route = edge`, the profile must also be valid on edge.
5. **Generate the credential** for (label, root).
   - Run `ssh-keygen` into a private tmpfs directory.
   - Verify that `ssh-keygen -y` reproduces the `.pub` exactly.
   - Encrypt the key into the vault, then unlink the plaintext.
   - Update `MANIFEST.b3`.
6. **Install the key** as `from="…",no-agent-forwarding,no-X11-forwarding <key> swrap:<label>:root:<ISO date>`. The write is atomic (temp file, fsync, rename), followed by `restorecon`.
7. **Verify** the new key in a fresh connection.
8. **Remove** all `swrap-enroll-*` lines, and verify that an enrollment-key login now fails.
9. **Install the extras:**
   - `/etc/profile.d/swrap.sh`;
   - the sshd drop-in with `AcceptEnv SWRAP_SESSION`, applied with the same safety procedure as `swcrypto apply` (section 9.3);
   - the sudoers handling from section 10.5.
10. **Inventory** the host, set `state = "active"`, commit.

Every step is idempotent. A failure leaves the host in `pending` with a precise description of what has already been done.

### 10.4 `swrotate <targets> [--algo …] [--user …]` and `swdel <label> [--keep-keys-on-host]`

- **Rotation** adds the new key, verifies it, removes the old one and verifies the removal. Retired keys stay encrypted in `vault/keys/retired/` for P30D and are then destroyed.
- **Deletion** removes swrap's credentials from the host, marks the host `removed`, and archives its keys. Recordings are never deleted by `swdel`.

### 10.5 Remote users and sudo: `swuser` (admin)

```
swuser add <targets> <ruser> [--sudo] [--shell /bin/bash] [--uid N]
swuser del <targets> <ruser> [--keep-home]
swuser lock|unlock <targets> <ruser>
swuser sudo <targets> <ruser> on|off
swuser list <targets>
swuser adopt <targets> <ruser>
```

- **Sudo is NOPASSWD and swrap-managed.**
  - swrap writes `/etc/sudoers.d/swrap-<ruser>` containing `<ruser> ALL=(ALL) NOPASSWD: ALL`.
  - The file is checked with `visudo -cf` and then renamed into place atomically.
- **No passwords.** Accounts are locked with `usermod -p '!'`; the key is the only authenticator.
- **Drift detection.** Inventory flags `swrap-*` sudoers files that are unexpected or modified. Sudo rules outside `swrap-*` are reported but never touched.

**As built (2026-10-03), 10.4 and 10.5:**
- `swuser add <targets> <ruser> [--sudo] [--shell] [--uid]`: `useradd -m`, `usermod -p '!'`, a key of its own generated into the vault (the host's root key algorithm), its authorized_keys line written as root (temp file, rename, owner, modes, restorecon), with `--sudo` `/etc/sudoers.d/swrap-<ruser>` (written to a dot-file sudo ignores, `visudo -cf`, renamed into place, 0440). Then a fresh login with the new key (and `sudo -n true`). An account left by an interrupted `add` (it carries swrap's key line) is completed, any other existing one is refused (`adopt` takes those over: key, password locked, an existing swrap sudoers file with the right content counts).
- `del` (sudoers file, `pkill`, `userdel [-r]`; keys retired), `lock`/`unlock` (`usermod -e 1` / `-e ''`: an expired account cannot log in, not even with its key; verified both ways), `sudo on|off`, `list` (the accounts in the host file checked on the host: exists, expired, sudoers file present and unchanged).
- Root work runs as root, or through a swrap-managed sudo account on hosts without a root key; that account cannot remove, lock or un-sudo itself.
- `swrotate <targets> [--user u] [--algo a]`: per account, a new key under a name that sorts after the old one (new sessions keep the old key until the new one is proven), added next to the old one with the old key, verified with a fresh login, the old line removed (by its key blob) with the new key, the old key verified refused, then retired; the account swrap works through goes last. Retired keys (`vault/keys/retired/<label>_<ruser>_<ts>`, also `swdel`'s `<label>_<ts>`) are destroyed after P30D by the daily doctor run.
- Inventory drift: a `swrap-*` sudoers file is *unexpected* (no managed sudo account), *modified* (its sha256 differs from what swuser writes) or *missing*.
- Every host is a recorded run (`kind` swuser / swrotate); host files change under the config lock and are committed.

### 10.6 Targets syntax (all fleet commands)

- **Forms:**
  - a single label;
  - a shell-style wildcard on labels, e.g. `web*` or `db-?`;
  - `@tag`, or `@all`;
  - comma-separated lists;
  - `!` to exclude.
- **Expansion only covers hosts the caller has grants for.** An explicit label without a grant is an error.
- **Quote wildcards**, e.g. `swupdate 'web*'`, so bash doesn't expand them against filenames. The client warns when a target looks like it has been filename-expanded.

### 10.7 Inventory (`swinv [targets]`, timer every PT6H, runs on core)

Each host gets one SSH call running an embedded collector. Its output lands in `state/` (git #2), committed as `inventory <ISO> <ulid>`:

```
state/hosts/<label>/
  facts.toml            os, kernel, arch, uptime, last boot (ISO), selinux, ssh server version,
                        negotiated algorithms, last_inventory (ISO), inventory_status, sudoers drift
  os-release
  packages.tsv          name \t epoch:version-release \t arch
  updates.tsv           name \t available version \t repo
  security-updates.tsv  advisory \t severity \t package
  needs-reboot          yes/no
  accounts.tsv          user \t uid \t shell \t sudo \t has_swrap_key
  sshd-effective.txt
  repos.tsv
state/packages/<name>.tsv     label \t version   (fleet-wide per package)
state/tags/<tag>/<label>      symlinks
state/summary.tsv             label, route, os, kernel, #updates, #security, reboot, last_seen (ISO), status
```

- **dnf version.** The collector detects dnf4 or dnf5 and uses `check-update`/`updateinfo` or `check-upgrade`/`advisory` accordingly.
- **Timeouts.** Each host has a PT2M timeout. On timeout the previous data is kept and the status is marked.
- **History.** `git log -p hosts/<label>/packages.tsv` shows a host's package history.
- **Edge mirror.** The same tree is pushed to edge's read-only mirror.
- **As built (2026-09-28).**
  - `swinv [targets]` (default: every host you may use, with your most privileged account); swrapd runs it over every active host every PT6H (root, else swrap-managed sudo, else the default account), 5 minutes after start and whenever the vault is unsealed. `swupdate` re-inventories the hosts it upgraded. Each run is recorded (kind `swinv`) and committed to `state/` as `inventory <ISO> <ulid>`.
  - The collector is read-only and understands dnf4, dnf5 and apt (Debian/Proxmox): updates via `repoquery --upgrades` (apt: `apt list --upgradable`, no `apt update`), security via `updateinfo`/`advisory` (apt: the `-security` suites), needs-reboot via `needs-restarting -r` or the newest `kernel-core` against the running kernel (apt: `/var/run/reboot-required`). `facts.toml` adds `hostname`, `account`, `package_manager`, `security_advisories`, `updates_complete`, `last_attempt`; the summary's security figure counts packages with a pending fix. Without root the host's row says what could not be read (sshd config, other accounts' keys).
  - Files are staged and flushed with two `syncfs` calls per host and per index rebuild (each is still replaced atomically); this disk's ~190 ms flush made per-file fsync take minutes.
  - **Monitoring**: `swrap status` and the login message carry a fleet line (unreachable hosts, hosts with security updates and how many packages, hosts needing a reboot). Alerts (audit + the alert list) on changes after a host's first inventory: unreachable, reachable again (audit only), security updates appearing, reboot becoming needed, new unexpected `swrap-*` sudoers files.
  - **Tickets (table).** Actionable conditions become tickets through table's create-only form `aaa_create_ticket` (token in the vault, `swrap table token ticket`). Per host: unreachable, reboot needed, security fixes to install (packages with an advisory *and* an available update: advisories that only name older installed kernels count as "reboot needed"), unexpected `swrap-*` sudoers files, no endpoint agent, no asset record in table (and swrap could not create one). One ticket when conditions appear (grouped per host), none while they persist, a new one after they cleared and came back; `affected_asset` points at the host's asset. Other alerts (doctor, retention, clock) at most once per P7D each. Tickets queue while table or the vault is unavailable and are sent every PT5M. `swrap table status` lists open conditions and the queue.
  - **Asset record (table).** After every inventory the `aaa_*` columns of each enrolled host's asset (found by `aaa_label`, else a unique IP address, else hostname; the core by its own hostname) are set through the forms `aaa_asset_read`/`aaa_asset_update` (tokens in the vault): `aaa_label`, `aaa_asimilated` (false again for assets whose host left swrap), and `aaa_running_projects`. Projects come from the collector's git scan (`gitrepos.tsv`: working trees under /opt, /srv, /root, /home, /var/www, /usr/local/src with origin, last commit, use by a running process or a systemd unit); a repository counts when used, or changed within `active_days` (30). Clones of the git server link to its cgit page with the repository's description. Hand-written lines are never changed; lines swrap added are replaced when repositories come and go; a repository a hand-written line already links to is not added. `aaa_ipv4`/`aaa_ipv6` of existing assets stay with the endpoint agent. An enrolled host with no asset is given one through the create-only form `aaa_create_asset` (token `asset-create`) once it has a good inventory: name and `aaa_label` = label, hostname, os, status running, `running_since` = OS install time (the basesystem, filesystem or setup package; /var/lib/dpkg on Debian), type server or virtualServer (`systemd-detect-virt`), health healthy, `aaa_asimilated` true, the IP addresses and the detected projects; purchase date, expected life and notes are left to people. Only when that fails does the "no asset record" ticket go out. Settings: `config/table.toml` (`swrap table set`).
  - **fail2ban (aaa).** swrap-web also writes each failed or throttled login to its journal (`swrap-web: login failed for "<user>" from <address>`, the user quoted), which fail2ban's `swrap-web` jail on the core reads next to `sshd`; the LAN and home are never banned. Bans go to table's IOC list through `ioc-report` (repository `ioc-report` on the git server).
  - **Endpoint agent (table).** The agent (disks, SMART, root filesystem full) needs six table forms of its own per host (`asset_read/update_<id>` bound to the asset, `disk_read/update/create_<id>`, `ticket_create_<id>`), which only a table admin can create. swrap holds the login of the AAA admin account `aaa_adm` (`admin_user`) in the vault (`swrap table admin-password`, stdin or a no-echo prompt; stored only after table accepts it as an admin). A host whose inventory finds no agent, and that has an asset, gets it once a day at most (`agent_auto`): on the core, the agent's own `--provision-env` creates or aligns the forms with that login (every secret regenerated) and writes the host's env to `/run/swrap/eagent` (tmpfs, 0700, removed right after); then, like `swr` and recorded as a run of kind `agent`, the env goes to the host on stdin, never into the recording, the kept script or the output (each form secret is redacted), the checksummed agent is installed to `/usr/local/sbin/endpoint-agent.py`, and `--install` sets up its timer and runs a first update that proves the secrets. The admin login never leaves the core. Hosts reach table at `endpoint` (or `agent_endpoint`); edge hosts at `agent_endpoint_edge`, and without it they get no automatic agent. `swrap table agent <label>` does the same on demand, also on a host that has the agent (rotating its form secrets). Only when the deployment fails does the "endpoint agent not deployed" ticket go out, with the reason.
  - **Edge mirror (as built 2026-10-03).** swrap-edged long-polls core (`EdgeReq::State`, checked every 5 s) and receives the committed tree (`git archive` of `state/`'s HEAD, without `ai-usage.json`) when it moved on. It is unpacked to `/var/lib/swrap-edge/state.<commit>` (root:swrap-edge, 0750, `REVISION` inside) and `/var/lib/swrap-edge/state` is a symlink swapped atomically; the previous copy is removed. While the link is down the last tree stays readable. Only the tree is mirrored, not the history (`git log -p` stays on core).

### 10.8 Where fleet jobs run

Fleet jobs run on core, from either origin. From edge, the client forwards the job to core; any script file is uploaded as part of the request, and live output streams back (as built: edge relays every output frame to the client as it arrives, a line per host as each finishes, not after the answer).

### 10.9 `swr` and `swx`

```
swr <script> <targets> [-u <ruser>] [--secret-env NAME]... [-- args…]
swx <targets> [-u <ruser>] [--secret-env NAME]... -- <command>
```

- **Execution on the target:**
  - `mktemp` a directory and upload the script.
  - `chmod 700`, then run it with its own shebang, or `bash` if there is none.
  - stdin is `/dev/null`.
  - The directory is removed afterwards.
- **Parallelism and recording.**
  - Up to 8 hosts run in parallel.
  - Each run gets `runs/…/meta.toml` (who, script blake3, script copy, targets, args) and per-host swrec files (`o` records with `fd`) plus `.rc`.
  - Output is shown live with a prefix per host, followed by a summary table with ISO durations.
- **`--secret-env NAME`.**
  - Reads the value from the caller's environment. In the AAA shell, set it with `read -rs NAME; export NAME`.
  - The value travels to core in memory only and is delivered to the target as a 0600 file. A wrapper sources the file and deletes it before `exec`.
  - The value is never written to disk on core or edge and never logged.
  - Any occurrence of it (4 bytes or longer) in the output is replaced by `[REDACTED:NAME]`, and an `n` record notes the redaction.
- **RBAC** is checked per host. Running as root requires a root grant.
- **As built (2026-09-28).**
  - Script and secrets reach the host together on the SSH connection's stdin (never on a command line): a wrapper splits them into a `mktemp -d` directory (mode 700), sources the secrets file and deletes it before the script starts, runs the script with stdin from `/dev/null` (the interpreter line is honoured without executing from the temp directory, which may be `noexec`), and removes the directory when it ends. `swx` sends its command as a one-line bash script.
  - Redaction works on the byte streams before anything is shown or recorded, also for a secret split across output chunks; the host's swrec notes `redacted: NAME ×n` and the table shows the count. Only whole values are replaced: a script printing part of a secret shows that part. The run keeps the script (redacted), its blake3, the arguments and the secret *names*.
  - Set a secret with `read -rs NAME; export NAME` in the AAA shell: the AAA shell audits command lines, so `export NAME=value` on one would store the value there.
  - Defaults: your most privileged account per host (`-u` picks one), `[fleet] parallel` hosts at once, `[fleet] default_timeout` (PT10M) per host. Exit status 1 if any host failed.

### 10.10 `swupdate`

```
swupdate <targets>               # dnf -y upgrade --refresh
swupdate <targets> --app <pkg>   # dnf -y upgrade --refresh <pkg>   (upgrade only; never installs)
```

- **Target scope.** Only hosts where the caller can act as `root`, or as an account with swrap-managed NOPASSWD sudo (in which case it runs via `sudo -n`).
  - Other hosts are silently excluded from wildcard and tag expansion.
  - An explicitly named host without such access is an error.
- **`--app` handling.** Hosts where the package is not installed report `not-installed` and are skipped.
- **Output and follow-up.**
  - Live prefixed output.
  - A final table: label, result, packages changed, `needs-reboot`, duration (ISO).
  - Recorded as a run of kind `swupdate`.
  - The affected hosts are re-inventoried automatically.
- **Scope limit.** v1 has no reboots and no other flags.
- **As built (2026-09-28).**
  - dnf never runs attached to the SSH session: it runs under `setsid` with SIGHUP and SIGPIPE ignored, writing to `/var/tmp/swupdate-<run>.log`, which the job follows for the live output. A dropped link, a killed client or the per-host timeout (PT1H) stops only the waiting, never a transaction half way; the host row then says `timeout` and names the log. The log is removed after a successful run and kept after a failed one.
  - Result per host: `ok`, `failed` (dnf's exit code, log kept), `not-installed` (`--app`), `unsupported` (no dnf, e.g. Debian/Proxmox; v1 does not drive apt), `timeout`, `unreachable`, `error`. Packages changed = new name.arch/EVR entries in `rpm -qa` afterwards. needs-reboot comes from `needs-restarting -r` (dnf4 or dnf5 plugin), else from comparing the newest installed `kernel-core` with the running kernel.
  - Up to `[fleet] parallel` (8) hosts at once. The run directory holds `meta.toml`, per-host swrec (output with `fd`, signed by core) and `<label>.rc` (JSON: exit, result, changed, needs_reboot, duration, detail). The audit log gets `fleet.update` at the start and with every host's row at the end. The exit status is 1 if any host failed.
  - Hosts on the edge network run through edge, which returns their output when dnf finishes (no live lines for them); from an edge login, output arrives when the whole job ends.
  - Re-inventory waits for `swinv` (10.7), which is not built yet.

---

## 11. SFTP virtual filesystem

### 11.1 Dispatch (both nodes)

`Subsystem sftp /usr/libexec/swrap/sftp-dispatch`.

- **Admins** (`swrap-admin`) get `/usr/libexec/openssh/sftp-server -l INFO`, which serves the **real filesystem of the node they logged into**. Access is audited.
- **Everyone else** gets `swrap-sftp`.
- **scp works too.** Since OpenSSH 9.0, `scp` uses the SFTP protocol, so it goes through the same path. `rsync` does not.

### 11.2 Namespace for non-admins

```
/                      read-only virtual root
├── web1/            → / on web1 as the default (most privileged) account
├── deploy@web1/     → / on web1 as deploy (one entry per additional granted account)
└── …
```

- **What is listed.** The listing comes from core at connect time and includes only granted accounts that have credentials (and `edge_allowed` hosts, if the origin is edge).
- **Normalisation.**
  - `..` and `realpath` are normalised in the proxy, so the prefix cannot be escaped.
  - Absolute symlink targets returned by the remote are re-prefixed.

### 11.3 Backends and routing

- **Protocol.** `swrap-sftp` speaks SFTP v3 over stdio.
- **Opening a backend.** On first access to an entry, it asks its local daemon for a backend. The exec node follows section 4.2:
  - **Local exec:** the worker starts `ssh -s sftp` with a per-session agent (remote signing when on edge) and hands back the stream.
  - **Delegated exec:** core opens the backend, and the stream travels over `core-pty.sock`.
- **Handles and idle timeout.** Handles are namespaced per backend. Idle backends close after PT5M.

### 11.4 Accounting

- Every operation becomes an `f` record in `rec/<user>/sftp/…`. On edge, these go through the spool.
- Whole-file transfers also record the blake3 of the content.
- File contents are not stored (decision 21.4).

### 11.5 As built (2026-09-28, core logins)

- **Dispatch.** `06-swrap.conf` sets `Subsystem sftp /usr/libexec/swrap/sftp-dispatch` (the first definition wins over the distro's). sshd runs it through the login shell; `swrap-shell -c` execs it directly. `swrap-admin` members get `sftp-server -l INFO` on the real filesystem (audited as `sftp.admin`); accounts outside `swrap-users` (root, system accounts) get `sftp-server` exactly as before.
- **Worker, not the user's process.** AAA users' connections go to swrapd, which starts a worker (swrap uid, like `sw` workers, survives daemon restarts). The worker speaks SFTP v3 to the client and owns the host connections and the recording; the user's process only relays bytes, so it never holds a host connection it could use unrecorded.
- **Host connections.** On first use of a directory the worker asks swrapd (`Req::SftpBackend`, per-session token), which checks the grant again at that moment, starts the per-connection signing agent (killed once ssh has authenticated, as for `sw`) and returns the ssh command; the worker runs `ssh -s <ruser>@<host> sftp` with the usual pinned-key options. A lost connection fails what was waiting on it; the next access reconnects. Idle connections close after PT5M.
- **Namespace.** Paths are normalised lexically in the worker, clamped at the virtual root; absolute symlink targets come back re-prefixed, and a new symlink may only point into its own host. The top level is read-only. Rename, hard link and server-side copy work within one host; across hosts they fail (clients fall back to copying). Supported extensions: posix-rename, statvfs, fstatvfs, hardlink, fsync, lsetstat, limits, expand-path (`~` is the virtual root), copy-data, home-directory; an extension the host's server lacks is answered as unsupported.
- **Recording.** `rec/<user>/sftp/…` (kind `sftp`, signed by core). Every request is an `f` record (op, label, ruser, the path on the host, result, attributes where given); reads and writes are summarised per handle at close as `get`/`put` with byte counts and the blake3 of the content when the whole file went through in order (`partial` otherwise). Search indexes file paths as `label:path`.
- **Tested** with OpenSSH `sftp`: browse, get, put, rename, mkdir/rmdir, remove, the refusals at the top level, a 64 MiB transfer each way (~90 MB/s on the LAN, recorded hashes identical), a killed host connection (reconnects).
- **Edge logins (as built 2026-10-03, 11.3 delegated).** Edge's sshd has the same `Subsystem sftp /usr/libexec/swrap/sftp-dispatch` (root, admins and other accounts still get `sftp-server`). An AAA user's SFTP on edge goes to swrap-edged, which delegates the whole session over `core-pty.sock`: the worker runs on core, its recording is core's (`origin=edge exec=core delegated=true`), and the namespace and every backend use the user's *edge* grants (only `edge_allowed` hosts).
- **Hosts only edge reaches (`network = edge`, e.g. web1).** ssh still runs on core, with the usual per-connection agent, hostbound check and pinned keys; its `ProxyCommand` is `swrapd tunnel <id>`, a one-use tunnel (PT1M, swrap uid only) for which edge opens the TCP connection (`EdgeJob::Connect`) and attaches it to the link. Edge relays only ciphertext. Refused while the link is down.
- **Tested** with OpenSSH `sftp`: get from web1 through the tunnel (core login), the namespace and a get from web1 for an edge login, root on the edge through its dispatcher.

---

## 12. Integrity strategy (non-ECC)

1. **Checksum at creation, verify at use.** This covers swrec CRC plus blake3 segments, gzip member CRCs, `MANIFEST.b3`, git objects, and the snapshot signature.
2. **Atomic writes with read-back.** Write to a temp file, fsync, read it back and compare blake3 with the in-memory buffer, rename, fsync the directory.
3. **No long-lived in-memory state.** Config and RBAC are re-read on every request.
4. **Verify before destroying.** Enrollment, rotation, compression and spool deletion only remove something after the replacement has been verified or acknowledged.
5. **Vault protections.** Every wrap and every key file is protected by an AEAD tag. After unwrapping, the DEK is checked against a stored blake3 keyed commitment, so a bit flip gives a clean error rather than a wrong key.
6. **Doctor jobs.**
   - Daily run and weekly `--scrub`.
   - `swrec verify`, including gzip members.
   - `git fsck --full`, then `git update-index --really-refresh` and a porcelain status check for silent working-tree changes.
   - The vault manifest, and `rpm -Va` on swrap and openssh.
   - A comparison of the snapshot version and state between core and edge.
   - On edge, a check that no spool file is older than the configured age when the link is up.
   - Findings go to the audit log and the admin MOTD.
7. **Backups.** `rustic` backs up core's primary data. Edge needs no backups: it is rebuilt from the installer, then the link key is re-authorized and its recording key re-pinned. The vault recovery key is kept offline.

---

## 13. Firewall and edge operation

### 13.1 Model `config/firewall.toml`

```toml
[[web_allow]]
id = "01J8ZQ…"
cidr = "198.51.100.7/32"
not_before = "2026-09-23T08:00:00Z"
not_after  = "2026-09-23T16:00:00Z"   # optional
comment = "hotel wifi"
created_by = "admin"
created = "2026-09-23T07:58:12Z"

[[ssh_block]]
id = "01J8ZR…"
cidr = "203.0.113.0/24"
not_after = "2026-10-23T00:00:00Z"
comment = "scanner"
```

- **Defaults.** The web GUI denies everyone by default. Edge SSH on :22 is open to everyone, subject only to `ssh_block` entries and rate limits.
- **Rate limits** are set in `edge.toml`.
- **sshd's own `PerSourcePenalties`** is enabled on edge's sshd as a second layer.

### 13.2 CLI (admin, from either node; executed on core)

```
swfw web allow <ip|cidr> [--for PT8H | --until 2026-09-24T00:00:00Z] [--comment "…"]
swfw web allow --my-ip [--for PT8H]
swfw web allow lan
swfw web revoke <id>
swfw ssh block <ip|cidr> [--for P30D] [--comment "…"]
swfw ssh unblock <id>
swfw list
swfw status          # snapshot version core vs edge, applied_at (ISO), link state
```

- **Publishing a change.** Each change is committed on core. Core then builds the snapshot, signs it with the vault's `edge-config` key and bumps the version.
- **Sealed vault.** While the vault is sealed, changes queue as `pending (vault sealed)`.
- **Applying on edge.** Edge fetches the new snapshot by long-poll, verifies it, and applies it atomically to the `inet swrap` nftables sets, using per-element timeouts derived from `not_after`. It then acknowledges.
- **Applying on core.** Core applies the web allow-list to its own nftables for LAN access to :443.
- **Defence in depth.** `swrap-web` also re-checks the source address, which it receives via PROXY v2.

### 13.3 Web relay

- **Mode.** In `port` mode (default :8443) or `sni` mode (:443 shared with Stalwart), swrap-edged checks the allow-list and then relays raw TLS bytes.
- **Relay header.** Before the TLS bytes, edge sends a header line `SWRAP-RELAY/1 {"conn","src","sport","ts","svc":"web"}` over `core-web.sock`.
- **Core side.** `swrap-ingress` validates the header and forwards to `swrap-web` using PROXY v2.
- **TLS** terminates on core, so edge never sees web passwords or content.

---

## 14. Vault: encryption at rest, unsealed by admin password login

### 14.1 Cryptography

- **DEK.** A random 256-bit DEK encrypts every key file with XChaCha20-Poly1305. Each file gets a random nonce, and its AAD is the relative path plus the key id.
- **Per-admin wraps.** For each admin the DEK is wrapped with argon2id(vault password), default m = 256 MiB, t = 3, p = 1. The parameters are stored with each wrap.
- **Recovery key.** 256 bits, shown once at install as base32 groups and stored offline. It also wraps the DEK.

### 14.2 Admin login = unseal

- **sshd on both nodes** (non-admins stay `publickey`-only; admins always need key + password):
  ```
  Match Group swrap-admin
      AuthenticationMethods publickey,keyboard-interactive:pam
  ```
- **PAM auth stack for sshd** (only admins ever reach it):
  - `pam_faillock`
  - `pam_exec.so expose_authtok quiet /usr/libexec/swrap/swrap-pam-unlock`

  The system `password-auth` include is removed from the sshd auth phase. The vault password *is* the admin's SSH password.
- **`swrap-pam-unlock` on core:**
  1. Unwrap the DEK with the password.
  2. Check the commitment. Authentication succeeds if and only if both steps pass.
  3. If the vault is sealed, hand the DEK to swrapd over `/run/swrap/unseal.sock` (root-only, `SO_PEERCRED` uid 0).
  4. Zeroize everything.
- **`swrap-pam-unlock` on edge:**
  - It sends (user, password) over the link to core, which runs the same verify-and-unseal and returns ok or fail.
  - The password exists in edge memory only briefly and is zeroized afterwards.
  - If the link is down, admin login on edge fails (fail-closed). The fallback is to log in on core from the LAN, or use the provider console.
  - Setting `edge.admin_offline_login = true` enables a separate edge-only admin password, stored as an argon2id hash on edge. It is off by default, and it must differ from the vault password, because edge could be compromised.
- **Auditing.** Every attempt is audited on core.
- **`swunlock`** exists as a manual fallback.
- **Holding the DEK in swrapd:**
  - `mlock`ed memory, zeroize-on-drop.
  - `PR_SET_DUMPABLE=0`, `LimitCORE=0`.
  - A copy lives in the `swrap` user's kernel keyring, so restarting swrapd does not reseal.
- **Resealing.** A reboot reseals, and so does `swadm vault seal`.
- **Risk.** An admin logging in on a compromised edge exposes the vault password. That alone is not enough to open the vault: the attacker also needs the wrap files and the admin's SSH key. Unseal from the LAN when practical.

### 14.3 While sealed

| Works | Doesn't |
|---|---|
| Both shells and their recording, link, edge log shipping, web playback and search, retention, compression, doctor (except vault checks), snapshot enforcement on edge | `sw` (all nodes), SFTP host entries, fleet, `swupdate`, `swinv`, enrollment, rotation, `swuser`, publishing firewall changes |

The MOTD on both nodes shows the seal state with an ISO timestamp.

### 14.4 Commands

```
swadm vault status | seal | passwd | add-admin <user> | recover
```

---

## 15. Retention (core; disk-based only)

- **No time-based deletion.** Every PT1M swrapd measures the filesystem holding `/var/lib/swrap`.
- **Watermarks.** At **≥ 90 %** (`high_watermark_pct`) it deletes the oldest items until usage is below `low_watermark_pct` (default 90). Set the low mark to 85 for hysteresis.
- **Eviction order.**
  1. The oldest start `ts` across `rec/*`, `runs/` and `logs/edge/`.
  2. `audit/` only when nothing else remains.
  - Live sessions are never deleted.
- **Auditing.** Every eviction is audited with id, kind, user, host, start and bytes.
- **Safety.**
  - If deleting everything deletable still would not get under the watermark, eviction stops and an alert is raised.
  - Evicting anything younger than `alert_if_evicting_younger_than` (default P30D) also raises an alert, since that pattern could mean deliberate output flooding to push out evidence.
- **Compression** (gzip after P7D, section 8.7) runs before eviction is considered.
- **Edge** retains nothing beyond its spool (section 8.8).

---

## 16. Web GUI (core; playback and search only)

- **Access.**
  - Reached through edge `:8443` (or `:443` in `sni` mode) or from the LAN, allow-listed in both cases.
  - TLS terminates on core.
- **Login.**
  - Username plus password (argon2id, set with `swpasswd`).
  - Cookie flags `HttpOnly; Secure; SameSite=Strict`, lifetime PT12H.
  - Backoff per source and per user, and every attempt is audited.
- **Permissions.** Users see their own records; admins see everything. There are no write endpoints other than login and logout.

### 16.1 Search (main page)

- **Timeframe (mandatory).**
  - An ISO interval, default `P1D/now`, with buttons for PT1H, P1D, P7D and P30D.
  - Files are pruned first by their `YYYY/MM/DD` path, then by header and end `ts`.
- **Fields.** Every field is optional, and all given fields are ANDed.

  | Field | Matches |
  |---|---|
  | `host` | label or address (glob) |
  | `ruser` | remote user (glob) |
  | `user` | AAA user (glob; admins only) |
  | `kind` | `sw`, `shell`, `sftp`, `run` |
  | `node` | origin or exec node (`core`, `edge`) |
  | `cmd` | `x` records and run command lines or script names |
  | `keys` | keystrokes rendered as text: printable characters as-is, `^C`, `<Up>`, `<Tab>`, `<Enter>` |
  | `out` | output with ANSI stripped and chunks joined, so matches across chunk boundaries work |
  | `file` | SFTP paths |
  | **free text** | all of the above plus header metadata |

- **Query syntax.**
  - Values are literal by default.
  - `/regex/` for a regular expression, `-term` to negate, `"…"` for a phrase.
  - Example of the equivalent one-line query language, which `swsearch` accepts identically:
    ```
    window:P7D/now host:web* cmd:/dnf .*install/ out:"permission denied" -ruser:deploy
    ```
- **Engine.**
  - A streaming zgrep-like scan over `.swrec` and `.swrec.gz`, parallelised with rayon and streamed to the browser via SSE.
  - The UI has a cancel button and shows progress in files and bytes scanned.
  - Results are capped at 1000. There is no persistent index.
- **Results.** Each hit shows the session header, the matching field, an ISO timestamp and a snippet with context. Clicking opens the player at `ts − PT2S`.

### 16.2 Player

- **Engine.** A vendored asciinema-player (Apache-2.0, no CDN, strict CSP), fed asciicast v2 generated on the fly from `.swrec` or `.gz`.
- **Side panel:**
  - metadata: origin and exec node, delegated, hostbound, negotiated crypto;
  - verification status and gap markers;
  - a command timeline that seeks on click;
  - an overlay toggle for keystrokes.
- **Shell recordings** show clickable links into their nested `sw` recordings.
- **Live sessions** can be followed in real time, including edge sessions as their records arrive.
- **Idle time** is capped at PT2S, and all times are shown in ISO format with the offset.

---

## 17. AAA users and inbound SSH (both nodes)

- **Groups** are `swrap-users` and `swrap-admin`.
- **Accounts.**
  - They are defined on core in `users/<name>.toml`: role, grants, disabled flag, inbound keys.
  - Edge creates and updates matching Linux accounts from the snapshot: login shell `swrap-shell`, no password.
- **Inbound keys** live in `/etc/ssh/authorized_keys/%u`, owned by root and managed only through `swadm key`.
- **Default accounts.**
  - `admin`: admin role, no host grants.
  - `deploy`: user role, grant `hosts="*"`, `remote_users=["*"]`, `via=["core","edge"]`.
- **sshd on both nodes.**
  - Users authenticate with a key only; admins need key plus password.
  - `AllowGroups swrap-users swrap-link`.
  - All forwarding off for users, `PermitTunnel no`, `PerSourcePenalties yes`, `LogLevel VERBOSE`.
  - The `inbound` profile applies, and it accepts FIDO2 keys.
  - Core listens on the LAN only.
- **Outbound nftables.** Outbound SSH to managed hosts is allowed only for uid `swrap` on core and uid `swrap-edge` on edge.

Admin commands (run on core; forwarded when typed on edge):

```
sudo swadm user add <name> [--admin] [--key …]     # core; edge picks it up via snapshot
sudo swadm user del <name>
swadm user list|disable|enable <name>
swadm key add|del|list <name>
swadm grant <aaa_user> <hosts> <remote_users> [--via core,edge] [--until <ISO>]
swadm revoke <aaa_user> <grant-id>
swadm show <aaa_user>
```

---

## 18. CLI summary

| Command | Who | Purpose |
|---|---|---|
| `sw [ruser@]label [-- cmd]` | granted | Recorded session (output, keystrokes, commands) |
| `swls` | all | My hosts and accounts, with route and default marked |
| `swr`, `swx` | granted | Fleet script or command, with `--secret-env` |
| `swupdate <targets> [--app pkg]` | granted (root/sudo) | Fleet dnf upgrade |
| `swinv [targets]` | granted | Refresh inventory |
| `swlog [--window I] [--kind k]` | all | List records (admins can add `--all`) |
| `swsearch <query>` | all | Same engine and syntax as web search |
| `swcat <id> [--keys] [--cmds]` | all | Plain-text dump with ISO timestamps |
| `swplay <id> [--speed 2] [--from PT5M]` | all | Terminal replay |
| `swpasswd` | all | Set web password |
| `swadd`, `swenroll`, `swdel`, `swrotate`, `swuser`, `swcrypto`, `swfw`, `swadm`, `swunlock` | admin | Management |
| `swrap doctor [--scrub] [--rebuild]` | admin | Integrity checks |
| `swrap edge status` | admin | Link state and uptime, snapshot versions, spool bytes, last ack, clock offset (all ISO) |

---

## 19. Performance and sizing

The numbers below are **engineering estimates** meant to guide sizing. Phase 13 includes benchmarks that replace them with measurements.

### 19.1 Per-session cost on the exec node

| Piece | Typical RSS |
|---|---|
| sshd for the AAA login (privsep monitor + session), shared by all `sw` in that login | 6–10 MiB |
| `swrap-shell` recorder | 2–4 MiB |
| `sw` client | 1–3 MiB |
| session worker (PTY, buffers, recorder) | 4–8 MiB |
| `ssh` client | 5–8 MiB |
| per-session `ssh-agent` (core only, short-lived) | ~2 MiB |

- **Memory.** A concurrent `sw` session costs about **20–30 MiB** on the node running it. A delegated session splits this: about 12 MiB on edge (login, shell, client, relay) and about 15 MiB on core.
- **CPU.**
  - Interactive work is negligible.
  - Bulk output is limited by recording: JSON escaping plus CRC32C and blake3. **Target at least 100 MB/s per core** for the recorder.
  - The encryption itself (ChaCha20-Poly1305 or AES-GCM with AES-NI) runs well above 1 GB/s per core.
  - In practice the user's terminal emulator is usually the slower side.
- **fsync.** At most one `fdatasync` per second per actively writing session. Even a consumer SSD under ZFS handles hundreds per second, so this is not a limit at personal scale.

- **Measured (2026-10-03, the reference core: 4 vCPU, 7.5 GiB).** A concurrent `sw` session ~15 MiB on core (README, Performance). A swai session with Claude Code 250–320 MiB (the harness 230–275 MiB, swrap's worker 14–42 MiB): the harness dominates, so `sessions_per_user` (12) and `min_available_mb` (1024) are what bound it; with 4 sessions running, about 15 more fit here. Recorder 690 MB/s CPU-bound (tmpfs), 105–113 MB/s to this VM's disk.

### 19.2 Storage

| Activity | Raw swrec per hour | After gzip (typ. ×5–×15) |
|---|---|---|
| Light interactive (editing, a few commands) | 20–200 KiB | 5–40 KiB |
| Typical admin work (dnf, logs, config) | 0.5–5 MiB | 0.1–1 MiB |
| Heavy output (`journalctl -f` on a busy host, builds) | 50–500 MiB | 5–60 MiB |

- **Measured, swai (25 sessions, 414 h):** 0.8 MiB per session-hour on average (0.2–2.6), gzip 4–9×; the TUI stream and tool outputs dominate, messages are stored once each.
- **Overhead.** JSON framing and escaping add roughly 20–100 % over raw terminal bytes. ANSI-heavy TUIs such as `htop` are at the high end.
- **Example.** 10 sessions a day of 1 hour each, at 5 MiB/h, is about 50 MiB/day raw. That is roughly 18 GiB/year raw and 2–4 GiB/year compressed. A 100 GiB data disk lasts many years; the 90 % watermark handles the rest.

### 19.3 Network

- **Edge-run sessions.** Interactive traffic goes user → edge → host. The edge → core recording stream is roughly 1.2–2× the session's output plus input, i.e. typically under 10 kB/s per session. Bursts of MB/s while dumping logs are absorbed by the spool if the link is slower.
- **Delegated sessions and SFTP to internal hosts** cross your home uplink twice (edge ↔ core). Large file transfers to internal hosts are bounded by home upload/download bandwidth.
- **Latency.**
  - Keystroke echo for edge-run sessions is RTT(user, edge) + RTT(edge, host). swrap adds under 1 ms; the p99 target is below 1 ms.
  - Session setup from edge adds about 2–4 edge↔core round trips: authorize, host keys, remote signing, and session-bind verification. That is typically tens of milliseconds in total.
  - Delegated sessions add RTT(edge, core) to every keystroke.

### 19.4 Search

- **Throughput.**
  - Uncompressed scans run at roughly 300–1000 MB/s per core from the page cache, less from disk.
  - gzip decompression runs at roughly 150–300 MB/s per core of output.
- **On 2 vCPU:**
  - a P7D window over about 500 MiB takes a few seconds;
  - a year of compressed data (tens of GiB raw) takes minutes.

  That is why the timeframe is mandatory and why the default is P1D.

### 19.5 Minimal and recommended setups

| | Minimal | Recommended |
|---|---|---|
| core VM | 2 vCPU, 2 GiB RAM, 20 GiB OS + 50 GiB data | 2–4 vCPU, 4 GiB RAM, 32 GiB OS + 100–200 GiB data |
| edge swrap budget (on the shared VM) | 256 MiB guaranteed, 512 MiB max, 1 GiB disk for spool | 512 MiB guaranteed, 1 GiB max, 2 GiB spool |
| edge VM total (with Stalwart) | 2 vCPU, 2 GiB | 2 vCPU, 4 GiB |

- **Memory notes.**
  - Argon2id with m = 256 MiB runs only on core, only at unseal and web login time, and for about PT1S.
  - Stalwart's own needs depend on mailbox count, spam filtering and full-text search. A small personal instance commonly fits in 0.5–1 GiB, but check Stalwart's current recommendations.
- **Reasonable concurrency.**
  - **Personal use is 1–10 concurrent sessions,** far below any limit here.
  - core at 2 vCPU / 4 GiB: about 50–100 concurrent interactive sessions before memory becomes the limit.
  - edge within a 512 MiB swrap budget: about 15–20 concurrent edge-run sessions.
  - Enforced defaults: 10 sessions per user, 20 per edge, 100 per core, plus sshd `MaxStartups 10:30:60` and `MaxSessions 10`.
  - Fleet parallelism 8 costs about 8 × 10 MiB on core.

---

## 20. Implementation phases (Stage 1)

Stage 2 phases are listed in section 24.12 and start only after every Stage 1 acceptance test in section 22 passes.

1. **Foundation.** Workspace; `swrap-core`, including a heavily tested ISO 8601 module; atomic writes; git; the framed protocol; `swrec` v1.1 with gzip members, verification, renderers and fuzzing.
2. **Vault.** DEK and wraps, recovery key, `swrap-pam-unlock` in core mode, sshd and PAM configuration, the kernel keyring, and `swadm vault`.
3. **Core sessions.** swrapd, workers, the per-session agent with the filtering proxy, `sw`, keystrokes, heuristic commands, and `swls`/`swlog`/`swcat`/`swplay`.
4. **AAA shell.** `swrap-shell`, the integration snippet, OSC capture and stripping, and pause/link.
5. **Search and web.** The engine, `swsearch`, `swrap-web` and live view.
6. **Enrollment and profiles.** `swadd`, `swenroll`, `swrotate`, `swdel`, `swcrypto` with per-node validation.
7. **Link and edge core services.** Link supervision; `swrap-edged` with the snapshot, account sync, remote-signing tunnel (including a session-bind check), spool and streaming, delegated PTY relay, forwarding of commands to core, and `swrap-pam-unlock` in edge mode.
8. **Inventory, fleet, updates.** `swinv`, `state/` with its edge mirror, `swr`/`swx` with secrets and redaction, `swupdate`.
9. **Users.** `swadm` and `swuser` with sudoers management and drift detection.
10. **SFTP.** Dispatch, `swrap-sftp`, local and delegated backends, `f` records.
11. **Firewall and web relay.** `swfw`, the nftables `inet swrap` table on both nodes, edge rate limiting, port/SNI web relay, `swrap-ingress`.
12. **Retention and operations.** Watermark eviction, compression, doctor and scrub, edge log shipping, SELinux modules, systemd slices and sandboxing, installers `swrap-install core|edge`, RPM specs, and a README with the Proxmox checklist, Stalwart co-location guide, backup guide and threat model.
    - *As built (2026-10-03), SELinux:* module `swrap` 1.3.0 with `swrapd_t`, `swrap_web_t` and `swrap_ai_t` (the swai harness, own home type, no network beyond its sandbox's loopback), rules drafted from a week of permissive denials and loaded while still permissive; `swrap install selinux [--enforce|--permissive]` switches; `swrap doctor --selinux` lists what enforcement would still deny.
13. **Benchmarks.**
    - `swrec bench` for recorder throughput.
    - A synthetic load test with N concurrent sessions against a local sshd emitting output; measure RSS per session, added keystroke latency and edge spool behaviour with the link cut.
    - Search throughput over generated corpora.
    - Update section 19 with the measured values.

---

## 21. Open decisions (defaults in bold)

1. **Break-glass access** (both nodes down, or the vault password lost). **You provide a break-glass public key at install. swrap installs it for root on every host without `from=`, and its private key lives offline.** The recovery key covers a lost vault password.
2. **Encryption of recordings at rest.** Recordings contain keystrokes, including passwords typed in `sw`. **VM disk encryption is documented, and files stay in clear so grep and search work.**
3. **Web 2FA.** **TOTP is available but off; the allow-list is required anyway.**
4. **SFTP content archival.** **Hashes only.**
5. **Admin access to host filesystems via SFTP.** **Not in v1**; admins see the node's real filesystem.
6. **Per-session output cap** against eviction flooding. **No cap; alert only.**
7. **`from=` restrictions when core's public IP is dynamic.** **On; set `network.from_restriction = false` if your ISP rotates addresses.**
8. **Edge OS.** **Rocky 10**, for host-bound signing.
9. **Third node or witness for HA.** **No; single-writer core by design.**
10. **Host key change policy.** **Hard fail; `swenroll --rekey-hostkey` with fingerprint confirmation.**
11. **Credential model.** **Per-(host, user) keys with remote signing**; an SSH-certificate backend is possible later.
12. **Shipping Stalwart logs to core.** **No.**
13. **Fleet execution on edge** for `route=edge` hosts. **Not in v1; fleet runs on core.**
14. **Admin offline login on edge while the link is down.** **Off; use the provider console.**
15. **Legacy targets.** **`legacy` profile, opt-in per host, warns on every use.**
16. **Detach/reattach of `sw` sessions.** **Not in v1.**
17. **Debian/Ubuntu targets.** **Pluggable collector; only rpm/dnf in v1.**

---

## 22. Acceptance tests (MUST pass)

**Records and retention**
- Kill the worker with `kill -9` mid-session; do 20 hard VM resets under load; run 10 000 fuzzed files (bit flips, deleted bytes, deleted LFs, truncation) for both `.swrec` and multi-member `.gz`. The reader never panics and damage stays local.
- Compression and spool deletion are crash-tested at every step.
- Filling the disk to 91 % evicts the oldest records until usage is below 90 % and never touches live sessions. When the fill comes from non-swrap data, eviction stops and an alert is raised.
- Every timestamp in files, CLI output and web responses passes an ISO 8601 validator. `--since 7d` is rejected.

**Placement and edge**
- From edge, `sw public-vm` runs `ssh` **on edge**. A packet capture shows no session traffic through core, only the record stream. `sw web1` (route core) runs on core with edge relaying.
- From core, both hosts run on core.
- `swrec verify` passes on core for edge-produced records, which are signed by edge's key.
- Cutting the link mid-session:
  - the edge-run session continues and its spool grows;
  - on reconnect, core's file becomes byte-identical to the edge spool, which is then deleted;
  - a full spool terminates the session with `reason=spool_full`;
  - a delegated session ends with `link_lost`;
  - new `sw` on edge is refused.
- Remote signing:
  - Edge never holds a private key; an inotify watch and a scan of `/proc/*/maps` for key material show nothing.
  - A forged sign request (wrong user, too many signatures, outside the time window, wrong host key in session-bind) is refused and audited.
- Compromised-edge simulation:
  - forged snapshots, replayed snapshots, oversized or malformed API frames, and log floods are rejected or contained;
  - RBAC cannot be changed from edge.
- Stalwart co-location: swrap never modifies nftables tables other than `inet swrap`, and mail ports stay reachable throughout the swrap install, upgrade and uninstall.

**Recording and search**
- Keystrokes appear in `sw` recordings and are absent from shell recordings.
- `read -rs X` leaves no trace on either node.
- Output containing a `--secret-env` value is redacted.
- A nested `sw` produces `l` markers with no duplicated bytes, and a forged marker is ignored.
- Each search field matches only its own stream. Free text matches everything. The timeframe prunes files, and hits open the player at the right place.

**Vault**
- After a reboot, `sw` is refused everywhere.
- An admin key-plus-password login on edge (with the link up) or on core unseals the vault.
- A swrapd restart keeps the vault unsealed; a reboot seals it again.
- Wrong passwords are rejected, audited and counted by faillock.
- A bit flip in a wrap file produces a clean error.
- No plaintext key ever lands on disk on either node.

**Hosts**
- `swupdate 'web*'` touches only granted hosts; `--app openssl` skips hosts without the package.
- `swuser add … --sudo` produces NOPASSWD sudo, and a manual edit is detected as drift.
- SFTP: only granted entries are visible; the prefix cannot be escaped; `scp` works; admins see the node's real filesystem; all operations produce `f` records; entry routing follows section 4.2.

**As built (2026-10-03): `tests/acceptance/acceptance.sh`.** The safe tests (read-only, or creating and removing their own data on a test host) run by default on the live system: ISO/UTC in CLI output and `--since 7d` refused, the fuzzer, edge-signed records verified on core, no keystrokes in shell recordings, `--secret-env` redaction, search fields kept apart, `swuser --sudo` and sudoers drift, SFTP namespace and `f` records, no key material on edge, mail ports and the `inet swrap` table, SFTP from an edge login, recorder throughput, refusal while sealed. Destructive ones (worker `kill -9`, disk fill to 91 %, link cut, 20 hard VM resets, 20 concurrent edge sessions) run only when named with `SWRAP_ACCEPT_DESTRUCTIVE=yes`, and print their procedure for a scratch setup. First run on core: all safe tests pass (the account test was left out on production hosts); fixed on the way: users now find their own fleet runs in search and the web player (by `who` in the run's meta.toml), `swls` refuses arguments. Recorder: 105–113 MB/s idle, 87–91 MB/s while a build ran.

**Performance** (phase 13)
- Recorder throughput is at least 100 MB/s per core.
- Added keystroke latency is under 1 ms at p99.
- 20 concurrent edge sessions fit within the swrap slice's `MemoryMax=512M`.

---

## 23. Configuration reference

### `config/swrap.toml`

```toml
[general]
display_timezone = "UTC"
default_profile = "modern"
enroll_key_ttl = "P14D"

[network]
internal_networks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"]
core_egress_addresses = ["203.0.113.10"]
from_restriction = true
lan_cidrs = ["192.168.1.0/24"]
managed_ports = [22]

[rec]
coalesce = "PT0.005S"
coalesce_max_bytes = 16384
sync_interval = "PT1S"
checkpoint_interval = "PT10S"
checkpoint_bytes = 262144
fold_repeats = true            # repeated output (spinners, animations) as `p` records, lossless

[retention]
high_watermark_pct = 90
low_watermark_pct = 90
check_interval = "PT1M"
compress_after = "P7D"
gzip_member_bytes = 262144
alert_if_evicting_younger_than = "P30D"

[limits]
sessions_per_user = 10
sessions_core = 100

[inventory]
interval = "PT6H"
host_timeout = "PT2M"
parallel = 8

[fleet]
parallel = 8
default_timeout = "PT10M"

[signing]
max_signatures_per_session = 4
window = "PT2M"
require_hostbound = false        # set true once edge runs OpenSSH ≥ 8.9 everywhere

[web]
bind = ["unix:/run/swrap/web.sock", "192.168.1.50:443"]
tls_cert = "/etc/swrap/tls/cert.pem"
tls_key  = "/etc/swrap/tls/key.pem"
session_lifetime = "PT12H"
search_default_window = "P1D/now"
search_max_results = 1000

[vault]
argon2_m_kib = 262144
argon2_t = 3
argon2_p = 1
```

### `config/edge.toml` (projected into the signed snapshot)

```toml
address = "edge.example.net"
link_port = 22
web_mode = "port"                # port | sni
web_port = 8443
web_sni = "swrap.example.net"    # used in sni mode
stalwart_https_backend = "127.0.0.1:8443"   # sni mode only
ssh_new_per_source = "10/PT1M"
ssh_unauth_concurrent_per_source = 3
web_new_per_source = "30/PT1M"
sessions_edge = 20
spool_max_bytes = 536870912
log_spool_max_bytes = 67108864
journald_max_retention = "P3D"
admin_offline_login = false
slice_memory_high = "384M"
slice_memory_max = "512M"
```

---

# Stage 2

## 24. AI workbench (build only after Stage 1 is tested)

> **As built:** this section was implemented as `swai`, a terminal harness (opencode) reached over SSH, instead of the Turnstone web GUI below. See the README section "swai: AI on your hosts, recorded". The safety requirements of this section still apply.

### 24.1 Goal

A second web GUI, for **normal (non-admin) users only**, that runs an AI agent harness on core. It is reached from the internet through edge, like the playback GUI.

- **Login** requires a single-use code checked out from the swrap CLI.
- **Inference** runs wherever the admin defines it, e.g. an OpenAI-compatible server at `10.0.0.20`.
- **Acting on hosts:** the agent can act only on hosts explicitly granted for AI. The intended pattern is **root on a dedicated, disposable test VM that exists only for the AI**.
- **Recording:** every model request and response and every tool call is recorded by swrap, like any other session.

Example: log in, pick the backend `lab-gpu` and the target `ai-lab`, type "build me a rust based app". The harness iterates on its own, making tool calls on `ai-lab` as root, and everything is recorded.

### 24.2 Build vs. reuse

- **The harness is not written by swrap.** swrap uses **Turnstone** (github.com/turnstonelabs/turnstone), a self-hosted orchestration engine for tool-using agents. It already provides:
  - the conversation loop, streaming, tool dispatch, retry and context compaction;
  - planning and parallel workstreams;
  - an LLM judge for tool calls;
  - OpenAI-compatible, Anthropic and Gemini backends;
  - MCP tools, a web UI, and OIDC login.
- **Turnstone is an external dependency, like OpenSSH.** It is Python, so it is the one exception to "everything built in Rust"; swrap only builds Rust glue around it.
- **Pin an exact Turnstone version** (image digest). Upstream moves fast and has renamed entry points and changed API shapes between releases. swrap talks to it only through standard interfaces: OIDC, MCP, the OpenAI/Anthropic HTTP APIs, and optionally its REST API for transcript export. An upgrade therefore touches configuration, not swrap code.
- **Verify every Turnstone-specific assumption in this section** against the docs of the pinned version at the start of phase S2.1. Where reality differs, use the fallbacks named inline.

### 24.3 Architecture

```
 Internet ──► edge :8444 (or SNI ai.<domain> on :443) ── allow-list "ai_allow" ──► link
                                                                                      │
 core ────────────────────────────────────────────────────────────────────────────────┤
   swrap-gate (Rust)  ◄── TLS terminates here                                          │
     • OIDC provider for Turnstone + authenticating reverse proxy in front of it      │
     • login = AAA username + one-time code from `swai login`                          │
            │ (only authenticated requests pass)                                       │
            ▼                                                                          │
   Turnstone (pinned, rootless podman, read-only rootfs, no host mounts except data)  │
     • network: NO direct egress. Can reach only:                                     │
            ├──► swrap-infer (Rust)  ──► inference backends (e.g. 10.0.0.20)      │
            └──► swrap-mcp  (Rust)   ──► swrapd ──► ssh ──► AI-granted hosts (ai-lab)  │
   Records: rec/<aaa_user>/ai/YYYY/MM/DD/<ts>_<ulid>.swrec[.gz]                        │
```

- **No other egress.** The container runs on an internal podman network with no default route. Its only reachable endpoints are swrap-infer and swrap-mcp, as unix sockets or loopback ports bound into the container's network.
- **No bypass of logging or RBAC.** Even if a user adds an arbitrary model URL or MCP server in Turnstone's UI, requests to it fail.
- **Built-in tools stay contained.** Turnstone's own shell and file tools act only inside the container, whose filesystem is ephemeral apart from its data volume. They SHOULD be disabled through Turnstone configuration if the pinned version allows it. If not, the container confinement above is the control.

### 24.4 Authentication: rotated one-time codes

- **Checking out a code.** In the AAA shell (either node; issued by core), run `swai login`. It prints a **single-use login code** and the URL:
  - 10 base32 characters in groups, 50 bits;
  - valid for **PT5M**;
  - bound to the calling AAA user;
  - only the blake3 hash is stored on core.
- **Web login.** The gate's login page asks for username and code. On success it consumes the code and issues its own session cookie (`HttpOnly; Secure; SameSite=Strict`, lifetime `ai.session_lifetime`, default PT8H). Then it completes Turnstone's OIDC login for that user.
- **Who may log in.** Only AAA users with role `user` and at least one AI grant. Admins are refused (separation of duties).
- **OIDC provider.** The gate implements the minimum OIDC surface Turnstone needs: discovery, JWKS, authorize (authorization code + PKCE), token, userinfo.
  - ID-token signing key: ed25519, stored in the vault, rotated every P30D, with the previous key kept in JWKS for P1D.
  - Claims: `sub` = AAA username, plus a `swrap_role` claim.
- **Fallback** if the pinned Turnstone cannot use an external OIDC provider: the gate stays an authenticating reverse proxy, and swrap provisions matching Turnstone users via `turnstone-admin`.
  - The gate maps its session to a Turnstone token that swrap rotates at every login.
  - Unauthenticated traffic still never reaches Turnstone.
- **Traffic.** Every HTTP request, SSE stream and WebSocket passes through the gate, which re-validates the session each time.
- **Revocation.** `swai logout [--all]` revokes sessions. A disabled AAA user loses AI access immediately.
- **Auditing and rate limits.** Every code issued, used, expired or failed is audited. Rate limiting is applied per source and per user.
- **Sealed vault.** The AI GUI is unavailable while the vault is sealed, because the OIDC signing key is in the vault.

### 24.5 AI grants: separate from human grants

AI never inherits a user's human grants. Access needs **both** keys below.

1. **The host must opt in:** `ai_allowed = true` in `hosts/<label>.toml`. Default is false.
2. **The user needs an explicit AI grant** in `users/<aaa_user>.toml`:

```toml
[[ai_grant]]
hosts = "ai-lab"              # label, glob or @tag — only hosts with ai_allowed = true ever match
remote_users = ["root"]
# until = "2027-01-01T00:00:00Z"
```

- **Default for `deploy`:** one AI grant, `ai-lab` as `root`. `ai-lab` is a VM that exists only for the AI.
- **Commands:** `swai grant <aaa_user> <hosts> <remote_users> [--until <ISO>]` and `swai revoke-grant <aaa_user> <id>` (admin only).
- **Recommended setup for the test VM** (README):
  - its own VLAN or Proxmox bridge, with internet egress but no route to the LAN or other managed hosts;
  - no credentials for anything else on it;
  - a Proxmox snapshot to roll back to.

  Root on that VM should mean nothing outside that VM.
- **`swai reset <label>` (MAY):** rolls the VM back to a named Proxmox snapshot through the Proxmox API.
  - The API token is stored in the vault, and is restricted to `VM.Snapshot.Rollback` and `VM.PowerMgmt` on that VM only.
  - The command requires an AI grant on the host plus `ai_reset = true` in its host file.
  - Every reset is audited.
  - **As built (2026-10-03), ready for a token:**
    - Admin: `swai reset-setup <label> --api https://<pve>:8006 --node <node> --vmid <id> --snapshot <name>` (or `--off`) writes `ai_reset = true` and `[proxmox]` into the host file (the host must have `ai_allowed`); `swai reset-token <label>` stores `user@realm!tokenid=secret` (no-echo prompt or stdin) at `vault/keys/proxmox/<label>.enc`; `swai reset-ca < /etc/pve/pve-root-ca.pem` pins the Proxmox CA (`config/proxmox/ca.pem`; without it the system roots apply).
    - Token on Proxmox: a role with `VM.Snapshot.Rollback` and `VM.PowerMgmt` only, granted on `/vms/<vmid>` to the token (privilege separation on). Nothing more is called: the rollback asks for `start=1` (older servers without it: rolled back, then `status/start`), and a token may read its own tasks' status.
    - `swai reset <label> [--force]` (AI users with a grant on the host): refuses while swai sessions work on the host unless `--force`; rollback, task polled to `OK`, VM started; then for core-network hosts waits up to PT5M for ssh and logs in with the pinned host keys (a snapshot older than enrollment, with other host keys, is reported and not connected to). Audit `ai.reset` (started, ok or error, duration), `ai.reset_setup`, `ai.reset_token`, `ai.reset_ca`.
    - Tested against a fake Proxmox API (request paths, token header, task polling, failed task, servers without `start`); not yet against a real Proxmox VE, which needs the token.

### 24.6 Inference backends: `swrap-infer`

- **Defined by admins in core's config.** Users pick from this list in the UI but cannot add their own; anything else is unreachable from the container.

```toml
# config/ai.toml
[[backend]]
name = "lab-gpu"
api = "openai"                         # openai | anthropic
base_url = "http://10.0.0.20:8000/v1"
models = ["qwen3-coder"]               # optional allow-list; empty = pass through
# api_key = vault:ai/lab-gpu           # only for commercial APIs; stored in the vault
timeout = "PT10M"
max_concurrent = 4
```

- **As built (2026-10-03): `max_concurrent`.** `swai backend add … --max-concurrent N` / `swai backend set <name> --max-concurrent N` (0 = no limit). Every session's recording proxy takes one of N slots (an `flock` on `/run/swrap/ai-slots/<backend>.<i>`) for the whole request and waits for a free one up to the backend timeout (then 503); a dead worker frees its slot. It is read per request, so a change applies at once.

- **Commands:** `swai backend add|del|list|test <name>` (admin). `test` sends a tiny completion and prints latency, model list and streaming support.
- **Turnstone configuration.** Turnstone is configured with one provider per backend, pointing at `http://swrap-infer/<name>/…`.
  - The API style must be OpenAI-compatible (`/v1/chat/completions`) or Anthropic Messages. `10.0.0.20/chat` must therefore be served as, or fronted by, an OpenAI-compatible endpoint. llama.cpp server, vLLM and Ollama's `/v1` all qualify.
  - `swai backend test` detects a mismatch and says so.
- **What swrap-infer does:**
  - streams requests and responses through unchanged (SSE included);
  - adds the backend's API key server-side, so keys never enter the container;
  - enforces model allow-lists, concurrency and timeouts;
  - **records everything** (24.8).
- **User attribution.** Every inference request is attributed to an AAA user.
  - Primary mechanism: the gate injects a per-user, per-login bearer token or header, if Turnstone forwards per-user provider credentials or headers.
  - Otherwise, records are attributed to the Turnstone workstream and conversation id, if Turnstone exposes one in requests, and linked to the user through the MCP session.
  - As a last resort, records are marked `user: "unattributed"` and correlated by time. The attribution method is written in each record header.

### 24.7 Tools on hosts: `swrap-mcp`

- **Transport and identity.** A Rust MCP server over the streamable HTTP transport. The official Rust MCP SDK (`rmcp`) is suggested.
  - It requires an OAuth bearer token issued by swrap-gate, which carries the AAA user identity and scope `ai.tools`. This uses Turnstone's per-user MCP OAuth support.
  - **Fallback:** one swrap-mcp endpoint per user, with a per-user secret that the gate injects.
- **Tools** (all results use ISO times):

| Tool | Arguments | Behaviour |
|---|---|---|
| `targets` | — | Lists `label`, `ruser`, OS facts for the caller's AI grants |
| `exec` | `target`, `command`, `cwd`?, `env`? (map), `timeout`? (ISO duration, default PT10M, max PT1H), `stdin`? | Runs `bash -lc` on the target as the granted user; returns exit code, stdout/stderr (each capped at 32 KiB head+tail for the model; full output recorded), duration |
| `read_file` | `target`, `path`, `offset`?, `limit`? | Returns content (text or base64), size, mtime, blake3 |
| `write_file` | `target`, `path`, `content`, `mode`?, `mkdirs`? | Atomic write (temp + rename), returns blake3 |
| `list_dir` | `target`, `path`, `depth`? (max 3) | Entries with type, size, mtime |
| `apply_patch` | `target`, `path`, `unified_diff` | Applies with `patch --dry-run` first; returns result |

- **Target selection.** `target` is `"<ruser>@<label>"` or `"<label>"`, resolved against **AI grants only**. The same privilege-ranking rule as `sw` applies, so for `deploy` on `ai-lab` it resolves to `root`.
- **Execution path.** Every call goes to swrapd, which runs it with the normal Stage 1 session machinery: RBAC check, per-session agent, pinned host key and crypto profile.
  - v1 opens one ssh connection per call. This is simple and robust; the extra cost is tens of milliseconds per call.
  - A later optimisation MAY keep one connection per MCP session.
- **Limits:**
  - 4 concurrent calls per user;
  - 600 calls per PT1H per user (configurable);
  - an overall per-conversation call budget, `ai.max_tool_calls`, default 500.

  Hitting a limit returns a clear tool error to the model and writes an `n` record.
- **Secrets.** swrap-mcp never exposes `--secret-env`. The AI cannot request secrets from the AAA shell.

### 24.8 Recording AI sessions

AI sessions get a new record kind `ai` in `rec/<aaa_user>/ai/…`. Each file covers one Turnstone conversation or workstream.

- **Header additions:** `workstream`, `backend`, `model`, `targets`, `attribution` (`header`, `workstream`, `time-correlated`, or `unattributed`), `turnstone_version`.
- **New record types:**

| k | Fields | Meaning |
|---|---|---|
| `m` | `h` (blake3 of canonical message JSON), `role`, `content` | A message body, stored **once** per conversation |
| `q` | `backend`, `model`, `msgs` (list of message hashes), `params` (temperature, max_tokens, tools list hash, …) | An inference request |
| `a` | `h`, `finish_reason`, `usage` (prompt/completion tokens), `latency`, `ttft` (time to first token, ISO durations) | The response. Its message body goes in an `m` record; streamed chunks are assembled before storing |
| `t` | `call_id`, `tool`, `target`, `ruser`, `args` (JSON), `exit`?, `result_bytes`, `duration` | A tool call via swrap-mcp |
| `o` | as Stage 1, plus `call_id`, `fd` | Full tool output |

- **Deduplication is essential.** Every inference request re-sends the whole conversation, so storing full requests would grow quadratically with conversation length. Storing each message once and referencing it by hash keeps it linear.
- **Integrity and lifecycle:** CRC framing, checkpoints and chain, and signing by core's recording key, same as Stage 1. Compression after P7D and disk-watermark eviction also apply unchanged.
- **Transcript export (MAY).** Periodically pull Turnstone's own conversation transcript through its REST API into `n` records for cross-checking. The swrap-side records from swrap-infer and swrap-mcp remain authoritative because swrap produced them.

### 24.9 Search and playback additions (playback GUI on core)

- **Search:**
  - New kind `ai`.
  - New fields: `prompt` (user messages), `reply` (assistant messages), `tool` (tool name), `args` (tool arguments).
  - `cmd` also matches `exec` commands, and `out` also matches tool output.
  - Free text covers all of these.
- **Player.** An `ai` session renders as a chat transcript: messages, tool calls with expandable arguments and results, and exit codes. It shows token usage and latency per turn, with a timeline scrubber in ISO time.
- **Cross-links.** Tool calls on a host link to the corresponding `t`/`o` records. Live following works as in Stage 1.
- **As built (2026-10-03).**
  - Search: `prompt:`, `reply:`, `tool:` and `args:` (each argument as `key=value`); `cmd:` matches `exec` commands, `out:` tool output; free text covers all of them. The search page has the four fields.
  - Player: `ai` recordings open on a **chat** tab (next to the TUI player and the text transcript), built from the records by `swrec::ai::chat` (`/api/rec/<id>/chat`): prompts (Claude Code's `<system-reminder>` blocks folded away as "context the harness added"), replies with thinking (or "not shown by the API"), each tool use with its swrap `t` record (target, exit code, duration; arguments and the result the model saw, expandable; a tool that started while its reply was still streaming is paired too), per turn the tokens (input incl. cache read/write, output), time to first token, latency and stop reason, inference errors, helper requests (titles, compaction) and notes. A scrubber sets an ISO time (UTC, or local with the page's box) and marks the turn at that moment; clicking a turn's time moves it there. A tool call's "terminal at …" switches to the TUI player at that moment. Live sessions refresh every 5 s and follow the end. Opened from a search hit, the chat starts at the hit.

### 24.10 Edge, firewall, CLI

- **Edge.** Relays the AI GUI on `edge.ai_web_port = 8444`, or by SNI `ai.<domain>` on 443 when `web_mode = "sni"`. It uses a separate allow-list:
  ```
  swfw ai allow <ip|cidr> [--for PT8H] [--comment …]
  swfw ai allow --my-ip
  swfw ai revoke <id>
  ```
  Default is deny all. The mechanism is the same as the web allow-list in 13.1–13.2.
- **User commands:**
  ```
  swai login                         # one-time code (PT5M)
  swai logout [--all]
  swai sessions                      # my active AI web sessions and conversations (ISO times)
  swai targets                       # hosts/users the AI may use for me
  swai reset <label>                 # MAY, if ai_reset = true
  ```
- **Admin commands:**
  ```
  swai backend add|del|list|test
  swai grant <aaa_user> <hosts> <remote_users> [--until <ISO>]
  swai revoke-grant <aaa_user> <id>
  swai status                        # gate, container, infer, mcp health; pinned Turnstone version
  ```

### 24.11 Resources

- **Turnstone container.** Plan for about 0.5–1 GiB RAM, depending on version and concurrent workstreams. Measure it in S2.6.
- **swrap-gate, swrap-infer and swrap-mcp** together are well under 100 MiB.
- **Recommended core size with Stage 2:** 4 vCPU and 6–8 GiB RAM. Inference runs on the backend machine, not on core.
- **Storage.** With message deduplication, a long agentic build session is typically a few MB to tens of MB of records, dominated by tool output such as compiler logs. Heavy daily use still fits comfortably within the Stage 1 data disk sizing.
- **Latency.** Tool calls add about one core→host SSH setup each. Inference latency is whatever the backend delivers, plus under 1 ms of proxying.

### 24.12 Stage 2 phases

- **S2.0 Gate check.** All Stage 1 acceptance tests in section 22 pass on the real core+edge deployment.
- **S2.1 Turnstone verification.** Pin a Turnstone version. Verify its OIDC login, per-user MCP OAuth, provider configuration, header forwarding and ability to disable built-in tools. Choose the primary path or the fallback for 24.4, 24.6 and 24.7. Record the results in `docs/stage2-turnstone.md`.
- **S2.2 swrap-infer.** Streaming proxy for OpenAI and Anthropic styles, backend config, vault-held API keys, deduplicated `m`/`q`/`a` recording, `swai backend`.
- **S2.3 swrap-mcp.** Tools, AI grants, `ai_allowed`, limits, `t`/`o` recording.
- **S2.4 swrap-gate.** One-time codes, OIDC provider (or the proxy fallback), session handling, `swai login|logout|sessions`.
- **S2.5 Deployment.** Rootless podman container with internal-only networking, edge relay port or SNI, `swfw ai`, `swai reset` (MAY).
- **S2.6 Playback and search additions, then benchmarks and the README.** The README covers the test-VM isolation guide.

### 24.13 Stage 2 open decisions (defaults in bold)

1. **Primary vs. fallback auth, attribution and MCP identity paths.** **Decided in S2.1 from the pinned Turnstone's actual capabilities.**
2. **Commercial inference APIs** (Anthropic, OpenAI, Gemini) alongside local ones. **Allowed, with keys only in the vault and only through swrap-infer.**
3. **Turnstone's judge / tool approval.** **On for `exec`, `write_file` and `apply_patch` at first**; relax it once you trust the setup. *As built, budget and handoff:* a session may make `max_tool_calls` tool calls (500). When `handoff_warn` (25) or fewer are left, every tool result says so; once they are gone a tool call returns an error saying the same. The AI then calls `handoff` (costs no budget) with a briefing: swrapd starts a successor for the same user, host, account, backend, model, effort and permissions, with a fresh budget and a fresh conversation whose first prompt is the briefing plus a digest of the last 40 tool calls. The successor runs detached; a terminal attached to the old session follows it (the old one ends with reason `handoff <id>`). Recordings are linked (`continues`, `chain` in the header; audit `ai.handoff`); at most `max_handoffs` (10) in a row, and `calls_per_hour` still applies. Unattended for real only with `--loose` (otherwise the successor waits at its first permission prompt). `swai limits [<key> <value>]` (admin) shows and sets the limits. *As built:* `swai approval ask|allow` (admin, all new sessions); and per session, for **one host only**, the sixth question "permissions" or `swai --loose`: no permission prompts at all (Claude Code runs with `--dangerously-skip-permissions`, so no auto-mode classifier either; opencode allows every tool). The sandbox keeps Claude Code's built-in tools off, so it still acts only on that host through swrap's tools, under the AI grant, recorded; the session header, the audit event (`ai.start`, `loose`), the banner and the session name say so. Refused for the whole AAA. Meant for throwaway VMs.
4. **AI GUI access for admins.** **No.**
5. **Proxmox snapshot reset.** **Implemented only if you provide a scoped API token.**
6. **Persistent per-session SSH connection for tools.** **Not initially.**

### 24.14 Stage 2 acceptance tests (MUST pass)

- **Login:**
  - Without a valid code there is no access at all: no Turnstone page, API or asset is reachable.
  - A code works exactly once, within PT5M, and only for the user it was issued to.
  - Admins are refused.
  - Every attempt is audited.
- **Isolation:**
  - From inside the container, any address other than swrap-infer and swrap-mcp is unreachable. That includes the inference backend directly, the LAN, the internet, and core's sshd.
  - Adding a custom model URL or MCP server in the Turnstone UI fails.
- **Grants:**
  - With only the `ai-lab` root AI grant, the AI cannot touch any other host, even ones `deploy` can reach as a human.
  - A host without `ai_allowed = true` never matches, even with a wildcard grant.
- **Recording:**
  - A full "build me a rust based app" run on `ai-lab` produces one `ai` record containing every inference request/response (deduplicated) and every tool call with full output.
  - `swrec verify` passes on it.
  - Search on `prompt:`, `reply:`, `tool:` and `cmd:` finds it, and the player shows the transcript.
- **Deduplication:** record size grows linearly, not quadratically, with conversation length. Verify with a synthetic 200-turn conversation.
- **Secrets:** backend API keys never appear inside the container, in Turnstone's database, or in any record.
- **Limits:** exceeding call rates or budgets returns tool errors and writes `n` records. It never crashes the session.
- **Sealed vault:** the AI GUI and tools are unavailable while sealed and come back after unseal.
