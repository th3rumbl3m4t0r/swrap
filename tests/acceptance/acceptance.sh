#!/bin/bash
# swrap acceptance tests (spec 22, 24.14). Run on core as root.
#
#   acceptance.sh                 the safe tests (read-only, or create and remove their own test
#                                 data on SWRAP_TEST_HOST); production keeps running
#   acceptance.sh --list          every test with its class
#   acceptance.sh <name>...       only these
#   destructive tests (VM resets, disk fill, link cuts, load) run only when named, with
#   SWRAP_ACCEPT_DESTRUCTIVE=yes and their target variables set; never on production by default.
#
# Settings (environment):
#   SWRAP_TEST_USER   AAA user (non-admin) the tests act as (default: claude)
#   SWRAP_TEST_HOST   a host that user may use as root, for tests that create and remove an
#                     account or files (default: test1)
#   SWRAP_EDGE        the edge label (default: edge)
#   SWRAP_EDGE_HOST   a host granted from edge for that user (default: web1)
#   SWRAP_VM          (destructive) a scratch core VM's Proxmox id for hard resets
# Results: one line per test (PASS/FAIL/SKIP), details in $OUT (default: a temp dir).
set -uo pipefail
U=${SWRAP_TEST_USER:-claude}
H=${SWRAP_TEST_HOST:-test1}
EDGE=${SWRAP_EDGE:-edge}
EH=${SWRAP_EDGE_HOST:-web1}
OUT=${OUT:-$(mktemp -d /var/tmp/swrap-accept.XXXXXX)}
chmod 755 "$OUT"
PASS=0 FAIL=0 SKIP=0
ISO_Z='[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})'

as_user() { su - "$U" -c "$1"; }
# A script run on a host as the test user (swr uploads it).
on_host() { local f="/home/$U/.accept-$RANDOM.sh"; printf '%s\n' "$2" > "$f"; chown "$U": "$f"; as_user "swr $f $1" 2>&1; rm -f "$f"; }
ok()   { echo "PASS  $T"; PASS=$((PASS+1)); }
bad()  { echo "FAIL  $T: $*"; echo "$T: $*" >> "$OUT/failures"; FAIL=$((FAIL+1)); }
skip() { echo "SKIP  $T: $*"; SKIP=$((SKIP+1)); }

# ---------------------------------------------------------------- safe tests

t_iso_cli() { # every timestamp in CLI output is ISO 8601; "7d" is refused
    local o="$OUT/cli.txt"
    { as_user "swls"; swrap status; as_user "swai ls"; as_user "swlog --since PT6H"; as_user "swinv"; } > "$o" 2>&1
    # Date-looking tokens that are not ISO (e.g. "Oct 3", "03/10/2026", "2026-10-03 18:00").
    if grep -nE '\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ 0-9]?[0-9]\b|\b[0-9]{2}/[0-9]{2}/[0-9]{4}\b|[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}' "$o" > "$OUT/cli-nonISO.txt"; then
        bad "non-ISO times in CLI output (see $OUT/cli-nonISO.txt)"; return
    fi
    grep -qE "$ISO_Z" "$o" || { bad "no timestamps found at all"; return; }
    if as_user "swlog --since 7d" > "$OUT/since7d.txt" 2>&1; then bad "swlog --since 7d was accepted"; return; fi
    ok
}

t_utc_z() { # the default display is UTC with Z, never +00:00
    local o; o=$(as_user "swlog --since P1D" 2>&1; swrap status 2>&1)
    if echo "$o" | grep -qE 'T[0-9:.]+\+00:00'; then bad "+00:00 instead of Z"; else ok; fi
}

t_fuzz() { # the reader never panics on damaged files (plain and gzip)
    local n=${FUZZ_N:-2000}
    if swrec fuzz --help 2>&1 | grep -q -- '--count'; then
        swrec fuzz --count "$n" > "$OUT/fuzz.txt" 2>&1 && ok || bad "swrec fuzz failed (see $OUT/fuzz.txt)"
    else
        swrec fuzz > "$OUT/fuzz.txt" 2>&1 && ok || bad "swrec fuzz failed (see $OUT/fuzz.txt)"
    fi
}

t_verify_edge_records() { # core verifies edge-produced recordings (signed by edge's key)
    local f; f=$(grep -l '"exec":"edge"' $(ls -t /var/lib/swrap/rec/*/sw/*/*/*/*.swrec 2>/dev/null | head -200) 2>/dev/null | head -3)
    [ -n "$f" ] || { skip "no edge-run sw recording in the newest 200"; return; }
    swrec verify $f > "$OUT/verify-edge.txt" 2>&1 && ok || bad "swrec verify failed (see $OUT/verify-edge.txt)"
}

t_shell_no_keys() { # shell recordings carry no keystrokes (i records)
    local n=0 f
    for f in $(ls -t /var/lib/swrap/rec/*/shell/*/*/*/*.swrec 2>/dev/null | head -50); do
        grep -q '"k":"i"' "$f" && n=$((n+1))
    done
    [ "$n" = 0 ] && ok || bad "$n shell recordings contain i records"
}

t_secret_env() { # a --secret-env value is redacted from output and recording
    local v="s3cr3t-$RANDOM$RANDOM" f="/home/$U/.accept-secret.sh" o
    printf 'echo "value is $ACCEPT_SECRET"\n' > "$f"; chown "$U": "$f"
    o=$(su - "$U" -c "ACCEPT_SECRET=$v swr --secret-env ACCEPT_SECRET $f $H" 2>&1); rm -f "$f"
    echo "$o" > "$OUT/secret-env.txt"
    if echo "$o" | grep -q "$v"; then bad "the value shows in the output"; return; fi
    local run; run=$(echo "$o" | grep -oE 'run [0-9A-Z]{26}' | tail -1 | cut -d' ' -f2)
    if [ -n "$run" ] && grep -rqs "$v" /var/lib/swrap/runs/*/"$run"* /var/lib/swrap/rec/"$U"/run 2>/dev/null; then bad "the value is in the recording"; return; fi
    ok
}

t_search_fields() { # each field matches only its own stream; free text matches all
    local tok="acc$RANDOM$RANDOM" f
    # A fleet run: the script's name is its `cmd`, what it prints its `out`; no keystrokes.
    f="/home/$U/$tok.sh"; printf 'echo %s-out\n' "$tok" > "$f"; chown "$U": "$f"
    as_user "swr $f $H" > /dev/null 2>&1; rm -f "$f"
    sleep 2
    local q="swsearch 'window:PT15M/now" c o k x
    c=$(as_user "$q cmd:$tok'" 2>&1 | tee "$OUT/search-cmd.txt" | grep -c "$tok")
    o=$(as_user "$q out:$tok-out'" 2>&1 | tee "$OUT/search-out.txt" | grep -c "$tok")
    k=$(as_user "$q keys:$tok'" 2>&1 | grep -c "$tok")
    x=$(as_user "$q $tok'" 2>&1 | grep -c "$tok")
    echo "cmd=$c out=$o keys=$k free=$x" > "$OUT/search.txt"
    [ "$c" -ge 1 ] && [ "$o" -ge 1 ] && [ "$k" = 0 ] && [ "$x" -ge 2 ] && ok || bad "cmd=$c out=$o keys=$k free=$x (want ≥1, ≥1, 0, ≥2)"
}

t_sudoers_drift() { # swuser add --sudo gives NOPASSWD sudo; a manual edit is drift
    local u="acc$RANDOM" o
    o=$(swuser add "$H" "$u" --sudo 2>&1) || { bad "swuser add: $o"; return; }
    echo "$o" > "$OUT/swuser.txt"
    echo "$o" | grep -q 'NOPASSWD sudo' || { bad "no sudo in: $o"; swuser del "$H" "$u" >/dev/null 2>&1; return; }
    on_host "$H" "echo '# manual edit' >> /etc/sudoers.d/swrap-$u" > /dev/null
    swinv "$H" > /dev/null 2>&1
    local d; d=$(grep -h sudoers_drift -A3 /var/lib/swrap/state/hosts/"$H"/facts.toml 2>/dev/null | tr '\n' ' ')
    swuser del "$H" "$u" > /dev/null 2>&1
    echo "$d" | grep -q "modified /etc/sudoers.d/swrap-$u" && ok || bad "drift not reported: $d"
}

t_sftp() { # granted entries only, no escape from the prefix, f records
    local b="$OUT/sftp.batch"
    printf 'ls\ncd ..\npwd\ncd /../../..\npwd\nls /etc\n' > "$b"; chmod 644 "$b"
    local o; o=$(as_user "timeout 60 sftp -D /usr/libexec/swrap/sftp-dispatch -b $b" 2>&1)
    echo "$o" > "$OUT/sftp.txt"
    echo "$o" | grep -A1 --no-group-separator '^sftp> pwd' | grep -v '^sftp>' | grep -qv '^Remote working directory: /$' && { bad "escaped the root: $o"; return; }
    echo "$o" | grep -q 'ls /etc' && echo "$o" | grep -A1 'ls /etc' | grep -qi 'passwd' && { bad "real /etc visible"; return; }
    local f; f=$(ls -t /var/lib/swrap/rec/"$U"/sftp/*/*/*/*.swrec | head -1)
    grep -q '"k":"f"' "$f" && ok || bad "no f records in $f"
}

t_edge_no_keys() { # edge holds no private key for managed hosts
    local o; o=$(on_host "$EDGE" 'grep -rlE "BEGIN (OPENSSH|RSA|EC) PRIVATE KEY" /var/lib/swrap-edge /run/swrap-edge /var/tmp /tmp /home 2>/dev/null | grep -v "/recsign/"; for p in /proc/[0-9]*; do grep -lsE "id_|\\.enc$" $p/maps 2>/dev/null; done; echo END')
    echo "$o" > "$OUT/edge-keys.txt"
    echo "$o" | grep -vE '^\S+ \| END$|^$' | grep -q '|' && bad "possible key material: $(echo "$o" | head -3)" || ok
}

t_stalwart_ports() { # only table inet swrap is swrap's; mail ports reachable
    local o; o=$(on_host "$EDGE" 'nft list tables')
    echo "$o" > "$OUT/edge-nft.txt"
    local p fails="" a
    a=$(sed -n 's/^address = "\(.*\)"/\1/p' /var/lib/swrap/config/hosts/"$EDGE".toml)
    for p in 25 465 587 993; do timeout 5 bash -c "</dev/tcp/$a/$p" 2>/dev/null || fails="$fails $p"; done
    [ -z "$fails" ] || { bad "mail ports not reachable from core:$fails"; return; }
    echo "$o" | grep -q 'table inet swrap' && ok || bad "no inet swrap table: $o"
}

t_edge_sftp() { # SFTP from an edge login: delegated, edge grants only
    local o; o=$(on_host "$EDGE" "printf 'ls\n' > /tmp/acc.b; chmod 644 /tmp/acc.b; su - $U -s /bin/bash -c 'timeout 60 sftp -D /usr/libexec/swrap/sftp-dispatch -b /tmp/acc.b'; rm -f /tmp/acc.b")
    echo "$o" > "$OUT/edge-sftp.txt"
    echo "$o" | grep -q "$EH" && ok || bad "no $EH entry from edge: $o"
}

t_recorder_speed() { # recorder ≥ 100 MB/s per core (spec 19, 22)
    # CPU-bound (tmpfs); the default directory measures the data disk's flush latency instead.
    local o; o=$(swrec bench --dir /dev/shm --mib 256 2>&1); echo "$o" > "$OUT/bench.txt"
    local mbs; mbs=$(echo "$o" | grep -oE '[0-9]+(\.[0-9]+)? MB/s' | head -1 | cut -d' ' -f1)
    [ -n "$mbs" ] || { skip "no MB/s figure in swrec bench output"; return; }
    awk -v m="$mbs" 'BEGIN{exit !(m >= 100)}' && ok || bad "$mbs MB/s"
}

t_vault_sealed_refusal() { # sw is refused while sealed — checked by message only when sealed
    if swrap status 2>&1 | grep -qi 'sealed'; then
        as_user "sw $H true" > "$OUT/sealed.txt" 2>&1 && bad "sw worked while sealed" || ok
    else
        skip "vault unsealed (run after a reboot, before an admin login)"
    fi
}

# ---------------------------------------------------------------- destructive (named only)

need_destructive() { [ "${SWRAP_ACCEPT_DESTRUCTIVE:-}" = yes ] || { skip "destructive: set SWRAP_ACCEPT_DESTRUCTIVE=yes on a test setup"; return 1; }; }

d_kill_worker() { # kill -9 a session worker mid-session: the file stays readable, damage local
    need_destructive || return
    local pid; pid=$(pgrep -f 'swrapd worker' | head -1)
    [ -n "$pid" ] || { skip "no running worker"; return; }
    kill -9 "$pid"; sleep 2
    local f; f=$(ls -t /var/lib/swrap/rec/*/sw/*/*/*/*.swrec | head -1)
    swrec verify "$f" > "$OUT/killed.txt" 2>&1; grep -qiE 'panic' "$OUT/killed.txt" && bad "reader panicked" || ok
}

d_disk_fill() { # fill /var/lib/swrap to 91 % with swrap-like data: eviction to < 90 %, live untouched
    need_destructive || return
    echo "procedure: on a scratch core only. fallocate files under /var/lib/swrap/rec/<user>/sw/<old date>/ until df shows 91 %,"
    echo "wait for the retention run, check df < 90 %, oldest gone, live sessions intact; then fill with non-swrap data"
    echo "(e.g. /var/lib/swrap/../junk on the same filesystem) and check eviction stops and an alert is raised."
    skip "manual procedure printed"
}

d_link_cut() { # cut the link mid-session: spool grows, byte-identical after reconnect, refusals
    need_destructive || return
    echo "procedure: start an edge-run sw session producing output (e.g. 'while :; do date; sleep 1; done');"
    echo "on core: systemctl kill -s STOP the swrap-link ssh (or nft drop to $EDGE:22 from core) for PT2M;"
    echo "check on edge: /var/lib/swrap-edge/spool grows; new sw on edge is refused; delegated sessions end link_lost;"
    echo "restore; check core's file == edge spool (cmp) and the spool file is deleted."
    skip "manual procedure printed"
}

d_vm_resets() { # 20 hard resets under load: records intact (scratch VM only)
    need_destructive || return
    [ -n "${SWRAP_VM:-}" ] || { skip "set SWRAP_VM to a scratch core VM id"; return; }
    echo "procedure: on the Proxmox host: for i in \$(seq 20); do qm reset $SWRAP_VM; sleep 120; done while sessions"
    echo "produce output; afterwards swrec verify every file and swrap doctor --scrub."
    skip "manual procedure printed"
}

d_edge_load() { # 20 concurrent edge sessions fit in MemoryMax=512M
    need_destructive || return
    echo "procedure: 20 x 'ssh -tt $U@$EDGE sw $EH \"yes | head -c 50M; sleep 60\"' in parallel;"
    echo "watch systemctl show swrap.slice -p MemoryCurrent on edge; it must stay below MemoryMax."
    skip "manual procedure printed"
}

SAFE=(t_iso_cli t_utc_z t_fuzz t_verify_edge_records t_shell_no_keys t_secret_env t_search_fields t_sudoers_drift t_sftp t_edge_no_keys t_stalwart_ports t_edge_sftp t_recorder_speed t_vault_sealed_refusal)
DESTRUCTIVE=(d_kill_worker d_disk_fill d_link_cut d_vm_resets d_edge_load)

if [ "${1:-}" = "--list" ]; then
    for t in "${SAFE[@]}"; do echo "safe         $t  $(grep -m1 "^$t()" "$0" | sed 's/.*# //')"; done
    for t in "${DESTRUCTIVE[@]}"; do echo "destructive  $t  $(grep -m1 "^$t()" "$0" | sed 's/.*# //')"; done
    exit 0
fi
[ "$(id -u)" = 0 ] || { echo "run as root on core"; exit 2; }
tests=("$@"); [ ${#tests[@]} -gt 0 ] || tests=("${SAFE[@]}")
echo "swrap acceptance $(date -u +%Y-%m-%dT%H:%M:%SZ) · user $U · host $H · edge $EDGE · details in $OUT"
for T in "${tests[@]}"; do
    declare -F "$T" > /dev/null || { echo "unknown test $T (--list)"; exit 2; }
    "$T"
done
echo "$PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" = 0 ]
