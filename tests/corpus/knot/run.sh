#!/usr/bin/env bash
# Knot DNS and Unbound tool-level interop (tests/corpus/README.md, "Knot
# DNS and Unbound"). Made for the GitHub Actions runner of
# .github/workflows/interop.yml: it runs knotd on 127.0.0.1:5301 and unbound
# on 127.0.0.1:5335, so do not run it on a workstation.
#
#   run.sh sign OUT          sign the zones with keymgr and kzonesign, and
#                            check Knot's output with kzonecheck,
#                            ldns-verify-zone and dnssec-verify
#   run.sh serve OUT         start knotd, unbound and the recording proxies
#                            (127.0.0.1:5300 -> knotd, :5400 -> unbound)
#   run.sh capture OUT       query both through the proxies with kdig and
#                            knsupdate
#   run.sh stop OUT          stop everything
#   run.sh check-dnsbox OUT  run kzonecheck, ldns-verify-zone and
#                            dnssec-verify on the zones dnsbox wrote into
#                            OUT/dnsbox (DNSBOX_INTEROP_WRITE=1 cargo test
#                            --test interop_knot)
#
# OUT receives everything tests/interop_knot.rs reads (point
# DNSBOX_INTEROP_DIR at it):
#
#   versions.txt, now        tool versions; the time of the run (seconds)
#   zones/<zone>.zone        Knot-signed zones (kzonesign), and the
#                            unsigned ones knotd serves
#   keys/<zone>/             keymgr's key list and the private keys (PEM)
#   ds/<zone>.ds             keymgr's DS records of the KSK
#   manifest.txt             zone, algorithm, denial chain
#   alltypes-omitted.txt     the records of ../bind9/alltypes.dnsbox Knot
#                            cannot read (zones/alltypes.example.zone has
#                            the others)
#   knot/<label>/            exchanges with knotd: NN-<udp|tcp>-<q|r>.hex
#                            (proxy.py) and kdig's output (kdig.txt)
#   unbound/<case>/<step>/   exchanges with unbound, likewise;
#                            unbound/cases.txt lists the cases
#   checks/                  logs of the zone checkers
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
CMD=${1:?usage: run.sh sign|serve|capture|stop|check-dnsbox OUT}
OUT=${2:?usage: run.sh $CMD OUT}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
WORK=${DNSBOX_INTEROP_WORK:-${RUNNER_TEMP:-/tmp}/dnsbox-interop-work}
mkdir -p "$WORK"

# The TSIG secret of every key: the bytes 00 01 .. 1f (as in
# tests/tsig_named.rs).
SECRET=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
HMACS="md5 sha1 sha224 sha256 sha384 sha512"
# name:number:Knot's name for it
ALGS="rsasha256:8:rsasha256 rsasha512:10:rsasha512 ecdsap256:13:ecdsap256sha256
ecdsap384:14:ecdsap384sha384 ed25519:15:ed25519 ed448:16:ed448"
CHAINS="nsec nsec3 optout"
# Zones signed with a deliberate defect after signing (bogus answers).
BOGUS="bogus bogus-nsec bogus-ds"
SERIAL=2026100401

children() {
    for spec in $ALGS; do
        for chain in $CHAINS; do
            echo "${spec%%:*}-$chain.interop."
        done
    done
}

log() { printf '\n=== %s\n' "$*"; }

# ---------------------------------------------------------------------
# sign
# ---------------------------------------------------------------------

policy() { # id knot-algorithm chain
    local id=$1 alg=$2 chain=$3
    cat <<EOF
  - id: $id
    keystore: pem
    algorithm: $alg
    manual: on
    dnskey-ttl: 3600
    zone-max-ttl: 3600
    rrsig-lifetime: 3650d
    rrsig-refresh: 30d
EOF
    case $alg in
    rsa*) printf '    ksk-size: 2048\n    zsk-size: 1024\n' ;;
    esac
    case $chain in
    nsec) printf '    nsec3: off\n    cds-cdnskey-publish: none\n' ;;
    nsec3)
        printf '    nsec3: on\n    nsec3-opt-out: off\n    nsec3-iterations: 5\n'
        printf '    cds-cdnskey-publish: always\n'
        ;;
    optout)
        printf '    nsec3: on\n    nsec3-opt-out: on\n    nsec3-iterations: 0\n'
        printf '    nsec3-salt-length: 0\n    cds-cdnskey-publish: none\n'
        ;;
    esac
}

sign_conf() {
    cat <<EOF
server:
    rundir: "$WORK/sign-run"
database:
    storage: "$WORK/sign-db"
keystore:
  - id: pem
    backend: pem
    config: "$WORK/sign-keys"
policy:
EOF
    for spec in $ALGS; do
        local name=${spec%%:*} kalg=${spec##*:}
        for chain in $CHAINS; do
            policy "$name-$chain" "$kalg" "$chain"
        done
    done
    cat <<EOF
template:
  - id: default
    storage: "$WORK/in"
    file: "%s.zone"
    dnssec-signing: on
    zonefile-load: whole
    journal-content: none
zone:
EOF
    for z in $(children); do
        printf '  - domain: %s\n    dnssec-policy: %s\n' "$z" "${z%%.*}"
        case $z in
        *-nsec3.*) printf '    zonemd-generate: zonemd-sha384\n' ;;
        *-optout.*) printf '    zonemd-generate: zonemd-sha512\n' ;;
        esac
    done
    printf '  - domain: bogus.interop.\n    dnssec-policy: ecdsap256-nsec\n'
    printf '  - domain: bogus-nsec.interop.\n    dnssec-policy: ecdsap384-nsec\n'
    printf '  - domain: bogus-ds.interop.\n    dnssec-policy: ed25519-nsec\n'
    printf '  - domain: interop.\n    dnssec-policy: ecdsap256-nsec\n'
}

# Generates the keys of zone $1 (algorithm number $2) with keymgr, signs
# the zone with kzonesign and collects keys and DS records.
sign_zone() {
    local zone=$1 algnum=$2 conf=$WORK/sign.conf
    local size_ksk="" size_zsk=""
    case $algnum in 8 | 10) size_ksk=size=2048 size_zsk=size=1024 ;; esac
    log "keymgr + kzonesign: $zone"
    keymgr -c "$conf" "$zone" generate algorithm="$algnum" ksk=yes zsk=no $size_ksk
    keymgr -c "$conf" "$zone" generate algorithm="$algnum" ksk=no zsk=yes $size_zsk
    local keys="$OUT/keys/${zone%.}"
    mkdir -p "$keys"
    keymgr -c "$conf" "$zone" list | tee "$keys/list.txt"
    for id in $(awk '{print $1}' "$keys/list.txt"); do
        cp "$WORK/sign-keys/$id.pem" "$keys/" || true
    done
    keymgr -c "$conf" "$zone" ds | tee "$OUT/ds/${zone%.}.ds"
    kzonesign -c "$conf" -o "$OUT/zones" "$zone"
    local signed="$OUT/zones/${zone%.}.zone"
    test -s "$signed" || { ls -l "$OUT/zones"; exit 1; }
}

# Breaks zone file $1 after signing: python3 script $2 (gets the records as
# owner, ttl, type, rdata; returns the new rdata).
tamper() {
    python3 - "$1" "$2" <<'EOF'
import sys
path, rule = sys.argv[1], sys.argv[2]
out, owner, changed = [], None, 0
for line in open(path):
    body = line.rstrip("\n")
    if not body.strip() or body.lstrip().startswith(";") or body.startswith("$"):
        out.append(line)
        continue
    toks = body.split()
    if not body[0].isspace():
        owner = toks.pop(0)
    # [TTL] [CLASS] TYPE RDATA (Knot writes TTL TYPE RDATA)
    i = 0
    while toks[i].isdigit() or toks[i] in ("IN", "CH"):
        i += 1
    rtype, rdata = toks[i], " ".join(toks[i + 1:])
    new = rdata
    if rule == "rdata" and owner.startswith("www.") and rtype == "A":
        new = "192.0.2.66"
    if rule == "nsec" and rtype == "NSEC":
        new = rdata + " SPF"
    if new != rdata:
        changed += 1
        line = "%s %s %s\n" % (owner, " ".join(toks[:i + 1]), new)
    out.append(line)
assert changed, "nothing tampered in " + path
open(path, "w").writelines(out)
print("tampered %d records in %s" % (changed, path))
EOF
}

cmd_sign() {
    rm -rf "$WORK/in" "$WORK/sign-db" "$WORK/sign-keys" "$WORK/sign-run"
    mkdir -p "$WORK/in" "$WORK/sign-db" "$WORK/sign-keys" "$WORK/sign-run" \
        "$OUT/zones" "$OUT/keys" "$OUT/ds" "$OUT/checks"
    {
        echo "# Tool versions of this run"
        knotd --version 2>&1 | head -n1 || true
        kdig --version 2>&1 | head -n1 || true
        keymgr --version 2>&1 | head -n1 || true
        kzonesign --version 2>&1 | head -n1 || true
        kzonecheck --version 2>&1 | head -n1 || true
        knsupdate --version 2>&1 | head -n1 || true
        unbound -V 2>&1 | head -n1 || true
        ldns-verify-zone -v 2>&1 | head -n1 || true
        dig -v 2>&1 | head -n1 || true
        uname -sr
    } | tee "$OUT/versions.txt"
    mkdir -p "$OUT/help"
    for t in kzonesign kzonecheck keymgr kdig knsupdate; do
        "$t" --help >"$OUT/help/$t.txt" 2>&1 || true
    done

    sign_conf >"$WORK/sign.conf"
    cat "$WORK/sign.conf"
    : >"$OUT/manifest.txt"
    for spec in $ALGS; do
        local name=${spec%%:*} rest=${spec#*:}
        local num=${rest%%:*}
        for chain in $CHAINS; do
            local zone="$name-$chain.interop."
            sed -e "1i \$ORIGIN $zone" "$HERE/child.zone" >"$WORK/in/${zone%.}.zone"
            sign_zone "$zone" "$num"
            echo "$zone $name $chain" >>"$OUT/manifest.txt"
        done
    done
    # The bogus zones: signed, then broken.
    for b in $BOGUS; do
        sed -e "1i \$ORIGIN $b.interop." "$HERE/child.zone" >"$WORK/in/$b.interop.zone"
    done
    sign_zone bogus.interop. 13
    tamper "$OUT/zones/bogus.interop.zone" rdata
    sign_zone bogus-nsec.interop. 14
    tamper "$OUT/zones/bogus-nsec.interop.zone" nsec
    sign_zone bogus-ds.interop. 15
    echo "bogus.interop. ecdsap256 nsec bogus-rdata" >>"$OUT/manifest.txt"
    echo "bogus-nsec.interop. ecdsap384 nsec bogus-nsec" >>"$OUT/manifest.txt"
    echo "bogus-ds.interop. ed25519 nsec bogus-ds" >>"$OUT/manifest.txt"

    # The parent: delegations with glue, DS records for the signed children
    # (a wrong one for bogus-ds), none for the unsigned ones.
    {
        echo "\$ORIGIN interop."
        echo "\$TTL 3600"
        echo "@ SOA ns hostmaster $SERIAL 7200 3600 1209600 300"
        echo "  NS ns"
        echo "ns A 127.0.0.1"
        echo "www A 192.0.2.80"
        for z in $(children) bogus.interop. bogus-nsec.interop. bogus-ds.interop. \
            insecure.interop. dyn.interop. bulk.interop.; do
            local l=${z%.interop.}
            echo "$l NS ns1.$l"
            echo "ns1.$l A 127.0.0.1"
        done
        for z in $(children) bogus.interop. bogus-nsec.interop.; do
            grep -v '^;' "$OUT/ds/${z%.}.ds" || true
        done
        # bogus-ds: the DS digests with their last hex digit changed.
        grep -v '^;' "$OUT/ds/bogus-ds.interop.ds" |
            sed -e 's/0$/X/;s/[1-9A-Fa-f]$/0/;s/X$/1/'
    } >"$WORK/in/interop.zone"
    cat "$WORK/in/interop.zone"
    sign_zone interop. 13
    echo "interop. ecdsap256 nsec parent" >>"$OUT/manifest.txt"
    cp "$OUT/ds/interop.ds" "$OUT/anchor.ds"

    # The unsigned zones knotd serves next to them.
    for z in $(children); do
        printf '$ORIGIN unsigned.%s\n$TTL 3600\n@ SOA ns hostmaster %s 7200 3600 1209600 300\n  NS ns\nns A 127.0.0.1\nwww A 192.0.2.80\n' \
            "$z" "$SERIAL" >"$OUT/zones/unsigned.${z%.}.zone"
    done
    printf '$ORIGIN insecure.interop.\n$TTL 3600\n@ SOA ns1 hostmaster %s 7200 3600 1209600 300\n  NS ns1\nns1 A 127.0.0.1\nwww A 192.0.2.80\n' \
        "$SERIAL" >"$OUT/zones/insecure.interop.zone"
    printf '$ORIGIN dyn.interop.\n$TTL 3600\n@ SOA ns1 hostmaster %s 7200 3600 1209600 300\n  NS ns1\nns1 A 127.0.0.1\nwww A 192.0.2.80\nold A 192.0.2.99\nt000 TXT "to be deleted"\nt001 TXT "to be deleted"\n' \
        "$SERIAL" >"$OUT/zones/dyn.interop.zone"
    # A zone big enough for a multi-message transfer.
    {
        printf '$ORIGIN bulk.interop.\n$TTL 3600\n@ SOA ns1 hostmaster %s 7200 3600 1209600 300\n  NS ns1\nns1 A 127.0.0.1\n' "$SERIAL"
        for i in $(seq 1 250); do
            printf 'h%04d A 192.0.%d.%d\nh%04d TXT "record %d of the bulk zone, padded to make the transfer span several messages"\n' \
                "$i" $((i / 256)) $((i % 256)) "$i" "$i"
        done
    } >"$OUT/zones/bulk.interop.zone"
    date +%s >"$OUT/now"

    log "Knot, ldns and BIND check Knot's zones"
    local rc=0
    for z in $(children) interop.; do
        check_zone "$z" "$OUT/zones/${z%.}.zone" "knot-${z%.}" || rc=1
    done
    # dnsbox's presentation of every type BIND reads, for knotd to serve:
    # minus the records Knot cannot read (types it does not know), which
    # go to alltypes-omitted.txt.
    kzonecheck -v -o alltypes.example. "$HERE/../bind9/alltypes.dnsbox" \
        >"$OUT/checks/alltypes.dnsbox.kzonecheck" 2>&1 || true
    python3 - "$HERE/../bind9/alltypes.dnsbox" "$OUT/checks/alltypes.dnsbox.kzonecheck" \
        "$OUT/zones/alltypes.example.zone" "$OUT/alltypes-omitted.txt" <<'PY'
import re, sys
src, log, out, omitted = sys.argv[1:]
bad = {int(m) for m in re.findall(r"line (\d+) \(", open(log).read())}
lines = open(src).readlines()
open(out, "w").writelines(l for i, l in enumerate(lines, 1) if i not in bad)
open(omitted, "w").writelines(l for i, l in enumerate(lines, 1) if i in bad)
print("alltypes: %d of %d lines omitted for Knot" % (len(bad), len(lines)))
PY
    kzonecheck -o alltypes.example. "$OUT/zones/alltypes.example.zone" || rc=1
    ls -l "$OUT/zones"
    return $rc
}

# Checks signed zone $1 in file $2 with kzonecheck, ldns-verify-zone and
# dnssec-verify; logs in OUT/checks/$3.*. Fails if any rejects it.
check_zone() {
    local zone=$1 file=$2 tag=$3 rc=0
    # With ZONEMD (RFC 8976), Knot checks it too.
    local z=""
    if grep -q "ZONEMD" "$file"; then z=-z; fi
    timeout 120 kzonecheck -v -d on $z -o "$zone" "$file" >"$OUT/checks/$tag.kzonecheck" 2>&1 || rc=1
    if [ -z "$z" ]; then
        timeout 120 ldns-verify-zone -V 3 "$file" >"$OUT/checks/$tag.ldns" 2>&1 || rc=1
    else
        # ldns 1.8.3 never returns on some of the zones with a ZONEMD
        # record (Knot and dnsbox agree on their digests): it checks the
        # zone without it, and the ZONEMD alone for the record.
        awk '!($3 == "ZONEMD" || $4 == "ZONEMD" || ($4 == "RRSIG" && $5 == "ZONEMD"))' "$file" >"$WORK/$tag.no-zonemd"
        timeout 120 ldns-verify-zone -V 3 "$WORK/$tag.no-zonemd" >"$OUT/checks/$tag.ldns" 2>&1 || rc=1
        if timeout 20 ldns-verify-zone -Z "$file" >"$OUT/checks/$tag.ldns-zonemd" 2>&1; then
            echo "  ldns-verify-zone -Z: ok"
        else
            echo "  ldns-verify-zone -Z: exit $? (124: no answer in 20 s)"
        fi
    fi
    timeout 120 dnssec-verify -o "$zone" "$file" >"$OUT/checks/$tag.dnssec-verify" 2>&1 || rc=1
    if [ $rc != 0 ]; then
        echo "FAILED: $tag"
        tail -n 20 "$OUT/checks/$tag".*
        return 1
    fi
    echo "ok: $tag"
}

# ---------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------

serve_conf() {
    cat <<EOF
server:
    rundir: "$WORK/serve-run"
    listen: 127.0.0.1@5301
    nsid: dnsbox-interop
    identity: knotd.dnsbox-interop
    edns-client-subnet: on
log:
  - target: "$OUT/knotd.log"
    any: info
database:
    storage: "$WORK/serve-db"
key:
EOF
    for h in $HMACS; do
        printf '  - id: hmac-%s.key\n    algorithm: hmac-%s\n    secret: %s\n' "$h" "$h" "$SECRET"
    done
    printf 'acl:\n  - id: tsig\n    key: ['
    local sep=""
    for h in $HMACS; do
        printf '%shmac-%s.key' "$sep" "$h"
        sep=", "
    done
    printf ']\n    action: [transfer, update]\n'
    cat <<EOF
mod-cookies:
  - id: default
    # A fixed secret, so that dnsbox can recompute knotd's RFC 9018
    # server cookies.
    secret: 0x000102030405060708090a0b0c0d0e0f
policy:
  - id: online
    algorithm: ed25519
    nsec3: on
    nsec3-iterations: 0
    rrsig-lifetime: 3650d
    rrsig-refresh: 30d
template:
  - id: default
    storage: "$OUT/zones"
    file: "%s.zone"
    dnssec-signing: off
    zonefile-sync: -1
    zonefile-load: whole
    journal-content: changes
    semantic-checks: off
    acl: tsig
    global-module: mod-cookies/default
zone:
EOF
    for z in $(children); do
        printf '  - domain: %s\n  - domain: unsigned.%s\n' "$z" "$z"
    done
    for z in interop. bogus.interop. bogus-nsec.interop. bogus-ds.interop. insecure.interop. bulk.interop.; do
        printf '  - domain: %s\n' "$z"
    done
    printf '  - domain: dyn.interop.\n    dnssec-signing: on\n    dnssec-policy: online\n'
    # dnsbox's presentation of every type BIND reads (tests/interop_zones.rs),
    # but those Knot does not know.
    printf '  - domain: alltypes.example.\n'
}

unbound_conf() {
    cat <<EOF
server:
    interface: 127.0.0.1
    port: 5335
    do-ip6: no
    do-not-query-localhost: no
    username: ""
    chroot: ""
    directory: "$WORK/unbound"
    pidfile: "$WORK/unbound/unbound.pid"
    use-syslog: no
    logfile: "$OUT/unbound.log"
    verbosity: 1
    val-log-level: 2
    log-servfail: yes
    access-control: 127.0.0.0/8 allow
    module-config: "validator iterator"
    trust-anchor-file: "$WORK/unbound/anchor.ds"
    aggressive-nsec: no
    qname-minimisation: no
    ede: yes
    answer-cookie: yes
    nsid: "ascii_unbound.dnsbox-interop"
    val-clean-additional: yes
EOF
    # One stub per zone knotd serves: knotd answers for all of them with
    # authority, so unbound would never see the zone cuts otherwise. Its
    # queries go through the proxy too (knot/unbound-upstream/).
    for z in interop. $(children) $(children | sed 's/^/unsigned./') bogus.interop. \
        bogus-nsec.interop. bogus-ds.interop. insecure.interop.; do
        printf 'stub-zone:\n    name: "%s"\n    stub-addr: 127.0.0.1@5300\n' "$z"
    done
}

cmd_serve() {
    mkdir -p "$WORK/serve-run" "$WORK/serve-db" "$WORK/unbound" "$OUT/knot" "$OUT/unbound"
    serve_conf >"$WORK/serve.conf"
    cat "$WORK/serve.conf"
    knotc -c "$WORK/serve.conf" conf-check
    knotd -c "$WORK/serve.conf" -d
    for _ in $(seq 1 50); do
        if kdig @127.0.0.1 -p 5301 +timeout=1 +retry=0 interop. SOA >/dev/null 2>&1; then break; fi
        sleep 0.2
    done
    knotc -c "$WORK/serve.conf" zone-status | tee "$OUT/zone-status.txt"

    # The trust anchor: interop.'s DS records.
    python3 - "$OUT/anchor.ds" >"$WORK/unbound/anchor.ds" <<'EOF'
import sys
for line in open(sys.argv[1]):
    t = line.split()
    if "DS" in t and not line.startswith(";"):
        i = t.index("DS")
        print(t[0], 3600, "IN", "DS", *t[i + 1:])
EOF
    cat "$WORK/unbound/anchor.ds"
    unbound_conf >"$WORK/unbound/unbound.conf"
    cat "$WORK/unbound/unbound.conf"
    unbound-checkconf "$WORK/unbound/unbound.conf"
    unbound -c "$WORK/unbound/unbound.conf"

    nohup python3 "$HERE/proxy.py" 5300 127.0.0.1 5301 "$OUT/knot" "$WORK/knot.label" \
        >"$WORK/proxy-knot.log" 2>&1 &
    echo $! >"$WORK/proxy-knot.pid"
    nohup python3 "$HERE/proxy.py" 5400 127.0.0.1 5335 "$OUT/unbound" "$WORK/unbound.label" \
        >"$WORK/proxy-unbound.log" 2>&1 &
    echo $! >"$WORK/proxy-unbound.pid"
    echo warmup >"$WORK/knot.label"
    echo warmup >"$WORK/unbound.label"
    for _ in $(seq 1 50); do
        if kdig @127.0.0.1 -p 5300 +timeout=1 +retry=0 interop. SOA >/dev/null 2>&1 &&
            kdig @127.0.0.1 -p 5400 +timeout=2 +retry=0 interop. SOA >/dev/null 2>&1; then
            break
        fi
        sleep 0.2
    done
    rm -rf "$OUT/knot/warmup" "$OUT/unbound/warmup"
    kdig @127.0.0.1 -p 5400 +dnssec www.ed25519-nsec.interop. A
}

cmd_stop() {
    for p in proxy-knot proxy-unbound; do
        kill "$(cat "$WORK/$p.pid" 2>/dev/null)" 2>/dev/null || true
    done
    kill "$(cat "$WORK/unbound/unbound.pid" 2>/dev/null)" 2>/dev/null || true
    knotc -c "$WORK/serve.conf" stop 2>/dev/null || true
}

# ---------------------------------------------------------------------
# capture
# ---------------------------------------------------------------------

FAILED=0

# kq LABEL KDIG-ARGS...: one kdig run against knotd, recorded as knot/LABEL.
kq() {
    local label=$1
    shift
    echo "$label" >"$WORK/knot.label"
    mkdir -p "$OUT/knot/$label"
    if ! kdig @127.0.0.1 -p 5300 +retry=0 +timeout=5 "$@" >"$OUT/knot/$label/kdig.txt" 2>&1; then
        echo "kdig failed: knot/$label: $*"
        FAILED=$((FAILED + 1))
    fi
    echo "kdig $*" >"$OUT/knot/$label/command.txt"
}

# kq_error LABEL KDIG-ARGS...: as kq, for a query knotd must refuse (kdig
# then exits with an error).
kq_error() {
    local label=$1
    shift
    echo "$label" >"$WORK/knot.label"
    mkdir -p "$OUT/knot/$label"
    if kdig @127.0.0.1 -p 5300 +retry=0 +timeout=5 "$@" >"$OUT/knot/$label/kdig.txt" 2>&1; then
        echo "kdig succeeded: knot/$label: $*"
        FAILED=$((FAILED + 1))
    fi
    echo "kdig $*" >"$OUT/knot/$label/command.txt"
}

# uq LABEL KDIG-ARGS...: the same against unbound, recorded as unbound/LABEL.
uq() {
    local label=$1
    shift
    echo "$label" >"$WORK/unbound.label"
    mkdir -p "$OUT/unbound/$label"
    if ! kdig @127.0.0.1 -p 5400 +retry=0 +timeout=4 "$@" >"$OUT/unbound/$label/kdig.txt" 2>&1; then
        echo "kdig failed: unbound/$label: $*"
        FAILED=$((FAILED + 1))
    fi
    echo "kdig $*" >"$OUT/unbound/$label/command.txt"
}

# The names from interop.'s child down to $1 (each a zone cut in our
# layout).
ancestors() {
    local rel=${1%interop.} name=interop.
    rel=${rel%.}
    local -a labels
    IFS=. read -ra labels <<<"$rel"
    for ((i = ${#labels[@]} - 1; i >= 0; i--)); do
        name="${labels[i]}.$name"
        echo "$name"
    done
}

# ucase CASE QNAME QTYPE ZONE EXPECTED: unbound's answer (DO), then
# everything a validator needs, with CD set: the answer, and DS and DNSKEY
# of every zone from interop. down to ZONE, the zone of QNAME.
ucase() {
    local case=$1 qname=$2 qtype=$3 zone=$4 expected=$5
    echo "unbound-upstream/$case" >"$WORK/knot.label"
    uq "$case/answer" +dnssec "$qname" "$qtype"
    uq "$case/cd" +dnssec +cdflag "$qname" "$qtype"
    uq "$case/dnskey-interop." +dnssec +cdflag interop. DNSKEY
    for a in $(ancestors "$zone"); do
        uq "$case/ds-$a" +dnssec +cdflag "$a" DS
        uq "$case/dnskey-$a" +dnssec +cdflag "$a" DNSKEY
    done
    echo "$case $qname $qtype $zone $expected" >>"$OUT/unbound/cases.txt"
}

cmd_capture() {
    log "knotd: the denial cases of every signed zone"
    for z in $(children) bogus.interop. bogus-nsec.interop. bogus-ds.interop. interop.; do
        local l=${z%.}
        kq "$l/dnskey" +dnssec "$z" DNSKEY
        kq "$l/soa" +dnssec "$z" SOA
        kq "$l/nxdomain" +dnssec "nosuch.$z" A
        kq "$l/nodata" +dnssec "www.$z" MX
        kq "$l/ent" +dnssec "b.ent.$z" A
        kq "$l/wildcard" +dnssec "host.wild.$z" A
        kq "$l/wildcard-nodata" +dnssec "host.wild.$z" MX
        kq "$l/cname" +dnssec "alias.$z" A
        kq "$l/dname" +dnssec "x.dname.$z" A
        kq "$l/referral-secure" +dnssec "host.secure.$z" A
        kq "$l/referral-insecure" +dnssec "host.insecure.$z" A
        kq "$l/ds-unsigned" +dnssec "other.$z" DS
        kq "$l/axfr" -y "hmac-sha256:hmac-sha256.key:$SECRET" "$z" AXFR
        kq "$l/axfr-json" +json -y "hmac-sha256:hmac-sha256.key:$SECRET" "$z" AXFR
    done

    log "knotd: dnsbox's presentation of every type (../bind9/alltypes.dnsbox)"
    kq alltypes/axfr -y "hmac-sha256:hmac-sha256.key:$SECRET" alltypes.example. AXFR
    kq alltypes/axfr-json +json -y "hmac-sha256:hmac-sha256.key:$SECRET" alltypes.example. AXFR

    log "knotd: EDNS, transports, CHAOS"
    local z=ed25519-nsec.interop.
    kq edns/nsid +nsid "$z" SOA
    kq edns/cookie +cookie "$z" SOA
    kq edns/padding +padding "$z" SOA
    kq edns/padding-tcp +tcp +padding=256 "$z" SOA
    kq edns/alignment +alignment "$z" SOA
    kq edns/zoneversion +zoneversion "$z" SOA
    kq edns/badcookie +cookie=0102030405060708a1a2a3a4a5a6a7a8a9aaabacadaeafb0 +badcookie "$z" SOA
    kq edns/subnet4 +subnet=192.0.2.0/24 "$z" SOA
    kq edns/subnet6 +subnet=2001:db8::/56 "$z" SOA
    kq edns/unknown-option +ednsopt=65001:c0ffee "$z" SOA
    kq edns/expire +expire "$z" SOA
    kq edns/json +json +nsid "$z" SOA
    kq edns/keepalive +tcp +ednsopt=11 "$z" SOA
    kq edns/version1 +edns=1 "$z" SOA
    kq edns/all +dnssec +nsid +cookie +padding +subnet=198.51.100.0/24 "$z" SOA
    kq edns/none +noedns "$z" SOA
    kq transport/tcp +tcp +dnssec rsasha512-nsec3.interop. DNSKEY
    kq transport/truncated +notcp +ignore +bufsize=512 +dnssec rsasha512-nsec3.interop. DNSKEY
    kq transport/fallback +bufsize=512 +dnssec rsasha512-nsec3.interop. DNSKEY
    kq transport/any "$z" ANY
    kq chaos/id.server CH TXT id.server.
    kq chaos/version.bind CH TXT version.bind.
    kq chaos/hostname.bind CH TXT hostname.bind.
    kq refused example.org. A

    log "knotd: transfers and updates with TSIG"
    for h in $HMACS; do
        kq "tsig/axfr-$h" -y "hmac-$h:hmac-$h.key:$SECRET" bulk.interop. AXFR
        kq "tsig/soa-$h" -y "hmac-$h:hmac-$h.key:$SECRET" interop. SOA
    done
    kq_error tsig/axfr-unsigned bulk.interop. AXFR
    kq_error tsig/axfr-badsig -y "hmac-sha256:hmac-sha256.key:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh4=" bulk.interop. AXFR
    kq_error tsig/axfr-badkey -y "hmac-sha256:no-such.key:$SECRET" bulk.interop. AXFR
    kq dyn/axfr-before -y "hmac-sha256:hmac-sha256.key:$SECRET" dyn.interop. AXFR
    local before
    before=$(kdig @127.0.0.1 -p 5301 +short dyn.interop. SOA | awk '{print $3}')
    echo "$before" >"$OUT/knot/dyn/serial-before"
    local n=0
    for h in $HMACS; do
        n=$((n + 1))
        echo "dyn/update-$h" >"$WORK/knot.label"
        mkdir -p "$OUT/knot/dyn/update-$h"
        knsupdate -y "hmac-$h:hmac-$h.key:$SECRET" >"$OUT/knot/dyn/update-$h/knsupdate.txt" 2>&1 <<EOF || FAILED=$((FAILED + 1))
server 127.0.0.1 5300
zone dyn.interop.
prereq nxdomain new$n.dyn.interop.
prereq yxrrset www.dyn.interop. A
update add new$n.dyn.interop. 300 A 192.0.2.$n
update add new$n.dyn.interop. 300 TXT "added with hmac-$h"
update delete t000.dyn.interop. TXT
send
answer
EOF
    done
    # A failing prerequisite: YXDOMAIN.
    echo "dyn/update-yxdomain" >"$WORK/knot.label"
    mkdir -p "$OUT/knot/dyn/update-yxdomain"
    knsupdate -y "hmac-sha256:hmac-sha256.key:$SECRET" >"$OUT/knot/dyn/update-yxdomain/knsupdate.txt" 2>&1 <<EOF || true
server 127.0.0.1 5300
zone dyn.interop.
prereq nxdomain www.dyn.interop.
update add www.dyn.interop. 300 A 192.0.2.81
send
answer
EOF
    for h in $HMACS; do
        kq "dyn/ixfr-$h" -y "hmac-$h:hmac-$h.key:$SECRET" dyn.interop. "IXFR=$before"
    done
    kq dyn/axfr-after -y "hmac-sha256:hmac-sha256.key:$SECRET" dyn.interop. AXFR
    local after
    after=$(kdig @127.0.0.1 -p 5301 +short dyn.interop. SOA | awk '{print $3}')
    kq dyn/ixfr-uptodate -y "hmac-sha256:hmac-sha256.key:$SECRET" dyn.interop. "IXFR=$after"
    kq dyn/ixfr-udp +notcp -y "hmac-sha256:hmac-sha256.key:$SECRET" dyn.interop. "IXFR=$before"

    log "unbound: secure, insecure and bogus answers"
    : >"$OUT/unbound/cases.txt"
    for z in $(children); do
        local l=${z%.interop.} chain=${z%.interop.}
        chain=${chain##*-}
        local denial=secure
        [ "$chain" = optout ] && denial=insecure
        ucase "$l/a" "www.$z" A "$z" secure
        ucase "$l/nxdomain" "nosuch.$z" A "$z" "$denial"
        ucase "$l/nodata" "www.$z" MX "$z" secure
        ucase "$l/wildcard" "host.wild.$z" A "$z" "$denial"
        ucase "$l/unsigned" "www.unsigned.$z" A "unsigned.$z" insecure
    done
    ucase bogus/rdata www.bogus.interop. A bogus.interop. bogus
    ucase bogus/nsec nosuch.bogus-nsec.interop. A bogus-nsec.interop. bogus
    ucase bogus/ds www.bogus-ds.interop. A bogus-ds.interop. bogus
    ucase insecure/a www.insecure.interop. A insecure.interop. insecure
    ucase parent/a www.interop. A interop. secure
    ucase parent/nxdomain nosuch.interop. A interop. secure
    echo "unbound-upstream/extra" >"$WORK/knot.label"
    uq extra/tcp +tcp +dnssec www.ed25519-nsec.interop. A
    uq extra/nsid-cookie +nsid +cookie www.ed25519-nsec.interop. A

    echo "$FAILED failed tool runs"
    [ "$FAILED" = 0 ]
}

cmd_check_dnsbox() {
    local rc=0 n=0
    mkdir -p "$OUT/checks"
    for f in "$OUT"/dnsbox/*.zone; do
        local zone
        zone=$(basename "$f" .zone).
        check_zone "$zone" "$f" "dnsbox-${zone%.}" || rc=1
        n=$((n + 1))
    done
    [ "$n" -ge 19 ] || { echo "only $n zones from dnsbox"; rc=1; }
    # The checkers do check: each rejects the tampered zones.
    for b in bogus bogus-nsec; do
        local f="$OUT/zones/$b.interop.zone"
        if kzonecheck -d on -o "$b.interop." "$f" >/dev/null 2>&1; then
            echo "kzonecheck accepts $b.interop."
            rc=1
        fi
        if ldns-verify-zone "$f" >/dev/null 2>&1; then
            echo "ldns-verify-zone accepts $b.interop."
            rc=1
        fi
        if dnssec-verify -o "$b.interop." "$f" >/dev/null 2>&1; then
            echo "dnssec-verify accepts $b.interop."
            rc=1
        fi
    done
    return $rc
}

case $CMD in
sign) cmd_sign ;;
serve) cmd_serve ;;
capture) cmd_capture ;;
stop) cmd_stop ;;
check-dnsbox) cmd_check_dnsbox ;;
*)
    echo "unknown command $CMD" >&2
    exit 2
    ;;
esac
