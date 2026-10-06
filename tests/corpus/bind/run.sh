#!/usr/bin/env bash
# BIND 9 tool-level interop (tests/corpus/README.md, "BIND 9 on the CI
# runner"). Made for the GitHub Actions runner of
# .github/workflows/interop.yml: it runs two named instances on
# 127.0.0.1:5351 (authoritative) and 127.0.0.1:5355 (validating resolver),
# so do not run it on a workstation.
#
#   run.sh sign OUT          make keys with dnssec-keygen, sign the zones
#                            with dnssec-signzone (every algorithm BIND
#                            supports, NSEC, NSEC3 and NSEC3 Opt-Out), check
#                            them with named-checkzone and dnssec-verify,
#                            and write them again with named-compilezone in
#                            each output style
#   run.sh serve OUT         start both named and the recording proxies
#                            (127.0.0.1:5350 -> authoritative, :5450 ->
#                            resolver)
#   run.sh capture OUT       query both through the proxies with dig and
#                            nsupdate (TSIG and SIG(0))
#   run.sh stop OUT          stop everything
#   run.sh check-dnsbox OUT  run named-checkzone, named-compilezone and
#                            dnssec-verify on the zones dnsbox wrote into
#                            OUT/dnsbox (DNSBOX_INTEROP_WRITE=1 cargo test
#                            --test interop_bind)
#
# OUT receives everything tests/interop_bind.rs reads (point
# DNSBOX_INTEROP_DIR at it):
#
#   versions.txt, now        tool versions; the time of the run (seconds)
#   algorithms.txt           every DNSSEC algorithm tried with
#                            dnssec-keygen: "<mnemonic> <number> ok" or
#                            "... unsupported: <message>"
#   manifest.txt             zone, algorithm, denial chain[, kind]
#   zones/<zone>.zone        dnssec-signzone's output, and the unsigned
#                            zones named serves
#   keys/<zone>/             dnssec-keygen's K*.key and K*.private
#   ds/<zone>.ds             dnssec-dsfromkey's DS records of the KSK
#   sig0/                    the SIG(0) keys (dnssec-keygen -T KEY)
#   compiled/<name>.<style>  named-compilezone -s full|relative of the
#                            zones (and of ../bind9/alltypes.zone)
#   alltypes-omitted.txt     the lines of ../bind9/alltypes.dnsbox named
#                            cannot read (none expected)
#   newtypes-omitted.txt     likewise for ../knot/newtypes.zone
#   named/<label>/           exchanges with the authoritative named:
#                            NN-<udp|tcp>-<q|r>.hex (../knot/proxy.py),
#                            dig's or nsupdate's output (dig.txt,
#                            nsupdate.txt) and the command (command.txt)
#   resolver/<case>/<step>/  exchanges with the resolver, likewise;
#                            resolver/cases.txt lists the cases
#   dnsbox/, dnsbox-compiled/
#                            the zones dnsbox wrote (cargo test) and
#                            named-compilezone's output of them
#                            (check-dnsbox)
#   checks/                  logs of the zone checkers
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
CORPUS=$(cd "$HERE/.." && pwd)
CMD=${1:?usage: run.sh sign|serve|capture|stop|check-dnsbox OUT}
OUT=${2:?usage: run.sh $CMD OUT}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
WORK=${DNSBOX_INTEROP_WORK:-${RUNNER_TEMP:-/tmp}/dnsbox-bind-work}
mkdir -p "$WORK"

# The TSIG secret of every key: the bytes 00 01 .. 1f (as in
# tests/tsig_named.rs and ../knot/run.sh).
SECRET=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
HMACS="md5 sha1 sha224 sha256 sha384 sha512"
# named's RFC 9018 server cookie secret (SipHash-2-4): 00 01 .. 0f.
COOKIE_SECRET=000102030405060708090a0b0c0d0e0f
# Every DNSSEC algorithm mnemonic dnssec-keygen has known: those it no
# longer supports are recorded in algorithms.txt.
# name:mnemonic:number:chains
ALGS="rsamd5:RSAMD5:1:nsec dsa:DSA:3:nsec rsasha1:RSASHA1:5:nsec
nsec3dsa:NSEC3DSA:6:nsec,nsec3,optout nsec3rsasha1:NSEC3RSASHA1:7:nsec,nsec3,optout
rsasha256:RSASHA256:8:nsec,nsec3,optout rsasha512:RSASHA512:10:nsec,nsec3,optout
eccgost:ECCGOST:12:nsec,nsec3,optout ecdsap256:ECDSAP256SHA256:13:nsec,nsec3,optout
ecdsap384:ECDSAP384SHA384:14:nsec,nsec3,optout ed25519:ED25519:15:nsec,nsec3,optout
ed448:ED448:16:nsec,nsec3,optout"
# Zones signed with a deliberate defect after signing (bogus answers).
BOGUS="bogus bogus-nsec bogus-ds"
# The SIG(0) keys of dyn.interop. (dnssec-keygen -T KEY): name:mnemonic
SIG0="ed25519:ED25519 ecdsap256:ECDSAP256SHA256 rsasha256:RSASHA256"
SERIAL=2026100601
AUTH_PORT=5351
AUTH_PROXY=5350
RESOLVER_PORT=5355
RESOLVER_PROXY=5450

log() { printf '\n=== %s\n' "$*"; }

# The signed children, from manifest.txt (once sign has run).
children() {
    awk 'NF == 3 {print $1}' "$OUT/manifest.txt"
}

# ---------------------------------------------------------------------
# sign
# ---------------------------------------------------------------------

stamp() { date -u -d "@$1" +%Y%m%d%H%M%S; }

# sign_zone ZONE MNEMONIC CHAIN [OUTPUT-FORMAT]: keys (dnssec-keygen: a
# KSK, with CDS/CDNSKEY published for NSEC3 zones, and a ZSK), the signed
# zone (dnssec-signzone -S) and the DS records (dnssec-dsfromkey).
sign_zone() {
    local zone=$1 alg=$2 chain=$3 format=${4:-text}
    local file=${zone%.} keys="$OUT/keys/${zone%.}"
    local kbits=() zbits=() sync=() nsec3=()
    case $alg in
    RSA* | NSEC3RSA*) kbits=(-b 2048) zbits=(-b 1024) ;;
    esac
    case $chain in
    nsec3)
        sync=(-P sync now)
        nsec3=(-3 aabbccdd -H 5)
        ;;
    optout) nsec3=(-3 - -H 0 -A) ;;
    esac
    log "dnssec-keygen + dnssec-signzone: $zone ($alg, $chain)"
    mkdir -p "$keys"
    local ksk zsk
    ksk=$(dnssec-keygen -q -K "$keys" -a "$alg" "${kbits[@]}" -f KSK -L 3600 "${sync[@]}" "$zone")
    zsk=$(dnssec-keygen -q -K "$keys" -a "$alg" "${zbits[@]}" -L 3600 "$zone")
    echo "KSK $ksk, ZSK $zsk"
    (cd "$keys" && dnssec-signzone -S -x -K "$keys" -d "$WORK/dsset" -o "$zone" \
        -s "$INCEPTION" -e "$EXPIRATION" -O "$format" "${nsec3[@]}" \
        -f "$OUT/zones/$file.zone" "$WORK/in/$file.zone")
    {
        echo "; DS records of the KSK of $zone (dnssec-dsfromkey -1, -2, -a SHA-384)"
        dnssec-dsfromkey -1 "$keys/$ksk.key"
        dnssec-dsfromkey -2 "$keys/$ksk.key"
        dnssec-dsfromkey -a SHA-384 "$keys/$ksk.key"
    } >"$OUT/ds/$file.ds"
    cat "$OUT/ds/$file.ds"
}

# Breaks zone file $1 (signed with -O full: one record per line) after
# signing: rule $2 is "rdata" (www A changed) or "nsec" (an extra type in
# every NSEC bitmap).
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
    # [TTL] [CLASS] TYPE RDATA
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

# readable ORIGIN SRC TAG: writes the lines of zone file SRC that named
# reads to OUT/zones/ORIGIN.zone (without the final dot), and the others
# to OUT/TAG-omitted.txt (named-checkzone stops at the first record it
# cannot read: drop it and try again).
readable() {
    local origin=$1 src=$2 tag=$3
    local dst="$OUT/zones/${origin%.}.zone"
    cp "$src" "$dst"
    : >"$OUT/$tag-omitted.txt"
    : >"$OUT/checks/$tag.named-checkzone"
    for _ in $(seq 1 100); do
        if named-checkzone -k ignore -i none "$origin" "$dst" >"$WORK/checkzone.log" 2>&1; then
            cat "$WORK/checkzone.log" >>"$OUT/checks/$tag.named-checkzone"
            break
        fi
        cat "$WORK/checkzone.log" >>"$OUT/checks/$tag.named-checkzone"
        local line
        line=$(grep -oE "$(basename "$dst"):[0-9]+:" "$WORK/checkzone.log" | head -n1 | cut -d: -f2)
        if [ -z "$line" ]; then
            cat "$WORK/checkzone.log"
            return 1
        fi
        sed -n "${line}p" "$dst" | tee -a "$OUT/$tag-omitted.txt"
        sed -i "${line}s/^/; omitted for named: /" "$dst"
    done
    echo "$tag: $(grep -c . "$OUT/$tag-omitted.txt" || true) lines omitted for named"
    named-checkzone -k ignore -i none "$origin" "$dst"
}

# compile NAME ORIGIN FILE: named-compilezone's text output of FILE in both
# styles into OUT/compiled/NAME.{full,relative}.
#
# BIND 9.18.39's named-compilezone -s relative aborts (an assertion in
# dns_name_fromregion) on some records: when a style fails, each record
# of the full-style output is compiled alone (with the apex SOA and NS
# and their glue) to find them;
# they go to OUT/compiled/NAME.STYLE.omitted and the rest is compiled.
compile() {
    local name=$1 origin=$2 file=$3 dir=${4:-$OUT/compiled}
    mkdir -p "$dir"
    for style in full relative; do
        local log="$OUT/checks/compile-$name.$style"
        if named-compilezone -k ignore -i none -s "$style" -o "$dir/$name.$style" \
            "$origin" "$file" >"$log" 2>&1; then
            continue
        fi
        cat "$log"
        [ "$style" != full ] || return 1
        local apex
        # The apex SOA and NS records and the NS targets' addresses.
        apex=$(awk -v o="$origin" '
            NR == FNR { if ($1 == o && $4 == "NS") ns[$5] = 1; next }
            ($1 == o && ($4 == "SOA" || $4 == "NS")) || (($4 == "A" || $4 == "AAAA") && ($1 in ns))
        ' "$dir/$name.full" "$dir/$name.full")
        : >"$dir/$name.$style.omitted"
        grep -v '^;' "$dir/$name.full" | while IFS= read -r line; do
            [ -n "$line" ] || continue
            printf '%s\n%s\n' "$apex" "$line" >"$WORK/one.zone"
            if ! named-compilezone -k ignore -i none -s "$style" -o "$WORK/one.out" \
                "$origin" "$WORK/one.zone" >"$WORK/one.log" 2>&1 </dev/null; then
                echo "$line" >>"$dir/$name.$style.omitted"
                { echo "== $line"; cat "$WORK/one.zone" "$WORK/one.log"; } >>"$log.isolated"
            fi
        done
        echo "named-compilezone -s $style fails on these records of $name:"
        cat "$dir/$name.$style.omitted"
        head -n 40 "$log.isolated" 2>/dev/null || true
        grep -vxFf "$dir/$name.$style.omitted" "$dir/$name.full" >"$WORK/rest.zone" || true
        # Not fatal: tests/interop_bind.rs checks which records failed.
        named-compilezone -k ignore -i none -s "$style" -o "$dir/$name.$style" \
            "$origin" "$WORK/rest.zone" >>"$log" 2>&1 || {
            cat "$log"
            echo "named-compilezone -s $style fails on the rest of $name too"
        }
    done
}

# check_zone ZONE FILE TAG: named-checkzone (full checks) and
# dnssec-verify; logs in OUT/checks/TAG.*.
check_zone() {
    local zone=$1 file=$2 tag=$3 rc=0
    timeout 120 named-checkzone -i full -k ignore "$zone" "$file" \
        >"$OUT/checks/$tag.named-checkzone" 2>&1 || rc=1
    timeout 120 dnssec-verify -o "$zone" "$file" >"$OUT/checks/$tag.dnssec-verify" 2>&1 || rc=1
    if [ $rc != 0 ]; then
        echo "FAILED: $tag"
        tail -n 20 "$OUT/checks/$tag".*
        return 1
    fi
    echo "ok: $tag"
}

cmd_sign() {
    rm -rf "$WORK/in" "$WORK/dsset"
    mkdir -p "$WORK/in" "$WORK/dsset" "$OUT/zones" "$OUT/keys" "$OUT/ds" "$OUT/checks" \
        "$OUT/compiled" "$OUT/sig0"
    {
        echo "# Tool versions of this run"
        named -v 2>&1 | head -n1 || true
        dig -v 2>&1 | head -n1 || true
        nsupdate -V 2>&1 | head -n1 || true
        dnssec-signzone -V 2>&1 | head -n1 || true
        named-checkzone -v 2>&1 | head -n1 || true
        python3 -c 'import dns.version; print("dnspython", dns.version.version)' || true
        openssl version || true
        uname -sr
    } | tee "$OUT/versions.txt"
    mkdir -p "$OUT/help"
    for t in dnssec-keygen dnssec-signzone named-compilezone dig nsupdate; do
        "$t" -h >"$OUT/help/$t.txt" 2>&1 || true
    done
    named -V >"$OUT/help/named-V.txt" 2>&1 || true

    NOW=$(date +%s)
    echo "$NOW" >"$OUT/now"
    # Valid from an hour before the run for ten years.
    INCEPTION=$(stamp $((NOW - 3600)))
    EXPIRATION=$(stamp $((NOW + 315360000)))

    : >"$OUT/manifest.txt"
    : >"$OUT/algorithms.txt"
    for spec in $ALGS; do
        IFS=: read -r name alg num chains <<<"$spec"
        local msg
        if ! msg=$(dnssec-keygen -q -K "$WORK" -a "$alg" -L 3600 probe.interop. 2>&1); then
            echo "$alg $num unsupported: $(echo "$msg" | tail -n1)" | tee -a "$OUT/algorithms.txt"
            continue
        fi
        echo "$alg $num ok" | tee -a "$OUT/algorithms.txt"
        for chain in ${chains//,/ }; do
            local zone="$name-$chain.interop."
            sed -e "1i \$ORIGIN $zone" "$CORPUS/knot/child.zone" >"$WORK/in/${zone%.}.zone"
            sign_zone "$zone" "$alg" "$chain"
            echo "$zone $name $chain" >>"$OUT/manifest.txt"
        done
    done

    # The bogus zones: signed (one record per line), then broken.
    for b in $BOGUS; do
        sed -e "1i \$ORIGIN $b.interop." "$CORPUS/knot/child.zone" >"$WORK/in/$b.interop.zone"
    done
    sign_zone bogus.interop. ECDSAP256SHA256 nsec full
    tamper "$OUT/zones/bogus.interop.zone" rdata
    sign_zone bogus-nsec.interop. ECDSAP384SHA384 nsec full
    tamper "$OUT/zones/bogus-nsec.interop.zone" nsec
    sign_zone bogus-ds.interop. ED25519 nsec full
    {
        echo "bogus.interop. ecdsap256 nsec bogus-rdata"
        echo "bogus-nsec.interop. ecdsap384 nsec bogus-nsec"
        echo "bogus-ds.interop. ed25519 nsec bogus-ds"
    } >>"$OUT/manifest.txt"

    # The parent: delegations with glue, the children's DS records
    # (SHA-256, SHA-384; wrong ones for bogus-ds), none for the unsigned
    # zones.
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
            grep -v '^;' "$OUT/ds/${z%.}.ds" | awk '$6 != 1'
        done
        # bogus-ds: the DS digests with their last hex digit changed.
        grep -v '^;' "$OUT/ds/bogus-ds.interop.ds" | awk '$6 != 1' |
            sed -e 's/0$/X/;s/[1-9A-Fa-f]$/0/;s/X$/1/'
    } >"$WORK/in/interop.zone"
    cat "$WORK/in/interop.zone"
    sign_zone interop. ECDSAP256SHA256 nsec
    echo "interop. ecdsap256 nsec parent" >>"$OUT/manifest.txt"
    grep -v '^;' "$OUT/ds/interop.ds" | awk '$6 != 1' >"$OUT/anchor.ds"

    # The unsigned zones named serves next to them.
    for z in $(children); do
        printf '$ORIGIN unsigned.%s\n$TTL 3600\n@ SOA ns hostmaster %s 7200 3600 1209600 300\n  NS ns\nns A 127.0.0.1\nwww A 192.0.2.80\n' \
            "$z" "$SERIAL" >"$OUT/zones/unsigned.${z%.}.zone"
    done
    printf '$ORIGIN insecure.interop.\n$TTL 3600\n@ SOA ns1 hostmaster %s 7200 3600 1209600 300\n  NS ns1\nns1 A 127.0.0.1\nwww A 192.0.2.80\n' \
        "$SERIAL" >"$OUT/zones/insecure.interop.zone"
    # The dynamic zone, with the KEY records of the SIG(0) keys.
    {
        printf '$ORIGIN dyn.interop.\n$TTL 3600\n@ SOA ns1 hostmaster %s 7200 3600 1209600 300\n  NS ns1\nns1 A 127.0.0.1\nwww A 192.0.2.80\nold A 192.0.2.99\nt000 TXT "to be deleted"\nt001 TXT "to be deleted"\n' "$SERIAL"
        for spec in $SIG0; do
            local k
            k=$(dnssec-keygen -q -K "$OUT/sig0" -T KEY -n HOST -a "${spec#*:}" \
                $([ "${spec#*:}" = RSASHA256 ] && echo "-b 1024") "sig0-${spec%%:*}.dyn.interop.")
            echo "$k" >"$OUT/sig0/${spec%%:*}.name"
            grep -v '^;' "$OUT/sig0/$k.key"
        done
    } >"$OUT/zones/dyn.interop.zone"
    cat "$OUT/zones/dyn.interop.zone"
    # A zone big enough for a multi-message transfer.
    {
        printf '$ORIGIN bulk.interop.\n$TTL 3600\n@ SOA ns1 hostmaster %s 7200 3600 1209600 300\n  NS ns1\nns1 A 127.0.0.1\n' "$SERIAL"
        for i in $(seq 1 250); do
            printf 'h%04d A 192.0.%d.%d\nh%04d TXT "record %d of the bulk zone, padded to make the transfer span several messages"\n' \
                "$i" $((i / 256)) $((i % 256)) "$i" "$i"
        done
    } >"$OUT/zones/bulk.interop.zone"

    log "named-checkzone and dnssec-verify check BIND's zones"
    local rc=0
    for z in $(children) interop.; do
        check_zone "$z" "$OUT/zones/${z%.}.zone" "bind-${z%.}" || rc=1
    done
    # dnssec-verify must reject the tampered zones (the checks check).
    for b in bogus bogus-nsec; do
        if dnssec-verify -o "$b.interop." "$OUT/zones/$b.interop.zone" >"$OUT/checks/bind-$b.dnssec-verify" 2>&1; then
            echo "dnssec-verify accepts $b.interop."
            rc=1
        fi
    done

    log "named-compilezone: every zone in both text styles"
    for z in $(children) interop. bogus.interop.; do
        compile "${z%.}" "$z" "$OUT/zones/${z%.}.zone" || rc=1
    done
    compile alltypes alltypes.example. "$CORPUS/bind9/alltypes.zone" || rc=1
    compile bulk.interop bulk.interop. "$OUT/zones/bulk.interop.zone" || rc=1

    log "named reads dnsbox's presentation of every type"
    # dnsbox's display of every type BIND reads (../bind9/alltypes.dnsbox)
    # and of the types typed since (../knot/newtypes.zone), but for the
    # records named cannot read.
    readable alltypes.example. "$CORPUS/bind9/alltypes.dnsbox" alltypes || rc=1
    readable newtypes.example. "$CORPUS/knot/newtypes.zone" newtypes || rc=1
    # BIND 9.18 reads a type-0 AMTRELAY only without its relay (RFC 8777
    # §4.3.1 has "."): serve it in BIND's form too, for dig to write it.
    if grep -q 'AMTRELAY 0 0 0 \.' "$OUT/newtypes-omitted.txt"; then
        printf '; BIND form of the record above\namtrelay.newtypes.example. 3600 IN AMTRELAY 0 0 0\n' \
            >>"$OUT/zones/newtypes.example.zone"
    fi
    compile newtypes newtypes.example. "$OUT/zones/newtypes.example.zone" || rc=1
    ls -l "$OUT/zones" "$OUT/compiled"
    return $rc
}

# ---------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------

keys_conf() {
    for h in $HMACS; do
        printf 'key "hmac-%s.key." { algorithm hmac-%s; secret "%s"; };\n' "$h" "$h" "$SECRET"
    done
}

auth_conf() {
    local d="$WORK/auth"
    cat <<EOF
options {
    directory "$d";
    pid-file "$d/named.pid";
    session-keyfile "$d/session.key";
    managed-keys-directory "$d";
    listen-on port $AUTH_PORT { 127.0.0.1; };
    listen-on-v6 { none; };
    recursion no;
    dnssec-validation no;
    notify no;
    allow-transfer { key hmac-md5.key.; key hmac-sha1.key.; key hmac-sha224.key.;
                     key hmac-sha256.key.; key hmac-sha384.key.; key hmac-sha512.key.; };
    check-names primary ignore;
    check-integrity no;
    server-id "named.dnsbox-interop";
    hostname "named.dnsbox-interop";
    version "dnsbox-interop";
    cookie-algorithm siphash24;
    cookie-secret "$COOKIE_SECRET";
    response-padding { any; } block-size 128;
    tcp-advertised-timeout 300;
    # IXFR however large the differences (the default, 100%, would send
    # dyn.interop.'s seven updates as an AXFR).
    max-ixfr-ratio unlimited;
    edns-udp-size 1232;
    max-udp-size 1232;
    minimal-responses no-auth-recursive;
};
controls { };
logging {
    channel main { file "$OUT/named-auth.log"; severity info; print-time yes; print-category yes; };
    category default { main; };
    category queries { main; };
    category update { main; };
    category xfer-out { main; };
    category dnssec { main; };
};
EOF
    keys_conf
    for z in $(children); do
        printf 'zone "%s" { type primary; file "%s/zones/%s.zone"; };\n' "$z" "$OUT" "${z%.}"
        printf 'zone "unsigned.%s" { type primary; file "%s/zones/unsigned.%s.zone"; };\n' "$z" "$OUT" "${z%.}"
    done
    for z in interop. bogus.interop. bogus-nsec.interop. bogus-ds.interop. insecure.interop. \
        bulk.interop. alltypes.example. newtypes.example.; do
        printf 'zone "%s" { type primary; file "%s/zones/%s.zone"; };\n' "$z" "$OUT" "${z%.}"
    done
    # The dynamic zone: TSIG keys and the SIG(0) keys may update it.
    printf 'zone "dyn.interop." { type primary; file "%s/dyn.interop.zone";\n    update-policy {\n' "$d"
    for h in $HMACS; do
        printf '        grant hmac-%s.key. zonesub ANY;\n' "$h"
    done
    for spec in $SIG0; do
        printf '        grant sig0-%s.dyn.interop. zonesub ANY;\n' "${spec%%:*}"
    done
    printf '    };\n};\n'
}

resolver_conf() {
    local d="$WORK/resolver"
    cat <<EOF
options {
    directory "$d";
    pid-file "$d/named.pid";
    session-keyfile "$d/session.key";
    managed-keys-directory "$d";
    listen-on port $RESOLVER_PORT { 127.0.0.1; };
    listen-on-v6 { none; };
    recursion yes;
    allow-recursion { 127.0.0.0/8; };
    allow-query-cache { 127.0.0.0/8; };
    dnssec-validation yes;
    qname-minimization off;
    servfail-ttl 0;
    server-id "resolver.dnsbox-interop";
    cookie-algorithm siphash24;
    cookie-secret "$COOKIE_SECRET";
    edns-udp-size 1232;
    max-udp-size 1232;
    minimal-responses no;
};
controls { };
logging {
    channel main { file "$OUT/named-resolver.log"; severity info; print-time yes; print-category yes; };
    category default { main; };
    category dnssec { main; };
    category resolver { main; };
    category lame-servers { main; };
};
EOF
    # The trust anchor: interop.'s DS records.
    printf 'trust-anchors {\n'
    awk '{printf "    %s static-ds %s %s %s \"%s\";\n", $1, $4, $5, $6, $7}' "$OUT/anchor.ds"
    printf '};\n'
    # Everything below interop. comes from the authoritative named, through
    # its proxy (resolver-upstream/).
    printf 'zone "interop." { type forward; forward only; forwarders { 127.0.0.1 port %s; }; };\n' "$AUTH_PROXY"
}

# start NAME CONF: starts named with CONF and waits for it.
start_named() {
    local name=$1 conf=$2 port=$3
    named-checkconf "$conf"
    named -c "$conf" -n 2
    for _ in $(seq 1 100); do
        if dig @127.0.0.1 -p "$port" +time=1 +tries=1 interop. SOA >/dev/null 2>&1; then
            echo "$name answers on $port"
            return 0
        fi
        sleep 0.2
    done
    echo "$name does not answer"
    tail -n 50 "$OUT/named-$name.log" || true
    return 1
}

cmd_serve() {
    mkdir -p "$WORK/auth" "$WORK/resolver" "$OUT/named" "$OUT/resolver"
    cp "$OUT/zones/dyn.interop.zone" "$WORK/auth/dyn.interop.zone"
    auth_conf >"$WORK/auth/named.conf"
    cat "$WORK/auth/named.conf"
    start_named auth "$WORK/auth/named.conf" $AUTH_PORT
    resolver_conf >"$WORK/resolver/named.conf"
    cat "$WORK/resolver/named.conf"

    nohup python3 "$CORPUS/knot/proxy.py" $AUTH_PROXY 127.0.0.1 $AUTH_PORT "$OUT/named" "$WORK/named.label" \
        >"$WORK/proxy-named.log" 2>&1 &
    echo $! >"$WORK/proxy-named.pid"
    nohup python3 "$CORPUS/knot/proxy.py" $RESOLVER_PROXY 127.0.0.1 $RESOLVER_PORT "$OUT/resolver" \
        "$WORK/resolver.label" >"$WORK/proxy-resolver.log" 2>&1 &
    echo $! >"$WORK/proxy-resolver.pid"
    echo warmup >"$WORK/named.label"
    echo warmup >"$WORK/resolver.label"
    start_named resolver "$WORK/resolver/named.conf" $RESOLVER_PORT
    for _ in $(seq 1 50); do
        if dig @127.0.0.1 -p $AUTH_PROXY +time=1 +tries=1 interop. SOA >/dev/null 2>&1 &&
            dig @127.0.0.1 -p $RESOLVER_PROXY +time=2 +tries=1 interop. SOA >/dev/null 2>&1; then
            break
        fi
        sleep 0.2
    done
    dig @127.0.0.1 -p $RESOLVER_PROXY +dnssec www.ed25519-nsec.interop. A
    rm -rf "$OUT/named/warmup" "$OUT/resolver/warmup"
}

cmd_stop() {
    for p in proxy-named proxy-resolver; do
        kill "$(cat "$WORK/$p.pid" 2>/dev/null)" 2>/dev/null || true
    done
    for n in auth resolver; do
        kill "$(cat "$WORK/$n/named.pid" 2>/dev/null)" 2>/dev/null || true
    done
}

# ---------------------------------------------------------------------
# capture
# ---------------------------------------------------------------------

FAILED=0

# q LABEL DIG-ARGS...: one dig run against the authoritative named,
# recorded as named/LABEL.
q() {
    local label=$1
    shift
    echo "$label" >"$WORK/named.label"
    mkdir -p "$OUT/named/$label"
    if ! dig @127.0.0.1 -p $AUTH_PROXY +tries=1 +time=5 "$@" >"$OUT/named/$label/dig.txt" 2>&1; then
        echo "dig failed: named/$label: $*"
        FAILED=$((FAILED + 1))
    fi
    echo "dig $*" >"$OUT/named/$label/command.txt"
}

# qx LABEL DIG-ARGS...: as q, for a query named refuses (dig's exit status
# is not checked).
qx() {
    local label=$1
    shift
    echo "$label" >"$WORK/named.label"
    mkdir -p "$OUT/named/$label"
    dig @127.0.0.1 -p $AUTH_PROXY +tries=1 +time=5 "$@" >"$OUT/named/$label/dig.txt" 2>&1 || true
    echo "dig $*" >"$OUT/named/$label/command.txt"
}

# rq LABEL DIG-ARGS...: the same against the resolver, recorded as
# resolver/LABEL.
rq() {
    local label=$1
    shift
    echo "$label" >"$WORK/resolver.label"
    mkdir -p "$OUT/resolver/$label"
    if ! dig @127.0.0.1 -p $RESOLVER_PROXY +tries=1 +time=5 "$@" >"$OUT/resolver/$label/dig.txt" 2>&1; then
        echo "dig failed: resolver/$label: $*"
        FAILED=$((FAILED + 1))
    fi
    echo "dig $*" >"$OUT/resolver/$label/command.txt"
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

# rcase CASE QNAME QTYPE ZONE EXPECTED: the resolver's answer (DO), then
# everything a validator needs, with CD set: the answer, and DS and DNSKEY
# of every zone from interop. down to ZONE, the zone of QNAME.
rcase() {
    local case=$1 qname=$2 qtype=$3 zone=$4 expected=$5
    echo "resolver-upstream/$case" >"$WORK/named.label"
    rq "$case/answer" +dnssec "$qname" "$qtype"
    rq "$case/cd" +dnssec +cdflag "$qname" "$qtype"
    rq "$case/dnskey-interop" +dnssec +cdflag interop. DNSKEY
    for a in $(ancestors "$zone"); do
        rq "$case/ds-${a%.}" +dnssec +cdflag "$a" DS
        rq "$case/dnskey-${a%.}" +dnssec +cdflag "$a" DNSKEY
    done
    echo "$case $qname $qtype $zone $expected" >>"$OUT/resolver/cases.txt"
}

# nsup LABEL ARGS... <<SCRIPT: one nsupdate run, recorded as named/LABEL;
# returns nsupdate's status.
nsup() {
    local label=$1
    shift
    echo "$label" >"$WORK/named.label"
    mkdir -p "$OUT/named/$label"
    echo "nsupdate $*" >"$OUT/named/$label/command.txt"
    local rc=0
    nsupdate "$@" >"$OUT/named/$label/nsupdate.txt" 2>&1 || rc=$?
    echo "exit $rc" >>"$OUT/named/$label/command.txt"
    return $rc
}

serial() {
    dig @127.0.0.1 -p $AUTH_PORT +short "$1" SOA | awk '{print $3}'
}

cmd_capture() {
    log "named: the denial cases of every signed zone"
    for z in $(children) bogus.interop. bogus-nsec.interop. bogus-ds.interop. interop.; do
        local l=${z%.}
        q "$l/dnskey" +dnssec "$z" DNSKEY
        q "$l/soa" +dnssec "$z" SOA
        q "$l/nxdomain" +dnssec "nosuch.$z" A
        q "$l/nodata" +dnssec "www.$z" MX
        q "$l/ent" +dnssec "b.ent.$z" A
        q "$l/wildcard" +dnssec "host.wild.$z" A
        q "$l/wildcard-nodata" +dnssec "host.wild.$z" MX
        q "$l/cname" +dnssec "alias.$z" A
        q "$l/dname" +dnssec "x.dname.$z" A
        q "$l/referral-secure" +dnssec "host.secure.$z" A
        q "$l/referral-insecure" +dnssec "host.insecure.$z" A
        q "$l/ds-unsigned" +dnssec "other.$z" DS
        q "$l/axfr" -y "hmac-sha256:hmac-sha256.key:$SECRET" "$z" AXFR
    done
    # dig's other output formats of a few answers.
    q ed25519-nsec3.interop/dnskey-multiline +dnssec +multiline ed25519-nsec3.interop. DNSKEY
    q ed25519-nsec3.interop/axfr-multiline +multiline -y "hmac-sha256:hmac-sha256.key:$SECRET" \
        ed25519-nsec3.interop. AXFR
    q ecdsap256-optout.interop/nxdomain-multiline +dnssec +multiline nosuch.ecdsap256-optout.interop. A

    log "named: dnsbox's presentation of every type"
    q alltypes/axfr -y "hmac-sha256:hmac-sha256.key:$SECRET" alltypes.example. AXFR
    q newtypes/axfr -y "hmac-sha256:hmac-sha256.key:$SECRET" newtypes.example. AXFR
    # Each RRset of alltypes.example. alone (dig 9.18 cannot read named's
    # AXFR of it: "bad label type").
    local i=0
    awk '!/^[;$]/ && NF >= 4 {print $1, $4}' "$OUT/zones/alltypes.example.zone" | sort -u |
        while read -r owner type; do
            i=$((i + 1))
            qx "alltypes/rrset-$(printf %03d $i)" +tcp +norec "$owner" "$type"
        done
    for t in AMTRELAY DSYNC HHIT BRID DOA; do
        local n
        n=$(echo "$t" | tr A-Z a-z)
        case $t in DSYNC) n=_dsync ;; HHIT | BRID) n=drip ;; esac
        q "newtypes/$(echo "$t" | tr A-Z a-z)" "$n.newtypes.example." "TYPE$(type_number "$t")"
    done

    log "named: EDNS, transports, CHAOS"
    local z=ed25519-nsec.interop.
    q edns/nsid +nsid "$z" SOA
    q edns/cookie +cookie "$z" SOA
    q edns/cookie-server +cookie=0102030405060708a1a2a3a4a5a6a7a8a9aaabacadaeafb0 "$z" SOA
    q edns/nocookie +nocookie "$z" SOA
    q edns/padding +padding=128 "$z" SOA
    q edns/padding-tcp +tcp +padding=128 "$z" SOA
    q edns/subnet4 +subnet=192.0.2.0/24 "$z" SOA
    q edns/subnet6 +subnet=2001:db8::/56 "$z" SOA
    q edns/subnet0 +subnet=0 "$z" SOA
    q edns/unknown-option +ednsopt=65001:c0ffee "$z" SOA
    q edns/expire +expire "$z" SOA
    q edns/keepalive +tcp +keepalive "$z" SOA
    q edns/version1 +edns=1 "$z" SOA
    qx edns/version1-nonegotiation +edns=1 +noednsnegotiation "$z" SOA
    q edns/flags +ednsflags=0x40 "$z" SOA
    q edns/all +dnssec +nsid +cookie +padding=128 +subnet=198.51.100.0/24 +expire "$z" SOA
    q edns/none +noedns "$z" SOA
    q transport/tcp +tcp +dnssec rsasha512-nsec3.interop. DNSKEY
    q transport/truncated +notcp +ignore +bufsize=512 +dnssec rsasha512-nsec3.interop. DNSKEY
    q transport/fallback +bufsize=512 +dnssec rsasha512-nsec3.interop. DNSKEY
    q transport/any "$z" ANY
    q chaos/id.server CH TXT id.server.
    q chaos/version.bind CH TXT version.bind.
    q chaos/hostname.bind CH TXT hostname.bind.
    qx refused example.org. A
    qx notimp +opcode=2 "$z" SOA

    log "named: transfers and updates with TSIG"
    for h in $HMACS; do
        q "tsig/axfr-$h" -y "hmac-$h:hmac-$h.key:$SECRET" bulk.interop. AXFR
        q "tsig/soa-$h" -y "hmac-$h:hmac-$h.key:$SECRET" interop. SOA
    done
    qx tsig/axfr-unsigned bulk.interop. AXFR
    qx tsig/axfr-badsig -y "hmac-sha256:hmac-sha256.key:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh4=" bulk.interop. AXFR
    qx tsig/axfr-badkey -y "hmac-sha256:no-such.key:$SECRET" bulk.interop. AXFR
    q dyn/axfr-before -y "hmac-sha256:hmac-sha256.key:$SECRET" dyn.interop. AXFR
    local before
    before=$(serial dyn.interop.)
    echo "$before" >"$OUT/named/dyn/serial-before"
    local n=0
    for h in $HMACS; do
        n=$((n + 1))
        nsup "dyn/update-$h" -y "hmac-$h:hmac-$h.key:$SECRET" <<EOF || FAILED=$((FAILED + 1))
server 127.0.0.1 $AUTH_PROXY
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
    nsup dyn/update-yxdomain -y "hmac-sha256:hmac-sha256.key:$SECRET" <<EOF || true
server 127.0.0.1 $AUTH_PROXY
zone dyn.interop.
prereq nxdomain www.dyn.interop.
update add www.dyn.interop. 300 A 192.0.2.81
send
answer
EOF
    # An update over TCP (nsupdate -v).
    nsup dyn/update-tcp -v -y "hmac-sha512:hmac-sha512.key:$SECRET" <<EOF || FAILED=$((FAILED + 1))
server 127.0.0.1 $AUTH_PROXY
zone dyn.interop.
update add tcp.dyn.interop. 300 AAAA 2001:db8::7
send
answer
EOF
    # SIG(0) (RFC 2931): nsupdate signs with each KEY of the zone; named
    # answers as it does (the answer is recorded, not required).
    for spec in $SIG0; do
        local s=${spec%%:*}
        nsup "dyn/sig0-$s" -k "$OUT/sig0/$(cat "$OUT/sig0/$s.name").private" <<EOF || true
server 127.0.0.1 $AUTH_PROXY
zone dyn.interop.
update add sig0-$s-added.dyn.interop. 300 TXT "signed with SIG(0), $s"
send
answer
EOF
    done
    # Unsigned: refused by the update policy.
    nsup dyn/update-unsigned <<EOF || true
server 127.0.0.1 $AUTH_PROXY
zone dyn.interop.
update add unsigned.dyn.interop. 300 A 192.0.2.82
send
answer
EOF
    for h in $HMACS; do
        q "dyn/ixfr-$h" -y "hmac-$h:hmac-$h.key:$SECRET" dyn.interop. "IXFR=$before"
    done
    q dyn/axfr-after -y "hmac-sha256:hmac-sha256.key:$SECRET" dyn.interop. AXFR
    local after
    after=$(serial dyn.interop.)
    echo "$after" >"$OUT/named/dyn/serial-after"
    q dyn/ixfr-uptodate -y "hmac-sha256:hmac-sha256.key:$SECRET" dyn.interop. "IXFR=$after"
    q dyn/ixfr-udp +notcp -y "hmac-sha256:hmac-sha256.key:$SECRET" dyn.interop. "IXFR=$before"

    log "resolver: secure, insecure and bogus answers"
    : >"$OUT/resolver/cases.txt"
    for z in $(children); do
        local l=${z%.interop.} chain=${z%.interop.}
        chain=${chain##*-}
        local denial=secure
        [ "$chain" = optout ] && denial=insecure
        rcase "$l/a" "www.$z" A "$z" secure
        rcase "$l/nxdomain" "nosuch.$z" A "$z" "$denial"
        rcase "$l/nodata" "www.$z" MX "$z" secure
        rcase "$l/wildcard" "host.wild.$z" A "$z" "$denial"
        rcase "$l/unsigned" "www.unsigned.$z" A "unsigned.$z" insecure
    done
    rcase bogus/rdata www.bogus.interop. A bogus.interop. bogus
    rcase bogus/nsec nosuch.bogus-nsec.interop. A bogus-nsec.interop. bogus
    rcase bogus/ds www.bogus-ds.interop. A bogus-ds.interop. bogus
    rcase insecure/a www.insecure.interop. A insecure.interop. insecure
    rcase parent/a www.interop. A interop. secure
    rcase parent/nxdomain nosuch.interop. A interop. secure
    echo "resolver-upstream/extra" >"$WORK/named.label"
    rq extra/tcp +tcp +dnssec www.ed25519-nsec.interop. A
    rq extra/nsid-cookie +nsid +cookie www.ed25519-nsec.interop. A

    echo "$FAILED failed tool runs"
    [ "$FAILED" = 0 ]
}

type_number() {
    case $1 in
    AMTRELAY) echo 260 ;;
    DSYNC) echo 66 ;;
    HHIT) echo 67 ;;
    BRID) echo 68 ;;
    DOA) echo 259 ;;
    esac
}

cmd_check_dnsbox() {
    local rc=0 n=0
    mkdir -p "$OUT/checks" "$OUT/dnsbox-compiled"
    for f in "$OUT"/dnsbox/*.zone; do
        local zone
        zone=$(basename "$f" .zone).
        n=$((n + 1))
        check_zone "$zone" "$f" "dnsbox-${zone%.}" || rc=1
        compile "${zone%.}" "$zone" "$f" "$OUT/dnsbox-compiled" || rc=1
    done
    [ "$n" -ge 20 ] || { echo "only $n zones from dnsbox"; rc=1; }
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
