#!/bin/sh
# Regenerates the BIND 9.18 part of the interop corpus (see
# tests/corpus/README.md). Needs named, named-checkzone, dnssec-keygen,
# dnssec-signzone and dnssec-dsfromkey (BIND 9.18) and python3; runs named
# as the current user on 127.0.0.1, port $PORT (default 53535).
#
#   sh tests/corpus/bind9/gen.sh
#
# Writes, in tests/corpus/bind9/:
#   alltypes.canonical      named-checkzone -D of alltypes.zone
#   alltypes.dnsbox.canonical
#                           named-checkzone -D of alltypes.dnsbox, dnsbox's
#                           display of alltypes.canonical (written by
#                           DNSBOX_WRITE_ALLTYPES=1 cargo test --test
#                           interop_zones; run that first when dnsbox's
#                           presentation format changes)
#   <alg>.signed            signed.zone signed by dnssec-signzone
#   <alg>.ds                DS records of its KSK (SHA-1, SHA-256, SHA-384)
#   <alg>.keys              its public and private keys (throwaway test keys)
# and in tests/corpus/: named-*.hex, responses of named serving all of them
# (capture_local.py). Keys are new on every run, so everything changes.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
PORT=${PORT:-53535}
WORK=$(mktemp -d)
trap 'kill "$(cat "$WORK/named.pid" 2>/dev/null)" 2>/dev/null || true; rm -rf "$WORK"' EXIT

# Signature validity: 2026-01-01 to 2036-01-01, so that the tests (which
# pass their own "now") never see an expired signature.
INCEPTION=20260101000000
EXPIRATION=20360101000000

named-checkzone -q -k ignore -i none -D -o "$HERE/alltypes.canonical" \
    alltypes.example. "$HERE/alltypes.zone" || true
test -s "$HERE/alltypes.canonical"
named-checkzone -q -k ignore -i none -D -o "$HERE/alltypes.dnsbox.canonical" \
    alltypes.example. "$HERE/alltypes.dnsbox" || true
test -s "$HERE/alltypes.dnsbox.canonical"

# name:algorithm:KSK bits:ZSK bits:denial (nsec | nsec3:<salt>:<iterations>
# | optout:<salt>:<iterations>)
ZONES="
rsasha1:RSASHA1:2048:1024:nsec
nsec3rsasha1:NSEC3RSASHA1:2048:1024:nsec3:aabbccdd:5
rsasha256:RSASHA256:2048:1024:optout:-:0
rsasha512:RSASHA512:2048:1024:nsec
ecdsap256:ECDSAP256SHA256:0:0:nsec3:-:0
ecdsap384:ECDSAP384SHA384:0:0:nsec
ed25519:ED25519:0:0:optout:cafe:1
ed448:ED448:0:0:nsec
"

CONF="$WORK/named.conf"
cat > "$CONF" <<EOF
options {
    directory "$WORK";
    pid-file "$WORK/named.pid";
    listen-on port $PORT { 127.0.0.1; };
    listen-on-v6 { none; };
    recursion no;
    dnssec-validation no;
    allow-transfer { any; };
    check-names primary ignore;
    minimal-responses no-auth-recursive;
    max-udp-size 1232;
    edns-udp-size 1232;
};
zone "alltypes.example" { type primary; file "$HERE/alltypes.zone"; };
EOF

for spec in $ZONES; do
    name=${spec%%:*}
    rest=${spec#*:}
    alg=${rest%%:*}; rest=${rest#*:}
    kbits=${rest%%:*}; rest=${rest#*:}
    zbits=${rest%%:*}; rest=${rest#*:}
    denial=${rest%%:*}
    zone="$name.example"
    keys="$WORK/$name"
    mkdir -p "$keys"
    size() { if [ "$1" != 0 ]; then echo "-b $1"; fi; }
    # shellcheck disable=SC2046
    ksk=$(dnssec-keygen -q -K "$keys" -a "$alg" $(size "$kbits") -f KSK -L 3600 "$zone")
    # shellcheck disable=SC2046
    zsk=$(dnssec-keygen -q -K "$keys" -a "$alg" $(size "$zbits") -L 3600 "$zone")
    case $denial in
        nsec) nsec3="" ;;
        nsec3) nsec3="-3 $(echo "$spec" | cut -d: -f6) -H $(echo "$spec" | cut -d: -f7)" ;;
        optout) nsec3="-3 $(echo "$spec" | cut -d: -f6) -H $(echo "$spec" | cut -d: -f7) -A" ;;
    esac
    # shellcheck disable=SC2086
    (cd "$keys" && dnssec-signzone -q -S -x -o "$zone" -K "$keys" -d "$keys" \
        -s "$INCEPTION" -e "$EXPIRATION" $nsec3 \
        -f "$HERE/$name.signed" "$HERE/signed.zone" >/dev/null)
    {
        echo "; DS records of the KSK of $zone (dnssec-dsfromkey)"
        dnssec-dsfromkey -1 "$keys/$ksk.key"
        dnssec-dsfromkey -2 "$keys/$ksk.key"
        dnssec-dsfromkey -a SHA-384 "$keys/$ksk.key"
    } > "$HERE/$name.ds"
    {
        echo "; Throwaway keys of $zone made by dnssec-keygen for the dnsbox tests."
        for k in "$ksk" "$zsk"; do
            echo "; $k.key"
            grep -v '^;' "$keys/$k.key"
            echo "; $k.private"
            sed 's/^/;! /' "$keys/$k.private"
        done
    } > "$HERE/$name.keys"
    echo "zone \"$zone\" { type primary; file \"$HERE/$name.signed\"; };" >> "$CONF"
done

named -c "$CONF" -n 1 >/dev/null 2>&1
sleep 2
python3 "$HERE/capture_local.py" "$PORT"
