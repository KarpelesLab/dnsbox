#!/bin/sh
# Regenerates the ldns part of the interop corpus (see
# tests/corpus/README.md) with NLnet Labs' ldns 1.8 example tools
# (ldns-read-zone, ldns-keygen, ldns-signzone, ldns-key2ds). Put them in
# PATH, or point LDNS at the directory holding them:
#
#   LDNS=/opt/ldns/bin sh tests/corpus/ldns/gen.sh
#
# Writes, in tests/corpus/ldns/:
#   alltypes.ldns   ../bind9/alltypes.zone as ldns-read-zone writes it
#   <alg>.signed    ../bind9/signed.zone signed by ldns-signzone, with
#                   ZONEMD records (SHA-384 and SHA-512) and NSEC or NSEC3
#   <alg>.ds        DS records of its KSK (ldns-key2ds: SHA-1, SHA-256,
#                   SHA-384)
#   <alg>.keys      its public and private keys (throwaway test keys)
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
BIND9="$HERE/../bind9"
if [ -n "${LDNS:-}" ]; then PATH="$LDNS:$PATH"; fi
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# ldns 1.8 cannot read some records of BIND's canonical dump of
# alltypes.zone: the types it has no presentation format for (A6, ATMA,
# AVC, NINFO, NXT, RKEY, SINK, TA), BIND's CERT algorithm mnemonics
# NSEC3RSASHA1 and NSEC3DSA, an empty CSYNC bitmap and a KEY without key
# data. The rest goes through ldns-read-zone.
{
    echo '$ORIGIN alltypes.example.'
    grep -v -E ' IN (A6|ATMA|AVC|NINFO|NXT|RKEY|SINK|TA)	|NSEC3RSASHA1|NSEC3DSA|CSYNC	0 0$|KEY	49664 3 5$' \
        "$BIND9/alltypes.canonical"
} > "$WORK/alltypes.zone"
ldns-read-zone "$WORK/alltypes.zone" > "$HERE/alltypes.ldns"

# Signature validity: 2026-01-01 to 2036-01-01.
INCEPTION=20260101000000
EXPIRATION=20360101000000

# name:algorithm:denial (nsec | nsec3:<salt>:<iterations> | optout:...)
for spec in ed25519:ED25519:nsec3:-:0 rsasha256:RSASHA256:optout:beef:2 \
            ecdsap256:ECDSAP256SHA256:nsec; do
    name=${spec%%:*}
    rest=${spec#*:}
    alg=${rest%%:*}
    denial=$(echo "$spec" | cut -d: -f3)
    zone="ldns-$name.example"
    cd "$WORK"
    bits=""
    case $alg in RSA*) bits="-b 2048" ;; esac
    # shellcheck disable=SC2086
    ksk=$(ldns-keygen -a "$alg" $bits -k "$zone")
    case $alg in RSA*) bits="-b 1024" ;; esac
    # shellcheck disable=SC2086
    zsk=$(ldns-keygen -a "$alg" $bits "$zone")
    case $denial in
        nsec) nsec3="" ;;
        nsec3) nsec3="-n -t $(echo "$spec" | cut -d: -f5)" ;;
        optout) nsec3="-n -p -t $(echo "$spec" | cut -d: -f5)" ;;
    esac
    salt=$(echo "$spec" | cut -d: -f4)
    if [ -n "$nsec3" ] && [ "$salt" != "-" ]; then nsec3="$nsec3 -s $salt"; fi
    # shellcheck disable=SC2086
    ldns-signzone -o "$zone" -i "$INCEPTION" -e "$EXPIRATION" $nsec3 \
        -z sha384 -z sha512 -f "$HERE/$name.signed" "$BIND9/signed.zone" "$ksk" "$zsk"
    {
        echo "; DS records of the KSK of $zone (ldns-key2ds)"
        for d in -1 -2 -4; do
            ldns-key2ds -n $d "$ksk.key"
        done
    } > "$HERE/$name.ds"
    {
        echo "; Throwaway keys of $zone made by ldns-keygen for the dnsbox tests."
        for k in "$ksk" "$zsk"; do
            echo "; $k.key"
            grep -v '^;' "$k.key"
            echo "; $k.private"
            sed 's/^/;! /' "$k.private"
        done
    } > "$HERE/$name.keys"
done
