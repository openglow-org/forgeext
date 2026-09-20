#!/bin/sh
# Copyright 2026 514 LLC d/b/a OpenGlow
# Written by Scott Wiederhold
# SPDX-License-Identifier: MIT
#
# mkffx.sh - pack a package directory into an extension archive (.ffx).
#
#   tools/mkffx.sh <package-dir> <out.ffx> [<private-key>]
#
# <package-dir> holds manifest.json at its top. The archive is an fwup
# archive with the product "ForgeFIRM extension", one resource
# (payload.tar.gz), and no task. With a private key (made with `fwup -g`)
# it is signed and the signature is checked against <private-key>'s .pub
# before the script reports success; without one the output is unsigned,
# which a machine installs only with the button held.
#
#   FWUP   the fwup binary (default: fwup on PATH)
#
# The payload is built the same way every time: sorted names, owner 0,
# time 0, no gzip timestamp. Two runs over the same directory give the same
# payload hash.
set -eu

[ $# -ge 2 ] || { sed -n '6,20p' "$0" >&2; exit 2; }
DIR=$1
OUT=$2
KEY=${3:-}
FWUP=${FWUP:-fwup}

[ -f "$DIR/manifest.json" ] || { echo "ERROR: $DIR has no manifest.json" >&2; exit 1; }
command -v "$FWUP" >/dev/null 2>&1 || { echo "ERROR: fwup not found (set FWUP)" >&2; exit 1; }

# The two fields the archive's own metadata repeats. The machine holds the
# archive's version to the manifest's, so a mismatch is caught there too.
field() {
    sed -n "s/^[[:space:]]*\"$1\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$DIR/manifest.json" | sed -n 1p
}
ID=$(field id)
VERSION=$(field version)
[ -n "$ID" ] && [ -n "$VERSION" ] || { echo "ERROR: manifest.json gives no id or no version on a line of its own" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM

tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@0 -C "$DIR" -cf "$WORK/payload.tar" .
gzip -n -9 "$WORK/payload.tar"

cat > "$WORK/fwup.conf" <<EOF
meta-product = "ForgeFIRM extension"
meta-description = "$ID"
meta-version = "$VERSION"
meta-platform = "forgefirm-ext"
file-resource payload.tar.gz {
    host-path = "$WORK/payload.tar.gz"
}
EOF

"$FWUP" -c -f "$WORK/fwup.conf" -o "$WORK/unsigned.ffx"

if [ -n "$KEY" ]; then
    [ -f "$KEY" ] || { echo "ERROR: private key '$KEY' not found" >&2; exit 1; }
    PUB="${KEY%.priv}.pub"
    [ -f "$PUB" ] || { echo "ERROR: public key '$PUB' not found - cannot check the signature; refusing to pack unverified" >&2; exit 1; }
    "$FWUP" -S -s "$KEY" -i "$WORK/unsigned.ffx" -o "$WORK/signed.ffx"
    "$FWUP" -V -i "$WORK/signed.ffx" -p "$PUB" >/dev/null || { echo "ERROR: signature self-check failed" >&2; exit 1; }
    cp "$WORK/signed.ffx" "$OUT"
    echo "signed: $OUT ($ID $VERSION)"
else
    cp "$WORK/unsigned.ffx" "$OUT"
    echo "UNSIGNED: $OUT ($ID $VERSION)"
fi
