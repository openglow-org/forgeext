# ffx.sh - a shell package's side of the ForgeFIRM extension API, version 0.1
# Copyright 2026 514 LLC d/b/a OpenGlow
# Written by Scott Wiederhold
# SPDX-License-Identifier: MIT
#
# Sourced by a shell package's service (busybox sh):
#
#     . "$FFX_PKG/lib/ffx.sh"
#     ffx_get /v0/self
#     ffx_post /v0/hold '{"raised": true, "reason": "no exhaust"}' || echo "refused: $FFX_BODY"
#
# A service reaches the machine through the Unix socket its environment names
# in FFX_API, and the image's curl is what speaks it. Each call prints the
# answer's body, keeps it in FFX_BODY and the status in FFX_STATUS, and
# returns 0 for a 200 and 1 for anything else (0 status: no answer at all).
# JSON in and out is the package's own: jsonfilter is not on the image, and a
# service that must read deep into an answer is better written in Python.

ffx_call() {
    # ffx_call METHOD PATH [JSON]
    _ffx_out=$(
        if [ -n "$3" ]; then
            curl -s --max-time 60 --unix-socket "$FFX_API" -X "$1" -H 'Content-Type: application/json' \
                --data-binary "$3" -w '\n%{http_code}' "http://forgeext$2"
        else
            curl -s --max-time 60 --unix-socket "$FFX_API" -X "$1" -w '\n%{http_code}' "http://forgeext$2"
        fi
    ) || true
    FFX_STATUS=${_ffx_out##*"
"}
    case "$FFX_STATUS" in
        000 | *[!0-9]* | '') FFX_STATUS=0; FFX_BODY= ;;
        *) FFX_BODY=${_ffx_out%"
"*} ;;
    esac
    printf '%s\n' "$FFX_BODY"
    [ "$FFX_STATUS" = 200 ]
}

ffx_get() { ffx_call GET "$1"; }
ffx_post() {
    if [ -n "$2" ]; then ffx_call POST "$1" "$2"; else ffx_call POST "$1" '{}'; fi
}

# ffx_hold 1|0 [REASON] - raise or clear this package's hold (granted). The
# reason is at most 95 bytes of printable ASCII without a quote or a backslash,
# which is what the host takes.
ffx_hold() {
    case "$1" in 1 | true) _r=true ;; *) _r=false ;; esac
    ffx_post /v0/hold "{\"raised\": $_r, \"reason\": \"$2\"}"
}
