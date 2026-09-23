#!/bin/sh
# @@NAME@@: reads the machine's mode once a minute and says it.
# lib/ffx.sh speaks the extension API through the image's curl; what this
# prints goes to the machine's log under the package's id.
. "$FFX_PKG/lib/ffx.sh"

ffx_get /v0/self > /dev/null && echo "started: $FFX_BODY"
while true; do
    if ffx_get /v0/machine/mode > /dev/null; then
        echo "mode: $FFX_BODY"
    else
        echo "the machine did not answer ($FFX_STATUS): $FFX_BODY"
    fi
    sleep 60
done
