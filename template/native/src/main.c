/*
 * @@NAME@@: a native service that reads the machine's mode once a minute.
 *
 * Built static for the machine's ARMv7 hard-float core, so nothing ties it
 * to the image's own libraries:
 *
 *     arm-linux-gnueabihf-gcc -static -O2 -Wall -o bin/run src/main.c
 *
 * (Debian and Ubuntu: apt install gcc-arm-linux-gnueabihf.) What it prints
 * goes to the machine's log under the package's id.
 */
#define FFX_IMPLEMENTATION
#include "ffx.h"

#include <stdio.h>
#include <unistd.h>

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    for (;;) {
        ffx_reply_t r;
        if (ffx_request("GET", "/v0/machine/mode", NULL, &r, 10000) == 0)
            printf("mode (%d): %s\n", r.status, r.body);
        else
            printf("the extension host did not answer\n");
        ffx_reply_free(&r);
        sleep(60);
    }
}
