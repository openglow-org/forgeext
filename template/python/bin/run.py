"""@@NAME@@: follows the machine's events and says what it saw.

It runs as the package's service: its own account, its own data directory
(FFX_DATA), and one way to the machine, the extension API socket that
lib/ffx.py speaks. What it prints goes to the machine's log under the
package's id.
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.environ["FFX_PKG"], "lib"))
import ffx  # noqa: E402

me = ffx.me()
print("started as %s %s, may use: %s" % (me["id"], me["version"], ", ".join(me["capabilities"])))
print("the machine is in %s mode" % ffx.machine.mode()["mode"])

started = time.monotonic()                      # the machine keeps no date: time with monotonic()
for ev in ffx.follow():
    print("%7.1f s  %s %s" % (time.monotonic() - started, ev["event"], ev.get("data")))
