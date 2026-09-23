/*
 * ffx-bridge.js - a package page's side of the control panel's bridge
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * A package's page runs in a sandboxed frame that can reach nothing: no
 * network, no session, no panel. Everything it wants it asks the panel for
 * over postMessage, and the panel decides by what the package may use. This
 * is the asking side: one promise per call, resolved with the panel's answer
 * or rejected with its words. A page is one self-contained file, so this
 * script is pasted into it (inside a <script> element) rather than loaded.
 *
 *   ffx.self()                          -> {id, version, tier, capabilities}
 *   ffx.machine.status() / .cool() / .mode()               (machine.read)
 *   ffx.settings.get() / .set({key: value})               (settings.own)
 *   ffx.camera.frame({camera, resolution, quality, lamp})  -> a Blob (JPEG)
 *   ffx.motion.jog({x, y, z, feed}) / .cancel()           (motion.jog)
 *   ffx.motion.job({program, lit_within_s, timeout_s})    (motion.job)
 *   ffx.motion.jobState() / .jobAbort()                   (motion.job)
 *   ffx.frame.height(px)                                  -> {px}, inside the panel's bounds
 *   ffx.service.call(method, path, body)                  -> {status, body}, from the package's own service
 *
 * Extension API 0.1. The panel answers only its own frame's parent window,
 * and this script listens to nothing else.
 */
var ffx = (function () {
  'use strict';
  var n = 0,
    waiting = {};

  window.addEventListener('message', function (ev) {
    var m = ev.data;
    if (ev.source !== window.parent || !m || m.forgefirm !== 1 || !waiting[m.id]) return;
    var w = waiting[m.id];
    delete waiting[m.id];
    clearTimeout(w.timer);
    if (m.ok) w.ok(m.value);
    else w.err(new Error(m.error || 'refused'));
  });

  /* One call. A camera frame can take seconds (the camera starts, and a
   * capture waits for a viewer to go), so the default wait is long. */
  function call(name, args, waitMs) {
    return new Promise(function (ok, err) {
      var id = ++n;
      waiting[id] = {
        ok: ok,
        err: err,
        timer: setTimeout(function () {
          if (!waiting[id]) return;
          delete waiting[id];
          err(new Error('the panel did not answer ' + name));
        }, waitMs || 40000)
      };
      window.parent.postMessage({ forgefirm: 1, id: id, call: name, args: args }, '*');
    });
  }

  return {
    version: '0.1',
    call: call,
    self: function () { return call('self'); },
    machine: {
      status: function () { return call('machine.status'); },
      cool: function () { return call('machine.cool'); },
      mode: function () { return call('machine.mode'); }
    },
    settings: {
      get: function () { return call('settings.get'); },
      set: function (patch) { return call('settings.set', patch); }
    },
    camera: {
      frame: function (opts) { return call('camera.frame', opts || { camera: 'lid' }, 60000); }
    },
    motion: {
      jog: function (move) { return call('motion.jog', move, 120000); },
      cancel: function () { return call('motion.cancel'); },
      job: function (spec) { return call('motion.job', spec); },
      jobState: function () { return call('motion.job.state'); },
      jobAbort: function () { return call('motion.job.abort'); }
    },
    frame: {
      height: function (px) { return call('frame.height', { px: px }); }
    },
    /* The package's own service answers; the host waits ten seconds for it. */
    service: {
      call: function (method, path, body) {
        return call('service.call', { method: method, path: path, body: body }, 20000);
      }
    }
  };
})();
