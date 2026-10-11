// SPDX-License-Identifier: AGPL-3.0-only

/** Origin-controlled plaintext persistence; no hardware isolation, rollback protection or power-loss durability guarantee. */
export async function createManeKey(binary, {
  namespace,
  storage = globalThis.localStorage,
  locks = globalThis.navigator?.locks,
  crypto = globalThis.crypto,
  clock = () => globalThis.performance.now(),
  onPresence = () => {},
} = {}) {
  if (typeof namespace !== 'string' || !/^[A-Za-z0-9_.-]{1,128}$/.test(namespace)) {
    throw new Error('A distinct storage namespace is required');
  }
  if (!locks?.request || !crypto?.getRandomValues || !storage?.getItem || !storage?.setItem) {
    throw new Error('Web Locks, Web Crypto and persistent storage are required');
  }
  const prefix = `manekey/v1/${namespace}/`;
  let resolveReady, rejectReady;
  const ready = new Promise((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
  let release;
  const held = new Promise(resolve => { release = resolve; });
  let instance, closed = false, busy = false, lastPresence = 0n, pageLength;
  const bytes = (pointer, length) => new Uint8Array(instance.exports.memory.buffer, pointer, length);
  const key = (domain, page, length) => {
    if (![0, 1].includes(domain) || ![0, 1].includes(page) || ![1024, 4096].includes(length)) {
      throw new Error('Invalid storage geometry');
    }
    pageLength ??= length;
    if (pageLength !== length) throw new Error('Inconsistent storage geometry');
    return `${prefix}${domain}/${page}`;
  };
  const imports = { manekey_host: {
    entropy_fill(pointer, length) {
      try { crypto.getRandomValues(bytes(pointer, length)); return 1; } catch { return 0; }
    },
    page_read(domain, page, pointer, length) {
      try {
        const stored = storage.getItem(key(domain, page, length));
        const output = bytes(pointer, length);
        if (stored === null) { output.fill(0xff); return 1; }
        const decoded = globalThis.atob(stored);
        if (decoded.length !== length) return 0;
        for (let index = 0; index < length; index += 1) output[index] = decoded.charCodeAt(index);
        return 1;
      } catch { return 0; }
    },
    page_write(domain, page, pointer, length) {
      try {
        const entry = key(domain, page, length);
        const encoded = globalThis.btoa(Array.from(bytes(pointer, length), value => String.fromCharCode(value)).join(''));
        storage.setItem(entry, encoded);
        return storage.getItem(entry) === encoded ? 1 : 0;
      } catch { return 0; }
    },
    clock_millis() {
      try { return clock(); } catch { return Number.NaN; }
    },
  } };

  const lifetime = locks.request(prefix, { mode: 'exclusive', ifAvailable: true }, async lock => {
    if (!lock) { rejectReady(new Error('Storage namespace is already in use')); return; }
    try {
      const loaded = await WebAssembly.instantiate(binary, imports);
      instance = loaded.instance ?? loaded;
      const wasm = instance.exports;
      if (wasm.manekey_product_init() !== 1) throw new Error('ManeKey initialization failed');
      const run = action => {
        if (closed || busy) throw new Error('Runtime is closed or reentered');
        busy = true;
        try {
          const result = action();
          const request = wasm.manekey_product_pending_request();
          if (request !== lastPresence) {
            lastPresence = request;
            onPresence(request === 0n ? null : request);
          }
          return result;
        } finally { busy = false; }
      };
      const response = length => bytes(wasm.manekey_product_response_ptr(), length).slice();
      resolveReady(Object.freeze({
        submit(request) {
          if (!(request instanceof Uint8Array) || request.length === 0 || request.length > wasm.manekey_product_input_capacity()) {
            throw new Error('Invalid request length');
          }
          return run(() => {
            bytes(wasm.manekey_product_input_ptr(), request.length).set(request);
            return response(wasm.manekey_product_submit(request.length));
          });
        },
        poll() { return run(() => response(wasm.manekey_product_poll())); },
        cancel() { return run(() => wasm.manekey_product_cancel() === 1); },
        confirm(request) {
          if (typeof request !== 'bigint' || request <= 0n || request > 0xffffffffffffffffn) return false;
          return run(() => wasm.manekey_product_confirm(request) === 1);
        },
        async close() {
          if (closed) return;
          if (busy) throw new Error('Runtime is reentered');
          try { wasm.manekey_product_cancel(); } finally { closed = true; release(); }
          await lifetime;
        },
      }));
      await held;
    } catch (error) { rejectReady(error); }
    finally { closed = true; }
  });
  lifetime.catch(rejectReady);
  return ready;
}
