// Exercise the real check payload through the upstream standalone queue runner.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const source = fs.readFileSync('payloads/elfldr-check.js', 'utf8');

function pointer(low) {
  return { low: low >>> 0, hi: low < 0 ? 0xffffffff : 0,
    add32(n) { return pointer(this.low + n); } };
}

function makeElf(size = 0x1007) {
  const bytes = new Uint8Array(size);
  bytes.set([0x7f, 0x45, 0x4c, 0x46]);
  for (let i = 4; i < bytes.length; i++) bytes[i] = i & 255;
  return bytes;
}

(async () => {
  const { runPayloadQueue } = await import(pathToFileURL(path.resolve(
    'third_party/ps5-webkit-remote-loader/src/standalone.js')).href);

  async function run(options = {}) {
    const elfBytes = makeElf();
    const memory = new Map(), calls = [], logs = [], fetched = [], written = [];
    const fd = options.fd ?? 12;
    const mapped = 0x30000000;
    let next = 0x20000000, unmapped = 0, closed = 0;
    const expectedElf = (options.args && options.args[0]) || 'ps5-linux-loader.elf';

    globalThis.window = globalThis;
    globalThis.fw_str = '11.00';
    globalThis.writeLog = (message, type) => logs.push({ message, type });
    globalThis.fetch = async (name) => {
      fetched.push(name);
      if (options.fetchThrows) throw new Error('fetch failed unexpectedly');
      return {
        ok: !options.fetchFails && name === expectedElf,
        arrayBuffer: async () => options.badElf ? new ArrayBuffer(8) : elfBytes.buffer,
      };
    };

    const p = {
      malloc(size) { const addr = pointer(next); next += size; return addr; },
      write1(addr, value) { memory.set(addr.low, value & 255); },
      write4(addr, value) {
        for (let i = 0; i < 4; i++) memory.set(addr.low + i, (value >>> (i * 8)) & 255);
      },
      read4(addr) {
        return [0, 1, 2, 3].reduce((v, i) => v | (memory.get(addr.low + i) << (i * 8)), 0);
      },
    };
    const chain = { async syscall(nr, ...args) {
      calls.push({ nr, args });
      if (nr === 0x61) {
        assert.deepEqual(args, [2, 1, 0]);
        return pointer(options.socketFails ? -1 : fd);
      }
      if (nr === 0x62) {
        assert.equal(args[0], fd);
        assert.equal(args[2], 16);
        assert.deepEqual(Array.from({ length: 16 }, (_, i) => memory.get(args[1].low + i)),
          [16, 2, 0x23, 0x3d, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
        if (options.connectThrows) throw new Error('connect failed unexpectedly');
        return pointer(options.listening ? 0 : -1);
      }
      if (nr === 0x1dd) return pointer(options.mmapFails ? -1 : mapped);
      if (nr === 4) {
        if (options.writeFails) return pointer(-1);
        const count = Math.min(args[2], options.shortWrite || args[2]);
        for (let i = 0; i < count; i++) written.push(memory.get(args[1].low + i));
        return pointer(count);
      }
      if (nr === 0x49) { unmapped++; return pointer(0); }
      if (nr === 6) {
        assert.equal(args[0], fd);
        closed++;
        if (options.closeThrows) throw new Error('close failed unexpectedly');
        return pointer(options.closeFails ? -1 : 0);
      }
      throw new Error('ELF loader check must not run another syscall: ' + nr);
    } };
    const summary = await runPayloadQueue({ p, chain, payloads: [
      { name: 'elfldr-check.js', source, args: options.args || [] },
      { name: 'kernel.js', source: `return async function (api) {
        if (api.krw) throw new Error('check must run before kernel access');
        api.krw = {}; await api.log('kernel marker');
      };` },
      { name: 'autoload.js', source: `return async function (api) {
        if (!api.krw) throw new Error('kernel must run before autoload');
        await api.log('autoload marker');
      };` },
    ] });
    return { summary, calls, fetched, written, elfBytes, unmapped, closed,
      text: logs.map(log => log.message).join('\n') };
  }

  // An existing loader gets the bundled ELF directly; the exploit and autoload
  // are skipped and no kernel access is needed. Descriptor 0 must also work.
  for (const options of [{ listening: true, fd: 0 }, { listening: true, fd: 12 },
    { listening: true, args: ['ps5-linux-loader.elf'] },
    { listening: true, args: ['custom-loader.elf'] }]) {
    const result = await run(options);
    assert.equal(result.summary.stopped, true, JSON.stringify(options));
    assert.equal(result.summary.run, 1);
    assert.equal(result.summary.failed, 0);
    assert.equal(result.summary.skipped, 2);
    assert.equal(result.summary.ok, true);
    assert(!result.text.includes('kernel marker'));
    assert(!result.text.includes('autoload marker'));
    assert.deepEqual(result.written, [...result.elfBytes]);
    assert.equal(result.unmapped, 1);
    assert.equal(result.closed, 1);
    assert.deepEqual(result.fetched,
      [(options.args && options.args[0]) || 'ps5-linux-loader.elf']);
    assert.deepEqual(result.calls.map(call => call.nr), [0x61, 0x62, 0x1dd, 4, 0x49, 6]);
  }

  // Short writes are retried until the whole ELF has been handed over.
  const short = await run({ listening: true, shortWrite: 113 });
  assert.equal(short.summary.failed, 0);
  assert.deepEqual(short.written, [...short.elfBytes]);

  // A refused connection allows the kernel exploit and autoload to run in order.
  // Nothing is fetched or mapped because there is no loader to hand it to.
  const absent = await run();
  assert.equal(absent.summary.run, 3);
  assert.equal(absent.summary.failed, 0);
  assert(!absent.summary.stopped);
  assert(absent.text.indexOf('kernel marker') < absent.text.indexOf('autoload marker'));
  assert.deepEqual(absent.calls.map(call => call.nr), [0x61, 0x62, 6]);
  assert.deepEqual(absent.fetched, []);

  // Any hand-off failure stops the queue instead of falling back to a blind
  // kernel exploit. Mapping cleanup happens whenever the ELF was mapped.
  for (const options of [{ listening: true, fetchFails: true },
    { listening: true, fetchThrows: true }, { listening: true, badElf: true },
    { listening: true, mmapFails: true }, { listening: true, writeFails: true },
    { listening: true, closeThrows: true }, { listening: true, closeFails: true }]) {
    const result = await run(options);
    assert.equal(result.summary.stopped, true, JSON.stringify(options));
    assert.equal(result.summary.failed, 1, JSON.stringify(options));
    assert.equal(result.summary.skipped, 2);
    assert(!result.text.includes('kernel marker'));
    assert(!result.text.includes('autoload marker'));
    const mapped = !options.fetchFails && !options.fetchThrows && !options.badElf && !options.mmapFails;
    assert.equal(result.unmapped, mapped ? 1 : 0, JSON.stringify(options));
    assert.equal(result.closed, 1, JSON.stringify(options));
  }

  // Probe failures before any hand-off attempt also stop the queue.
  for (const options of [{ socketFails: true }, { connectThrows: true },
    { closeThrows: true }, { closeFails: true }]) {
    const result = await run(options);
    assert.equal(result.summary.stopped, true, JSON.stringify(options));
    assert.equal(result.summary.failed, 1, JSON.stringify(options));
    assert.equal(result.summary.skipped, 2);
    assert(!result.text.includes('kernel marker'));
    assert(!result.text.includes('autoload marker'));
    assert.equal(result.calls.filter(call => call.nr === 6).length,
      options.socketFails ? 0 : 1);
  }

  console.log('ELF loader check passed: an accepted socket receives the loader directly; refused sockets continue; hand-off errors stop safely; nothing is sent to a missing loader.');
})().catch(error => { console.error(error); process.exitCode = 1; });
