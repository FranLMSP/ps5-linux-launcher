// First payload: if an ELF loader already accepts connections on loopback, the
// console is already jailbroken. Hand that loader the bundled Linux loader
// directly and skip the WebKit/kernel exploit -- re-running the exploit is
// unnecessary and is where the "deserialize" noise comes from.
//
// If nothing is listening, continue with the normal exploit + autoload flow.
// The runner has prepared WebKit/ROP, so all of this works without kernel
// access: socket/connect/write, plus an anonymous mapping for the ELF bytes.
const NR = { SOCKET: 0x61, CONNECT: 0x62, WRITE: 4, CLOSE: 6, MMAP: 0x1dd, MUNMAP: 0x49 };
const DEFAULT_ELF = 'ps5-linux-loader.elf';
const FW12_ELF = 'ps5-linux-loader-12xx.elf';

function failed(value) {
  return (value.low | 0) === -1;
}

// A combined page embeds two loaders. The 12.xx loader is a different build:
// the all-11/13 one deliberately has no 12.xx tables. Payload args carry the
// resource names (default, 12.xx); a single arg remains a manual override.
function loaderCandidates(api) {
  const args = api && Array.isArray(api.args) ? api.args : [];
  const isTwelve = /^12\./.test(String((api && api.fw) || ''));
  let names;
  if (args.length >= 2) names = isTwelve ? [args[1], args[0]] : [args[0]];
  else if (args.length === 1) names = [args[0], DEFAULT_ELF];
  else names = isTwelve ? [FW12_ELF, DEFAULT_ELF] : [DEFAULT_ELF];
  return names.filter((name, index, all) => name && all.indexOf(name) === index);
}

async function stageElf(api, candidates) {
  let elfName = null;
  let response = null;
  for (let i = 0; i < candidates.length; i++) {
    try {
      const r = await fetch(candidates[i]);
      if (r.ok) { response = r; elfName = candidates[i]; break; }
    } catch (e) {}
  }
  if (!response || !elfName) throw new Error('Could not load ' + candidates.join(' or ') + '.');

  const bytes = await response.arrayBuffer();
  const view = new DataView(bytes);
  if (bytes.byteLength < 0x1000 || view.getUint32(0, true) !== 0x464c457f)
    throw new Error(elfName + ' is not an ELF binary.');

  const size = bytes.byteLength;
  const mapped = Math.ceil(size / 0x4000) * 0x4000;
  const base = await api.chain.syscall(NR.MMAP, 0, mapped, 3, 0x1002, -1, 0);
  if (failed(base)) throw new Error('Could not map ' + elfName + '.');
  try {
    let i = 0;
    for (; i + 4 <= size; i += 4) api.p.write4(base.add32(i), view.getUint32(i, true));
    for (; i < size; i++) api.p.write1(base.add32(i), view.getUint8(i));
    if ((api.p.read4(base) >>> 0) !== 0x464c457f)
      throw new Error(elfName + ' copy failed.');
    return { name: elfName, base, size, mapped };
  } catch (error) {
    await api.chain.syscall(NR.MUNMAP, base, mapped);
    throw error;
  }
}

return async function (api) {
  let fd = -1;
  let elf = null;
  let handoff = false;

  try {
    const addr = api.p.malloc(16, 1);
    for (let i = 0; i < 16; i++) api.p.write1(addr.add32(i), 0);
    // sockaddr_in: length, AF_INET, network-order port 9021, 127.0.0.1.
    [16, 2, 0x23, 0x3d, 127, 0, 0, 1].forEach((v, i) => api.p.write1(addr.add32(i), v));

    const socket = await api.chain.syscall(NR.SOCKET, 2, 1, 0);
    if (failed(socket)) throw new Error('Could not create the ELF loader probe socket.');
    fd = socket.low | 0;

    const connected = await api.chain.syscall(NR.CONNECT, fd, addr, 16);
    if (failed(connected)) {
      await api.log('No ELF loader is accepting connections on port 9021. Continuing.', 'info');
      return;
    }

    handoff = true;
    const candidates = loaderCandidates(api);
    const name = candidates[0];
    await api.log('ELF loader already running; sending ' + name + ' for FW ' +
      ((api && api.fw) || 'unknown') +
      ' directly and skipping the exploit.', 'info');

    elf = await stageElf(api, candidates);
    let sent = 0;
    while (sent < elf.size) {
      const want = Math.min(0x10000, elf.size - sent);
      const result = await api.chain.syscall(NR.WRITE, fd, elf.base.add32(sent), want);
      const count = result.low | 0;
      if (count <= 0 || count > want)
        throw new Error('ELF transfer failed after ' + sent + ' bytes.');
      sent += count;
    }
    await api.log('Sent ' + sent + ' bytes of ' + elf.name +
      ' to the already-running ELF loader.', 'success');
    api.stopQueue('Linux loader was sent to the already-running ELF loader');
  } catch (error) {
    api.stopQueue(handoff
      ? 'Could not hand the Linux loader to the already-running ELF loader'
      : 'Could not check whether the ELF loader is already running');
    throw error;
  } finally {
    try {
      if (elf) await api.chain.syscall(NR.MUNMAP, elf.base, elf.mapped);
    } finally {
      if (fd >= 0) {
        try {
          const closed = await api.chain.syscall(NR.CLOSE, fd);
          if (failed(closed)) throw new Error('Could not close the ELF loader probe socket.');
        } catch (error) {
          api.stopQueue('Could not close the ELF loader probe socket');
          throw error;
        }
      }
    }
  }
};
