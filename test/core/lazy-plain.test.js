// The runtime's own lazy fetch, with no lazy source: a program's read of a
// lazy file is a ranged request from its Worker, and a host that ignores
// Range and sends no Content-Length (the test server's `?plain`) is read
// from its whole answer, fetched once by that Worker rather than once a read.
import { System } from '../../page/runtime/src/index.js';
import { MemoryFilesystem } from '../../page/runtime/src/fs.js';

export const meta = { hosts: ['browser'], images: ['busybox'], timeout: 180 };

export default async function (t) {
  const { eq, check, timeout } = t;
  const sys = new System({ baseUrl: t.baseUrl, debug: t.debug() });
  const fs = new MemoryFilesystem(sys);
  const hits = async (name) => (await fetch(`/__t/hits?${encodeURIComponent(name)}`)).json();
  fs.addTar(t.work('bb.tar.zst'));
  const size = 3 << 20;
  fs.addTar(null, { lazy: [['/data/ranged', size, t.work('lazy-plain.bin')], ['/data/plain', size, `${t.work('lazy-plain2.bin')}?plain`]] });
  // (one server may run the test more than once: counted from here)
  const before = { 'lazy-plain.bin': await hits('lazy-plain.bin'), 'lazy-plain2.bin': await hits('lazy-plain2.bin') };
  await timeout(sys.boot(), 60000, 'boot');
  const env = { PATH: '/bin:/usr/bin', HOME: '/root' };
  const sh = (cmd) => timeout(sys.run(['sh', '-c', cmd], { env }), 60000, cmd);
  for (const [path, name] of [['/data/ranged', 'lazy-plain.bin'], ['/data/plain', 'lazy-plain2.bin']]) {
    const r = await sh(`cat ${path} > /tmp/copy`);
    const got = await fs.readFile('/tmp/copy');
    check(`${path} reads whole and right`, r.code === 0 && got.length === size && got.every((v) => v === 9), `code ${r.code}, ${got.length} bytes ${r.stderr.trim()}`);
    const n = (await hits(name)) - before[name];
    if (name === 'lazy-plain.bin') check('the ranged file in several requests', n >= 2, `${n}`);
    else eq('the plain host asked once (one Worker read it)', n, 1);
  }
  await sys.shutdown();
}
