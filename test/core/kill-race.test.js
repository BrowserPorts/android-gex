// A process that crashes in the runtime is reported (System's `crash`
// event) even when another process kills it at the same moment: rt-probe
// killrace's child crashes the kernel on purpose (prctl PR_GEX_DEBUG_TRAP,
// armed by `debugpanic=prctl`), and its sibling sends it SIGKILL as soon as
// it says it is about to, so the kill lands while the crashed child's
// Worker is ending. Before, the kill's end claimed the process first and
// the crash was never said.
import { System } from '../../page/runtime/src/index.js';
import { MemoryFilesystem } from '../../page/runtime/src/fs.js';

export const meta = { hosts: ['node', 'browser'], images: ['busybox'], timeout: 300 };

const ROUNDS = 8;

export default async function (t) {
  const { check, eq, timeout } = t;
  const sys = new System({ baseUrl: t.baseUrl, debug: { ...t.debug(), debugpanic: 'prctl' } });
  const fs = new MemoryFilesystem(sys);
  fs.addTar(t.work('bb.tar.zst'));
  const crashes = [];
  sys.addEventListener('crash', (e) => crashes.push({ pid: e.pid, name: e.name, reason: e.reason, code: e.code, signal: e.signal }));
  await timeout(sys.boot(), 60000, 'boot');
  const r = await sys.run(['rt-probe', 'killrace', String(ROUNDS)], { env: { PATH: '/bin:/usr/bin' } });
  eq('killrace: it ran to its end', r.code, 0);
  const rounds = r.stdout.split('\n').filter((l) => l.startsWith('round ')).map((l) => l.split(' ').map(Number));
  eq('killrace: every round', rounds.length, ROUNDS);
  for (let i = 0; i < 100 && crashes.length < rounds.length; i++) await new Promise((res) => setTimeout(res, 50));
  t.say(`rounds: ${JSON.stringify(rounds)} crashes: ${JSON.stringify(crashes)}`);
  for (const [, n, , pid, status] of rounds) {
    const c = crashes.find((x) => x.pid === pid);
    check(`round ${n}: pid ${pid} (status ${status}) is reported as a crash`, !!c, `crash reports: ${JSON.stringify(crashes)}`);
  }
  await sys.shutdown();
}
