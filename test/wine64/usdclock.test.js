// KUSER_SHARED_DATA's clocks under 64-bit Wine (usdclock.c), natively and on
// the page, with the door: a process reads SystemTime, InterruptTime and
// TickCount advancing at the rate of the elapsed time and never half written,
// from the host's one clock (gex.usd_tick).
import { wine64 } from '../lib/winerun.mjs';

export const meta = { hosts: ['node'], arches: ['x86'], images: ['win-progs'], timeout: 1800 };

const allOk = /(ok [^\n]*\n)+0 failures/;

export default async function (t) {
  const w = wine64(t, { door: 1 });
  for (const [name, page] of [['usdclock', undefined], ['usdclock page', {}]]) {
    const r = await w.nt({ name, want: allOk, exe: 'usdclock.exe', args: ['3'], timeout: 600000, page });
    // the measured rates, in the log
    for (const l of (r?.stdout ?? '').split('\n').filter((x) => /^(ok|FAIL) usdclock/.test(x))) t.say(`${name}: ${l}`);
  }
  w.clean();
}
