// KUSER_SHARED_DATA's clocks under 64-bit Wine (usdclock.c), natively and on
// the page, with the door: a process reads SystemTime, InterruptTime and
// TickCount advancing at the rate of the elapsed time and never half written,
// from the host's one clock (gex.usd_tick), and has no thread of its own for
// them.
import { wine64 } from '../lib/winerun.mjs';

export const meta = { hosts: ['node'], arches: ['x86'], images: ['win-progs'], timeout: 1800 };

const allOk = /(ok [^\n]*\n)+0 failures/;

export default async function (t) {
  const w = wine64(t, { door: 1 });
  await w.nt({ name: 'usdclock', want: allOk, exe: 'usdclock.exe', args: ['3'], timeout: 600000 });
  await w.nt({ name: 'usdclock page', want: allOk, exe: 'usdclock.exe', args: ['3'], timeout: 600000, page: {} });
  w.clean();
}
