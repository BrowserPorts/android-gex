// Code running across a page boundary while the second page changes between
// calls (pagecross.c): its protection toggled, data beside the code written,
// the page decommitted and committed again, or decommitted so the call's
// fetch there faults to a vectored handler that maps it back. A block that
// runs onto a page whose translation is retired is lifted again or faults
// as Windows would, and never comes back to translation for ever: each case
// ends with every call right. The i386 program and the same program built
// for x86_64, natively and on the page.
import { wow64 } from '../lib/winerun.mjs';

export const meta = { hosts: ['node'], arches: ['x86'], timeout: 1500 };

export default async function (t) {
  const w = wow64(t);
  const want = /^pagecross ok/m;
  const timeout = 600000;
  const exe = await w.mingw('pagecross');
  const exe64 = await w.mingw('pagecross', { out: 'pagecross64.exe', x64: true });
  const n = await w.native(['C:\\pagecross.exe'], { files: { 'pagecross.exe': exe }, timeout });
  t.check(`native: ${want.source}`, want.test(n.out), w.detail(n));
  const n64 = await w.native(['C:\\pagecross64.exe'], { files: { 'pagecross64.exe': exe64 }, timeout, name: 'native64' });
  t.check(`native64: ${want.source}`, want.test(n64.out), w.detail(n64));
  const p = await w.page(['/t/pagecross.exe'], { files: { '/t/pagecross.exe': exe }, timeout });
  t.check(`page: ${want.source}`, want.test(p.out), w.detail(p));
  const p64 = await w.page(['/t/pagecross64.exe'], { files: { '/t/pagecross64.exe': exe64 }, timeout, name: 'page64' });
  t.check(`page64: ${want.source}`, want.test(p64.out), w.detail(p64));
  w.clean();
}
