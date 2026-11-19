// CompositorWindows sizes its canvas in device pixels: the backing store is the
// canvas's content box at the real devicePixelRatio (1.5 is 1.5, not 2), and
// follows a layout change and a change of scale (a zoom, another monitor) with
// the frames drawn at it. `scale: 1` turns it off: the page's own size.
import { System } from '../../page/runtime/src/index.js';
import { MemoryFilesystem } from '../../page/runtime/src/fs.js';
import { CompositorWindows } from '../../page/runtime/src/windows/compositor.js';

export const meta = {
  hosts: ['browser'], images: ['busybox'], timeout: 120,
  html: '<canvas id="a" style="position:absolute;left:0;top:0;width:400px;height:300px"></canvas>',
};

export default async function (t) {
  const { check, timeout, until } = t;
  const dsf = (deviceScaleFactor) => t.cdp({ method: 'Emulation.setDeviceMetricsOverride', width: 1000, height: 700, deviceScaleFactor, mobile: false });
  await dsf(1.5);
  await until(async () => devicePixelRatio === 1.5, 'devicePixelRatio 1.5', 5000);
  const sys = new System({ baseUrl: t.baseUrl, debug: t.debug() });
  new MemoryFilesystem(sys).addTar(t.work('bb.tar.zst'));
  const a = document.getElementById('a');
  const out = new CompositorWindows(sys, { canvas: a });
  await timeout(sys.boot(), 60000, 'boot');
  const seen = async (want) => {
    let d = null;
    await until(async () => { d = await out.describe({ pixels: false }); return d && `${d.output} ${d.scale}` === want; }, want, 10000)
      .catch((e) => { throw new Error(`${e.message}: ${d?.output} ${d?.scale}`); });
  };
  await seen('600x450 1.5');
  check('the backing store is the content box at 1.5', true);
  a.style.width = '500px'; a.style.height = '200px';
  await seen('750x300 1.5');
  check('a layout change resizes it', true);
  await dsf(2);
  await seen('1000x400 2');
  check('a change of scale resizes it and the frames are drawn at it', true);
  await dsf(1.25);
  await seen('625x250 1.25');
  check('and back down, unrounded', true);
  await sys.shutdown();
  // scale: 1, the page's own size: the canvas is left as it is.
  const sys2 = new System({ baseUrl: t.baseUrl, debug: t.debug() });
  new MemoryFilesystem(sys2).addTar(t.work('bb.tar.zst'));
  const c = document.createElement('canvas');
  c.width = 320; c.height = 200;
  c.style.cssText = 'position:absolute;left:600px;top:0;width:160px;height:100px';
  document.body.append(c);
  const out2 = new CompositorWindows(sys2, { canvas: c, scale: 1 });
  await timeout(sys2.boot(), 60000, 'boot');
  let d2 = null;
  await until(async () => (d2 = await out2.describe({ pixels: false }))?.output === '320x200', 'scale 1: 320x200', 10000)
    .catch((e) => { throw new Error(`${e.message}: ${d2?.output}`); });
  check('scale: 1 keeps the page\'s size', d2.scale === 1, String(d2.scale));
  await sys2.shutdown();
  await dsf(1);
}
