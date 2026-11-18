import { defineConfig } from 'vite';
import { fileURLToPath } from 'node:url';

// The runtime package's build (page/runtime/build.sh) starts from this.
//
// GEX_PAGE_MODE=mp|sp: a bundle carries one build's code (hosts/browser/js/mode.mjs),
// the other's dropped, as page/runtime/build.sh does for the packages. Unset: both.
const MODE = process.env.GEX_PAGE_MODE || '';
if (MODE && MODE !== 'mp' && MODE !== 'sp') throw new Error(`GEX_PAGE_MODE=${MODE}: mp or sp`);
const pageMode = {
  name: 'gex-page-mode',
  enforce: 'pre',
  load: (id) => MODE && /\/shims\/browser\/js\/mode\.mjs$/.test(id.split('?')[0])
    ? `export const SP_CODE = ${MODE === 'sp'};\nexport const MP_CODE = ${MODE === 'mp'};\n`
    : null,
  // A Worker's chunk is emitted wherever `new Worker(new URL(...))` appears,
  // dead branch or not, so the MP page drops the single-thread system
  // Worker's construction here (kernel.js singleWorker throws before it).
  transform(code, id) {
    if (MODE !== 'mp' || !/\/runtime\/src\/kernel\.js$/.test(id.split('?')[0])) return null;
    const single = "new Worker(new URL('./kernel-single-worker.js', import.meta.url), { type: 'module', name: 'gex-system' })";
    if (!code.includes(single)) this.error('kernel.js no longer starts the single-thread Worker as vite.config.js expects');
    return code.replace(single, 'null');
  },
};

export default defineConfig({
  plugins: [pageMode],
  // GEX_FEATURES_OFF=compositor,...: a bundle without them, the code behind
  // each constant dropped.
  define: {
    __GEX_COMPOSITOR__: JSON.stringify(!(process.env.GEX_FEATURES_OFF || '').split(',').includes('compositor')),
  },
  build: {
    target: 'es2022',
    chunkSizeWarningLimit: 2048,
  },
  // `worker.mjs` is an ES module with top-level await; the default `iife`
  // worker output cannot express that.
  //
  // Each Worker is one file, its dynamic imports inlined. Split, the chunks a
  // Worker imports lazily take the helpers they share from the Worker's own
  // file, an import cycle (worker -> wl-bridge -> worker). The page starts
  // every guest Worker from one fetched copy of its module graph
  // (worker-graph.js), which a cycle defeats: each Worker then fetched its
  // files again, ~27 MB a desktop start on an origin without an HTTP cache.
  worker: { format: 'es', plugins: () => [pageMode], rolldownOptions: { output: { inlineDynamicImports: true } } },
  resolve: {
    alias: {
      // A page built over this config (a test page) reaches the shim's
      // modules as `@gex/...`.
      '@gex': fileURLToPath(new URL('../hosts/browser/js', import.meta.url)),
    },
  },
});
