//! Dense block tables on the native host (`gex_emit::dense`; the page's
//! half is `hosts/browser/src/dense.rs`). `GEX_DENSE=1` turns them on.
//!
//! Why: every guest thread is a store of its own, and a wasm table cannot
//! be shared between stores, so classically each thread's dispatch tables
//! held a slot for every four bytes of every page of code the system had
//! numbered (eight bytes a slot) and its instances a function reference
//! for every block (32 bytes): some 25 MiB a thread in a booting Android,
//! which the host could not hold. Dense, a page's slots are `u32` words in
//! the process's own memory, one set for all its threads (the *slot
//! maps*), each naming an entry of one more table, `blocks`, and an arm;
//! an entry is a function of up to 256 blocks. A thread's `blocks` holds
//! an entry per 256 blocks its process installed.
//!
//! * Runtime translations are numbered in tables `FIRST_TABLE..` (4 to 7),
//!   which are the dense ones; the program's image keeps tables 0 to 3.
//! * The maps are made whole when the process is set up, below 4 GiB (the
//!   dispatch code computes with 32-bit addresses), and their pages cost
//!   nothing until a word is written. Their addresses are in the reserved
//!   low region (`dense::MAPS`), where the dispatch code reads them.
//! * A module is given its range of `blocks` when it is published
//!   ([`Maps::register`]; the count is the `JitShared`'s, which a forked
//!   child shares), and the words of its slots are written when a store
//!   installs it ([`Blocks::write`]), into that store's process's memory,
//!   as its directory entries are: a forked child shares its parent's
//!   registry but not its memory (whose maps it got a copy of at the fork,
//!   zero pages skipped). A thread that has not instantiated a module
//!   whose words are there finds an empty entry, which traps; the trap is
//!   answered as a stale table's is (`catch_up_and_resume`: the page's
//!   modules are taken, else the entry is given the miss wrapper,
//!   [`fill`]).
//! * Its base reaches it at instantiation (the `dense_base` global), so
//!   its bytes, and the cache's key for them, do not depend on it.
//!
//! Not yet: the function tier's bridges and call-out watches on dense
//! slots, x86's other mode.

use anyhow::{anyhow, bail, Result};
use gex_emit::dense::{self, Section};

/// Whether this run asked for dense tables (`GEX_DENSE=1`).
pub(crate) fn wanted() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("GEX_DENSE").is_ok_and(|v| v != "0"))
}

/// Turn dense emission on for this run, before anything is translated,
/// where the run can have it; says why not where it cannot.
pub(crate) fn start() {
    if !wanted() || dense::on() {
        return;
    }
    if gex_abi::X86 {
        eprintln!("gex: GEX_DENSE: not for x86 yet (its other mode's directory); classic tables");
        return;
    }
    if gex_emit::profile::enabled() {
        eprintln!("gex: GEX_DENSE: not with profiling (its module defines global 0); classic tables");
        return;
    }
    dense::set(true);
}

pub(crate) fn on() -> bool {
    dense::on()
}

/// The first virtual slot runtime translations are numbered from: the
/// first dense table's, when dense.
pub(crate) fn first_slot(next: u64) -> u64 {
    if on() {
        next.max(dense::FIRST_TABLE as u64 * gex_xlate::PageTable::slots_per_table())
    } else {
        next
    }
}

/// A process's dense numbering and maps, kept with its `JitShared`.
#[derive(Clone, Debug, Default)]
pub(crate) struct Maps {
    /// The next free index of `blocks` (0 is the miss wrapper's).
    next: u32,
    /// Each dense table's slot map: its guest address, 0 for none.
    map: [u64; dense::TABLES],
}

/// A whole slot map's bytes.
const MAP_BYTES: u64 = dense::MAP_SLOTS * 4;

/// Write the word at `addr` of the guest's memory, as the directory's
/// entries are written (`write_dispatch_dir`): four aligned bytes.
fn put(memory: &gex_mem::GuestMemory, addr: u64, w: u32) -> Result<()> {
    let data = memory.bytes();
    let off = addr as usize;
    if addr % 4 != 0 || off + 4 > data.len() {
        bail!("dense slot word {addr:#x} is outside the guest's memory");
    }
    data[off..off + 4].copy_from_slice(&w.to_le_bytes());
    Ok(())
}

fn get(memory: &gex_mem::GuestMemory, addr: u64) -> Option<u32> {
    gex_kernel::GuestMem::new(memory.bytes()).read_u32(addr).ok()
}

impl Maps {
    /// The maps for a process being set up, before anything is translated
    /// in it: each table's whole, below 4 GiB, its address in the low
    /// region.
    pub(crate) fn make(state: &mut crate::HostState) -> Result<Maps> {
        let memory = state.memory.clone().ok_or_else(|| anyhow!("guest memory unavailable"))?;
        let mut m = Maps { next: 1, map: [0; dense::TABLES] };
        for k in 0..dense::TABLES {
            let at = crate::libprov::alloc_above_code(state, MAP_BYTES, "[gex dense slot map]")?;
            if at == 0 || at + MAP_BYTES > 1 << 32 {
                bail!("dense slot map {k} at {at:#x} is not below 4 GiB");
            }
            m.map[k] = at;
            put(&memory, dense::MAPS + 4 * k as u64, at as u32)?;
        }
        Ok(m)
    }

    /// Give a module just compiled its range of `blocks`: `None` for a
    /// module with no dense blocks. Under the `JitShared` lock.
    pub(crate) fn register(&mut self, wasm: &[u8]) -> Result<Option<Section>> {
        if !on() {
            return Ok(None);
        }
        let Some(at) = dense::locate(wasm) else {
            if dense::has_section(wasm) {
                bail!("a translation's dense section cannot be read");
            }
            return Ok(None);
        };
        let Some(mut s) = dense::section(wasm, &at) else { bail!("a translation's dense section cannot be read") };
        s.base = self.next.max(1);
        self.next = s.base + s.span();
        Ok(Some(s))
    }

    /// The maps' addresses.
    pub(crate) fn maps(&self) -> [u64; dense::TABLES] {
        self.map
    }

    /// How long a thread's `blocks` must be for everything numbered.
    pub(crate) fn len(&self) -> u32 {
        self.next.max(1)
    }

}

/// `(ctx) -> ()` made `(ctx, arm) -> ()`: what an entry of `blocks` must
/// be. The miss stub is a block, and `blocks[0]` and every entry a thread
/// has not instantiated must reach it, the arm dropped.
/// (module (type (func (param i32))) (type (func (param i32 i32)))
///   (import "w" "f" (func (type 0)))
///   (func (export "e") (type 1) local.get 0 return_call 0))
const ENTRY_WRAP: &[u8] = &[
    0, 97, 115, 109, 1, 0, 0, 0, //
    1, 10, 2, 96, 1, 127, 0, 96, 2, 127, 127, 0, //
    2, 7, 1, 1, 119, 1, 102, 0, 0, //
    3, 2, 1, 1, //
    7, 5, 1, 1, 101, 0, 1, //
    10, 8, 1, 6, 0, 32, 0, 18, 0, 11,
];

/// The miss stub as an entry, in this store.
pub(crate) fn miss_entry(
    mut cx: impl wasmtime::AsContextMut<Data = crate::HostState>,
    engine: &wasmtime::Engine,
    miss: wasmtime::Func,
) -> Result<wasmtime::Func> {
    static MODULE: std::sync::Mutex<Vec<(wasmtime::Engine, wasmtime::Module)>> = std::sync::Mutex::new(Vec::new());
    let module = {
        let mut g = MODULE.lock().unwrap_or_else(|e| e.into_inner());
        match g.iter().find(|(e, _)| wasmtime::Engine::same(e, engine)) {
            Some((_, m)) => m.clone(),
            None => {
                let m = wasmtime::Module::new(engine, ENTRY_WRAP)?;
                g.push((engine.clone(), m.clone()));
                m
            }
        }
    };
    let instance = wasmtime::Instance::new(cx.as_context_mut(), &module, &[miss.into()])?;
    instance.get_func(cx.as_context_mut(), "e").ok_or_else(|| anyhow!("the entry wrapper has no export"))
}

/// A store's `blocks` and its miss entry, and its process's maps.
#[derive(Clone, Debug)]
pub(crate) struct Blocks {
    pub table: wasmtime::Table,
    pub miss: wasmtime::Func,
    map: [u64; dense::TABLES],
}

impl Blocks {
    /// The image instance's `blocks`, its entry 0 the miss wrapper: `None`
    /// when dispatch is not dense.
    pub(crate) fn of(
        mut cx: impl wasmtime::AsContextMut<Data = crate::HostState>,
        engine: &wasmtime::Engine,
        instance: &wasmtime::Instance,
        miss: wasmtime::Func,
        maps: &Maps,
    ) -> Result<Option<Blocks>> {
        if !on() {
            return Ok(None);
        }
        let table = instance
            .get_table(cx.as_context_mut(), dense::TABLE_NAME)
            .ok_or_else(|| anyhow!("the translated image does not export `{}`", dense::TABLE_NAME))?;
        let miss = miss_entry(cx.as_context_mut(), engine, miss)?;
        if table.size(cx.as_context_mut()) == 0 {
            table.grow(cx.as_context_mut(), 1, wasmtime::Ref::Func(None))?;
        }
        table.set(cx.as_context_mut(), 0, miss.into())?;
        Ok(Some(Blocks { table, miss, map: maps.maps() }))
    }

    /// Point a module's slots at its entries, in this store's process's
    /// memory: when the store installs it. Not a slot a module published
    /// after it points at already: dense bases are given in publish order,
    /// so a word naming a higher entry is a later translation's (the page
    /// translated again, or another thread's that won it), and stays.
    ///
    /// The maps are the process's, and its threads install modules in no
    /// fixed order: a lazy thread takes a page's newest unit first and
    /// older ones later. An older one written over the newer word sent
    /// dispatch to a block whose page check had failed, which then failed
    /// it for ever (the zygote, spinning before it forked `system_server`).
    pub(crate) fn write(&self, memory: &gex_mem::GuestMemory, s: &Section) -> Result<()> {
        for (j, &e) in s.entries.iter().enumerate() {
            let k = gex_abi::dispatch_entry_table(e);
            if !dense::table(k) {
                continue;
            }
            let slot = gex_abi::dispatch_entry_base(e) as u64;
            let map = self.map[k - dense::FIRST_TABLE];
            if map == 0 || slot >= dense::MAP_SLOTS {
                bail!("dense slot {slot} of table {k} has no map");
            }
            let word = s.word(j);
            if get(memory, map + 4 * slot).is_some_and(|old| old >> 8 > word >> 8) {
                continue;
            }
            put(memory, map + 4 * slot, word)?;
        }
        Ok(())
    }

    /// The word of the slot `table`/`index` names, where the table is dense.
    pub(crate) fn word_at(&self, memory: &gex_mem::GuestMemory, table: usize, index: u64) -> Option<u32> {
        if !dense::table(table) || index >= dense::MAP_SLOTS {
            return None;
        }
        let map = self.map[table - dense::FIRST_TABLE];
        (map != 0).then(|| get(memory, map + 4 * index)).flatten()
    }

    /// Long enough for `len` entries, the new ones empty (an empty entry a
    /// dispatch reaches traps, and is answered by [`fill`]).
    pub(crate) fn reach(&self, mut cx: impl wasmtime::AsContextMut<Data = crate::HostState>, len: u32) -> Result<()> {
        let have = self.table.size(cx.as_context_mut());
        if (len as u64) > have {
            self.table.grow(cx.as_context_mut(), len as u64 - have, wasmtime::Ref::Func(None))?;
        }
        Ok(())
    }
}

/// A dispatch to a dense slot whose entry this store has nothing in, or
/// has not got: the entry is given the miss wrapper, and the dispatch
/// made again translates or catches up. Whether that was the case.
pub(crate) fn fill(mut cx: impl wasmtime::AsContextMut<Data = crate::HostState>, blocks: &Blocks, word: u32) -> Result<bool> {
    let index = dense::index_of(word) as u64;
    if index == 0 {
        return Ok(false);
    }
    let have = blocks.table.size(cx.as_context_mut());
    if index >= have {
        blocks.table.grow(cx.as_context_mut(), index + 1 - have, wasmtime::Ref::Func(None))?;
    } else if !matches!(blocks.table.get(cx.as_context_mut(), index), Some(wasmtime::Ref::Func(None))) {
        return Ok(false);
    }
    blocks.table.set(cx.as_context_mut(), index, blocks.miss.into())?;
    Ok(true)
}
