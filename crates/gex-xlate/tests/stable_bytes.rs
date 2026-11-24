//! A runtime translation's bytes are what a translation cache is keyed by,
//! so the same guest code has to give the same bytes in every process,
//! whatever the process numbered for it. Under
//! `gex_emit::with_instantiation_globals` and dense dispatch (how the native
//! host translates), the slot bases its page checks expect and its dense
//! blocks' entries are given to each instance, not written in: the same
//! code given different slots, as a process whose other threads met other
//! pages first gives it, is the same bytes, and only `page_globals` and
//! `dense_entries` differ.
//!
//! Its own test binary: dense dispatch is a switch for the whole process.

#![cfg(not(feature = "x86"))]

use gex_xlate::{translate_runtime, BlockLimits, PageTable};

#[test]
fn the_same_code_numbered_otherwise_is_the_same_bytes() {
    gex_emit::dense::set(true);
    // add x0, x0, #1 at a page's last word; ret on the next page.
    let mut mem = vec![0u8; 0x20000];
    mem[0x10ffc..0x11000].copy_from_slice(&0x9100_0400u32.to_le_bytes());
    mem[0x11000..0x11004].copy_from_slice(&0xd65f_03c0u32.to_le_bytes());
    let at = |first: u64| {
        let mem = &mem;
        move || {
            let mut pages = PageTable::new();
            pages.advance_to(first);
            translate_runtime(
                mem,
                0x10ffc,
                &|a| (0x10000..0x12000).contains(&a),
                &|_| false,
                pages,
                BlockLimits::default(),
                16,
                true,
                &Default::default(),
            )
            .0
        }
    };
    // Runtime pages in the first dense table, as the native host numbers
    // them, the second translation seven pages on.
    let low = gex_emit::dense::FIRST_TABLE as u64 * PageTable::slots_per_table();
    let high = low + 7 * gex_abi::SLOTS_PER_PAGE;
    let (a, b) = (gex_emit::with_instantiation_globals(at(low)), gex_emit::with_instantiation_globals(at(high)));
    assert_eq!(a.page_globals.len(), 2, "both pages are checked");
    assert_eq!(a.page_globals, a.covered.iter().map(|&(_, base)| base).collect::<Vec<_>>());
    assert_ne!(a.page_globals, b.page_globals);
    assert!(!a.dense_entries.is_empty());
    assert_ne!(a.dense_entries, b.dense_entries);
    assert_eq!(a.wasm, b.wasm);
    // Written in, the numbers make the bytes differ.
    let (c, d) = (at(low)(), at(high)());
    assert!(c.page_globals.is_empty() && c.dense_entries.is_empty());
    assert_ne!(c.wasm, d.wasm);
}
