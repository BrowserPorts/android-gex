//! The call tables, made from gfxstream's API descriptions (`spec/`) as
//! emugen reads them (`codegen/generic-apigen` in gfxstream: `Parser.cpp`,
//! `TypeFactory.cpp`, `ApiGen.cpp`):
//!
//! - `.types`: a type's name, its size in bits, a format, and optionally
//!   whether it is a pointer (else: its name ends in `*`).
//! - `.in`: one entry a line, `GL_ENTRY(return type, name, type param, ...)`;
//!   an entry's opcode is the API's base plus its place in the file.
//! - `.attrib`: a section an entry (`GLOBAL` for the API), with a pointer's
//!   direction (`dir`: `in`, the default, `out` or `inout`), its length
//!   expression (not needed here: the wire carries every pointer's length),
//!   its flags (`var_flag`: `nullAllowed`, `isLarge`), and the entry's
//!   (`flag`: `custom_decoder`, `not_api`, `unsupported`).
//!
//! A type is its tokens with whitespace taken out and a leading `const`
//! dropped (`GLchar * const *` is `GLchar*const*`).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::Path;

struct Type {
    bytes: u32,
    pointer: bool,
}

fn types(text: &str, out: &mut HashMap<String, Type>) {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        let name = f[0].to_string();
        let bits: u32 = f[1].parse().unwrap_or_else(|_| panic!("a type's size: {line}"));
        let pointer = match f.get(3) {
            Some(&"true") => true,
            Some(&"false") => false,
            _ => name.ends_with('*'),
        };
        out.insert(name, Type { bytes: bits / 8, pointer });
    }
}

fn normalize(t: &str) -> String {
    let s: String = t.chars().filter(|c| !c.is_whitespace()).collect();
    s.strip_prefix("const").map(str::to_string).unwrap_or(s)
}

/// A parameter declaration's type and name: the name is the last word.
fn param(decl: &str) -> (String, String) {
    let decl = decl.trim();
    let split = decl.rfind(|c: char| c.is_whitespace() || c == '*').expect("a parameter's name");
    let (ty, name) = decl.split_at(split + 1);
    (normalize(ty), name.trim().to_string())
}

struct Entry {
    name: String,
    ret: String,
    params: Vec<(String, String)>,
}

fn entries(text: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        // `GL_ENRTY` as well: renderControl.in's first line is spelled so,
        // and emugen takes whatever is in the parentheses.
        if !(line.starts_with("GL_ENTRY(") || line.starts_with("GL_ENRTY(")) {
            continue;
        }
        let inner = &line[line.find('(').unwrap() + 1..line.rfind(')').expect("an entry's end")];
        let mut parts = inner.split(',').map(str::trim);
        let ret = normalize(parts.next().unwrap());
        let name = parts.next().expect("an entry's name").to_string();
        let params = parts.filter(|p| !p.is_empty() && *p != "void").map(param).collect();
        out.push(Entry { name, ret, params });
    }
    out
}

#[derive(Default)]
struct Attrib {
    dir: HashMap<String, String>,
    flags: Vec<String>,
}

fn attribs(text: &str) -> (u32, HashMap<String, Attrib>) {
    let mut base = 0;
    let mut out: HashMap<String, Attrib> = HashMap::new();
    let mut current = String::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if !line.starts_with(char::is_whitespace) {
            current = line.trim().to_string();
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        match (current.as_str(), f[0]) {
            ("GLOBAL", "base_opcode") => base = f[1].parse().expect("a base opcode"),
            ("GLOBAL", _) => {}
            (_, "dir") => {
                out.entry(current.clone()).or_default().dir.insert(f[1].to_string(), f[2].to_string());
            }
            (_, "flag") => out.entry(current.clone()).or_default().flags.extend(f[1..].iter().map(|s| s.to_string())),
            _ => {}
        }
    }
    (base, out)
}

/// The host's EGL for the `host` feature: on macOS Homebrew's Mesa, or
/// `GEX_MESA_PREFIX` (as `gex-gl` finds it).
fn link_mesa() {
    println!("cargo:rerun-if-env-changed=GEX_MESA_PREFIX");
    if std::env::var_os("CARGO_FEATURE_HOST").is_none() || std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    let prefix = std::env::var_os("GEX_MESA_PREFIX").map(std::path::PathBuf::from).or_else(|| {
        ["/opt/homebrew/opt/mesa", "/usr/local/opt/mesa"].into_iter().map(std::path::PathBuf::from).find(|p| p.join("lib").exists())
    });
    let prefix = prefix.expect("gex-gfxstream: no Mesa on macOS; `brew install mesa` or set GEX_MESA_PREFIX");
    println!("cargo:rustc-link-search=native={}", prefix.join("lib").display());
}

fn main() {
    link_mesa();
    let spec = Path::new("spec");
    println!("cargo:rerun-if-changed=spec");
    let mut known = HashMap::new();
    types(&std::fs::read_to_string(spec.join("gex.types")).unwrap(), &mut known);
    let mut code = String::new();
    writeln!(code, "// Generated by build.rs from spec/: do not edit.").unwrap();
    for (api, konst) in [("renderControl", "RENDER_CONTROL"), ("gles1", "GLES1"), ("gles2", "GLES2")] {
        let read = |ext: &str| std::fs::read_to_string(spec.join(format!("{api}.{ext}"))).unwrap_or_else(|e| panic!("{api}.{ext}: {e}"));
        // emugen's own (`TypeFactory::initBaseTypes`), then the API's.
        let mut ty = HashMap::new();
        for (n, bytes) in [("char", 1), ("int", 4), ("float", 4), ("short", 2)] {
            ty.insert(n.to_string(), Type { bytes, pointer: false });
        }
        types(&read("types"), &mut ty);
        for (k, v) in &known {
            ty.entry(k.clone()).or_insert(Type { bytes: v.bytes, pointer: v.pointer });
        }
        let (base, attrs) = attribs(&read("attrib"));
        let list = entries(&read("in"));
        writeln!(code, "pub static {konst}: Api = Api {{ name: {api:?}, base: {base}, entries: &[").unwrap();
        for e in &list {
            let a = attrs.get(&e.name);
            let size_of = |t: &str| -> u32 {
                if t == "void" {
                    return 0;
                }
                ty.get(t).unwrap_or_else(|| panic!("{api}: {}: no type {t}", e.name)).bytes
            };
            let ret = size_of(&e.ret);
            let mut params = String::new();
            for (t, n) in &e.params {
                let info = ty.get(t.as_str()).unwrap_or_else(|| panic!("{api}: {}: no type {t}", e.name));
                let kind = if info.pointer {
                    match a.and_then(|a| a.dir.get(n)).map(String::as_str).unwrap_or("in") {
                        "in" => "Kind::In".to_string(),
                        "out" => "Kind::Out".to_string(),
                        "inout" => "Kind::InOut".to_string(),
                        d => panic!("{api}: {}: {n}: direction {d}", e.name),
                    }
                } else {
                    format!("Kind::Scalar({})", info.bytes)
                };
                write!(params, "Param {{ name: {n:?}, kind: {kind} }}, ").unwrap();
            }
            let flag = |f: &str| a.is_some_and(|a| a.flags.iter().any(|x| x == f));
            writeln!(
                code,
                "    Entry {{ name: {:?}, ret: {ret}, params: &[{params}], custom_decoder: {}, not_api: {}, unsupported: {} }},",
                e.name,
                flag("custom_decoder"),
                flag("not_api"),
                flag("unsupported")
            )
            .unwrap();
        }
        writeln!(code, "] }};").unwrap();
    }
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    std::fs::write(out.join("apis.rs"), code).unwrap();
}
