//! The per-interface network settings under `/proc/sys/net`: `ipv4/conf`
//! and `ipv6/conf` (`all`, `default` and each interface), and `ipv4/neigh`
//! and `ipv6/neigh` (`default` and each interface), as `devinet.c`,
//! `addrconf.c` and `neighbour.c` make them. Android's netd lists them and
//! sets values on every interface (`accept_ra`, `accept_redirects`,
//! `use_oif_addrs_only`, `base_reachable_time_ms`, ...).
//!
//! The file lists, modes and starting values are Linux's
//! ([`crate::netconf_tables`]); a value is kept as written (a number,
//! within what the file takes as a C `int`), and changing `forwarding`, or
//! IPv6's `disable_ipv6`, under `all` changes it for `default` and every
//! interface too, as Linux's handlers do. Nothing here acts on them: this
//! kernel's internet sockets are the host's.

use crate::errno::Errno;
use crate::netconf_tables::{IPV4_CONF, IPV6_CONF, NEIGH};
use std::collections::HashMap;
use std::sync::Mutex;

/// What has been written, by path under `sys/net/`.
static SET: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

/// The interfaces there are, by name.
fn interfaces() -> Vec<String> {
    crate::netlink::interface_names()
}

/// `(family, kind, entry, file)` of a path under `/proc`.
fn parse(path: &str) -> Option<(&str, &str, &str, Option<&str>)> {
    let rest = path.strip_prefix("sys/net/")?;
    let mut it = rest.splitn(4, '/');
    let family = it.next()?;
    if family != "ipv4" && family != "ipv6" {
        return None;
    }
    let kind = it.next()?;
    if kind != "conf" && kind != "neigh" {
        return None;
    }
    let entry = it.next()?;
    Some((family, kind, entry, it.next()))
}

/// The entries of `family`'s `kind`: `all` and `default` for `conf`,
/// `default` for `neigh`, and every interface.
fn entries(kind: &str) -> Vec<String> {
    let mut out: Vec<String> = if kind == "conf" { vec!["all".into(), "default".into()] } else { vec!["default".into()] };
    out.extend(interfaces());
    out
}

/// A file's mode and starting value.
fn file(family: &str, kind: &str, entry: &str, name: &str) -> Option<(u32, String)> {
    if !entries(kind).iter().any(|e| e == entry) {
        return None;
    }
    if kind == "neigh" {
        return NEIGH.iter().find(|f| f.0 == name).map(|f| (f.1, f.2.to_string()));
    }
    let table = if family == "ipv4" { IPV4_CONF } else { IPV6_CONF };
    let &(_, mode, all, default, lo) = table.iter().find(|f| f.0 == name)?;
    let value = match entry {
        "all" => all.to_string(),
        "default" => default.to_string(),
        "lo" => lo.to_string(),
        // Another interface starts as `default` is, with its own MTU.
        _ if family == "ipv6" && name == "mtu" => crate::netlink::interface_mtu(entry).unwrap_or(1280).to_string(),
        _ => default.to_string(),
    };
    Some((mode, value))
}

/// Whether `path` is one of these directories.
pub fn is_dir(path: &str) -> bool {
    match path {
        "sys/net/ipv4" | "sys/net/ipv6" => true,
        _ => matches!(parse(path), Some((_, kind, entry, None)) if entries(kind).iter().any(|e| e == entry))
            || matches!(path.strip_prefix("sys/net/"), Some("ipv4/conf" | "ipv4/neigh" | "ipv6/conf" | "ipv6/neigh")),
    }
}

/// A directory's entries: `(name, is a directory)`.
pub fn list(path: &str) -> Option<Vec<(String, bool)>> {
    match path {
        "sys/net/ipv4" | "sys/net/ipv6" => return Some(vec![("conf".into(), true), ("neigh".into(), true)]),
        "sys/net/ipv4/conf" | "sys/net/ipv6/conf" => return Some(entries("conf").into_iter().map(|e| (e, true)).collect()),
        "sys/net/ipv4/neigh" | "sys/net/ipv6/neigh" => return Some(entries("neigh").into_iter().map(|e| (e, true)).collect()),
        _ => {}
    }
    let (family, kind, entry, None) = parse(path)? else { return None };
    if !entries(kind).iter().any(|e| e == entry) {
        return None;
    }
    let names: Vec<&str> = match kind {
        "neigh" => NEIGH.iter().map(|f| f.0).collect(),
        _ if family == "ipv4" => IPV4_CONF.iter().map(|f| f.0).collect(),
        _ => IPV6_CONF.iter().map(|f| f.0).collect(),
    };
    Some(names.into_iter().map(|n| (n.to_string(), false)).collect())
}

/// A file's mode, where `path` is one.
pub fn mode(path: &str) -> Option<u32> {
    let (family, kind, entry, Some(name)) = parse(path)? else { return None };
    file(family, kind, entry, name).map(|(m, _)| m)
}

/// What a file reads: `EIO` for one not yet set that has no value
/// (`stable_secret`).
pub fn read(path: &str) -> Option<Result<Vec<u8>, Errno>> {
    let (family, kind, entry, Some(name)) = parse(path)? else { return None };
    let (_, start) = file(family, kind, entry, name)?;
    let key = path["sys/net/".len()..].to_string();
    let g = SET.lock().unwrap_or_else(|e| e.into_inner());
    let value = g.as_ref().and_then(|m| m.get(&key).cloned()).unwrap_or(start);
    if value.is_empty() {
        return Some(Err(Errno::EIO));
    }
    Some(Ok(format!("{value}\n").into_bytes()))
}

/// A write: how much of `buf` was taken.
pub fn write(path: &str, buf: &[u8]) -> Option<Result<u64, Errno>> {
    let (family, kind, entry, Some(name)) = parse(path)? else { return None };
    let (mode, _) = file(family, kind, entry, name)?;
    Some((|| {
        if mode & 0o222 == 0 {
            return Err(Errno::EACCES);
        }
        let (value, taken) = if name == "stable_secret" {
            // An IPv6 address (`proc_ip6_stable_secret`), else EIO.
            let text = std::str::from_utf8(buf).map_err(|_| Errno::EIO)?.trim_end_matches(['\n', '\0']).trim();
            let a: std::net::Ipv6Addr = text.parse().map_err(|_| Errno::EIO)?;
            (a.to_string(), buf.len())
        } else {
            let (v, taken) = crate::vfs::procfs::sysctl_number_pub(buf)?;
            if v < i32::MIN as i64 || v > i32::MAX as i64 {
                return Err(Errno::EINVAL);
            }
            (v.to_string(), taken)
        };
        let mut g = SET.lock().unwrap_or_else(|e| e.into_inner());
        let m = g.get_or_insert_with(HashMap::new);
        let carries = entry == "all" && kind == "conf" && (name == "forwarding" || (family == "ipv6" && name == "disable_ipv6"));
        if carries {
            for e in entries("conf") {
                m.insert(format!("{family}/conf/{e}/{name}"), value.clone());
            }
        } else {
            m.insert(format!("{family}/{kind}/{entry}/{name}"), value);
        }
        Ok(taken as u64)
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(p: &str) -> Result<String, Errno> {
        read(p).expect("a file").map(|b| String::from_utf8(b).unwrap())
    }

    /// The trees as Linux lays them out, and its starting values; all's
    /// forwarding carried to default and each interface; stable_secret
    /// unreadable until set; a number past an int refused.
    #[test]
    fn settings_read_and_carry_as_linux_has_them() {
        let conf = list("sys/net/ipv4/conf").unwrap();
        assert!(conf.iter().any(|(n, d)| n == "all" && *d) && conf.iter().any(|(n, _)| n == "lo"));
        assert!(list("sys/net/ipv6/neigh").unwrap().iter().any(|(n, _)| n == "default"));
        assert_eq!(text("sys/net/ipv4/conf/default/accept_source_route").unwrap(), "1\n");
        assert_eq!(text("sys/net/ipv4/conf/all/accept_source_route").unwrap(), "0\n");
        assert_eq!(text("sys/net/ipv6/conf/lo/mtu").unwrap(), "65536\n");
        assert_eq!(mode("sys/net/ipv4/conf/lo/mc_forwarding"), Some(0o444));
        write("sys/net/ipv6/conf/all/forwarding", b"1\n").unwrap().unwrap();
        assert_eq!(text("sys/net/ipv6/conf/lo/forwarding").unwrap(), "1\n");
        assert_eq!(text("sys/net/ipv6/conf/default/forwarding").unwrap(), "1\n");
        assert_eq!(text("sys/net/ipv6/conf/lo/stable_secret"), Err(Errno::EIO));
        write("sys/net/ipv6/conf/lo/stable_secret", b"::1\n").unwrap().unwrap();
        assert_eq!(text("sys/net/ipv6/conf/lo/stable_secret").unwrap(), "::1\n");
        assert_eq!(write("sys/net/ipv4/neigh/lo/base_reachable_time_ms", b"9999999999"), Some(Err(Errno::EINVAL)));
        assert_eq!(write("sys/net/ipv4/conf/lo/mc_forwarding", b"1"), Some(Err(Errno::EACCES)));
        assert!(read("sys/net/ipv4/conf/nosuch/forwarding").is_none());
    }
}
