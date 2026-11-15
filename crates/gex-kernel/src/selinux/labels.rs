//! The labels of files: what a file's `security.selinux` attribute reads
//! and takes, and the label a new file is given.
//!
//! How a filesystem labels its files is the policy's to say, by the
//! filesystem's type ([`Policy::fs_use`]): by each file's own attribute
//! (ext4), by a transition from its maker and the filesystem (tmpfs), as
//! its maker (pipes), by `genfscon` from its path (proc, sysfs), or not at
//! all. A file's SID follows from that, the file's path and class, and
//! the attribute it has stored, if any ([`file_sid`]).
//!
//! As security/selinux/hooks.c at android17-6.18 (`inode_doinit_with_dentry`,
//! `selinux_inode_getsecurity`, `selinux_inode_setxattr`,
//! `selinux_inode_init_security`), and as Linux 7.0 was seen to label and
//! relabel files with testdata/labels.33 loaded. This is the reckoning
//! alone: the system calls that use it are the kernel's, and
//! tests/android/src/filelabel.c, which passes on Linux 7.0 and here,
//! goes through them. Not here: what
//! the policy lets a process relabel (`relabelfrom`, `relabelto`,
//! `associate`), which waits for the hooks; a mount's `context=` options;
//! and a process's own directory in proc, which is labelled as the
//! process.

use super::policy::{av, fs_use};
use super::server::{Error, Server, SID_KERNEL, SID_UNLABELED};
use crate::errno::Errno;

/// The attribute's name.
pub const XATTR: &str = "security.selinux";
/// `SECINITSID_FILE`: what a file with no attribute is, on a filesystem
/// labelled by attribute.
const SID_FILE: u32 = 5;
/// `SECINITSID_DEVNULL`: selinuxfs's `null`.
const SID_DEVNULL: u32 = 27;
/// `POLICYDB_CAP_GENFS_SECLABEL_SYMLINKS`: `genfscon` labels symbolic
/// links too.
const CAP_GENFS_SECLABEL_SYMLINKS: u32 = 6;
/// `POLICYDB_CAP_CGROUPSECLABEL` and `POLICYDB_CAP_FUNCTIONFS_SECLABEL`.
const CAP_CGROUP_SECLABEL: u32 = 4;
const CAP_FUNCTIONFS_SECLABEL: u32 = 12;

/// What the kernel knows of a file, to label it.
#[derive(Debug, Clone, Copy)]
pub struct File<'a> {
    /// Its filesystem's type, as `/proc/mounts` names it.
    pub fstype: &'a str,
    /// Its path from its filesystem's root, with a leading slash.
    pub path: &'a str,
    /// Its class as policies name it: `file`, `dir`, `lnk_file`,
    /// `chr_file`, `blk_file`, `fifo_file`, `sock_file`.
    pub class: &'a str,
    /// The attribute its filesystem keeps for it, as it was written.
    pub stored: Option<&'a [u8]>,
}

/// A file's class by what kind of file it is.
pub fn class_of(kind: crate::vfs::FileType) -> &'static str {
    use crate::vfs::FileType;
    match kind {
        FileType::Regular => "file",
        FileType::Directory => "dir",
        FileType::Symlink => "lnk_file",
        FileType::CharDevice => "chr_file",
        FileType::BlockDevice => "blk_file",
        FileType::Fifo => "fifo_file",
        FileType::Socket => "sock_file",
    }
}

fn errno(e: Error) -> Errno {
    match e {
        Error::Invalid => Errno::EINVAL,
        Error::Denied => Errno::EACCES,
        Error::NotPermitted => Errno::EPERM,
    }
}

/// A stored attribute as the string the kernel takes it for: to its first
/// NUL.
fn text(value: &[u8]) -> String {
    String::from_utf8_lossy(&value[..value.iter().position(|&b| b == 0).unwrap_or(value.len())]).into_owned()
}

/// How a filesystem of type `fstype` labels its files, and its own SID:
/// `(fs_use::NONE, unlabeled)` before a policy and where no rule speaks.
fn filesystem(s: &mut Server, fstype: &str) -> (u32, u32) {
    let Some(p) = s.policy() else { return (fs_use::NONE, SID_UNLABELED) };
    let (behavior, context) = p.fs_use(fstype);
    let context = context.map(|c| p.context_string(c));
    (behavior, context.and_then(|c| s.context_to_sid(&c).ok()).unwrap_or(SID_UNLABELED))
}

/// Whether a file of a filesystem labelled so can be given a label
/// (`SBLABEL_MNT`): one labelled by attribute, by transition or as its
/// maker; and of those labelled by `genfscon`, the few that keep
/// attributes in memory.
fn takes_labels(s: &Server, fstype: &str, behavior: u32) -> bool {
    let cap = |bit| s.policy().is_some_and(|p| p.policycaps.get(bit));
    match behavior {
        fs_use::XATTR | fs_use::TRANS | fs_use::TASK | fs_use::NATIVE => true,
        fs_use::GENFS => {
            matches!(fstype, "sysfs" | "pstore" | "debugfs" | "tracefs" | "rootfs")
                || (cap(CAP_CGROUP_SECLABEL) && matches!(fstype, "cgroup" | "cgroup2"))
                || (cap(CAP_FUNCTIONFS_SECLABEL) && fstype == "functionfs")
        }
        _ => false,
    }
}

/// The SID of the text of an attribute, kept as written where the policy
/// has no words for it (`security_context_to_sid_default`, forced).
fn stored_sid(s: &mut Server, value: &[u8], default: u32) -> u32 {
    s.context_to_sid_force(&text(value)).unwrap_or(default)
}

/// A file's SID, as the policy now loaded labels it
/// (`inode_doinit_with_dentry`). Unlabeled before a policy.
pub fn file_sid(s: &mut Server, f: &File<'_>) -> u32 {
    if s.policy().is_none() {
        return SID_UNLABELED;
    }
    let (behavior, fs_sid) = filesystem(s, f.fstype);
    if f.fstype == "selinuxfs" && f.path == "/null" {
        return SID_DEVNULL;
    }
    match behavior {
        fs_use::XATTR | fs_use::NATIVE => match f.stored {
            Some(value) => stored_sid(s, value, SID_FILE),
            None => SID_FILE,
        },
        // What it was given when it was made; one made before the policy
        // was loaded, as what the kernel would have made then.
        fs_use::TRANS => match f.stored {
            Some(value) => stored_sid(s, value, fs_sid),
            None => {
                let class = s.policy().and_then(|p| p.class_named(f.class)).unwrap_or(0);
                s.compute_sid(SID_KERNEL, fs_sid, class, av::TRANSITION, None).unwrap_or(fs_sid)
            }
        },
        fs_use::TASK => match f.stored {
            Some(value) => stored_sid(s, value, SID_KERNEL),
            None => SID_KERNEL,
        },
        fs_use::GENFS => {
            // One of the few that keep attributes has what it was given.
            if let Some(value) = f.stored.filter(|_| takes_labels(s, f.fstype, behavior)) {
                return stored_sid(s, value, fs_sid);
            }
            let p = s.policy().expect("a policy is loaded");
            if f.class == "lnk_file" && !p.policycaps.get(CAP_GENFS_SECLABEL_SYMLINKS) {
                return fs_sid;
            }
            let class = p.class_named(f.class).unwrap_or(0);
            let context = p.genfs_context(f.fstype, f.path, class).map(|c| p.context_string(c));
            context.and_then(|c| s.context_to_sid(&c).ok()).unwrap_or(SID_UNLABELED)
        }
        _ => fs_sid,
    }
}

/// What `getxattr` of the attribute reads: the file's context and the
/// NUL that ends it; for a process with `CAP_MAC_ADMIN` a context the
/// policy has no words for as it was written, for any other as
/// unlabeled. `EOPNOTSUPP` before a policy, when the caller falls back
/// to what the filesystem has stored.
pub fn get(s: &mut Server, f: &File<'_>, mac_admin: bool) -> Result<Vec<u8>, Errno> {
    if s.policy().is_none() {
        return Err(Errno::EOPNOTSUPP);
    }
    let sid = file_sid(s, f);
    let context = s.sid_to_context(sid, mac_admin).map_err(errno)?;
    Ok([context.as_bytes(), b"\0"].concat())
}

/// Whether `listxattr` names the attribute for a file that has none
/// stored: always once a policy is loaded, on a filesystem that asks the
/// security module for its attributes (the caller's to know which do).
pub fn listed(s: &Server) -> bool {
    s.policy().is_some()
}

/// `setxattr` of the attribute by a process of SID `task`: `Ok` when the
/// filesystem may store `value` as it is.
///
/// Before a policy anything is stored. With one: `EOPNOTSUPP` on a
/// filesystem whose files take no labels; `EINVAL` for no context (but a
/// process with `CAP_MAC_ADMIN` may write one the policy has no words
/// for, which is kept), for nothing at all, and for a class the policy
/// has not; `EPERM` for a change the policy's validatetrans rules refuse,
/// when it is enforced.
pub fn set(s: &mut Server, f: &File<'_>, task: u32, value: &[u8], mac_admin: bool) -> Result<(), Errno> {
    if s.policy().is_none() {
        return Ok(());
    }
    let (behavior, _) = filesystem(s, f.fstype);
    if !takes_labels(s, f.fstype, behavior) {
        return Err(Errno::EOPNOTSUPP);
    }
    let old = file_sid(s, f);
    let new = match s.context_to_sid(&text(value)) {
        Ok(sid) => sid,
        Err(Error::Invalid) if mac_admin => s.context_to_sid_force(&text(value)).map_err(errno)?,
        Err(e) => return Err(errno(e)),
    };
    let class = s.policy().and_then(|p| p.class_named(f.class)).ok_or(Errno::EINVAL)?;
    match s.validate_transition(old, new, task, class) {
        // A refusal counts only where the policy is enforced.
        Err(Error::NotPermitted) if !s.enforcing() => Ok(()),
        other => other.map_err(errno),
    }
}

/// `removexattr` of the attribute: nothing loses its label once a policy
/// is loaded.
pub fn remove(s: &Server) -> Result<(), Errno> {
    if s.policy().is_some() {
        return Err(Errno::EACCES);
    }
    Ok(())
}

/// The label of something a process makes (`selinux_inode_init_security`):
/// its SID, and the attribute to store with it where its filesystem
/// stores one (the context and its NUL). `None` before a policy.
///
/// `ids` are the process's ([`super::procattr`]): what it asked that its
/// files be (`fscreate`), or else what the policy makes of the process,
/// the directory's SID `dir`, the class and the name.
pub fn new_file(s: &mut Server, ids: &[u32; 6], fstype: &str, dir: u32, class: &str, name: &str) -> Option<(u32, Option<Vec<u8>>)> {
    let class = s.policy()?.class_named(class).unwrap_or(0);
    let asked = ids[super::procattr::FSCREATE];
    let sid = if asked != 0 { asked } else { s.compute_sid(ids[super::procattr::CURRENT], dir, class, av::TRANSITION, Some(name)).ok()? };
    let (behavior, _) = filesystem(s, fstype);
    if !takes_labels(s, fstype, behavior) {
        return Some((sid, None));
    }
    let context = s.sid_to_context(sid, true).ok()?;
    Some((sid, Some([context.as_bytes(), b"\0"].concat())))
}

#[cfg(test)]
mod tests {
    use super::super::procattr;
    use super::*;

    /// testdata/labels.conf, which is test.conf with tmpfs labelled by
    /// transition, compiled by checkpolicy at version 33.
    const LABELS: &[u8] = include_bytes!("testdata/labels.33");
    const FILE_T: &str = "system_u:object_r:file_t:s0";
    const EXEC_T: &str = "system_u:object_r:exec_t:s0";
    const TMP_T: &str = "system_u:object_r:tmp_t:s0";
    const KERNEL_T: &str = "system_u:system_r:kernel_t:s0";

    fn loaded() -> Server {
        let mut s = Server::default();
        s.load(LABELS).unwrap();
        s
    }

    fn read(s: &mut Server, f: &File<'_>, mac_admin: bool) -> String {
        String::from_utf8(get(s, f, mac_admin).unwrap()).unwrap()
    }

    fn of<'a>(fstype: &'a str, path: &'a str, class: &'a str, stored: Option<&'a [u8]>) -> File<'a> {
        File { fstype, path, class, stored }
    }

    /// What Linux 7.0 read from files it had not been asked to label,
    /// with labels.33 loaded: by genfscon in proc, sysfs and selinuxfs,
    /// the file SID's context on ext4, the process's for a pipe, and
    /// unlabeled where no rule speaks.
    #[test]
    fn a_file_reads_the_label_its_filesystem_gives_it() {
        let mut s = loaded();
        for (f, want) in [
            (of("proc", "/cpuinfo", "file", None), FILE_T),
            (of("proc", "/sys/kernel/hostname", "file", None), EXEC_T),
            (of("proc", "/sys/kernel", "dir", None), TMP_T),
            (of("proc", "/sysvipc", "dir", None), TMP_T),
            (of("selinuxfs", "/enforce", "file", None), TMP_T),
            (of("selinuxfs", "/null", "chr_file", None), TMP_T),
            (of("sysfs", "/kernel", "dir", None), FILE_T),
            (of("ext4", "/etc/hostname", "file", None), "system_u:object_r:file_t:s0-s1:c0.c2"),
            (of("ext4", "/root/new", "file", Some(b"system_u:object_r:exec_t:s0\0")), EXEC_T),
            (of("pipefs", "/", "fifo_file", None), KERNEL_T),
            (of("devpts", "/", "dir", None), TMP_T),
            (of("devtmpfs", "/null", "chr_file", None), FILE_T),
            // Made before the policy was loaded: as the kernel's would be.
            (of("tmpfs", "/", "dir", None), TMP_T),
        ] {
            assert_eq!(read(&mut s, &f, false), format!("{want}\0"), "{f:?}");
        }
    }

    /// Each `setxattr` Linux 7.0 was given for a file of a tmpfs, by root,
    /// and what the file read after.
    #[test]
    fn a_label_is_set_as_a_kernel_sets_it() {
        let mut s = loaded();
        let mut stored: Vec<u8> = b"system_u:object_r:tmp_t:s0\0".to_vec();
        fn put(s: &mut Server, stored: &mut Vec<u8>, value: &[u8]) -> (Result<(), Errno>, String) {
            let f = File { fstype: "tmpfs", path: "/a", class: "file", stored: Some(stored) };
            let r = set(s, &f, SID_KERNEL, value, true);
            if r.is_ok() {
                *stored = value.to_vec();
            }
            let f = File { fstype: "tmpfs", path: "/a", class: "file", stored: Some(stored) };
            (r, String::from_utf8(get(s, &f, true).unwrap()).unwrap())
        }
        assert_eq!(put(&mut s, &mut stored, EXEC_T.as_bytes()), (Ok(()), format!("{EXEC_T}\0")));
        assert_eq!(put(&mut s, &mut stored, b"system_u:object_r:file_t:s0\0"), (Ok(()), format!("{FILE_T}\0")));
        assert_eq!(put(&mut s, &mut stored, b"system_u:object_r:old_file_t:s0"), (Ok(()), format!("{FILE_T}\0")), "an alias reads as its type");
        // Root may write what the policy has no words for: it reads back
        // to root as written.
        assert_eq!(put(&mut s, &mut stored, b"system_u:object_r:file_t:s0\n"), (Ok(()), "system_u:object_r:file_t:s0\n\0".to_string()));
        assert_eq!(put(&mut s, &mut stored, b"nobody:object_r:file_t:s0"), (Ok(()), "nobody:object_r:file_t:s0\0".to_string()));
        assert_eq!(put(&mut s, &mut stored, b"junk"), (Ok(()), "junk\0".to_string()));
        assert_eq!(put(&mut s, &mut stored, b""), (Err(Errno::EINVAL), "junk\0".to_string()));
        assert_eq!(put(&mut s, &mut stored, b"system_u:object_r:file_t:s0-s1:c0.c2"), (Ok(()), "system_u:object_r:file_t:s0-s1:c0.c2\0".to_string()));
        assert_eq!(put(&mut s, &mut stored, KERNEL_T.as_bytes()), (Ok(()), format!("{KERNEL_T}\0")), "nothing enforced keeps a file from a process's context");
        assert_eq!(remove(&s), Err(Errno::EACCES));
        // To anyone else what the policy has no words for is unlabeled,
        // and cannot be written (from the reference: only root was seen).
        stored = b"junk".to_vec();
        let f = File { fstype: "tmpfs", path: "/a", class: "file", stored: Some(&stored) };
        assert_eq!(read(&mut s, &f, false), format!("{FILE_T}\0"));
        assert_eq!(set(&mut s, &f, SID_KERNEL, b"more junk", false), Err(Errno::EINVAL));
        // A class this policy has not (a symbolic link): EINVAL, as seen.
        let link = File { fstype: "tmpfs", path: "/lnk", class: "lnk_file", stored: None };
        assert_eq!(set(&mut s, &link, SID_KERNEL, EXEC_T.as_bytes(), true), Err(Errno::EINVAL));
        // Filesystems whose files take no labels, and one that does
        // though genfscon labels it.
        assert_eq!(set(&mut s, &of("proc", "/cpuinfo", "file", None), SID_KERNEL, FILE_T.as_bytes(), true), Err(Errno::EOPNOTSUPP));
        assert_eq!(set(&mut s, &of("selinuxfs", "/enforce", "file", None), SID_KERNEL, FILE_T.as_bytes(), true), Err(Errno::EOPNOTSUPP));
        assert_eq!(set(&mut s, &of("sysfs", "/kernel/uevent_helper", "file", None), SID_KERNEL, FILE_T.as_bytes(), true), Ok(()));
        assert_eq!(read(&mut s, &of("sysfs", "/kernel/uevent_helper", "file", Some(EXEC_T.as_bytes())), false), format!("{EXEC_T}\0"));
    }

    /// What Linux 7.0 labelled files newly made in a tmpfs: as the
    /// directory they are made in, unless the process asked otherwise or
    /// the policy has a transition for the process, the directory, the
    /// class and the name.
    #[test]
    fn a_new_file_is_labelled_as_a_kernel_labels_it() {
        let mut s = loaded();
        let sid = |s: &mut Server, c: &str| s.context_to_sid(c).unwrap();
        let (tmp, exec) = (sid(&mut s, TMP_T), sid(&mut s, EXEC_T));
        let app = sid(&mut s, "system_u:system_r:app_t:s0");
        let label = |s: &mut Server, ids: &[u32; 6], dir: u32, class: &str, name: &str| {
            let (sid, stored) = new_file(s, ids, "tmpfs", dir, class, name).unwrap();
            let stored = String::from_utf8(stored.unwrap()).unwrap();
            assert_eq!(s.sid_to_context(sid, false).unwrap() + "\0", stored);
            stored
        };
        let kernel = procattr::INITIAL;
        assert_eq!(label(&mut s, &kernel, tmp, "file", "a"), format!("{TMP_T}\0"));
        assert_eq!(label(&mut s, &kernel, tmp, "dir", "dir"), format!("{TMP_T}\0"));
        assert_eq!(label(&mut s, &kernel, exec, "file", "in"), format!("{EXEC_T}\0"), "in a relabelled directory");
        // What the process asked its files to be, a directory too.
        let mut asked = procattr::INITIAL;
        asked[procattr::FSCREATE] = exec;
        assert_eq!(label(&mut s, &asked, tmp, "file", "fc"), format!("{EXEC_T}\0"));
        assert_eq!(label(&mut s, &asked, tmp, "dir", "fcd"), format!("{EXEC_T}\0"));
        // The policy's transitions by name, for a process of app_t.
        let mut as_app = procattr::INITIAL;
        as_app[procattr::CURRENT] = app;
        assert_eq!(label(&mut s, &as_app, tmp, "file", "special"), format!("{FILE_T}\0"));
        assert_eq!(label(&mut s, &as_app, tmp, "file", "plain"), format!("{TMP_T}\0"));
        assert_eq!(label(&mut s, &as_app, tmp, "dir", "other"), format!("{EXEC_T}\0"));
        assert_eq!(label(&mut s, &as_app, tmp, "dir", "plaindir"), format!("{TMP_T}\0"));
        assert_eq!(label(&mut s, &as_app, exec, "file", "special"), format!("{EXEC_T}\0"));
        // On ext4, seen too: as its directory (the file SID's type), at
        // the process's level.
        let root = file_sid(&mut s, &of("ext4", "/root", "dir", None));
        let (new, stored) = new_file(&mut s, &kernel, "ext4", root, "file", "probe").unwrap();
        assert_eq!((s.sid_to_context(new, false).as_deref(), stored.as_deref()), (Ok(FILE_T), Some(&b"system_u:object_r:file_t:s0\0"[..])));
        // A filesystem that stores no labels gives the SID and nothing
        // to store.
        assert!(matches!(new_file(&mut s, &kernel, "proc", tmp, "file", "x"), Some((_, None))));
    }

    /// Before a policy nothing is labelled: reads fall to what the
    /// filesystem has stored, anything may be stored, and a new file gets
    /// nothing (from the reference).
    #[test]
    fn before_a_policy_the_attribute_is_the_filesystems_own() {
        let mut s = Server::default();
        let f = of("tmpfs", "/a", "file", None);
        assert_eq!(get(&mut s, &f, true), Err(Errno::EOPNOTSUPP));
        assert_eq!(set(&mut s, &f, SID_KERNEL, b"anything", false), Ok(()));
        assert_eq!((remove(&s), listed(&s)), (Ok(()), false));
        assert_eq!(new_file(&mut s, &procattr::INITIAL, "tmpfs", SID_UNLABELED, "file", "a"), None);
        assert_eq!(file_sid(&mut s, &f), SID_UNLABELED);
    }
}
