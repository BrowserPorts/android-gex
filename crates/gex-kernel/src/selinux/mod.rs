//! SELinux, the kernel's side of it: what Android's userland will not
//! start without. Its init loads a policy before anything else runs,
//! `servicemanager` asks who each caller is, and every label on a file or
//! a process is this module's to give.
//!
//! So far the policy, what follows from it, and what is loaded:
//! [`policy::Policy`] reads the binary form a program writes to
//! `/sys/fs/selinux/load`, reads and writes contexts as text, and makes
//! the computations everything else rests on, what one context may do to
//! another, what context something new gets and whether a relabel is one
//! the policy lets be made (security/selinux/ss/services.c).
//! [`server::Server`] is the policy that is loaded: the SIDs it has given
//! out, its booleans, and what becomes of both when another policy takes
//! its place. It also says what selinuxfs's files hold: what each that
//! only reads its state reads, the words of the status page, and the
//! answer to a question written to `context`, `access`, `create`,
//! `member`, `relabel` or `validatetrans`. Their answers are checked
//! against a Linux kernel's.
//!
//! [`crate::vfs::SelinuxFs`] is the filesystem that serves them, which a
//! program mounts by its type.
//!
//! [`procattr`] is a process's own context and what it asks for, and
//! [`labels`] what a file's label is and may become.
//!
//! Still to come, and nothing here pretends otherwise: the system calls
//! that read and set a file's label, the transition an `execve` makes by
//! it, and the hooks that ask. No host mounts selinuxfs
//! of itself, so a program that looks for SELinux and has not mounted it
//! finds it absent.

pub mod labels;
pub mod policy;
pub mod procattr;
pub mod server;

use std::sync::{Arc, Mutex, OnceLock};

/// `security_secid_to_secctx`: a SID's context as the loaded policy
/// writes it, with the NUL that ends it; before a policy, a kernel SID's
/// name.
pub fn secid_to_secctx(sid: u32) -> Result<Vec<u8>, crate::errno::Errno> {
    let server = kernel_server();
    let text = server.lock().unwrap_or_else(|e| e.into_inner()).sid_to_context(sid, false).map_err(|_| crate::errno::Errno::EINVAL)?;
    Ok([text.as_bytes(), b"\0"].concat())
}

/// The kernel's security server: the one every mount of selinuxfs is
/// over, as Linux has one for the machine.
pub fn kernel_server() -> Arc<Mutex<server::Server>> {
    static SERVER: OnceLock<Arc<Mutex<server::Server>>> = OnceLock::new();
    Arc::clone(SERVER.get_or_init(Default::default))
}
