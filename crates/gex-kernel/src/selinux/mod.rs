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
//! its place. Their answers are checked against a Linux kernel's.
//!
//! Still to come, and nothing here pretends otherwise: selinuxfs,
//! `/proc/<pid>/attr`, the labels of files, and the hooks that ask. Until
//! then no file of selinuxfs exists, and a program that looks for SELinux
//! finds it absent.

pub mod policy;
pub mod server;
