//! Darwin's numbering, for a macOS host.
//!
//! Only what the host side needs is here: a macOS host's errors arrive in
//! Darwin's numbers, which [`crate::errno::Errno::from_host`] answers in
//! Linux's.
pub mod errno;
