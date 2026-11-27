//! The byte form of a snapshot of a running system: what the kernel's state
//! is written as, and read back from, when a started system is saved and
//! later resumed instead of booted again.
//!
//! Hand-written, little-endian and versioned, in the style the kernel's own
//! savers already use ([`crate::signal::Signals::to_bytes`],
//! [`crate::seccomp::State::to_bytes`]): the state holds locks, atomics,
//! trait objects and host closures, which no derive reaches through.
//!
//! - [`W`] writes and [`R`] reads integers, variable-length integers, byte
//!   strings and text.
//! - A *section* is a tag, a version and a length, then its bytes
//!   ([`W::section`], [`R::section`]): a reader can skip one it does not
//!   know, and a change of layout is a new version, refused by a reader of
//!   the old one rather than misread.
//! - [`Ids`] gives each shared object (an `Arc`, by its address) a dense
//!   number the first time it is met, so an object several places refer to
//!   is written once and named by its number everywhere else.
//! - [`Refused`] is a snapshot that cannot be taken, saying what stopped
//!   it: a handle of a kind nobody has written saving for stops the whole
//!   snapshot by name, never drops out of it silently.

use std::collections::HashMap;

/// What an open file is made again as when a snapshot is read back
/// ([`crate::vfs::FileHandle::snap`]): one number a kind of handle, never
/// reused for another.
pub type Kind = u16;

/// Why a snapshot could not be taken or read: what stopped it, as a
/// person reading the error needs it ("a binder thread with a reply
/// pending", "an unknown section 0x31 version 2").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refused(pub String);

impl Refused {
    pub fn new(why: impl Into<String>) -> Refused {
        Refused(why.into())
    }
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "snapshot refused: {}", self.0)
    }
}

impl std::error::Error for Refused {}

/// A snapshot's bytes as they are written.
#[derive(Default, Debug)]
pub struct W {
    buf: Vec<u8>,
}

impl W {
    pub fn new() -> W {
        W::default()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn bool(&mut self, v: bool) {
        self.u8(v as u8);
    }

    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn i32(&mut self, v: i32) {
        self.u32(v as u32);
    }

    pub fn i64(&mut self, v: i64) {
        self.u64(v as u64);
    }

    /// An unsigned number in as few bytes as it needs: seven bits a byte,
    /// the high bit set on every byte but the last (LEB128).
    pub fn var(&mut self, mut v: u64) {
        loop {
            let low = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                self.u8(low);
                return;
            }
            self.u8(low | 0x80);
        }
    }

    /// A length or count: [`W::var`] of a `usize`.
    pub fn len_of(&mut self, n: usize) {
        self.var(n as u64);
    }

    /// Bytes, their length first.
    pub fn bytes(&mut self, b: &[u8]) {
        self.len_of(b.len());
        self.buf.extend_from_slice(b);
    }

    /// Text, as its UTF-8 bytes.
    pub fn str(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }

    /// `Some(v)` as 1 and `v`, `None` as 0.
    pub fn opt<T>(&mut self, v: Option<T>, mut put: impl FnMut(&mut W, T)) {
        match v {
            Some(v) => {
                self.u8(1);
                put(self, v);
            }
            None => self.u8(0),
        }
    }

    /// A section: `tag`, `version`, then the length of what `body` writes,
    /// then that. A body's refusal is the section's.
    pub fn section(&mut self, tag: u32, version: u16, body: impl FnOnce(&mut W) -> Result<(), Refused>) -> Result<(), Refused> {
        let mut inner = W::new();
        body(&mut inner)?;
        self.u32(tag);
        self.u16(version);
        self.u64(inner.buf.len() as u64);
        self.buf.extend_from_slice(&inner.buf);
        Ok(())
    }
}

/// A snapshot's bytes as they are read back. Every read that runs past the
/// end or finds what cannot be is a [`Refused`] naming where.
#[derive(Debug)]
pub struct R<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> R<'a> {
    pub fn new(buf: &'a [u8]) -> R<'a> {
        R { buf, at: 0 }
    }

    /// Where the next read starts.
    pub fn at(&self) -> usize {
        self.at
    }

    /// Whether everything has been read.
    pub fn done(&self) -> bool {
        self.at == self.buf.len()
    }

    /// That everything has been read: a reader that leaves bytes behind
    /// has read a different layout from the one written.
    pub fn end(&self, what: &str) -> Result<(), Refused> {
        if self.done() {
            Ok(())
        } else {
            Err(Refused::new(format!("{} bytes left unread at the end of {what}", self.buf.len() - self.at)))
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Refused> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.buf.len());
        let Some(end) = end else {
            return Err(Refused::new(format!("a read of {n} bytes at {} runs past the end ({} bytes)", self.at, self.buf.len())));
        };
        let s = &self.buf[self.at..end];
        self.at = end;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8, Refused> {
        Ok(self.take(1)?[0])
    }

    pub fn bool(&mut self) -> Result<bool, Refused> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            b => Err(Refused::new(format!("{b} at {} where a true or false was written", self.at - 1))),
        }
    }

    pub fn u16(&mut self) -> Result<u16, Refused> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    pub fn u32(&mut self) -> Result<u32, Refused> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn u64(&mut self) -> Result<u64, Refused> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub fn i32(&mut self) -> Result<i32, Refused> {
        Ok(self.u32()? as i32)
    }

    pub fn i64(&mut self) -> Result<i64, Refused> {
        Ok(self.u64()? as i64)
    }

    pub fn var(&mut self) -> Result<u64, Refused> {
        let start = self.at;
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let b = self.u8()?;
            let bits = (b & 0x7f) as u64;
            // The tenth byte may carry only the top bit of 64.
            if shift == 63 && bits > 1 {
                break;
            }
            v |= bits << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(Refused::new(format!("a number at {start} longer than 64 bits")))
    }

    /// A length or count, no larger than what is left to read could hold
    /// (each element takes a byte at least), so that a corrupt length is a
    /// refusal and not an allocation of gigabytes.
    pub fn len_of(&mut self) -> Result<usize, Refused> {
        let at = self.at;
        let n = self.var()?;
        let left = (self.buf.len() - self.at) as u64;
        if n > left {
            return Err(Refused::new(format!("a count of {n} at {at} with {left} bytes left")));
        }
        Ok(n as usize)
    }

    pub fn bytes(&mut self) -> Result<&'a [u8], Refused> {
        let n = self.len_of()?;
        self.take(n)
    }

    pub fn str(&mut self) -> Result<&'a str, Refused> {
        let at = self.at;
        let b = self.bytes()?;
        std::str::from_utf8(b).map_err(|_| Refused::new(format!("text at {at} that is not UTF-8")))
    }

    pub fn opt<T>(&mut self, get: impl FnOnce(&mut R<'a>) -> Result<T, Refused>) -> Result<Option<T>, Refused> {
        match self.u8()? {
            0 => Ok(None),
            1 => get(self).map(Some),
            b => Err(Refused::new(format!("{b} at {} where something or nothing was written", self.at - 1))),
        }
    }

    /// The next section's tag and version, and a reader of its bytes alone;
    /// this reader goes on after it.
    pub fn section(&mut self) -> Result<(u32, u16, R<'a>), Refused> {
        let tag = self.u32()?;
        let version = self.u16()?;
        let at = self.at;
        let n = self.u64()?;
        let n = usize::try_from(n).map_err(|_| Refused::new(format!("section {tag:#x} at {at} of {n} bytes")))?;
        let body = self.take(n).map_err(|_| Refused::new(format!("section {tag:#x} at {at} says {n} bytes, more than are left")))?;
        Ok((tag, version, R::new(body)))
    }

    /// The next section, which must be `tag` at `version`.
    pub fn expect(&mut self, tag: u32, version: u16, what: &str) -> Result<R<'a>, Refused> {
        let (t, v, body) = self.section()?;
        if t != tag {
            return Err(Refused::new(format!("{what}: section {t:#x} where {tag:#x} was expected")));
        }
        if v != version {
            return Err(Refused::new(format!("{what}: version {v}, and this build reads version {version}")));
        }
        Ok(body)
    }
}

/// Dense numbers for shared objects, by their address: the first time an
/// object is met it is given the next number (and its writer writes it in
/// full); every later time only the number is written.
///
/// The address is a key only while the object is alive, which the
/// snapshot holds it for (the system is stopped while it is written).
#[derive(Default, Debug)]
pub struct Ids {
    by_addr: HashMap<usize, u32>,
}

impl Ids {
    pub fn new() -> Ids {
        Ids::default()
    }

    /// The number of the object at `addr`, and whether this was the first
    /// time it was met.
    pub fn of_addr(&mut self, addr: usize) -> (u32, bool) {
        let next = self.by_addr.len() as u32;
        match self.by_addr.entry(addr) {
            std::collections::hash_map::Entry::Occupied(e) => (*e.get(), false),
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(next);
                (next, true)
            }
        }
    }

    /// [`Ids::of_addr`] of what an `Arc` points to (a `dyn` one's data, not
    /// its vtable, so two `Arc`s of one object agree however they are
    /// typed).
    pub fn of<T: ?Sized>(&mut self, a: &std::sync::Arc<T>) -> (u32, bool) {
        self.of_addr(std::sync::Arc::as_ptr(a) as *const () as usize)
    }

    pub fn len(&self) -> usize {
        self.by_addr.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_addr.is_empty()
    }
}

/// Objects read back, by the numbers [`Ids`] gave them when written: the
/// first mention of a number brings the object, later ones refer to it.
#[derive(Debug)]
pub struct Found<T> {
    objects: Vec<Option<T>>,
}

impl<T> Default for Found<T> {
    fn default() -> Self {
        Found { objects: Vec::new() }
    }
}

impl<T: Clone> Found<T> {
    pub fn new() -> Found<T> {
        Found::default()
    }

    /// Object `id`, read with `make` the first time it is met (when it is
    /// the next number: the writer numbered objects in the order it met
    /// them, and the reader meets them in the same order).
    pub fn get_or(&mut self, id: u32, make: impl FnOnce() -> Result<T, Refused>) -> Result<T, Refused> {
        let i = id as usize;
        if let Some(Some(o)) = self.objects.get(i) {
            return Ok(o.clone());
        }
        if i != self.objects.len() {
            return Err(Refused::new(format!("object {id} referred to before it was written ({} so far)", self.objects.len())));
        }
        let o = make()?;
        self.objects.push(Some(o.clone()));
        Ok(o)
    }

    pub fn len(&self) -> usize {
        self.objects.len()
    }

    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn what_is_written_reads_back() {
        let mut w = W::new();
        w.u8(7);
        w.bool(true);
        w.u16(0xbeef);
        w.u32(0xdead_beef);
        w.u64(u64::MAX - 1);
        w.i32(-5);
        w.i64(i64::MIN);
        for v in [0, 1, 127, 128, 300, u32::MAX as u64, u64::MAX] {
            w.var(v);
        }
        w.bytes(b"\0bytes\xff");
        w.str("text é");
        w.opt(Some(9u32), |w, v| w.u32(v));
        w.opt(None::<u32>, |w, v| w.u32(v));
        let b = w.into_bytes();
        let mut r = R::new(&b);
        assert_eq!(r.u8().unwrap(), 7);
        assert!(r.bool().unwrap());
        assert_eq!(r.u16().unwrap(), 0xbeef);
        assert_eq!(r.u32().unwrap(), 0xdead_beef);
        assert_eq!(r.u64().unwrap(), u64::MAX - 1);
        assert_eq!(r.i32().unwrap(), -5);
        assert_eq!(r.i64().unwrap(), i64::MIN);
        for v in [0, 1, 127, 128, 300, u32::MAX as u64, u64::MAX] {
            assert_eq!(r.var().unwrap(), v);
        }
        assert_eq!(r.bytes().unwrap(), b"\0bytes\xff");
        assert_eq!(r.str().unwrap(), "text é");
        assert_eq!(r.opt(|r| r.u32()).unwrap(), Some(9));
        assert_eq!(r.opt(|r| r.u32()).unwrap(), None);
        r.end("the test").unwrap();
    }

    #[test]
    fn a_small_number_takes_a_byte() {
        let mut w = W::new();
        w.var(127);
        assert_eq!(w.len(), 1);
        w.var(128);
        assert_eq!(w.len(), 3);
    }

    #[test]
    fn what_cannot_be_is_refused_not_misread() {
        // past the end
        assert!(R::new(&[1, 2]).u32().is_err());
        // a count larger than what is left
        let mut w = W::new();
        w.var(1 << 40);
        let b = w.into_bytes();
        assert!(R::new(&b).bytes().unwrap_err().0.contains("count"));
        // a number longer than 64 bits
        assert!(R::new(&[0xff; 11]).var().is_err());
        // not a boolean, not an option
        assert!(R::new(&[2]).bool().is_err());
        assert!(R::new(&[2]).opt(|r| r.u8()).is_err());
        // not text
        assert!(R::new(&[2, 0xff, 0xfe]).str().is_err());
        // bytes left over
        let r = R::new(&[0]);
        assert!(r.end("x").unwrap_err().0.contains("1 bytes left"));
    }

    #[test]
    fn a_section_can_be_skipped_or_must_match() {
        let mut w = W::new();
        w.section(0x10, 1, |w| {
            w.u64(42);
            Ok(())
        })
        .unwrap();
        w.section(0x20, 3, |w| {
            w.str("second");
            Ok(())
        })
        .unwrap();
        let b = w.into_bytes();

        // skip the first without knowing it
        let mut r = R::new(&b);
        let (t, v, _) = r.section().unwrap();
        assert_eq!((t, v), (0x10, 1));
        let mut second = r.expect(0x20, 3, "second").unwrap();
        assert_eq!(second.str().unwrap(), "second");
        second.end("second").unwrap();
        assert!(r.done());

        // the wrong tag, the wrong version
        let mut r = R::new(&b);
        assert!(r.expect(0x11, 1, "first").unwrap_err().0.contains("0x11"));
        let mut r = R::new(&b);
        assert!(r.expect(0x10, 2, "first").unwrap_err().0.contains("version 1"));

        // a body's refusal is the section's, and writes nothing
        let mut w = W::new();
        let e = w.section(0x30, 1, |_| Err(Refused::new("a handle of no known kind"))).unwrap_err();
        assert_eq!(e, Refused::new("a handle of no known kind"));
        assert!(w.is_empty());

        // a length that says more than there is
        let mut short = b.clone();
        short.truncate(b.len() - 1);
        let mut r = R::new(&short);
        r.section().unwrap();
        assert!(r.section().is_err());
    }

    #[test]
    fn a_shared_object_is_written_once_and_found_again() {
        let a: Arc<dyn std::fmt::Debug + Send + Sync> = Arc::new(1u32);
        let b = Arc::new(2u32);
        let a2 = Arc::clone(&a);
        let mut ids = Ids::new();
        assert_eq!(ids.of(&a), (0, true));
        assert_eq!(ids.of(&b), (1, true));
        assert_eq!(ids.of(&a2), (0, false));
        assert_eq!(ids.len(), 2);

        let mut found: Found<Arc<u32>> = Found::new();
        let one = found.get_or(0, || Ok(Arc::new(1))).unwrap();
        let two = found.get_or(1, || Ok(Arc::new(2))).unwrap();
        let again = found.get_or(0, || panic!("made twice")).unwrap();
        assert!(Arc::ptr_eq(&one, &again));
        assert_eq!(*two, 2);
        // a number met before it was written
        assert!(found.get_or(5, || Ok(Arc::new(5))).is_err());
    }
}
