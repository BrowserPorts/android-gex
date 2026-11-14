//! The security server: the policy that is loaded, the SIDs it has given
//! out, and its booleans (security/selinux/ss/services.c and sidtab.c).
//!
//! A SID is the number the kernel keeps for a context. The first 27 are
//! the kernel's own, named, which a policy gives contexts to; the rest are
//! given out as contexts are met. Before any policy is loaded the named
//! ones stand for their names and everything is allowed.
//!
//! Its tests are what Linux 7.0 was seen to show, before a policy, with
//! one, and with another in its place (`initial_contexts`, a process's
//! `attr/current`, the status page's words), and the answers a kernel
//! gave through selinuxfs with a policy loaded. What it does for a
//! context that finds its names again in a later policy, and for one a
//! policy has the names for but does not allow, is the reference's as
//! read, not yet as seen.

use crate::selinux::policy::{av, Context, Decision, OContext, Policy, POLICY_CAPABILITIES, VERSION_MAX};
use std::collections::HashMap;

/// `SECINITSID_NUM`: the last of the kernel's own SIDs.
pub const INITIAL_SIDS: u32 = 27;
pub const SID_KERNEL: u32 = 1;
pub const SID_UNLABELED: u32 = 3;
pub const SID_INIT: u32 = 7;

/// The kernel's SIDs by name (include/initial_sid_to_string.h): the ones
/// with no name are no longer used.
pub const INITIAL_SID_NAMES: [Option<&str>; 28] = [
    None, Some("kernel"), Some("security"), Some("unlabeled"), None, Some("file"), None, Some("init"), Some("any_socket"), Some("port"),
    Some("netif"), Some("netmsg"), Some("node"), None, None, None, None, None, None, None, None, None, None, None, None, None, None, Some("devnull"),
];

/// `POLICYDB_CAP_USERSPACE_INITIAL_CONTEXT`: the policy gives the init
/// SID a context of its own.
const CAP_USERSPACE_INITIAL_CONTEXT: u32 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// `EINVAL`: no such SID, or text that is no context.
    Invalid,
    /// `EACCES`: a context the policy does not allow, and it is enforced.
    Denied,
    /// `EPERM`: a change of label the policy's validatetrans rules refuse.
    NotPermitted,
}

/// What a SID stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    Context(Context),
    /// A context of an earlier policy that the one loaded has no words
    /// for, kept as it was written: it is treated as unlabeled.
    Unmapped(String),
}

struct Loaded {
    policy: Policy,
    bools: Vec<bool>,
    /// What each boolean becomes at the next commit: what it is, until
    /// `booleans/<name>` is written.
    pending: Vec<bool>,
    initial: Vec<Option<Entry>>,
    /// SID 28 and on, in the order given out.
    others: Vec<Entry>,
    by_context: HashMap<Context, u32>,
}

#[derive(Default)]
pub struct Server {
    loaded: Option<Loaded>,
    enforcing: bool,
    /// How many policies have been loaded (`latest_granting`).
    pub seqno: u32,
    /// How many times the status page has been written anew.
    changes: u32,
}

impl Loaded {
    fn entry(&self, sid: u32) -> Option<&Entry> {
        if sid <= INITIAL_SIDS {
            self.initial.get(sid as usize)?.as_ref()
        } else {
            self.others.get((sid - INITIAL_SIDS - 1) as usize)
        }
    }

    /// The context a SID has for a decision: an unmapped one is unlabeled
    /// (`sidtab_search`).
    fn context(&self, sid: u32) -> Option<&Context> {
        match self.entry(sid)? {
            Entry::Context(c) => Some(c),
            Entry::Unmapped(_) => match self.entry(SID_UNLABELED)? {
                Entry::Context(c) => Some(c),
                Entry::Unmapped(_) => None,
            },
        }
    }

    /// The SID of a context, given one if it has none
    /// (`sidtab_context_to_sid`).
    fn sid_of(&mut self, c: Context) -> u32 {
        if let Some(&sid) = self.by_context.get(&c) {
            return sid;
        }
        self.others.push(Entry::Context(c.clone()));
        let sid = INITIAL_SIDS + self.others.len() as u32;
        self.by_context.insert(c, sid);
        sid
    }
}

impl Server {
    pub fn policy(&self) -> Option<&Policy> {
        self.loaded.as_ref().map(|l| &l.policy)
    }

    /// `security_load_policy`: a first policy, or one in place of
    /// another, whose SIDs keep their numbers and whose booleans keep
    /// their states by name.
    pub fn load(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let policy = Policy::read(bytes).map_err(|_| Error::Invalid)?;
        // The kernel's SIDs, as the policy has them (`policydb_load_isids`).
        let mut initial: Vec<Option<Entry>> = vec![None; INITIAL_SIDS as usize + 1];
        for c in &policy.initial_sids {
            let OContext::InitialSid { sid, context } = c else { continue };
            if *sid == 0 {
                return Err(Error::Invalid);
            }
            if INITIAL_SID_NAMES.get(*sid as usize).copied().flatten().is_some() {
                initial[*sid as usize] = Some(Entry::Context(context.clone()));
            }
        }
        // Init starts as the kernel unless the policy says it has a
        // context of its own for it.
        if !policy.policycaps.get(CAP_USERSPACE_INITIAL_CONTEXT) {
            let kernel = initial[SID_KERNEL as usize].clone().ok_or(Error::Invalid)?;
            initial[SID_INIT as usize] = Some(kernel);
        }
        let mut bools = policy.bool_defaults();
        let mut others = Vec::new();
        if let Some(old) = &self.loaded {
            for (i, b) in policy.bools.iter().enumerate() {
                if let Some(at) = old.policy.bools.iter().position(|o| o.name == b.name) {
                    bools[i] = old.bools[at];
                }
            }
            // Each SID's context again in the new policy's terms, name by
            // name (`convert_context`). One with a name the new policy
            // lacks is kept as text; one it has every name for but does
            // not allow stands, unless it is enforced.
            for e in &old.others {
                others.push(match e {
                    Entry::Context(c) => match policy.convert_context(&old.policy, c) {
                        Some(new) if policy.context_ok(&new) || !self.enforcing => Entry::Context(new),
                        _ => Entry::Unmapped(old.policy.context_string(c)),
                    },
                    // Text an earlier policy left: it may have words now.
                    Entry::Unmapped(text) => match policy.context_from_str(text) {
                        Some(c) => Entry::Context(c),
                        None => Entry::Unmapped(text.clone()),
                    },
                });
            }
        }
        let mut by_context = HashMap::new();
        for (i, e) in initial.iter().enumerate() {
            if let Some(Entry::Context(c)) = e {
                by_context.entry(c.clone()).or_insert(i as u32);
            }
        }
        for (i, e) in others.iter().enumerate() {
            if let Entry::Context(c) = e {
                by_context.entry(c.clone()).or_insert(INITIAL_SIDS + 1 + i as u32);
            }
        }
        // Nothing waits for a commit across a load.
        let pending = bools.clone();
        self.loaded = Some(Loaded { policy, bools, pending, initial, others, by_context });
        self.seqno += 1;
        self.changes += 1;
        Ok(())
    }

    /// `security_sid_to_context`: a SID's context as text. With `force`,
    /// an unmapped one as it was written; without, as unlabeled.
    pub fn sid_to_context(&self, sid: u32, force: bool) -> Result<String, Error> {
        let Some(l) = &self.loaded else {
            // Before a policy the kernel's SIDs are their names, and init
            // is "kernel": what is not "kernel" is taken to mean a policy
            // is loaded.
            let sid = if sid == SID_INIT { SID_KERNEL } else { sid };
            return INITIAL_SID_NAMES.get(sid as usize).copied().flatten().map(str::to_string).ok_or(Error::Invalid);
        };
        match l.entry(sid).ok_or(Error::Invalid)? {
            Entry::Context(c) => Ok(l.policy.context_string(c)),
            Entry::Unmapped(text) if force => Ok(text.clone()),
            Entry::Unmapped(_) => l.context(sid).map(|c| l.policy.context_string(c)).ok_or(Error::Invalid),
        }
    }

    /// `security_context_to_sid`: the SID of a context given as text.
    pub fn context_to_sid(&mut self, text: &str) -> Result<u32, Error> {
        if text.is_empty() {
            return Err(Error::Invalid);
        }
        let Some(l) = &mut self.loaded else {
            // A kernel SID's name is that SID (all but the last of them,
            // as the kernel's loop has it), and anything else the kernel.
            let named = (1..INITIAL_SIDS).find(|&i| INITIAL_SID_NAMES[i as usize] == Some(text));
            return Ok(named.unwrap_or(SID_KERNEL));
        };
        let c = l.policy.context_from_str(text).ok_or(Error::Invalid)?;
        Ok(l.sid_of(c))
    }

    /// `security_compute_av_user`. Everything, before a policy.
    pub fn compute_av(&self, ssid: u32, tsid: u32, class: u32) -> Decision {
        let all = Decision { allowed: !0, auditallow: 0, auditdeny: !0, flags: 0 };
        let Some(l) = &self.loaded else { return all };
        match (l.context(ssid), l.context(tsid)) {
            (Some(s), Some(t)) => l.policy.compute_av(s, t, class, &l.bools),
            _ => Decision { allowed: 0, ..all },
        }
    }

    /// `security_compute_sid`, for a program's question (`create`,
    /// `member`, `relabel`): the SID of the context something new gets.
    pub fn compute_sid(&mut self, ssid: u32, tsid: u32, class: u32, specified: u16, name: Option<&str>) -> Result<u32, Error> {
        /// The kernel's own number for the process class.
        const SECCLASS_PROCESS: u32 = 2;
        let enforcing = self.enforcing;
        let Some(l) = &mut self.loaded else {
            return Ok(if class == SECCLASS_PROCESS { ssid } else { tsid });
        };
        let (s, t) = (l.context(ssid).ok_or(Error::Invalid)?.clone(), l.context(tsid).ok_or(Error::Invalid)?.clone());
        let new = l.policy.compute_context(&s, &t, class, specified, name, &l.bools).ok_or(Error::Invalid)?;
        // One the policy does not allow stands, unless it is enforced.
        if !l.policy.context_ok(&new) && enforcing {
            return Err(Error::Denied);
        }
        if new == s {
            return Ok(ssid);
        }
        if new == t {
            return Ok(tsid);
        }
        Ok(l.sid_of(new))
    }

    /// `security_validate_transition_user`: whether something of a class
    /// may go from one label to another at a task's hand. Anything may,
    /// before a policy; a refusal is one whether or not it is enforced.
    pub fn validate_transition(&self, old: u32, new: u32, task: u32, class: u32) -> Result<(), Error> {
        let Some(l) = &self.loaded else { return Ok(()) };
        let (Some(o), Some(n), Some(t)) = (l.context(old), l.context(new), l.context(task)) else { return Err(Error::Invalid) };
        match l.policy.validate_transition(o, n, t, class) {
            Some(true) => Ok(()),
            Some(false) => Err(Error::NotPermitted),
            None => Err(Error::Invalid),
        }
    }

    /// A question written to one of selinuxfs's files that answer in the
    /// file it was written to (`context`, `access`, `create`, `member`,
    /// `relabel`), or to `validatetrans`, which answers by the write's
    /// success alone. Contexts are text, a class is its number in the
    /// policy, and a context in the answer ends in a NUL. `None` for any
    /// other file.
    pub fn transact(&mut self, file: &str, question: &str) -> Option<Result<Vec<u8>, Error>> {
        if !matches!(file, "context" | "access" | "create" | "member" | "relabel" | "validatetrans") {
            return None;
        }
        Some(self.answer(file, question))
    }

    fn answer(&mut self, file: &str, question: &str) -> Result<Vec<u8>, Error> {
        let context = |s: &Server, sid: u32| s.sid_to_context(sid, false).map(|text| [text.as_bytes(), b"\0"].concat());
        if file == "context" {
            // The context as the policy writes it.
            let sid = self.context_to_sid(question.trim_end_matches('\0'))?;
            return context(self, sid);
        }
        // Two contexts and a class's number, as the kernel's `sscanf`
        // takes them, and what follows.
        let (scon, tcon, class, rest) = scanned(question.trim_end_matches('\0')).ok_or(Error::Invalid)?;
        let (word, _) = word(rest);
        match file {
            // What follows the class is not read.
            "access" => {
                let (ssid, tsid) = (self.context_to_sid(scon)?, self.context_to_sid(tcon)?);
                let d = self.compute_av(ssid, tsid, class);
                Ok(format!("{:x} {:x} {:x} {:x} {} {:x}", d.allowed, !0u32, d.auditallow, d.auditdeny, self.seqno, d.flags).into_bytes())
            }
            // A new object's name may follow, with `+` for a space and
            // `%xx` for any byte. One that is not text is no name a policy
            // here has, which is as if none were given.
            "create" => {
                let name = match word {
                    "" => None,
                    coded => String::from_utf8(percent_decoded(coded).ok_or(Error::Invalid)?).ok(),
                };
                let (ssid, tsid) = (self.context_to_sid(scon)?, self.context_to_sid(tcon)?);
                let sid = self.compute_sid(ssid, tsid, class, av::TRANSITION, name.as_deref())?;
                context(self, sid)
            }
            "member" | "relabel" => {
                let specified = if file == "member" { av::MEMBER } else { av::CHANGE };
                let (ssid, tsid) = (self.context_to_sid(scon)?, self.context_to_sid(tcon)?);
                let sid = self.compute_sid(ssid, tsid, class, specified, None)?;
                context(self, sid)
            }
            // Old, new, the class, and the task's after it.
            "validatetrans" if !word.is_empty() => {
                let (old, new, task) = (self.context_to_sid(scon)?, self.context_to_sid(tcon)?, self.context_to_sid(word)?);
                self.validate_transition(old, new, task, class).map(|()| Vec::new())
            }
            _ => Err(Error::Invalid),
        }
    }

    pub fn enforcing(&self) -> bool {
        self.enforcing
    }

    /// `enforce` written: a change of it is a change of the status page,
    /// the same value again is nothing.
    pub fn set_enforcing(&mut self, on: bool) {
        if on != self.enforcing {
            self.enforcing = on;
            self.changes += 1;
        }
    }

    /// The words of the status page a program maps to see a change
    /// without a system call (`struct selinux_kernel_status`): its
    /// version, a sequence that is odd while the page is being written
    /// and so goes up by two a change, enforcing, the count of loads, and
    /// whether an unknown permission is denied.
    pub fn status(&self) -> [u32; 5] {
        let deny_unknown = !self.policy().is_some_and(|p| p.allow_unknown);
        [1, self.changes * 2, self.enforcing as u32, self.seqno, deny_unknown as u32]
    }

    /// What a file of selinuxfs that only reads its state reads, and its
    /// mode (security/selinux/selinuxfs.c): `enforce`, `policyvers`,
    /// `mls`, `deny_unknown`, `reject_unknown`, `checkreqprot`, and the
    /// files under [`Server::dir`]'s directories. A number is its digits
    /// with no newline; a context ends in a NUL. `None` for any other
    /// name: the files that take a question, `load`, `status` and `policy`
    /// are the filesystem's to answer.
    pub fn file(&self, path: &str) -> Option<(u32, Result<Vec<u8>, Error>)> {
        let policy = self.policy();
        let number = |mode: u32, n: u32| Some((mode, Ok(n.to_string().into_bytes())));
        match path.split('/').collect::<Vec<_>>().as_slice() {
            ["enforce"] => number(0o644, self.enforcing as u32),
            // The newest policy this reads, whatever is loaded.
            ["policyvers"] => number(0o444, VERSION_MAX),
            ["mls"] => number(0o444, policy.is_some_and(|p| p.mls) as u32),
            // Before a policy nothing is unknown to it: denied, as a
            // policy that says nothing would have it.
            ["deny_unknown"] => number(0o444, !policy.is_some_and(|p| p.allow_unknown) as u32),
            ["reject_unknown"] => number(0o444, policy.is_some_and(|p| p.reject_unknown) as u32),
            // What mmap's PROT_EXEC is checked by: the kernel no longer
            // lets it be anything but what the program asked for.
            ["checkreqprot"] => number(0o644, 0),
            ["class", class, "index"] => number(0o444, policy?.class_named(class)?),
            ["class", class, "perms", perm] => {
                let policy = policy?;
                let perms = policy.perms_of(policy.class_named(class)?);
                number(0o444, perms.iter().find(|(_, name)| name == perm)?.0)
            }
            // Its value, and the one that waits for a commit.
            ["booleans", name] => {
                let l = self.loaded.as_ref()?;
                let at = l.policy.bools.iter().position(|b| b.name == *name)?;
                Some((0o644, Ok(format!("{} {}", l.bools[at] as u8, l.pending[at] as u8).into_bytes())))
            }
            ["initial_contexts", name] => {
                let sid = INITIAL_SID_NAMES.iter().position(|n| n.as_deref() == Some(*name))? as u32;
                Some((0o444, self.sid_to_context(sid, false).map(|text| [text.as_bytes(), b"\0"].concat())))
            }
            ["policy_capabilities", name] => {
                let bit = POLICY_CAPABILITIES.iter().position(|c| c == name)? as u32;
                number(0o444, policy.is_some_and(|p| p.policycaps.get(bit)) as u32)
            }
            _ => None,
        }
    }

    /// The names in a directory of selinuxfs that the policy fills, or
    /// the kernel's own lists: `class`, `class/<name>`,
    /// `class/<name>/perms`, `booleans`, `initial_contexts`,
    /// `policy_capabilities`. Before a policy `class` and `booleans` are
    /// empty. Each is mode 0555.
    pub fn dir(&self, path: &str) -> Option<Vec<String>> {
        let policy = self.policy();
        match path.split('/').collect::<Vec<_>>().as_slice() {
            ["class"] => Some(policy.map(|p| p.classes.iter().map(|c| c.name.clone()).collect()).unwrap_or_default()),
            ["class", class] => policy?.class_named(class).map(|_| vec!["index".to_string(), "perms".to_string()]),
            ["class", class, "perms"] => {
                let policy = policy?;
                Some(policy.perms_of(policy.class_named(class)?).into_iter().map(|(_, name)| name.to_string()).collect())
            }
            ["booleans"] => Some(policy.map(|p| p.bools.iter().map(|b| b.name.clone()).collect()).unwrap_or_default()),
            ["initial_contexts"] => Some(INITIAL_SID_NAMES.iter().flatten().map(|n| n.to_string()).collect()),
            ["policy_capabilities"] => Some(POLICY_CAPABILITIES.iter().map(|n| n.to_string()).collect()),
            _ => None,
        }
    }

    /// `booleans/<name>` written: the value it takes at the next commit.
    pub fn set_pending_bool(&mut self, name: &str, value: bool) -> Result<(), Error> {
        let l = self.loaded.as_mut().ok_or(Error::Invalid)?;
        let at = l.policy.bools.iter().position(|b| b.name == name).ok_or(Error::Invalid)?;
        l.pending[at] = value;
        Ok(())
    }

    /// `commit_pending_bools` written with other than 0
    /// (`security_set_bools`): every boolean takes the value that waits
    /// for it. It counts as a load and a change of the status page
    /// whether or not a value changed; before a policy there is nothing
    /// to commit and nothing is counted.
    pub fn commit_bools(&mut self) {
        let Some(l) = self.loaded.as_mut() else { return };
        l.bools = l.pending.clone();
        self.seqno += 1;
        self.changes += 1;
    }

    /// Set a boolean, by name: its file written and a commit.
    pub fn set_bool(&mut self, name: &str, value: bool) -> Result<(), Error> {
        self.set_pending_bool(name, value)?;
        self.commit_bools();
        Ok(())
    }
}

/// The next word of `text` (`%s`: white space passed over, then all that
/// is not), and what follows it.
fn word(text: &str) -> (&str, &str) {
    let space = |c: char| matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r');
    let text = text.trim_start_matches(space);
    text.split_at(text.find(space).unwrap_or(text.len()))
}

/// `sscanf(text, "%s %s %hu", ...)` and the rest of the text: two words
/// and a number, which is the digits a third word starts with (at least
/// one), kept to sixteen bits. So `12abc` is 12 and `abc` follows.
fn scanned(text: &str) -> Option<(&str, &str, u32, &str)> {
    let (first, rest) = word(text);
    let (second, rest) = word(rest);
    let (third, _) = word(rest);
    let rest = &rest[rest.len() - rest.trim_start_matches([' ', '\t', '\n', '\x0b', '\x0c', '\r']).len()..];
    let digits = third.bytes().take_while(u8::is_ascii_digit).count();
    if first.is_empty() || second.is_empty() || digits == 0 {
        return None;
    }
    let number = third[..digits].bytes().fold(0u64, |n, d| n.wrapping_mul(10).wrapping_add((d - b'0') as u64));
    Some((first, second, number as u16 as u32, &rest[digits..]))
}

/// A name as `create` takes it: `+` a space, `%xx` a byte, and the name
/// ends at a byte of 0. `None` for a `%` without its two digits.
fn percent_decoded(coded: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut bytes = coded.bytes();
    while let Some(b) = bytes.next() {
        let b = match b {
            b'+' => b' ',
            b'%' => {
                let (hi, lo) = ((bytes.next()? as char).to_digit(16)?, (bytes.next()? as char).to_digit(16)?);
                (hi << 4 | lo) as u8
            }
            other => other,
        };
        if b == 0 {
            break;
        }
        out.push(b);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const V33: &[u8] = include_bytes!("testdata/test.33");

    /// As Linux 6.8 was seen to be with SELinux on and nothing loaded: a
    /// process is "kernel", the named SIDs read their names.
    #[test]
    fn before_a_policy_the_kernels_sids_are_their_names() {
        let mut s = Server::default();
        assert_eq!(s.sid_to_context(SID_KERNEL, false).as_deref(), Ok("kernel"));
        assert_eq!(s.sid_to_context(SID_INIT, false).as_deref(), Ok("kernel"));
        assert_eq!(s.sid_to_context(5, false).as_deref(), Ok("file"));
        assert_eq!(s.sid_to_context(27, false).as_deref(), Ok("devnull"));
        assert_eq!(s.sid_to_context(4, false), Err(Error::Invalid));
        assert_eq!(s.sid_to_context(28, false), Err(Error::Invalid));
        assert_eq!((s.context_to_sid("file"), s.context_to_sid("anything at all"), s.context_to_sid("")), (Ok(5), Ok(SID_KERNEL), Err(Error::Invalid)));
        assert_eq!(s.compute_av(1, 5, 2).allowed, !0);
    }

    /// With test.33 loaded, as the kernel that loaded it answered.
    #[test]
    fn with_a_policy_sids_are_contexts() {
        let mut s = Server::default();
        assert_eq!(s.status(), [1, 0, 0, 0, 1], "the status page before a policy, as Linux 7.0's read");
        s.load(V33).unwrap();
        assert_eq!(s.seqno, 1);
        assert_eq!(s.status(), [1, 2, 0, 1, 1], "and after");
        // initial_contexts, as it read: kernel, security, unlabeled, file
        // and devnull.
        assert_eq!(s.sid_to_context(SID_KERNEL, false).as_deref(), Ok("system_u:system_r:kernel_t:s0"));
        assert_eq!(s.sid_to_context(2, false).as_deref(), Ok("system_u:object_r:file_t:s0"));
        assert_eq!(s.sid_to_context(SID_UNLABELED, false).as_deref(), Ok("system_u:object_r:file_t:s0"));
        assert_eq!(s.sid_to_context(5, false).as_deref(), Ok("system_u:object_r:file_t:s0-s1:c0.c2"));
        assert_eq!(s.sid_to_context(27, false).as_deref(), Ok("system_u:object_r:tmp_t:s0"));
        // The policy names a context for init (init_t) and has not the
        // capability that makes it count: init is the kernel's.
        assert_eq!(s.sid_to_context(SID_INIT, false).as_deref(), Ok("system_u:system_r:kernel_t:s0"));
        let init = s.context_to_sid("system_u:system_r:init_t:s0").unwrap();
        let exec = s.context_to_sid("system_u:object_r:exec_t:s0").unwrap();
        assert_eq!((init, exec), (28, 29));
        assert_eq!(s.context_to_sid("system_u:system_r:init_t:s0"), Ok(28), "the same context, the same SID");
        assert_eq!(s.context_to_sid("system_u:system_r:kernel_t:s0"), Ok(SID_KERNEL));
        assert_eq!(s.context_to_sid("nobody:system_r:init_t:s0"), Err(Error::Invalid));
        // create init exec process => system_u:app_r:app_t:s1:c0.c1, which
        // the policy does not allow together (app_r in system_u is fine,
        // the range is the transition's): given while not enforcing.
        let new = s.compute_sid(init, exec, 1, av::TRANSITION, None).unwrap();
        assert_eq!(s.sid_to_context(new, false).as_deref(), Ok("system_u:app_r:app_t:s1:c0,c1"));
    }

    /// selinuxfs's files before a policy, as Linux 6.8 was seen to have
    /// them (but `policyvers`, which is the newest this reads: 35, as on
    /// Linux 7.0 and android17-6.18, where 6.8 read 33). The NUL a
    /// context ends in and a capability's 0 are the reference's as read:
    /// the kernel's answers were kept without the one, and not asked for
    /// the other.
    #[test]
    fn before_a_policy_its_files_read_as_a_kernels() {
        let s = Server::default();
        let read = |path: &str| s.file(path).map(|(mode, bytes)| (mode, String::from_utf8(bytes.unwrap()).unwrap()));
        for (path, mode, want) in [
            ("enforce", 0o644, "0"),
            ("policyvers", 0o444, "35"),
            ("mls", 0o444, "0"),
            ("deny_unknown", 0o444, "1"),
            ("reject_unknown", 0o444, "0"),
            ("checkreqprot", 0o644, "0"),
            ("initial_contexts/file", 0o444, "file\0"),
            ("initial_contexts/devnull", 0o444, "devnull\0"),
            ("policy_capabilities/open_perms", 0o444, "0"),
        ] {
            assert_eq!(read(path), Some((mode, want.to_string())), "{path}");
        }
        assert_eq!(s.dir("class"), Some(vec![]));
        assert_eq!(s.dir("booleans"), Some(vec![]));
        let mut names = s.dir("initial_contexts").unwrap();
        names.sort();
        assert_eq!(names.join(" "), "any_socket devnull file init kernel netif netmsg node port security unlabeled");
        assert_eq!(s.dir("policy_capabilities").unwrap().len(), 14);
        assert_eq!((read("class/file/index"), read("booleans/allow_stuff"), read("load"), read("initial_contexts/nothing")), (None, None, None, None));
    }

    /// And with test.33 loaded: every file the kernel's answers have
    /// (testdata/answers.txt's `read` lines), after the booleans it had
    /// set by then.
    #[test]
    fn with_a_policy_its_files_read_as_a_kernels() {
        let mut s = Server::default();
        s.load(V33).unwrap();
        let mut read = 0;
        for line in include_str!("testdata/answers.txt").lines() {
            let Some((question, want)) = line.split_once(" => ") else { continue };
            match question.split_whitespace().collect::<Vec<_>>().as_slice() {
                ["bool", name, value] => s.set_bool(name, *value == "1").unwrap(),
                // 6.8's newest policy, not this one's.
                ["read", "policyvers"] => assert_eq!(want, "33"),
                // A process's own, which is not selinuxfs's.
                ["read", path] if path.starts_with('/') => {}
                ["read", path] => {
                    let (_, bytes) = s.file(path).unwrap_or_else(|| panic!("{path}"));
                    let text = String::from_utf8(bytes.unwrap()).unwrap();
                    assert_eq!(text.ends_with('\0'), path.starts_with("initial_contexts/"), "{path}");
                    assert_eq!(text.trim_end_matches('\0'), want, "{path}");
                    read += 1;
                }
                _ => {}
            }
        }
        assert!(read >= 15, "{read} files");
        // A commit of booleans is a change and counts as a load: the
        // kernel's page read 1 24 0 12 1 after two loads with commits
        // between them, the sequence twice the count.
        let before = s.status();
        s.set_bool("other_thing", false).unwrap();
        assert_eq!(s.status(), [1, before[1] + 2, 0, before[3] + 1, 1]);
        // From the reference, not yet seen: a value written and not
        // committed reads beside the one in force and changes nothing,
        // and a commit puts it in force, counted even with nothing new.
        s.set_pending_bool("other_thing", true).unwrap();
        assert_eq!(s.file("booleans/other_thing"), Some((0o644, Ok(b"0 1".to_vec()))));
        assert_eq!(s.status(), [1, before[1] + 2, 0, before[3] + 1, 1]);
        assert_eq!(s.set_pending_bool("nothing", true), Err(Error::Invalid));
        s.commit_bools();
        assert_eq!(s.file("booleans/other_thing"), Some((0o644, Ok(b"1 1".to_vec()))));
        s.commit_bools();
        assert_eq!(s.status(), [1, before[1] + 6, 0, before[3] + 3, 1]);
        // Nor seen: enforcing set is a change, and set to what it is
        // already is none.
        s.set_enforcing(true);
        s.set_enforcing(true);
        assert_eq!(s.status(), [1, before[1] + 8, 1, before[3] + 3, 1]);
        assert_eq!(s.file("enforce"), Some((0o644, Ok(b"1".to_vec()))));
        // In the policy's order of them, which is not the alphabet's.
        assert_eq!(s.dir("booleans"), Some(vec!["other_thing".to_string(), "allow_stuff".to_string()]));
        assert_eq!(s.dir("class/file"), Some(vec!["index".to_string(), "perms".to_string()]));
        let perms = s.dir("class/file/perms").unwrap();
        assert_eq!((perms[0].as_str(), perms[6].as_str()), ("read", "open"), "by number, as class/file/perms/* read");
        assert!(s.dir("class").unwrap().contains(&"binder".to_string()));
        assert_eq!((s.dir("class/nothing"), s.file("class/file/perms/nothing").map(|f| f.0)), (None, None));
    }

    /// Write each question of `answers` (lines of
    /// tests/android/oracle/selinux-ask.py's) to the file that script
    /// wrote it to, and hold the answer to the kernel's. How many were
    /// asked.
    fn replay(s: &mut Server, answers: &str) -> usize {
        let class = |s: &Server, name: &str| String::from_utf8(s.file(&format!("class/{name}/index")).unwrap().1.unwrap()).unwrap();
        let mut asked = 0;
        for line in answers.lines() {
            let Some((question, want)) = line.split_once(" => ") else { continue };
            let words: Vec<&str> = question.split_whitespace().collect();
            let (file, text) = match words.as_slice() {
                ["bool", name, value] => {
                    s.set_bool(name, *value == "1").unwrap();
                    continue;
                }
                ["context", c] => ("context", c.to_string()),
                ["access", sc, tc, cl] => ("access", format!("{sc} {tc} {} ffffffff", class(&s, cl))),
                [kind @ ("create" | "member" | "relabel"), sc, tc, cl, name @ ..] => (*kind, format!("{sc} {tc} {} {}", class(&s, cl), name.join(" ")).trim_end().to_string()),
                ["validatetrans", old, new, cl, task] => ("validatetrans", format!("{old} {new} {} {task}", class(&s, cl))),
                // A process's own, which is not selinuxfs's.
                ["read", path] if path.starts_with('/') => continue,
                // The asked kernel's newest policy: this one's, unless it
                // was Linux 6.8.
                ["read", "policyvers"] if want == "33" => continue,
                ["read", path] => {
                    let (_, bytes) = s.file(path).unwrap_or_else(|| panic!("{path}"));
                    let text = String::from_utf8(bytes.unwrap()).unwrap();
                    assert_eq!(text.trim_end_matches('\0'), want, "{path}");
                    asked += 1;
                    continue;
                }
                _ => panic!("{question}"),
            };
            let got = match s.transact(file, &text).unwrap() {
                Ok(bytes) if file == "validatetrans" => {
                    assert!(bytes.is_empty());
                    "ok".to_string()
                }
                Ok(bytes) if file == "access" => {
                    // The count of loads is in it, which the answers were
                    // kept without.
                    let text = String::from_utf8(bytes).unwrap();
                    let w: Vec<&str> = text.split(' ').collect();
                    assert_eq!(w[4], s.seqno.to_string());
                    format!("{} {} {} {} {}", w[0], w[1], w[2], w[3], w[5])
                }
                Ok(bytes) => {
                    assert_eq!(bytes.last(), Some(&0), "{question}");
                    String::from_utf8(bytes[..bytes.len() - 1].to_vec()).unwrap()
                }
                Err(Error::Invalid) => "errno EINVAL".to_string(),
                Err(Error::NotPermitted) => "errno EPERM".to_string(),
                Err(Error::Denied) => "errno EACCES".to_string(),
            };
            assert_eq!(got, want, "{question}");
            asked += 1;
        }
        asked
    }

    /// Every question a kernel was asked through selinuxfs with test.33
    /// loaded (testdata/answers.txt), and its answers.
    #[test]
    fn its_question_files_answer_as_a_kernels() {
        let mut s = Server::default();
        s.load(V33).unwrap();
        let asked = replay(&mut s, include_str!("testdata/answers.txt"));
        assert!(asked > 900, "{asked} questions");
        // Not a question, and not a file that takes one.
        assert_eq!(s.transact("access", "system_u:system_r:init_t:s0"), Some(Err(Error::Invalid)));
        assert_eq!(s.transact("create", "a b 1 %4"), Some(Err(Error::Invalid)));
        assert_eq!(s.transact("enforce", "1"), None);
        // From the reference's sscanf, not seen: a number is the digits
        // its word starts with, kept to sixteen bits, and what is left of
        // the word is the next one.
        assert_eq!(scanned("a  b\t12abc d"), Some(("a", "b", 12, "abc d")));
        assert_eq!(scanned("a b 65538"), Some(("a", "b", 2, "")));
        assert_eq!((scanned("a b"), scanned("a b x1"), scanned("")), (None, None, None));
        let (init, exec) = ("system_u:system_r:init_t:s0", "system_u:object_r:exec_t:s0");
        let plain = s.transact("create", &format!("{init} {exec} 1")).unwrap();
        assert!(plain.is_ok());
        assert_eq!(s.transact("create", &format!("{init} {exec} 65537 ignored more")).unwrap().is_ok(), true);
        assert_eq!(s.transact("relabel", &format!("{init} {exec} 1junk")).unwrap().is_ok(), true);
        assert_eq!(s.transact("validatetrans", &format!("{exec} {exec} 1")), Some(Err(Error::Invalid)), "no task");
        assert_eq!(percent_decoded("a+b%2fc%00d").as_deref(), Some(&b"a b/c"[..]));
    }

    /// Before a policy the question files answer too, from the reference
    /// (not put to a kernel): everything is allowed, a name of one of the
    /// kernel's SIDs is that SID and any other text the kernel's, and
    /// something new is labelled as its maker if it is a process (class
    /// 2) and as what it is made in if not.
    #[test]
    fn before_a_policy_its_question_files_answer() {
        let mut s = Server::default();
        let mut ask = |file: &str, text: &str| String::from_utf8(s.transact(file, text).unwrap().unwrap()).unwrap();
        assert_eq!(ask("access", "kernel file 6"), "ffffffff ffffffff 0 ffffffff 0 0");
        assert_eq!(ask("context", "file"), "file\0");
        assert_eq!(ask("context", "anything at all"), "kernel\0");
        assert_eq!(ask("create", "kernel file 2"), "kernel\0");
        assert_eq!(ask("create", "kernel file 6 name"), "file\0");
        assert_eq!(ask("validatetrans", "file devnull 6 kernel"), "");
    }

    /// The same for any policy there is a kernel's answers about, as
    /// `policy`'s test of the name has it: `GEX_SELINUX_POLICY` and
    /// `GEX_SELINUX_ANSWERS`.
    #[test]
    #[ignore = "needs GEX_SELINUX_POLICY and GEX_SELINUX_ANSWERS"]
    fn its_question_files_answer_about_a_policy_given_as_a_kernels() {
        let policy = std::fs::read(std::env::var("GEX_SELINUX_POLICY").expect("GEX_SELINUX_POLICY")).unwrap();
        let answers = std::fs::read_to_string(std::env::var("GEX_SELINUX_ANSWERS").expect("GEX_SELINUX_ANSWERS")).unwrap();
        let mut s = Server::default();
        s.load(&policy).unwrap();
        let asked = replay(&mut s, &answers);
        assert!(asked > 0);
        println!("{asked} questions, each answered as the kernel answered it");
    }

    /// When another policy takes a policy's place, a SID keeps its number
    /// and its context goes over name by name. As Linux showed with
    /// other.33 (test.conf with its init_t named start_t) loaded over
    /// test.33: a process that was system_u:system_r:init_t:s0 read as
    /// the new policy's unlabeled context, and the count of loads was 2.
    #[test]
    fn another_policy_in_its_place_keeps_the_sids() {
        let mut s = Server::default();
        s.load(V33).unwrap();
        let init = s.context_to_sid("system_u:system_r:init_t:s0").unwrap();
        let app = s.context_to_sid("system_u:system_r:app_t:s0").unwrap();
        s.load(include_bytes!("testdata/other.33")).unwrap();
        assert_eq!(s.seqno, 2);
        assert_eq!(s.status(), [1, 4, 0, 2, 1], "as its status page read");
        assert_eq!(s.sid_to_context(init, false).as_deref(), Ok("system_u:object_r:file_t:s0"), "no init_t now: unlabeled");
        assert_eq!(s.sid_to_context(init, true).as_deref(), Ok("system_u:system_r:init_t:s0"), "as it was written, for whoever may see that");
        // A context the new policy has every name for is itself, under
        // its number; and the kernel's own SIDs are the new policy's.
        assert_eq!(s.sid_to_context(app, false).as_deref(), Ok("system_u:system_r:app_t:s0"));
        assert_eq!(s.context_to_sid("system_u:system_r:app_t:s0"), Ok(app));
        assert_eq!(s.sid_to_context(SID_KERNEL, false).as_deref(), Ok("system_u:system_r:kernel_t:s0"));
        assert_eq!(s.sid_to_context(SID_UNLABELED, false).as_deref(), Ok("system_u:object_r:file_t:s0"));
        // The first policy again: the text has its names back.
        s.load(V33).unwrap();
        assert_eq!(s.sid_to_context(init, false).as_deref(), Ok("system_u:system_r:init_t:s0"));
        assert_eq!(s.context_to_sid("system_u:system_r:init_t:s0"), Ok(init));
    }
}
