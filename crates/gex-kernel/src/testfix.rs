//! Test inputs made from sources in the tree and kept out of it: the
//! compiled SELinux policies (from `selinux/testdata/*.conf`) and an ext4
//! image like an APEX's payload (`tests/android/oracle/ext4-fixture.sh`),
//! which `tests/fixtures.sh` makes into a directory. Tests read them from
//! `GEX_TEST_FIXTURES`; with it unset, a test that needs one says so and
//! passes, and with it set but the file missing, the test fails.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

/// The fixture `name` (`test.33`, `apex.img`, ...), or `None` when no
/// fixtures directory is given.
pub fn get(name: &str) -> Option<&'static [u8]> {
    static READ: Mutex<Option<HashMap<String, &'static [u8]>>> = Mutex::new(None);
    let Some(dir) = std::env::var_os("GEX_TEST_FIXTURES") else {
        eprintln!("skipped: this test needs {name}; set GEX_TEST_FIXTURES to the directory tests/fixtures.sh makes");
        return None;
    };
    let mut read = READ.lock().unwrap_or_else(|e| e.into_inner());
    let read = read.get_or_insert_with(HashMap::new);
    if let Some(bytes) = read.get(name) {
        return Some(bytes);
    }
    let path = Path::new(&dir).join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e} (GEX_TEST_FIXTURES is set; tests/fixtures.sh makes it)", path.display()));
    let bytes: &'static [u8] = Box::leak(bytes.into_boxed_slice());
    read.insert(name.to_string(), bytes);
    Some(bytes)
}

/// The fixture `name`'s bytes, or a return from the test when there is no
/// fixtures directory (`get` has said so).
macro_rules! fixture {
    ($name:expr) => {
        match crate::testfix::get($name) {
            Some(bytes) => bytes,
            None => return,
        }
    };
}

/// A value a fixture makes, or a return from the test without it.
macro_rules! or_skip {
    ($e:expr) => {
        match $e {
            Some(v) => v,
            None => return,
        }
    };
}
