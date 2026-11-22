//! The host's own threads, by an id that names one while it lives: its CPU
//! time and name, for the stall dumps (`hosts/native`'s `stall`).
//!
//! On Linux the id is the thread's kernel id, and the rest is read from
//! `/proc/self/task`. macOS has no `/proc`: the id is the system-wide
//! 64-bit thread id (`pthread_threadid_np`, `THREAD_IDENTIFIER_INFO`), and
//! the list comes from `task_threads` with `thread_info`'s
//! `THREAD_EXTENDED_INFO` (user and system time in nanoseconds, the pthread
//! name). A Mach port name is not used as the id: one that no right holds
//! may come back as another name at the next `task_threads`.

use std::collections::HashMap;

/// The calling thread's id: the one `threads` lists it by. 0 when the host
/// cannot say.
pub fn current() -> u64 {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link("/proc/thread-self")
            .ok()
            .and_then(|p| p.file_name().and_then(|n| n.to_str()).and_then(|n| n.parse().ok()))
            .unwrap_or(0)
    }
    #[cfg(target_os = "macos")]
    {
        extern "C" {
            fn pthread_threadid_np(thread: usize, id: *mut u64) -> i32;
        }
        let mut id = 0u64;
        // SAFETY: a null thread is the caller; the id is written to `id`.
        if unsafe { pthread_threadid_np(0, &mut id) } != 0 {
            return 0;
        }
        id
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        0
    }
}

/// Every thread of this process, by id: its name and CPU time, user and
/// system, in milliseconds.
pub fn threads() -> HashMap<u64, (String, u64)> {
    let mut out = HashMap::new();
    #[cfg(target_os = "linux")]
    if let Ok(rd) = std::fs::read_dir("/proc/self/task") {
        for e in rd.flatten() {
            let Some(h) = e.file_name().to_str().and_then(|n| n.parse::<u64>().ok()) else { continue };
            let Ok(s) = std::fs::read_to_string(format!("/proc/self/task/{h}/stat")) else { continue };
            let Some(close) = s.rfind(')') else { continue };
            let f: Vec<&str> = s[close + 2..].split_whitespace().collect();
            // utime, stime: fields 14 and 15 of the whole line, in clock ticks.
            let (Some(u), Some(st)) = (f.get(11).and_then(|v| v.parse::<u64>().ok()), f.get(12).and_then(|v| v.parse::<u64>().ok())) else { continue };
            let name = std::fs::read_to_string(format!("/proc/self/task/{h}/comm")).map(|s| s.trim().to_string()).unwrap_or_default();
            out.insert(h, (name, (u + st) * 10));
        }
    }
    #[cfg(target_os = "macos")]
    mach::each(|id, i| {
        let n = i.pth_name.iter().position(|&b| b == 0).unwrap_or(i.pth_name.len());
        let name = String::from_utf8_lossy(&i.pth_name[..n]).into_owned();
        out.insert(id, (name, (i.pth_user_time + i.pth_system_time) / 1_000_000));
    });
    out
}

#[cfg(target_os = "macos")]
mod mach {
    /// `struct thread_extended_info` (`<mach/thread_info.h>`).
    #[repr(C)]
    #[allow(dead_code)]
    pub struct Extended {
        pub pth_user_time: u64,
        pub pth_system_time: u64,
        pub pth_cpu_usage: i32,
        pub pth_policy: i32,
        pub pth_run_state: i32,
        pub pth_flags: i32,
        pub pth_sleep_time: i32,
        pub pth_curpri: i32,
        pub pth_priority: i32,
        pub pth_maxpriority: i32,
        pub pth_name: [u8; 64],
    }

    /// `struct thread_identifier_info`.
    #[repr(C)]
    #[allow(dead_code)]
    struct Identifier {
        thread_id: u64,
        thread_handle: u64,
        dispatch_qaddr: u64,
    }

    const THREAD_IDENTIFIER_INFO: i32 = 4;
    const THREAD_EXTENDED_INFO: i32 = 5;

    #[allow(non_upper_case_globals)]
    extern "C" {
        static mach_task_self_: u32;
        fn thread_info(thread: u32, flavor: i32, info: *mut i32, count: *mut u32) -> i32;
        fn task_threads(task: u32, list: *mut *mut u32, count: *mut u32) -> i32;
        fn mach_port_deallocate(task: u32, name: u32) -> i32;
        fn vm_deallocate(task: u32, address: usize, size: usize) -> i32;
    }

    /// `thread_info` of flavour `flavor` into `T`, the flavour's struct.
    fn info<T>(port: u32, flavor: i32, mut v: T) -> Option<T> {
        let mut n = (std::mem::size_of::<T>() / 4) as u32;
        // SAFETY: `v` is the flavour's struct and `n` its size in 32-bit
        // words, so the kernel writes no further than `v`. A port that no
        // longer names a running thread is an error return, not a fault.
        let kr = unsafe { thread_info(port, flavor, &mut v as *mut T as *mut i32, &mut n) };
        (kr == 0).then_some(v)
    }

    /// `f` for each thread of the task, with its id and its information.
    pub fn each(mut f: impl FnMut(u64, Extended)) {
        let mut list: *mut u32 = std::ptr::null_mut();
        let mut n: u32 = 0;
        // SAFETY: the task's own port, a constant of the process.
        let task = unsafe { mach_task_self_ };
        // SAFETY: the kernel allocates the array and writes its address and
        // length into `list` and `n`.
        if unsafe { task_threads(task, &mut list, &mut n) } != 0 || list.is_null() {
            return;
        }
        // SAFETY: `task_threads` gave `n` ports at `list`.
        let ports = unsafe { std::slice::from_raw_parts(list, n as usize) }.to_vec();
        for &p in &ports {
            let id = info(p, THREAD_IDENTIFIER_INFO, Identifier { thread_id: 0, thread_handle: 0, dispatch_qaddr: 0 });
            let ext = info(
                p,
                THREAD_EXTENDED_INFO,
                Extended {
                    pth_user_time: 0,
                    pth_system_time: 0,
                    pth_cpu_usage: 0,
                    pth_policy: 0,
                    pth_run_state: 0,
                    pth_flags: 0,
                    pth_sleep_time: 0,
                    pth_curpri: 0,
                    pth_priority: 0,
                    pth_maxpriority: 0,
                    pth_name: [0; 64],
                },
            );
            if let (Some(id), Some(ext)) = (id, ext) {
                f(id.thread_id, ext);
            }
            // SAFETY: each port in the list came with a reference added for
            // this call; this gives it back.
            unsafe { mach_port_deallocate(task, p) };
        }
        // SAFETY: the array `task_threads` allocated, of `n` ports.
        unsafe { vm_deallocate(task, list as usize, n as usize * 4) };
    }
}
