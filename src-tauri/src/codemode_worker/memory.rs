use std::process::{Child, Command};

use super::MEMORY_LIMIT_BYTES;

pub const MEMORY_EXIT_CODE: i32 = 86;

pub fn is_memory_termination(status: &std::process::ExitStatus) -> bool {
    if status.code() == Some(MEMORY_EXIT_CODE) {
        return true;
    }
    #[cfg(windows)]
    {
        // Native allocation/commitment exhaustion can also terminate a worker.
        // Generic fail-fast (0xC0000409) is not specific to memory exhaustion.
        return status
            .code()
            .is_some_and(|code| matches!(code as u32, 0xC0000017 | 0xC000012D));
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn configure(command: &mut Command) -> std::io::Result<()> {
    use std::os::unix::process::CommandExt;
    // glibc otherwise reserves a large arena per host-call thread, consuming
    // the address-space limit even for small, ordinary parallel scripts.
    #[cfg(target_os = "linux")]
    command.env("MALLOC_ARENA_MAX", "2");
    // SAFETY: only async-signal-safe resource-limit syscalls run after fork.
    unsafe {
        command.pre_exec(|| {
            let mut inherited = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::getrlimit(libc::RLIMIT_AS, &mut inherited) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let bytes = (MEMORY_LIMIT_BYTES as libc::rlim_t)
                .min(inherited.rlim_cur)
                .min(inherited.rlim_max);
            let memory = libc::rlimit {
                rlim_cur: bytes,
                rlim_max: bytes,
            };
            let core = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_AS, &memory) != 0
                || libc::setrlimit(libc::RLIMIT_CORE, &core) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn configure(command: &mut Command) -> std::io::Result<()> {
    use std::os::unix::process::CommandExt;
    // Darwin's RLIMIT_AS is an RSS hint and cannot be lowered below the
    // already mapped gateway image. The worker allocator enforces the actual
    // heap budget after exec; disable core dumps as a second containment aid.
    // SAFETY: only the async-signal-safe setrlimit call runs after fork.
    unsafe {
        command.pre_exec(|| {
            let core = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &core) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}

#[cfg(windows)]
pub fn configure(command: &mut Command) -> std::io::Result<()> {
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::System::Threading::{CREATE_NO_WINDOW, CREATE_SUSPENDED};
    // No worker instruction may execute before it belongs to the limited job.
    command.creation_flags(CREATE_NO_WINDOW | CREATE_SUSPENDED);
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub fn configure(_command: &mut Command) -> std::io::Result<()> {
    Err(std::io::Error::other(
        "code mode memory isolation is unavailable on this platform",
    ))
}

#[cfg(not(windows))]
pub struct Job;

#[cfg(not(windows))]
impl Job {
    pub fn attach(_child: &Child) -> std::io::Result<Self> {
        Ok(Self)
    }
}

#[cfg(windows)]
pub struct Job(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Job {
    pub fn attach(child: &Child) -> std::io::Result<Self> {
        use std::mem::{size_of, zeroed};
        use std::os::windows::io::AsRawHandle;
        use std::ptr;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
        };
        // SAFETY: initialized structures, checked handles, and a suspended child.
        unsafe {
            let handle = CreateJobObjectW(ptr::null(), ptr::null());
            if handle.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            let job = Self(handle);
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
            info.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
            info.ProcessMemoryLimit = MEMORY_LIMIT_BYTES;
            if SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) == 0
                || AssignProcessToJobObject(handle, child.as_raw_handle() as _) == 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Self::resume(child)?;
            Ok(job)
        }
    }

    fn resume(child: &Child) -> std::io::Result<()> {
        use std::mem::size_of;
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };
        use windows_sys::Win32::System::Threading::{
            OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
        };
        // std::process::Child exposes only the process handle. The suspended
        // process has exactly one thread; locate it without running the loader.
        // SAFETY: snapshot/thread handles are checked and closed on every path.
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                return Err(std::io::Error::last_os_error());
            }
            let result = (|| {
                let mut entry = THREADENTRY32 {
                    dwSize: size_of::<THREADENTRY32>() as u32,
                    ..Default::default()
                };
                let mut found = Thread32First(snapshot, &mut entry);
                while found != 0 {
                    if entry.th32OwnerProcessID == child.id() {
                        let thread = OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID);
                        if thread.is_null() {
                            return Err(std::io::Error::last_os_error());
                        }
                        let resumed = ResumeThread(thread);
                        let error = (resumed == u32::MAX).then(std::io::Error::last_os_error);
                        CloseHandle(thread);
                        return error.map_or(Ok(()), Err);
                    }
                    found = Thread32Next(snapshot, &mut entry);
                }
                Err(std::io::Error::other(
                    "code mode worker primary thread was not found",
                ))
            })();
            CloseHandle(snapshot);
            result
        }
    }
}

#[cfg(windows)]
impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: this value exclusively owns the job handle.
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

// Account from process startup so frees of pre-worker allocations cannot
// undercount the heap. Allocation failure exits before Boa can turn a refused
// allocation into a catchable RangeError. The exit code supplies attribution
// without trusting script-controlled error text. The OS limits still apply on
// Linux and Windows; this allocator supplies the heap cap on Darwin.
#[cfg(any(unix, windows))]
mod allocator {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    static USED: AtomicUsize = AtomicUsize::new(0);
    static LIMITED: AtomicBool = AtomicBool::new(false);

    pub struct WorkerAllocator;

    pub fn enable() {
        LIMITED.store(true, Ordering::SeqCst);
        reserve(0);
    }

    fn memory_exit() -> ! {
        // No allocating panic, destructors, or atexit handlers on this path.
        #[cfg(unix)]
        unsafe {
            libc::_exit(super::MEMORY_EXIT_CODE);
        }
        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::System::Threading::{GetCurrentProcess, TerminateProcess};
            TerminateProcess(GetCurrentProcess(), super::MEMORY_EXIT_CODE as u32);
            std::process::abort();
        }
    }

    fn allocation_failed() {
        if LIMITED.load(Ordering::SeqCst) {
            memory_exit();
        }
    }

    fn reserve(bytes: usize) {
        let previous = USED.fetch_add(bytes, Ordering::SeqCst);
        if LIMITED.load(Ordering::SeqCst)
            && previous.saturating_add(bytes) > super::MEMORY_LIMIT_BYTES
        {
            memory_exit();
        }
    }

    // SAFETY: pointers and layouts are forwarded unchanged to System. The
    // counters never allocate and failed allocations undo their reservation.
    unsafe impl GlobalAlloc for WorkerAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            reserve(layout.size());
            let ptr = unsafe { System.alloc(layout) };
            if ptr.is_null() {
                allocation_failed();
                USED.fetch_sub(layout.size(), Ordering::SeqCst);
            }
            ptr
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            reserve(layout.size());
            let ptr = unsafe { System.alloc_zeroed(layout) };
            if ptr.is_null() {
                allocation_failed();
                USED.fetch_sub(layout.size(), Ordering::SeqCst);
            }
            ptr
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe {
                System.dealloc(ptr, layout);
            }
            USED.fetch_sub(layout.size(), Ordering::SeqCst);
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            let growth = size.saturating_sub(layout.size());
            reserve(growth);
            let next = unsafe { System.realloc(ptr, layout, size) };
            if next.is_null() {
                allocation_failed();
                USED.fetch_sub(growth, Ordering::SeqCst);
            } else if size < layout.size() {
                USED.fetch_sub(layout.size() - size, Ordering::SeqCst);
            }
            next
        }
    }
}

#[cfg(any(unix, windows))]
pub use allocator::WorkerAllocator;

pub fn enable_worker_limit() {
    #[cfg(any(unix, windows))]
    allocator::enable();
}
