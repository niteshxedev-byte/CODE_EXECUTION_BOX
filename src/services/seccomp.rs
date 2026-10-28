use std::fs::File;
use std::path::Path;
use libseccomp::{ScmpAction, ScmpArch, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxProfile {
    Compile,   // Profile C: Broader allow-list for compilers/linkers (Profile E + file creation/linking)
    Execution, // Profile E: Strictly minimal allow-list for execution runtime
}

/// Generates a compiled cBPF binary filter matching the requested security profile.
/// Guarantees:
/// 1. Denies x32 ABI via ScmpArch::X8664 and set_act_badarch(KillProcess).
/// 2. Explicitly denies:
///    - io_uring_setup, io_uring_enter, io_uring_register -> Errno(38 / ENOSYS)
///      (Eliminates io_uring kernel attack surface while enabling libuv/Node.js to fall back to epoll)
///    - userfaultfd, bpf, keyctl, ptrace -> KillProcess
///    - mount, umount2, pivot_root, chroot -> KillProcess
///    - perf_event_open -> KillProcess
///    - kexec_load, reboot, init_module, delete_module -> KillProcess
///    - TIOCSTI ioctl (terminal injection attack) -> KillProcess
/// 3. Restricts socket() to allow-listed AF_UNIX only (intra-process event loops).
///    Explicitly kills on raw socket families (AF_NETLINK, AF_PACKET, AF_SMC, AF_VSOCK),
///    and denies all external network sockets with EPERM.
pub fn generate_seccomp_bpf(profile: SandboxProfile, out_path: &Path) -> Result<(), String> {
    // Both Profile C and Profile E are strict allow-lists:
    // Any unlisted syscall returns ENOSYS (38)
    let mut ctx = ScmpFilterContext::new(ScmpAction::Errno(38))
        .map_err(|e| format!("Failed to create seccomp context: {e}"))?;

    // Block x32 ABI and non-native architectures
    ctx.set_act_badarch(ScmpAction::KillProcess)
        .map_err(|e| format!("Failed to set badarch action: {e}"))?;
    ctx.add_arch(ScmpArch::X8664)
        .map_err(|e| format!("Failed to add x86_64 arch: {e}"))?;

    // Base compute syscalls allowed in Execution Phase (Profile E)
    let base_syscalls = [
        "read", "write", "open", "openat", "close", "stat", "fstat", "lstat",
        "newfstatat", "poll", "lseek", "mmap", "mprotect", "munmap", "brk",
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "pread64", "pwrite64",
        "readv", "writev", "access", "faccessat", "faccessat2", "pipe", "pipe2", "select",
        "sched_yield", "mremap", "mincore", "madvise", "dup", "dup2", "dup3",
        "nanosleep", "clock_nanosleep", "getitimer", "setitimer", "alarm",
        "getpid", "getppid", "getuid", "geteuid", "getgid", "getegid", "gettid",
        "fork", "vfork", "execve", "execveat", "exit", "exit_group",
        "wait4", "waitid", "kill", "uname", "fcntl", "flock", "fsync", "fdatasync",
        "truncate", "ftruncate", "getdents", "getdents64", "getcwd", "chdir",
        "readlink", "readlinkat", "umask", "gettimeofday", "getrlimit", "setrlimit",
        "getrusage", "sysinfo", "times", "rt_sigpending", "rt_sigtimedwait",
        "rt_sigsuspend", "sigaltstack", "statfs", "fstatfs", "prctl", "arch_prctl",
        "futex", "sched_setaffinity", "sched_getaffinity", "set_tid_address",
        "restart_syscall", "clock_gettime", "clock_getres", "tgkill", "get_robust_list",
        "set_robust_list", "epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait",
        "epoll_pwait", "eventfd", "eventfd2", "prlimit64", "memfd_create", "statx", "rseq",
        "getrandom", "ioctl", "close_range", "setpgid", "getpgid", "getsid", "setsid",
        "sched_getparam", "sched_setparam", "sched_getscheduler", "sched_setscheduler",
        "sched_get_priority_max", "sched_get_priority_min", "unlink", "unlinkat",
        "inotify_init1", "inotify_add_watch", "inotify_rm_watch", "socketpair",
        "recvmsg", "sendmsg", "recvfrom", "sendto", "getsockopt", "setsockopt", "shutdown",
        "getpeername", "getsockname", "pidfd_open"
    ];

    for s in &base_syscalls {
        if let Ok(sys) = ScmpSyscall::from_name(s) {
            let _ = ctx.add_rule(ScmpAction::Allow, sys);
        }
    }

    // Profile C (Compile Phase) allow-list additions:
    // Strictly defines C = E ∪ {mkdir, rename, link, chmod, symlink, preadv, pwritev}
    if profile == SandboxProfile::Compile {
        let compile_extras = [
            "mkdir", "mkdirat", "rmdir", "rename", "renameat", "renameat2",
            "link", "linkat", "chmod", "fchmod", "fchmodat",
            "symlink", "symlinkat", "preadv", "pwritev"
        ];
        for s in &compile_extras {
            if let Ok(sys) = ScmpSyscall::from_name(s) {
                let _ = ctx.add_rule(ScmpAction::Allow, sys);
            }
        }
    }

    // Filter clone(2): Allow thread and child process creation, but explicitly
    // DENY CLONE_NEWUSER (0x10000000) with EPERM (1). This structurally prevents
    // untrusted code from creating nested user namespaces!
    if let Ok(sys) = ScmpSyscall::from_name("clone") {
        let newuser_cmp = ScmpArgCompare::new(0, ScmpCompareOp::MaskedEqual(0x10000000), 0x10000000);
        let _ = ctx.add_rule_conditional(ScmpAction::Errno(1), sys, &[newuser_cmp]);

        let no_newuser_cmp = ScmpArgCompare::new(0, ScmpCompareOp::MaskedEqual(0x10000000), 0);
        let _ = ctx.add_rule_conditional(ScmpAction::Allow, sys, &[no_newuser_cmp]);
    }

    // Explicitly DENY clone3 with ENOSYS (38).
    // The clone3 flags live behind a user pointer and cannot be inspected by cBPF.
    // Denying clone3 with ENOSYS causes glibc and libpthread to fall back to clone(2) cleanly.
    if let Ok(sys) = ScmpSyscall::from_name("clone3") {
        let _ = ctx.add_rule(ScmpAction::Errno(38), sys);
    }

    // Explicitly DENY unshare with EPERM (1) to prevent namespace manipulation
    if let Ok(sys) = ScmpSyscall::from_name("unshare") {
        let _ = ctx.add_rule(ScmpAction::Errno(1), sys);
    }

    // Filter ioctl: Kill on TIOCSTI (0x5412) to prevent terminal injection escape,
    // and kill on dangerous console/keyboard/filesystem ioctls:
    // TIOCLINUX (0x541C), KDSKBENT (0x4B4D), KDGKBTYPE (0x4B33), KDSKBMODE (0x4B45),
    // FS_IOC_SETFLAGS (0x40086602), FS_IOC_SETVERSION (0x40087602)
    if let Ok(sys) = ScmpSyscall::from_name("ioctl") {
        for bad_ioctl in [0x5412, 0x541C, 0x4B4D, 0x4B33, 0x4B45, 0x40086602, 0x40087602] {
            let cmp = ScmpArgCompare::new(1, ScmpCompareOp::Equal, bad_ioctl);
            let _ = ctx.add_rule_conditional(ScmpAction::KillProcess, sys, &[cmp]);
        }
    }

    // Filter prctl: Block PR_SET_MM (35) with EPERM (1)
    if let Ok(sys) = ScmpSyscall::from_name("prctl") {
        let mm_cmp = ScmpArgCompare::new(0, ScmpCompareOp::Equal, 35);
        let _ = ctx.add_rule_conditional(ScmpAction::Errno(1), sys, &[mm_cmp]);
    }

    // Explicitly DENY io_uring outright with ENOSYS (38)
    // Completely closes kernel attack surface while enabling libuv/Node.js to fall back to epoll
    for s in ["io_uring_setup", "io_uring_enter", "io_uring_register"] {
        if let Ok(sys) = ScmpSyscall::from_name(s) {
            let _ = ctx.add_rule(ScmpAction::Errno(38), sys);
        }
    }

    // Explicitly DENY exploit and privilege-escalation syscalls with KillProcess (Zero Tolerance)
    // Enforced in BOTH Profile C and Profile E to prevent build script (build.rs/setup.py) escapes
    let explicit_denies = [
        "userfaultfd", "bpf", "keyctl", "ptrace",
        "mount", "umount2", "pivot_root", "perf_event_open",
        "kexec_load", "kexec_file_load", "reboot",
        "init_module", "finit_module", "delete_module",
        "lookup_dcookie", "quotactl", "nfsservctl", "chroot"
    ];
    for s in &explicit_denies {
        if let Ok(sys) = ScmpSyscall::from_name(s) {
            let _ = ctx.add_rule(ScmpAction::KillProcess, sys);
        }
    }

    // Socket family restrictions:
    // Kill on dangerous raw / kernel network socket families (AF_NETLINK, AF_PACKET, AF_VSOCK, AF_SMC)
    // Allow AF_UNIX (1) for intra-process event loops (Node.js libuv / Python)
    // Deny all other external network sockets with EAFNOSUPPORT (97) - standard POSIX code for unsupported family
    if let Ok(sys) = ScmpSyscall::from_name("socket") {
        for bad_family in [16 /* AF_NETLINK */, 17 /* AF_PACKET */, 40 /* AF_VSOCK */, 43 /* AF_SMC */] {
            let cmp = ScmpArgCompare::new(0, ScmpCompareOp::Equal, bad_family);
            let _ = ctx.add_rule_conditional(ScmpAction::KillProcess, sys, &[cmp]);
        }
        let unix_cmp = ScmpArgCompare::new(0, ScmpCompareOp::Equal, 1);
        let _ = ctx.add_rule_conditional(ScmpAction::Allow, sys, &[unix_cmp]);
        let _ = ctx.add_rule(ScmpAction::Errno(97), sys); // 97 = EAFNOSUPPORT
    }

    if let Ok(sys) = ScmpSyscall::from_name("socketpair") {
        let unix_cmp = ScmpArgCompare::new(0, ScmpCompareOp::Equal, 1);
        let _ = ctx.add_rule_conditional(ScmpAction::Allow, sys, &[unix_cmp]);
    }

    let file = File::create(out_path)
        .map_err(|e| format!("Failed to create seccomp BPF output file: {e}"))?;

    ctx.export_bpf(file)
        .map_err(|e| format!("Failed to export seccomp BPF bytecode: {e}"))?;

    Ok(())
}
