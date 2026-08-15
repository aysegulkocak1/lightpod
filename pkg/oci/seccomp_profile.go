package oci

// DefaultSeccompProfile is the built-in policy.
//
// Allowlist, not blocklist. A blocklist needs updating every time the kernel
// gains a syscall, and the gap between "kernel ships io_uring" and "runtime
// blocks it" is where escapes live.
//
// Default action is EPERM rather than KILL: robotics and ML stacks probe for
// optional syscalls at startup and should degrade, not die.
//
// Expressed as an OCI type so it lands in the generated config.json and can be
// read with `lightpod spec` instead of dug out of Go source.
func DefaultSeccompProfile() *LinuxSeccomp {
	eperm := uint(1) // EPERM
	return &LinuxSeccomp{
		DefaultAction:   ActErrno,
		DefaultErrnoRet: &eperm,
		Architectures:   defaultSeccompArchitectures,
		Syscalls: []LinuxSyscall{
			{
				Names:  defaultAllowedSyscalls,
				Action: ActAllow,
			},
		},
	}
}

// Advisory metadata for other tools reading our config.json. Our own compiler
// pins the filter to the running arch and kills anything else.
var defaultSeccompArchitectures = []string{
	"SCMP_ARCH_X86_64",
	"SCMP_ARCH_AARCH64",
	"SCMP_ARCH_ARM",
}

// defaultAllowedSyscalls: what a normal workload needs, nothing more.
//
// Left out on purpose — mount/umount2/pivot_root/chroot, the module and kexec
// calls, ptrace and process_vm_*, bpf, perf_event_open, setns, unshare, the
// keyring calls, userfaultfd, io_uring, swapon/quotactl/acct. Each is either an
// escape primitive or a way to tamper with the host.
//
// clone and clone3 are allowed — a container that can't fork is useless. Their
// namespace flags are handled by a different layer: without CAP_SYS_ADMIN the
// kernel refuses them anyway.
var defaultAllowedSyscalls = []string{
	// process lifecycle
	"execve", "execveat", "exit", "exit_group", "clone", "clone3", "fork", "vfork",
	"wait4", "waitid", "kill", "tkill", "tgkill", "getpid", "getppid", "gettid",
	"set_tid_address", "rt_sigreturn", "sigreturn",

	// scheduling and identity
	"sched_yield", "sched_getaffinity", "sched_setaffinity", "sched_getparam",
	"sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min",
	"getuid", "geteuid", "getgid", "getegid", "getgroups", "setgroups",
	"setuid", "setgid", "setresuid", "setresgid", "getresuid", "getresgid",
	"setpgid", "getpgid", "getpgrp", "setsid", "getsid", "capget", "capset",
	"getpriority", "setpriority", "getrlimit", "setrlimit", "prlimit64", "getrusage",

	// file I/O
	"read", "write", "readv", "writev", "pread64", "pwrite64", "preadv", "pwritev",
	"preadv2", "pwritev2", "open", "openat", "openat2", "close", "close_range",
	"creat", "lseek", "dup", "dup2", "dup3", "pipe", "pipe2", "fcntl", "flock",
	"fsync", "fdatasync", "sync", "syncfs", "truncate", "ftruncate", "fallocate",
	"sendfile", "copy_file_range", "splice", "tee", "vmsplice", "readahead",

	// filesystem metadata
	"stat", "fstat", "lstat", "newfstatat", "statx", "statfs", "fstatfs",
	"access", "faccessat", "faccessat2", "readlink", "readlinkat",
	"getdents", "getdents64", "getcwd", "chdir", "fchdir",
	"mkdir", "mkdirat", "rmdir", "unlink", "unlinkat", "rename", "renameat",
	"renameat2", "link", "linkat", "symlink", "symlinkat",
	"chmod", "fchmod", "fchmodat", "chown", "fchown", "lchown", "fchownat",
	"umask", "utime", "utimes", "utimensat", "futimesat",
	"getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr",
	"setxattr", "lsetxattr", "fsetxattr", "removexattr", "lremovexattr", "fremovexattr",

	// memory
	"mmap", "mmap2", "munmap", "mremap", "mprotect", "madvise", "mincore",
	"brk", "mlock", "mlock2", "munlock", "mlockall", "munlockall", "memfd_create",
	"membarrier",

	// signals
	"rt_sigaction", "rt_sigprocmask", "rt_sigpending", "rt_sigqueueinfo",
	"rt_sigsuspend", "rt_sigtimedwait", "rt_tgsigqueueinfo", "sigaltstack",
	"signalfd", "signalfd4", "pause", "restart_syscall",

	// time
	"nanosleep", "clock_nanosleep", "clock_gettime", "clock_getres",
	"gettimeofday", "times", "time",
	"timer_create", "timer_settime", "timer_gettime", "timer_getoverrun",
	"timer_delete", "timerfd_create", "timerfd_settime", "timerfd_gettime",
	"getitimer", "setitimer", "alarm",

	// event notification
	"poll", "ppoll", "select", "pselect6", "epoll_create", "epoll_create1",
	"epoll_ctl", "epoll_wait", "epoll_pwait", "epoll_pwait2",
	"eventfd", "eventfd2", "inotify_init", "inotify_init1", "inotify_add_watch",
	"inotify_rm_watch",

	// futex and IPC
	"futex", "futex_waitv", "set_robust_list", "get_robust_list",
	"shmget", "shmat", "shmdt", "shmctl", "semget", "semop", "semtimedop",
	"semctl", "msgget", "msgsnd", "msgrcv", "msgctl",
	"mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify",
	"mq_getsetattr",

	// networking — needed by robotics middleware (ROS, DDS, MQTT)
	"socket", "socketpair", "bind", "listen", "accept", "accept4", "connect",
	"getsockname", "getpeername", "sendto", "recvfrom", "sendmsg", "recvmsg",
	"sendmmsg", "recvmmsg", "shutdown", "getsockopt", "setsockopt",

	// terminal and misc
	"ioctl", "uname", "sysinfo", "getrandom", "arch_prctl", "prctl",
	"personality", "gettid", "sched_getattr", "sched_setattr",
	"rseq", "set_thread_area", "get_thread_area", "ugetrlimit",
}
