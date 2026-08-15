package runtime

// setns(2) on amd64. Go's syscall package doesn't export SYS_SETNS everywhere.
// Per-arch constant so a missing port is a compile error, not a surprise.
const sysSetns = 308
