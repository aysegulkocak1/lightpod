// Package security: capabilities, seccomp, no_new_privs. No libseccomp, no
// libcap — the whole policy is auditable in this repo.
package security

import (
	"syscall"
	"unsafe"
)

// prctl options the syscall package doesn't export.
const (
	prSetKeepCaps        = 8
	prCapBSetRead        = 23
	prCapBSetDrop        = 24
	prSetNoNewPrivs      = 38
	prCapAmbient         = 47
	prCapAmbientRaise    = 2
	prCapAmbientClearAll = 4
)

// seccomp(2) operations and flags.
const (
	seccompSetModeFilter   = 1
	seccompFilterFlagTsync = 1
)

// prctl wraps prctl(2). Every raw syscall in this package lives in this file,
// so the unsafe surface is reviewable in one place.
func prctl(option, arg2, arg3, arg4, arg5 uintptr) error {
	_, err := prctlRet(option, arg2, arg3, arg4, arg5)
	return err
}

// prctlRet is for options that answer in the return value, like PR_CAPBSET_READ.
func prctlRet(option, arg2, arg3, arg4, arg5 uintptr) (int, error) {
	ret, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, option, arg2, arg3, arg4, arg5, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(ret), nil
}

// capHeader is the cap_user_header_t of capset(2)/capget(2).
type capHeader struct {
	version uint32
	pid     int32
}

// capData is one cap_user_data_t. Version 3 takes two: bits 0-31 and 32-63.
type capData struct {
	effective   uint32
	permitted   uint32
	inheritable uint32
}

// capVersion3 is _LINUX_CAPABILITY_VERSION_3, the 64-bit capability ABI.
const capVersion3 = 0x20080522

// capset wraps capset(2).
func capset(hdr *capHeader, data *[2]capData) error {
	if _, _, errno := syscall.RawSyscall(
		syscall.SYS_CAPSET,
		uintptr(unsafe.Pointer(hdr)),
		uintptr(unsafe.Pointer(&data[0])),
		0,
	); errno != 0 {
		return errno
	}
	return nil
}

// capget wraps capget(2).
func capget(hdr *capHeader, data *[2]capData) error {
	if _, _, errno := syscall.RawSyscall(
		syscall.SYS_CAPGET,
		uintptr(unsafe.Pointer(hdr)),
		uintptr(unsafe.Pointer(&data[0])),
		0,
	); errno != 0 {
		return errno
	}
	return nil
}

// sockFilter is one classic BPF instruction (struct sock_filter).
type sockFilter struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

// sockFprog is struct sock_fprog.
//
// No explicit padding — Go aligns the pointer the same way C does, so this is
// right on both 64-bit and 32-bit. Hand-written padding would only be right on one.
type sockFprog struct {
	len    uint16
	filter *sockFilter
}

// seccompSetFilter installs the BPF program.
//
// seccomp(2) rather than prctl(PR_SET_SECCOMP) because only it supports TSYNC.
// Go is multi-threaded; a filter covering one thread would be bypassed by
// scheduling work onto another.
func seccompSetFilter(filter []sockFilter) error {
	// SYS_SECCOMP isn't exported on every arch, so take it from the generated
	// table — same source the filter itself uses.
	nr, ok := syscallNumbers["seccomp"]
	if !ok {
		return errUnsupportedArch
	}

	prog := sockFprog{
		len:    uint16(len(filter)),
		filter: &filter[0],
	}
	if _, _, errno := syscall.RawSyscall(
		uintptr(nr),
		seccompSetModeFilter,
		seccompFilterFlagTsync,
		uintptr(unsafe.Pointer(&prog)),
	); errno != 0 {
		return errno
	}
	return nil
}
