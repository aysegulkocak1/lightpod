package security

import (
	"errors"
	"fmt"

	"github.com/aysegulkocak1/lightpod/pkg/oci"
)

var errUnsupportedArch = errors.New("seccomp: this architecture is not supported by lightpod")

// Classic BPF opcodes, composed from the class/size/mode bits so the program
// reads against bpf(4) instead of being magic numbers.
const (
	bpfLD  = 0x00
	bpfW   = 0x00
	bpfABS = 0x20
	bpfJMP = 0x05
	bpfJEQ = 0x10
	bpfJGE = 0x30
	bpfK   = 0x00
	bpfRET = 0x06

	opLoadAbsWord = bpfLD | bpfW | bpfABS  // ld [k]
	opJumpEqual   = bpfJMP | bpfJEQ | bpfK // jeq #k, jt, jf
	opJumpGE      = bpfJMP | bpfJGE | bpfK // jge #k, jt, jf
	opReturn      = bpfRET | bpfK          // ret #k
)

// Offsets into struct seccomp_data:
// { int nr; __u32 arch; __u64 instruction_pointer; __u64 args[6]; }
const (
	offsetNr   = 0
	offsetArch = 4
)

// seccomp filter return actions.
const (
	retKillProcess = 0x80000000
	retTrap        = 0x00030000
	retErrno       = 0x00050000
	retTrace       = 0x7ff00000
	retLog         = 0x7ffc0000
	retAllow       = 0x7fff0000
	retKillThread  = 0x00000000

	errnoMask = 0x0000ffff
)

// maxFilterInstructions is the kernel's BPF_MAXINSNS limit for seccomp filters.
const maxFilterInstructions = 4096

// __X32_SYSCALL_BIT. x32 calls set bit 30 but still report AUDIT_ARCH_X86_64.
const x32SyscallBit = 0x40000000

// ApplySeccomp compiles the profile and installs it.
//
// Call as late as possible, right before execve — setup needs mount and
// pivot_root, which any sane profile denies. Also must come after
// PR_SET_NO_NEW_PRIVS or the kernel refuses the filter.
func ApplySeccomp(profile *oci.LinuxSeccomp) error {
	if profile == nil {
		return nil
	}
	filter, err := CompileSeccomp(profile)
	if err != nil {
		return err
	}
	if err := seccompSetFilter(filter); err != nil {
		return fmt.Errorf("installing seccomp filter (%d instructions): %w", len(filter), err)
	}
	return nil
}

// CompileSeccomp turns an OCI profile into a classic BPF program.
//
// Kept separate from installation so it can be unit tested without a container.
// A mis-compiled filter is a silently weakened sandbox — never announces itself.
func CompileSeccomp(profile *oci.LinuxSeccomp) ([]sockFilter, error) {
	if auditArch == 0 {
		return nil, errUnsupportedArch
	}

	defaultAction, err := actionValue(profile.DefaultAction, profile.DefaultErrnoRet)
	if err != nil {
		return nil, fmt.Errorf("defaultAction: %w", err)
	}

	var filter []sockFilter

	// Pin to one arch first. Otherwise a process on x86_64 can call through the
	// i386 or x32 ABI, where the same number is a different syscall, and walk
	// straight past the allowlist.
	//
	// The kill sits right after the comparison to keep every jump offset at 0
	// or 1
	filter = append(filter,
		sockFilter{code: opLoadAbsWord, k: offsetArch},
		sockFilter{code: opJumpEqual, jt: 1, jf: 0, k: auditArch},
		sockFilter{code: opReturn, k: retKillProcess},
		sockFilter{code: opLoadAbsWord, k: offsetNr},
	)

	// x32 shares AUDIT_ARCH_X86_64, so the check above misses it.
	if guardX32 {
		filter = append(filter,
			sockFilter{code: opJumpGE, jt: 0, jf: 1, k: x32SyscallBit},
			sockFilter{code: opReturn, k: retKillProcess},
		)
	}

	for i, rule := range profile.Syscalls {
		if len(rule.Args) > 0 {
			// Ignoring the condition would widen a narrow rule.
			return nil, fmt.Errorf("syscalls[%d]: argument-conditional rules are not supported yet", i)
		}
		action, err := actionValue(rule.Action, rule.ErrnoRet)
		if err != nil {
			return nil, fmt.Errorf("syscalls[%d]: %w", i, err)
		}
		for _, name := range rule.Names {
			nr, ok := syscallNumbers[name]
			if !ok {
				// Profiles are portable; a syscall that doesn't exist here just
				// can't be called. Default action still covers it.
				continue
			}
			filter = append(filter,
				sockFilter{code: opJumpEqual, jt: 0, jf: 1, k: uint32(nr)},
				sockFilter{code: opReturn, k: action},
			)
		}
	}

	filter = append(filter, sockFilter{code: opReturn, k: defaultAction})

	if len(filter) > maxFilterInstructions {
		return nil, fmt.Errorf("seccomp filter is %d instructions, kernel limit is %d",
			len(filter), maxFilterInstructions)
	}
	return filter, nil
}

// actionValue maps an OCI seccomp action to its BPF return value.
func actionValue(action oci.LinuxSeccompAction, errnoRet *uint) (uint32, error) {
	switch action {
	case oci.ActAllow:
		return retAllow, nil
	case oci.ActErrno:
		errno := uint32(1) // EPERM
		if errnoRet != nil {
			errno = uint32(*errnoRet)
		}
		return retErrno | (errno & errnoMask), nil
	case oci.ActKillProcess:
		return retKillProcess, nil
	case oci.ActKill:
		return retKillThread, nil
	case oci.ActTrap:
		return retTrap, nil
	case oci.ActTrace:
		return retTrace, nil
	case oci.ActLog:
		return retLog, nil
	case "":
		return 0, errors.New("action is empty")
	default:
		return 0, fmt.Errorf("unknown action %q", action)
	}
}

// SetNoNewPrivs stops this process and its children gaining privileges through
// execve — setuid bits and file capabilities stop working.
//
// Required before loading a seccomp filter unprivileged, and the one thing that
// keeps a dropped capability from coming back via a setuid binary in the image.
func SetNoNewPrivs() error {
	if err := prctl(prSetNoNewPrivs, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", err)
	}
	return nil
}

// SetKeepCaps controls whether capabilities survive a uid change.
//
// The kernel clears permitted caps when a process leaves uid 0. Right for
// setuid programs, wrong here: we apply the capability policy after the switch,
// and without this it would be applied to an already-empty set — looking
// effective while doing nothing.
func SetKeepCaps(keep bool) error {
	value := uintptr(0)
	if keep {
		value = 1
	}
	if err := prctl(prSetKeepCaps, value, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(PR_SET_KEEPCAPS, %v): %w", keep, err)
	}
	return nil
}
