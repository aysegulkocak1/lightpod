package security

import (
	"testing"

	"github.com/aysegulkocak1/lightpod/pkg/oci"
)

// The compiler is unit tested because a mis-compiled filter fails silently: the
// container starts, the workload runs, and the sandbox simply is not there. A
// runtime error would at least be noticed.

func TestCompileSeccompStructure(t *testing.T) {
	profile := &oci.LinuxSeccomp{
		DefaultAction: oci.ActErrno,
		Syscalls: []oci.LinuxSyscall{
			{Names: []string{"read", "write"}, Action: oci.ActAllow},
		},
	}

	filter, err := CompileSeccomp(profile)
	if err != nil {
		t.Fatalf("CompileSeccomp: %v", err)
	}

	// The architecture check must be the very first thing the filter does.
	// Anything before it would be evaluated for calls arriving on a foreign
	// ABI, where the syscall numbers mean something else entirely.
	if filter[0].code != opLoadAbsWord || filter[0].k != offsetArch {
		t.Fatalf("filter does not start by loading the arch field: %+v", filter[0])
	}
	if filter[1].code != opJumpEqual || filter[1].k != auditArch {
		t.Fatalf("second instruction is not the arch comparison: %+v", filter[1])
	}
	if filter[2].code != opReturn || filter[2].k != retKillProcess {
		t.Fatalf("arch mismatch does not lead to a kill: %+v", filter[2])
	}

	last := filter[len(filter)-1]
	if last.code != opReturn || last.k != retErrno|1 {
		t.Fatalf("filter does not end with the default ERRNO action: %+v", last)
	}
}

func TestCompileSeccompJumpOffsetsStayInRange(t *testing.T) {
	// BPF jump offsets are 8-bit. A layout that pointed branches at the end of
	// the program would overflow silently once a profile grew past 255
	// instructions, and the default profile is far larger than that.
	filter, err := CompileSeccomp(oci.DefaultSeccompProfile())
	if err != nil {
		t.Fatalf("CompileSeccomp: %v", err)
	}
	if len(filter) < 100 {
		t.Fatalf("default profile compiled to only %d instructions; the allowlist did not resolve", len(filter))
	}
	for i, insn := range filter {
		if insn.jt > 1 || insn.jf > 1 {
			t.Fatalf("instruction %d has an out-of-range jump (jt=%d jf=%d)", i, insn.jt, insn.jf)
		}
	}
}

func TestCompileSeccompRejectsArgRules(t *testing.T) {
	// Ignoring an argument condition would widen a narrow rule. The failure
	// direction matters: a wider sandbox than the author wrote is a security
	// regression, so this must be an error and not a skip.
	profile := &oci.LinuxSeccomp{
		DefaultAction: oci.ActErrno,
		Syscalls: []oci.LinuxSyscall{{
			Names:  []string{"ioctl"},
			Action: oci.ActAllow,
			Args:   []oci.LinuxSeccompArg{{Index: 1, Value: 0x5401, Op: "SCMP_CMP_EQ"}},
		}},
	}
	if _, err := CompileSeccomp(profile); err == nil {
		t.Fatal("expected an error for an argument-conditional rule, got nil")
	}
}

func TestCompileSeccompRejectsUnknownAction(t *testing.T) {
	profile := &oci.LinuxSeccomp{DefaultAction: "SCMP_ACT_NONSENSE"}
	if _, err := CompileSeccomp(profile); err == nil {
		t.Fatal("expected an error for an unknown default action, got nil")
	}
}

func TestDefaultProfileDeniesEscapeSyscalls(t *testing.T) {
	// These are the syscalls that turn a container compromise into a host
	// compromise. If a future edit adds one to the allowlist, this test is the
	// thing that objects.
	forbidden := []string{
		"mount", "umount2", "pivot_root", "ptrace", "init_module",
		"finit_module", "delete_module", "kexec_load", "reboot",
		"setns", "unshare", "bpf", "perf_event_open", "add_key", "keyctl",
		"userfaultfd", "swapon",
	}

	allowed := map[string]bool{}
	for _, rule := range oci.DefaultSeccompProfile().Syscalls {
		if rule.Action != oci.ActAllow {
			continue
		}
		for _, name := range rule.Names {
			allowed[name] = true
		}
	}

	for _, name := range forbidden {
		if allowed[name] {
			t.Errorf("%s is in the default allowlist; it is a container escape primitive", name)
		}
	}
}

func TestDefaultProfileAllowsRealTimeScheduling(t *testing.T) {
	// Robotics control loops need SCHED_FIFO/SCHED_RR. Blocking these bought
	// nothing anyway — sched_setattr does the same job and was always allowed —
	// while breaking every RT workload. The real gate is CAP_SYS_NICE.
	required := []string{
		"sched_setscheduler", "sched_setparam", "sched_setattr",
		"sched_rr_get_interval", "mlockall", "setpriority",
	}

	allowed := allowedSyscalls()
	for _, name := range required {
		if !allowed[name] {
			t.Errorf("%s is not allowed; real-time workloads will fail at startup", name)
		}
	}
}

func TestRealTimeStaysGatedByCapabilities(t *testing.T) {
	// Allowing the syscall is only safe because the capability is not granted.
	// If CAP_SYS_NICE ever lands in the defaults, every container gains the
	// ability to starve the host CPU.
	for _, name := range oci.DefaultCapabilities {
		if name == "CAP_SYS_NICE" {
			t.Fatal("CAP_SYS_NICE is in the default capability set: containers can now " +
				"raise real-time priority and starve the host")
		}
	}
}

func allowedSyscalls() map[string]bool {
	allowed := map[string]bool{}
	for _, rule := range oci.DefaultSeccompProfile().Syscalls {
		if rule.Action != oci.ActAllow {
			continue
		}
		for _, name := range rule.Names {
			allowed[name] = true
		}
	}
	return allowed
}

func TestDefaultProfileAllowsOrdinaryWork(t *testing.T) {
	// The opposite failure: a profile so tight nothing runs. These are the
	// syscalls any process makes before it does anything interesting.
	required := []string{"read", "write", "execve", "openat", "mmap", "exit_group", "clone"}

	allowed := map[string]bool{}
	for _, rule := range oci.DefaultSeccompProfile().Syscalls {
		if rule.Action != oci.ActAllow {
			continue
		}
		for _, name := range rule.Names {
			allowed[name] = true
		}
	}

	for _, name := range required {
		if !allowed[name] {
			t.Errorf("%s is missing from the default allowlist; ordinary programs will not run", name)
		}
	}
}

func TestSyscallTableResolvesCommonNames(t *testing.T) {
	// Guards the generated table: an empty or misgenerated map would make every
	// allowlist entry silently unresolvable, producing a filter that denies
	// everything.
	for _, name := range []string{"read", "write", "execve", "mount", "seccomp"} {
		if _, ok := syscallNumbers[name]; !ok {
			t.Errorf("syscall %q is missing from the generated table for this architecture", name)
		}
	}
}
