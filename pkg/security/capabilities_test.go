package security

import (
	"testing"

	"github.com/aysegulkocak1/lightpod/pkg/oci"
)

func TestParseCapabilities(t *testing.T) {
	set, err := parseCapabilities([]string{"CAP_CHOWN", "CAP_SYS_ADMIN"})
	if err != nil {
		t.Fatalf("parseCapabilities: %v", err)
	}
	if !set.has(CAP_CHOWN) || !set.has(CAP_SYS_ADMIN) {
		t.Fatalf("expected CHOWN and SYS_ADMIN to be set, got %v", set.Names())
	}
	if set.has(CAP_NET_RAW) {
		t.Fatal("NET_RAW was not requested but is set")
	}
}

func TestParseCapabilitiesRejectsUnknown(t *testing.T) {
	// A typo in config.json must not quietly produce a different privilege set
	// than the author intended.
	if _, err := parseCapabilities([]string{"CAP_MADE_UP"}); err == nil {
		t.Fatal("expected an error for an unknown capability, got nil")
	}
}

func TestCapabilitySetSplitsAcrossBothWords(t *testing.T) {
	// capset(2) version 3 takes two 32-bit words. A capability above bit 31 has
	// to land in the high word; getting this wrong would silently fail to drop
	// the newer capabilities, CAP_BPF and CAP_PERFMON among them.
	set, err := parseCapabilities([]string{"CAP_CHOWN", "CAP_BPF"})
	if err != nil {
		t.Fatalf("parseCapabilities: %v", err)
	}
	if set.low() != 1<<CAP_CHOWN {
		t.Errorf("low word = %#x, want %#x", set.low(), 1<<CAP_CHOWN)
	}
	if set.high() != 1<<(CAP_BPF-32) {
		t.Errorf("high word = %#x, want %#x", set.high(), 1<<(CAP_BPF-32))
	}
}

func TestDefaultCapabilitiesExcludeEscapePrimitives(t *testing.T) {
	// The default set is a security decision; this pins it so that a future
	// convenience change has to argue with a failing test.
	forbidden := map[string]string{
		"CAP_SYS_ADMIN":  "grants mount and namespace control",
		"CAP_SYS_MODULE": "loads kernel modules",
		"CAP_SYS_PTRACE": "reads other processes' memory",
		"CAP_SYS_RAWIO":  "grants raw hardware access",
		"CAP_NET_ADMIN":  "reconfigures host networking",
		"CAP_NET_RAW":    "enables ARP and DNS spoofing",
		"CAP_MKNOD":      "creates device nodes",
		"CAP_SYS_BOOT":   "reboots the host",
	}
	for _, name := range oci.DefaultCapabilities {
		if reason, bad := forbidden[name]; bad {
			t.Errorf("%s is in the default capability set: it %s", name, reason)
		}
	}
}

func TestDefaultCapabilitiesAreAllKnown(t *testing.T) {
	// ApplyCapabilities rejects unknown names, so an unrecognised default would
	// make every container fail to start.
	if _, err := parseCapabilities(oci.DefaultCapabilities); err != nil {
		t.Fatalf("default capability set does not parse: %v", err)
	}
}
