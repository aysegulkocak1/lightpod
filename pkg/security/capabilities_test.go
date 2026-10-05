package security

import (
	"strings"
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

func TestResolveCapabilitiesNilDropsEverything(t *testing.T) {
	// No section means no capabilities, not "keep what we inherited", which in
	// rootfull mode is the host's full root set.
	p, err := resolveCapabilities(nil)
	if err != nil {
		t.Fatalf("resolveCapabilities(nil): %v", err)
	}
	for _, s := range []struct {
		name string
		set  capSet
	}{
		{"bounding", p.bounding},
		{"effective", p.effective},
		{"permitted", p.permitted},
		{"inheritable", p.inheritable},
		{"ambient", p.ambient},
	} {
		if s.set != 0 {
			t.Errorf("%s set = %#x (%v), want empty", s.name, uint64(s.set), s.set.Names())
		}
	}
}

func TestResolveCapabilitiesEmptySectionMatchesNil(t *testing.T) {
	// "capabilities": {} and no capabilities key at all mean the same thing.
	fromNil, err := resolveCapabilities(nil)
	if err != nil {
		t.Fatalf("resolveCapabilities(nil): %v", err)
	}
	fromEmpty, err := resolveCapabilities(&oci.LinuxCapabilities{})
	if err != nil {
		t.Fatalf("resolveCapabilities(&{}): %v", err)
	}
	if fromNil != fromEmpty {
		t.Errorf("nil section resolved to %+v, empty section to %+v", fromNil, fromEmpty)
	}
}

func TestResolveCapabilitiesCarriesEachSetSeparately(t *testing.T) {
	// The sets aren't interchangeable: permitted without effective is a cap the
	// process can raise but isn't using.
	p, err := resolveCapabilities(&oci.LinuxCapabilities{
		Bounding:    []string{"CAP_CHOWN", "CAP_NET_RAW"},
		Effective:   []string{"CAP_CHOWN"},
		Permitted:   []string{"CAP_CHOWN", "CAP_NET_RAW"},
		Inheritable: []string{"CAP_NET_RAW"},
		Ambient:     []string{"CAP_NET_RAW"},
	})
	if err != nil {
		t.Fatalf("resolveCapabilities: %v", err)
	}
	if !p.bounding.has(CAP_CHOWN) || !p.bounding.has(CAP_NET_RAW) {
		t.Errorf("bounding = %v, want CHOWN and NET_RAW", p.bounding.Names())
	}
	if p.effective.has(CAP_NET_RAW) {
		t.Errorf("effective = %v, must not contain NET_RAW", p.effective.Names())
	}
	if p.inheritable.has(CAP_CHOWN) {
		t.Errorf("inheritable = %v, must not contain CHOWN", p.inheritable.Names())
	}
}

func TestResolveCapabilitiesNamesTheOffendingSet(t *testing.T) {
	// Five sets parse the same way, so the error has to say which one failed.
	_, err := resolveCapabilities(&oci.LinuxCapabilities{
		Bounding:  []string{"CAP_CHOWN"},
		Effective: []string{"CAP_MADE_UP"},
	})
	if err == nil {
		t.Fatal("expected an error for an unknown capability name, got nil")
	}
	if got := err.Error(); !strings.Contains(got, "effective") {
		t.Errorf("error %q does not name the set it came from", got)
	}
}
