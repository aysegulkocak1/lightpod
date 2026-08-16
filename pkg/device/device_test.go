package device

import (
	"os"
	"strings"
	"testing"

	"github.com/aysegulkocak1/lightpod/pkg/oci"
)

func TestMkdevRoundTrip(t *testing.T) {
	// The encoding splits both numbers across two bit ranges. A naive
	// (major<<8)|minor passes the small cases and quietly corrupts the large
	// ones, which is what /dev/nvidia-caps and dynamic minors actually use.
	cases := []struct{ major, minor int64 }{
		{1, 3},    // /dev/null
		{195, 0},  // /dev/nvidia0
		{10, 200}, // /dev/net/tun
		{4096, 1}, // major above the low 12 bits
		{1, 300},  // minor above the low 8 bits
		{5000, 9000},
	}
	for _, c := range cases {
		dev := Mkdev(c.major, c.minor)
		if got := Major(dev); got != c.major {
			t.Errorf("Major(Mkdev(%d,%d)) = %d", c.major, c.minor, got)
		}
		if got := Minor(dev); got != c.minor {
			t.Errorf("Minor(Mkdev(%d,%d)) = %d", c.major, c.minor, got)
		}
	}
}

func TestParseRawDevice(t *testing.T) {
	dev, err := ParseRawDevice("/dev/null")
	if err != nil {
		t.Fatalf("ParseRawDevice: %v", err)
	}
	if dev.Path != "/dev/null" || dev.Type != "c" || dev.Major != 1 || dev.Minor != 3 {
		t.Fatalf("unexpected device: %+v", dev)
	}
}

func TestParseRawDeviceRemapsPath(t *testing.T) {
	dev, err := ParseRawDevice("/dev/null:/dev/zero")
	if err != nil {
		t.Fatalf("ParseRawDevice: %v", err)
	}
	// The container path is what was asked for; the numbers still come from the
	// host node named on the left.
	if dev.Path != "/dev/zero" || dev.Major != 1 || dev.Minor != 3 {
		t.Fatalf("unexpected device: %+v", dev)
	}
}

func TestParseRawDeviceRejects(t *testing.T) {
	for _, input := range []string{
		"dev/null",             // not absolute
		"/dev/null:/dev/x:bad", // invalid permissions
		"/dev/null:a:b:c",      // too many fields
		"/dev/definitely-absent",
		"/etc", // not a device node
	} {
		if _, err := ParseRawDevice(input); err == nil {
			t.Errorf("ParseRawDevice(%q) should have failed", input)
		}
	}
}

func newSpec() *oci.Spec {
	return &oci.Spec{
		Version: "1.2.0",
		Process: &oci.Process{Args: []string{"/bin/true"}, Env: []string{"PATH=/bin"}},
		Linux:   &oci.Linux{},
	}
}

func TestSetNVIDIAEnv(t *testing.T) {
	spec := newSpec()
	if err := SetNVIDIAEnv(spec, "0,1"); err != nil {
		t.Fatalf("SetNVIDIAEnv: %v", err)
	}
	env := strings.Join(spec.Process.Env, " ")
	if !strings.Contains(env, "NVIDIA_VISIBLE_DEVICES=0,1") {
		t.Errorf("NVIDIA_VISIBLE_DEVICES not set: %v", spec.Process.Env)
	}
	if !strings.Contains(env, "NVIDIA_DRIVER_CAPABILITIES=all") {
		t.Errorf("NVIDIA_DRIVER_CAPABILITIES not defaulted: %v", spec.Process.Env)
	}
}

func TestSetNVIDIAEnvKeepsAnExplicitCapabilityList(t *testing.T) {
	spec := newSpec()
	spec.Process.Env = append(spec.Process.Env, "NVIDIA_DRIVER_CAPABILITIES=compute")
	if err := SetNVIDIAEnv(spec, "all"); err != nil {
		t.Fatal(err)
	}
	for _, kv := range spec.Process.Env {
		if kv == "NVIDIA_DRIVER_CAPABILITIES=all" {
			t.Error("overrode an explicitly set NVIDIA_DRIVER_CAPABILITIES")
		}
	}
}

func TestInjectNVIDIAHook(t *testing.T) {
	// Stand in for the toolkit's hook so this runs without it installed.
	fake := t.TempDir() + "/nvidia-container-runtime-hook"
	if err := os.WriteFile(fake, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LIGHTPOD_NVIDIA_HOOK", fake)

	spec := newSpec()
	if err := InjectNVIDIAHook(spec); err != nil {
		t.Fatalf("InjectNVIDIAHook: %v", err)
	}
	// Prestart, not createRuntime: that is the contract the hook is written for.
	if spec.Hooks == nil || len(spec.Hooks.Prestart) != 1 {
		t.Fatalf("prestart hook missing: %+v", spec.Hooks)
	}
	if spec.Hooks.Prestart[0].Path != fake {
		t.Errorf("hook path = %q, want %q", spec.Hooks.Prestart[0].Path, fake)
	}
	if len(spec.Hooks.CreateRuntime) != 0 {
		t.Error("hook went to the wrong lifecycle list")
	}
}

func TestInjectNVIDIAHookExplainsAMissingToolkit(t *testing.T) {
	t.Setenv("LIGHTPOD_NVIDIA_HOOK", t.TempDir()+"/absent")
	if err := InjectNVIDIAHook(newSpec()); err == nil {
		t.Fatal("expected an error when the hook is missing")
	}
}
