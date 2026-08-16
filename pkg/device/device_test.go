package device

import (
	"os"
	"path/filepath"
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

func TestIsCDIName(t *testing.T) {
	cases := map[string]bool{
		"nvidia.com/gpu=0":   true,
		"nvidia.com/gpu=all": true,
		"/dev/video0":        false,
		"/dev/video0:rw":     false,
		"nvidia.com/gpu":     false, // no device part, not a usable CDI name
	}
	for input, want := range cases {
		if got := IsCDIName(input); got != want {
			t.Errorf("IsCDIName(%q) = %v, want %v", input, got, want)
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

// cdiFixture is the shape nvidia-ctk emits, trimmed to what we read.
const cdiFixture = `{
  "cdiVersion": "0.6.0",
  "kind": "nvidia.com/gpu",
  "containerEdits": {
    "env": ["NVIDIA_VISIBLE_DEVICES=void"],
    "mounts": [
      {"hostPath": "/usr/lib/libnvidia-ml.so.1",
       "containerPath": "/usr/lib/libnvidia-ml.so.1",
       "options": ["ro", "nosuid", "nodev", "bind"]}
    ],
    "hooks": [
      {"hookName": "createContainer",
       "path": "/usr/bin/nvidia-cdi-hook",
       "args": ["nvidia-cdi-hook", "update-ldcache"]}
    ]
  },
  "devices": [
    {
      "name": "0",
      "containerEdits": {
        "env": ["NVIDIA_VISIBLE_DEVICES=0"],
        "deviceNodes": [
          {"path": "/dev/null", "hostPath": "/dev/null", "type": "c", "major": 1, "minor": 3}
        ]
      }
    }
  ]
}`

func loadFixture(t *testing.T, files map[string]string) *Registry {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	reg, err := LoadRegistry([]string{dir})
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	return reg
}

func newSpec() *oci.Spec {
	return &oci.Spec{
		Version: "1.2.0",
		Process: &oci.Process{Args: []string{"/bin/true"}},
		Linux:   &oci.Linux{},
	}
}

func TestCDIInject(t *testing.T) {
	reg := loadFixture(t, map[string]string{"nvidia.json": cdiFixture})
	spec := newSpec()

	if err := reg.Inject(spec, "nvidia.com/gpu=0"); err != nil {
		t.Fatalf("Inject: %v", err)
	}

	// Kind-wide edits and the device's own must both land.
	if len(spec.Mounts) != 1 || spec.Mounts[0].Source != "/usr/lib/libnvidia-ml.so.1" {
		t.Errorf("driver library mount missing: %+v", spec.Mounts)
	}
	if len(spec.Linux.Devices) != 1 || spec.Linux.Devices[0].Path != "/dev/null" {
		t.Errorf("device node missing: %+v", spec.Linux.Devices)
	}
	if len(spec.Process.Env) != 2 {
		t.Errorf("expected both env entries, got %v", spec.Process.Env)
	}
	// createContainer, not createRuntime: it has to run inside the container's
	// namespaces or the ldcache update lands on the host.
	if spec.Hooks == nil || len(spec.Hooks.CreateContainer) != 1 {
		t.Fatalf("createContainer hook missing: %+v", spec.Hooks)
	}
	if len(spec.Hooks.CreateRuntime) != 0 {
		t.Errorf("hook went to the wrong lifecycle list")
	}
}

func TestCDIUnknownDevice(t *testing.T) {
	reg := loadFixture(t, map[string]string{"nvidia.json": cdiFixture})
	err := reg.Inject(newSpec(), "nvidia.com/gpu=7")
	if err == nil {
		t.Fatal("expected an error for an unknown device")
	}
	if !strings.Contains(err.Error(), "available") {
		t.Errorf("error should list the available devices, got: %v", err)
	}
}

func TestCDIYAMLOnlyExplainsItself(t *testing.T) {
	// The common real-world case: the toolkit wrote YAML by default. The error
	// has to name the fix, or the user is left with "device not found".
	reg := loadFixture(t, map[string]string{"nvidia.yaml": "kind: nvidia.com/gpu\n"})
	err := reg.Inject(newSpec(), "nvidia.com/gpu=0")
	if err == nil {
		t.Fatal("expected an error when only YAML is present")
	}
	if !strings.Contains(err.Error(), "--format=json") {
		t.Errorf("error should give the regeneration command, got: %v", err)
	}
}

func TestCDIRejectsUnknownMajorVersion(t *testing.T) {
	_, err := LoadRegistry([]string{t.TempDir()})
	if err != nil {
		t.Fatalf("empty dir should be fine: %v", err)
	}

	dir := t.TempDir()
	spec := strings.Replace(cdiFixture, `"cdiVersion": "0.6.0"`, `"cdiVersion": "1.0.0"`, 1)
	if err := os.WriteFile(filepath.Join(dir, "future.json"), []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRegistry([]string{dir}); err == nil {
		t.Fatal("expected an error for an unknown CDI major version")
	}
}

func TestCDIRejectsUnknownHookName(t *testing.T) {
	// A hook we drop means the device is injected but not finished setting up.
	bad := strings.Replace(cdiFixture, `"hookName": "createContainer"`, `"hookName": "whenever"`, 1)
	reg := loadFixture(t, map[string]string{"nvidia.json": bad})
	if err := reg.Inject(newSpec(), "nvidia.com/gpu=0"); err == nil {
		t.Fatal("expected an error for an unknown hook lifecycle name")
	}
}
