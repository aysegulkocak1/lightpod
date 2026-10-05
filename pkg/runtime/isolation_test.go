package runtime

import (
	"strings"
	"syscall"
	"testing"

	"github.com/aysegulkocak1/lightpod/pkg/oci"
)

// cgroupsPath is spec input like a mount target is, and filepath.Join resolves
// ".." lexically, so unchecked these land outside the delegated subtree.
func TestContainerCgroupPathRejectsEscape(t *testing.T) {
	root := "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service"

	escapes := []string{
		"../../user.slice",
		"/../../../system.slice/sshd.service",
		"lightpod/../../../..",
		"a/b/../../../../../etc",
	}
	for _, custom := range escapes {
		spec := &oci.Spec{Linux: &oci.Linux{CgroupsPath: custom}}
		path, err := containerCgroupPath(root, "demo", spec)
		if err == nil {
			t.Errorf("cgroupsPath %q was accepted and resolved to %q, want an error", custom, path)
		}
	}
}

// Limits written at the root apply to everything on the host.
func TestContainerCgroupPathRejectsRootItself(t *testing.T) {
	root := "/sys/fs/cgroup"
	for _, custom := range []string{"/", ".", "lightpod/.."} {
		spec := &oci.Spec{Linux: &oci.Linux{CgroupsPath: custom}}
		if _, err := containerCgroupPath(root, "demo", spec); err == nil {
			t.Errorf("cgroupsPath %q resolved to the cgroup root and was accepted", custom)
		}
	}
}

// A sibling sharing a name prefix is not inside the root.
func TestContainerCgroupPathRejectsPrefixSibling(t *testing.T) {
	spec := &oci.Spec{Linux: &oci.Linux{CgroupsPath: "../cgroup-evil/demo"}}
	if _, err := containerCgroupPath("/sys/fs/cgroup", "demo", spec); err == nil {
		t.Error("a sibling path sharing the root's name prefix was accepted")
	}
}

func TestContainerCgroupPathDefaultsUnderLightpod(t *testing.T) {
	path, err := containerCgroupPath("/sys/fs/cgroup", "demo", &oci.Spec{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "/sys/fs/cgroup/lightpod/demo"; path != want {
		t.Errorf("default path = %q, want %q", path, want)
	}
}

func TestContainerCgroupPathAcceptsCustomAndFlattensSystemd(t *testing.T) {
	cases := []struct {
		custom string
		want   string
	}{
		{"mygroup/web", "/sys/fs/cgroup/mygroup/web"},
		{"/absolute/is/root-relative", "/sys/fs/cgroup/absolute/is/root-relative"},
		// runc takes "slice:prefix:name" for systemd. We're daemonless, so it
		// becomes one directory name rather than a systemd unit.
		{"user.slice:lightpod:demo", "/sys/fs/cgroup/user.slice-lightpod-demo"},
	}
	for _, tc := range cases {
		spec := &oci.Spec{Linux: &oci.Linux{CgroupsPath: tc.custom}}
		path, err := containerCgroupPath("/sys/fs/cgroup", "demo", spec)
		if err != nil {
			t.Errorf("cgroupsPath %q: unexpected error: %v", tc.custom, err)
			continue
		}
		if path != tc.want {
			t.Errorf("cgroupsPath %q = %q, want %q", tc.custom, path, tc.want)
		}
	}
}

// prepareRootfs needs real namespaces, so only the resolution half is testable
// here: the spec value maps to flags for the rootfs mount, never for "/".
func TestRootfsPropagationResolvesKnownModes(t *testing.T) {
	cases := map[string]uintptr{
		"private":     syscall.MS_PRIVATE,
		"rprivate":    syscall.MS_PRIVATE | syscall.MS_REC,
		"slave":       syscall.MS_SLAVE,
		"rslave":      syscall.MS_SLAVE | syscall.MS_REC,
		"unbindable":  syscall.MS_UNBINDABLE,
		"runbindable": syscall.MS_UNBINDABLE | syscall.MS_REC,
	}
	for mode, want := range cases {
		spec := &oci.Spec{Linux: &oci.Linux{RootfsPropagation: mode}}
		got, err := rootfsPropagation(spec)
		if err != nil {
			t.Errorf("rootfsPropagation(%q): unexpected error: %v", mode, err)
			continue
		}
		if got != want {
			t.Errorf("rootfsPropagation(%q) = %#x, want %#x", mode, got, want)
		}
	}
}

// An ignored mode leaves the container with propagation it never asked for.
func TestRootfsPropagationRejectsUnknownMode(t *testing.T) {
	spec := &oci.Spec{Linux: &oci.Linux{RootfsPropagation: "sideways"}}
	_, err := rootfsPropagation(spec)
	if err == nil {
		t.Fatal("unknown rootfsPropagation was accepted, want an error")
	}
	if !strings.Contains(err.Error(), "sideways") {
		t.Errorf("error %q does not name the offending mode", err)
	}
}

// pivot_root returns EINVAL when new_root is on a shared mount, and we always
// pivot, so these can never be honoured.
func TestRootfsPropagationRejectsSharedModes(t *testing.T) {
	for _, mode := range []string{"shared", "rshared"} {
		spec := &oci.Spec{Linux: &oci.Linux{RootfsPropagation: mode}}
		_, err := rootfsPropagation(spec)
		if err == nil {
			t.Errorf("rootfsPropagation(%q) was accepted; pivot_root would fail with EINVAL", mode)
			continue
		}
		if !strings.Contains(err.Error(), "pivot_root") {
			t.Errorf("error for %q does not explain the pivot_root constraint: %v", mode, err)
		}
	}
}

// No propagation asked for means no second mount call, not a zero-flag one.
func TestRootfsPropagationAbsentIsZero(t *testing.T) {
	for _, spec := range []*oci.Spec{
		{},
		{Linux: &oci.Linux{}},
		{Linux: &oci.Linux{RootfsPropagation: ""}},
	} {
		got, err := rootfsPropagation(spec)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if got != 0 {
			t.Errorf("rootfsPropagation = %#x, want 0", got)
		}
	}
}

// A sysctl key becomes a path, so it is spec-controlled path input.
func TestCheckSysctlKeyRejectsNonSysctlNames(t *testing.T) {
	bad := []string{
		"",
		"../../etc/passwd",
		"net/ipv4/ip_forward",
		"net..ipv4.ip_forward",
		".net.ipv4.ip_forward",
		"net.ipv4.ip_forward.",
		"net.ipv4..",
		"net.\x00.evil",
	}
	for _, key := range bad {
		if err := checkSysctlKey(key); err == nil {
			t.Errorf("sysctl key %q was accepted, want an error", key)
		}
	}
}

func TestCheckSysctlKeyAcceptsRealNames(t *testing.T) {
	good := []string{
		"net.ipv4.ip_forward",
		"kernel.shmmax",
		"net.ipv4.conf.all.rp_filter",
		"fs.mqueue.queues_max",
		"kernel.domainname",
	}
	for _, key := range good {
		if err := checkSysctlKey(key); err != nil {
			t.Errorf("sysctl key %q was rejected: %v", key, err)
		}
	}
}

// A bare strings.HasPrefix reads /rootfs-evil as inside /rootfs.
func TestIsWithinRejectsPrefixSibling(t *testing.T) {
	cases := []struct {
		parent, path string
		want         bool
	}{
		{"/rootfs", "/rootfs", true},
		{"/rootfs", "/rootfs/etc/passwd", true},
		{"/rootfs", "/rootfs-evil", false},
		{"/rootfs", "/rootfs-evil/etc/passwd", false},
		{"/rootfs", "/", false},
		{"/sys/fs/cgroup", "/sys/fs/cgroup-x", false},
	}
	for _, tc := range cases {
		if got := oci.IsWithin(tc.parent, tc.path); got != tc.want {
			t.Errorf("IsWithin(%q, %q) = %v, want %v", tc.parent, tc.path, got, tc.want)
		}
	}
}
