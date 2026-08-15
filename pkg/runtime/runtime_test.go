package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/aysegulkocak1/lightpod/pkg/oci"
)

// hybridMountinfo is the mount table of a machine running cgroup v1 and v2 side
// by side — still the default on plenty of shipped distributions, and the exact
// layout that a hardcoded /sys/fs/cgroup path gets wrong.
const hybridMountinfo = `23 28 0:22 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
29 23 0:26 / /sys/fs/cgroup ro,nosuid,nodev,noexec shared:9 - tmpfs tmpfs ro,mode=755
30 29 0:27 / /sys/fs/cgroup/unified rw,nosuid,nodev,noexec,relatime shared:10 - cgroup2 cgroup2 rw,nsdelegate
31 29 0:28 / /sys/fs/cgroup/systemd rw,nosuid,nodev,noexec,relatime shared:11 - cgroup cgroup rw,name=systemd
35 29 0:32 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime shared:15 - cgroup cgroup rw,memory`

const unifiedMountinfo = `23 28 0:22 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
29 23 0:26 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:9 - cgroup2 cgroup2 rw,nsdelegate,memory_recursive_prot`

func TestParseCgroup2MountpointHybrid(t *testing.T) {
	got, err := parseCgroup2Mountpoint(strings.NewReader(hybridMountinfo))
	if err != nil {
		t.Fatalf("parseCgroup2Mountpoint: %v", err)
	}
	if got != "/sys/fs/cgroup/unified" {
		t.Errorf("got %q, want /sys/fs/cgroup/unified", got)
	}
}

func TestParseCgroup2MountpointUnified(t *testing.T) {
	got, err := parseCgroup2Mountpoint(strings.NewReader(unifiedMountinfo))
	if err != nil {
		t.Fatalf("parseCgroup2Mountpoint: %v", err)
	}
	if got != "/sys/fs/cgroup" {
		t.Errorf("got %q, want /sys/fs/cgroup", got)
	}
}

func TestParseCgroup2MountpointAbsent(t *testing.T) {
	// A v1-only machine must produce a clear refusal, not a path that happens
	// to exist and silently applies no limits.
	v1Only := `31 29 0:28 / /sys/fs/cgroup/systemd rw,relatime shared:11 - cgroup cgroup rw,name=systemd`
	if _, err := parseCgroup2Mountpoint(strings.NewReader(v1Only)); err == nil {
		t.Fatal("expected an error when no cgroup2 filesystem is mounted, got nil")
	}
}

func TestParseMountOptions(t *testing.T) {
	flags, propagation, data := parseMountOptions(
		[]string{"nosuid", "noexec", "nodev", "ro", "rslave", "mode=755", "size=65536k"})

	for name, want := range map[string]uintptr{
		"nosuid": syscall.MS_NOSUID,
		"noexec": syscall.MS_NOEXEC,
		"nodev":  syscall.MS_NODEV,
		"ro":     syscall.MS_RDONLY,
	} {
		if flags&want == 0 {
			t.Errorf("%s flag was not set", name)
		}
	}
	if propagation != syscall.MS_SLAVE|syscall.MS_REC {
		t.Errorf("propagation = %#x, want MS_SLAVE|MS_REC", propagation)
	}
	// Unrecognised options are filesystem data, not flags to be dropped.
	if !strings.Contains(data, "mode=755") || !strings.Contains(data, "size=65536k") {
		t.Errorf("data = %q, expected the tmpfs options to be preserved", data)
	}
}

func TestParseMountOptionsClearingOptions(t *testing.T) {
	// "rw" after "ro" must clear the flag. Treating it as a no-op would produce
	// a read-only mount where the spec asked for a writable one.
	flags, _, _ := parseMountOptions([]string{"ro", "rw"})
	if flags&syscall.MS_RDONLY != 0 {
		t.Error("rw did not clear MS_RDONLY")
	}
}

func TestSecureJoinStaysInsideRootfs(t *testing.T) {
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := secureJoin(rootfs, "/etc/passwd")
	if err != nil {
		t.Fatalf("secureJoin: %v", err)
	}
	if got != filepath.Join(rootfs, "etc", "passwd") {
		t.Errorf("got %q", got)
	}
}

func TestSecureJoinClampsParentTraversal(t *testing.T) {
	// ".." at the container root resolves to the root itself, exactly as it
	// would for a process already inside it. Letting it climb would let a
	// crafted mount destination target a host path.
	rootfs := t.TempDir()
	got, err := secureJoin(rootfs, "/../../../etc/shadow")
	if err != nil {
		t.Fatalf("secureJoin: %v", err)
	}
	if !strings.HasPrefix(got, rootfs) {
		t.Fatalf("secureJoin escaped the rootfs: %q", got)
	}
}

func TestSecureJoinFollowsSymlinksInsideRootfs(t *testing.T) {
	// The attack this defends against: an image ships /etc as a symlink to an
	// absolute host path, so that mounting "/etc/resolv.conf" writes to the
	// host's. The link must be resolved relative to the container root.
	rootfs := t.TempDir()
	if err := os.Symlink("/../../etc", filepath.Join(rootfs, "evil")); err != nil {
		t.Fatal(err)
	}

	got, err := secureJoin(rootfs, "/evil/shadow")
	if err != nil {
		t.Fatalf("secureJoin: %v", err)
	}
	if !strings.HasPrefix(got, rootfs) {
		t.Fatalf("symlink escaped the rootfs: %q", got)
	}
}

func TestSubIDRange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subuid")
	content := "someone:100000:65536\n1000:200000:65536\n# a comment\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	start, count, err := subIDRange(path, 1000)
	if err != nil {
		t.Fatalf("subIDRange: %v", err)
	}
	if start != 200000 || count != 65536 {
		t.Errorf("got start=%d count=%d, want 200000/65536", start, count)
	}
}

func TestSubIDRangeMissingEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subuid")
	if err := os.WriteFile(path, []byte("other:100000:65536\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := subIDRange(path, 4242); err == nil {
		t.Fatal("expected an error for a uid with no range, got nil")
	}
}

func TestIsSelfMapping(t *testing.T) {
	// Only the trivial single-id mapping may be written without the setuid
	// helper. Misjudging this either breaks multi-range mapping or attempts a
	// privileged write that fails.
	self := []oci.LinuxIDMapping{{ContainerID: 0, HostID: 1000, Size: 1}}
	if !isSelfMapping(self, 1000) {
		t.Error("a single-id mapping onto our own uid should be self-mappable")
	}

	wide := []oci.LinuxIDMapping{
		{ContainerID: 0, HostID: 1000, Size: 1},
		{ContainerID: 1, HostID: 100000, Size: 65536},
	}
	if isSelfMapping(wide, 1000) {
		t.Error("a multi-range mapping needs newuidmap and is not self-mappable")
	}
}

func TestCloneFlagsFromSpec(t *testing.T) {
	spec := &oci.Spec{Linux: &oci.Linux{Namespaces: []oci.LinuxNamespace{
		{Type: oci.PIDNamespace},
		{Type: oci.MountNamespace},
		{Type: oci.UserNamespace},
		// A namespace with a path is joined with setns, so it must NOT
		// contribute a clone flag — doing so would create a fresh namespace and
		// silently break pod sharing.
		{Type: oci.NetworkNamespace, Path: "/proc/1/ns/net"},
	}}}

	flags, err := cloneFlags(spec)
	if err != nil {
		t.Fatalf("cloneFlags: %v", err)
	}
	if flags&syscall.CLONE_NEWPID == 0 || flags&syscall.CLONE_NEWNS == 0 || flags&syscall.CLONE_NEWUSER == 0 {
		t.Errorf("flags = %#x, missing a requested namespace", flags)
	}
	if flags&syscall.CLONE_NEWNET != 0 {
		t.Error("a path-referenced namespace must not be cloned")
	}
}

func TestCloneFlagsRejectsUnknownNamespace(t *testing.T) {
	spec := &oci.Spec{Linux: &oci.Linux{Namespaces: []oci.LinuxNamespace{{Type: "quantum"}}}}
	if _, err := cloneFlags(spec); err == nil {
		t.Fatal("expected an error for an unknown namespace type, got nil")
	}
}

func TestSharesToWeight(t *testing.T) {
	// The spec is written in cgroup v1 shares; cgroup v2 wants weights. The
	// default must map to the default, or every container silently gets a
	// different CPU share than requested.
	if got := sharesToWeight(1024); got < 30 || got > 50 {
		t.Errorf("sharesToWeight(1024) = %d, want roughly 39 (the v2 default band)", got)
	}
	if got := sharesToWeight(0); got != 100 {
		t.Errorf("sharesToWeight(0) = %d, want 100", got)
	}
	if got := sharesToWeight(262144); got > 10000 {
		t.Errorf("sharesToWeight(262144) = %d, exceeds the cgroup v2 maximum", got)
	}
}

func TestFormatLimit(t *testing.T) {
	if got := formatLimit(-1); got != "max" {
		t.Errorf("formatLimit(-1) = %q, want max", got)
	}
	if got := formatLimit(0); got != "max" {
		t.Errorf("formatLimit(0) = %q, want max", got)
	}
	if got := formatLimit(67108864); got != "67108864" {
		t.Errorf("formatLimit(67108864) = %q", got)
	}
}

func TestPrivilegeModeStateRootDiffers(t *testing.T) {
	// Rootfull and rootless must not share a state directory: an unprivileged
	// user writing into the root store could forge container records.
	rootfull, err := ModeRootfull.StateRoot()
	if err != nil {
		t.Fatal(err)
	}
	if rootfull != "/run/lightpod" {
		t.Errorf("rootfull state root = %q", rootfull)
	}

	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	rootless, err := ModeRootless.StateRoot()
	if err != nil {
		t.Fatal(err)
	}
	if rootless == rootfull {
		t.Error("rootless and rootfull share a state root")
	}
}

func TestParsePrivilegeModeRejectsRootfullWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; this check only applies to unprivileged users")
	}
	if _, err := ParsePrivilegeMode("rootfull"); err == nil {
		t.Fatal("expected an error asking for rootfull as an unprivileged user, got nil")
	}
}
