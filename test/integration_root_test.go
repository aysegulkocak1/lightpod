//go:build integration_root

// End-to-end tests for the rootfull path — the things rootless structurally
// cannot do: real device nodes via mknod, real-time priority, and cgroup
// controllers at the hierarchy root.
//
//	sudo -E env "PATH=$PATH" go test -tags integration_root ./test/...
package test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root; run with sudo -E env \"PATH=$PATH\" go test -tags integration_root ./test/...")
	}
}

func TestRootfullSecurityPostureMatchesRootless(t *testing.T) {
	requireRoot(t)
	env := setup(t)
	report := env.runCheck(t, "rootfull-posture")

	// Running as host root must not buy the container anything. If any of these
	// differ from the rootless run, privilege is leaking through.
	if report.Pid != 1 || report.VisibleProcs != 1 {
		t.Errorf("pid=%d visibleProcs=%d, want 1 and 1", report.Pid, report.VisibleProcs)
	}
	if report.NoNewPrivs != "1" {
		t.Errorf("NoNewPrivs = %q, want 1", report.NoNewPrivs)
	}
	if report.Seccomp != "2" {
		t.Errorf("Seccomp = %q, want 2 (filter mode)", report.Seccomp)
	}
	if report.MountAllowed {
		t.Error("rootfull container could mount — capabilities are not being dropped")
	}
	if report.KcoreReadable || report.SysrqWritable {
		t.Error("masked and read-only paths are not in effect under rootfull")
	}
	if report.HostRootVisible {
		t.Error("host filesystem is reachable — pivot_root did not take effect")
	}
}

func TestRootfullCreatesRealDeviceNodes(t *testing.T) {
	requireRoot(t)
	env := setup(t)

	// Rootfull takes the mknod path rather than bind mounting the host node.
	// createDevices fails hard on error, so a working read proves mknod ran.
	stdout, stderr, err := env.run(t, "run", "--rootfs", env.rootfs,
		"--cgroup", "none", "rootdev", "/check", "readdev", "/dev/urandom")
	if err != nil {
		t.Fatalf("running container: %v\nstderr: %s", err, stderr)
	}
	if !strings.Contains(stdout, "device-readable") {
		t.Fatalf("device node not usable: %q", stdout)
	}
}

func TestRootfullPassesThroughRawDevice(t *testing.T) {
	requireRoot(t)
	env := setup(t)

	stdout, stderr, err := env.run(t, "run", "--rootfs", env.rootfs,
		"--cgroup", "none", "--device", "/dev/urandom:/dev/sensor",
		"rootdev2", "/check", "readdev", "/dev/sensor")
	if err != nil {
		t.Fatalf("running container: %v\nstderr: %s", err, stderr)
	}
	if !strings.Contains(stdout, "device-readable") {
		t.Fatalf("remapped device not usable: %q", stdout)
	}
}

func TestRootfullRealTimeSchedulingWorks(t *testing.T) {
	requireRoot(t)
	env := setup(t)

	// This is the case rootless cannot reach: real-time priority is a global
	// resource, so the kernel wants CAP_SYS_NICE in the initial user namespace.
	// Robotics control loops therefore need rootfull, the same way GPUs do.
	granted := env.runCheck(t, "rootfull-rt", "--cap-add", "CAP_SYS_NICE")
	if !granted.RTSyscallOK {
		t.Fatal("sched_setscheduler blocked by seccomp under rootfull")
	}
	if !granted.RTFifoOK {
		t.Skip("SCHED_FIFO denied even with CAP_SYS_NICE and root; this kernel likely " +
			"has CONFIG_RT_GROUP_SCHED and needs an RT budget on the cgroup")
	}

	// And without the capability it must still be refused.
	denied := env.runCheck(t, "rootfull-rt-denied")
	if denied.RTFifoOK {
		t.Error("SCHED_FIFO succeeded without CAP_SYS_NICE — the capability gate is open")
	}
}

func TestRootfullMountsRealSysfs(t *testing.T) {
	requireRoot(t)
	env := setup(t)

	// Rootless binds the host's /sys and drags every submount along. Rootfull
	// mounts a fresh sysfs, so the table is much shorter.
	report := env.runCheck(t, "rootfull-mounts")
	if report.MountCount > 30 {
		t.Errorf("rootfull container has %d mounts; expected a fresh sysfs, not the host's tree",
			report.MountCount)
	}
}

func TestRootfullCgroupLimits(t *testing.T) {
	requireRoot(t)
	env := setup(t)

	// Only meaningful where cgroup v2 actually owns the controllers. On a hybrid
	// system this is a property of the machine, not of lightpod.
	if !cgroupV2HasControllers(t) {
		t.Skip("cgroup v2 has no controllers on this machine (hybrid mode); " +
			"boot with systemd.unified_cgroup_hierarchy=1 to exercise limits")
	}

	stdout, stderr, err := env.run(t, "run", "--rootfs", env.rootfs,
		"--memory", "64m", "oom", "/check", "alloc", "256")
	if err == nil && strings.Contains(stdout, "reached 256MB") {
		t.Fatalf("container allocated 256MB under a 64MB limit\nstderr: %s", stderr)
	}
	if !strings.Contains(stdout, "allocated") {
		t.Fatalf("container did not start allocating at all: %q\nstderr: %s", stdout, stderr)
	}
}

// cgroupV2HasControllers reports whether the unified hierarchy actually owns
// any controllers, which is false on a hybrid system.
func cgroupV2HasControllers(t *testing.T) bool {
	t.Helper()
	for _, path := range []string{
		"/sys/fs/cgroup/cgroup.controllers",
		"/sys/fs/cgroup/unified/cgroup.controllers",
	} {
		if data, err := os.ReadFile(path); err == nil {
			return len(strings.Fields(string(data))) > 0
		}
	}
	return false
}

// Sysctls must land in the container's namespaces and not the host's.
//
// Rootfull only: without a user namespace in the way, a write through the
// host's procfs would actually succeed. Both halves are asserted, because
// checking only the host would also pass if the sysctl were silently dropped.
func TestRootfullSysctlAppliesInContainerNotHost(t *testing.T) {
	requireRoot(t)

	const hostPath = "/proc/sys/net/ipv4/ip_forward"
	before, err := os.ReadFile(hostPath)
	if err != nil {
		t.Skipf("cannot read %s: %v", hostPath, err)
	}
	original := strings.TrimSpace(string(before))

	// The opposite of the host's value, so a leaking write is visible.
	want := "1"
	if original == "1" {
		want = "0"
	}

	// On regression this test is what changed the host, so put it back.
	t.Cleanup(func() {
		if data, err := os.ReadFile(hostPath); err == nil {
			if strings.TrimSpace(string(data)) != original {
				_ = os.WriteFile(hostPath, []byte(original+"\n"), 0o644)
			}
		}
	})

	env := setup(t)

	specJSON, _, err := env.run(t, "spec", "--rootfs", env.rootfs, "/check")
	if err != nil {
		t.Fatalf("generating spec: %v", err)
	}
	var spec map[string]any
	if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
		t.Fatalf("parsing spec: %v", err)
	}
	linux, ok := spec["linux"].(map[string]any)
	if !ok {
		t.Fatal("generated spec has no linux section")
	}
	linux["sysctl"] = map[string]string{"net.ipv4.ip_forward": want}

	// Read it back from inside, so "applied" is distinguishable from "dropped".
	process, ok := spec["process"].(map[string]any)
	if !ok {
		t.Fatal("generated spec has no process section")
	}
	process["args"] = []string{"/check", "readfile", hostPath}

	bundle := filepath.Join(t.TempDir(), "bundle")
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(spec)
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), encoded, 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := env.run(t, "run", "--bundle", bundle, "--cgroup", "none", "sysctl-host")
	if err != nil {
		t.Fatalf("running container with a sysctl: %v\nstderr: %s", err, stderr)
	}

	// Half one: the container got what it asked for.
	if inside := strings.TrimSpace(stdout); inside != want {
		t.Errorf("container read %q from its own %s, want %q; the sysctl did not apply",
			inside, hostPath, want)
	}

	// Half two: the host did not.
	after, err := os.ReadFile(hostPath)
	if err != nil {
		t.Fatalf("re-reading %s: %v", hostPath, err)
	}
	if got := strings.TrimSpace(string(after)); got != original {
		t.Fatalf("container's sysctl changed the HOST: %s went %s -> %s "+
			"(it was only ever asking for %s inside its own namespace)",
			hostPath, original, got, want)
	}
}
