//go:build integration

// End-to-end tests for the rootless path.
//
// Behind a build tag because they create namespaces, mounts and cgroups — slow,
// and they need an unprivileged user namespace. The pkg/ unit tests cover what
// can be checked without a kernel. Shared helpers live in helpers_test.go.
//
//	go test -tags integration ./test/...
package test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestContainerIsolation(t *testing.T) {
	env := setup(t)
	report := env.runCheck(t, "isolation")

	if report.Pid != 1 {
		t.Errorf("container process has pid %d, want 1 — the PID namespace is not in effect", report.Pid)
	}
	if report.VisibleProcs != 1 {
		t.Errorf("container sees %d processes, want 1 — host processes are visible", report.VisibleProcs)
	}
	if report.Hostname != "lightpod" {
		t.Errorf("hostname = %q, want lightpod — the UTS namespace is not in effect", report.Hostname)
	}
	if report.HostRootVisible {
		t.Error("host filesystem paths are reachable — pivot_root did not take effect")
	}
}

func TestContainerSecurityPosture(t *testing.T) {
	env := setup(t)
	report := env.runCheck(t, "posture")

	if report.NoNewPrivs != "1" {
		t.Errorf("NoNewPrivs = %q, want 1 — a setuid binary in the image could regain privileges", report.NoNewPrivs)
	}
	// 2 is SECCOMP_MODE_FILTER. 0 would mean the sandbox is simply absent.
	if report.Seccomp != "2" {
		t.Errorf("Seccomp = %q, want 2 (filter mode) — no seccomp filter is loaded", report.Seccomp)
	}
	if report.MountAllowed {
		t.Error("the container was able to mount a filesystem — this is an escape primitive")
	}
	if report.KcoreReadable {
		t.Error("/proc/kcore is readable — the container can read host physical memory")
	}
	if report.SysrqWritable {
		t.Error("/proc/sysrq-trigger is writable — the container can panic or reboot the host")
	}

	// Catches the capability policy silently no-opping.
	if report.CapEff == "0000003fffffffff" || report.CapEff == "000001ffffffffff" {
		t.Errorf("CapEff = %s — the container holds a full capability set", report.CapEff)
	}
	if report.CapEff != report.CapBnd {
		t.Errorf("CapEff (%s) and CapBnd (%s) disagree", report.CapEff, report.CapBnd)
	}
}

func TestSeccompUnconfinedIsOptIn(t *testing.T) {
	env := setup(t)

	confined := env.runCheck(t, "confined")
	if confined.Seccomp != "2" {
		t.Fatalf("default container is not seccomp-confined: %q", confined.Seccomp)
	}

	unconfined := env.runCheck(t, "unconfined", "--seccomp", "unconfined")
	if unconfined.Seccomp != "0" {
		t.Errorf("--seccomp unconfined did not disable the filter: %q", unconfined.Seccomp)
	}
	// Capabilities are a separate layer, so mount must still fail without the
	// filter. That's the whole point of layering.
	if unconfined.MountAllowed {
		t.Error("mount succeeded without seccomp — capabilities are not being dropped")
	}
}

func TestLifecycleVerbs(t *testing.T) {
	env := setup(t)

	// create takes a bundle, not a rootfs. Sleep so it stays up long enough to
	// inspect and signal.
	bundle := filepath.Join(t.TempDir(), "bundle")
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	spec, _, err := env.run(t, "spec", "--rootfs", env.rootfs, "/check", "sleep", "30")
	if err != nil {
		t.Fatalf("generating spec: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}

	if out, err := env.runDetached(t, "create", "--bundle", bundle, "--cgroup", "none", "life"); err != nil {
		t.Fatalf("create: %v\n%s", err, out)
	}
	defer env.run(t, "delete", "--force", "life")

	stdout, _, err := env.run(t, "state", "life")
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	var st struct {
		Status string `json:"status"`
		Pid    int    `json:"pid"`
	}
	if err := json.Unmarshal([]byte(stdout), &st); err != nil {
		t.Fatalf("parsing state: %v\n%s", err, stdout)
	}
	if st.Status != "created" {
		t.Errorf("status after create = %q, want created", st.Status)
	}
	if st.Pid <= 0 {
		t.Error("state reports no pid")
	}

	if out, err := env.runDetached(t, "start", "life"); err != nil {
		t.Fatalf("start: %v\n%s", err, out)
	}

	stdout, _, _ = env.run(t, "state", "life")
	_ = json.Unmarshal([]byte(stdout), &st)
	if st.Status != "running" {
		t.Errorf("status after start = %q, want running", st.Status)
	}

	if _, stderr, err := env.run(t, "kill", "life", "KILL"); err != nil {
		t.Fatalf("kill: %v\n%s", err, stderr)
	}

	// Nothing observes the exit, so the store reconciles on the next read. Give
	// the kernel a moment to reap.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		stdout, _, _ = env.run(t, "state", "life")
		_ = json.Unmarshal([]byte(stdout), &st)
		if st.Status == "stopped" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if st.Status != "stopped" {
		t.Errorf("status after kill = %q, want stopped", st.Status)
	}

	if _, stderr, err := env.run(t, "delete", "life"); err != nil {
		t.Fatalf("delete: %v\n%s", err, stderr)
	}
	if _, _, err := env.run(t, "state", "life"); err == nil {
		t.Error("state succeeded for a deleted container")
	}
}

func TestHooksRunAtEveryLifecyclePoint(t *testing.T) {
	// Hooks are the whole mechanism GPU support arrives through. If a hook point
	// stops firing, GPU containers start silently without their device.
	env := setup(t)
	dir := t.TempDir()

	log := filepath.Join(dir, "hooks.log")
	hook := filepath.Join(dir, "hook.sh")
	script := "#!/bin/sh\ncat > /dev/null\necho \"$1\" >> \"" + log + "\"\n"
	if err := os.WriteFile(hook, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	specJSON, _, err := env.run(t, "spec", "--rootfs", env.rootfs, "/check")
	if err != nil {
		t.Fatalf("generating spec: %v", err)
	}
	var spec map[string]any
	if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
		t.Fatal(err)
	}
	delete(spec["linux"].(map[string]any), "resources")

	points := []string{"prestart", "createRuntime", "createContainer", "poststart", "poststop"}
	hooks := map[string]any{}
	for _, p := range points {
		hooks[p] = []any{map[string]any{"path": hook, "args": []string{hook, p}}}
	}
	spec["hooks"] = hooks

	bundle := filepath.Join(dir, "bundle")
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(spec)
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), encoded, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, stderr, err := env.run(t, "run", "--bundle", bundle, "--cgroup", "none", "hooked"); err != nil {
		t.Fatalf("running container with hooks: %v\n%s", err, stderr)
	}

	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("no hooks ran: %v", err)
	}
	fired := strings.Fields(string(data))
	for _, p := range points {
		found := false
		for _, f := range fired {
			if f == p {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s hook did not fire (fired: %v)", p, fired)
		}
	}

	// createRuntime before createContainer — tools rely on the
	// runtime-namespace hook having gone first.
	runtimeIdx, containerIdx := -1, -1
	for i, f := range fired {
		if f == "createRuntime" {
			runtimeIdx = i
		}
		if f == "createContainer" {
			containerIdx = i
		}
	}
	if runtimeIdx >= 0 && containerIdx >= 0 && runtimeIdx > containerIdx {
		t.Error("createContainer ran before createRuntime, violating the spec's ordering")
	}
}

func TestRejectsBundleEscapingRootfs(t *testing.T) {
	// Bundles come from registries and orchestrators, so they're untrusted. A
	// root.path climbing out would have us pivot into a host directory.
	env := setup(t)
	bundle := t.TempDir()

	spec := `{"ociVersion":"1.2.0","root":{"path":"../../../etc"},
	          "process":{"args":["/check"],"cwd":"/"},"linux":{}}`
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, _, err := env.run(t, "create", "--bundle", bundle, "escape"); err == nil {
		env.run(t, "delete", "--force", "escape")
		t.Fatal("a bundle whose root.path escapes the bundle directory was accepted")
	}
}

func TestVolumeMount(t *testing.T) {
	env := setup(t)

	data := t.TempDir()
	if err := os.WriteFile(filepath.Join(data, "model.bin"), []byte("weights"), 0o644); err != nil {
		t.Fatal(err)
	}

	// The whole point of -v for this project: getting a model or a dataset into
	// the container without baking it into the image.
	stdout, stderr, err := env.run(t, "run", "--rootfs", env.rootfs, "--cgroup", "none",
		"-v", data+":/data:ro", "vol", "/check", "readfile", "/data/model.bin")
	if err != nil {
		t.Fatalf("running container: %v\nstderr: %s", err, stderr)
	}
	if !strings.Contains(stdout, "weights") {
		t.Fatalf("volume content not visible inside the container: %q", stdout)
	}

	// :ro has to actually be read-only. A bind that silently stays writable is
	// how a container corrupts the host's dataset.
	stdout, _, err = env.run(t, "run", "--rootfs", env.rootfs, "--cgroup", "none",
		"-v", data+":/data:ro", "volro", "/check", "writefile", "/data/new")
	if err != nil {
		t.Fatalf("running container: %v", err)
	}
	if !strings.Contains(stdout, "write-failed") {
		t.Fatalf("read-only volume accepted a write: %q", stdout)
	}
}

func TestRawDevicePassthrough(t *testing.T) {
	env := setup(t)

	// /dev/urandom stands in for a camera or serial port: same code path, but
	// present on every machine.
	stdout, stderr, err := env.run(t, "run", "--rootfs", env.rootfs, "--cgroup", "none",
		"--device", "/dev/urandom", "dev", "/check", "readdev", "/dev/urandom")
	if err != nil {
		t.Fatalf("running container: %v\nstderr: %s", err, stderr)
	}
	if !strings.Contains(stdout, "device-readable") {
		t.Fatalf("passed-through device was not readable: %q", stdout)
	}
}

func TestRealTimeSyscallReachesTheCapabilityGate(t *testing.T) {
	env := setup(t)
	report := env.runCheck(t, "rt")

	// SCHED_OTHER needs no capability, so a failure here means seccomp blocked
	// the syscall.
	if !report.RTSyscallOK {
		t.Error("sched_setscheduler is blocked by seccomp; real-time workloads cannot start")
	}
	// And the real gate must still be shut.
	if report.RTFifoOK {
		t.Error("SCHED_FIFO succeeded without CAP_SYS_NICE; the capability gate is open")
	}
}

func TestRealTimeWorksWithCapability(t *testing.T) {
	env := setup(t)
	report := env.runCheck(t, "rtcap", "--cap-add", "CAP_SYS_NICE")

	if !report.RTFifoOK {
		t.Skipf("SCHED_FIFO still denied with CAP_SYS_NICE; this kernel likely has "+
			"CONFIG_RT_GROUP_SCHED and needs an RT budget (capEff=%s)", report.CapEff)
	}
}

func TestShmSizeIsConfigurable(t *testing.T) {
	env := setup(t)

	// ROS 2's DDS puts shared-memory segments in /dev/shm and runs out quietly
	// at the 64MB default.
	def := env.runCheck(t, "shmdef")
	if def.ShmSizeKB != 65536 {
		t.Errorf("default /dev/shm = %dKB, want 65536", def.ShmSizeKB)
	}

	big := env.runCheck(t, "shmbig", "--shm-size", "256m")
	if big.ShmSizeKB != 262144 {
		t.Errorf("--shm-size 256m gave %dKB, want 262144", big.ShmSizeKB)
	}
}

func TestTTYFlagFailsLoudly(t *testing.T) {
	env := setup(t)

	// A flag that silently does nothing is worse than a missing one.
	_, stderr, err := env.run(t, "run", "--rootfs", env.rootfs, "--cgroup", "none",
		"--tty", "ttytest", "/check")
	if err == nil {
		t.Fatal("--tty was accepted even though no pty is allocated")
	}
	if !strings.Contains(stderr, "not implemented") {
		t.Errorf("error should say the flag is unimplemented, got: %s", stderr)
	}
}

func TestPruneFreesAStaleID(t *testing.T) {
	env := setup(t)

	if _, err := env.runDetached(t, "create", "--rootfs", env.rootfs, "--cgroup", "none",
		"stale", "/check", "sleep", "1"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, stderr, err := env.run(t, "start", "stale"); err != nil {
		t.Fatalf("start: %v\n%s", err, stderr)
	}

	// Wait for it to exit on its own, the way a crashed container would.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		stdout, _, err := env.run(t, "state", "stale")
		if err == nil && strings.Contains(stdout, `"stopped"`) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// The id is taken until the record goes away.
	if _, err := env.runDetached(t, "create", "--rootfs", env.rootfs, "--cgroup", "none",
		"stale", "/check", "sleep", "1"); err == nil {
		t.Fatal("a stopped container's id was reusable without prune")
	}

	stdout, stderr, err := env.run(t, "prune")
	if err != nil {
		t.Fatalf("prune: %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "stale") {
		t.Fatalf("prune did not report removing the container: %q", stdout)
	}

	if _, err := env.runDetached(t, "create", "--rootfs", env.rootfs, "--cgroup", "none",
		"stale", "/check", "sleep", "1"); err != nil {
		t.Fatalf("id still unusable after prune: %v", err)
	}
	env.run(t, "delete", "--force", "stale")
}

func TestEnvAndWorkdir(t *testing.T) {
	env := setup(t)

	stdout, stderr, err := env.run(t, "run", "--rootfs", env.rootfs, "--cgroup", "none",
		"-e", "ROS_DOMAIN_ID=42", "--workdir", "/", "envtest", "/check", "printenv", "ROS_DOMAIN_ID")
	if err != nil {
		t.Fatalf("running container: %v\nstderr: %s", err, stderr)
	}
	if !strings.Contains(stdout, "42") {
		t.Fatalf("--env did not reach the container: %q", stdout)
	}
}
