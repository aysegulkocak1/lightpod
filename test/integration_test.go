//go:build integration

// End-to-end tests that start real containers.
//
// Behind a build tag because they create namespaces, mounts and cgroups — slow,
// and they need an unprivileged user namespace. The pkg/ unit tests cover what
// can be checked without a kernel.
//
//	go test -tags integration ./test/...
package test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// What isolationcheck reports from inside. The only source worth trusting —
// asserting on the runtime's own logs is just the runtime agreeing with itself.
type isolationReport struct {
	Pid             int    `json:"pid"`
	Hostname        string `json:"hostname"`
	UID             int    `json:"uid"`
	VisibleProcs    int    `json:"visibleProcs"`
	NoNewPrivs      string `json:"noNewPrivs"`
	Seccomp         string `json:"seccomp"`
	CapEff          string `json:"capEff"`
	CapBnd          string `json:"capBnd"`
	KcoreReadable   bool   `json:"kcoreReadable"`
	SysrqWritable   bool   `json:"sysrqWritable"`
	MountAllowed    bool   `json:"mountAllowed"`
	HostRootVisible bool   `json:"hostRootVisible"`
}

// testEnv is a built lightpod binary plus a single-binary rootfs.
type testEnv struct {
	lightpod string
	rootfs   string
	stateDir string
}

// setup builds what the tests need. The rootfs is a single static binary rather
// than a distro image, so there's nothing to download — same constraint the
// target devices have.
func setup(t *testing.T) *testEnv {
	t.Helper()

	dir := t.TempDir()
	env := &testEnv{
		lightpod: filepath.Join(dir, "lightpod"),
		rootfs:   filepath.Join(dir, "rootfs"),
		stateDir: filepath.Join(dir, "state"),
	}

	if err := os.MkdirAll(env.rootfs, 0o755); err != nil {
		t.Fatal(err)
	}

	build := exec.Command("go", "build", "-o", env.lightpod, "../cmd/lightpod")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building lightpod: %v\n%s", err, out)
	}

	check := exec.Command("go", "build", "-o", filepath.Join(env.rootfs, "check"), "./isolationcheck")
	check.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := check.CombinedOutput(); err != nil {
		t.Fatalf("building isolationcheck: %v\n%s", err, out)
	}

	return env
}

func (e *testEnv) run(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	full := append([]string{"--root", e.stateDir}, args...)
	cmd := exec.Command(e.lightpod, full...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// runDetached uses real files for stdio instead of pipes.
//
// A created container inherits the caller's stdout/stderr and holds them — the
// runc contract podman and nvidia-container-runtime rely on. With os/exec's
// pipe capture the parent waits for EOF, so it waits for the container, and
// `create` looks like it hangs. Real supervisors hand over files or FIFOs they
// manage themselves; this models that.
func (e *testEnv) runDetached(t *testing.T, args ...string) (string, error) {
	t.Helper()

	out, err := os.CreateTemp(t.TempDir(), "stdio")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	full := append([]string{"--root", e.stateDir}, args...)
	cmd := exec.Command(e.lightpod, full...)
	cmd.Stdout = out
	cmd.Stderr = out
	runErr := cmd.Run()

	data, _ := os.ReadFile(out.Name())
	return string(data), runErr
}

// runCheck starts a container that reports on its own isolation.
func (e *testEnv) runCheck(t *testing.T, id string, extra ...string) isolationReport {
	t.Helper()
	args := append([]string{"run", "--rootfs", e.rootfs, "--cgroup", "none"}, extra...)
	args = append(args, id, "/check")

	stdout, stderr, err := e.run(t, args...)
	if err != nil {
		t.Fatalf("running container: %v\nstderr: %s", err, stderr)
	}

	var report isolationReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("parsing isolation report: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	return report
}

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

	// Catches the capability policy silently no-opping, which is exactly what an
	// earlier version of this runtime did.
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
