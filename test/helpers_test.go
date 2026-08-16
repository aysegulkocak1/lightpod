//go:build integration || integration_root

// Shared plumbing for the end-to-end suites. Both the rootless (`integration`)
// and rootfull (`integration_root`) tags build this file.
package test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// What isolationcheck reports from inside. The only source worth trusting —
// asserting on the runtime's own logs is just the runtime agreeing with itself.
type isolationReport struct {
	Pid             int    `json:"pid"`
	Hostname        string `json:"hostname"`
	UID             int    `json:"uid"`
	VisibleProcs    int    `json:"visibleProcs"`
	MountCount      int    `json:"mountCount"`
	NoNewPrivs      string `json:"noNewPrivs"`
	Seccomp         string `json:"seccomp"`
	CapEff          string `json:"capEff"`
	CapBnd          string `json:"capBnd"`
	KcoreReadable   bool   `json:"kcoreReadable"`
	SysrqWritable   bool   `json:"sysrqWritable"`
	MountAllowed    bool   `json:"mountAllowed"`
	HostRootVisible bool   `json:"hostRootVisible"`
	ShmSizeKB       int    `json:"shmSizeKB"`
	RTSyscallOK     bool   `json:"rtSyscallOK"`
	RTFifoOK        bool   `json:"rtFifoOK"`
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
// A created container holds the caller's stdout/stderr — the runc contract
// podman relies on. With os/exec's pipe capture the parent waits for EOF, so
// `create` looks like it hangs. Real supervisors hand over files they manage
// themselves; this models that.
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
	return e.runCheckGlobal(t, nil, id, extra...)
}

// runCheckGlobal is runCheck with flags that belong before the subcommand.
//
// Global flags (--rootfull, --root) and run flags live in different flag sets,
// so passing one where the other is expected fails with "flag provided but not
// defined" rather than being quietly ignored.
func (e *testEnv) runCheckGlobal(t *testing.T, globals []string, id string, extra ...string) isolationReport {
	t.Helper()
	args := append([]string{}, globals...)
	args = append(args, "run", "--rootfs", e.rootfs, "--cgroup", "none")
	args = append(args, extra...)
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
