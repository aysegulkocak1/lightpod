package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/aysegulkocak1/lightpod/pkg/oci"
	"github.com/aysegulkocak1/lightpod/pkg/state"
)

// Descriptors handed to init. Go's exec places ExtraFiles from fd 3 up, so
// these have to match the order they're built in.
const (
	fdConfig = 3 // read end of the spec pipe
	fdSync   = 4 // parent/child handshake socket
	fdFifo   = 5 // O_PATH handle to the start FIFO
)

// The two container-side stages. Not documented commands — both need inherited
// descriptors and do nothing useful by hand.
const (
	initStage1Command = "init"
	initStage2Command = "init2"
)

// O_PATH, not exported by the syscall package. Refers to a file without opening
// either end — the only way to hold a FIFO without blocking or counting as its
// reader.
const oPath = 0x200000

// initConfig is what the init side needs. Sent over a pipe rather than argv so
// the config never shows up in the host's process list.
type initConfig struct {
	Spec   *oci.Spec     `json:"spec"`
	Rootfs string        `json:"rootfs"`
	ID     string        `json:"id"`
	Bundle string        `json:"bundle"`
	Mode   PrivilegeMode `json:"mode"`

	// The pid as the host sees it. Init can't work this out itself — inside the
	// PID namespace it's 1 — but hooks get the host pid, since that's the only
	// number a host-side tool can act on.
	HostPid int `json:"hostPid"`
}

// Container is the host-side handle.
//
// Everything in this file runs on the host; the container side is init.go. They
// never share code paths — after the clone it should be obvious from the file
// name which side of the boundary you're on.
type Container struct {
	ID     string
	Bundle string
	Rootfs string
	Spec   *oci.Spec
	Mode   PrivilegeMode

	// --cgroup=none: skip cgroups entirely.
	NoCgroup bool

	store  *state.Store
	cgroup *CgroupManager
	cmd    *exec.Cmd
}

// New builds a container handle from a loaded bundle.
func New(id, bundle string, spec *oci.Spec, mode PrivilegeMode, store *state.Store) (*Container, error) {
	if err := state.ValidateID(id); err != nil {
		return nil, err
	}
	rootfs, err := oci.ResolveRootfs(spec, bundle)
	if err != nil {
		return nil, err
	}
	if spec.Process == nil || len(spec.Process.Args) == 0 {
		return nil, fmt.Errorf("spec has no process.args to execute")
	}

	absBundle, err := filepath.Abs(bundle)
	if err != nil {
		return nil, fmt.Errorf("resolving bundle path: %w", err)
	}

	return &Container{
		ID:     id,
		Bundle: absBundle,
		Rootfs: rootfs,
		Spec:   spec,
		Mode:   mode,
		store:  store,
	}, nil
}

// Adopt builds a handle when the bundle is gone. Otherwise deleting the bundle
// directory would leave a container nobody can kill or delete — teardown
// shouldn't depend on state outside the store.
func Adopt(id string, record *state.Container, mode PrivilegeMode, store *state.Store) *Container {
	return &Container{
		ID:     id,
		Bundle: record.Bundle,
		Rootfs: record.Rootfs,
		Mode:   mode,
		store:  store,
	}
}

// Create runs the container through setup and leaves it blocked just before the
// user command.
//
// The OCI create verb. Splitting it from start is what lets a CNI plugin, a GPU
// hook or an orchestrator act on a fully configured container before the
// workload gets to run.
func (c *Container) Create() (err error) {
	if _, err := c.store.Load(c.ID); err == nil {
		return fmt.Errorf("container %q already exists", c.ID)
	}

	if err := os.MkdirAll(c.store.Dir(c.ID), 0o700); err != nil {
		return fmt.Errorf("creating container directory: %w", err)
	}
	defer func() {
		if err != nil {
			// Cgroup too, not just the record — a device retrying the same
			// container for weeks shouldn't pile up empty directories.
			if c.cgroup != nil {
				_ = c.cgroup.Cleanup()
			}
			_ = c.store.Delete(c.ID)
		}
	}()

	fifoPath := filepath.Join(c.store.Dir(c.ID), "start.fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil && !os.IsExist(err) {
		return fmt.Errorf("creating start FIFO: %w", err)
	}

	// O_PATH doesn't block and doesn't count as the reader the container waits
	// for. The child reopens it via /proc/self/fd after the pivot, once the host
	// path is gone.
	fifo, err := os.OpenFile(fifoPath, oPath|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("opening start FIFO: %w", err)
	}
	defer fifo.Close()

	configR, configW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("creating config pipe: %w", err)
	}
	defer configR.Close()
	defer configW.Close()

	parentSock, childSock, err := socketPair()
	if err != nil {
		return err
	}
	defer parentSock.Close()
	defer childSock.Close()

	flags, err := cloneFlags(c.Spec)
	if err != nil {
		return err
	}

	cmd := exec.Command("/proc/self/exe", initStage1Command)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{configR, childSock, fifo}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: flags,
		// Not using SysProcAttr.UidMappings: Go's version can't call newuidmap,
		// so it can't map a /etc/subuid range, which would pin every rootless
		// container to a single uid. We write the maps ourselves after the clone.
		Setsid: true,
	}
	// /proc/self/exe rather than a path on disk — the kernel guarantees it's
	// this exact binary, so nobody can swap it underneath us.
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting container init process: %w", err)
	}
	c.cmd = cmd
	pid := cmd.Process.Pid

	defer func() {
		if err != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	}()

	sync := newSyncPipe(parentSock)

	cfg := &initConfig{
		Spec:    c.Spec,
		Rootfs:  c.Rootfs,
		ID:      c.ID,
		Bundle:  c.Bundle,
		Mode:    c.Mode,
		HostPid: pid,
	}
	if err := json.NewEncoder(configW).Encode(cfg); err != nil {
		return fmt.Errorf("sending config to init process: %w", err)
	}
	configW.Close()

	if err := sync.await(syncNsReady); err != nil {
		return err
	}

	// Give it an identity and a budget while it waits.
	uids, gids := idMappings(c.Spec, c.Mode)
	if err := writeIDMaps(pid, uids, gids, c.Mode); err != nil {
		return err
	}

	cg, err := NewCgroupManager(c.ID, c.Spec, c.Mode, c.NoCgroup)
	if err != nil {
		return err
	}
	c.cgroup = cg
	if err := cg.Apply(pid); err != nil {
		return err
	}
	if c.Spec.Linux != nil {
		if err := cg.SetResources(c.Spec.Linux.Resources); err != nil {
			return err
		}
	}

	if err := sync.send(syncMapsReady); err != nil {
		return err
	}

	// Mounts are in place, pivot hasn't happened. Hooks that write into the
	// container's filesystem go here.
	if err := sync.await(syncHookPoint); err != nil {
		return err
	}

	ociState := &oci.State{
		Version:     c.Spec.Version,
		ID:          c.ID,
		Status:      oci.StatusCreating,
		Pid:         pid,
		Bundle:      c.Bundle,
		Annotations: c.Spec.Annotations,
	}
	if c.Spec.Hooks != nil {
		// Prestart is deprecated but legacy nvidia-container-runtime still
		// injects it, so run both lists.
		if err := runHooks(c.Spec.Hooks.Prestart, ociState); err != nil {
			sync.sendError(err)
			return err
		}
		if err := runHooks(c.Spec.Hooks.CreateRuntime, ociState); err != nil {
			sync.sendError(err)
			return err
		}
	}

	if err := sync.send(syncHooksDone); err != nil {
		return err
	}

	// Setup done, container is parked waiting for start.
	if err := sync.await(syncProcReady); err != nil {
		return err
	}

	record := &state.Container{
		ID:          c.ID,
		Bundle:      c.Bundle,
		Rootfs:      c.Rootfs,
		Pid:         pid,
		Status:      oci.StatusCreated,
		CgroupPath:  cg.Path,
		Created:     time.Now().UTC().Format(time.RFC3339),
		Annotations: c.Spec.Annotations,
	}
	if err := c.store.Save(record); err != nil {
		return err
	}
	return nil
}

// Start releases a created container. Opening the FIFO for reading is what
// unblocks it — it's been sitting in open() for writing since setup finished.
func (c *Container) Start() error {
	record, err := c.store.Load(c.ID)
	if err != nil {
		return err
	}
	if record.Status != oci.StatusCreated {
		return fmt.Errorf("cannot start container %q in state %q", c.ID, record.Status)
	}

	fifoPath := filepath.Join(c.store.Dir(c.ID), "start.fifo")
	f, err := os.OpenFile(fifoPath, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("opening start FIFO: %w", err)
	}
	buf := make([]byte, 1)
	_, _ = f.Read(buf)
	f.Close()

	record.Status = oci.StatusRunning
	if err := c.store.Save(record); err != nil {
		return err
	}

	if c.Spec.Hooks != nil {
		if err := runHooks(c.Spec.Hooks.Poststart, record.ToOCI()); err != nil {
			// Workload is already running — failing now would misreport a
			// container that's up and fine.
			fmt.Fprintf(os.Stderr, "lightpod: poststart hook failed: %v\n", err)
		}
	}
	return nil
}

// Run creates, starts and waits in the foreground.
//
// The edge-device path: one process, no daemon, exit code forwarded. Reuses
// Create and Start instead of shortcutting, so there's one setup sequence to audit.
func (c *Container) Run() (int, error) {
	if err := c.Create(); err != nil {
		return 1, err
	}
	if err := c.Start(); err != nil {
		return 1, err
	}

	stop := forwardSignals(c.cmd.Process)
	defer stop()

	err := c.cmd.Wait()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if ok := asExitError(err, &exitErr); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return 1, fmt.Errorf("waiting for container: %w", err)
		}
	}

	if record, loadErr := c.store.Load(c.ID); loadErr == nil {
		record.Status = oci.StatusStopped
		record.Pid = 0
		_ = c.store.Save(record)
	}
	return exitCode, nil
}

// Kill sends a signal to the container's init process.
func (c *Container) Kill(sig syscall.Signal) error {
	record, err := c.store.Load(c.ID)
	if err != nil {
		return err
	}
	if record.Status == oci.StatusStopped {
		return fmt.Errorf("container %q is not running", c.ID)
	}
	if err := syscall.Kill(record.Pid, sig); err != nil {
		return fmt.Errorf("signalling container %q (pid %d): %w", c.ID, record.Pid, err)
	}
	return nil
}

// Delete removes a stopped container and its resources.
func (c *Container) Delete(force bool) error {
	record, err := c.store.Load(c.ID)
	if err != nil {
		return err
	}

	if record.Status != oci.StatusStopped {
		if !force {
			return fmt.Errorf("container %q is %s; stop it first or pass --force", c.ID, record.Status)
		}
		if record.Pid > 0 {
			_ = syscall.Kill(record.Pid, syscall.SIGKILL)
			waitForExit(record.Pid, 5*time.Second)
		}
	}

	if record.CgroupPath != "" {
		cg := &CgroupManager{Path: record.CgroupPath}
		if err := cg.Cleanup(); err != nil {
			fmt.Fprintf(os.Stderr, "lightpod: %v\n", err)
		}
	}

	if c.Spec != nil && c.Spec.Hooks != nil {
		runPoststopHooks(c.Spec.Hooks.Poststop, record.ToOCI())
	}

	return c.store.Delete(c.ID)
}

// State returns the runtime-spec state document for this container.
func (c *Container) State() (*oci.State, error) {
	record, err := c.store.Load(c.ID)
	if err != nil {
		return nil, err
	}
	return record.ToOCI(), nil
}

// socketPair is the handshake channel. A pair rather than two pipes — it goes
// both ways, and one fd per side keeps the numbering init depends on simple.
func socketPair() (parent, child *os.File, err error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("creating sync socket pair: %w", err)
	}
	return os.NewFile(uintptr(fds[0]), "sync-parent"), os.NewFile(uintptr(fds[1]), "sync-child"), nil
}

// waitForExit polls until the pid goes away or we give up.
func waitForExit(pid int, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}
