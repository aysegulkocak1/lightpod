package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/aysegulkocak1/lightpod/pkg/oci"
	"github.com/aysegulkocak1/lightpod/pkg/security"
)

// InitMain is the entry point of the container-side process — everything here
// runs inside the new namespaces, as PID 1 of the container.
//
// It is reached by re-executing /proc/self/exe with the "init" argument. The
// re-exec exists because namespace transitions are per-thread and the Go
// runtime is multi-threaded: there is no safe way to unshare inside a running
// Go program. Re-executing gives a process that is born in the right
// namespaces, and the final execve replaces the Go runtime entirely, so the
// container does not carry a Go heap it never asked for.
//
// The ordering in this function is a security contract, not a style choice.
// Each step is annotated with why it sits where it does.
// InitStage1 gets the container an identity, then replaces itself.
//
// Why two stages. When the parent clones into a new user namespace the child's
// uid isn't mapped yet, so it reads as the overflow uid. Go's exec then runs
// execve immediately — and execve from a non-zero uid wipes the permitted
// capability set. Writing uid_map afterwards gives back the identity but not
// the caps; those are only recomputed on exec. Symptom was a PID 1 that
// couldn't even make its own mount namespace private.
//
// So we exec once more after the mapping exists. By then we're uid 0 in the
// namespace, the kernel hands over the full permitted set, and stage 2 starts
// with what it needs. Costs one exec of an already-resident binary.
//
// Handshaking here also leaves the parent free to use newuidmap/newgidmap,
// which is how rootless gets a whole /etc/subuid range instead of one id.
func InitStage1() error {
	// Config stays unread in the pipe — stage 2 wants it and we're about to be
	// replaced.
	sync := newSyncPipe(os.NewFile(fdSync, "sync"))

	if err := sync.send(syncNsReady); err != nil {
		return err
	}
	if err := sync.await(syncMapsReady); err != nil {
		return err
	}

	// ExtraFiles aren't close-on-exec, so stage 2 finds fds 3/4/5 where it
	// expects them.
	if err := syscall.Exec("/proc/self/exe", []string{"lightpod", initStage2Command}, os.Environ()); err != nil {
		err = fmt.Errorf("re-executing for stage 2: %w", err)
		sync.sendError(err)
		return err
	}
	return nil
}

// InitStage2 does the real setup, with capabilities. Never returns on success.
func InitStage2() error {
	configFile := os.NewFile(fdConfig, "config")
	if configFile == nil {
		return fmt.Errorf("init: config descriptor %d is missing (this command is not meant to be run directly)", fdConfig)
	}
	var cfg initConfig
	if err := json.NewDecoder(configFile).Decode(&cfg); err != nil {
		return fmt.Errorf("init: reading config: %w", err)
	}
	configFile.Close()

	sync := newSyncPipe(os.NewFile(fdSync, "sync"))

	if err := initSetup(&cfg, sync); err != nil {
		sync.sendError(err)
		return err
	}
	return nil
}

// initSetup runs the container-side sequence through to execve.
func initSetup(cfg *initConfig, sync *syncPipe) error {
	// Path-referenced namespaces (pod members sharing a net ns) aren't created
	// by the clone, so join them here.
	if err := joinNamespaces(cfg.Spec); err != nil {
		return err
	}

	if cfg.Spec.Hostname != "" && cfg.Spec.HasNamespace(oci.UTSNamespace) {
		if err := syscall.Sethostname([]byte(cfg.Spec.Hostname)); err != nil {
			return fmt.Errorf("setting hostname: %w", err)
		}
	}

	if err := applySysctls(cfg.Spec); err != nil {
		return err
	}

	// Step 4: every mount, but not the pivot.
	if err := prepareRootfs(cfg); err != nil {
		return err
	}

	// Hand over so the parent can run its hooks while the rootfs is still
	// reachable from the host.
	if err := sync.send(syncHookPoint); err != nil {
		return err
	}
	if err := sync.await(syncHooksDone); err != nil {
		return err
	}

	// createContainer hooks must run in the container's namespaces, hence here
	// and not in the parent. NVIDIA's CDI specs use this one for ldcache and
	// symlink fixups.
	if cfg.Spec.Hooks != nil {
		containerState := &oci.State{
			Version:     cfg.Spec.Version,
			ID:          cfg.ID,
			Status:      oci.StatusCreating,
			Pid:         cfg.HostPid,
			Bundle:      cfg.Bundle,
			Annotations: cfg.Spec.Annotations,
		}
		if err := runHooks(cfg.Spec.Hooks.CreateContainer, containerState); err != nil {
			return err
		}
	}

	// Step 8: from here on the host filesystem is unreachable.
	if err := finalizeRootfs(cfg); err != nil {
		return err
	}

	// Report ready before seccomp: a useful profile would otherwise have to
	// allow the very syscalls used to report success.
	//
	// Also before touching the FIFO. Opening it for writing blocks until a
	// reader shows up, and that reader is `lightpod start`, which only runs
	// after create returns — which waits for this message. Other order deadlocks.
	if err := sync.send(syncProcReady); err != nil {
		return err
	}
	sync.Close()

	// Block until `lightpod start` opens the other end. Reopened via
	// /proc/self/fd since the original path is on the host, gone after the
	// pivot. Blocking in open() is the whole mechanism — no polling, no daemon.
	fifo, err := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", fdFifo), os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("waiting on start FIFO: %w", err)
	}
	if _, err := fifo.Write([]byte{0}); err != nil {
		fifo.Close()
		return fmt.Errorf("signalling start FIFO: %w", err)
	}
	fifo.Close()

	if cfg.Spec.Hooks != nil {
		startState := &oci.State{
			Version: cfg.Spec.Version,
			ID:      cfg.ID,
			Status:  oci.StatusCreated,
			Pid:     cfg.HostPid,
			Bundle:  cfg.Bundle,
		}
		if err := runHooks(cfg.Spec.Hooks.StartContainer, startState); err != nil {
			return err
		}
	}

	return execUserProcess(cfg)
}

// applySysctls writes the namespaced kernel parameters the spec asks for.
func applySysctls(spec *oci.Spec) error {
	if spec.Linux == nil || len(spec.Linux.Sysctl) == 0 {
		return nil
	}
	for key, value := range spec.Linux.Sysctl {
		path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
		if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
			return fmt.Errorf("setting sysctl %s=%s: %w", key, value, err)
		}
	}
	return nil
}

// execUserProcess drops privileges and becomes the user's command.
//
// Order is the last line of defence, don't rearrange:
//  1. Resolve the binary while the filesystem is still freely readable.
//  2. Switch uid/gid, with KEEPCAPS first so the caps survive the transition.
//  3. Apply the capability policy.
//  4. no_new_privs, making the drop permanent across execve.
//  5. seccomp last — everything above uses syscalls a real profile denies.
func execUserProcess(cfg *initConfig) error {
	process := cfg.Spec.Process

	env := process.Env
	if env == nil {
		env = os.Environ()
	}
	// LookPath uses our own PATH, still the host's unless we take the
	// container's first.
	for _, kv := range env {
		if name, value, ok := strings.Cut(kv, "="); ok && name == "PATH" {
			os.Setenv("PATH", value)
			break
		}
	}

	binary, err := exec.LookPath(process.Args[0])
	if err != nil {
		return fmt.Errorf("resolving %q inside the container: %w", process.Args[0], err)
	}

	if err := setupUser(process); err != nil {
		return err
	}

	if err := security.ApplyCapabilities(process.Capabilities); err != nil {
		return err
	}

	if process.NoNewPrivileges {
		if err := security.SetNoNewPrivs(); err != nil {
			return err
		}
	}

	if cfg.Spec.Linux != nil {
		if err := security.ApplySeccomp(cfg.Spec.Linux.Seccomp); err != nil {
			return err
		}
	}

	if err := syscall.Exec(binary, process.Args, env); err != nil {
		return fmt.Errorf("executing %s: %w", binary, err)
	}
	return nil // unreachable: execve does not return on success
}

// setupUser switches to the uid/gid the spec asks for.
func setupUser(process *oci.Process) error {
	if process.User.UID == 0 && process.User.GID == 0 && len(process.User.AdditionalGids) == 0 {
		return nil
	}

	// Keep caps across the uid change so our policy decides, not the kernel's
	// default clearing.
	if err := security.SetKeepCaps(true); err != nil {
		return err
	}

	if len(process.User.AdditionalGids) > 0 {
		gids := make([]int, len(process.User.AdditionalGids))
		for i, g := range process.User.AdditionalGids {
			gids[i] = int(g)
		}
		if err := syscall.Setgroups(gids); err != nil {
			return fmt.Errorf("setting supplementary groups: %w", err)
		}
	}

	// Group before user — once we're unprivileged we can't change gid.
	if err := syscall.Setgid(int(process.User.GID)); err != nil {
		return fmt.Errorf("setting gid %d: %w", process.User.GID, err)
	}
	if err := syscall.Setuid(int(process.User.UID)); err != nil {
		return fmt.Errorf("setting uid %d: %w", process.User.UID, err)
	}

	if err := security.SetKeepCaps(false); err != nil {
		return err
	}
	return nil
}
