package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/aysegulkocak1/lightpod/pkg/oci"
	"github.com/aysegulkocak1/lightpod/pkg/runtime"
)

// Shortcuts run offers on top of a bundle.
type runFlags struct {
	bundle   string
	rootfs   string
	memory   string
	cpus     float64
	pids     int64
	hostname string
	cgroup   string
	seccomp  string
	readonly bool
	tty      bool
	shmSize  string
	ipc      string
	workdir  string
	user     string
	gpu      string
	volumes  repeatedFlag
	devices  repeatedFlag
	env      repeatedFlag
	addCaps  repeatedFlag
}

// repeatedFlag collects a flag given more than once, like -v and --device.
type repeatedFlag []string

func (r *repeatedFlag) String() string { return strings.Join(*r, ",") }

func (r *repeatedFlag) Set(value string) error {
	*r = append(*r, value)
	return nil
}

// registerRunFlags wires the shared flag set used by both run and create, so
// the two commands cannot drift apart.
func registerRunFlags(fs *flag.FlagSet, rf *runFlags) {
	fs.StringVar(&rf.bundle, "bundle", "", "OCI bundle directory containing config.json")
	fs.StringVar(&rf.rootfs, "rootfs", "", "root filesystem directory (generates a bundle with secure defaults)")
	fs.Var(&rf.volumes, "v", "bind mount, host:container[:ro] (repeatable)")
	fs.Var(&rf.volumes, "volume", "bind mount, host:container[:ro] (repeatable)")
	fs.Var(&rf.devices, "device", "host device to expose, e.g. /dev/video0[:rw] (repeatable)")
	fs.StringVar(&rf.gpu, "gpu", "", "NVIDIA GPUs to expose: all, or indices like 0 or 0,1")
	fs.Var(&rf.env, "env", "environment variable, KEY=VALUE (repeatable)")
	fs.Var(&rf.env, "e", "environment variable, KEY=VALUE (repeatable)")
	fs.Var(&rf.addCaps, "cap-add", "capability to grant, e.g. CAP_SYS_NICE (repeatable)")
	fs.StringVar(&rf.user, "user", "", "uid[:gid] to run as")
	fs.StringVar(&rf.workdir, "workdir", "", "working directory inside the container")
	fs.StringVar(&rf.memory, "memory", "", "memory limit, e.g. 64m or 1g")
	fs.Float64Var(&rf.cpus, "cpus", 0, "CPU limit as a fraction of one core, e.g. 1.5")
	fs.Int64Var(&rf.pids, "pids", 0, "maximum number of processes")
	fs.StringVar(&rf.shmSize, "shm-size", "", "size of /dev/shm, e.g. 256m (DDS and ROS 2 need more than the 64m default)")
	fs.StringVar(&rf.ipc, "ipc", "", "set to \"host\" to share the host IPC namespace")
	fs.StringVar(&rf.hostname, "hostname", "", "container hostname")
	fs.StringVar(&rf.cgroup, "cgroup", "", "set to \"none\" to run without cgroup limits")
	fs.StringVar(&rf.seccomp, "seccomp", "", "set to \"unconfined\" to run without a seccomp filter")
	fs.BoolVar(&rf.readonly, "read-only", false, "mount the container root filesystem read-only")
	fs.BoolVar(&rf.tty, "tty", false, "allocate a terminal (not implemented yet)")
}

// cmdRun creates, starts and waits in one command.
//
// What an edge device actually uses: one foreground process under a systemd
// unit, no daemon, exit code forwarded so the supervisor can act on it.
func cmdRun(opts *globalOptions, args []string) error {
	var rf runFlags
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	registerRunFlags(fs, &rf)
	if err := fs.Parse(args); err != nil {
		return err
	}

	rest := fs.Args()
	if len(rest) < 1 {
		return fmt.Errorf("run needs a container id")
	}
	id := rest[0]
	command := rest[1:]

	store, mode, err := openStore(opts)
	if err != nil {
		return err
	}

	bundle, spec, err := resolveBundle(&rf, command, mode, store.Dir(id))
	if err != nil {
		return err
	}
	spec, err = applyGPU(bundle, id, spec, rf.gpu)
	if err != nil {
		return err
	}

	c, err := runtime.New(id, bundle, spec, mode, store)
	if err != nil {
		return err
	}
	c.NoCgroup = rf.cgroup == "none"

	code, err := c.Run()
	if err != nil {
		return err
	}

	// Foreground run leaves nothing behind, like every other `run` out there.
	if delErr := c.Delete(true); delErr != nil {
		fmt.Fprintf(os.Stderr, "lightpod: cleanup: %v\n", delErr)
	}
	if code != 0 {
		os.Exit(code)
	}
	return nil
}

// resolveBundle produces the bundle we actually run from.
//
// --rootfs doesn't bypass it: it generates a full spec, writes a real bundle,
// and we start from that. One code path, one set of security defaults to audit,
// and any running container's real config is on disk rather than inferred from
// the command line that started it.
func resolveBundle(rf *runFlags, command []string, mode runtime.PrivilegeMode, workDir string) (string, *oci.Spec, error) {
	if rf.bundle != "" && rf.rootfs != "" {
		return "", nil, fmt.Errorf("--bundle and --rootfs are mutually exclusive")
	}

	if rf.bundle != "" {
		spec, err := oci.Load(rf.bundle)
		if err != nil {
			return "", nil, err
		}
		if len(command) > 0 && spec.Process != nil {
			spec.Process.Args = command
		}
		if err := applyRunFlags(spec, rf); err != nil {
			return "", nil, err
		}
		return rf.bundle, spec, nil
	}

	if rf.rootfs == "" {
		return "", nil, fmt.Errorf("run needs either --bundle or --rootfs")
	}
	if len(command) == 0 {
		return "", nil, fmt.Errorf("run needs a command to execute")
	}

	rootfs, err := filepath.Abs(rf.rootfs)
	if err != nil {
		return "", nil, fmt.Errorf("resolving rootfs path: %w", err)
	}

	spec := oci.Default(rootfs, command, mode == runtime.ModeRootless)
	if err := applyRunFlags(spec, rf); err != nil {
		return "", nil, err
	}

	// Lives next to the container's state, which is on tmpfs — no disk I/O and
	// it goes away with the container.
	bundle := filepath.Join(workDir, "bundle")
	if err := os.MkdirAll(bundle, 0o700); err != nil {
		return "", nil, fmt.Errorf("creating generated bundle directory: %w", err)
	}
	if err := oci.Save(spec, bundle); err != nil {
		return "", nil, err
	}
	return bundle, spec, nil
}

// applyRunFlags folds the shortcuts into the spec.
func applyRunFlags(spec *oci.Spec, rf *runFlags) error {
	if spec.Linux == nil {
		spec.Linux = &oci.Linux{}
	}
	if spec.Linux.Resources == nil {
		spec.Linux.Resources = &oci.LinuxResources{}
	}

	if rf.hostname != "" {
		spec.Hostname = rf.hostname
	}
	if rf.readonly && spec.Root != nil {
		spec.Root.Readonly = true
	}
	if rf.tty {
		return fmt.Errorf("--tty is not implemented yet: lightpod does not allocate a pty. " +
			"Run without it, or use `lightpod exec` once that lands")
	}

	if err := applyProcessFlags(spec, rf); err != nil {
		return err
	}
	if err := applyMountFlags(spec, rf); err != nil {
		return err
	}
	if err := applyDeviceFlags(spec, rf); err != nil {
		return err
	}

	if rf.memory != "" {
		bytes, err := parseSize(rf.memory)
		if err != nil {
			return fmt.Errorf("--memory: %w", err)
		}
		spec.Linux.Resources.Memory = &oci.LinuxMemory{Limit: &bytes}
	}

	if rf.cpus > 0 {
		const period = 100000
		quota := int64(rf.cpus * period)
		p := uint64(period)
		spec.Linux.Resources.CPU = &oci.LinuxCPU{Quota: &quota, Period: &p}
	}

	if rf.pids > 0 {
		spec.Linux.Resources.Pids = &oci.LinuxPids{Limit: rf.pids}
	}

	if rf.seccomp == "unconfined" {
		fmt.Fprintln(os.Stderr, "lightpod: WARNING: seccomp is disabled; the container can issue any syscall")
		spec.Linux.Seccomp = nil
	}

	return nil
}

// parseSize accepts plain byte counts and the usual k/m/g suffixes.
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	multiplier := int64(1)
	switch {
	case strings.HasSuffix(s, "g"), strings.HasSuffix(s, "gb"):
		multiplier = 1 << 30
	case strings.HasSuffix(s, "m"), strings.HasSuffix(s, "mb"):
		multiplier = 1 << 20
	case strings.HasSuffix(s, "k"), strings.HasSuffix(s, "kb"):
		multiplier = 1 << 10
	}
	digits := strings.TrimRight(s, "kmgb")
	value, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a valid size", s)
	}
	return value * multiplier, nil
}
