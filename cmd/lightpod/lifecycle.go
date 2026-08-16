package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/aysegulkocak1/lightpod/pkg/oci"
	"github.com/aysegulkocak1/lightpod/pkg/runtime"
)

// cmdCreate is the OCI create verb. Flags mirror runc's, including ones we
// don't implement — podman and nvidia-container-runtime pass them regardless.
func cmdCreate(opts *globalOptions, args []string) error {
	var rf runFlags
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	fs.StringVar(&rf.bundle, "bundle", "", "path to the OCI bundle")
	fs.StringVar(&rf.rootfs, "rootfs", "", "root filesystem directory; generates a bundle with secure defaults")
	fs.StringVar(&rf.memory, "memory", "", "memory limit, e.g. 64m or 1g")
	fs.Float64Var(&rf.cpus, "cpus", 0, "CPU limit as a fraction of one core")
	fs.Int64Var(&rf.pids, "pids", 0, "maximum number of processes")
	fs.StringVar(&rf.hostname, "hostname", "", "container hostname")
	fs.StringVar(&rf.cgroup, "cgroup", "", "set to \"none\" to run without cgroup limits")
	fs.StringVar(&rf.seccomp, "seccomp", "", "set to \"unconfined\" to run without a seccomp filter")
	fs.BoolVar(&rf.readonly, "read-only", false, "mount the container root filesystem read-only")
	pidFile := fs.String("pid-file", "", "write the container process id to this file")
	fs.String("console-socket", "", "accepted for runc compatibility")
	fs.Bool("no-pivot", false, "accepted for runc compatibility")
	fs.Bool("no-new-keyring", false, "accepted for runc compatibility")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("create needs a container id")
	}
	id := fs.Arg(0)
	command := fs.Args()[1:]

	// runc defaults --bundle to the working directory, so keep that when
	// neither flag is given: that is how podman and nvidia-container-runtime
	// sometimes invoke us.
	if rf.bundle == "" && rf.rootfs == "" {
		rf.bundle = "."
	}

	store, mode, err := openStore(opts)
	if err != nil {
		return err
	}

	bundle, spec, err := resolveBundle(&rf, command, mode, store.Dir(id))
	if err != nil {
		return err
	}

	c, err := runtime.New(id, bundle, spec, mode, store)
	if err != nil {
		return err
	}
	c.NoCgroup = rf.cgroup == "none"

	if err := c.Create(); err != nil {
		return err
	}

	if *pidFile != "" {
		record, err := c.State()
		if err != nil {
			return err
		}
		if err := os.WriteFile(*pidFile, []byte(strconv.Itoa(record.Pid)), 0o644); err != nil {
			return fmt.Errorf("writing pid file: %w", err)
		}
	}
	return nil
}

// cmdStart implements the OCI `start` verb.
func cmdStart(opts *globalOptions, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("start needs exactly one container id")
	}
	c, err := loadContainer(opts, args[0])
	if err != nil {
		return err
	}
	return c.Start()
}

// cmdState prints the state document hooks and orchestrators read.
func cmdState(opts *globalOptions, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("state needs exactly one container id")
	}
	c, err := loadContainer(opts, args[0])
	if err != nil {
		return err
	}
	s, err := c.State()
	if err != nil {
		return err
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}

// cmdKill implements the OCI `kill` verb.
func cmdKill(opts *globalOptions, args []string) error {
	fs := flag.NewFlagSet("kill", flag.ContinueOnError)
	all := fs.Bool("all", false, "signal every process in the container")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("kill needs a container id")
	}
	_ = all // whole-container signalling needs the cgroup freezer; TODO

	sig := syscall.SIGTERM
	if fs.NArg() > 1 {
		parsed, err := parseSignal(fs.Arg(1))
		if err != nil {
			return err
		}
		sig = parsed
	}

	c, err := loadContainer(opts, fs.Arg(0))
	if err != nil {
		return err
	}
	return c.Kill(sig)
}

// cmdDelete implements the OCI `delete` verb.
func cmdDelete(opts *globalOptions, args []string) error {
	fs := flag.NewFlagSet("delete", flag.ContinueOnError)
	force := fs.Bool("force", false, "kill the container if it is still running")
	fs.BoolVar(force, "f", false, "shorthand for --force")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("delete needs exactly one container id")
	}

	c, err := loadContainer(opts, fs.Arg(0))
	if err != nil {
		return err
	}
	return c.Delete(*force)
}

// cmdPs lists containers from the state store.
func cmdPs(opts *globalOptions, args []string) error {
	fs := flag.NewFlagSet("ps", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the container list as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, _, err := openStore(opts)
	if err != nil {
		return err
	}
	containers, err := store.List()
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(containers)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tPID\tSTATUS\tCREATED\tBUNDLE")
	for _, c := range containers {
		pid := "-"
		if c.Pid > 0 {
			pid = strconv.Itoa(c.Pid)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", c.ID, pid, c.Status, c.Created, c.Bundle)
	}
	return w.Flush()
}

// cmdPrune removes records for containers that are no longer running.
//
// A lightpod killed mid-run leaves its record behind and that id stays unusable.
// On a device restarting a container under a fixed name, one crash wedges it.
func cmdPrune(opts *globalOptions, args []string) error {
	fs := flag.NewFlagSet("prune", flag.ContinueOnError)
	dryRun := fs.Bool("dry-run", false, "list what would be removed without removing it")
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, _, err := openStore(opts)
	if err != nil {
		return err
	}
	containers, err := store.List()
	if err != nil {
		return err
	}

	var removed int
	for _, record := range containers {
		if record.Status != oci.StatusStopped {
			continue
		}
		if *dryRun {
			fmt.Println(record.ID)
			removed++
			continue
		}
		// Through the container handle, so the cgroup and poststop hooks get
		// cleaned up too and not just the record.
		c, err := loadContainer(opts, record.ID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "lightpod: %s: %v\n", record.ID, err)
			continue
		}
		if err := c.Delete(false); err != nil {
			fmt.Fprintf(os.Stderr, "lightpod: %s: %v\n", record.ID, err)
			continue
		}
		fmt.Println(record.ID)
		removed++
	}

	if removed == 0 {
		fmt.Fprintln(os.Stderr, "nothing to prune")
	}
	return nil
}

// loadContainer rebuilds a handle for an existing container.
//
// The spec gets re-read from the recorded bundle, because every command after
// create runs in a separate process and still needs to know the hooks.
func loadContainer(opts *globalOptions, id string) (*runtime.Container, error) {
	store, mode, err := openStore(opts)
	if err != nil {
		return nil, err
	}
	record, err := store.Load(id)
	if err != nil {
		return nil, err
	}

	spec, err := oci.Load(record.Bundle)
	if err != nil {
		// A deleted bundle shouldn't make the container undeletable.
		return runtime.Adopt(id, record, mode, store), nil
	}
	return runtime.New(id, record.Bundle, spec, mode, store)
}

// The signals anyone actually sends a container.
var signalNames = map[string]syscall.Signal{
	"HUP": syscall.SIGHUP, "INT": syscall.SIGINT, "QUIT": syscall.SIGQUIT,
	"KILL": syscall.SIGKILL, "USR1": syscall.SIGUSR1, "USR2": syscall.SIGUSR2,
	"TERM": syscall.SIGTERM, "STOP": syscall.SIGSTOP, "CONT": syscall.SIGCONT,
	"ABRT": syscall.SIGABRT, "ALRM": syscall.SIGALRM, "PIPE": syscall.SIGPIPE,
}

// parseSignal accepts a name ("TERM", "SIGTERM") or a number.
func parseSignal(s string) (syscall.Signal, error) {
	if n, err := strconv.Atoi(s); err == nil {
		return syscall.Signal(n), nil
	}
	name := strings.TrimPrefix(strings.ToUpper(s), "SIG")
	if sig, ok := signalNames[name]; ok {
		return sig, nil
	}
	return 0, fmt.Errorf("unknown signal %q", s)
}
