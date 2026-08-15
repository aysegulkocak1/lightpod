// Command lightpod is a daemonless OCI container runtime for edge, IoT and
// robotics. It speaks the OCI verbs, so it works on its own or underneath
// podman / nvidia-container-runtime with --runtime=lightpod.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/aysegulkocak1/lightpod/pkg/runtime"
	"github.com/aysegulkocak1/lightpod/pkg/state"
	"github.com/aysegulkocak1/lightpod/pkg/version"
)

// globalOptions are the flags before the subcommand.
//
// Some exist purely for compatibility: podman and nvidia-container-runtime call
// their runtime with runc's global flags, and rejecting an unknown one fails the
// whole container. Accepting and ignoring is the difference between working
// under those tools and not.
type globalOptions struct {
	root         string
	privilege    string
	logFile      string
	logFormat    string
	systemdGroup bool
	debug        bool
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "lightpod: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	opts := &globalOptions{}

	// Parsed by hand: these come before a subcommand, and flag.Parse stops at
	// the first non-flag without telling us whose flags are whose.
	var command string
	i := 0
	for ; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			command = arg
			i++
			break
		}

		name, value, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		next := func() (string, error) {
			if hasValue {
				return value, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("flag --%s needs a value", name)
			}
			i++
			return args[i], nil
		}

		var err error
		switch name {
		case "help", "h":
			usage()
			return nil
		case "version", "v":
			fmt.Println(version.String())
			return nil
		case "root":
			opts.root, err = next()
		case "privilege", "mode":
			opts.privilege, err = next()
		case "rootless":
			opts.privilege = "rootless"
		case "rootfull", "rootful":
			opts.privilege = "rootfull"
		case "log":
			opts.logFile, err = next()
		case "log-format":
			opts.logFormat, err = next()
		case "debug":
			opts.debug = true
		case "systemd-cgroup":
			opts.systemdGroup = true
		case "criu", "rootless-compat":
			_, err = next() // runc flags with no meaning here
		default:
			return fmt.Errorf("unknown global flag --%s", name)
		}
		if err != nil {
			return err
		}
	}

	if command == "" {
		usage()
		return fmt.Errorf("no command given")
	}

	rest := args[i:]

	switch command {
	case "init":
		// Not user-facing. First container-side stage; needs inherited fds, so
		// running it by hand does nothing.
		return runtime.InitStage1()
	case "init2":
		return runtime.InitStage2()
	case "create":
		return cmdCreate(opts, rest)
	case "start":
		return cmdStart(opts, rest)
	case "run":
		return cmdRun(opts, rest)
	case "state":
		return cmdState(opts, rest)
	case "kill":
		return cmdKill(opts, rest)
	case "delete", "rm":
		return cmdDelete(opts, rest)
	case "ps", "list":
		return cmdPs(opts, rest)
	case "spec":
		return cmdSpec(opts, rest)
	case "help":
		usage()
		return nil
	case "version":
		fmt.Println(version.String())
		return nil
	default:
		return fmt.Errorf("unknown command %q (try `lightpod help`)", command)
	}
}

// openStore resolves the privilege mode and opens the state directory.
func openStore(opts *globalOptions) (*state.Store, runtime.PrivilegeMode, error) {
	mode, err := runtime.ParsePrivilegeMode(opts.privilege)
	if err != nil {
		return nil, 0, err
	}

	dir := opts.root
	if dir == "" {
		dir, err = mode.StateRoot()
		if err != nil {
			return nil, 0, err
		}
	}

	store, err := state.New(dir)
	if err != nil {
		return nil, 0, err
	}
	return store, mode, nil
}

func usage() {
	fmt.Fprint(os.Stderr, `lightpod — a minimal, security-first OCI container runtime

Usage:
  lightpod [global flags] <command> [arguments]

Commands:
  run     [flags] <id> [--] <command>...   create, start and wait in the foreground
  create  [flags] <id> [command...]        create a container without starting it
  start   <id>                             start a created container
  state   <id>                             print the OCI state document
  kill    <id> [signal]                    signal a running container (default TERM)
  delete  [--force] <id>                   remove a stopped container
  ps                                       list containers
  spec    [--rootfs <dir>] [command...]    print a config.json with secure defaults
  version                                  print build information

Global flags:
  --root <dir>        state directory (default: /run/lightpod, or
                      $XDG_RUNTIME_DIR/lightpod when rootless)
  --rootless          run in a user namespace even as root
  --rootfull          require uid 0; fail instead of falling back to rootless

  The mode is detected from the effective uid, so running under sudo already
  means rootfull. The two flags above are overrides: --rootless gives a root
  caller the extra isolation of a user namespace, and --rootfull turns a
  silent downgrade (and its missing GPU) into an error.

  --log <file>        accepted for runc compatibility
  --log-format <fmt>  accepted for runc compatibility
  --systemd-cgroup    accepted for runc compatibility
  --version           print build information

Flags for run and create:
  --bundle <dir>      OCI bundle directory containing config.json
  --rootfs <dir>      shortcut: generate a bundle with secure defaults for this rootfs
  --memory <bytes>    memory limit
  --cpus <n>          CPU limit, as a fraction of one core
  --pids <n>          maximum number of processes
  --hostname <name>   container hostname
  --cgroup none       run without cgroup limits (explicitly unlimited)
  --seccomp unconfined
                      run without a seccomp filter (explicitly unsandboxed)

Note on create:
  A created container inherits this process's stdin, stdout and stderr and keeps
  holding them until it exits — the OCI behaviour that podman and
  nvidia-container-runtime rely on. So if you capture "lightpod create" output
  through a pipe, that pipe stays open for the container's lifetime. Redirect to
  a file instead, or use "run" for foreground work.

Examples:
  lightpod run --rootfs ./busybox demo /bin/sh
  lightpod create --bundle ./mybundle web && lightpod start web
  podman --runtime=$(command -v lightpod) run alpine echo hi
`)
}
