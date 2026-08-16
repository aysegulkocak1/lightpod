// Command lightpod is a daemonless container engine for edge, IoT and robotics.
//
// Meant to be used on its own — no daemon, no higher-level tool. It also
// implements the OCI runtime verbs, so other tools can drive it.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/aysegulkocak1/lightpod/pkg/runtime"
	"github.com/aysegulkocak1/lightpod/pkg/state"
	"github.com/aysegulkocak1/lightpod/pkg/version"
)

// globalOptions are the flags before the subcommand.
type globalOptions struct {
	root         string
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
	fs := flag.NewFlagSet("lightpod", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = usage

	fs.StringVar(&opts.root, "root", "", "state directory")
	fs.StringVar(&opts.logFile, "log", "", "accepted for runc compatibility")
	fs.StringVar(&opts.logFormat, "log-format", "", "accepted for runc compatibility")
	fs.BoolVar(&opts.systemdGroup, "systemd-cgroup", false, "accepted for runc compatibility")
	fs.BoolVar(&opts.debug, "debug", false, "verbose logging")
	showVersion := fs.Bool("version", false, "print build information")
	// Taken and ignored; rejecting one would fail the container when another
	// tool passes it.
	fs.String("criu", "", "accepted for runc compatibility")
	fs.Bool("rootless-compat", false, "accepted for runc compatibility")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println(version.String())
		return nil
	}

	// Parse stops at the first non-flag, so what is left starts with the
	// subcommand and carries that subcommand's own flags untouched.
	rest := fs.Args()
	if len(rest) == 0 {
		usage()
		return fmt.Errorf("no command given")
	}
	command := rest[0]
	rest = rest[1:]

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
	case "prune":
		return cmdPrune(opts, rest)
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

// openStore picks the privilege mode from the effective uid and opens the
// state directory.
func openStore(opts *globalOptions) (*state.Store, runtime.PrivilegeMode, error) {
	mode := runtime.DetectPrivilegeMode()

	dir := opts.root
	if dir == "" {
		var err error
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
	fmt.Fprint(os.Stderr, `lightpod — a minimal, security-first container engine

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
  prune   [--dry-run]                      remove records of stopped containers
  spec    [--rootfs <dir>] [command...]    print a config.json with secure defaults
  version                                  print build information

Global flags:
  --root <dir>        state directory (default: /run/lightpod, or
                      $XDG_RUNTIME_DIR/lightpod when rootless)

  Rootless or rootfull is decided by the effective uid: run under sudo to get
  rootfull. There is no flag for it.

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
  --device <path>     host device, e.g. /dev/video0 (repeatable)
  --gpu <spec>        NVIDIA GPUs: all, or indices like 0 or 0,1
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
  lightpod run --rootfs ./app -v /srv/models:/models:ro --device /dev/video0 cam /app
  lightpod run --rootfs ./cuda-app --gpu all gpu /app
  lightpod create --rootfs ./app web && lightpod start web && lightpod ps

OCI runtime compatibility:
  lightpod also implements the OCI runtime verbs, so tools that drive a runtime
  can drive it. Not the primary way to use it, and not yet usable end to end:
  networking and image pull are still missing.

    podman --runtime=$(command -v lightpod) run alpine echo hi
`)
}
