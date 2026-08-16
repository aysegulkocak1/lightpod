package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aysegulkocak1/lightpod/pkg/oci"
	"github.com/aysegulkocak1/lightpod/pkg/runtime"
)

// cmdSpec prints (or writes) a config.json with the defaults in it.
//
// So you can see the security posture before anything runs — every capability,
// masked path and seccomp rule. Defaults you can only find by reading source
// are defaults nobody checks.
func cmdSpec(opts *globalOptions, args []string) error {
	fs := flag.NewFlagSet("spec", flag.ContinueOnError)
	rootfs := fs.String("rootfs", "rootfs", "root filesystem path to record in the spec")
	bundle := fs.String("bundle", "", "write config.json into this bundle directory instead of stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	mode := runtime.DetectPrivilegeMode()

	command := fs.Args()
	if len(command) == 0 {
		command = []string{"sh"}
	}

	spec := oci.Default(*rootfs, command, mode == runtime.ModeRootless)

	if *bundle != "" {
		if err := os.MkdirAll(*bundle, 0o755); err != nil {
			return fmt.Errorf("creating bundle directory: %w", err)
		}
		if err := oci.Save(spec, *bundle); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", filepath.Join(*bundle, oci.ConfigFile))
		return nil
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "\t")
	return enc.Encode(spec)
}
