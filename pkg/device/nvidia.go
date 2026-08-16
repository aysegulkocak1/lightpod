package device

import (
	"fmt"
	"os"
	"strings"

	"github.com/aysegulkocak1/lightpod/pkg/oci"
)

// What the NVIDIA Container Toolkit installs. Reads the container state on
// stdin and shells out to nvidia-container-cli, which does the actual work.
const hookBinary = "nvidia-container-runtime-hook"

// hookSearchPaths covers the usual packaging locations.
var hookSearchPaths = []string{
	"/usr/bin/" + hookBinary,
	"/usr/local/bin/" + hookBinary,
	"/usr/local/nvidia/toolkit/" + hookBinary,
	"/sbin/" + hookBinary,
}

// SetNVIDIAEnv marks the spec as wanting GPUs. Both the runtime shim and the
// hook read these to decide what to expose, so they are set before either.
//
// devices goes into NVIDIA_VISIBLE_DEVICES — "all", or indices like "0,1".
func SetNVIDIAEnv(spec *oci.Spec, devices string) error {
	if spec.Process == nil {
		return fmt.Errorf("spec has no process section")
	}
	setEnv(spec, "NVIDIA_VISIBLE_DEVICES", devices)
	// Without a capability list the toolkit mounts nothing useful.
	if !hasEnv(spec, "NVIDIA_DRIVER_CAPABILITIES") {
		setEnv(spec, "NVIDIA_DRIVER_CAPABILITIES", "all")
	}
	return nil
}

// InjectNVIDIAHook is the fallback when the toolkit's runtime shim is not
// around: add its prestart hook and let it inject when we run the hook.
//
// NVIDIA has deprecated this path in favour of CDI, which is why it is second
// choice rather than first.
func InjectNVIDIAHook(spec *oci.Spec) error {
	hook, err := findNVIDIAHook()
	if err != nil {
		return err
	}
	if spec.Hooks == nil {
		spec.Hooks = &oci.Hooks{}
	}
	// Prestart, not createRuntime: that is the contract the hook is written for.
	spec.Hooks.Prestart = append(spec.Hooks.Prestart, oci.Hook{
		Path: hook,
		Args: []string{hookBinary, "prestart"},
	})
	return nil
}

// findNVIDIAHook locates the toolkit's hook binary.
func findNVIDIAHook() (string, error) {
	if custom := os.Getenv("LIGHTPOD_NVIDIA_HOOK"); custom != "" {
		if _, err := os.Stat(custom); err != nil {
			return "", fmt.Errorf("LIGHTPOD_NVIDIA_HOOK=%s: %w", custom, err)
		}
		return custom, nil
	}

	for _, path := range hookSearchPaths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("%s not found in %s.\n"+
		"GPU support needs the NVIDIA Container Toolkit installed on the host:\n"+
		"  https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html\n"+
		"Set LIGHTPOD_NVIDIA_HOOK to point at it if it lives elsewhere",
		hookBinary, strings.Join(hookSearchPaths, ", "))
}

func hasEnv(spec *oci.Spec, key string) bool {
	for _, kv := range spec.Process.Env {
		if name, _, _ := strings.Cut(kv, "="); name == key {
			return true
		}
	}
	return false
}

// setEnv replaces the variable if present, appends it otherwise.
func setEnv(spec *oci.Spec, key, value string) {
	entry := key + "=" + value
	for i, kv := range spec.Process.Env {
		if name, _, _ := strings.Cut(kv, "="); name == key {
			spec.Process.Env[i] = entry
			return
		}
	}
	spec.Process.Env = append(spec.Process.Env, entry)
}
