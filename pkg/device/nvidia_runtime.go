package device

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// runtimeBinary is the toolkit's runtime shim. Its whole job is to rewrite a
// bundle's config.json with the GPU edits and forward the command to a
// low-level runtime.
const runtimeBinary = "nvidia-container-runtime"

// FindNVIDIARuntime locates the toolkit's runtime shim, or reports why not.
func FindNVIDIARuntime() (string, bool) {
	if custom := os.Getenv("LIGHTPOD_NVIDIA_RUNTIME"); custom != "" {
		if _, err := os.Stat(custom); err == nil {
			return custom, true
		}
		return "", false
	}
	path, err := exec.LookPath(runtimeBinary)
	if err != nil {
		return "", false
	}
	return path, true
}

// PrepareBundleWithNVIDIA has the toolkit apply its GPU edits to a bundle.
//
// The toolkit rewrites config.json on disk and then hands the command to a
// low-level runtime. We point it at a stub that does nothing, so the rewrite
// happens and nothing else does — the caller re-reads config.json and runs the
// container itself.
//
// Doing it this way rather than sitting under the toolkit keeps the container
// as our own child, and uses whatever mode the toolkit defaults to (currently
// CDI) instead of the deprecated hook.
func PrepareBundleWithNVIDIA(runtimePath, bundle, containerID string) error {
	work, err := os.MkdirTemp("", "lightpod-nvidia-")
	if err != nil {
		return fmt.Errorf("creating work directory: %w", err)
	}
	defer os.RemoveAll(work)

	marker := filepath.Join(work, "called")
	stub := filepath.Join(work, "stub-runtime")
	script := "#!/bin/sh\ntouch " + marker + "\nexit 0\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		return fmt.Errorf("writing stub runtime: %w", err)
	}

	configPath := filepath.Join(work, "config.toml")
	config := "[nvidia-container-runtime]\nruntimes = [\"" + stub + "\"]\n"
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		return fmt.Errorf("writing toolkit config: %w", err)
	}

	before, err := os.ReadFile(filepath.Join(bundle, "config.json"))
	if err != nil {
		return fmt.Errorf("reading bundle config: %w", err)
	}

	cmd := exec.Command(runtimePath, "create", "--bundle", bundle, containerID)
	cmd.Env = append(os.Environ(), "NVIDIA_CTK_CONFIG_FILE_PATH="+configPath)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w\n%s", runtimeBinary, err, strings.TrimSpace(stderr.String()))
	}

	// If the stub was not the runtime it called, it called something else —
	// possibly runc, which would have tried to create the container for real.
	// Refuse rather than carry on against a bundle we cannot vouch for.
	if _, err := os.Stat(marker); err != nil {
		return fmt.Errorf("%s did not use the stub runtime, so it may have started "+
			"a container with a different runtime. Check NVIDIA_CTK_CONFIG_FILE_PATH "+
			"support in your toolkit version, or set LIGHTPOD_GPU_MODE=hook", runtimeBinary)
	}

	after, err := os.ReadFile(filepath.Join(bundle, "config.json"))
	if err != nil {
		return fmt.Errorf("re-reading bundle config: %w", err)
	}
	if string(before) == string(after) {
		return fmt.Errorf("%s left the bundle unchanged, so no GPU was injected. "+
			"Check that the driver is installed and NVIDIA_VISIBLE_DEVICES is set",
			runtimeBinary)
	}
	return nil
}
