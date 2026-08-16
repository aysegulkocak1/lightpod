package runtime

import (
	"fmt"
	"os"
	"path/filepath"
)

// PrivilegeMode picks between the two ways to run a container.
//
// A type rather than `if os.Getuid() == 0` sprinkled around, because the
// difference isn't one branch: id mapping, cgroup placement, device nodes and
// state location all change. Easy to get four of those right and forget the fifth.
type PrivilegeMode int

const (
	// Runs as uid 0 on the host. Needed for mknod, device cgroup rules, and in
	// practice for GPU passthrough.
	ModeRootfull PrivilegeMode = iota

	// Unprivileged user inside a user namespace. Safer — an escape lands on an
	// unprivileged uid — but no mknod, no device cgroup, and limits only inside
	// a delegated subtree.
	ModeRootless
)

func (m PrivilegeMode) String() string {
	switch m {
	case ModeRootfull:
		return "rootfull"
	case ModeRootless:
		return "rootless"
	default:
		return "unknown"
	}
}

// DetectPrivilegeMode picks the mode from the effective uid.
func DetectPrivilegeMode() PrivilegeMode {
	if os.Geteuid() == 0 {
		return ModeRootfull
	}
	return ModeRootless
}

// StateRoot holds per-container state. Wants to be on a tmpfs so a crash
// doesn't leave phantom containers behind after a power cycle — which is how
// edge devices normally restart.
func (m PrivilegeMode) StateRoot() (string, error) {
	if m == ModeRootfull {
		return "/run/lightpod", nil
	}

	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		// Not /tmp — a world-writable state dir would let any local user forge
		// container records.
		dir = fmt.Sprintf("/run/user/%d", os.Getuid())
		if _, err := os.Stat(dir); err != nil {
			return "", fmt.Errorf("XDG_RUNTIME_DIR is unset and %s is unavailable: %w", dir, err)
		}
	}
	return filepath.Join(dir, "lightpod"), nil
}

// SupportsDeviceNodes: can we mknod, or do we have to bind mount host nodes.
func (m PrivilegeMode) SupportsDeviceNodes() bool {
	return m == ModeRootfull
}
