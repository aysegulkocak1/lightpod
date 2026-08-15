package runtime

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/aysegulkocak1/lightpod/pkg/oci"
)

// CgroupManager puts a container in a cgroup v2 group and applies its limits.
//
// v2 only. v1 can't express delegation to an unprivileged user safely, which
// would mean rootless containers quietly running unlimited — and an unlimited
// container on a 4GB board takes the whole board down, not just itself.
type CgroupManager struct {
	Path string

	// Set by --cgroup=none: create nothing, apply nothing.
	disabled bool
}

// The v2 hierarchy exists but every controller is still bound to v1. Nothing to
// delegate, so this is a boot-time setting, not a permissions problem.
var errCgroupV2NotInUse = fmt.Errorf(
	"this system mounts cgroup v2 but runs its controllers on cgroup v1 (hybrid mode),\n" +
		"so there is nothing to enforce limits with. Either:\n" +
		"  - switch to unified cgroups: add systemd.unified_cgroup_hierarchy=1 to the\n" +
		"    kernel command line (GRUB_CMDLINE_LINUX in /etc/default/grub), then\n" +
		"    sudo update-grub && reboot\n" +
		"  - or run with --cgroup=none to accept an unlimited container explicitly")

// The most common rootless setup failure, so spell out the fix.
var errNoCgroupDelegation = fmt.Errorf(
	"no writable cgroup v2 delegation found for this user.\n" +
		"Rootless resource limits need systemd to delegate a cgroup subtree. Either:\n" +
		"  - enable delegation:  sudo mkdir -p /etc/systemd/system/user@.service.d && \\\n" +
		"      printf '[Service]\\nDelegate=memory pids cpu cpuset\\n' | \\\n" +
		"      sudo tee /etc/systemd/system/user@.service.d/delegate.conf && sudo systemctl daemon-reload\n" +
		"      (then log out and back in)\n" +
		"  - or run with --cgroup=none to accept an unlimited container explicitly")

// NewCgroupManager prepares the container's cgroup.
//
// Errors out rather than warning and carrying on. A container asked to stay
// under 64MB that silently got no limit is worse than one that refused to
// start — you'd believe in a protection that isn't there.
func NewCgroupManager(id string, spec *oci.Spec, mode PrivilegeMode, disabled bool) (*CgroupManager, error) {
	if disabled {
		return &CgroupManager{disabled: true}, nil
	}

	mountpoint, root, err := cgroupRoot(mode)
	if err != nil {
		return nil, err
	}

	path := filepath.Join(root, "lightpod", id)
	if spec.Linux != nil && spec.Linux.CgroupsPath != "" {
		// Like runc: an absolute cgroupsPath is relative to the cgroup root,
		// not the filesystem root.
		custom := spec.Linux.CgroupsPath
		if strings.Contains(custom, ":") {
			// systemd's "slice:prefix:name". We're daemonless and don't talk to
			// systemd, so flatten it into a directory name.
			parts := strings.Split(custom, ":")
			custom = strings.Join(parts, "-")
		}
		path = filepath.Join(root, strings.TrimPrefix(custom, "/"))
	}

	// Controllers have to be delegated down each level, so enable them on every
	// ancestor we create.
	if err := enableControllers(root, path); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, fmt.Errorf("creating cgroup %s: %w", path, err)
	}

	// Check the needed controllers actually made it here. Finding out at write
	// time gives a bare "permission denied" on a file path, which says nothing
	// about the real cause.
	if spec.Linux != nil {
		if err := checkControllers(mountpoint, path, spec.Linux.Resources); err != nil {
			_ = os.Remove(path)
			return nil, err
		}
	}

	return &CgroupManager{Path: path}, nil
}

// checkControllers: can this cgroup actually enforce what the spec asks for.
func checkControllers(mountpoint, path string, r *oci.LinuxResources) error {
	if r == nil {
		return nil
	}

	needed := map[string]bool{}
	if r.Memory != nil {
		needed["memory"] = true
	}
	if r.CPU != nil {
		needed["cpu"] = true
	}
	if r.Pids != nil {
		needed["pids"] = true
	}
	if len(needed) == 0 {
		return nil
	}

	data, err := os.ReadFile(filepath.Join(path, "cgroup.controllers"))
	if err != nil {
		return fmt.Errorf("reading controllers available at %s: %w", path, err)
	}
	available := map[string]bool{}
	for _, c := range strings.Fields(string(data)) {
		available[c] = true
	}

	var missing []string
	for c := range needed {
		if !available[c] {
			missing = append(missing, c)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)

	// Two very different causes, and pointing at the wrong one sends people
	// down the wrong path. If the v2 root has no controllers at all the system
	// is running them on v1 and no amount of delegation will help.
	hint := errNoCgroupDelegation
	if rootHasNoControllers(mountpoint) {
		hint = errCgroupV2NotInUse
	}

	return fmt.Errorf("the %s cgroup v2 controller(s) are not available at %s, "+
		"so the requested limits cannot be enforced.\n%w",
		strings.Join(missing, ", "), path, hint)
}

// cgroupRoot returns the v2 mount point and the directory we may create groups
// under. Rootfull can use the root itself; rootless only a delegated subtree.
func cgroupRoot(mode PrivilegeMode) (mountpoint, root string, err error) {
	mountpoint, err = cgroup2Mountpoint()
	if err != nil {
		return "", "", err
	}
	if mode == ModeRootfull {
		return mountpoint, mountpoint, nil
	}
	root, err = delegatedRoot(mountpoint)
	return mountpoint, root, err
}

// rootHasNoControllers reports a hybrid system: v2 is mounted but every
// controller is still on v1, so there is nothing to enable anywhere.
func rootHasNoControllers(mountpoint string) bool {
	data, err := os.ReadFile(filepath.Join(mountpoint, "cgroup.controllers"))
	if err != nil {
		return false
	}
	return len(strings.Fields(string(data))) == 0
}

// cgroup2Mountpoint finds the unified hierarchy in the mount table.
//
// Discovered, not assumed to be /sys/fs/cgroup. On a hybrid system — still the
// default on plenty of distributions — that path is a tmpfs holding the v1
// controllers and v2 lives under /sys/fs/cgroup/unified.
func cgroup2Mountpoint() (string, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return "", fmt.Errorf("reading mount table: %w", err)
	}
	defer f.Close()
	return parseCgroup2Mountpoint(f)
}

// parseCgroup2Mountpoint scans mountinfo lines. Split out so it can be tested
// against both layouts without needing a machine of each kind.
func parseCgroup2Mountpoint(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		// Field count before " - " varies; fstype is the first one after it.
		sep := strings.Index(line, " - ")
		if sep < 0 {
			continue
		}
		pre := strings.Fields(line[:sep])
		post := strings.Fields(line[sep+3:])
		if len(pre) < 5 || len(post) < 1 {
			continue
		}
		if post[0] == "cgroup2" {
			return pre[4], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scanning mount table: %w", err)
	}
	return "", fmt.Errorf("no cgroup2 filesystem is mounted; lightpod requires cgroup v2 " +
		"(boot with systemd.unified_cgroup_hierarchy=1, or use --cgroup=none)")
}

// delegatedRoot finds the highest cgroup dir this user can write to.
//
// systemd puts the session in a scope under a delegated user@<uid>.service, so
// walk up until write access stops — that boundary is the delegated root.
func delegatedRoot(mountpoint string) (string, error) {
	own, err := ownCgroupPath()
	if err != nil {
		return "", err
	}

	current := filepath.Join(mountpoint, strings.TrimPrefix(own, "/"))
	best := ""
	for {
		if syscall.Access(current, 0o002) == nil {
			best = current
		}
		parent := filepath.Dir(current)
		if parent == current || !strings.HasPrefix(parent, mountpoint) {
			break
		}
		current = parent
	}
	if best == "" {
		return "", errNoCgroupDelegation
	}
	return best, nil
}

// ownCgroupPath is the "0::" line of /proc/self/cgroup.
func ownCgroupPath() (string, error) {
	f, err := os.Open("/proc/self/cgroup")
	if err != nil {
		return "", fmt.Errorf("reading own cgroup: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if rest, ok := strings.CutPrefix(scanner.Text(), "0::"); ok {
			return rest, nil
		}
	}
	return "", fmt.Errorf("this process is not in a cgroup v2 hierarchy")
}

// enableControllers writes subtree_control at every level between root and leaf.
// A controller only reaches a child if the parent delegated it, so skipping a
// level silently drops the limits.
func enableControllers(root, leaf string) error {
	available, err := os.ReadFile(filepath.Join(root, "cgroup.controllers"))
	if err != nil {
		return fmt.Errorf("reading available cgroup controllers: %w", err)
	}

	var wanted []string
	for _, c := range strings.Fields(string(available)) {
		switch c {
		case "memory", "pids", "cpu", "cpuset", "io":
			wanted = append(wanted, "+"+c)
		}
	}
	if len(wanted) == 0 {
		return nil
	}
	enable := strings.Join(wanted, " ")

	rel, err := filepath.Rel(root, filepath.Dir(leaf))
	if err != nil {
		return fmt.Errorf("resolving cgroup path: %w", err)
	}

	dir := root
	for _, part := range append([]string{"."}, strings.Split(rel, string(filepath.Separator))...) {
		if part != "." {
			dir = filepath.Join(dir, part)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("creating cgroup %s: %w", dir, err)
			}
		}
		// Not fatal on its own — some controllers can't be enabled while the
		// cgroup holds processes directly. checkControllers catches what matters.
		_ = os.WriteFile(filepath.Join(dir, "cgroup.subtree_control"), []byte(enable), 0o644)
	}
	return nil
}

// Apply moves a process into the cgroup. Has to happen before the workload
// starts so limits cover it from the first allocation.
func (m *CgroupManager) Apply(pid int) error {
	if m.disabled {
		return nil
	}
	path := filepath.Join(m.Path, "cgroup.procs")
	if err := os.WriteFile(path, []byte(strconv.Itoa(pid)), 0o644); err != nil {
		return fmt.Errorf("adding pid %d to cgroup %s: %w", pid, m.Path, err)
	}
	return nil
}

// SetResources writes the limits from the spec.
func (m *CgroupManager) SetResources(r *oci.LinuxResources) error {
	if m.disabled || r == nil {
		return nil
	}

	if r.Memory != nil {
		if r.Memory.Limit != nil {
			if err := m.write("memory.max", formatLimit(*r.Memory.Limit)); err != nil {
				return err
			}
		}
		if r.Memory.Reservation != nil {
			if err := m.write("memory.low", formatLimit(*r.Memory.Reservation)); err != nil {
				return err
			}
		}
		if r.Memory.Swap != nil && r.Memory.Limit != nil {
			// v1 counted memory+swap together, v2 counts swap on its own, so
			// subtract memory back out of the spec's combined value.
			swap := *r.Memory.Swap - *r.Memory.Limit
			if *r.Memory.Swap <= 0 {
				swap = *r.Memory.Swap
			}
			if err := m.write("memory.swap.max", formatLimit(swap)); err != nil {
				return err
			}
		}
	}

	if r.CPU != nil {
		if r.CPU.Quota != nil {
			period := uint64(100000)
			if r.CPU.Period != nil && *r.CPU.Period > 0 {
				period = *r.CPU.Period
			}
			quota := "max"
			if *r.CPU.Quota > 0 {
				quota = strconv.FormatInt(*r.CPU.Quota, 10)
			}
			if err := m.write("cpu.max", fmt.Sprintf("%s %d", quota, period)); err != nil {
				return err
			}
		}
		if r.CPU.Shares != nil && *r.CPU.Shares > 0 {
			if err := m.write("cpu.weight", strconv.FormatUint(sharesToWeight(*r.CPU.Shares), 10)); err != nil {
				return err
			}
		}
		if r.CPU.Cpus != "" {
			if err := m.write("cpuset.cpus", r.CPU.Cpus); err != nil {
				return err
			}
		}
		if r.CPU.Mems != "" {
			if err := m.write("cpuset.mems", r.CPU.Mems); err != nil {
				return err
			}
		}
	}

	if r.Pids != nil {
		if err := m.write("pids.max", formatLimit(r.Pids.Limit)); err != nil {
			return err
		}
	}

	return nil
}

func (m *CgroupManager) write(file, value string) error {
	path := filepath.Join(m.Path, file)
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("cgroup controller for %s is not available at %s. "+
				"The controller may not be delegated to this user; see --cgroup=none to opt out of limits",
				file, m.Path)
		}
		return fmt.Errorf("writing %s=%s: %w", path, value, err)
	}
	return nil
}

// formatLimit: cgroup v2 spells unlimited "max".
func formatLimit(v int64) string {
	if v <= 0 {
		return "max"
	}
	return strconv.FormatInt(v, 10)
}

// sharesToWeight maps v1 cpu.shares (2-262144) onto v2 cpu.weight (1-10000).
// The spec is still written in v1 terms.
func sharesToWeight(shares uint64) uint64 {
	if shares == 0 {
		return 100
	}
	weight := 1 + ((shares-2)*9999)/262142
	if weight < 1 {
		return 1
	}
	if weight > 10000 {
		return 10000
	}
	return weight
}

// Cleanup removes the cgroup. Failure is reported but not fatal — a leftover
// empty directory costs nothing and shouldn't fail an otherwise clean teardown.
func (m *CgroupManager) Cleanup() error {
	if m.disabled || m.Path == "" {
		return nil
	}
	if err := os.Remove(m.Path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing cgroup %s: %w", m.Path, err)
	}
	return nil
}
