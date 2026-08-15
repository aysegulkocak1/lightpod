package runtime

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"github.com/aysegulkocak1/lightpod/pkg/oci"
)

// cloneFlags turns the spec's namespace list into clone(2) flags. Ones with a
// Path get joined via setns after the clone, so they add no flag here.
func cloneFlags(spec *oci.Spec) (uintptr, error) {
	if spec.Linux == nil {
		return 0, nil
	}

	var flags uintptr
	for _, ns := range spec.Linux.Namespaces {
		if ns.Path != "" {
			continue
		}
		switch ns.Type {
		case oci.UTSNamespace:
			flags |= syscall.CLONE_NEWUTS
		case oci.IPCNamespace:
			flags |= syscall.CLONE_NEWIPC
		case oci.NetworkNamespace:
			flags |= syscall.CLONE_NEWNET
		case oci.PIDNamespace:
			flags |= syscall.CLONE_NEWPID
		case oci.MountNamespace:
			flags |= syscall.CLONE_NEWNS
		case oci.UserNamespace:
			flags |= syscall.CLONE_NEWUSER
		case oci.CgroupNamespace:
			flags |= syscall.CLONE_NEWCGROUP
		case oci.TimeNamespace:
			// Can't enter a time namespace you created with clone; needs a
			// different mechanism.
			return 0, fmt.Errorf("time namespaces are not supported yet")
		default:
			return 0, fmt.Errorf("unknown namespace type %q", ns.Type)
		}
	}
	return flags, nil
}

// idMappings returns the uid/gid mappings to install.
//
// An explicit mapping in the spec wins. Otherwise rootless gets the usual
// layout: container root maps to the invoking user, the rest into that user's
// /etc/subuid range so images with non-root users still work.
func idMappings(spec *oci.Spec, mode PrivilegeMode) (uids, gids []oci.LinuxIDMapping) {
	if spec.Linux != nil && len(spec.Linux.UIDMappings) > 0 {
		return spec.Linux.UIDMappings, spec.Linux.GIDMappings
	}
	if mode == ModeRootfull {
		// Usually no user namespace here; if you want one, declare the mapping.
		return nil, nil
	}

	hostUID := uint32(os.Getuid())
	hostGID := uint32(os.Getgid())

	uids = []oci.LinuxIDMapping{{ContainerID: 0, HostID: hostUID, Size: 1}}
	gids = []oci.LinuxIDMapping{{ContainerID: 0, HostID: hostGID, Size: 1}}

	// Missing subuid range isn't fatal — the container runs, it just can't
	// represent users other than root.
	if start, count, err := subIDRange("/etc/subuid", hostUID); err == nil && count > 0 {
		uids = append(uids, oci.LinuxIDMapping{ContainerID: 1, HostID: start, Size: count})
	}
	if start, count, err := subIDRange("/etc/subgid", hostGID); err == nil && count > 0 {
		gids = append(gids, oci.LinuxIDMapping{ContainerID: 1, HostID: start, Size: count})
	}
	return uids, gids
}

// subIDRange reads the subordinate id range for an id. Entries are keyed by
// username or number depending on who wrote the file, so accept both.
func subIDRange(path string, id uint32) (start, count uint32, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	names := []string{strconv.FormatUint(uint64(id), 10)}
	if u, err := user.LookupId(names[0]); err == nil {
		names = append(names, u.Username)
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(strings.TrimSpace(scanner.Text()), ":")
		if len(fields) != 3 {
			continue
		}
		if !contains(names, fields[0]) {
			continue
		}
		s, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			continue
		}
		c, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			continue
		}
		return uint32(s), uint32(c), nil
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, fmt.Errorf("reading %s: %w", path, err)
	}
	return 0, 0, fmt.Errorf("no subordinate id range for %d in %s", id, path)
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// writeIDMaps installs the mappings for a child.
//
// A single entry onto our own id we can write ourselves. Anything wider needs
// the setuid newuidmap/newgidmap helpers — handing out an id range is
// privileged and only /etc/subuid can authorise it.
func writeIDMaps(pid int, uids, gids []oci.LinuxIDMapping, mode PrivilegeMode) error {
	if len(uids) == 0 && len(gids) == 0 {
		return nil
	}

	selfMapped := isSelfMapping(uids, uint32(os.Getuid())) && isSelfMapping(gids, uint32(os.Getgid()))
	if mode == ModeRootfull || selfMapped {
		// Has to be denied before gid_map or the kernel rejects the write. Also
		// closes the old trick of using a user namespace to drop a group that
		// granted negative permissions on a host file.
		if err := os.WriteFile(fmt.Sprintf("/proc/%d/setgroups", pid), []byte("deny"), 0o644); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("denying setgroups for pid %d: %w", pid, err)
		}
		if err := writeMapFile(fmt.Sprintf("/proc/%d/uid_map", pid), uids); err != nil {
			return err
		}
		return writeMapFile(fmt.Sprintf("/proc/%d/gid_map", pid), gids)
	}

	if err := runIDMapHelper("newuidmap", pid, uids); err != nil {
		return err
	}
	return runIDMapHelper("newgidmap", pid, gids)
}

// isSelfMapping: the trivial "container root is me" case, no helper needed.
func isSelfMapping(mappings []oci.LinuxIDMapping, self uint32) bool {
	return len(mappings) == 1 && mappings[0].Size == 1 && mappings[0].HostID == self
}

func writeMapFile(path string, mappings []oci.LinuxIDMapping) error {
	if len(mappings) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for _, m := range mappings {
		fmt.Fprintf(&buf, "%d %d %d\n", m.ContainerID, m.HostID, m.Size)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// runIDMapHelper shells out to newuidmap/newgidmap for multi-range mappings.
func runIDMapHelper(tool string, pid int, mappings []oci.LinuxIDMapping) error {
	if len(mappings) == 0 {
		return nil
	}

	args := []string{strconv.Itoa(pid)}
	for _, m := range mappings {
		args = append(args,
			strconv.FormatUint(uint64(m.ContainerID), 10),
			strconv.FormatUint(uint64(m.HostID), 10),
			strconv.FormatUint(uint64(m.Size), 10),
		)
	}

	cmd := exec.Command(tool, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w (stderr: %s). Rootless containers need "+
			"the uidmap package installed and an /etc/subuid entry for this user",
			tool, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// joinNamespaces enters namespaces the spec references by path. This is what
// makes pods work — a second container joins the first's net and ipc namespaces.
func joinNamespaces(spec *oci.Spec) error {
	if spec.Linux == nil {
		return nil
	}
	for _, ns := range spec.Linux.Namespaces {
		if ns.Path == "" {
			continue
		}
		f, err := os.Open(ns.Path)
		if err != nil {
			return fmt.Errorf("opening namespace %s: %w", ns.Path, err)
		}
		_, _, errno := syscall.RawSyscall(sysSetns, f.Fd(), 0, 0)
		f.Close()
		if errno != 0 {
			return fmt.Errorf("joining %s namespace at %s: %w", ns.Type, ns.Path, errno)
		}
	}
	return nil
}
