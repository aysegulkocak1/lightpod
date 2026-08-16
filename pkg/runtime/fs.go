package runtime

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/aysegulkocak1/lightpod/pkg/device"
	"github.com/aysegulkocak1/lightpod/pkg/oci"
)

// Mount options to MS_* flags. Some options clear rather than set ("rw" clears
// MS_RDONLY).
var mountFlagNames = map[string]struct {
	clear bool
	flag  uintptr
}{
	"ro":            {false, syscall.MS_RDONLY},
	"rw":            {true, syscall.MS_RDONLY},
	"suid":          {true, syscall.MS_NOSUID},
	"nosuid":        {false, syscall.MS_NOSUID},
	"dev":           {true, syscall.MS_NODEV},
	"nodev":         {false, syscall.MS_NODEV},
	"exec":          {true, syscall.MS_NOEXEC},
	"noexec":        {false, syscall.MS_NOEXEC},
	"sync":          {false, syscall.MS_SYNCHRONOUS},
	"async":         {true, syscall.MS_SYNCHRONOUS},
	"dirsync":       {false, syscall.MS_DIRSYNC},
	"remount":       {false, syscall.MS_REMOUNT},
	"mand":          {false, syscall.MS_MANDLOCK},
	"nomand":        {true, syscall.MS_MANDLOCK},
	"atime":         {true, syscall.MS_NOATIME},
	"noatime":       {false, syscall.MS_NOATIME},
	"diratime":      {true, syscall.MS_NODIRATIME},
	"nodiratime":    {false, syscall.MS_NODIRATIME},
	"bind":          {false, syscall.MS_BIND},
	"rbind":         {false, syscall.MS_BIND | syscall.MS_REC},
	"relatime":      {false, syscall.MS_RELATIME},
	"norelatime":    {true, syscall.MS_RELATIME},
	"strictatime":   {false, syscall.MS_STRICTATIME},
	"nostrictatime": {true, syscall.MS_STRICTATIME},
}

// Applied in a second mount call — the kernel won't change propagation and
// mount in one go.
var propagationFlags = map[string]uintptr{
	"private":     syscall.MS_PRIVATE,
	"rprivate":    syscall.MS_PRIVATE | syscall.MS_REC,
	"slave":       syscall.MS_SLAVE,
	"rslave":      syscall.MS_SLAVE | syscall.MS_REC,
	"shared":      syscall.MS_SHARED,
	"rshared":     syscall.MS_SHARED | syscall.MS_REC,
	"unbindable":  syscall.MS_UNBINDABLE,
	"runbindable": syscall.MS_UNBINDABLE | syscall.MS_REC,
}

// parseMountOptions splits options into flags, propagation and the fs data string.
func parseMountOptions(options []string) (flags, propagation uintptr, data string) {
	var dataOpts []string
	for _, opt := range options {
		if entry, ok := mountFlagNames[opt]; ok {
			if entry.clear {
				flags &^= entry.flag
			} else {
				flags |= entry.flag
			}
			continue
		}
		if p, ok := propagationFlags[opt]; ok {
			propagation |= p
			continue
		}
		dataOpts = append(dataOpts, opt)
	}
	return flags, propagation, strings.Join(dataOpts, ",")
}

// prepareRootfs does every mount but stops short of pivot_root.
//
// Split that way because createRuntime and createContainer hooks run in
// between: it's the only window where a host-side tool can still reach the
// container's future root at its host path while writing into the container's
// mount namespace. The NVIDIA toolkit injects driver libraries exactly there.
func prepareRootfs(cfg *initConfig) error {
	rootfs := cfg.Rootfs

	// Private first. Anything mounted before this propagates back to the host,
	// and a container mounting over a host path is a straight escape.
	propagation := uintptr(syscall.MS_PRIVATE | syscall.MS_REC)
	if cfg.Spec.Linux != nil && cfg.Spec.Linux.RootfsPropagation != "" {
		if p, ok := propagationFlags[cfg.Spec.Linux.RootfsPropagation]; ok {
			propagation = p
		}
	}
	if err := syscall.Mount("", "/", "", propagation, ""); err != nil {
		return fmt.Errorf("making mount namespace private: %w", err)
	}

	// pivot_root needs the new root to be a mount point; binding it onto itself
	// is the usual way to turn a plain directory into one.
	if err := syscall.Mount(rootfs, rootfs, "bind", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("bind mounting rootfs %s onto itself: %w", rootfs, err)
	}

	for _, m := range cfg.Spec.Mounts {
		if err := mountOne(rootfs, m); err != nil {
			return err
		}
	}

	if err := createDevices(cfg); err != nil {
		return err
	}
	if err := createDevSymlinks(rootfs); err != nil {
		return err
	}

	if cfg.Spec.Linux != nil {
		if err := maskPaths(rootfs, cfg.Spec.Linux.MaskedPaths); err != nil {
			return err
		}
		if err := readonlyPaths(rootfs, cfg.Spec.Linux.ReadonlyPaths); err != nil {
			return err
		}
	}
	return nil
}

// mountOne performs a single spec mount inside the rootfs.
func mountOne(rootfs string, m oci.Mount) error {
	target, err := secureJoin(rootfs, m.Destination)
	if err != nil {
		return fmt.Errorf("resolving mount destination %s: %w", m.Destination, err)
	}

	flags, propagation, data := parseMountOptions(m.Options)

	// Bind target has to match the source's kind — file source, file target.
	if flags&syscall.MS_BIND != 0 {
		fi, err := os.Stat(m.Source)
		if err != nil {
			return fmt.Errorf("bind mount source %s: %w", m.Source, err)
		}
		if fi.IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("creating bind target %s: %w", target, err)
			}
		} else {
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("creating bind target directory for %s: %w", target, err)
			}
			f, err := os.OpenFile(target, os.O_CREATE, 0o644)
			if err != nil && !os.IsExist(err) {
				return fmt.Errorf("creating bind target file %s: %w", target, err)
			}
			if f != nil {
				f.Close()
			}
		}
	} else if err := os.MkdirAll(target, 0o755); err != nil {
		return fmt.Errorf("creating mount point %s: %w", target, err)
	}

	source := m.Source
	if source == "" {
		source = m.Type
	}
	fstype := m.Type
	if flags&syscall.MS_BIND != 0 {
		// Ignored for binds anyway, and specs like to put "none" or "bind" here.
		fstype = ""
	}

	if err := syscall.Mount(source, target, fstype, flags, data); err != nil {
		return fmt.Errorf("mounting %s (%s) at %s: %w", source, m.Type, m.Destination, err)
	}

	// Read-only binds take two calls. Passing both flags at once silently gives
	// you a writable mount.
	if flags&syscall.MS_BIND != 0 && flags&syscall.MS_RDONLY != 0 {
		remount := flags | syscall.MS_REMOUNT
		if err := syscall.Mount("", target, "", remount, ""); err != nil {
			return fmt.Errorf("remounting %s read-only: %w", m.Destination, err)
		}
	}

	if propagation != 0 {
		if err := syscall.Mount("", target, "", propagation, ""); err != nil {
			return fmt.Errorf("setting propagation on %s: %w", m.Destination, err)
		}
	}
	return nil
}

// createDevices makes the container's device nodes.
//
// Rootfull uses mknod. Rootless can't — the kernel forbids it in a user
// namespace — so we bind the host's node instead. Not a weaker sandbox: the
// container still only sees what's listed here and still can't create more.
func createDevices(cfg *initConfig) error {
	devices := oci.DefaultDevices
	if cfg.Spec.Linux != nil {
		devices = append(devices, cfg.Spec.Linux.Devices...)
	}

	for _, dev := range devices {
		target, err := secureJoin(cfg.Rootfs, dev.Path)
		if err != nil {
			return fmt.Errorf("resolving device path %s: %w", dev.Path, err)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("creating directory for device %s: %w", dev.Path, err)
		}

		if cfg.Mode.SupportsDeviceNodes() {
			if err := mknodDevice(target, dev); err != nil {
				return err
			}
			continue
		}

		if err := bindDevice(target, dev); err != nil {
			return err
		}
	}
	return nil
}

func mknodDevice(target string, dev oci.LinuxDevice) error {
	var mode uint32
	switch dev.Type {
	case "c", "u":
		mode = syscall.S_IFCHR
	case "b":
		mode = syscall.S_IFBLK
	case "p":
		mode = syscall.S_IFIFO
	default:
		return fmt.Errorf("device %s has unknown type %q", dev.Path, dev.Type)
	}
	perm := uint32(0o666)
	if dev.FileMode != nil {
		perm = *dev.FileMode
	}
	mode |= perm & 0o7777

	if err := syscall.Mknod(target, mode, int(device.Mkdev(dev.Major, dev.Minor))); err != nil {
		if os.IsExist(err) {
			return nil
		}
		return fmt.Errorf("creating device node %s: %w", dev.Path, err)
	}

	uid, gid := 0, 0
	if dev.UID != nil {
		uid = int(*dev.UID)
	}
	if dev.GID != nil {
		gid = int(*dev.GID)
	}
	if err := os.Chown(target, uid, gid); err != nil {
		return fmt.Errorf("setting owner on device %s: %w", dev.Path, err)
	}
	return nil
}

func bindDevice(target string, dev oci.LinuxDevice) error {
	if _, err := os.Stat(dev.Path); err != nil {
		// Host doesn't have it, so we can't offer it. /dev/tty is often missing
		// in a non-interactive session and refusing to start would break every
		// headless service.
		return nil
	}
	f, err := os.OpenFile(target, os.O_CREATE, 0o644)
	if err != nil && !os.IsExist(err) {
		return fmt.Errorf("creating bind target for device %s: %w", dev.Path, err)
	}
	if f != nil {
		f.Close()
	}
	if err := syscall.Mount(dev.Path, target, "", syscall.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind mounting device %s: %w", dev.Path, err)
	}
	return nil
}

// Links POSIX software expects under /dev.
var devSymlinks = map[string]string{
	"/proc/self/fd":   "/dev/fd",
	"/proc/self/fd/0": "/dev/stdin",
	"/proc/self/fd/1": "/dev/stdout",
	"/proc/self/fd/2": "/dev/stderr",
	"/dev/pts/ptmx":   "/dev/ptmx",
}

func createDevSymlinks(rootfs string) error {
	for oldname, newname := range devSymlinks {
		target, err := secureJoin(rootfs, newname)
		if err != nil {
			return fmt.Errorf("resolving %s: %w", newname, err)
		}
		if err := os.Symlink(oldname, target); err != nil && !os.IsExist(err) {
			return fmt.Errorf("linking %s -> %s: %w", newname, oldname, err)
		}
	}
	return nil
}

// maskPaths covers a path so the container can't read it. Directories get an
// empty read-only tmpfs, files get /dev/null — software probing the path sees
// something harmless instead of tripping over a missing one.
func maskPaths(rootfs string, paths []string) error {
	for _, p := range paths {
		target, err := secureJoin(rootfs, p)
		if err != nil {
			return fmt.Errorf("resolving masked path %s: %w", p, err)
		}
		fi, err := os.Stat(target)
		if err != nil {
			continue // nothing there to leak
		}
		if fi.IsDir() {
			if err := syscall.Mount("tmpfs", target, "tmpfs", syscall.MS_RDONLY, "size=0k"); err != nil {
				return fmt.Errorf("masking directory %s: %w", p, err)
			}
			continue
		}
		if err := syscall.Mount("/dev/null", target, "", syscall.MS_BIND, ""); err != nil {
			return fmt.Errorf("masking file %s: %w", p, err)
		}
	}
	return nil
}

// readonlyPaths remounts a path read-only but still readable.
func readonlyPaths(rootfs string, paths []string) error {
	for _, p := range paths {
		target, err := secureJoin(rootfs, p)
		if err != nil {
			return fmt.Errorf("resolving read-only path %s: %w", p, err)
		}
		if _, err := os.Stat(target); err != nil {
			continue
		}
		if err := syscall.Mount(target, target, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
			return fmt.Errorf("binding %s for read-only remount: %w", p, err)
		}
		flags := uintptr(syscall.MS_BIND | syscall.MS_REMOUNT | syscall.MS_RDONLY | syscall.MS_REC)
		if err := syscall.Mount(target, target, "", flags, ""); err != nil {
			return fmt.Errorf("remounting %s read-only: %w", p, err)
		}
	}
	return nil
}

// finalizeRootfs pivots in and applies the final read-only remount. Up to here
// the host filesystem is still reachable; after it, it's gone.
func finalizeRootfs(cfg *initConfig) error {
	if err := pivotRoot(cfg.Rootfs); err != nil {
		return fmt.Errorf("pivoting into %s: %w", cfg.Rootfs, err)
	}

	if cfg.Spec.Root != nil && cfg.Spec.Root.Readonly {
		flags := uintptr(syscall.MS_BIND | syscall.MS_REMOUNT | syscall.MS_RDONLY | syscall.MS_REC)
		if err := syscall.Mount("", "/", "", flags, ""); err != nil {
			return fmt.Errorf("remounting container root read-only: %w", err)
		}
	}

	cwd := "/"
	if cfg.Spec.Process != nil && cfg.Spec.Process.Cwd != "" {
		cwd = cfg.Spec.Process.Cwd
	}
	if err := os.Chdir(cwd); err != nil {
		return fmt.Errorf("changing to working directory %s: %w", cwd, err)
	}
	return nil
}

// pivotRoot swaps the root filesystem.
//
// Not chroot: chroot is escapable by anything holding an fd to a directory
// outside the new root. After the pivot the old root is detached completely.
func pivotRoot(newroot string) error {
	oldroot := filepath.Join(newroot, ".oldroot")
	if err := os.MkdirAll(oldroot, 0o700); err != nil {
		return fmt.Errorf("creating old root mount point: %w", err)
	}

	if err := syscall.PivotRoot(newroot, oldroot); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("chdir to new root: %w", err)
	}

	// MNT_DETACH, not a plain unmount — the old root's submounts are still busy
	// right now, and the lazy detach takes the whole subtree anyway.
	if err := syscall.Unmount("/.oldroot", syscall.MNT_DETACH); err != nil {
		return fmt.Errorf("detaching old root: %w", err)
	}
	if err := os.Remove("/.oldroot"); err != nil {
		return fmt.Errorf("removing old root mount point: %w", err)
	}
	return nil
}

// secureJoin resolves a container path against the rootfs and refuses anything
// that escapes.
//
// Symlinks resolve relative to the rootfs, not the host, so an image shipping
// "/etc -> ../../../../etc" can't trick us into mounting over a host file.
func secureJoin(rootfs, unsafePath string) (string, error) {
	const maxSymlinkDepth = 32

	current := rootfs
	remaining := filepath.Clean("/" + unsafePath)

	for depth := 0; remaining != "" && remaining != "/"; depth++ {
		if depth > maxSymlinkDepth {
			return "", fmt.Errorf("too many symbolic links resolving %q", unsafePath)
		}

		remaining = strings.TrimPrefix(remaining, "/")
		part, rest, _ := strings.Cut(remaining, "/")
		remaining = rest

		switch part {
		case "", ".":
			continue
		case "..":
			// Climbing past the root lands back on it, same as it would for a
			// process already inside.
			if current != rootfs {
				current = filepath.Dir(current)
			}
			continue
		}

		next := filepath.Join(current, part)
		fi, err := os.Lstat(next)
		if err != nil {
			// Doesn't exist yet — a mount point about to be created. Nothing
			// left to resolve, so the rest is safe to append.
			return filepath.Join(next, remaining), nil
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			current = next
			continue
		}

		link, err := os.Readlink(next)
		if err != nil {
			return "", fmt.Errorf("reading symlink %s: %w", next, err)
		}
		if filepath.IsAbs(link) {
			current = rootfs
			remaining = filepath.Join(link, remaining)
		} else {
			remaining = filepath.Join(link, remaining)
		}
		remaining = "/" + strings.TrimPrefix(remaining, "/")
	}

	if !strings.HasPrefix(current, rootfs) {
		return "", fmt.Errorf("path %q escapes the container root", unsafePath)
	}
	return current, nil
}
