package runtime

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type Mount struct {
	Source  string
	Target  string
	Fstype  string
	Flags   uintptr
	Options string
}

// SetupRootfs prepares the isolated filesystem for the container process.
func SetupRootfs(rootfs string, mounts []Mount) error {
	if err := syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("failed to make / private: %w", err)
	}
	if err := syscall.Mount(rootfs, rootfs, "bind", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("failed to bind mount rootfs to itself: %w", err)
	}

	for _, m := range mounts {
		targetPath := filepath.Join(rootfs, m.Target)
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return fmt.Errorf("failed to create target dir %s: %w", targetPath, err)
		}

		if m.Flags&syscall.MS_BIND != 0 {
			os.MkdirAll(targetPath, 0755)
		}

		if err := syscall.Mount(m.Source, targetPath, m.Fstype, m.Flags, m.Options); err != nil {
			return fmt.Errorf("failed to mount %s to %s: %w", m.Source, m.Target, err)
		}
	}

	if err := pivotRoot(rootfs); err != nil {
		return fmt.Errorf("pivot_root failed: %w", err)
	}
	return mountVirtualFilesystems()
}

func pivotRoot(newroot string) error {
	putold := filepath.Join(newroot, ".oldroot")

	if err := os.MkdirAll(putold, 0700); err != nil {
		return fmt.Errorf("failed to create putold dir: %w", err)
	}
	if err := syscall.PivotRoot(newroot, putold); err != nil {
		return fmt.Errorf("syscall PivotRoot failed: %w", err)
	}

	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("chdir / failed: %w", err)
	}
	putoldInside := "/.oldroot"
	if err := syscall.Unmount(putoldInside, syscall.MNT_DETACH); err != nil {
		return fmt.Errorf("unmount putold failed: %w", err)
	}

	if err := os.Remove(putoldInside); err != nil {
		return fmt.Errorf("remove putold dir failed: %w", err)
	}

	return nil
}

// mountVirtualFilesystems mounts /proc, /sys, and a minimal /dev
func mountVirtualFilesystems() error {
	defaultMounts := []Mount{
		{Source: "proc", Target: "/proc", Fstype: "proc", Flags: syscall.MS_NOEXEC | syscall.MS_NOSUID | syscall.MS_NODEV, Options: ""},
		{Source: "sysfs", Target: "/sys", Fstype: "sysfs", Flags: syscall.MS_NOEXEC | syscall.MS_NOSUID | syscall.MS_NODEV, Options: ""},
		{Source: "tmpfs", Target: "/dev", Fstype: "tmpfs", Flags: syscall.MS_NOSUID | syscall.MS_STRICTATIME, Options: "mode=755,size=65536k"},
	}

	for _, m := range defaultMounts {
		if err := os.MkdirAll(m.Target, 0755); err != nil {
			return fmt.Errorf("failed to create %s: %w", m.Target, err)
		}
		if err := syscall.Mount(m.Source, m.Target, m.Fstype, m.Flags, m.Options); err != nil {
			return fmt.Errorf("failed to mount %s: %w", m.Target, err)
		}
	}

	return nil
}
