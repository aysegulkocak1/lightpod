package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/aysegulkocak1/lightpod/pkg/device"
	"github.com/aysegulkocak1/lightpod/pkg/oci"
)

// applyProcessFlags folds --env, --user, --workdir and --cap-add into the spec.
func applyProcessFlags(spec *oci.Spec, rf *runFlags) error {
	if spec.Process == nil {
		return fmt.Errorf("spec has no process section")
	}

	spec.Process.Env = append(spec.Process.Env, rf.env...)

	if rf.workdir != "" {
		if !strings.HasPrefix(rf.workdir, "/") {
			return fmt.Errorf("--workdir %q must be an absolute path", rf.workdir)
		}
		spec.Process.Cwd = rf.workdir
	}

	if rf.user != "" {
		uidPart, gidPart, hasGID := strings.Cut(rf.user, ":")
		uid, err := strconv.ParseUint(uidPart, 10, 32)
		if err != nil {
			return fmt.Errorf("--user %q: uid must be numeric (name lookup needs the image's /etc/passwd, which is not read yet)", rf.user)
		}
		spec.Process.User.UID = uint32(uid)
		spec.Process.User.GID = uint32(uid)
		if hasGID {
			gid, err := strconv.ParseUint(gidPart, 10, 32)
			if err != nil {
				return fmt.Errorf("--user %q: gid must be numeric", rf.user)
			}
			spec.Process.User.GID = uint32(gid)
		}
	}

	for _, name := range rf.addCaps {
		name = strings.ToUpper(name)
		if !strings.HasPrefix(name, "CAP_") {
			name = "CAP_" + name
		}
		if spec.Process.Capabilities == nil {
			spec.Process.Capabilities = &oci.LinuxCapabilities{}
		}
		caps := spec.Process.Capabilities
		// Bounding as well as the live sets: without it the kernel would cap
		// the capability straight back off.
		caps.Bounding = appendUnique(caps.Bounding, name)
		caps.Effective = appendUnique(caps.Effective, name)
		caps.Permitted = appendUnique(caps.Permitted, name)
	}

	return nil
}

func appendUnique(list []string, value string) []string {
	for _, existing := range list {
		if existing == value {
			return list
		}
	}
	return append(list, value)
}

// applyMountFlags folds -v, --shm-size and --ipc into the spec.
func applyMountFlags(spec *oci.Spec, rf *runFlags) error {
	for _, v := range rf.volumes {
		mount, err := parseVolume(v)
		if err != nil {
			return err
		}
		spec.Mounts = append(spec.Mounts, mount)
	}

	if rf.shmSize != "" {
		size, err := parseSize(rf.shmSize)
		if err != nil {
			return fmt.Errorf("--shm-size: %w", err)
		}
		if err := resizeShm(spec, size); err != nil {
			return err
		}
	}

	switch rf.ipc {
	case "":
	case "host":
		// Joining the host IPC namespace is what lets DDS shared-memory
		// transport work between the host and the container. It is a real
		// reduction in isolation — System V IPC and POSIX message queues become
		// shared — so it stays opt-in and noisy.
		fmt.Fprintln(os.Stderr, "lightpod: WARNING: --ipc host shares the host IPC namespace; container and host can see each other's shared memory")
		if spec.Linux == nil {
			spec.Linux = &oci.Linux{}
		}
		if err := setNamespacePath(spec, oci.IPCNamespace, "/proc/1/ns/ipc"); err != nil {
			return err
		}
	default:
		return fmt.Errorf("--ipc %q is not supported (only \"host\")", rf.ipc)
	}

	return nil
}

// parseVolume turns host:container[:ro|rw] into a bind mount.
func parseVolume(value string) (oci.Mount, error) {
	parts := strings.Split(value, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return oci.Mount{}, fmt.Errorf("volume %q must be host:container[:ro]", value)
	}

	host, container := parts[0], parts[1]
	if !strings.HasPrefix(host, "/") || !strings.HasPrefix(container, "/") {
		return oci.Mount{}, fmt.Errorf("volume %q: both paths must be absolute", value)
	}

	// nosuid and nodev on every volume: a data directory has no business
	// carrying setuid binaries or device nodes into the container, and mounting
	// one that does is a classic way to hand over host privileges.
	options := []string{"rbind", "nosuid", "nodev"}
	mode := "rw"
	if len(parts) == 3 {
		mode = parts[2]
	}
	switch mode {
	case "rw":
	case "ro":
		options = append(options, "ro")
	default:
		return oci.Mount{}, fmt.Errorf("volume %q: mode must be ro or rw, got %q", value, mode)
	}

	return oci.Mount{
		Destination: container,
		Source:      host,
		Type:        "none",
		Options:     options,
	}, nil
}

// resizeShm rewrites the size option on the /dev/shm mount.
//
// The 64MB default is fine for most things and far too small for ROS 2: Fast
// DDS puts its shared-memory segments there and runs out silently.
func resizeShm(spec *oci.Spec, size int64) error {
	for i := range spec.Mounts {
		if spec.Mounts[i].Destination != "/dev/shm" {
			continue
		}
		options := spec.Mounts[i].Options[:0]
		for _, opt := range spec.Mounts[i].Options {
			if !strings.HasPrefix(opt, "size=") {
				options = append(options, opt)
			}
		}
		spec.Mounts[i].Options = append(options, fmt.Sprintf("size=%d", size))
		return nil
	}
	return fmt.Errorf("--shm-size: this bundle has no /dev/shm mount to resize")
}

// setNamespacePath points a namespace at an existing one instead of creating it.
func setNamespacePath(spec *oci.Spec, kind oci.LinuxNamespaceType, path string) error {
	for i := range spec.Linux.Namespaces {
		if spec.Linux.Namespaces[i].Type == kind {
			spec.Linux.Namespaces[i].Path = path
			return nil
		}
	}
	spec.Linux.Namespaces = append(spec.Linux.Namespaces, oci.LinuxNamespace{Type: kind, Path: path})
	return nil
}

// applyDeviceFlags resolves --device values, which are either host paths or CDI
// names.
//
// CDI lookup is lazy: the registry is only read when a CDI name actually
// appears, so a machine with no /etc/cdi pays nothing.
func applyDeviceFlags(spec *oci.Spec, rf *runFlags) error {
	if len(rf.devices) == 0 {
		return nil
	}
	if spec.Linux == nil {
		spec.Linux = &oci.Linux{}
	}

	var registry *device.Registry
	for _, value := range rf.devices {
		if device.IsCDIName(value) {
			if registry == nil {
				var err error
				registry, err = device.LoadRegistry(device.DefaultSpecDirs)
				if err != nil {
					return err
				}
			}
			if err := registry.Inject(spec, value); err != nil {
				return err
			}
			continue
		}

		dev, err := device.ParseRawDevice(value)
		if err != nil {
			return err
		}
		spec.Linux.Devices = append(spec.Linux.Devices, dev)
	}
	return nil
}
