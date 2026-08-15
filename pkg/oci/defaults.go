package oci

import "github.com/aysegulkocak1/lightpod/pkg/version"

// DefaultCapabilities is what a container starts with: the usual container set
// minus NET_RAW (ARP/DNS spoofing on the host LAN), MKNOD (classic escape
// primitive) and AUDIT_WRITE (forged host audit records). Rarely needed on an
// edge device; ask for them in config.json if you really do.
var DefaultCapabilities = []string{
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_FOWNER",
	"CAP_FSETID",
	"CAP_KILL",
	"CAP_NET_BIND_SERVICE",
	"CAP_SETFCAP",
	"CAP_SETGID",
	"CAP_SETPCAP",
	"CAP_SETUID",
	"CAP_SYS_CHROOT",
}

// DefaultMaskedPaths get covered so the container can't read them. They leak
// host kernel memory or hardware detail.
var DefaultMaskedPaths = []string{
	"/proc/asound",
	"/proc/acpi",
	"/proc/interrupts",
	"/proc/kcore", // raw host physical memory
	"/proc/keys",
	"/proc/latency_stats",
	"/proc/timer_list",
	"/proc/timer_stats",
	"/proc/sched_debug",
	"/proc/scsi",
	"/sys/firmware", // host firmware / EFI variables
	"/sys/devices/virtual/powercap",
}

// DefaultReadonlyPaths stay readable — some tooling needs them — but writing to
// them reconfigures the host kernel.
var DefaultReadonlyPaths = []string{
	"/proc/bus",
	"/proc/fs",
	"/proc/irq",
	"/proc/sys",
	"/proc/sysrq-trigger", // writing here reboots or panics the host
}

// Default builds a spec with the secure defaults.
//
// Both `run --rootfs` and `spec` go through here. One generator, not two —
// separate default sets drift, and the one nobody updates becomes the weak one.
func Default(rootfs string, args []string, rootless bool) *Spec {
	namespaces := []LinuxNamespace{
		{Type: PIDNamespace},
		{Type: NetworkNamespace},
		{Type: IPCNamespace},
		{Type: UTSNamespace},
		{Type: MountNamespace},
		{Type: CgroupNamespace},
	}
	if rootless {
		// Mandatory, not optional: without it an unprivileged process can't
		// create any of the others.
		namespaces = append([]LinuxNamespace{{Type: UserNamespace}}, namespaces...)
	}

	spec := &Spec{
		Version:  version.OCIVersion,
		Hostname: "lightpod",
		Root: &Root{
			Path:     rootfs,
			Readonly: false,
		},
		Process: &Process{
			Terminal: false,
			User:     User{UID: 0, GID: 0},
			Args:     args,
			Env: []string{
				"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				"TERM=xterm",
			},
			Cwd: "/",
			Capabilities: &LinuxCapabilities{
				Bounding:  DefaultCapabilities,
				Effective: DefaultCapabilities,
				Permitted: DefaultCapabilities,
				// Inheritable and Ambient stay empty — ambient is the set that
				// survives execve.
			},
			NoNewPrivileges: true,
		},
		Mounts: DefaultMounts(rootless),
		Linux: &Linux{
			Namespaces:    namespaces,
			MaskedPaths:   DefaultMaskedPaths,
			ReadonlyPaths: DefaultReadonlyPaths,
			Resources: &LinuxResources{
				// Keeps a fork bomb inside the container.
				Pids: &LinuxPids{Limit: 1024},
			},
			Seccomp: DefaultSeccompProfile(),
		},
	}
	return spec
}

// DefaultMounts is the standard virtual filesystem set. Rootless can't mount a
// fresh sysfs, so /sys comes from the host read-only instead.
func DefaultMounts(rootless bool) []Mount {
	sys := Mount{
		Destination: "/sys",
		Type:        "sysfs",
		Source:      "sysfs",
		Options:     []string{"nosuid", "noexec", "nodev", "ro"},
	}
	if rootless {
		sys = Mount{
			Destination: "/sys",
			Type:        "none",
			Source:      "/sys",
			Options:     []string{"rbind", "nosuid", "noexec", "nodev", "ro"},
		}
	}

	return []Mount{
		{
			Destination: "/proc",
			Type:        "proc",
			Source:      "proc",
			Options:     []string{"nosuid", "noexec", "nodev"},
		},
		{
			Destination: "/dev",
			Type:        "tmpfs",
			Source:      "tmpfs",
			Options:     []string{"nosuid", "strictatime", "mode=755", "size=65536k"},
		},
		{
			Destination: "/dev/pts",
			Type:        "devpts",
			Source:      "devpts",
			Options:     []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"},
		},
		{
			Destination: "/dev/shm",
			Type:        "tmpfs",
			Source:      "shm",
			Options:     []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"},
		},
		{
			Destination: "/dev/mqueue",
			Type:        "mqueue",
			Source:      "mqueue",
			Options:     []string{"nosuid", "noexec", "nodev"},
		},
		sys,
	}
}

// DefaultDevices is what every container gets — the nodes POSIX programs assume
// exist. None of them grant host access.
var DefaultDevices = []LinuxDevice{
	{Path: "/dev/null", Type: "c", Major: 1, Minor: 3, FileMode: filemode(0o666)},
	{Path: "/dev/zero", Type: "c", Major: 1, Minor: 5, FileMode: filemode(0o666)},
	{Path: "/dev/full", Type: "c", Major: 1, Minor: 7, FileMode: filemode(0o666)},
	{Path: "/dev/random", Type: "c", Major: 1, Minor: 8, FileMode: filemode(0o666)},
	{Path: "/dev/urandom", Type: "c", Major: 1, Minor: 9, FileMode: filemode(0o666)},
	{Path: "/dev/tty", Type: "c", Major: 5, Minor: 0, FileMode: filemode(0o666)},
}

func filemode(m uint32) *uint32 { return &m }
