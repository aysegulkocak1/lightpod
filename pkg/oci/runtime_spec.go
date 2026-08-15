// Package oci holds the OCI runtime-spec types. Data only, no logic.
//
// Everything is omitempty so a config.json written by another tool round-trips
// intact. Dropping a field we don't understand could silently weaken it.
package oci

// Spec is the top level of <bundle>/config.json.
type Spec struct {
	Version     string            `json:"ociVersion"`
	Process     *Process          `json:"process,omitempty"`
	Root        *Root             `json:"root,omitempty"`
	Hostname    string            `json:"hostname,omitempty"`
	Domainname  string            `json:"domainname,omitempty"`
	Mounts      []Mount           `json:"mounts,omitempty"`
	Hooks       *Hooks            `json:"hooks,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Linux       *Linux            `json:"linux,omitempty"`
}

// Process describes the container's initial process.
type Process struct {
	Terminal        bool               `json:"terminal,omitempty"`
	ConsoleSize     *Box               `json:"consoleSize,omitempty"`
	User            User               `json:"user"`
	Args            []string           `json:"args,omitempty"`
	CommandLine     string             `json:"commandLine,omitempty"`
	Env             []string           `json:"env,omitempty"`
	Cwd             string             `json:"cwd"`
	Capabilities    *LinuxCapabilities `json:"capabilities,omitempty"`
	Rlimits         []POSIXRlimit      `json:"rlimits,omitempty"`
	NoNewPrivileges bool               `json:"noNewPrivileges,omitempty"`
	ApparmorProfile string             `json:"apparmorProfile,omitempty"`
	OOMScoreAdj     *int               `json:"oomScoreAdj,omitempty"`
	SelinuxLabel    string             `json:"selinuxLabel,omitempty"`
}

// Box is a terminal size in characters.
type Box struct {
	Height uint `json:"height"`
	Width  uint `json:"width"`
}

// User is the uid/gid the container process runs as.
type User struct {
	UID            uint32   `json:"uid"`
	GID            uint32   `json:"gid"`
	Umask          *uint32  `json:"umask,omitempty"`
	AdditionalGids []uint32 `json:"additionalGids,omitempty"`
	Username       string   `json:"username,omitempty"`
}

// LinuxCapabilities is capset(2)'s five sets. All five matter — dropping only
// the bounding set leaves effective privileges untouched.
type LinuxCapabilities struct {
	Bounding    []string `json:"bounding,omitempty"`
	Effective   []string `json:"effective,omitempty"`
	Inheritable []string `json:"inheritable,omitempty"`
	Permitted   []string `json:"permitted,omitempty"`
	Ambient     []string `json:"ambient,omitempty"`
}

// POSIXRlimit is a setrlimit(2) entry.
type POSIXRlimit struct {
	Type string `json:"type"`
	Hard uint64 `json:"hard"`
	Soft uint64 `json:"soft"`
}

// Root is the container root filesystem.
type Root struct {
	Path     string `json:"path"`
	Readonly bool   `json:"readonly,omitempty"`
}

// Mount is a single mount(2) to perform inside the container mount namespace.
type Mount struct {
	Destination string           `json:"destination"`
	Type        string           `json:"type,omitempty"`
	Source      string           `json:"source,omitempty"`
	Options     []string         `json:"options,omitempty"`
	UIDMappings []LinuxIDMapping `json:"uidMappings,omitempty"`
	GIDMappings []LinuxIDMapping `json:"gidMappings,omitempty"`
}

// Hook is a program run at a lifecycle point. Gets the container State on stdin.
type Hook struct {
	Path    string   `json:"path"`
	Args    []string `json:"args,omitempty"`
	Env     []string `json:"env,omitempty"`
	Timeout *int     `json:"timeout,omitempty"`
}

// Hooks groups the lifecycle hook lists. Prestart is deprecated but legacy
// nvidia-container-runtime still injects it, so we keep it.
type Hooks struct {
	Prestart        []Hook `json:"prestart,omitempty"`
	CreateRuntime   []Hook `json:"createRuntime,omitempty"`
	CreateContainer []Hook `json:"createContainer,omitempty"`
	StartContainer  []Hook `json:"startContainer,omitempty"`
	Poststart       []Hook `json:"poststart,omitempty"`
	Poststop        []Hook `json:"poststop,omitempty"`
}

// Linux holds the Linux-specific configuration.
type Linux struct {
	UIDMappings       []LinuxIDMapping  `json:"uidMappings,omitempty"`
	GIDMappings       []LinuxIDMapping  `json:"gidMappings,omitempty"`
	Sysctl            map[string]string `json:"sysctl,omitempty"`
	Resources         *LinuxResources   `json:"resources,omitempty"`
	CgroupsPath       string            `json:"cgroupsPath,omitempty"`
	Namespaces        []LinuxNamespace  `json:"namespaces,omitempty"`
	Devices           []LinuxDevice     `json:"devices,omitempty"`
	Seccomp           *LinuxSeccomp     `json:"seccomp,omitempty"`
	RootfsPropagation string            `json:"rootfsPropagation,omitempty"`
	MaskedPaths       []string          `json:"maskedPaths,omitempty"`
	ReadonlyPaths     []string          `json:"readonlyPaths,omitempty"`
	MountLabel        string            `json:"mountLabel,omitempty"`
}

// LinuxIDMapping is one line of /proc/<pid>/uid_map or gid_map.
type LinuxIDMapping struct {
	ContainerID uint32 `json:"containerID"`
	HostID      uint32 `json:"hostID"`
	Size        uint32 `json:"size"`
}

// LinuxNamespaceType names a namespace kind as the spec spells it.
type LinuxNamespaceType string

const (
	PIDNamespace     LinuxNamespaceType = "pid"
	NetworkNamespace LinuxNamespaceType = "network"
	MountNamespace   LinuxNamespaceType = "mount"
	IPCNamespace     LinuxNamespaceType = "ipc"
	UTSNamespace     LinuxNamespaceType = "uts"
	UserNamespace    LinuxNamespaceType = "user"
	CgroupNamespace  LinuxNamespaceType = "cgroup"
	TimeNamespace    LinuxNamespaceType = "time"
)

// LinuxNamespace requests a namespace. Empty Path = create one, set Path = join
// that one (pods).
type LinuxNamespace struct {
	Type LinuxNamespaceType `json:"type"`
	Path string             `json:"path,omitempty"`
}

// LinuxDevice is a device node to create inside the container.
type LinuxDevice struct {
	Path     string  `json:"path"`
	Type     string  `json:"type"`
	Major    int64   `json:"major"`
	Minor    int64   `json:"minor"`
	FileMode *uint32 `json:"fileMode,omitempty"`
	UID      *uint32 `json:"uid,omitempty"`
	GID      *uint32 `json:"gid,omitempty"`
}

// LinuxResources are the cgroup limits.
type LinuxResources struct {
	Devices []LinuxDeviceCgroup `json:"devices,omitempty"`
	Memory  *LinuxMemory        `json:"memory,omitempty"`
	CPU     *LinuxCPU           `json:"cpu,omitempty"`
	Pids    *LinuxPids          `json:"pids,omitempty"`
}

// LinuxDeviceCgroup is one device access rule.
type LinuxDeviceCgroup struct {
	Allow  bool   `json:"allow"`
	Type   string `json:"type,omitempty"`
	Major  *int64 `json:"major,omitempty"`
	Minor  *int64 `json:"minor,omitempty"`
	Access string `json:"access,omitempty"`
}

// LinuxMemory maps to the cgroup v2 memory controller.
type LinuxMemory struct {
	Limit            *int64  `json:"limit,omitempty"`
	Reservation      *int64  `json:"reservation,omitempty"`
	Swap             *int64  `json:"swap,omitempty"`
	Swappiness       *uint64 `json:"swappiness,omitempty"`
	DisableOOMKiller *bool   `json:"disableOOMKiller,omitempty"`
}

// LinuxCPU maps to the cgroup v2 cpu and cpuset controllers.
type LinuxCPU struct {
	Shares *uint64 `json:"shares,omitempty"`
	Quota  *int64  `json:"quota,omitempty"`
	Period *uint64 `json:"period,omitempty"`
	Cpus   string  `json:"cpus,omitempty"`
	Mems   string  `json:"mems,omitempty"`
}

// LinuxPids maps to the cgroup v2 pids controller.
type LinuxPids struct {
	Limit int64 `json:"limit"`
}

// LinuxSeccompAction is the action a seccomp rule takes.
type LinuxSeccompAction string

const (
	ActKill        LinuxSeccompAction = "SCMP_ACT_KILL"
	ActKillProcess LinuxSeccompAction = "SCMP_ACT_KILL_PROCESS"
	ActTrap        LinuxSeccompAction = "SCMP_ACT_TRAP"
	ActErrno       LinuxSeccompAction = "SCMP_ACT_ERRNO"
	ActTrace       LinuxSeccompAction = "SCMP_ACT_TRACE"
	ActAllow       LinuxSeccompAction = "SCMP_ACT_ALLOW"
	ActLog         LinuxSeccompAction = "SCMP_ACT_LOG"
)

// LinuxSeccomp is the seccomp profile.
type LinuxSeccomp struct {
	DefaultAction   LinuxSeccompAction `json:"defaultAction"`
	DefaultErrnoRet *uint              `json:"defaultErrnoRet,omitempty"`
	Architectures   []string           `json:"architectures,omitempty"`
	Flags           []string           `json:"flags,omitempty"`
	Syscalls        []LinuxSyscall     `json:"syscalls,omitempty"`
}

// LinuxSyscall is one seccomp rule covering a set of syscall names.
type LinuxSyscall struct {
	Names    []string           `json:"names"`
	Action   LinuxSeccompAction `json:"action"`
	ErrnoRet *uint              `json:"errnoRet,omitempty"`
	Args     []LinuxSeccompArg  `json:"args,omitempty"`
}

// LinuxSeccompArg is an argument-level condition on a syscall rule.
type LinuxSeccompArg struct {
	Index    uint   `json:"index"`
	Value    uint64 `json:"value"`
	ValueTwo uint64 `json:"valueTwo,omitempty"`
	Op       string `json:"op"`
}
