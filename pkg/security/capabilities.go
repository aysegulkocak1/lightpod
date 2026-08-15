package security

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/aysegulkocak1/lightpod/pkg/oci"
)

// Capability bit numbers from <linux/capability.h>.
const (
	CAP_CHOWN              = 0
	CAP_DAC_OVERRIDE       = 1
	CAP_DAC_READ_SEARCH    = 2
	CAP_FOWNER             = 3
	CAP_FSETID             = 4
	CAP_KILL               = 5
	CAP_SETGID             = 6
	CAP_SETUID             = 7
	CAP_SETPCAP            = 8
	CAP_LINUX_IMMUTABLE    = 9
	CAP_NET_BIND_SERVICE   = 10
	CAP_NET_BROADCAST      = 11
	CAP_NET_ADMIN          = 12
	CAP_NET_RAW            = 13
	CAP_IPC_LOCK           = 14
	CAP_IPC_OWNER          = 15
	CAP_SYS_MODULE         = 16
	CAP_SYS_RAWIO          = 17
	CAP_SYS_CHROOT         = 18
	CAP_SYS_PTRACE         = 19
	CAP_SYS_PACCT          = 20
	CAP_SYS_ADMIN          = 21
	CAP_SYS_BOOT           = 22
	CAP_SYS_NICE           = 23
	CAP_SYS_RESOURCE       = 24
	CAP_SYS_TIME           = 25
	CAP_SYS_TTY_CONFIG     = 26
	CAP_MKNOD              = 27
	CAP_LEASE              = 28
	CAP_AUDIT_WRITE        = 29
	CAP_AUDIT_CONTROL      = 30
	CAP_SETFCAP            = 31
	CAP_MAC_OVERRIDE       = 32
	CAP_MAC_ADMIN          = 33
	CAP_SYSLOG             = 34
	CAP_WAKE_ALARM         = 35
	CAP_BLOCK_SUSPEND      = 36
	CAP_AUDIT_READ         = 37
	CAP_PERFMON            = 38
	CAP_BPF                = 39
	CAP_CHECKPOINT_RESTORE = 40
)

// capabilityNames maps the spec's capability spelling to its bit number.
var capabilityNames = map[string]int{
	"CAP_CHOWN":              CAP_CHOWN,
	"CAP_DAC_OVERRIDE":       CAP_DAC_OVERRIDE,
	"CAP_DAC_READ_SEARCH":    CAP_DAC_READ_SEARCH,
	"CAP_FOWNER":             CAP_FOWNER,
	"CAP_FSETID":             CAP_FSETID,
	"CAP_KILL":               CAP_KILL,
	"CAP_SETGID":             CAP_SETGID,
	"CAP_SETUID":             CAP_SETUID,
	"CAP_SETPCAP":            CAP_SETPCAP,
	"CAP_LINUX_IMMUTABLE":    CAP_LINUX_IMMUTABLE,
	"CAP_NET_BIND_SERVICE":   CAP_NET_BIND_SERVICE,
	"CAP_NET_BROADCAST":      CAP_NET_BROADCAST,
	"CAP_NET_ADMIN":          CAP_NET_ADMIN,
	"CAP_NET_RAW":            CAP_NET_RAW,
	"CAP_IPC_LOCK":           CAP_IPC_LOCK,
	"CAP_IPC_OWNER":          CAP_IPC_OWNER,
	"CAP_SYS_MODULE":         CAP_SYS_MODULE,
	"CAP_SYS_RAWIO":          CAP_SYS_RAWIO,
	"CAP_SYS_CHROOT":         CAP_SYS_CHROOT,
	"CAP_SYS_PTRACE":         CAP_SYS_PTRACE,
	"CAP_SYS_PACCT":          CAP_SYS_PACCT,
	"CAP_SYS_ADMIN":          CAP_SYS_ADMIN,
	"CAP_SYS_BOOT":           CAP_SYS_BOOT,
	"CAP_SYS_NICE":           CAP_SYS_NICE,
	"CAP_SYS_RESOURCE":       CAP_SYS_RESOURCE,
	"CAP_SYS_TIME":           CAP_SYS_TIME,
	"CAP_SYS_TTY_CONFIG":     CAP_SYS_TTY_CONFIG,
	"CAP_MKNOD":              CAP_MKNOD,
	"CAP_LEASE":              CAP_LEASE,
	"CAP_AUDIT_WRITE":        CAP_AUDIT_WRITE,
	"CAP_AUDIT_CONTROL":      CAP_AUDIT_CONTROL,
	"CAP_SETFCAP":            CAP_SETFCAP,
	"CAP_MAC_OVERRIDE":       CAP_MAC_OVERRIDE,
	"CAP_MAC_ADMIN":          CAP_MAC_ADMIN,
	"CAP_SYSLOG":             CAP_SYSLOG,
	"CAP_WAKE_ALARM":         CAP_WAKE_ALARM,
	"CAP_BLOCK_SUSPEND":      CAP_BLOCK_SUSPEND,
	"CAP_AUDIT_READ":         CAP_AUDIT_READ,
	"CAP_PERFMON":            CAP_PERFMON,
	"CAP_BPF":                CAP_BPF,
	"CAP_CHECKPOINT_RESTORE": CAP_CHECKPOINT_RESTORE,
}

// capSet is a 64-bit capability bitmask.
type capSet uint64

func (s *capSet) add(bit int)     { *s |= 1 << uint(bit) }
func (s capSet) has(bit int) bool { return s&(1<<uint(bit)) != 0 }
func (s capSet) low() uint32      { return uint32(s & 0xffffffff) }
func (s capSet) high() uint32     { return uint32(s >> 32) }

// parseCapabilities turns spec names into a bitmask. Unknown name is an error,
// not a skip — a typo shouldn't quietly produce a different privilege set.
func parseCapabilities(names []string) (capSet, error) {
	var set capSet
	for _, name := range names {
		bit, ok := capabilityNames[strings.ToUpper(name)]
		if !ok {
			return 0, fmt.Errorf("unknown capability %q", name)
		}
		set.add(bit)
	}
	return set, nil
}

// ApplyCapabilities reduces the process to exactly what the spec asks for,
// across all five sets.
//
// Order matters:
//  1. Bounding first, while we still hold CAP_SETPCAP — dropping needs it.
//  2. Clear ambient, so nothing survives the coming execve by accident.
//  3. capset for effective/permitted/inheritable. This is the step that
//     actually removes live privileges; bounding alone caps only what could be
//     regained later.
//  4. Ambient raises last — a cap can only go ambient once it's in permitted
//     and inheritable.
func ApplyCapabilities(caps *oci.LinuxCapabilities) error {
	if caps == nil {
		return nil
	}

	bounding, err := parseCapabilities(caps.Bounding)
	if err != nil {
		return fmt.Errorf("capabilities.bounding: %w", err)
	}
	effective, err := parseCapabilities(caps.Effective)
	if err != nil {
		return fmt.Errorf("capabilities.effective: %w", err)
	}
	permitted, err := parseCapabilities(caps.Permitted)
	if err != nil {
		return fmt.Errorf("capabilities.permitted: %w", err)
	}
	inheritable, err := parseCapabilities(caps.Inheritable)
	if err != nil {
		return fmt.Errorf("capabilities.inheritable: %w", err)
	}
	ambient, err := parseCapabilities(caps.Ambient)
	if err != nil {
		return fmt.Errorf("capabilities.ambient: %w", err)
	}

	lastCap := lastCapability()
	for bit := 0; bit <= lastCap; bit++ {
		if bounding.has(bit) {
			continue
		}
		if err := prctl(prCapBSetDrop, uintptr(bit), 0, 0, 0); err != nil {
			// EINVAL just means this kernel doesn't have the cap, so it can't be
			// held either. Anything else and we'd be starting with a wider
			// bounding set than asked for.
			if err == syscall.EINVAL {
				continue
			}
			return fmt.Errorf("dropping bounding capability %d: %w", bit, err)
		}
	}

	if err := prctl(prCapAmbient, prCapAmbientClearAll, 0, 0, 0); err != nil {
		return fmt.Errorf("clearing ambient capability set: %w", err)
	}

	hdr := capHeader{version: capVersion3, pid: 0}
	var data [2]capData
	data[0] = capData{
		effective:   effective.low(),
		permitted:   permitted.low(),
		inheritable: inheritable.low(),
	}
	data[1] = capData{
		effective:   effective.high(),
		permitted:   permitted.high(),
		inheritable: inheritable.high(),
	}
	if err := capset(&hdr, &data); err != nil {
		return fmt.Errorf("capset: %w", err)
	}

	for bit := 0; bit <= lastCap; bit++ {
		if !ambient.has(bit) {
			continue
		}
		if err := prctl(prCapAmbient, prCapAmbientRaise, uintptr(bit), 0, 0); err != nil {
			return fmt.Errorf("raising ambient capability %d: %w", bit, err)
		}
	}

	return nil
}

// CurrentBounding reports what's left in the bounding set. For checking a
// container really was reduced, rather than trusting ApplyCapabilities' nil.
func CurrentBounding() (capSet, error) {
	var set capSet
	for bit := 0; bit <= lastCapability(); bit++ {
		held, err := prctlRet(prCapBSetRead, uintptr(bit), 0, 0, 0)
		if err != nil {
			if err == syscall.EINVAL {
				continue
			}
			return 0, fmt.Errorf("reading bounding capability %d: %w", bit, err)
		}
		if held == 1 {
			set.add(bit)
		}
	}
	return set, nil
}

// CurrentEffective reports the calling process's effective capability set.
func CurrentEffective() (capSet, error) {
	hdr := capHeader{version: capVersion3, pid: 0}
	var data [2]capData
	if err := capget(&hdr, &data); err != nil {
		return 0, fmt.Errorf("capget: %w", err)
	}
	return capSet(data[0].effective) | capSet(data[1].effective)<<32, nil
}

// Names renders a capability set as sorted spec names, for diagnostics.
func (s capSet) Names() []string {
	var names []string
	for name, bit := range capabilityNames {
		if s.has(bit) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// lastCapability is the highest capability this kernel knows. Read rather than
// assumed, so we stay right on kernels newer than this build.
func lastCapability() int {
	const fallback = CAP_CHECKPOINT_RESTORE
	data, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return fallback
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || value < 0 {
		return fallback
	}
	return value
}
