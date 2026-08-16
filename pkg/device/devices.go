// Package device turns --device requests into spec entries: raw host paths for
// sensors, cameras and serial ports, and CDI names for GPUs.
package device

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/aysegulkocak1/lightpod/pkg/oci"
)

// Mkdev encodes a major/minor pair the way makedev(3) does.
//
// Both numbers are split across two bit ranges, so the naive (major<<8)|minor
// quietly loses the high bits — which /dev/nvidia-caps and dynamic minors have.
func Mkdev(major, minor int64) uint64 {
	return uint64(((major & 0xfff) << 8) |
		(minor & 0xff) |
		((major &^ 0xfff) << 32) |
		((minor &^ 0xff) << 12))
}

// Major extracts the major number from a raw device number.
//
// The uint32 conversions are not decoration: glibc's macros truncate to
// unsigned int after shifting, and without that the high half of the device
// number leaks into the result.
func Major(dev uint64) int64 {
	return int64((dev>>8)&0xfff | uint64(uint32(dev>>32)&^0xfff))
}

// Minor extracts the minor number from a raw device number.
func Minor(dev uint64) int64 {
	return int64(dev&0xff | uint64(uint32(dev>>12)&^0xff))
}

// ParseRawDevice turns a --device value into a spec device entry.
//
//	/dev/video0                 same path inside, rwm
//	/dev/video0:/dev/video1     different path inside
//	/dev/video0:rw              restricted permissions
//	/dev/video0:/dev/video1:rw  both
//
// Second field is a container path if it starts with a slash, permissions
// otherwise — same rule other runtimes use.
func ParseRawDevice(value string) (oci.LinuxDevice, error) {
	parts := strings.Split(value, ":")
	if len(parts) > 3 {
		return oci.LinuxDevice{}, fmt.Errorf("device %q has too many fields", value)
	}

	hostPath := parts[0]
	containerPath := hostPath
	permissions := "rwm"

	switch len(parts) {
	case 2:
		if strings.HasPrefix(parts[1], "/") {
			containerPath = parts[1]
		} else {
			permissions = parts[1]
		}
	case 3:
		containerPath = parts[1]
		permissions = parts[2]
	}

	if !strings.HasPrefix(hostPath, "/") {
		return oci.LinuxDevice{}, fmt.Errorf("device %q: host path must be absolute", value)
	}
	if err := validatePermissions(permissions); err != nil {
		return oci.LinuxDevice{}, fmt.Errorf("device %q: %w", value, err)
	}

	dev, err := describe(hostPath)
	if err != nil {
		return oci.LinuxDevice{}, err
	}
	dev.Path = containerPath
	return dev, nil
}

func validatePermissions(p string) error {
	if p == "" {
		return fmt.Errorf("empty permission string")
	}
	for _, c := range p {
		if c != 'r' && c != 'w' && c != 'm' {
			return fmt.Errorf("permission %q must contain only r, w and m", p)
		}
	}
	return nil
}

// describe stats a host device node and reads back its type and numbers.
func describe(hostPath string) (oci.LinuxDevice, error) {
	fi, err := os.Stat(hostPath)
	if err != nil {
		return oci.LinuxDevice{}, fmt.Errorf("device %s: %w", hostPath, err)
	}

	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return oci.LinuxDevice{}, fmt.Errorf("device %s: cannot read device numbers", hostPath)
	}

	var kind string
	switch fi.Mode() & os.ModeType {
	case os.ModeDevice | os.ModeCharDevice:
		kind = "c"
	case os.ModeDevice:
		kind = "b"
	case os.ModeNamedPipe:
		kind = "p"
	default:
		return oci.LinuxDevice{}, fmt.Errorf("device %s is not a device node", hostPath)
	}

	mode := uint32(fi.Mode().Perm())
	uid := st.Uid
	gid := st.Gid

	return oci.LinuxDevice{
		Type:     kind,
		Major:    Major(uint64(st.Rdev)),
		Minor:    Minor(uint64(st.Rdev)),
		FileMode: &mode,
		UID:      &uid,
		GID:      &gid,
	}, nil
}
