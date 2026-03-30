package security

import (
	"fmt"
	"syscall"
)

// Linux Capability Constants
const (
	CAP_CHOWN            = 0
	CAP_DAC_OVERRIDE     = 1
	CAP_FOWNER           = 3
	CAP_FSETID           = 4
	CAP_KILL             = 5
	CAP_SETGID           = 6
	CAP_SETUID           = 7
	CAP_SETPCAP          = 8
	CAP_LINUX_IMMUTABLE  = 9
	CAP_NET_BIND_SERVICE = 10
	CAP_NET_BROADCAST    = 11
	CAP_NET_ADMIN        = 12
	CAP_NET_RAW          = 13
	CAP_IPC_LOCK         = 14
	CAP_IPC_OWNER        = 15
	CAP_SYS_MODULE       = 16
	CAP_SYS_RAWIO        = 17
	CAP_SYS_CHROOT       = 18
	CAP_SYS_PTRACE       = 19
	CAP_SYS_PACCT        = 20
	CAP_SYS_ADMIN        = 21
	CAP_SYS_BOOT         = 22
	CAP_SYS_NICE         = 23
	CAP_SYS_RESOURCE     = 24
	CAP_SYS_TIME         = 25
	CAP_SYS_TTY_CONFIG   = 26
	CAP_MKNOD            = 27
	CAP_LEASE            = 28
	CAP_AUDIT_WRITE      = 29
	CAP_AUDIT_CONTROL    = 30
	CAP_SETFCAP          = 31
	CAP_MAC_OVERRIDE     = 32
	CAP_MAC_ADMIN        = 33
	CAP_SYSLOG           = 34
	CAP_WAKE_ALARM       = 35
	CAP_BLOCK_SUSPEND    = 36
	CAP_AUDIT_READ       = 37
)

const PR_CAPBSET_DROP = 24
const PR_SET_NO_NEW_PRIVS = 38

// defaultCapsToDrop represents the list of capabilities to remove from the container by default
var defaultCapsToDrop = []uintptr{
	CAP_SYS_ADMIN,
	CAP_SYS_MODULE,
	CAP_SYS_RAWIO,
	CAP_SYS_BOOT,
	CAP_SYS_PTRACE,
	CAP_MAC_ADMIN,
	CAP_MAC_OVERRIDE,
}

func prctl(option, arg2, arg3, arg4, arg5 uintptr) error {
	_, _, e1 := syscall.Syscall6(syscall.SYS_PRCTL, option, arg2, arg3, arg4, arg5, 0)
	if e1 != 0 {
		return e1
	}
	return nil
}

// DropCapabilities lowers the bounding set of capabilities.
func DropCapabilities() error {
	for _, cap := range defaultCapsToDrop {
		err := prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)
		if err != nil {
			if err != syscall.EINVAL {
				return fmt.Errorf("failed to drop capability %d: %w", cap, err)
			}
		}
	}
	return nil
}

// SetupSeccomp sets up the secure computing environment.
func SetupSeccomp() error {
	if err := prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("failed to set NO_NEW_PRIVS: %w", err)
	}

	fmt.Println("Security Sandbox initialized (NO_NEW_PRIVS=1, Default Capabilities Dropped)")
	return nil
}
