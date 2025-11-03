package runtime

import (
    "fmt"
    "os"
    "syscall"
    "os/exec"
    "bytes"
)

// NamespaceType represents the type of namespace.
type NamespaceType string

const (
    NEWNET    NamespaceType = "network"
    NEWPID    NamespaceType = "pid"
    NEWNS     NamespaceType = "mount"
    NEWUTS    NamespaceType = "uts"
    NEWIPC    NamespaceType = "ipc"
    NEWUSER   NamespaceType = "user"
    NEWCGROUP NamespaceType = "cgroup"
)

// NamespaceFlags converts a list of NamespaceType to syscall flags.
func NamespaceFlags(namespaces []NamespaceType) uintptr {
    var flags uintptr
    for _, ns := range namespaces {
        switch ns {
        case NEWUTS:
            flags |= syscall.CLONE_NEWUTS
        case NEWIPC:
            flags |= syscall.CLONE_NEWIPC
        case NEWNET:
            flags |= syscall.CLONE_NEWNET
        case NEWPID:
            flags |= syscall.CLONE_NEWPID
        case NEWNS:
            flags |= syscall.CLONE_NEWNS
        case NEWUSER:
            flags |= syscall.CLONE_NEWUSER
        case NEWCGROUP:
            flags |= syscall.CLONE_NEWCGROUP
        }
    }
    return flags
}


// SetupNetworkNamespace sets up the network namespace.
func SetupNetworkNamespace() error {
    // Placeholder for network namespace setup
    fmt.Println("Setting up network namespace...")
    return nil
}

// SetupUTSNamespace sets the hostname for the UTS namespace.
func SetupUTSNamespace() error {
    hostname := "lightpod"
    if err := syscall.Sethostname([]byte(hostname)); err != nil {
        return fmt.Errorf("failed to set hostname: %w", err)
    }
    fmt.Printf("UTS namespace setup complete: hostname set to %s\n", hostname)
    return nil
}

// SetupIPCNamespace sets up the IPC namespace.
func SetupIPCNamespace() error {
    // Placeholder for IPC namespace setup
    fmt.Println("Setting up IPC namespace...")
    return nil
}

// SetupUserNamespace sets up UID/GID mapping for the USER namespace.
func SetupUserNamespaceRootfull(pid int, uid int, gid int) error {

    setgroupsPath := fmt.Sprintf("/proc/%d/setgroups", pid)
    if err := os.WriteFile(setgroupsPath, []byte("deny"), 0644); err != nil {
        return fmt.Errorf("failed to write setgroups: %w", err)
    }

    uidMapPath := fmt.Sprintf("/proc/%d/uid_map", pid)
    uidMap := fmt.Sprintf("0 %d 1\n", uid)
    if err := os.WriteFile(uidMapPath, []byte(uidMap), 0644); err != nil {
        return fmt.Errorf("failed to write uid_map: %w", err)
    }

    gidMapPath := fmt.Sprintf("/proc/%d/gid_map", pid)
    gidMap := fmt.Sprintf("0 %d 1\n", gid)
    if err := os.WriteFile(gidMapPath, []byte(gidMap), 0644); err != nil {
        return fmt.Errorf("failed to write gid_map: %w", err)
    }

    fmt.Printf("User namespace setup complete for PID %d (UID=%d, GID=%d)\n", pid, uid, gid)
    return nil
}

func RunNewIDMap(pid, uid, gid int) error {
	uidCmd := exec.Command("newuidmap", fmt.Sprintf("%d", pid), "0", fmt.Sprintf("%d", uid), "1")
	
    var stderr bytes.Buffer
    uidCmd.Stderr = &stderr
    
    if err := uidCmd.Run(); err != nil {
        return fmt.Errorf("newuidmap failed: %w. Stderr: %s", err, stderr.String())
    }
	gidCmd := exec.Command("newgidmap", fmt.Sprintf("%d", pid), "0", fmt.Sprintf("%d", gid), "1")
	
    var errg bytes.Buffer
    gidCmd.Stderr = &errg
    
    if err := gidCmd.Run(); err != nil {
        return fmt.Errorf("newgidmap failed: %w. Stderr: %s", err, stderr.String())
    }

	fmt.Printf("Rootless USER namespace setup complete for PID %d (UID=%d, GID=%d)\n", pid, uid, gid)
	return nil
}


// SetupPIDNamespace tests the PID namespace by creating a child process.
func SetupPIDNamespace() error {
    pid, err := syscall.ForkExec("/bin/true", []string{}, &syscall.ProcAttr{
        Files: []uintptr{0, 1, 2},
    })
    if err != nil {
        return fmt.Errorf("failed to fork process in PID namespace: %w", err)
    }
    fmt.Printf("PID namespace setup complete: test process created with PID %d\n", pid)
    return nil
}