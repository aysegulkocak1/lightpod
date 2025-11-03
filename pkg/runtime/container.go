package runtime

import (
    "fmt"
    "os"
    "syscall"
)

// Container represents a container instance
type Container struct {
    Name       string
    Rootfs     string
    Cmd        []string
    Hostname   string
    Rootless   bool
    PID        int
    Namespaces []NamespaceType
    Cgroups    map[string]string
    Mounts     []Mount
}


// ContainsNamespace checks if the container has a specific namespace.
func (c *Container) ContainsNamespace(ns NamespaceType) bool {
    for _, n := range c.Namespaces {
        if n == ns {
            return true
        }
    }
    return false
}

// ApplyNamespaces sets up and applies namespaces for the container.
func (c *Container) ApplyNamespaces() error {
    if err := c.configureNamespaces(); err != nil {
        return fmt.Errorf("failed to configure namespaces: %w", err)
    }
    return nil
}

// configureNamespaces applies namespaces based on rootless/rootful mode.
func (c *Container) configureNamespaces() error {
    if c.Rootless {
        // Rootless: only USER and PID namespace
        var rootlessNamespaces []NamespaceType
        for _, ns := range c.Namespaces {
            if ns == NEWUSER || ns == NEWPID {
                rootlessNamespaces = append(rootlessNamespaces, ns)
            }
        }
        if len(rootlessNamespaces) > 0 {
            if err := c.unshareNamespaces(rootlessNamespaces); err != nil {
                return fmt.Errorf("failed to setup rootless namespaces: %w", err)
            }
        }
    } else {
        // Rootful: root-required namespaces
        for _, ns := range c.Namespaces {
            switch ns {
            case NEWUTS:
                if err := SetupUTSNamespace(); err != nil {
                    return fmt.Errorf("failed to setup UTS namespace: %w", err)
                }
            case NEWNET:
                if err := SetupNetworkNamespace(); err != nil {
                    return fmt.Errorf("failed to setup NET namespace: %w", err)
                }
            case NEWIPC:
                if err := SetupIPCNamespace(); err != nil {
                    return fmt.Errorf("failed to setup IPC namespace: %w", err)
                }
            case NEWPID:
                if err := SetupPIDNamespace(); err != nil {
                    return fmt.Errorf("failed to setup PID namespace: %w", err)
                }
            case NEWUSER:
                if err := c.cloneNamespaces([]NamespaceType{NEWUSER}); err != nil {
                    return fmt.Errorf("failed to setup USER namespace: %w", err)
                }
            }
        }
    }
    return nil
}

// unshareNamespaces performs unshare syscall for rootless mode.
func (c *Container) unshareNamespaces(namespaces []NamespaceType) error {
	flags := NamespaceFlags(namespaces)
	_, _, syserr := syscall.RawSyscall(syscall.SYS_UNSHARE, flags, 0, 0)
    if syserr != 0 {
        return fmt.Errorf("unshare failed: %w", syscall.Errno(syserr)) 
    }

	for _, ns := range namespaces {
		switch ns {
		case NEWUSER:
			uid := os.Getuid()
			gid := os.Getgid()
			if err := RunNewIDMap(os.Getpid(), uid, gid); err != nil {
				return fmt.Errorf("failed to setup USER namespace rootless: %w", err)
			}
		case NEWPID:
			if err := SetupPIDNamespace(); err != nil {
				return fmt.Errorf("failed to setup PID namespace: %w", err)
			}
		}
	}

	return nil
}

// cloneNamespaces performs clone syscall for rootful USER namespace.
func (c *Container) cloneNamespaces(namespaces []NamespaceType) error {
    
    flags := NamespaceFlags(namespaces) | uintptr(syscall.SIGCHLD) | syscall.CLONE_CHILD_CLEARTID 
    
    pid, _, syserr := syscall.RawSyscall(syscall.SYS_CLONE, flags, 0, 0)
    
    if syserr != 0 {
        return fmt.Errorf("clone failed: %v", syserr) 
    }

    childPID := int(pid) 

    if childPID == 0 {
       
        // if err := c.setupContainerEnvironment(); err != nil { 
        //     fmt.Fprintf(os.Stderr, "Child setup failed: %v\n", err)
        //     os.Exit(1)
        // }
        
        if err := syscall.Kill(syscall.Getpid(), syscall.SIGSTOP); err != nil {
            fmt.Fprintf(os.Stderr, "Child failed to send SIGSTOP: %v\n", err)
            os.Exit(1)
        }
        return nil
    }
    
    
    var ws syscall.WaitStatus
    if _, err := syscall.Wait4(childPID, &ws, syscall.WNOHANG | syscall.WUNTRACED, nil); err != nil {
         return fmt.Errorf("initial wait4 failed: %w", err)
    }

    if err := SetupUserNamespaceRootfull(childPID, os.Getuid(), os.Getgid()); err != nil {
        syscall.Kill(childPID, syscall.SIGKILL)
        return fmt.Errorf("USER namespace failed: %w", err)
    }

    if err := syscall.Kill(childPID, syscall.SIGCONT); err != nil {
        syscall.Kill(childPID, syscall.SIGKILL)
        return fmt.Errorf("failed to signal child with SIGCONT: %w", err)
    }

    if _, err := syscall.Wait4(childPID, &ws, 0, nil); err != nil {
        return fmt.Errorf("wait4 failed: %w", err)
    }

    c.PID = childPID
    return nil
}

