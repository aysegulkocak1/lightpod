package runtime

import (
    "fmt"
    "os"
    "syscall"
)


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


func SetupUserMapping(uid, gid int) error {
    if err := os.WriteFile("/proc/self/setgroups", []byte("deny"), 0644); err != nil {
        return fmt.Errorf("failed to write setgroups: %w", err)
    }
    uidMap := fmt.Sprintf("0 %d 1\n", uid)
    if err := os.WriteFile("/proc/self/uid_map", []byte(uidMap), 0644); err != nil {
        return fmt.Errorf("failed to write uid_map: %w", err)
    }
    gidMap := fmt.Sprintf("0 %d 1\n", gid)
    if err := os.WriteFile("/proc/self/gid_map", []byte(gidMap), 0644); err != nil {
        return fmt.Errorf("failed to write gid_map: %w", err)
    }
    return nil
}


func ValidateNamespaceSupport(ns NamespaceType) bool {
    var nsFile string
    switch ns {
    case NEWUTS:
        nsFile = "uts"
    case NEWIPC:
        nsFile = "ipc"
    case NEWNET:
        nsFile = "net"
    case NEWPID:
        nsFile = "pid"
    case NEWNS:
        nsFile = "mnt"
    case NEWUSER:
        nsFile = "user"
    case NEWCGROUP:
        nsFile = "cgroup"
    default:
        return false
    }
    _, err := os.Stat("/proc/self/ns/" + nsFile)
    return err == nil
}








