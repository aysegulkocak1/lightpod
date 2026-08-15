// isolationcheck runs as the container's only process and reports what it can
// see about its own confinement, as JSON.
//
// "The container started" proves almost nothing. Whether the isolation is
// actually in force can only be answered honestly from inside. Built with
// CGO_ENABLED=0 so a rootfs can be just this one binary.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
)

type report struct {
	Pid             int      `json:"pid"`
	Hostname        string   `json:"hostname"`
	UID             int      `json:"uid"`
	VisibleProcs    int      `json:"visibleProcs"`
	MountCount      int      `json:"mountCount"`
	NoNewPrivs      string   `json:"noNewPrivs"`
	Seccomp         string   `json:"seccomp"`
	CapEff          string   `json:"capEff"`
	CapBnd          string   `json:"capBnd"`
	KcoreReadable   bool     `json:"kcoreReadable"`
	SysrqWritable   bool     `json:"sysrqWritable"`
	MountAllowed    bool     `json:"mountAllowed"`
	HostRootVisible bool     `json:"hostRootVisible"`
	Errors          []string `json:"errors,omitempty"`
}

func main() {
	// Keeps the lifecycle tests a container to poke at.
	if len(os.Args) > 1 && os.Args[1] == "sleep" {
		seconds := 60
		if len(os.Args) > 2 {
			fmt.Sscanf(os.Args[2], "%d", &seconds)
		}
		time.Sleep(time.Duration(seconds) * time.Second)
		return
	}

	// Eats memory in 8MB steps so a cgroup limit can be checked for real. Each
	// chunk is written to, otherwise the pages are never faulted in and the
	// limit never trips.
	if len(os.Args) > 1 && os.Args[1] == "alloc" {
		megabytes := 256
		if len(os.Args) > 2 {
			fmt.Sscanf(os.Args[2], "%d", &megabytes)
		}
		var held [][]byte
		for allocated := 0; allocated < megabytes; allocated += 8 {
			chunk := make([]byte, 8<<20)
			for i := range chunk {
				chunk[i] = 1
			}
			held = append(held, chunk)
			fmt.Printf("allocated %dMB\n", allocated+8)
		}
		fmt.Printf("reached %dMB without being killed\n", len(held)*8)
		return
	}

	r := report{Pid: os.Getpid(), UID: os.Getuid()}

	if name, err := os.Hostname(); err == nil {
		r.Hostname = name
	}

	// With a PID namespace /proc only shows our own.
	if entries, err := os.ReadDir("/proc"); err == nil {
		for _, e := range entries {
			if e.IsDir() && e.Name()[0] >= '0' && e.Name()[0] <= '9' {
				r.VisibleProcs++
			}
		}
	}

	if data, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
		r.MountCount = len(strings.Split(strings.TrimSpace(string(data)), "\n"))
	}

	// Straight from the kernel's own accounting, so the runtime can't fake it.
	for _, line := range readStatus() {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "NoNewPrivs":
			r.NoNewPrivs = value
		case "Seccomp":
			r.Seccomp = value // 0 = off, 1 = strict, 2 = filtered
		case "CapEff":
			r.CapEff = value
		case "CapBnd":
			r.CapBnd = value
		}
	}

	if f, err := os.Open("/proc/kcore"); err == nil {
		buf := make([]byte, 1)
		n, _ := f.Read(buf)
		r.KcoreReadable = n > 0
		f.Close()
	}

	if f, err := os.OpenFile("/proc/sysrq-trigger", os.O_WRONLY, 0); err == nil {
		r.SysrqWritable = true
		f.Close()
	}

	// The canonical escape primitive. Should fail — EPERM under seccomp, or
	// for lack of CAP_SYS_ADMIN without it.
	if err := os.MkdirAll("/tmp/lightpod-probe", 0o755); err == nil {
		if err := syscall.Mount("proc", "/tmp/lightpod-probe", "proc", 0, ""); err == nil {
			r.MountAllowed = true
			_ = syscall.Unmount("/tmp/lightpod-probe", 0)
		}
	}

	// If the pivot worked these just aren't there.
	for _, p := range []string{"/etc/shadow", "/home", "/boot"} {
		if _, err := os.Stat(p); err == nil {
			r.HostRootVisible = true
			r.Errors = append(r.Errors, fmt.Sprintf("host path %s is visible", p))
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(r)
}

func readStatus() []string {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return nil
	}
	return strings.Split(string(data), "\n")
}
