package runtime

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/aysegulkocak1/lightpod/pkg/security"
)

type Container struct {
	Name       string
	Rootfs     string
	Cmd        []string
	Hostname   string
	Rootless   bool
	PID        int
	Namespaces []NamespaceType
	Cgroup     *CgroupManager
	Mounts     []Mount
}

// Start launches the container process in isolated namespaces
func (c *Container) Start() error {

	if len(c.Cmd) == 0 {
		return fmt.Errorf("container cmd is empty")
	}

	args := append([]string{"init", c.Hostname, c.Rootfs}, c.Cmd...)
	cmd := exec.Command("/proc/self/exe", args...)

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	flags := NamespaceFlags(c.Namespaces)

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: uintptr(flags),
	}

	if c.Rootless {
		cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}
		cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start container process: %w", err)
	}

	c.PID = cmd.Process.Pid
	fmt.Printf("Container '%s' starting with Host PID: %d\n", c.Name, c.PID)

	if c.Cgroup != nil {
		if err := c.Cgroup.Apply(c.PID); err != nil {
			fmt.Printf("Warning: Failed to apply cgroup limits: %v\n", err)
		}
	}

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("container exited with error: %w", err)
	}

	return nil
}

// Init processes the setup inside the container, executed as PID 1, before the actual command.
func Init(hostname string, rootfs string, mounts []Mount, userCmd string, args []string) error {
	if hostname != "" {
		if err := syscall.Sethostname([]byte(hostname)); err != nil {
			return fmt.Errorf("failed to set hostname: %w", err)
		}
	}

	if rootfs != "" && rootfs != "/" {
		if err := SetupRootfs(rootfs, mounts); err != nil {
			return fmt.Errorf("failed to setup rootfs: %w", err)
		}
	}

	if err := security.SetupSeccomp(); err != nil {
		return fmt.Errorf("failed to apply seccomp logic: %w", err)
	}

	if err := security.DropCapabilities(); err != nil {
		return fmt.Errorf("failed to drop capabilities: %w", err)
	}

	cmdPath, err := exec.LookPath(userCmd)
	if err != nil {
		return fmt.Errorf("command not found in PATH: %w", err)
	}

	env := os.Environ()

	if err := syscall.Exec(cmdPath, append([]string{userCmd}, args...), env); err != nil {
		return fmt.Errorf("syscall.Exec failed: %w", err)
	}

	return nil
}
