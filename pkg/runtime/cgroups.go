package runtime

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// Cgroup V2
const cgroupRoot = "/sys/fs/cgroup/lightpod"

type CgroupManager struct {
	Path string
}

// NewCgroupManager creates a new cgroup directory for the container
func NewCgroupManager(containerName string) (*CgroupManager, error) {
	cgroupPath := filepath.Join(cgroupRoot, containerName)

	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cgroup directory %s: %w", cgroupPath, err)
	}

	return &CgroupManager{Path: cgroupPath}, nil
}

// SetResources applies the memory and CPU limits to our cgroup
func (m *CgroupManager) SetResources(memoryMaxBytes int64, cpuWeight int) error {
	if memoryMaxBytes > 0 {
		memLimitPath := filepath.Join(m.Path, "memory.max")
		if err := os.WriteFile(memLimitPath, []byte(strconv.FormatInt(memoryMaxBytes, 10)), 0644); err != nil {
			return fmt.Errorf("failed to write memory.max: %w", err)
		}
	}

	if cpuWeight > 0 {
		cpuWeightPath := filepath.Join(m.Path, "cpu.weight")
		if err := os.WriteFile(cpuWeightPath, []byte(strconv.Itoa(cpuWeight)), 0644); err != nil {
			return fmt.Errorf("failed to write cpu.weight: %w", err)
		}
	}

	return nil
}

// Apply adds the given process ID to the cgroup so that limits are enforced
func (m *CgroupManager) Apply(pid int) error {
	procsPath := filepath.Join(m.Path, "cgroup.procs")

	if err := os.WriteFile(procsPath, []byte(strconv.Itoa(pid)), 0644); err != nil {
		return fmt.Errorf("failed to write pid %d to cgroup.procs: %w", pid, err)
	}

	return nil
}

// Cleanup removes the cgroup.
func (m *CgroupManager) Cleanup() error {
	if err := os.Remove(m.Path); err != nil {
		return fmt.Errorf("failed to remove cgroup %s: %w", m.Path, err)
	}
	return nil
}
