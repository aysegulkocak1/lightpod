// Package state keeps container metadata on disk. No daemon means no process
// holding the list in memory, so a later `ps` or `kill` has to recover
// everything from the filesystem.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/aysegulkocak1/lightpod/pkg/oci"
	"github.com/aysegulkocak1/lightpod/pkg/version"
)

// Container is lightpod's on-disk record for one container.
type Container struct {
	SchemaVersion int                 `json:"schemaVersion"`
	ID            string              `json:"id"`
	Bundle        string              `json:"bundle"`
	Rootfs        string              `json:"rootfs"`
	Pid           int                 `json:"pid"`
	Status        oci.ContainerStatus `json:"status"`
	CgroupPath    string              `json:"cgroupPath,omitempty"`
	Created       string              `json:"created"`
	Annotations   map[string]string   `json:"annotations,omitempty"`
}

// Store is a directory of container records.
type Store struct {
	root string
}

// New opens the store, creating it if needed. 0700 — it records pids and bundle
// paths, and on a shared machine nobody else should read or forge those.
func New(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating state directory %s: %w", dir, err)
	}
	return &Store{root: dir}, nil
}

// Root returns the store's directory.
func (s *Store) Root() string { return s.root }

// Dir returns the per-container directory, which also holds the start FIFO.
func (s *Store) Dir(id string) string { return filepath.Join(s.root, id) }

func (s *Store) path(id string) string { return filepath.Join(s.Dir(id), "state.json") }

// ValidateID stops an id writing outside the store.
func ValidateID(id string) error {
	if id == "" {
		return fmt.Errorf("container id cannot be empty")
	}
	if id == "." || id == ".." || strings.ContainsAny(id, "/\\\x00") {
		return fmt.Errorf("container id %q contains a path separator", id)
	}
	return nil
}

// withLock serialises writers. The atomic rename in Save protects readers, but
// two creates racing on the same id would both find it free.
func (s *Store) withLock(fn func() error) error {
	f, err := os.OpenFile(filepath.Join(s.root, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("opening store lock: %w", err)
	}
	defer f.Close()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("locking store: %w", err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	return fn()
}

// Create claims an id and writes the first record, failing if it is taken.
func (s *Store) Create(c *Container) error {
	if err := ValidateID(c.ID); err != nil {
		return err
	}
	return s.withLock(func() error {
		if existing, err := s.Load(c.ID); err == nil {
			return fmt.Errorf("container %q already exists (%s)", c.ID, existing.Status)
		}
		return s.Save(c)
	})
}

// Save writes a record, replacing any previous one. Temp file then rename, so a
// concurrent reader gets the old record or the new one, never a half-written
// file that parses as a container with no pid.
func (s *Store) Save(c *Container) error {
	if err := ValidateID(c.ID); err != nil {
		return err
	}
	c.SchemaVersion = version.StateSchema

	if err := os.MkdirAll(s.Dir(c.ID), 0o700); err != nil {
		return fmt.Errorf("creating container state directory: %w", err)
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding state for %s: %w", c.ID, err)
	}

	tmp := s.path(c.ID) + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("writing state for %s: %w", c.ID, err)
	}
	if err := os.Rename(tmp, s.path(c.ID)); err != nil {
		return fmt.Errorf("committing state for %s: %w", c.ID, err)
	}
	return nil
}

// Load reads a record and reconciles its status with reality.
//
// Nothing notices a container dying without a daemon, so a record can claim
// "running" long after the process is gone. Reconciling on read keeps `ps` honest.
func (s *Store) Load(id string) (*Container, error) {
	if err := ValidateID(id); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(s.path(id))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("container %q does not exist", id)
		}
		return nil, fmt.Errorf("reading state for %s: %w", id, err)
	}

	var c Container
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parsing state for %s: %w", id, err)
	}
	if c.SchemaVersion > version.StateSchema {
		return nil, fmt.Errorf("container %s was created by a newer lightpod "+
			"(state schema %d, this build understands %d)", id, c.SchemaVersion, version.StateSchema)
	}

	if c.Status == oci.StatusRunning || c.Status == oci.StatusCreated {
		if !processAlive(c.Pid) {
			c.Status = oci.StatusStopped
			c.Pid = 0
		}
	}
	return &c, nil
}

// List returns every container record, sorted by id for stable output.
func (s *Store) List() ([]*Container, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing state directory: %w", err)
	}

	var containers []*Container
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		c, err := s.Load(entry.Name())
		if err != nil {
			continue // one bad record shouldn't hide the rest
		}
		containers = append(containers, c)
	}
	sort.Slice(containers, func(i, j int) bool { return containers[i].ID < containers[j].ID })
	return containers, nil
}

// Delete removes a container's record and its directory.
func (s *Store) Delete(id string) error {
	if err := ValidateID(id); err != nil {
		return err
	}
	return s.withLock(func() error {
		if err := os.RemoveAll(s.Dir(id)); err != nil {
			return fmt.Errorf("removing state for %s: %w", id, err)
		}
		return nil
	})
}

// processAlive: signal 0 does the existence and permission checks without
// delivering anything.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	// EPERM means it exists but belongs to someone else. Still alive.
	return err == nil || err == syscall.EPERM
}

// ToOCI is the state document hooks get and `lightpod state` prints.
func (c *Container) ToOCI() *oci.State {
	return &oci.State{
		Version:     version.OCIVersion,
		ID:          c.ID,
		Status:      c.Status,
		Pid:         c.Pid,
		Bundle:      c.Bundle,
		Annotations: c.Annotations,
	}
}
