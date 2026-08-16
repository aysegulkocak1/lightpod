package device

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aysegulkocak1/lightpod/pkg/oci"
)

// DefaultSpecDirs are the standard CDI locations: static specs in /etc, ones
// generated at boot in /var/run. Later directories win on conflict.
var DefaultSpecDirs = []string{"/etc/cdi", "/var/run/cdi"}

// CDISpec is one CDI specification file.
//
// Only JSON is read.
type CDISpec struct {
	Version        string         `json:"cdiVersion"`
	Kind           string         `json:"kind"`
	Devices        []CDIDevice    `json:"devices"`
	ContainerEdits ContainerEdits `json:"containerEdits,omitempty"`
}

// CDIDevice is one addressable device within a kind, e.g. the "0" in
// nvidia.com/gpu=0.
type CDIDevice struct {
	Name           string         `json:"name"`
	ContainerEdits ContainerEdits `json:"containerEdits"`
}

// ContainerEdits is what a device contributes to the container: device nodes,
// library mounts, environment and hooks.
type ContainerEdits struct {
	Env         []string        `json:"env,omitempty"`
	DeviceNodes []CDIDeviceNode `json:"deviceNodes,omitempty"`
	Mounts      []CDIMount      `json:"mounts,omitempty"`
	Hooks       []CDIHook       `json:"hooks,omitempty"`
}

type CDIDeviceNode struct {
	Path        string  `json:"path"`
	HostPath    string  `json:"hostPath,omitempty"`
	Type        string  `json:"type,omitempty"`
	Major       int64   `json:"major,omitempty"`
	Minor       int64   `json:"minor,omitempty"`
	FileMode    *uint32 `json:"fileMode,omitempty"`
	Permissions string  `json:"permissions,omitempty"`
	UID         *uint32 `json:"uid,omitempty"`
	GID         *uint32 `json:"gid,omitempty"`
}

type CDIMount struct {
	HostPath      string   `json:"hostPath"`
	ContainerPath string   `json:"containerPath"`
	Type          string   `json:"type,omitempty"`
	Options       []string `json:"options,omitempty"`
}

type CDIHook struct {
	HookName string   `json:"hookName"`
	Path     string   `json:"path"`
	Args     []string `json:"args,omitempty"`
	Env      []string `json:"env,omitempty"`
	Timeout  *int     `json:"timeout,omitempty"`
}

// Registry is the set of CDI specs found on this machine.
type Registry struct {
	specs []CDISpec

	// yamlOnly records kinds that exist only as YAML, so a lookup failure can
	// say what is actually wrong instead of "device not found".
	yamlFiles []string
}

// LoadRegistry reads every *.json CDI spec from the given directories.
// A missing directory is normal — most machines have no CDI at all.
func LoadRegistry(dirs []string) (*Registry, error) {
	reg := &Registry{}

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("reading CDI directory %s: %w", dir, err)
		}

		for _, entry := range entries {
			name := entry.Name()
			switch strings.ToLower(filepath.Ext(name)) {
			case ".yaml", ".yml":
				reg.yamlFiles = append(reg.yamlFiles, filepath.Join(dir, name))
				continue
			case ".json":
			default:
				continue
			}

			path := filepath.Join(dir, name)
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("reading CDI spec %s: %w", path, err)
			}
			var spec CDISpec
			if err := json.Unmarshal(data, &spec); err != nil {
				return nil, fmt.Errorf("parsing CDI spec %s: %w", path, err)
			}
			if spec.Kind == "" {
				return nil, fmt.Errorf("CDI spec %s has no kind", path)
			}
			if err := checkCDIVersion(spec.Version, path); err != nil {
				return nil, err
			}
			reg.specs = append(reg.specs, spec)
		}
	}
	return reg, nil
}

// checkCDIVersion refuses a spec written against a major version we do not
// understand, rather than injecting a partially understood device.
func checkCDIVersion(version, path string) error {
	if version == "" {
		return fmt.Errorf("CDI spec %s has no cdiVersion", path)
	}
	major, _, _ := strings.Cut(version, ".")
	if major != "0" {
		return fmt.Errorf("CDI spec %s uses cdiVersion %s, which this build of lightpod does not understand",
			path, version)
	}
	return nil
}

// Inject resolves a qualified device name and applies its edits to the spec.
//
// The name is "vendor.com/class=device", e.g. nvidia.com/gpu=0. The special
// device name "all" is whatever the vendor defined it as; it is not special
// cased here.
func (r *Registry) Inject(spec *oci.Spec, qualified string) error {
	kind, name, ok := strings.Cut(qualified, "=")
	if !ok || kind == "" || name == "" {
		return fmt.Errorf("device %q is not a CDI name (expected vendor.com/class=device)", qualified)
	}

	for _, s := range r.specs {
		if s.Kind != kind {
			continue
		}
		for _, d := range s.Devices {
			if d.Name != name {
				continue
			}
			// Kind-wide edits first, then the device's own: the vendor puts
			// shared driver libraries in the former and per-device nodes in the
			// latter, and the device must be able to build on the shared parts.
			if err := applyEdits(spec, s.ContainerEdits); err != nil {
				return fmt.Errorf("applying %s container edits: %w", kind, err)
			}
			if err := applyEdits(spec, d.ContainerEdits); err != nil {
				return fmt.Errorf("applying %s edits: %w", qualified, err)
			}
			return nil
		}
		return fmt.Errorf("CDI kind %s has no device %q (available: %s)",
			kind, name, strings.Join(deviceNames(s), ", "))
	}

	return r.notFoundError(kind)
}

// notFoundError explains a missing kind, including the common case where the
// vendor wrote YAML and we only read JSON.
func (r *Registry) notFoundError(kind string) error {
	if len(r.yamlFiles) > 0 {
		return fmt.Errorf("no CDI spec for %s.\n"+
			"Found YAML specs that lightpod does not read (%s).\n"+
			"lightpod reads JSON only, because it carries no YAML parser. Regenerate with:\n"+
			"  sudo nvidia-ctk cdi generate --format=json --output=/etc/cdi/nvidia.json",
			kind, strings.Join(r.yamlFiles, ", "))
	}
	if len(r.specs) == 0 {
		return fmt.Errorf("no CDI specs found in %s.\n"+
			"For NVIDIA devices, generate one with:\n"+
			"  sudo nvidia-ctk cdi generate --format=json --output=/etc/cdi/nvidia.json",
			strings.Join(DefaultSpecDirs, " or "))
	}
	return fmt.Errorf("no CDI spec for kind %s (found: %s)", kind, strings.Join(r.Kinds(), ", "))
}

// Kinds lists the device kinds available, for diagnostics.
func (r *Registry) Kinds() []string {
	seen := map[string]bool{}
	var kinds []string
	for _, s := range r.specs {
		if !seen[s.Kind] {
			seen[s.Kind] = true
			kinds = append(kinds, s.Kind)
		}
	}
	sort.Strings(kinds)
	return kinds
}

func deviceNames(s CDISpec) []string {
	var names []string
	for _, d := range s.Devices {
		names = append(names, d.Name)
	}
	sort.Strings(names)
	return names
}

// applyEdits merges one set of container edits into the runtime spec.
func applyEdits(spec *oci.Spec, edits ContainerEdits) error {
	if spec.Process == nil {
		return fmt.Errorf("spec has no process section")
	}
	if spec.Linux == nil {
		spec.Linux = &oci.Linux{}
	}

	spec.Process.Env = append(spec.Process.Env, edits.Env...)

	for _, node := range edits.DeviceNodes {
		dev, err := deviceNodeToSpec(node)
		if err != nil {
			return err
		}
		spec.Linux.Devices = append(spec.Linux.Devices, dev)
	}

	for _, m := range edits.Mounts {
		options := m.Options
		if len(options) == 0 {
			options = []string{"rbind", "ro", "nosuid", "nodev"}
		}
		spec.Mounts = append(spec.Mounts, oci.Mount{
			Destination: m.ContainerPath,
			Source:      m.HostPath,
			Type:        "none",
			Options:     options,
		})
	}

	for _, h := range edits.Hooks {
		if err := appendHook(spec, h); err != nil {
			return err
		}
	}
	return nil
}

// deviceNodeToSpec fills in whatever the CDI spec left out by stat'ing the host
// node. Vendors routinely omit major/minor and expect the runtime to look them
// up.
func deviceNodeToSpec(node CDIDeviceNode) (oci.LinuxDevice, error) {
	hostPath := node.HostPath
	if hostPath == "" {
		hostPath = node.Path
	}

	dev := oci.LinuxDevice{
		Path:     node.Path,
		Type:     node.Type,
		Major:    node.Major,
		Minor:    node.Minor,
		FileMode: node.FileMode,
		UID:      node.UID,
		GID:      node.GID,
	}

	if dev.Type == "" || (dev.Major == 0 && dev.Minor == 0) {
		found, err := describe(hostPath)
		if err != nil {
			return oci.LinuxDevice{}, fmt.Errorf("CDI device node %s: %w", node.Path, err)
		}
		if dev.Type == "" {
			dev.Type = found.Type
		}
		if dev.Major == 0 && dev.Minor == 0 {
			dev.Major, dev.Minor = found.Major, found.Minor
		}
		if dev.FileMode == nil {
			dev.FileMode = found.FileMode
		}
		if dev.UID == nil {
			dev.UID = found.UID
		}
		if dev.GID == nil {
			dev.GID = found.GID
		}
	}
	return dev, nil
}

// appendHook routes a CDI hook to the matching lifecycle list.
//
// NVIDIA's specs use createContainer for ldcache and symlink fixups, which is
// why the runtime runs that list inside the container's namespaces.
func appendHook(spec *oci.Spec, h CDIHook) error {
	if spec.Hooks == nil {
		spec.Hooks = &oci.Hooks{}
	}
	hook := oci.Hook{Path: h.Path, Args: h.Args, Env: h.Env, Timeout: h.Timeout}

	switch h.HookName {
	case "prestart":
		spec.Hooks.Prestart = append(spec.Hooks.Prestart, hook)
	case "createRuntime":
		spec.Hooks.CreateRuntime = append(spec.Hooks.CreateRuntime, hook)
	case "createContainer":
		spec.Hooks.CreateContainer = append(spec.Hooks.CreateContainer, hook)
	case "startContainer":
		spec.Hooks.StartContainer = append(spec.Hooks.StartContainer, hook)
	case "poststart":
		spec.Hooks.Poststart = append(spec.Hooks.Poststart, hook)
	case "poststop":
		spec.Hooks.Poststop = append(spec.Hooks.Poststop, hook)
	default:
		// Dropping a hook we do not recognise would mean the device is injected
		// but not finished setting up — worse than refusing.
		return fmt.Errorf("CDI hook has unknown lifecycle name %q", h.HookName)
	}
	return nil
}
