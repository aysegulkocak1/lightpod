package oci

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ConfigFile is the fixed name of the spec inside a bundle directory.
const ConfigFile = "config.json"

// Load reads <bundle>/config.json. The bundle is the single source of truth —
// nvidia-container-runtime works by rewriting it before calling us.
func Load(bundle string) (*Spec, error) {
	path := filepath.Join(bundle, ConfigFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var spec Spec
	// No DisallowUnknownFields: a newer tool's extra fields shouldn't stop us
	// running. We never rewrite a bundle we were given, so nothing is lost.
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if spec.Version == "" {
		return nil, fmt.Errorf("%s: ociVersion is required", path)
	}
	return &spec, nil
}

// Save writes the spec to <bundle>/config.json.
func Save(spec *Spec, bundle string) error {
	data, err := json.MarshalIndent(spec, "", "\t")
	if err != nil {
		return fmt.Errorf("encoding spec: %w", err)
	}
	path := filepath.Join(bundle, ConfigFile)
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// ResolveRootfs returns the absolute rootfs path.
//
// root.path may be relative to the bundle. Resolved once here, with a traversal
// check — otherwise a hostile bundle could point at "../../.." and have us
// pivot into a host directory.
func ResolveRootfs(spec *Spec, bundle string) (string, error) {
	if spec.Root == nil || spec.Root.Path == "" {
		return "", fmt.Errorf("spec has no root.path")
	}

	rootfs := spec.Root.Path
	if !filepath.IsAbs(rootfs) {
		rootfs = filepath.Join(bundle, rootfs)
	}
	rootfs = filepath.Clean(rootfs)

	absBundle, err := filepath.Abs(bundle)
	if err != nil {
		return "", fmt.Errorf("resolving bundle path: %w", err)
	}
	// Relative paths must stay in the bundle. Absolute ones are trusted — that's
	// `--rootfs /srv/images/busybox`, typed by the caller, not chosen by the bundle.
	if !filepath.IsAbs(spec.Root.Path) && !isWithin(absBundle, rootfs) {
		return "", fmt.Errorf("root.path %q escapes the bundle directory", spec.Root.Path)
	}

	fi, err := os.Stat(rootfs)
	if err != nil {
		return "", fmt.Errorf("rootfs %s: %w", rootfs, err)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("rootfs %s is not a directory", rootfs)
	}
	return rootfs, nil
}

// isWithin reports whether path is parent or a descendant of it.
func isWithin(parent, path string) bool {
	if path == parent {
		return true
	}
	return strings.HasPrefix(path, parent+string(filepath.Separator))
}

// HasNamespace reports whether the spec asks for this namespace.
func (s *Spec) HasNamespace(t LinuxNamespaceType) bool {
	if s.Linux == nil {
		return false
	}
	for _, ns := range s.Linux.Namespaces {
		if ns.Type == t {
			return true
		}
	}
	return false
}

// Namespace returns the namespace entry of the given type, or nil.
func (s *Spec) Namespace(t LinuxNamespaceType) *LinuxNamespace {
	if s.Linux == nil {
		return nil
	}
	for i := range s.Linux.Namespaces {
		if s.Linux.Namespaces[i].Type == t {
			return &s.Linux.Namespaces[i]
		}
	}
	return nil
}
