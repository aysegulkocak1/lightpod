package oci

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// runcSpec is a trimmed but representative `runc spec` output. It exists to
// prove lightpod can consume a bundle produced by another tool — the property
// that lets it sit underneath podman or nvidia-container-runtime.
const runcSpec = `{
	"ociVersion": "1.2.0",
	"process": {
		"terminal": true,
		"user": {"uid": 0, "gid": 0},
		"args": ["sh"],
		"env": ["PATH=/usr/bin", "TERM=xterm"],
		"cwd": "/",
		"capabilities": {
			"bounding": ["CAP_AUDIT_WRITE", "CAP_KILL"],
			"effective": ["CAP_AUDIT_WRITE", "CAP_KILL"],
			"permitted": ["CAP_AUDIT_WRITE", "CAP_KILL"]
		},
		"rlimits": [{"type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024}],
		"noNewPrivileges": true
	},
	"root": {"path": "rootfs", "readonly": true},
	"hostname": "runc",
	"mounts": [
		{"destination": "/proc", "type": "proc", "source": "proc"},
		{"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
		 "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]}
	],
	"hooks": {
		"prestart": [{"path": "/usr/bin/nvidia-container-runtime-hook", "args": ["nvidia-container-runtime-hook", "prestart"]}],
		"createContainer": [{"path": "/usr/bin/nvidia-cdi-hook", "args": ["nvidia-cdi-hook", "update-ldcache"], "timeout": 30}]
	},
	"annotations": {"cdi.k8s.io/nvidia": "nvidia.com/gpu=0"},
	"linux": {
		"resources": {"memory": {"limit": 67108864}, "pids": {"limit": 100}},
		"namespaces": [{"type": "pid"}, {"type": "network", "path": "/proc/42/ns/net"}],
		"maskedPaths": ["/proc/kcore"],
		"readonlyPaths": ["/proc/sys"],
		"seccomp": {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": [{"names": ["read"], "action": "SCMP_ACT_ALLOW"}]}
	}
}`

func TestSpecRoundTrip(t *testing.T) {
	var spec Spec
	if err := json.Unmarshal([]byte(runcSpec), &spec); err != nil {
		t.Fatalf("unmarshalling a runc spec: %v", err)
	}

	// Spot-check the fields that carry security meaning. A field silently lost
	// here would be a protection the operator configured and lightpod ignored.
	if spec.Version != "1.2.0" {
		t.Errorf("ociVersion = %q", spec.Version)
	}
	if !spec.Process.NoNewPrivileges {
		t.Error("noNewPrivileges was lost")
	}
	if !spec.Root.Readonly {
		t.Error("root.readonly was lost")
	}
	if got := len(spec.Process.Capabilities.Bounding); got != 2 {
		t.Errorf("bounding capabilities = %d, want 2", got)
	}
	if len(spec.Linux.MaskedPaths) != 1 || spec.Linux.MaskedPaths[0] != "/proc/kcore" {
		t.Errorf("maskedPaths = %v", spec.Linux.MaskedPaths)
	}
	if spec.Linux.Seccomp == nil || spec.Linux.Seccomp.DefaultAction != ActErrno {
		t.Error("seccomp profile was lost")
	}
	if spec.Linux.Resources.Memory.Limit == nil || *spec.Linux.Resources.Memory.Limit != 67108864 {
		t.Error("memory limit was lost")
	}

	// Hooks are how GPU support arrives; losing one means a container that
	// starts without its device.
	if spec.Hooks == nil || len(spec.Hooks.Prestart) != 1 || len(spec.Hooks.CreateContainer) != 1 {
		t.Fatalf("hooks were lost: %+v", spec.Hooks)
	}
	if spec.Hooks.CreateContainer[0].Timeout == nil || *spec.Hooks.CreateContainer[0].Timeout != 30 {
		t.Error("hook timeout was lost")
	}
	if spec.Annotations["cdi.k8s.io/nvidia"] != "nvidia.com/gpu=0" {
		t.Error("CDI annotation was lost")
	}

	// A namespace with a path is joined rather than created — the mechanism
	// pods rely on.
	ns := spec.Namespace(NetworkNamespace)
	if ns == nil || ns.Path != "/proc/42/ns/net" {
		t.Errorf("network namespace path was lost: %+v", ns)
	}

	// Re-encoding and decoding must be lossless, since lightpod hands the spec
	// to its init process as JSON.
	encoded, err := json.Marshal(&spec)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	var again Spec
	if err := json.Unmarshal(encoded, &again); err != nil {
		t.Fatalf("re-unmarshalling: %v", err)
	}
	if again.Hooks == nil || len(again.Hooks.Prestart) != 1 {
		t.Error("hooks did not survive the round trip")
	}
	if !again.Process.NoNewPrivileges {
		t.Error("noNewPrivileges did not survive the round trip")
	}
}

func TestLoadAndSave(t *testing.T) {
	bundle := t.TempDir()
	if err := os.WriteFile(filepath.Join(bundle, ConfigFile), []byte(runcSpec), 0o644); err != nil {
		t.Fatal(err)
	}

	spec, err := Load(bundle)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	out := t.TempDir()
	if err := Save(spec, out); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := Load(out); err != nil {
		t.Fatalf("reloading a saved spec: %v", err)
	}
}

func TestLoadRejectsSpecWithoutVersion(t *testing.T) {
	bundle := t.TempDir()
	if err := os.WriteFile(filepath.Join(bundle, ConfigFile), []byte(`{"hostname":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bundle); err == nil {
		t.Fatal("expected an error for a spec with no ociVersion, got nil")
	}
}

func TestResolveRootfsRejectsTraversal(t *testing.T) {
	// A bundle is untrusted input — it can arrive from an image registry or a
	// remote orchestrator. A relative root.path climbing out of the bundle
	// would have the runtime bind-mount and pivot into a host directory.
	bundle := t.TempDir()
	spec := &Spec{Version: "1.2.0", Root: &Root{Path: "../../../etc"}}
	if _, err := ResolveRootfs(spec, bundle); err == nil {
		t.Fatal("expected an error for a root.path escaping the bundle, got nil")
	}
}

func TestResolveRootfsAcceptsRelativePathInsideBundle(t *testing.T) {
	bundle := t.TempDir()
	if err := os.Mkdir(filepath.Join(bundle, "rootfs"), 0o755); err != nil {
		t.Fatal(err)
	}
	spec := &Spec{Version: "1.2.0", Root: &Root{Path: "rootfs"}}

	got, err := ResolveRootfs(spec, bundle)
	if err != nil {
		t.Fatalf("ResolveRootfs: %v", err)
	}
	want, _ := filepath.Abs(filepath.Join(bundle, "rootfs"))
	if got != want {
		t.Errorf("ResolveRootfs = %q, want %q", got, want)
	}
}

func TestResolveRootfsRejectsMissingDirectory(t *testing.T) {
	bundle := t.TempDir()
	spec := &Spec{Version: "1.2.0", Root: &Root{Path: "rootfs"}}
	if _, err := ResolveRootfs(spec, bundle); err == nil {
		t.Fatal("expected an error for a missing rootfs, got nil")
	}
}

func TestDefaultSpecIsSecure(t *testing.T) {
	// The generated default is what `lightpod run --rootfs` produces. These
	// assertions are the security contract of that shortcut.
	spec := Default("/srv/rootfs", []string{"sh"}, true)

	if !spec.Process.NoNewPrivileges {
		t.Error("default spec does not set noNewPrivileges")
	}
	if spec.Linux.Seccomp == nil {
		t.Error("default spec has no seccomp profile")
	}
	if len(spec.Process.Capabilities.Ambient) != 0 {
		t.Error("default spec grants ambient capabilities; these survive execve")
	}
	if len(spec.Linux.MaskedPaths) == 0 || len(spec.Linux.ReadonlyPaths) == 0 {
		t.Error("default spec does not mask or protect any /proc paths")
	}
	if spec.Linux.Resources == nil || spec.Linux.Resources.Pids == nil {
		t.Error("default spec has no pids limit; a fork bomb would reach the host")
	}
	if !spec.HasNamespace(UserNamespace) {
		t.Error("rootless default spec has no user namespace")
	}
	if !spec.HasNamespace(PIDNamespace) || !spec.HasNamespace(MountNamespace) {
		t.Error("default spec is missing a core namespace")
	}
}

func TestDefaultSpecRootfullOmitsUserNamespace(t *testing.T) {
	// A rootfull container does not need a user namespace, and forcing one on
	// would break GPU passthrough, which expects real host device access.
	spec := Default("/srv/rootfs", []string{"sh"}, false)
	if spec.HasNamespace(UserNamespace) {
		t.Error("rootfull default spec should not create a user namespace")
	}
	if !spec.HasNamespace(PIDNamespace) {
		t.Error("rootfull default spec is missing the pid namespace")
	}
}
