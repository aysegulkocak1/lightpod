package device

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeToolkit writes a stand-in nvidia-container-runtime: it edits the bundle's
// config.json the way the real one does, then execs whatever low-level runtime
// its config names.
func fakeToolkit(t *testing.T, edit bool, useStub bool) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "nvidia-container-runtime")

	editLine := ""
	if edit {
		// Append a marker env entry, standing in for the real GPU edits.
		editLine = `python3 - "$BUNDLE" <<'PY'
import json,sys
p=sys.argv[1]+"/config.json"
d=json.load(open(p))
d["process"]["env"].append("FAKE_GPU_INJECTED=1")
json.dump(d,open(p,"w"))
PY
`
	}
	callStub := "true"
	if useStub {
		// Mimic reading runtimes = ["..."] out of the config we were pointed at.
		callStub = `STUB=$(sed -n 's/.*runtimes = \["\(.*\)"\].*/\1/p' "$NVIDIA_CTK_CONFIG_FILE_PATH"); "$STUB" "$@"`
	}

	script := `#!/bin/sh
BUNDLE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --bundle) BUNDLE="$2"; shift 2;;
    *) shift;;
  esac
done
` + editLine + callStub + "\n"

	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func makeBundle(t *testing.T) string {
	t.Helper()
	bundle := t.TempDir()
	spec := map[string]any{
		"ociVersion": "1.2.0",
		"process":    map[string]any{"args": []string{"/bin/true"}, "env": []string{"PATH=/bin"}},
		"root":       map[string]any{"path": "rootfs"},
	}
	data, _ := json.Marshal(spec)
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	return bundle
}

func TestPrepareBundleWithNVIDIA(t *testing.T) {
	bundle := makeBundle(t)
	toolkit := fakeToolkit(t, true, true)

	if err := PrepareBundleWithNVIDIA(toolkit, bundle, "test"); err != nil {
		t.Fatalf("PrepareBundleWithNVIDIA: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(bundle, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "FAKE_GPU_INJECTED") {
		t.Error("the toolkit's edits did not land in the bundle")
	}
}

func TestPrepareBundleRefusesWhenTheStubWasNotUsed(t *testing.T) {
	// The dangerous case: the toolkit ignored our config and called some other
	// runtime, which may have started a container behind our back.
	bundle := makeBundle(t)
	toolkit := fakeToolkit(t, true, false)

	err := PrepareBundleWithNVIDIA(toolkit, bundle, "test")
	if err == nil {
		t.Fatal("expected an error when the stub runtime was bypassed")
	}
	if !strings.Contains(err.Error(), "stub runtime") {
		t.Errorf("error should name the cause, got: %v", err)
	}
}

func TestPrepareBundleRefusesWhenNothingWasInjected(t *testing.T) {
	// Toolkit ran and used our stub but changed nothing — no GPU actually
	// arrived, so starting the container would silently run on the CPU.
	bundle := makeBundle(t)
	toolkit := fakeToolkit(t, false, true)

	err := PrepareBundleWithNVIDIA(toolkit, bundle, "test")
	if err == nil {
		t.Fatal("expected an error when the bundle was left unchanged")
	}
	if !strings.Contains(err.Error(), "unchanged") {
		t.Errorf("error should say nothing was injected, got: %v", err)
	}
}

func TestFindNVIDIARuntimeHonoursOverride(t *testing.T) {
	t.Setenv("LIGHTPOD_NVIDIA_RUNTIME", t.TempDir()+"/absent")
	if _, ok := FindNVIDIARuntime(); ok {
		t.Error("reported a runtime that does not exist")
	}
}
