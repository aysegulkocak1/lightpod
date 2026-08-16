package main

import (
	"fmt"
	"os"

	"github.com/aysegulkocak1/lightpod/pkg/device"
	"github.com/aysegulkocak1/lightpod/pkg/oci"
)

// applyGPU lets the NVIDIA toolkit edit the bundle, and returns the spec to run.
//
// Two ways in, tried in that order:
//
//   - the toolkit's runtime shim rewrites config.json on disk and we re-read it.
//     This is what Docker's chain uses and it follows whatever mode the toolkit
//     defaults to, currently CDI.
//   - failing that, its prestart hook goes into the spec and we run the hook
//     ourselves. Older path, deprecated by NVIDIA, but works without the shim.
//
// LIGHTPOD_GPU_MODE=runtime|hook pins one.
func applyGPU(bundle, id string, spec *oci.Spec, gpu string) (*oci.Spec, error) {
	if gpu == "" {
		return spec, nil
	}

	mode := os.Getenv("LIGHTPOD_GPU_MODE")
	runtimePath, haveRuntime := device.FindNVIDIARuntime()

	switch {
	case mode == "hook":
		haveRuntime = false
	case mode == "runtime" && !haveRuntime:
		return nil, fmt.Errorf("LIGHTPOD_GPU_MODE=runtime but nvidia-container-runtime was not found")
	case mode != "" && mode != "hook" && mode != "runtime":
		return nil, fmt.Errorf("LIGHTPOD_GPU_MODE=%q is not valid (want runtime or hook)", mode)
	}

	if haveRuntime {
		if err := device.PrepareBundleWithNVIDIA(runtimePath, bundle, id); err != nil {
			return nil, err
		}
		// The toolkit rewrote it, so the version in memory is stale.
		return oci.Load(bundle)
	}

	if err := device.InjectNVIDIAHook(spec); err != nil {
		return nil, err
	}
	if err := oci.Save(spec, bundle); err != nil {
		return nil, err
	}
	return spec, nil
}
