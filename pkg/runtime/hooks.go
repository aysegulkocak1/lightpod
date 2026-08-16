package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/aysegulkocak1/lightpod/pkg/oci"
)

// runHooks runs a hook list, feeding each the container state on stdin.
//
// This is how outside tooling extends the runtime without us knowing about it —
// the NVIDIA toolkit injects driver libraries entirely through hooks, which is
// why there's no vendor code here. A failing hook aborts creation: a container
// whose GPU injection failed shouldn't quietly run on the CPU.
func runHooks(hooks []oci.Hook, state *oci.State) error {
	if len(hooks) == 0 {
		return nil
	}

	payload, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encoding container state for hooks: %w", err)
	}

	for i, hook := range hooks {
		if err := runHook(hook, payload); err != nil {
			return fmt.Errorf("hook %d (%s): %w", i, hook.Path, err)
		}
	}
	return nil
}

func runHook(hook oci.Hook, state []byte) error {
	ctx := context.Background()
	if hook.Timeout != nil && *hook.Timeout > 0 {
		// A hanging hook would hang creation forever.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(*hook.Timeout)*time.Second)
		defer cancel()
	}

	args := hook.Args
	if len(args) == 0 {
		args = []string{hook.Path}
	}

	cmd := exec.CommandContext(ctx, hook.Path)
	cmd.Args = args
	cmd.Env = hook.Env
	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}
	cmd.Stdin = bytes.NewReader(state)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("timed out after %d seconds", *hook.Timeout)
		}
		return fmt.Errorf("%w (stderr: %s)", err, bytes.TrimSpace(stderr.Bytes()))
	}
	return nil
}

// runPoststopHooks logs failures instead of returning them. The container is
// already gone; refusing to clean up would leave an undeletable entry behind.
func runPoststopHooks(hooks []oci.Hook, state *oci.State) {
	if err := runHooks(hooks, state); err != nil {
		fmt.Fprintf(os.Stderr, "lightpod: poststop hook failed: %v\n", err)
	}
}
