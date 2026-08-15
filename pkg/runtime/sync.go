package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// syncType is a step in the parent/child handshake.
//
// The container can't just be forked and forgotten — some setup happens on the
// host while the child waits (id maps, cgroup, runtime-namespace hooks), some
// in the child between two host steps. This makes the ordering explicit instead
// of racy.
type syncType string

const (
	// Child is in its namespaces, hasn't done anything else yet.
	syncNsReady syncType = "nsReady"

	// Parent wrote uid_map/gid_map and put the child in its cgroup. Before this
	// the child has no usable identity.
	syncMapsReady syncType = "mapsReady"

	// Mounts are done, pivot hasn't happened. The only moment createRuntime
	// hooks are useful — nvidia-container-cli injects here, while the rootfs is
	// still reachable at its host path.
	syncHookPoint syncType = "hookPoint"

	syncHooksDone syncType = "hooksDone"

	// Setup done, about to block for start. Sent before seccomp — installing a
	// filter is privileged, and the filter would otherwise have to allow it.
	syncProcReady syncType = "procReady"

	syncError syncType = "error"
)

// syncMessage is one line of the handshake.
type syncMessage struct {
	Type    syncType `json:"t"`
	Message string   `json:"msg,omitempty"`
}

// syncPipe is one end of the parent/child handshake channel.
type syncPipe struct {
	file *os.File
	enc  *json.Encoder
	dec  *json.Decoder
}

func newSyncPipe(f *os.File) *syncPipe {
	return &syncPipe{
		file: f,
		enc:  json.NewEncoder(f),
		dec:  json.NewDecoder(f),
	}
}

// send writes a step marker.
func (p *syncPipe) send(t syncType) error {
	if err := p.enc.Encode(syncMessage{Type: t}); err != nil {
		return fmt.Errorf("sending sync message %q: %w", t, err)
	}
	return nil
}

// sendError gives the other side a real message instead of "pipe closed".
func (p *syncPipe) sendError(cause error) {
	_ = p.enc.Encode(syncMessage{Type: syncError, Message: cause.Error()})
}

// await blocks until the expected step arrives. EOF is fatal — the pipe only
// closes if the other side died, and carrying on would leave a half-built
// container.
func (p *syncPipe) await(expect syncType) error {
	var msg syncMessage
	if err := p.dec.Decode(&msg); err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("waiting for %q: the other side exited unexpectedly", expect)
		}
		return fmt.Errorf("waiting for %q: %w", expect, err)
	}
	switch msg.Type {
	case expect:
		return nil
	case syncError:
		return errors.New(msg.Message)
	default:
		return fmt.Errorf("expected sync message %q but got %q", expect, msg.Type)
	}
}

func (p *syncPipe) Close() error { return p.file.Close() }
