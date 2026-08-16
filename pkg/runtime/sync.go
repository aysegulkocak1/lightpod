package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// syncType is a step in the parent/child handshake.
type syncType string

const (
	syncNsReady syncType = "nsReady"

	syncMapsReady syncType = "mapsReady"

	syncHookPoint syncType = "hookPoint"

	syncHooksDone syncType = "hooksDone"

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
