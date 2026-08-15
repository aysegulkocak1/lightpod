package oci

// ContainerStatus is the lifecycle state reported by `lightpod state`.
type ContainerStatus string

const (
	StatusCreating ContainerStatus = "creating"
	StatusCreated  ContainerStatus = "created"
	StatusRunning  ContainerStatus = "running"
	StatusStopped  ContainerStatus = "stopped"
)

// State is the runtime-spec state document: printed by `lightpod state` and fed
// to every hook on stdin. nvidia-container-cli finds the container through Pid.
type State struct {
	Version     string            `json:"ociVersion"`
	ID          string            `json:"id"`
	Status      ContainerStatus   `json:"status"`
	Pid         int               `json:"pid,omitempty"`
	Bundle      string            `json:"bundle"`
	Annotations map[string]string `json:"annotations,omitempty"`
}
