// Package version carries build identity, filled in at link time:
//
//	go build -ldflags "-X .../pkg/version.Version=v0.2.0-alpha \
//	                   -X .../pkg/version.Commit=$(git rev-parse --short HEAD)"
package version

import "fmt"

var (
	// SemVer. Pre-1.0 is v0.MINOR.PATCH-alpha, MINOR tracking the milestone.
	Version = "v0.2.0-alpha"

	Commit    = "unknown"
	BuildDate = "unknown"
)

// Schema versions are pinned separately from the binary version — upgrading
// lightpod shouldn't silently change an on-disk or on-wire contract.
const (
	// runtime-spec revision we emit in generated config.json.
	OCIVersion = "1.2.0"

	// Stamped into state.json. A newer schema is refused rather than
	// misinterpreted.
	StateSchema = 1
)

// String is what `lightpod --version` prints.
func String() string {
	return fmt.Sprintf("lightpod %s (commit %s, built %s, oci-spec %s)",
		Version, Commit, BuildDate, OCIVersion)
}
