//go:build !amd64 && !arm64 && !arm

package security

// Keeps unported architectures compiling. auditArch 0 makes CompileSeccomp
// fail, so the container refuses to start rather than running unfiltered — an
// unported arch shouldn't quietly become the least protected one.
const auditArch = 0

const guardX32 = false

var syscallNumbers = map[string]int{}
