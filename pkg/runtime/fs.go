package runtime

// import (
//     "fmt"
//     "os"
//     "syscall"
// )

// Mount represents a mount point inside the container
type Mount struct {
    Source  string
    Target  string
    Fstype  string
    Options []string
}
