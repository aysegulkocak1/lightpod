package runtime_test

import (
    "testing"
    "github.com/aysegulkocak1/lightpod/pkg/runtime"
)

func TestRootlessNamespaces(t *testing.T) {
    c := runtime.Container{
        Name:     "rootless-test",
        Rootless: true,
        Namespaces: []runtime.NamespaceType{
            runtime.NEWUSER,
            runtime.NEWUTS,
            runtime.NEWPID,
        },
    }

    if err := c.ApplyNamespaces(); err != nil {
        t.Fatalf("Failed to apply namespaces: %v", err)
    }
}
