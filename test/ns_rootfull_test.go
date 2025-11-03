package runtime_test

import (
    "testing"
    "github.com/aysegulkocak1/lightpod/pkg/runtime"
)

func TestRootfullNamespaces(t *testing.T) {
    c := runtime.Container{
        Name:     "rootfull-test",
        Rootless: false,
        Namespaces: []runtime.NamespaceType{
            runtime.NEWUTS,
            runtime.NEWPID,
            runtime.NEWNET,
            runtime.NEWUSER,
        },
    }

    if err := c.ApplyNamespaces(); err != nil {
        t.Fatalf("Failed to apply namespaces: %v", err)
    }
}
