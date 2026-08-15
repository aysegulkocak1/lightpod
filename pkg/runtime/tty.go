package runtime

import (
	"errors"
	"os"
	"os/signal"
	"syscall"
)

// What we relay to the container's init.
//
// Without this, Ctrl-C kills lightpod and orphans the workload, and a systemd
// stop never reaches the process that needs to shut down — on an edge device,
// sensors and motors still running after their supervisor is gone.
//
// Only what an operator or supervisor actually sends. Subscribing to everything
// would also catch SIGURG, which the Go runtime uses constantly for preemption.
var forwardedSignals = []os.Signal{
	syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP,
	syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGWINCH,
}

func forwardSignals(proc *os.Process) (stop func()) {
	ch := make(chan os.Signal, 8)
	signal.Notify(ch, forwardedSignals...)

	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-ch:
				if s, ok := sig.(syscall.Signal); ok {
					_ = proc.Signal(s)
				}
			case <-done:
				return
			}
		}
	}()

	return func() {
		signal.Stop(ch)
		close(done)
	}
}

// asExitError separates "the workload ran and failed" from "it never ran" —
// very different things to whoever called us.
func asExitError(err error, target any) bool {
	return errors.As(err, target)
}
