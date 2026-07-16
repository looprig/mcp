//go:build !unix

// This file is the fallback for platforms with no process groups (Windows).
// It is honest about what it cannot do: the server itself is terminated, its
// descendants are not, because there is no portable handle here that names
// them. A host that needs a hard boundary on such a platform supplies a
// ProcessLauncher — a job object, a container — which is precisely why that
// seam exists.

package stdio

import (
	"errors"
	"os"
	"syscall"
)

// sysProcAttr adds nothing: there is no portable process-group attribute here.
func sysProcAttr() *syscall.SysProcAttr { return nil }

// terminateGroup asks the process to shut down. Only the process itself is
// signalled; see the file comment.
func terminateGroup(p *os.Process) error {
	if p == nil {
		return errors.New("no process to signal")
	}
	if err := p.Signal(os.Interrupt); err != nil {
		if errors.Is(err, os.ErrProcessDone) {
			return nil
		}
		return err
	}
	return nil
}

// killGroup destroys the process. Only the process itself is killed; see the
// file comment.
func killGroup(p *os.Process) error {
	if p == nil {
		return errors.New("no process to kill")
	}
	if err := p.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}

// exitSignal has no signal to report on a platform without them.
func exitSignal(*os.ProcessState) string { return "" }
