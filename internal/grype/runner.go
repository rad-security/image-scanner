package grype

import (
	"context"
	"errors"
	"io"
	"os/exec"
)

// Run executes the grype binary at binPath with args, streaming stdout to
// stdout and stderr to stderr. The returned exit code is grype's own. A
// non-nil error is only returned for failures unrelated to grype's exit
// status (e.g. failure to start the process).
func Run(ctx context.Context, binPath string, args []string, stdout, stderr io.Writer) (int, error) {
	cmd := exec.CommandContext(ctx, binPath, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode(), nil
		}
		return -1, err
	}
	return 0, nil
}
