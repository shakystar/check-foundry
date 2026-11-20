package runner

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"runtime"
	"time"
)

type capped struct {
	data  []byte
	limit int
}

func (w *capped) Write(p []byte) (int, error) {
	if len(p) > w.limit-len(w.data) {
		return 0, errors.New("output limit exceeded")
	}
	w.data = append(w.data, p...)
	return len(p), nil
}

// Run starts a tool with OS isolation and only the explicitly provided environment.
func Run(ctx context.Context, dir, bin string, env []string, args ...string) ([]byte, int, error) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(ctx, "/usr/bin/sandbox-exec", append([]string{"-p", "(version 1)(allow default)(deny network*)(deny file-write*)", bin}, args...)...)
	case "linux":
		cmd = exec.CommandContext(ctx, "bwrap", append([]string{"--die-with-parent", "--unshare-net", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--chdir", dir, "--", bin}, args...)...)
	default:
		return nil, -1, errors.New("offline isolation unsupported on this OS")
	}
	cmd.Dir = dir
	cmd.Env = append([]string{"HOME=" + dir, "PATH=/usr/bin:/bin"}, env...)
	out := capped{limit: 64 << 20}
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	cmd.WaitDelay = 3 * time.Second
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, -1, ctx.Err()
	}
	if err != nil {
		var e *exec.ExitError
		if errors.As(err, &e) {
			return out.data, e.ExitCode(), nil
		}
		return nil, -1, err
	}
	return out.data, 0, nil
}
