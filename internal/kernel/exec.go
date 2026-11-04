// Package kernel runs the three privileged programs Portcullis needs (nft,
// conntrack and ip) and reads the few /proc files it attests. It is the only
// package that starts processes. Every command runs from a fixed, validated,
// root-owned absolute path with structured argv (never a shell), a cleared
// environment, bounded input and output, and a deadline. Callers pass only
// typed, validated values; nothing here interprets guest-supplied text.
package kernel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

var (
	// ErrUnsafeBinary rejects an executable whose path, type or ownership
	// would let a non-root user choose or replace what runs as root.
	ErrUnsafeBinary = errors.New("unsafe privileged executable")
	// ErrArgument rejects input before any process is started.
	ErrArgument = errors.New("invalid privileged command input")
	// ErrCommand reports a command that failed, timed out or exceeded an
	// output bound. The error text carries a sanitized stderr excerpt of at
	// most 512 bytes; stdin batches are never included.
	ErrCommand = errors.New("privileged command failed")
)

const (
	minTimeout  = time.Second
	maxTimeout  = 30 * time.Second
	maxStdin    = 1 << 20
	maxStdout   = 8 << 20
	maxStderr   = 64 << 10
	maxArgs     = 32
	maxArgBytes = 256
	maxExcerpt  = 512
	waitDelay   = time.Second
)

// childEnv is the complete environment of every child: no inherited
// variables (LD_PRELOAD, NFT_*, locale tricks) can reach a root process.
func childEnv() []string { return []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"} }

// Option adjusts NewExec validation.
type Option func(*Exec)

// InsecureAllowNonRootForTests relaxes the ownership and parent-directory
// checks so unit tests can run fake executables from t.TempDir(). The target
// must still be a regular, executable file that is neither group- nor
// world-writable and is owned by root or the effective uid. NewExec refuses
// this option outside a test binary, so production code cannot weaken
// validation by accident.
func InsecureAllowNonRootForTests() Option { return func(x *Exec) { x.insecure = true } }

// Exec runs one validated executable. It is immutable after NewExec and safe
// for concurrent use.
type Exec struct {
	path     string // fully resolved target executed by path
	name     string // argv[0]: base name of the configured path
	timeout  time.Duration
	insecure bool
}

// NewExec validates path once at construction: it must be absolute and
// clean; its symlink-resolved target must be a regular executable file, and
// the target and every parent directory up to / must be owned by root and
// not group- or world-writable (sticky world-writable directories such as
// /tmp are rejected too: anyone may create new names in them). Because the
// trusted chain cannot be modified by non-root users, executing the resolved
// path later is not subject to a replacement race by an unprivileged user.
func NewExec(path string, timeout time.Duration, opts ...Option) (*Exec, error) {
	x := &Exec{timeout: timeout}
	for _, o := range opts {
		if o != nil {
			o(x)
		}
	}
	if x.insecure && !testing.Testing() {
		return nil, fmt.Errorf("%w: test-only validation relaxation used outside tests", ErrUnsafeBinary)
	}
	if timeout < minTimeout || timeout > maxTimeout {
		return nil, fmt.Errorf("%w: timeout %v outside [%v, %v]", ErrArgument, timeout, minTimeout, maxTimeout)
	}
	if path == "" || len(path) > 4096 || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\n") {
		return nil, fmt.Errorf("%w: %q is not a clean absolute path", ErrUnsafeBinary, path)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("%w: resolving %q: %v", ErrUnsafeBinary, path, err)
	}
	fi, err := os.Lstat(resolved)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %v", ErrUnsafeBinary, resolved, err)
	}
	if err := checkFile(resolved, fi, x.insecure); err != nil {
		return nil, err
	}
	if !x.insecure {
		for dir := filepath.Dir(resolved); ; dir = filepath.Dir(dir) {
			di, err := os.Lstat(dir)
			if err != nil {
				return nil, fmt.Errorf("%w: %q: %v", ErrUnsafeBinary, dir, err)
			}
			if err := checkDir(dir, di); err != nil {
				return nil, err
			}
			if dir == "/" {
				break
			}
		}
	}
	x.path, x.name = resolved, filepath.Base(path)
	return x, nil
}

func ownerUID(fi fs.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

func checkFile(path string, fi fs.FileInfo, insecure bool) error {
	mode := fi.Mode()
	switch {
	case !mode.IsRegular():
		return fmt.Errorf("%w: %q is not a regular file", ErrUnsafeBinary, path)
	case mode.Perm()&0o111 == 0:
		return fmt.Errorf("%w: %q is not executable", ErrUnsafeBinary, path)
	case mode.Perm()&0o022 != 0:
		return fmt.Errorf("%w: %q is group- or world-writable", ErrUnsafeBinary, path)
	}
	uid, ok := ownerUID(fi)
	if !ok || (uid != 0 && !(insecure && int(uid) == os.Geteuid())) {
		return fmt.Errorf("%w: %q is not owned by root", ErrUnsafeBinary, path)
	}
	return nil
}

func checkDir(dir string, fi fs.FileInfo) error {
	if !fi.IsDir() {
		return fmt.Errorf("%w: %q is not a directory", ErrUnsafeBinary, dir)
	}
	if uid, ok := ownerUID(fi); !ok || uid != 0 {
		return fmt.Errorf("%w: directory %q is not owned by root", ErrUnsafeBinary, dir)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: directory %q is group- or world-writable", ErrUnsafeBinary, dir)
	}
	return nil
}

func checkArgs(args []string) error {
	if len(args) > maxArgs {
		return fmt.Errorf("%w: too many arguments", ErrArgument)
	}
	for i, a := range args {
		if a == "" || len(a) > maxArgBytes {
			return fmt.Errorf("%w: argument %d is empty or longer than %d bytes", ErrArgument, i, maxArgBytes)
		}
		for j := 0; j < len(a); j++ {
			// Printable ASCII only: excludes NUL, newline and terminal escapes,
			// which also keeps arguments safe to quote in error text.
			if a[j] < 0x20 || a[j] > 0x7e {
				return fmt.Errorf("%w: argument %d contains a control or non-ASCII byte", ErrArgument, i)
			}
		}
	}
	return nil
}

// Run executes the validated program with args. The deadline is the earlier
// of ctx and the constructor timeout; on expiry the whole process group is
// killed and WaitDelay bounds any wait on pipes held open by descendants.
// Output beyond the bounds is an error, never a truncated success.
func (x *Exec) Run(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	if x == nil || x.path == "" {
		return nil, fmt.Errorf("%w: executor was not constructed with NewExec", ErrUnsafeBinary)
	}
	if err := checkArgs(args); err != nil {
		return nil, err
	}
	if len(stdin) > maxStdin {
		return nil, fmt.Errorf("%w: stdin exceeds %d bytes", ErrArgument, maxStdin)
	}
	ctx, cancel := context.WithTimeout(ctx, x.timeout)
	defer cancel()
	stdout := &boundedBuffer{limit: maxStdout}
	stderr := &boundedBuffer{limit: maxStderr}
	cmd := x.command(ctx, stdin, args, stdout, stderr)
	err := cmd.Run()
	fail := func(code int, cause error) error {
		return &commandError{name: x.name, args: args, code: code, stderr: stderr.buf.Bytes(), cause: cause}
	}
	switch {
	case stdout.exceeded:
		return nil, fail(-1, fmt.Errorf("stdout exceeded %d bytes", maxStdout))
	case stderr.exceeded:
		return nil, fail(-1, fmt.Errorf("stderr exceeded %d bytes", maxStderr))
	case err == nil:
		return stdout.buf.Bytes(), nil
	case ctx.Err() != nil:
		return nil, fail(-1, fmt.Errorf("killed: %w", ctx.Err()))
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return nil, fail(ee.ExitCode(), err)
	}
	return nil, fail(-1, err)
}

func (x *Exec) command(ctx context.Context, stdin []byte, args []string, stdout, stderr *boundedBuffer) *exec.Cmd {
	cmd := exec.CommandContext(ctx, x.path, args...)
	// argv[0] is the configured name so multi-call binaries dispatch as
	// configured; the kernel executes the resolved, validated path.
	cmd.Args[0] = x.name
	cmd.Env = childEnv()
	cmd.Dir = "/"
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.SysProcAttr = sysProcAttr()
	cmd.Cancel = func() error {
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err == nil {
			return nil
		}
		return cmd.Process.Kill()
	}
	cmd.WaitDelay = waitDelay
	return cmd
}

// boundedBuffer keeps at most limit bytes and fails the write that would
// exceed it, so the child receives EPIPE instead of streaming unboundedly.
// Each buffer is written by one os/exec copy goroutine and read after Wait.
type boundedBuffer struct {
	buf      bytes.Buffer
	limit    int
	exceeded bool
}

var errOutputLimit = errors.New("output limit exceeded")

func (b *boundedBuffer) Write(p []byte) (int, error) {
	room := b.limit - b.buf.Len()
	if b.exceeded || len(p) > room {
		b.exceeded = true
		b.buf.Write(p[:max(room, 0)])
		return max(room, 0), errOutputLimit
	}
	return b.buf.Write(p)
}

type commandError struct {
	name   string
	args   []string
	code   int    // exit status, or -1 if the process did not exit normally
	stderr []byte // raw, bounded by maxStderr; only excerpted in Error
	cause  error
}

func (e *commandError) Error() string {
	var b strings.Builder
	b.WriteString(ErrCommand.Error())
	b.WriteString(": ")
	b.WriteString(e.name)
	for _, a := range e.args {
		b.WriteByte(' ')
		b.WriteString(a)
	}
	fmt.Fprintf(&b, ": %v", e.cause)
	if s := excerpt(e.stderr); s != "" {
		b.WriteString(": stderr: ")
		b.WriteString(s)
	}
	return b.String()
}

func (e *commandError) Unwrap() []error { return []error{ErrCommand, e.cause} }

// excerpt returns at most maxExcerpt bytes of printable ASCII: whitespace
// runs collapse to one space and every other byte becomes '?', so command
// output cannot inject log lines or terminal escapes.
func excerpt(b []byte) string {
	out := make([]byte, 0, min(len(b), maxExcerpt+2))
	space := false
	for _, c := range b {
		if len(out) > maxExcerpt {
			break
		}
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			space = len(out) > 0
			continue
		case c < 0x20 || c > 0x7e:
			c = '?'
		}
		if space {
			out = append(out, ' ')
			space = false
		}
		out = append(out, c)
	}
	if len(out) > maxExcerpt {
		return string(out[:maxExcerpt-3]) + "..."
	}
	return string(out)
}

// exitStderr reports the exit status and raw stderr of a command failure.
func exitStderr(err error) (int, []byte, bool) {
	var ce *commandError
	if !errors.As(err, &ce) {
		return 0, nil, false
	}
	return ce.code, ce.stderr, true
}
