//go:build linux

package ipc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	// ErrPeer rejects a control client whose kernel credentials (SO_PEERCRED)
	// are not authorized for the socket.
	ErrPeer = errors.New("ipc: control socket peer not authorized")
	// ErrDescriptor rejects missing, extra or invalid SCM_RIGHTS descriptors.
	ErrDescriptor = errors.New("ipc: guest connection descriptor rejected")
	// ErrMessage rejects malformed, oversized or truncated control messages.
	ErrMessage = errors.New("ipc: malformed or oversized control message")
	// ErrConfig rejects an unsafe or inconsistent ServerConfig.
	ErrConfig = errors.New("ipc: invalid control socket configuration")
)

const (
	defaultMaxConns = 32
	maxMaxConns     = 1024
	defaultTimeout  = 3 * time.Second
	maxTimeout      = 60 * time.Second
	callTimeout     = 5 * time.Second
	shutdownGrace   = time.Second
	maxSocketPath   = 107 // sun_path is 108 bytes including the NUL terminator
)

var (
	guestOps    = map[Op]bool{OpStatus: true, OpRequest: true, OpRelease: true}
	operatorOps = map[Op]bool{OpSnapshot: true, OpRevoke: true, OpReset: true}
	// requestFields is derived from Request's JSON tags so the exact-key
	// check below cannot drift from the frozen protocol type.
	requestFields = jsonFieldNames(reflect.TypeOf(Request{}))
	errTooLarge   = fmt.Errorf("%w: exceeds %d bytes", ErrMessage, MaxMessageBytes)
)

// ServerConfig describes one control socket.
type ServerConfig struct {
	Path string
	// Mode is applied with chmod after listen (0666 guest, 0600 operator).
	// It is defence in depth only: SO_PEERCRED is the authorization check.
	Mode os.FileMode
	// AllowedUIDs lists the peer uids accepted; an empty list rejects all.
	AllowedUIDs []uint32
	// Guest requires exactly one SCM_RIGHTS descriptor per request; when
	// false any descriptor is rejected (and closed).
	Guest bool
	// PortalAddr is required when Guest: the received socket's local
	// address must equal it exactly.
	PortalAddr netip.AddrPort
	// Ops are the operations accepted on this socket. Guest sockets may
	// only list guest operations and operator sockets operator operations.
	Ops []Op
	// MaxConns bounds concurrent connections (default 32); excess
	// connections are closed immediately without being read.
	MaxConns int
	// Timeout is the whole-exchange deadline per connection (default 3s).
	Timeout time.Duration
	// Log receives rejection reasons (never payloads); nil uses slog.Default.
	Log *slog.Logger
}

func (cfg ServerConfig) normalize() (ServerConfig, map[Op]bool, error) {
	bad := func(format string, args ...any) (ServerConfig, map[Op]bool, error) {
		return ServerConfig{}, nil, fmt.Errorf("%w: %s", ErrConfig, fmt.Sprintf(format, args...))
	}
	if !filepath.IsAbs(cfg.Path) || filepath.Clean(cfg.Path) != cfg.Path || len(cfg.Path) > maxSocketPath ||
		strings.ContainsAny(cfg.Path, "\x00\n") {
		return bad("socket path must be a clean absolute path of at most %d bytes", maxSocketPath)
	}
	if cfg.Mode == 0 || cfg.Mode&^os.ModePerm != 0 {
		return bad("socket mode must be non-zero permission bits only")
	}
	if cfg.Guest {
		if !cfg.PortalAddr.IsValid() || !cfg.PortalAddr.Addr().Is4() || cfg.PortalAddr.Port() == 0 {
			return bad("guest socket requires an IPv4 portal address with a port")
		}
	} else if cfg.PortalAddr.IsValid() {
		return bad("operator socket must not name a portal address")
	}
	allowed := operatorOps
	if cfg.Guest {
		allowed = guestOps
	}
	if len(cfg.Ops) == 0 {
		return bad("no operations configured")
	}
	ops := make(map[Op]bool, len(cfg.Ops))
	for _, op := range cfg.Ops {
		if !allowed[op] {
			return bad("operation %q is not valid on this socket kind", op)
		}
		ops[op] = true
	}
	switch {
	case cfg.MaxConns < 0 || cfg.MaxConns > maxMaxConns:
		return bad("max connections must be 0..%d", maxMaxConns)
	case cfg.MaxConns == 0:
		cfg.MaxConns = defaultMaxConns
	}
	switch {
	case cfg.Timeout < 0 || cfg.Timeout > maxTimeout:
		return bad("timeout must be 0..%s", maxTimeout)
	case cfg.Timeout == 0:
		cfg.Timeout = defaultTimeout
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	cfg.AllowedUIDs = append([]uint32(nil), cfg.AllowedUIDs...)
	return cfg, ops, nil
}

// Server is one listening control socket.
type Server struct {
	cfg      ServerConfig
	ops      map[Op]bool
	ln       *net.UnixListener
	created  fs.FileInfo
	sem      chan struct{}
	closed   atomic.Bool
	serving  atomic.Bool
	once     sync.Once
	closeErr error
}

// Listen validates cfg and creates the socket. The parent directory must
// be a real directory owned by root or this process's euid and not group-
// or world-writable, so no other user can replace the socket path. A stale
// file at Path is removed only if it is a socket nobody is listening on;
// regular files, directories and symlinks are never removed.
func Listen(cfg ServerConfig) (*Server, error) {
	cfg, ops, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	if err := checkSocketDir(filepath.Dir(cfg.Path)); err != nil {
		return nil, err
	}
	if err := removeStaleSocket(cfg.Path); err != nil {
		return nil, err
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: cfg.Path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("ipc: listen %s: %w", cfg.Path, err)
	}
	// We unlink ourselves, and only the inode we created (see Close).
	ln.SetUnlinkOnClose(false)
	s := &Server{cfg: cfg, ops: ops, ln: ln, sem: make(chan struct{}, cfg.MaxConns)}
	info, err := os.Lstat(cfg.Path)
	if err != nil || info.Mode().Type() != fs.ModeSocket {
		ln.Close()
		return nil, fmt.Errorf("%w: socket path changed during listen", ErrConfig)
	}
	s.created = info
	if err := os.Chmod(cfg.Path, cfg.Mode); err != nil {
		s.Close()
		return nil, fmt.Errorf("ipc: chmod %s: %w", cfg.Path, err)
	}
	if info, err := os.Lstat(cfg.Path); err != nil || !os.SameFile(info, s.created) || info.Mode().Perm() != cfg.Mode {
		s.Close()
		return nil, fmt.Errorf("%w: socket mode could not be verified", ErrConfig)
	}
	return s, nil
}

func checkSocketDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("%w: socket directory: %v", ErrConfig, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: socket directory %s is not a directory", ErrConfig, dir)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: socket directory %s is group- or world-writable", ErrConfig, dir)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (st.Uid != 0 && int(st.Uid) != os.Geteuid()) {
		return fmt.Errorf("%w: socket directory %s must be owned by root or the server user", ErrConfig, dir)
	}
	return nil
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("ipc: inspect %s: %w", path, err)
	}
	if info.Mode().Type() != fs.ModeSocket {
		return fmt.Errorf("%w: refusing to replace non-socket file at %s", ErrConfig, path)
	}
	// A socket with a live listener belongs to another running instance.
	c, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err == nil {
		c.Close()
		return fmt.Errorf("%w: socket %s is in use", ErrConfig, path)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("%w: cannot determine whether %s is stale: %v", ErrConfig, path, err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("ipc: remove stale socket %s: %w", path, err)
	}
	return nil
}

// Close stops accepting, and removes the socket file if it is still the
// one this server created. It is idempotent.
func (s *Server) Close() error {
	s.once.Do(func() {
		s.closed.Store(true)
		s.closeErr = s.ln.Close()
		if info, err := os.Lstat(s.cfg.Path); err == nil && s.created != nil && os.SameFile(info, s.created) {
			_ = os.Remove(s.cfg.Path)
		}
	})
	return s.closeErr
}

// Serve accepts connections until ctx is cancelled or Close is called,
// then waits (bounded) for in-flight connections and returns nil. Handler
// contexts derive from ctx, so cancellation reaches in-flight requests.
func (s *Server) Serve(ctx context.Context, h Handler) error {
	if h == nil {
		return errors.New("ipc: nil handler")
	}
	if !s.serving.CompareAndSwap(false, true) {
		return errors.New("ipc: Serve called more than once")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { s.Close() })
	defer stop()

	var wg sync.WaitGroup
	var loopErr error
	backoff := 5 * time.Millisecond
	for {
		conn, err := s.ln.AcceptUnix()
		if err != nil {
			if s.closed.Load() {
				break
			}
			if isTransientAccept(err) {
				select {
				case <-time.After(backoff):
				case <-ctx.Done():
				}
				backoff = min(2*backoff, time.Second)
				continue
			}
			loopErr = fmt.Errorf("ipc: accept: %w", err)
			break
		}
		backoff = 5 * time.Millisecond
		select {
		case s.sem <- struct{}{}:
		default:
			conn.Close()
			s.cfg.Log.Debug("ipc: connection limit reached", "socket", s.cfg.Path)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-s.sem }()
			s.serveConn(ctx, conn, h)
		}()
	}
	cancel()
	s.Close()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(s.cfg.Timeout + shutdownGrace):
		if loopErr == nil {
			loopErr = errors.New("ipc: in-flight connections did not finish before shutdown grace")
		}
	}
	return loopErr
}

func isTransientAccept(err error) bool {
	for _, e := range []error{syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM, syscall.ECONNABORTED, syscall.EINTR} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

func failure(code ErrorCode, message string) Response {
	return Response{OK: false, Error: code, Message: message}
}

func (s *Server) serveConn(ctx context.Context, conn *net.UnixConn, h Handler) {
	defer conn.Close()
	deadline := time.Now().Add(s.cfg.Timeout)
	if conn.SetDeadline(deadline) != nil {
		return
	}
	reject := func(resp Response, reason error, peer Peer) {
		s.cfg.Log.Warn("ipc: rejected control request", "socket", s.cfg.Path, "uid", peer.UID, "pid", peer.PID, "reason", reason)
		writeResponse(conn, resp)
	}

	// Authorization happens before a single byte (or descriptor) is read.
	peer, err := peerCredentials(conn)
	if err != nil {
		s.cfg.Log.Warn("ipc: peer credentials unavailable", "socket", s.cfg.Path, "err", err)
		return
	}
	if !s.uidAllowed(peer.UID) {
		reject(failure(ErrForbidden, "control socket peer is not authorized"), ErrPeer, peer)
		return
	}

	maxFDs := 0
	if s.cfg.Guest {
		maxFDs = 1
	}
	body, fds, err := receiveMessage(conn, maxFDs)
	if err != nil {
		switch {
		case errors.Is(err, ErrDescriptor):
			reject(failure(ErrForbidden, "guest connection descriptor rejected"), err, peer)
		case errors.Is(err, errTooLarge):
			reject(failure(ErrBadRequest, "control request too large"), err, peer)
		default:
			s.cfg.Log.Debug("ipc: control read failed", "socket", s.cfg.Path, "err", err)
		}
		return
	}
	// Every received descriptor is closed exactly once: right after
	// validation on the success path, or by this defer on any other path.
	release := func() {
		for _, fd := range fds {
			syscall.Close(fd)
		}
		fds = nil
	}
	defer release()
	if s.cfg.Guest && len(fds) != 1 {
		reject(failure(ErrForbidden, "guest connection descriptor rejected"), fmt.Errorf("%w: exactly one descriptor required", ErrDescriptor), peer)
		return
	}

	req, err := decodeRequest(body)
	if err != nil {
		reject(failure(ErrBadRequest, "malformed control request"), err, peer)
		return
	}
	if !s.ops[req.Op] {
		reject(failure(ErrForbidden, "operation not permitted on this socket"), fmt.Errorf("op %q not allowed", string(req.Op)), peer)
		return
	}
	var guest *GuestConn
	if s.cfg.Guest {
		gc, err := ValidateGuestFD(fds[0], s.cfg.PortalAddr)
		release()
		if err != nil {
			reject(failure(ErrForbidden, "guest connection descriptor rejected"), err, peer)
			return
		}
		guest = &gc
	}
	hctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	writeResponse(conn, s.invoke(hctx, h, peer, req, guest))
}

func (s *Server) uidAllowed(uid uint32) bool {
	for _, allowed := range s.cfg.AllowedUIDs {
		if uid == allowed {
			return true
		}
	}
	return false
}

func (s *Server) invoke(ctx context.Context, h Handler, peer Peer, req Request, guest *GuestConn) (resp Response) {
	defer func() {
		if r := recover(); r != nil {
			s.cfg.Log.Error("ipc: handler panic", "socket", s.cfg.Path, "op", string(req.Op), "panic", fmt.Sprint(r))
			resp = failure(ErrInternal, "internal controller error")
		}
	}()
	return h.Handle(ctx, peer, req, guest)
}

func writeResponse(conn *net.UnixConn, resp Response) {
	data, err := json.Marshal(resp)
	if err != nil || len(data) > MaxResponseBytes {
		data, _ = json.Marshal(failure(ErrInternal, "response exceeds control message limit"))
	}
	_, _ = conn.Write(data)
}

// receiveMessage reads the whole request (until the client half-closes)
// with recvmsg so descriptors attached to any chunk are seen. The control
// buffer holds two descriptors, so a second one is detectable; more set
// MSG_CTRUNC. On error every received descriptor is already closed.
func receiveMessage(conn *net.UnixConn, maxFDs int) (body []byte, fds []int, err error) {
	defer func() {
		if err != nil {
			for _, fd := range fds {
				syscall.Close(fd)
			}
			fds = nil
		}
	}()
	buf := make([]byte, MaxMessageBytes+1)
	oob := make([]byte, syscall.CmsgSpace(2*4))
	total := 0
	for {
		if total == len(buf) {
			return nil, fds, errTooLarge
		}
		n, oobn, flags, _, rerr := conn.ReadMsgUnix(buf[total:], oob)
		if oobn > 0 {
			got, perr := parseRights(oob[:oobn])
			fds = append(fds, got...)
			if perr != nil {
				return nil, fds, perr
			}
		}
		if flags&syscall.MSG_CTRUNC != 0 {
			return nil, fds, fmt.Errorf("%w: control data truncated", ErrDescriptor)
		}
		if len(fds) > maxFDs {
			return nil, fds, fmt.Errorf("%w: %d descriptors received, at most %d allowed", ErrDescriptor, len(fds), maxFDs)
		}
		total += n
		if errors.Is(rerr, io.EOF) {
			return buf[:total], fds, nil
		}
		if rerr != nil {
			return nil, fds, fmt.Errorf("%w: read: %v", ErrMessage, rerr)
		}
	}
}

// parseRights extracts SCM_RIGHTS descriptors. Go's ReadMsgUnix passes
// MSG_CMSG_CLOEXEC on Linux (net/unixsock_readmsg_cmsg_cloexec.go), so the
// descriptors are close-on-exec atomically; CloseOnExec is belt and braces
// so nft/ip/conntrack children can never inherit a guest socket.
func parseRights(oob []byte) ([]int, error) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, fmt.Errorf("%w: control message: %v", ErrDescriptor, err)
	}
	var fds []int
	var bad error
	for i := range msgs {
		if msgs[i].Header.Level != syscall.SOL_SOCKET || msgs[i].Header.Type != syscall.SCM_RIGHTS {
			bad = fmt.Errorf("%w: unexpected control message", ErrDescriptor)
			continue
		}
		got, err := syscall.ParseUnixRights(&msgs[i])
		if err != nil {
			bad = fmt.Errorf("%w: rights: %v", ErrDescriptor, err)
			continue
		}
		for _, fd := range got {
			syscall.CloseOnExec(fd)
		}
		fds = append(fds, got...)
	}
	return fds, bad
}

func peerCredentials(conn *net.UnixConn) (Peer, error) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return Peer{}, fmt.Errorf("%w: %v", ErrPeer, err)
	}
	var cred *syscall.Ucred
	var cerr error
	if err := rc.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return Peer{}, fmt.Errorf("%w: %v", ErrPeer, err)
	}
	if cerr != nil {
		return Peer{}, fmt.Errorf("%w: SO_PEERCRED: %v", ErrPeer, cerr)
	}
	return Peer{UID: cred.Uid, GID: cred.Gid, PID: cred.Pid}, nil
}

// decodeRequest is strict: one JSON object whose keys are exactly
// Request's JSON names (case-sensitive, no duplicates), then the typed
// decode with unknown fields disallowed and no trailing data. Errors are
// fixed text so attacker-controlled bytes are never logged.
func decodeRequest(body []byte) (Request, error) {
	malformed := fmt.Errorf("%w: invalid request JSON", ErrMessage)
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return Request{}, malformed
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		key, ok := tok.(string)
		if err != nil || !ok || !requestFields[key] || seen[key] {
			return Request{}, fmt.Errorf("%w: unknown or duplicate field", ErrMessage)
		}
		seen[key] = true
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return Request{}, malformed
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return Request{}, malformed
	}
	if _, err := dec.Token(); err != io.EOF {
		return Request{}, fmt.Errorf("%w: trailing data", ErrMessage)
	}
	strict := json.NewDecoder(bytes.NewReader(body))
	strict.DisallowUnknownFields()
	var req Request
	if err := strict.Decode(&req); err != nil {
		return Request{}, malformed
	}
	return req, nil
}

func jsonFieldNames(t reflect.Type) map[string]bool {
	names := map[string]bool{}
	for i := range t.NumField() {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = t.Field(i).Name
		}
		names[name] = true
	}
	return names
}

// Call performs one request on the control socket at path. When guest is
// non-nil its descriptor is sent with SCM_RIGHTS in the same sendmsg as
// the first payload bytes, inside RawConn.Control so the descriptor cannot
// be closed and reused concurrently. Responses are read with plain reads,
// so any descriptors a server might attach are discarded by the kernel.
func Call(ctx context.Context, path string, req Request, guest net.Conn) (Response, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return Response{}, fmt.Errorf("%w: encode: %v", ErrMessage, err)
	}
	if len(payload) > MaxMessageBytes {
		return Response{}, errTooLarge
	}
	var rc syscall.RawConn
	if guest != nil {
		sc, ok := guest.(syscall.Conn)
		if !ok {
			return Response{}, fmt.Errorf("%w: guest connection has no descriptor", ErrDescriptor)
		}
		if rc, err = sc.SyscallConn(); err != nil {
			return Response{}, fmt.Errorf("%w: %v", ErrDescriptor, err)
		}
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(callTimeout)
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return Response{}, fmt.Errorf("ipc: dial %s: %w", path, err)
	}
	conn := c.(*net.UnixConn)
	defer conn.Close()
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	if rc != nil {
		n := 0
		var werr error
		if cerr := rc.Control(func(fd uintptr) {
			n, _, werr = conn.WriteMsgUnix(payload, syscall.UnixRights(int(fd)), nil)
		}); cerr != nil {
			return Response{}, fmt.Errorf("%w: %v", ErrDescriptor, cerr)
		}
		if werr == nil && n < len(payload) {
			_, werr = conn.Write(payload[n:])
		}
		if werr != nil {
			return Response{}, fmt.Errorf("ipc: send: %w", werr)
		}
	} else if _, err := conn.Write(payload); err != nil {
		return Response{}, fmt.Errorf("ipc: send: %w", err)
	}
	if err := conn.CloseWrite(); err != nil {
		return Response{}, fmt.Errorf("ipc: close write: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(conn, MaxResponseBytes+1))
	// A server that rejects before reading closes with our request unread;
	// Linux then reports ECONNRESET after the queued response.
	if err != nil && !(errors.Is(err, syscall.ECONNRESET) && len(data) > 0) {
		if ctx.Err() != nil {
			return Response{}, fmt.Errorf("ipc: %w", ctx.Err())
		}
		return Response{}, fmt.Errorf("ipc: receive: %w", err)
	}
	if len(data) > MaxResponseBytes {
		return Response{}, fmt.Errorf("%w: response exceeds %d bytes", ErrMessage, MaxResponseBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var resp Response
	if err := dec.Decode(&resp); err != nil {
		return Response{}, fmt.Errorf("%w: response: %v", ErrMessage, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return Response{}, fmt.Errorf("%w: trailing response data", ErrMessage)
	}
	return resp, nil
}
