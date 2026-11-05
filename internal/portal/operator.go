package portal

// The loopback operator dashboard. Static assets carry no data; every API
// call requires the bearer token and is forwarded over the root-only
// operator socket without any guest connection.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/thetechbenders/portcullis/internal/ipc"
	"github.com/thetechbenders/portcullis/internal/model"
)

const (
	minTokenBytes = 32
	maxTokenBytes = 512
)

type operatorHandler struct {
	c        Controller
	tokenSum [sha256.Size]byte
	timeout  time.Duration
	log      *slog.Logger
}

// NewOperatorHandler returns the operator dashboard handler. token must be
// 32-512 visible ASCII bytes.
func NewOperatorHandler(c Controller, token string) (http.Handler, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil controller", ErrConfig)
	}
	if len(token) < minTokenBytes || len(token) > maxTokenBytes || !printableASCII(token) {
		return nil, fmt.Errorf("%w: token must be %d-%d visible ASCII characters", ErrConfig, minTokenBytes, maxTokenBytes)
	}
	return &operatorHandler{c: c, tokenSum: sha256.Sum256([]byte(token)), timeout: 5 * time.Second, log: slog.Default()}, nil
}

// loopbackRequest requires both a loopback listener and a loopback Host
// naming that listener's port, so the dashboard cannot be reached through
// a rebinding name or an accidentally non-loopback listener.
func loopbackRequest(r *http.Request) bool {
	var local netip.AddrPort
	switch a := r.Context().Value(http.LocalAddrContextKey).(type) {
	case *net.TCPAddr:
		local = a.AddrPort()
	default:
		return false
	}
	if !local.Addr().Unmap().IsLoopback() {
		return false
	}
	host, port, ok := splitHost(r.Host)
	if !ok || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
		return false
	}
	want := strconv.Itoa(int(local.Port()))
	if port == "" {
		return want == "80"
	}
	return port == want
}

// authorized compares SHA-256 digests in constant time so neither the
// token's content nor its length is revealed through timing.
func (o *operatorHandler) authorized(r *http.Request) bool {
	v := r.Header.Values("Authorization")
	if len(v) != 1 {
		return false
	}
	scheme, cred, ok := strings.Cut(v[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return false
	}
	sum := sha256.Sum256([]byte(cred))
	return subtle.ConstantTimeCompare(sum[:], o.tokenSum[:]) == 1
}

func (o *operatorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hardenResponse(w)
	if !loopbackRequest(r) {
		writeError(w, http.StatusForbidden, "forbidden", "The operator dashboard only answers loopback requests.")
		return
	}
	var method string
	switch r.URL.Path {
	case "/":
		serveAsset(w, r, assetOperatorHTML)
		return
	case "/assets/operator.css":
		serveAsset(w, r, assetOperatorCSS)
		return
	case "/assets/operator.js":
		serveAsset(w, r, assetOperatorJS)
		return
	case "/assets/icon.svg":
		serveAsset(w, r, assetIcon)
		return
	case "/api/snapshot":
		method = http.MethodGet
	case "/api/revoke", "/api/reset":
		method = http.MethodPost
	default:
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
		return
	}
	if r.Method != method {
		methodNotAllowed(w, method)
		return
	}
	if !o.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="portcullis-operator"`)
		writeError(w, http.StatusUnauthorized, "unauthorized", "A valid dashboard token is required.")
		return
	}
	req := ipc.Request{Op: ipc.OpSnapshot}
	if method == http.MethodPost {
		if rej := checkBrowserMutation(r); rej != nil {
			rej.write(w)
			return
		}
		if r.URL.Path == "/api/revoke" {
			var body struct {
				MAC string `json:"mac"`
			}
			if rej := readStrictBody(w, r, &body, "mac"); rej != nil {
				rej.write(w)
				return
			}
			mac, err := model.ParseMAC(body.MAC)
			if err != nil {
				writeError(w, http.StatusBadRequest, string(ipc.ErrBadRequest), "mac must be a unicast Ethernet address.")
				return
			}
			req = ipc.Request{Op: ipc.OpRevoke, Target: mac.String()}
		} else {
			var body struct{}
			if rej := readStrictBody(w, r, &body); rej != nil {
				rej.write(w)
				return
			}
			req = ipc.Request{Op: ipc.OpReset}
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), o.timeout)
	defer cancel()
	// Operator calls never carry a guest connection.
	resp, err := o.c.Call(ctx, req, nil)
	if err != nil {
		o.log.Warn("operator controller call failed", "op", req.Op, "err", err)
		writeError(w, http.StatusServiceUnavailable, string(ipc.ErrUnavailable), "The controller is not reachable.")
		return
	}
	if resp.OK {
		if req.Op == ipc.OpSnapshot && resp.Snapshot == nil {
			writeError(w, http.StatusBadGateway, string(ipc.ErrInternal), "The controller returned no snapshot.")
			return
		}
		writeJSON(w, http.StatusOK, envelope{OK: true, Message: clip(resp.Message, 256), Snapshot: resp.Snapshot})
		return
	}
	status, code := http.StatusBadGateway, string(ipc.ErrInternal)
	if s, ok := statusFor[resp.Error]; ok {
		status, code = s, string(resp.Error)
	}
	writeError(w, status, code, clip(resp.Message, 256))
}
