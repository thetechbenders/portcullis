package portal

// The functional guest portal. It is unprivileged and holds no authority:
// every decision is made by portcullisd from the guest's live TCP connection,
// which this handler passes to the controller unchanged. The portal never
// names a client, never synthesizes a granted state and never trusts any
// browser-supplied identity.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/thetechbenders/portcullis/internal/ipc"
)

// ErrConfig wraps every handler construction failure.
var ErrConfig = errors.New("invalid portal handler configuration")

const (
	defaultTimeout = 3 * time.Second
	maxTimeout     = 30 * time.Second
	maxHosts       = 32
)

// unreachableReason is shown when the controller cannot be asked. It says
// plainly that nothing is open.
const unreachableReason = "The access controller is not reachable. Access remains blocked."

// Controller is the privileged controller as seen by the portal. guest is the
// raw accepted guest connection for guest operations and nil for operator
// operations; the controller derives identity from it, never from req.
type Controller interface {
	Call(ctx context.Context, req ipc.Request, guest net.Conn) (ipc.Response, error)
}

type connContextKey struct{}

// ConnContext is installed as http.Server.ConnContext. It stores the raw
// accepted connection so handlers can hand the guest's own kernel socket to
// the controller instead of any address the request claims.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	if c == nil {
		return ctx
	}
	return context.WithValue(ctx, connContextKey{}, c)
}

func connFrom(ctx context.Context) net.Conn {
	c, _ := ctx.Value(connContextKey{}).(net.Conn)
	return c
}

// GuestConfig configures NewGuestHandler.
type GuestConfig struct {
	// AllowedHosts are lowercase hostnames or IPv4 literals the portal
	// answers as itself (DNS-rebinding defence: any other Host is foreign).
	AllowedHosts []string
	// PortalURL is the canonical http URL unauthorized requests redirect to.
	PortalURL string
	// ProbeHosts are operating-system captive-portal probe hostnames.
	ProbeHosts []string
	// Timeout bounds each controller call; zero selects 3s.
	Timeout time.Duration
	// Log receives controller failures; nil selects slog.Default(). Request
	// bodies and Host values are never logged.
	Log *slog.Logger
}

type guestHandler struct {
	allowed   map[string]bool
	probes    map[string]bool
	portalURL string
	port      string
	timeout   time.Duration
	c         Controller
	log       *slog.Logger
}

// NewGuestHandler returns the guest portal handler.
func NewGuestHandler(cfg GuestConfig, c Controller) (http.Handler, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil controller", ErrConfig)
	}
	h := &guestHandler{allowed: map[string]bool{}, probes: map[string]bool{}, c: c, log: cfg.Log}
	if h.log == nil {
		h.log = slog.Default()
	}
	switch {
	case cfg.Timeout == 0:
		h.timeout = defaultTimeout
	case cfg.Timeout < 0 || cfg.Timeout > maxTimeout:
		return nil, fmt.Errorf("%w: timeout must be within (0, %s]", ErrConfig, maxTimeout)
	default:
		h.timeout = cfg.Timeout
	}
	if len(cfg.AllowedHosts) == 0 || len(cfg.AllowedHosts) > maxHosts || len(cfg.ProbeHosts) > maxHosts {
		return nil, fmt.Errorf("%w: 1-%d allowed hosts and at most %d probe hosts required", ErrConfig, maxHosts, maxHosts)
	}
	for _, name := range cfg.AllowedHosts {
		host, port, ok := splitHost(name)
		if !ok || port != "" || host != name || h.allowed[name] || !(isIPv4Literal(name) || isHostname(name)) {
			return nil, fmt.Errorf("%w: invalid or duplicate allowed host %q", ErrConfig, name)
		}
		h.allowed[name] = true
	}
	for _, name := range cfg.ProbeHosts {
		host, port, ok := splitHost(name)
		if !ok || port != "" || host != name || !isHostname(name) || h.allowed[name] || h.probes[name] {
			return nil, fmt.Errorf("%w: invalid or duplicate probe host %q", ErrConfig, name)
		}
		h.probes[name] = true
	}
	u, err := url.Parse(cfg.PortalURL)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Opaque != "" || u.RawQuery != "" ||
		u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path[0] != '/') || !printableASCII(cfg.PortalURL) {
		return nil, fmt.Errorf("%w: portal URL must be a plain http URL", ErrConfig)
	}
	host, port, ok := splitHost(u.Host)
	if !ok || !h.allowed[host] {
		return nil, fmt.Errorf("%w: portal URL host must be an allowed host", ErrConfig)
	}
	if port == "" {
		port = "80"
	}
	h.portalURL, h.port = cfg.PortalURL, port
	return h, nil
}

func isIPv4Literal(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is4() && a.String() == s
}

func isHostname(s string) bool {
	_, err := netip.ParseAddr(s)
	return err != nil && hostnamePattern.MatchString(s)
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] >= 0x7f {
			return false
		}
	}
	return s != ""
}

func (h *guestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hardenResponse(w)
	host, port, ok := splitHost(r.Host)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_request", "Malformed Host header.")
		return
	}
	ours := port == h.port || (port == "" && h.port == "80")
	switch {
	case ours && h.allowed[host]:
		h.servePortal(w, r)
	case ours && h.probes[host]:
		h.serveProbe(w, r, host)
	case r.Method == http.MethodGet || r.Method == http.MethodHead:
		// Foreign names (including DNS-rebinding attempts) are never served
		// as the portal; the Host value is never echoed.
		h.redirect(w)
	default:
		writeError(w, http.StatusForbidden, "forbidden", "This host is not served here.")
	}
}

func (h *guestHandler) redirect(w http.ResponseWriter) {
	w.Header().Set("Location", h.portalURL)
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusFound)
}

func (h *guestHandler) servePortal(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/":
		serveAsset(w, r, assetGuestHTML)
	case "/assets/guest.css":
		serveAsset(w, r, assetGuestCSS)
	case "/assets/guest.js":
		serveAsset(w, r, assetGuestJS)
	case "/assets/icon.svg":
		serveAsset(w, r, assetIcon)
	case "/api/session":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		if v := r.Header.Values("Sec-Fetch-Site"); len(v) > 0 && (len(v) != 1 || (v[0] != "same-origin" && v[0] != "none")) {
			writeError(w, http.StatusForbidden, "forbidden", "Cross-site request refused.")
			return
		}
		h.call(w, r, ipc.Request{Op: ipc.OpStatus})
	case "/api/access":
		var body struct {
			DurationSeconds int `json:"duration_seconds"`
		}
		if !h.mutation(w, r, &body, "duration_seconds") {
			return
		}
		if body.DurationSeconds < 0 {
			writeError(w, http.StatusBadRequest, "bad_request", "Duration must not be negative.")
			return
		}
		h.call(w, r, ipc.Request{Op: ipc.OpRequest, DurationSeconds: body.DurationSeconds})
	case "/api/release":
		var body struct{}
		if !h.mutation(w, r, &body) {
			return
		}
		h.call(w, r, ipc.Request{Op: ipc.OpRelease})
	default:
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
	}
}

// mutation applies the POST protections; false means a response was written
// and the controller must not be called.
func (h *guestHandler) mutation(w http.ResponseWriter, r *http.Request, body any, fields ...string) bool {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return false
	}
	if rej := checkBrowserMutation(r); rej != nil {
		rej.write(w)
		return false
	}
	if rej := readStrictBody(w, r, body, fields...); rej != nil {
		rej.write(w)
		return false
	}
	return true
}

func unreachableSession() *ipc.Session {
	return &ipc.Session{State: ipc.StateUnavailable, Reason: unreachableReason}
}

func knownState(s ipc.State) bool {
	switch s {
	case ipc.StateUnrecognized, ipc.StateAmbiguous, ipc.StateDenied, ipc.StateGranted, ipc.StateRevoked, ipc.StateUnavailable:
		return true
	}
	return false
}

// call forwards one guest operation with the request's own connection and
// relays the controller's answer. Without the connection it fails closed:
// the controller is never asked to act for an unidentified guest.
func (h *guestHandler) call(w http.ResponseWriter, r *http.Request, req ipc.Request) {
	conn := connFrom(r.Context())
	if conn == nil {
		h.log.Error("guest request without its connection; refusing", "op", req.Op)
		writeJSON(w, http.StatusInternalServerError, envelope{Error: string(ipc.ErrInternal),
			Message: "The portal could not identify this connection.", Session: unreachableSession()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	resp, err := h.c.Call(ctx, req, conn)
	if err != nil {
		// Whatever the response carried, an error means the controller's
		// answer is unknown: report unavailable, never granted.
		h.log.Warn("controller call failed", "op", req.Op, "err", err)
		writeJSON(w, http.StatusServiceUnavailable, envelope{Error: string(ipc.ErrUnavailable),
			Message: unreachableReason, Session: unreachableSession()})
		return
	}
	var session *ipc.Session
	if resp.Session != nil {
		if !knownState(resp.Session.State) {
			writeError(w, http.StatusBadGateway, string(ipc.ErrInternal), "The controller returned an unrecognized state.")
			return
		}
		s := *resp.Session
		s.Reason = clip(s.Reason, 512)
		s.ClientAddress = clip(s.ClientAddress, 64)
		s.ClientMACHint = clip(s.ClientMACHint, 64)
		session = &s
	}
	if resp.OK {
		if session == nil {
			writeError(w, http.StatusBadGateway, string(ipc.ErrInternal), "The controller returned no session.")
			return
		}
		writeJSON(w, http.StatusOK, envelope{OK: true, Session: session})
		return
	}
	status, code := http.StatusBadGateway, string(ipc.ErrInternal)
	if s, ok := statusFor[resp.Error]; ok {
		status, code = s, string(resp.Error)
	}
	if resp.Error == ipc.ErrRateLimited && session != nil && session.RetryAfterSeconds > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(session.RetryAfterSeconds))
	}
	writeJSON(w, status, envelope{Error: code, Message: clip(resp.Message, 256), Session: session})
}

// probeSuccess holds each platform's expected "online" answer.
var probeSuccess = map[string]struct {
	status      int
	contentType string
	body        string
}{
	"captive.apple.com":             {http.StatusOK, "text/html; charset=utf-8", "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"},
	"connectivitycheck.gstatic.com": {http.StatusNoContent, "", ""},
	"clients3.google.com":           {http.StatusNoContent, "", ""},
	"connectivitycheck.android.com": {http.StatusNoContent, "", ""},
	"www.msftconnecttest.com":       {http.StatusOK, "text/plain; charset=utf-8", "Microsoft Connect Test"},
	"detectportal.firefox.com":      {http.StatusOK, "text/plain; charset=utf-8", "success\n"},
	"nmcheck.gnome.org":             {http.StatusOK, "text/plain; charset=utf-8", "NetworkManager is online\n"},
}

// serveProbe answers OS captive-portal checks: the platform's success
// response only when the controller reports an effective kernel grant, and
// a redirect to the portal for every other state or failure.
func (h *guestHandler) serveProbe(w http.ResponseWriter, r *http.Request, host string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, "GET, HEAD")
		return
	}
	conn := connFrom(r.Context())
	if conn == nil {
		h.redirect(w)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	resp, err := h.c.Call(ctx, ipc.Request{Op: ipc.OpStatus}, conn)
	if err != nil || !resp.OK || resp.Session == nil || resp.Session.State != ipc.StateGranted {
		h.redirect(w)
		return
	}
	ok, known := probeSuccess[host]
	if !known {
		ok.status = http.StatusNoContent
	}
	if ok.contentType != "" {
		w.Header().Set("Content-Type", ok.contentType)
		w.Header().Set("Content-Length", strconv.Itoa(len(ok.body)))
	}
	w.WriteHeader(ok.status)
	if r.Method == http.MethodGet && ok.body != "" {
		_, _ = w.Write([]byte(ok.body))
	}
}
