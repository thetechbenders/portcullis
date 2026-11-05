package portal

// Shared HTTP hardening for the guest portal and the operator dashboard:
// response headers, the JSON envelope, Host parsing, browser-mutation
// (CSRF) checks, strict JSON bodies and embedded static assets.

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/thetechbenders/portcullis/internal/ipc"
)

// contentSecurityPolicy permits only same-origin scripts, styles and API
// calls. No inline script or style is allowed, so injected markup cannot
// execute even if a rendering bug slipped through.
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// maxBodyBytes bounds every browser POST body.
const maxBodyBytes = 1024

// hardenResponse sets the security headers carried by every response,
// including errors and redirects. No response ever sets a cookie.
func hardenResponse(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	h.Set("Content-Security-Policy", contentSecurityPolicy)
}

// envelope is the JSON shape of every API response.
type envelope struct {
	OK       bool          `json:"ok"`
	Error    string        `json:"error,omitempty"`
	Message  string        `json:"message,omitempty"`
	Session  *ipc.Session  `json:"session,omitempty"`
	Snapshot *ipc.Snapshot `json:"snapshot,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, body envelope) {
	data, err := json.Marshal(body)
	if err != nil {
		status, data = http.StatusInternalServerError, []byte(`{"ok":false,"error":"internal"}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, envelope{Error: code, Message: message})
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
}

// statusFor maps controller error codes to HTTP statuses.
var statusFor = map[ipc.ErrorCode]int{
	ipc.ErrBadRequest:  http.StatusBadRequest,
	ipc.ErrForbidden:   http.StatusForbidden,
	ipc.ErrIdentity:    http.StatusForbidden,
	ipc.ErrConflict:    http.StatusConflict,
	ipc.ErrRateLimited: http.StatusTooManyRequests,
	ipc.ErrUnavailable: http.StatusServiceUnavailable,
	ipc.ErrInternal:    http.StatusBadGateway,
}

// clip bounds a relayed string and forces valid UTF-8.
func clip(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

var hostnamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// splitHost parses a Host header value into a lowercase host (IPv6 without
// brackets) and an optional canonical decimal port. Anything that is not
// plain ASCII hostname, IPv4 or bracketed IPv6 syntax is malformed. ASCII
// is checked before lowercasing because Unicode case folding maps some
// non-ASCII runes (for example U+212A KELVIN SIGN) onto ASCII letters.
func splitHost(raw string) (host, port string, ok bool) {
	if raw == "" || len(raw) > 260 {
		return "", "", false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] <= ' ' || raw[i] >= 0x7f {
			return "", "", false
		}
	}
	if strings.HasPrefix(raw, "[") {
		end := strings.IndexByte(raw, ']')
		if end < 0 {
			return "", "", false
		}
		addr, err := netip.ParseAddr(raw[1:end])
		if err != nil || !addr.Is6() || addr.Zone() != "" {
			return "", "", false
		}
		if rest := raw[end+1:]; rest != "" {
			if rest[0] != ':' || !validPort(rest[1:]) {
				return "", "", false
			}
			port = rest[1:]
		}
		return addr.String(), port, true
	}
	host = raw
	if i := strings.LastIndexByte(raw, ':'); i >= 0 {
		host, port = raw[:i], raw[i+1:]
		if !validPort(port) {
			return "", "", false
		}
	}
	host = strings.ToLower(host)
	// A single trailing dot (absolute FQDN) is well-formed; it simply never
	// matches a configured name, so such requests are treated as foreign.
	if len(host) > 254 || !hostnamePattern.MatchString(strings.TrimSuffix(host, ".")) {
		return "", "", false
	}
	return host, port, true
}

func validPort(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n >= 1 && n <= 65535 && strconv.Itoa(n) == s
}

// rejection is a request refused before any controller call.
type rejection struct {
	status        int
	code, message string
}

func (r *rejection) write(w http.ResponseWriter) { writeError(w, r.status, r.code, r.message) }

// checkBrowserMutation enforces the CSRF and DNS-rebinding defences shared
// by every POST: a JSON content type (which a cross-site HTML form cannot
// send), a custom header (which forces a CORS preflight we never answer), an
// Origin equal to the served Host, and same-origin fetch metadata when the
// browser reports it. The caller has already checked that Host is allowed.
func checkBrowserMutation(r *http.Request) *rejection {
	ct := r.Header.Values("Content-Type")
	if len(ct) != 1 {
		return &rejection{http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json."}
	}
	mt, params, err := mime.ParseMediaType(ct[0])
	if err != nil || mt != "application/json" {
		return &rejection{http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json."}
	}
	for k, v := range params {
		if k != "charset" || !strings.EqualFold(v, "utf-8") {
			return &rejection{http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json."}
		}
	}
	if v := r.Header.Values("X-Portcullis-Request"); len(v) != 1 || v[0] != "1" {
		return &rejection{http.StatusForbidden, "forbidden", "Missing request header."}
	}
	if v := r.Header.Values("Origin"); len(v) != 1 || v[0] != "http://"+r.Host {
		return &rejection{http.StatusForbidden, "forbidden", "Cross-origin request refused."}
	}
	if v := r.Header.Values("Sec-Fetch-Site"); len(v) > 0 && (len(v) != 1 || v[0] != "same-origin") {
		return &rejection{http.StatusForbidden, "forbidden", "Cross-site request refused."}
	}
	return nil
}

// readStrictBody reads a bounded JSON object whose top-level keys are a
// subset of fields (exact case, no duplicates, scalar non-null values) and
// decodes it into v with unknown fields and trailing data rejected.
func readStrictBody(w http.ResponseWriter, r *http.Request, v any, fields ...string) *rejection {
	tooLarge := &rejection{http.StatusRequestEntityTooLarge, "payload_too_large", "Request body is too large."}
	if r.ContentLength > maxBodyBytes {
		return tooLarge
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return tooLarge
		}
		return &rejection{http.StatusBadRequest, "bad_request", "Unreadable request body."}
	}
	if err := decodeStrict(data, v, fields...); err != nil {
		return &rejection{http.StatusBadRequest, "bad_request", "Malformed request body."}
	}
	return nil
}

var errStrictJSON = errors.New("request body is not a strict JSON object")

func decodeStrict(data []byte, v any, fields ...string) error {
	if !utf8.Valid(data) {
		return errStrictJSON
	}
	allowed := make(map[string]bool, len(fields))
	for _, f := range fields {
		allowed[f] = true
	}
	// Token pass: Go's decoder matches keys case-insensitively and lets the
	// last duplicate win, so exact names and uniqueness are checked here.
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return errStrictJSON
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		key, isKey := tok.(string)
		if err != nil || !isKey || !allowed[key] || seen[key] {
			return errStrictJSON
		}
		seen[key] = true
		val, err := dec.Token()
		if err != nil || val == nil {
			return errStrictJSON
		}
		if _, nested := val.(json.Delim); nested {
			return errStrictJSON
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return errStrictJSON
	}
	if _, err := dec.Token(); err != io.EOF {
		return errStrictJSON
	}
	strict := json.NewDecoder(bytes.NewReader(data))
	strict.DisallowUnknownFields()
	if err := strict.Decode(v); err != nil {
		return errStrictJSON
	}
	return nil
}

//go:embed web
var webFS embed.FS

type asset struct {
	body        []byte
	contentType string
}

func mustAsset(name, contentType string) asset {
	body, err := webFS.ReadFile("web/" + name)
	if err != nil {
		panic("portal: missing embedded asset " + name)
	}
	return asset{body: body, contentType: contentType}
}

var (
	assetGuestHTML    = mustAsset("guest.html", "text/html; charset=utf-8")
	assetGuestCSS     = mustAsset("guest.css", "text/css; charset=utf-8")
	assetGuestJS      = mustAsset("guest.js", "text/javascript; charset=utf-8")
	assetOperatorHTML = mustAsset("operator.html", "text/html; charset=utf-8")
	assetOperatorCSS  = mustAsset("operator.css", "text/css; charset=utf-8")
	assetOperatorJS   = mustAsset("operator.js", "text/javascript; charset=utf-8")
	assetIcon         = mustAsset("icon.svg", "image/svg+xml")
)

func serveAsset(w http.ResponseWriter, r *http.Request, a asset) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, "GET, HEAD")
		return
	}
	w.Header().Set("Content-Type", a.contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(a.body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(a.body)
	}
}
