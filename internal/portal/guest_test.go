package portal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thetechbenders/portcullis/internal/ipc"
)

type recordedCall struct {
	req  ipc.Request
	conn net.Conn
}

// fakeController records every call and the connection it received.
type fakeController struct {
	mu    sync.Mutex
	calls []recordedCall
	resp  ipc.Response
	err   error
	block bool
}

func (f *fakeController) Call(ctx context.Context, req ipc.Request, conn net.Conn) (ipc.Response, error) {
	f.mu.Lock()
	f.calls = append(f.calls, recordedCall{req, conn})
	resp, err, block := f.resp, f.err, f.block
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return ipc.Response{OK: true, Session: &ipc.Session{State: ipc.StateGranted}}, ctx.Err()
	}
	return resp, err
}

func (f *fakeController) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

const testPortal = "portal.portcullis.test"

func newGuest(t *testing.T, fc *fakeController) http.Handler {
	t.Helper()
	h, err := NewGuestHandler(GuestConfig{
		AllowedHosts: []string{testPortal, "10.203.0.1"},
		PortalURL:    "http://" + testPortal + "/",
		ProbeHosts: []string{"captive.apple.com", "connectivitycheck.gstatic.com", "clients3.google.com",
			"connectivitycheck.android.com", "www.msftconnecttest.com", "detectportal.firefox.com", "nmcheck.gnome.org"},
		Timeout: 200 * time.Millisecond,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, fc)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func testConn(t *testing.T) net.Conn {
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return a
}

// guestReq builds a request carrying conn (nil = no connection context).
func guestReq(method, host, path, body string, conn net.Conn) *http.Request {
	r := httptest.NewRequest(method, "http://"+host+path, strings.NewReader(body))
	r.Host = host
	if conn != nil {
		r = r.WithContext(ConnContext(r.Context(), conn))
	}
	return r
}

func validPost(r *http.Request) *http.Request {
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Portcullis-Request", "1")
	r.Header.Set("Origin", "http://"+r.Host)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	return r
}

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func decodeEnvelope(t *testing.T, w *httptest.ResponseRecorder) envelope {
	t.Helper()
	var e envelope
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("response is not JSON (%d): %q", w.Code, w.Body.String())
	}
	return e
}

var wantHeaders = map[string]string{
	"Cache-Control":           "no-store",
	"X-Content-Type-Options":  "nosniff",
	"X-Frame-Options":         "DENY",
	"Referrer-Policy":         "no-referrer",
	"Permissions-Policy":      "camera=(), microphone=(), geolocation=()",
	"Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
}

func assertHardened(t *testing.T, name string, w *httptest.ResponseRecorder) {
	t.Helper()
	for k, v := range wantHeaders {
		if got := w.Header().Get(k); got != v {
			t.Errorf("%s: header %s = %q, want %q", name, k, got, v)
		}
	}
	if w.Header().Get("Set-Cookie") != "" {
		t.Errorf("%s: response sets a cookie", name)
	}
}

func TestNewGuestHandlerRejectsBadConfig(t *testing.T) {
	good := GuestConfig{AllowedHosts: []string{testPortal}, PortalURL: "http://" + testPortal + "/", ProbeHosts: []string{"captive.apple.com"}}
	for name, mutate := range map[string]func(*GuestConfig){
		"no hosts":         func(c *GuestConfig) { c.AllowedHosts = nil },
		"uppercase host":   func(c *GuestConfig) { c.AllowedHosts = []string{"Portal.portcullis.test"} },
		"host with port":   func(c *GuestConfig) { c.AllowedHosts = []string{testPortal + ":80"} },
		"ipv6 host":        func(c *GuestConfig) { c.AllowedHosts = []string{"::1"} },
		"duplicate host":   func(c *GuestConfig) { c.AllowedHosts = []string{testPortal, testPortal} },
		"https url":        func(c *GuestConfig) { c.PortalURL = "https://" + testPortal + "/" },
		"foreign url host": func(c *GuestConfig) { c.PortalURL = "http://evil.example/" },
		"url userinfo":     func(c *GuestConfig) { c.PortalURL = "http://u@" + testPortal + "/" },
		"url query":        func(c *GuestConfig) { c.PortalURL = "http://" + testPortal + "/?x=1" },
		"probe overlaps":   func(c *GuestConfig) { c.ProbeHosts = []string{testPortal} },
		"probe ip":         func(c *GuestConfig) { c.ProbeHosts = []string{"10.0.0.1"} },
		"negative timeout": func(c *GuestConfig) { c.Timeout = -time.Second },
		"huge timeout":     func(c *GuestConfig) { c.Timeout = time.Hour },
	} {
		cfg := good
		mutate(&cfg)
		if _, err := NewGuestHandler(cfg, &fakeController{}); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: expected ErrConfig, got %v", name, err)
		}
	}
	if _, err := NewGuestHandler(good, nil); !errors.Is(err, ErrConfig) {
		t.Error("nil controller accepted")
	}
	if _, err := NewGuestHandler(good, &fakeController{}); err != nil {
		t.Fatal(err)
	}
}

func TestGuestRoutesAndMethods(t *testing.T) {
	fc := &fakeController{resp: ipc.Response{OK: true, Session: &ipc.Session{State: ipc.StateDenied}}}
	h := newGuest(t, fc)
	conn := testConn(t)
	for _, tc := range []struct {
		method, path string
		status       int
		ctype        string
	}{
		{"GET", "/", 200, "text/html; charset=utf-8"},
		{"HEAD", "/", 200, "text/html; charset=utf-8"},
		{"GET", "/assets/guest.css", 200, "text/css; charset=utf-8"},
		{"GET", "/assets/guest.js", 200, "text/javascript; charset=utf-8"},
		{"GET", "/assets/icon.svg", 200, "image/svg+xml"},
		{"POST", "/", 405, ""},
		{"DELETE", "/assets/guest.js", 405, ""},
		{"POST", "/api/session", 405, ""},
		{"GET", "/api/access", 405, ""},
		{"OPTIONS", "/api/access", 405, ""},
		{"PUT", "/api/release", 405, ""},
		{"GET", "/missing", 404, ""},
		{"GET", "/assets/operator.js", 404, ""},
		{"GET", "/api/snapshot", 404, ""},
	} {
		w := serve(h, guestReq(tc.method, testPortal, tc.path, "", conn))
		if w.Code != tc.status {
			t.Errorf("%s %s: status %d, want %d", tc.method, tc.path, w.Code, tc.status)
		}
		if tc.ctype != "" && w.Header().Get("Content-Type") != tc.ctype {
			t.Errorf("%s %s: content type %q", tc.method, tc.path, w.Header().Get("Content-Type"))
		}
		if tc.status == 405 && w.Header().Get("Allow") == "" {
			t.Errorf("%s %s: 405 without Allow", tc.method, tc.path)
		}
		assertHardened(t, tc.method+" "+tc.path, w)
	}
	if fc.count() != 0 {
		t.Fatalf("static/invalid routes called the controller %d times", fc.count())
	}
	page := serve(h, guestReq("GET", testPortal, "/", "", conn)).Body.String()
	for _, want := range []string{"Portcullis", "Guest access, enforced at the gateway", "<svg", "<noscript>", `aria-live="polite"`} {
		if !strings.Contains(page, want) {
			t.Errorf("guest page lacks %q", want)
		}
	}
}

func TestGuestAPIPassesOwnConnection(t *testing.T) {
	fc := &fakeController{resp: ipc.Response{OK: true, Session: &ipc.Session{State: ipc.StateGranted, RemainingSeconds: 100, GrantedSeconds: 120}}}
	h := newGuest(t, fc)
	conn := testConn(t)
	for _, tc := range []struct {
		method, path, body string
		want               ipc.Request
	}{
		{"GET", "/api/session", "", ipc.Request{Op: ipc.OpStatus}},
		{"POST", "/api/access", `{"duration_seconds":120}`, ipc.Request{Op: ipc.OpRequest, DurationSeconds: 120}},
		{"POST", "/api/access", `{}`, ipc.Request{Op: ipc.OpRequest}},
		{"POST", "/api/release", ` {} `, ipc.Request{Op: ipc.OpRelease}},
	} {
		before := fc.count()
		r := guestReq(tc.method, testPortal, tc.path, tc.body, conn)
		if tc.method == "POST" {
			validPost(r)
		}
		w := serve(h, r)
		if w.Code != 200 || fc.count() != before+1 {
			t.Fatalf("%s %s: status %d calls %d", tc.method, tc.path, w.Code, fc.count()-before)
		}
		got := fc.calls[len(fc.calls)-1]
		if got.req != tc.want || got.conn != conn {
			t.Fatalf("%s: controller got %+v conn %v", tc.path, got.req, got.conn)
		}
		if e := decodeEnvelope(t, w); !e.OK || e.Session == nil || e.Session.State != ipc.StateGranted || e.Session.RemainingSeconds != 100 {
			t.Fatalf("%s: relayed %+v", tc.path, e)
		}
	}
	// The gateway IPv4 literal is an allowed portal host too.
	if w := serve(h, guestReq("GET", "10.203.0.1", "/api/session", "", conn)); w.Code != 200 {
		t.Fatalf("gateway literal host: %d", w.Code)
	}
}

func TestGuestPostProtectionsMakeNoCall(t *testing.T) {
	fc := &fakeController{resp: ipc.Response{OK: true, Session: &ipc.Session{State: ipc.StateGranted}}}
	h := newGuest(t, fc)
	conn := testConn(t)
	type mut func(*http.Request)
	set := func(k, v string) mut { return func(r *http.Request) { r.Header.Set(k, v) } }
	del := func(k string) mut { return func(r *http.Request) { r.Header.Del(k) } }
	add := func(k, v string) mut { return func(r *http.Request) { r.Header.Add(k, v) } }
	for _, tc := range []struct {
		name, path, body string
		mutate           mut
		status           int
	}{
		{"no content type", "/api/access", `{}`, del("Content-Type"), 415},
		{"text/plain", "/api/access", `{}`, set("Content-Type", "text/plain"), 415},
		{"form", "/api/access", `{}`, set("Content-Type", "application/x-www-form-urlencoded"), 415},
		{"latin1", "/api/access", `{}`, set("Content-Type", "application/json; charset=latin1"), 415},
		{"extra param", "/api/access", `{}`, set("Content-Type", "application/json; boundary=x"), 415},
		{"no custom header", "/api/access", `{}`, del("X-Portcullis-Request"), 403},
		{"custom header 0", "/api/access", `{}`, set("X-Portcullis-Request", "0"), 403},
		{"custom header twice", "/api/access", `{}`, add("X-Portcullis-Request", "1"), 403},
		{"no origin", "/api/access", `{}`, del("Origin"), 403},
		{"null origin", "/api/access", `{}`, set("Origin", "null"), 403},
		{"foreign origin", "/api/access", `{}`, set("Origin", "http://evil.example"), 403},
		{"https origin", "/api/access", `{}`, set("Origin", "https://"+testPortal), 403},
		{"origin other port", "/api/access", `{}`, set("Origin", "http://"+testPortal+":8080"), 403},
		{"origin trailing slash", "/api/access", `{}`, set("Origin", "http://"+testPortal+"/"), 403},
		{"cross-site fetch", "/api/access", `{}`, set("Sec-Fetch-Site", "cross-site"), 403},
		{"same-site fetch", "/api/release", `{}`, set("Sec-Fetch-Site", "same-site"), 403},
		{"oversized", "/api/access", `{"duration_seconds":1` + strings.Repeat(" ", 1100) + `}`, nil, 413},
		{"empty body", "/api/access", ``, nil, 400},
		{"null body", "/api/access", `null`, nil, 400},
		{"array body", "/api/access", `[]`, nil, 400},
		{"unknown field", "/api/access", `{"duration_seconds":60,"mac":"02:00:00:00:00:01"}`, nil, 400},
		{"case-folded field", "/api/access", `{"Duration_Seconds":60}`, nil, 400},
		{"duplicate field", "/api/access", `{"duration_seconds":30,"duration_seconds":900}`, nil, 400},
		{"trailing object", "/api/access", `{} {}`, nil, 400},
		{"trailing garbage", "/api/access", `{}x`, nil, 400},
		{"string duration", "/api/access", `{"duration_seconds":"60"}`, nil, 400},
		{"float duration", "/api/access", `{"duration_seconds":60.5}`, nil, 400},
		{"null duration", "/api/access", `{"duration_seconds":null}`, nil, 400},
		{"nested duration", "/api/access", `{"duration_seconds":{"a":1}}`, nil, 400},
		{"negative duration", "/api/access", `{"duration_seconds":-5}`, nil, 400},
		{"release with field", "/api/release", `{"duration_seconds":60}`, nil, 400},
		{"invalid utf8", "/api/release", "{\"\xff\":1}", nil, 400},
	} {
		r := validPost(guestReq("POST", testPortal, tc.path, tc.body, conn))
		if tc.mutate != nil {
			tc.mutate(r)
		}
		w := serve(h, r)
		if w.Code != tc.status {
			t.Errorf("%s: status %d, want %d (%s)", tc.name, w.Code, tc.status, w.Body.String())
		}
		if e := decodeEnvelope(t, w); e.OK || e.Error == "" || e.Session != nil {
			t.Errorf("%s: envelope %+v", tc.name, e)
		}
		assertHardened(t, tc.name, w)
	}
	if fc.count() != 0 {
		t.Fatalf("rejected requests reached the controller %d times", fc.count())
	}
	// Cross-site fetch metadata on the session read is refused too.
	r := guestReq("GET", testPortal, "/api/session", "", conn)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	if w := serve(h, r); w.Code != 403 || fc.count() != 0 {
		t.Fatalf("cross-site session read: %d calls %d", w.Code, fc.count())
	}
}

func TestGuestHostRouting(t *testing.T) {
	fc := &fakeController{resp: ipc.Response{OK: true, Session: &ipc.Session{State: ipc.StateGranted}}}
	h := newGuest(t, fc)
	conn := testConn(t)
	for _, tc := range []struct {
		name, host, method, path string
		status                   int
	}{
		{"rebinding GET api", "evil.example", "GET", "/api/session", 302},
		{"rebinding GET root", "evil.example", "GET", "/", 302},
		{"rebinding HEAD", "evil.example", "HEAD", "/", 302},
		{"rebinding POST", "evil.example", "POST", "/api/access", 403},
		{"wrong port", testPortal + ":8080", "GET", "/api/session", 302},
		{"wrong port POST", testPortal + ":8080", "POST", "/api/access", 403},
		{"trailing dot", testPortal + ".", "GET", "/api/session", 302},
		{"other ipv4", "10.203.0.2", "POST", "/api/release", 403},
		{"ipv6 literal", "[::1]", "GET", "/", 302},
		{"malformed chars", "bad_host!", "GET", "/", 400},
		{"empty host", "", "GET", "/", 400},
		{"bad port", testPortal + ":0", "GET", "/", 400},
		{"port leading zero", testPortal + ":080", "GET", "/", 400},
		{"kelvin sign", "portal.portcullis.tesK", "GET", "/api/session", 400},
		{"space", "portal portcullis.test", "GET", "/", 400},
	} {
		r := guestReq(tc.method, "x.test", tc.path, `{}`, conn)
		r.Host = tc.host
		if tc.method == "POST" {
			validPost(r)
		}
		w := serve(h, r)
		if w.Code != tc.status {
			t.Errorf("%s: status %d, want %d", tc.name, w.Code, tc.status)
		}
		if tc.status == 302 && w.Header().Get("Location") != "http://"+testPortal+"/" {
			t.Errorf("%s: Location %q", tc.name, w.Header().Get("Location"))
		}
		if tc.host != "" {
			dump := w.Body.String()
			for k, v := range w.Header() {
				dump += k + strings.Join(v, ",")
			}
			if strings.Contains(dump, tc.host) {
				t.Errorf("%s: Host value echoed in response", tc.name)
			}
		}
		assertHardened(t, tc.name, w)
	}
	if fc.count() != 0 {
		t.Fatalf("foreign or malformed hosts reached the controller %d times", fc.count())
	}
	// Uppercase portal names are lowercased and served; port 80 is ours.
	for _, host := range []string{"PORTAL.Portcullis.TEST", testPortal + ":80"} {
		if w := serve(h, guestReq("GET", host, "/api/session", "", conn)); w.Code != 200 {
			t.Errorf("%s: status %d", host, w.Code)
		}
	}
}

func TestGuestMissingConnFailsClosed(t *testing.T) {
	fc := &fakeController{resp: ipc.Response{OK: true, Session: &ipc.Session{State: ipc.StateGranted}}}
	h := newGuest(t, fc)
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/api/session", ""}, {"POST", "/api/access", `{}`}, {"POST", "/api/release", `{}`},
	} {
		r := guestReq(tc.method, testPortal, tc.path, tc.body, nil)
		if tc.method == "POST" {
			validPost(r)
		}
		w := serve(h, r)
		e := decodeEnvelope(t, w)
		if w.Code != 500 || e.OK || e.Session == nil || e.Session.State == ipc.StateGranted {
			t.Errorf("%s: status %d envelope %+v", tc.path, w.Code, e)
		}
	}
	if w := serve(h, guestReq("GET", "captive.apple.com", "/hotspot-detect.html", "", nil)); w.Code != 302 {
		t.Errorf("probe without conn: %d", w.Code)
	}
	if fc.count() != 0 {
		t.Fatalf("controller called %d times without a guest connection", fc.count())
	}
}

func TestGuestStatusMapping(t *testing.T) {
	conn := testConn(t)
	sess := func(s ipc.State) *ipc.Session { return &ipc.Session{State: s, RetryAfterSeconds: 17} }
	for _, tc := range []struct {
		name   string
		resp   ipc.Response
		status int
		code   string
		retry  string
	}{
		{"ok", ipc.Response{OK: true, Session: sess(ipc.StateDenied)}, 200, "", ""},
		{"bad request", ipc.Response{Error: ipc.ErrBadRequest, Session: sess(ipc.StateDenied)}, 400, "bad_request", ""},
		{"forbidden", ipc.Response{Error: ipc.ErrForbidden, Session: sess(ipc.StateRevoked)}, 403, "forbidden", ""},
		{"identity", ipc.Response{Error: ipc.ErrIdentity, Session: sess(ipc.StateAmbiguous)}, 403, "identity", ""},
		{"conflict", ipc.Response{Error: ipc.ErrConflict, Session: sess(ipc.StateDenied)}, 409, "conflict", ""},
		{"rate limited", ipc.Response{Error: ipc.ErrRateLimited, Session: sess(ipc.StateDenied)}, 429, "rate_limited", "17"},
		{"unavailable", ipc.Response{Error: ipc.ErrUnavailable, Session: sess(ipc.StateUnavailable)}, 503, "unavailable", ""},
		{"internal", ipc.Response{Error: ipc.ErrInternal, Session: sess(ipc.StateDenied)}, 502, "internal", ""},
		{"unknown code", ipc.Response{Error: "weird"}, 502, "internal", ""},
		{"ok without session", ipc.Response{OK: true}, 502, "internal", ""},
		{"unknown state", ipc.Response{OK: true, Session: &ipc.Session{State: "superuser"}}, 502, "internal", ""},
	} {
		fc := &fakeController{resp: tc.resp}
		w := serve(newGuest(t, fc), validPost(guestReq("POST", testPortal, "/api/access", `{}`, conn)))
		e := decodeEnvelope(t, w)
		if w.Code != tc.status || e.Error != tc.code || w.Header().Get("Retry-After") != tc.retry {
			t.Errorf("%s: status %d code %q retry %q", tc.name, w.Code, e.Error, w.Header().Get("Retry-After"))
		}
	}
	// A snapshot accidentally attached to a guest answer is never relayed.
	fc := &fakeController{resp: ipc.Response{OK: true, Session: sess(ipc.StateDenied), Snapshot: &ipc.Snapshot{Enforcement: "ok"}}}
	if w := serve(newGuest(t, fc), guestReq("GET", testPortal, "/api/session", "", conn)); strings.Contains(w.Body.String(), "snapshot") {
		t.Fatal("guest response relayed an operator snapshot")
	}
}

func TestGuestControllerErrorIsUnavailableNeverGranted(t *testing.T) {
	conn := testConn(t)
	for name, fc := range map[string]*fakeController{
		// The error must win even when the response claims a grant.
		"error with granted": {resp: ipc.Response{OK: true, Session: &ipc.Session{State: ipc.StateGranted}}, err: errors.New("dial: no such file")},
		"timeout":            {block: true},
	} {
		h := newGuest(t, fc)
		for _, r := range []*http.Request{
			guestReq("GET", testPortal, "/api/session", "", conn),
			validPost(guestReq("POST", testPortal, "/api/access", `{"duration_seconds":60}`, conn)),
		} {
			w := serve(h, r)
			e := decodeEnvelope(t, w)
			if w.Code != 503 || e.OK || e.Error != "unavailable" || e.Session == nil ||
				e.Session.State != ipc.StateUnavailable || e.Session.Reason != unreachableReason {
				t.Errorf("%s %s: status %d envelope %+v", name, r.URL.Path, w.Code, e)
			}
			if strings.Contains(w.Body.String(), "granted") || strings.Contains(w.Body.String(), "no such file") {
				t.Errorf("%s: leaked grant or error detail: %s", name, w.Body.String())
			}
		}
	}
}

func TestGuestProbes(t *testing.T) {
	conn := testConn(t)
	want := map[string]struct {
		status int
		body   string
	}{
		"captive.apple.com":             {200, "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"},
		"connectivitycheck.gstatic.com": {204, ""},
		"clients3.google.com":           {204, ""},
		"connectivitycheck.android.com": {204, ""},
		"www.msftconnecttest.com":       {200, "Microsoft Connect Test"},
		"detectportal.firefox.com":      {200, "success\n"},
		"nmcheck.gnome.org":             {200, "NetworkManager is online\n"},
	}
	notGranted := map[string]*fakeController{
		"denied":      {resp: ipc.Response{OK: true, Session: &ipc.Session{State: ipc.StateDenied}}},
		"revoked":     {resp: ipc.Response{OK: true, Session: &ipc.Session{State: ipc.StateRevoked}}},
		"unavailable": {resp: ipc.Response{Error: ipc.ErrUnavailable, Session: &ipc.Session{State: ipc.StateUnavailable}}},
		"not ok":      {resp: ipc.Response{Error: ipc.ErrInternal, Session: &ipc.Session{State: ipc.StateGranted}}},
		"error":       {resp: ipc.Response{OK: true, Session: &ipc.Session{State: ipc.StateGranted}}, err: errors.New("down")},
		"no session":  {resp: ipc.Response{OK: true}},
	}
	for host, exp := range want {
		granted := &fakeController{resp: ipc.Response{OK: true, Session: &ipc.Session{State: ipc.StateGranted}}}
		w := serve(newGuest(t, granted), guestReq("GET", host, "/some/probe/path", "", conn))
		if w.Code != exp.status || w.Body.String() != exp.body {
			t.Errorf("%s granted: %d %q", host, w.Code, w.Body.String())
		}
		if len(granted.calls) != 1 || granted.calls[0].req.Op != ipc.OpStatus || granted.calls[0].conn != conn {
			t.Errorf("%s: controller calls %+v", host, granted.calls)
		}
		assertHardened(t, host, w)
		for name, fc := range notGranted {
			w := serve(newGuest(t, fc), guestReq("GET", host, "/", "", conn))
			if w.Code != 302 || w.Header().Get("Location") != "http://"+testPortal+"/" || strings.Contains(w.Body.String(), "Success") {
				t.Errorf("%s %s: %d %q", host, name, w.Code, w.Header().Get("Location"))
			}
			assertHardened(t, host+" "+name, w)
		}
	}
	fc := &fakeController{}
	if w := serve(newGuest(t, fc), guestReq("POST", "captive.apple.com", "/", "", conn)); w.Code != 405 || fc.count() != 0 {
		t.Fatalf("POST probe: %d calls %d", w.Code, fc.count())
	}
}

// TestGuestOverRealServer checks ConnContext wiring with net/http: the
// controller receives the server side of the client's own TCP connection.
func TestGuestOverRealServer(t *testing.T) {
	fc := &fakeController{resp: ipc.Response{OK: true, Session: &ipc.Session{State: ipc.StateDenied}}}
	srv := httptest.NewUnstartedServer(nil)
	host := srv.Listener.Addr().String()
	h, err := NewGuestHandler(GuestConfig{AllowedHosts: []string{"127.0.0.1"}, PortalURL: "http://" + host + "/"}, fc)
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = h
	srv.Config.ConnContext = ConnContext
	srv.Start()
	defer srv.Close()

	dialer := &net.Dialer{}
	var clientLocal net.Addr
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := dialer.DialContext(ctx, network, addr)
		if err == nil {
			clientLocal = c.LocalAddr()
		}
		return c, err
	}}}
	resp, err := client.Get(srv.URL + "/api/session")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || fc.count() != 1 {
		t.Fatalf("status %d calls %d", resp.StatusCode, fc.count())
	}
	got := fc.calls[0].conn
	if _, ok := got.(*net.TCPConn); !ok || got.RemoteAddr().String() != clientLocal.String() {
		t.Fatalf("controller got conn %T remote %v, client local %v", got, got.RemoteAddr(), clientLocal)
	}
}

func TestGuestConcurrentRequests(t *testing.T) {
	fc := &fakeController{resp: ipc.Response{OK: true, Session: &ipc.Session{State: ipc.StateDenied}}}
	h := newGuest(t, fc)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			if w := serve(h, guestReq("GET", testPortal, "/api/session", "", a)); w.Code != 200 {
				t.Errorf("status %d", w.Code)
			}
		}()
	}
	wg.Wait()
	if fc.count() != 32 {
		t.Fatalf("calls %d", fc.count())
	}
}

// TestAssetsAreCSPCompatible enforces what the CSP relies on: no inline
// script, style or event handlers in HTML and no HTML-string sinks in JS.
func TestAssetsAreCSPCompatible(t *testing.T) {
	scriptTag := regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)</script>`)
	srcAttr := regexp.MustCompile(`(?i)\ssrc="/assets/[a-z]+\.js"`)
	banned := regexp.MustCompile(`(?i)(<style\b|\sstyle\s*=|\son[a-z]+\s*=|javascript:)`)
	for _, a := range []asset{assetGuestHTML, assetOperatorHTML} {
		html := string(a.body)
		if banned.MatchString(html) {
			t.Errorf("HTML contains inline style/handler: %q", banned.FindString(html))
		}
		tags := scriptTag.FindAllStringSubmatch(html, -1)
		if len(tags) != 1 || strings.Count(strings.ToLower(html), "<script") != 1 {
			t.Fatalf("expected exactly one script tag, got %d", len(tags))
		}
		if !srcAttr.MatchString(tags[0][0]) || strings.TrimSpace(tags[0][1]) != "" {
			t.Errorf("script tag is inline or not same-origin: %q", tags[0][0])
		}
	}
	sinks := regexp.MustCompile(`innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\s*\(|new Function|setAttribute\(\s*['"]style|cssText`)
	for name, a := range map[string]asset{"guest.js": assetGuestJS, "operator.js": assetOperatorJS} {
		if m := sinks.FindString(string(a.body)); m != "" {
			t.Errorf("%s uses forbidden sink %q", name, m)
		}
	}
	if strings.Contains(string(assetOperatorJS.body), "localStorage") || strings.Contains(string(assetGuestJS.body), "Storage") {
		t.Error("token or state persisted beyond the tab")
	}
}
