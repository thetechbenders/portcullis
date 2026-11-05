package portal

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thetechbenders/portcullis/internal/ipc"
)

const testToken = "0123456789abcdef0123456789abcdef0123456789abcdef"

func newOperator(t *testing.T, fc *fakeController) http.Handler {
	t.Helper()
	h, err := NewOperatorHandler(fc, testToken)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// opReq builds a request as served by a listener on local.
func opReq(method, host, path, body string, local net.Addr) *http.Request {
	r := httptest.NewRequest(method, "http://x.test"+path, strings.NewReader(body))
	r.Host = host
	if local != nil {
		r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, local))
	}
	return r
}

var loopback8788 = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8788}

func authed(r *http.Request) *http.Request {
	r.Header.Set("Authorization", "Bearer "+testToken)
	return r
}

func TestNewOperatorHandlerValidation(t *testing.T) {
	for name, tok := range map[string]string{
		"short": strings.Repeat("a", 31), "space": strings.Repeat("a", 31) + " b", "newline": strings.Repeat("a", 32) + "\n", "empty": "",
	} {
		if _, err := NewOperatorHandler(&fakeController{}, tok); !errors.Is(err, ErrConfig) {
			t.Errorf("%s token accepted", name)
		}
	}
	if _, err := NewOperatorHandler(nil, testToken); !errors.Is(err, ErrConfig) {
		t.Error("nil controller accepted")
	}
}

func TestOperatorLoopbackOnly(t *testing.T) {
	fc := &fakeController{resp: ipc.Response{OK: true, Snapshot: &ipc.Snapshot{Enforcement: "ok"}}}
	h := newOperator(t, fc)
	v6 := &net.TCPAddr{IP: net.IPv6loopback, Port: 8788}
	for _, tc := range []struct {
		name, host string
		local      net.Addr
		status     int
	}{
		{"ipv4", "127.0.0.1:8788", loopback8788, 200},
		{"localhost", "localhost:8788", loopback8788, 200},
		{"ipv6", "[::1]:8788", v6, 200},
		{"rebinding name", "evil.example:8788", loopback8788, 403},
		{"guest address", "10.203.0.1:8788", loopback8788, 403},
		{"wrong port", "127.0.0.1:9999", loopback8788, 403},
		{"missing port", "127.0.0.1", loopback8788, 403},
		{"no local addr", "127.0.0.1:8788", nil, 403},
		{"non-loopback listener", "127.0.0.1:8788", &net.TCPAddr{IP: net.IPv4(10, 203, 0, 1), Port: 8788}, 403},
		{"malformed", "127.0.0.1:8788:1", loopback8788, 403},
	} {
		for _, path := range []string{"/", "/api/snapshot"} {
			w := serve(h, authed(opReq("GET", tc.host, path, "", tc.local)))
			if w.Code != tc.status {
				t.Errorf("%s %s: status %d, want %d", tc.name, path, w.Code, tc.status)
			}
			assertHardened(t, tc.name, w)
		}
	}
	if fc.count() != 3 {
		t.Fatalf("controller calls %d, want 3 (accepted snapshots only)", fc.count())
	}
}

func TestOperatorRoutesAndAuth(t *testing.T) {
	fc := &fakeController{resp: ipc.Response{OK: true, Snapshot: &ipc.Snapshot{Enforcement: "ok", Counters: []ipc.CounterView{{Rule: "guest-egress", Packets: 7}}}}}
	h := newOperator(t, fc)
	for _, tc := range []struct {
		method, path string
		status       int
		ctype        string
	}{
		{"GET", "/", 200, "text/html; charset=utf-8"},
		{"GET", "/assets/operator.css", 200, "text/css; charset=utf-8"},
		{"GET", "/assets/operator.js", 200, "text/javascript; charset=utf-8"},
		{"GET", "/assets/icon.svg", 200, "image/svg+xml"},
		{"GET", "/assets/guest.js", 404, ""},
		{"GET", "/api/session", 404, ""},
		{"POST", "/api/snapshot", 405, ""},
		{"GET", "/api/revoke", 405, ""},
		{"GET", "/api/reset", 405, ""},
	} {
		w := serve(h, opReq(tc.method, "127.0.0.1:8788", tc.path, "", loopback8788))
		if w.Code != tc.status || (tc.ctype != "" && w.Header().Get("Content-Type") != tc.ctype) {
			t.Errorf("%s %s: %d %q", tc.method, tc.path, w.Code, w.Header().Get("Content-Type"))
		}
		assertHardened(t, tc.path, w)
	}
	if fc.count() != 0 {
		t.Fatal("static routes called the controller")
	}
	for name, auth := range map[string][]string{
		"missing":        nil,
		"basic":          {"Basic " + testToken},
		"wrong last":     {"Bearer " + testToken[:len(testToken)-1] + "0"},
		"prefix":         {"Bearer " + testToken[:32]},
		"longer":         {"Bearer " + testToken + "x"},
		"trailing space": {"Bearer " + testToken + " "},
		"no scheme":      {testToken},
		"twice":          {"Bearer " + testToken, "Bearer " + testToken},
	} {
		for _, tc := range []struct{ method, path, body string }{{"GET", "/api/snapshot", ""}, {"POST", "/api/reset", "{}"}} {
			r := opReq(tc.method, "127.0.0.1:8788", tc.path, tc.body, loopback8788)
			for _, v := range auth {
				r.Header.Add("Authorization", v)
			}
			if tc.method == "POST" {
				validPost(r)
			}
			w := serve(h, r)
			if w.Code != 401 || !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Bearer") {
				t.Errorf("%s %s: status %d", name, tc.path, w.Code)
			}
			assertHardened(t, name, w)
		}
	}
	if fc.count() != 0 {
		t.Fatalf("unauthorized requests reached the controller %d times", fc.count())
	}
	r := opReq("GET", "127.0.0.1:8788", "/api/snapshot", "", loopback8788)
	r.Header.Set("Authorization", "bearer "+testToken) // scheme is case-insensitive
	w := serve(h, r)
	e := decodeEnvelope(t, w)
	if w.Code != 200 || !e.OK || e.Snapshot == nil || len(e.Snapshot.Counters) != 1 || e.Snapshot.Counters[0].Packets != 7 {
		t.Fatalf("snapshot: %d %+v", w.Code, e)
	}
	if fc.calls[0].req.Op != ipc.OpSnapshot || fc.calls[0].conn != nil {
		t.Fatalf("snapshot call %+v", fc.calls[0])
	}
}

func TestOperatorMutations(t *testing.T) {
	fc := &fakeController{resp: ipc.Response{OK: true}}
	h := newOperator(t, fc)
	post := func(path, body string) *httptest.ResponseRecorder {
		r := validPost(authed(opReq("POST", "127.0.0.1:8788", path, body, loopback8788)))
		// A guest connection in the context must never be forwarded.
		r = r.WithContext(ConnContext(r.Context(), testConn(t)))
		return serve(h, r)
	}
	if w := post("/api/revoke", `{"mac":"02:00:00:00:0A:01"}`); w.Code != 200 {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	if w := post("/api/reset", `{}`); w.Code != 200 {
		t.Fatalf("reset: %d", w.Code)
	}
	want := []ipc.Request{{Op: ipc.OpRevoke, Target: "02:00:00:00:0a:01"}, {Op: ipc.OpReset}}
	for i, c := range fc.calls {
		if c.req != want[i] || c.conn != nil {
			t.Fatalf("call %d: %+v conn %v", i, c.req, c.conn)
		}
	}
	before := fc.count()
	for name, tc := range map[string]struct {
		path, body string
		mutate     func(*http.Request)
		status     int
	}{
		"bad mac":        {"/api/revoke", `{"mac":"nope"}`, nil, 400},
		"multicast mac":  {"/api/revoke", `{"mac":"01:00:5e:00:00:01"}`, nil, 400},
		"missing mac":    {"/api/revoke", `{}`, nil, 400},
		"extra field":    {"/api/revoke", `{"mac":"02:00:00:00:0a:01","all":true}`, nil, 400},
		"reset field":    {"/api/reset", `{"force":true}`, nil, 400},
		"trailing":       {"/api/reset", `{}{}`, nil, 400},
		"oversized":      {"/api/reset", `{` + strings.Repeat(" ", 2000) + `}`, nil, 413},
		"text/plain":     {"/api/reset", `{}`, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 415},
		"no header":      {"/api/reset", `{}`, func(r *http.Request) { r.Header.Del("X-Portcullis-Request") }, 403},
		"foreign origin": {"/api/reset", `{}`, func(r *http.Request) { r.Header.Set("Origin", "http://evil.example:8788") }, 403},
		"no origin":      {"/api/revoke", `{"mac":"02:00:00:00:0a:01"}`, func(r *http.Request) { r.Header.Del("Origin") }, 403},
		"cross-site":     {"/api/reset", `{}`, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
	} {
		r := validPost(authed(opReq("POST", "127.0.0.1:8788", tc.path, tc.body, loopback8788)))
		if tc.mutate != nil {
			tc.mutate(r)
		}
		if w := serve(h, r); w.Code != tc.status {
			t.Errorf("%s: status %d, want %d", name, w.Code, tc.status)
		}
	}
	if fc.count() != before {
		t.Fatalf("rejected operator requests reached the controller %d times", fc.count()-before)
	}
}

func TestOperatorControllerFailures(t *testing.T) {
	for name, tc := range map[string]struct {
		fc     *fakeController
		status int
	}{
		"unreachable":     {&fakeController{err: errors.New("dial")}, 503},
		"ok no snapshot":  {&fakeController{resp: ipc.Response{OK: true}}, 502},
		"forbidden":       {&fakeController{resp: ipc.Response{Error: ipc.ErrForbidden}}, 403},
		"unknown failure": {&fakeController{resp: ipc.Response{Error: "odd"}}, 502},
	} {
		w := serve(newOperator(t, tc.fc), authed(opReq("GET", "127.0.0.1:8788", "/api/snapshot", "", loopback8788)))
		if e := decodeEnvelope(t, w); w.Code != tc.status || e.OK {
			t.Errorf("%s: %d %+v", name, w.Code, e)
		}
	}
}
