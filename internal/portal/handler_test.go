package portal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPreviewIsDenyOnly(t *testing.T) {
	h := NewPreviewHandler()
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	if r.Code != http.StatusOK {
		t.Fatalf("status %d", r.Code)
	}
	var state status
	if err := json.Unmarshal(r.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if state.Authorization != "denied" || state.Mode != "preview" {
		t.Fatalf("unexpected authorization: %+v", state)
	}
	if r.Header().Get("Cache-Control") != "no-store" || r.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("missing response hardening")
	}
}

func TestPreviewHasNoMutationOrFakeGrants(t *testing.T) {
	h := NewPreviewHandler()
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest(method, "/api/status", nil))
		if r.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s: got %d", method, r.Code)
		}
	}
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/", nil))
	if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), "Request access (not connected)") || !strings.Contains(r.Body.String(), "disabled") {
		t.Fatal("preview must explicitly disable access grants")
	}
}

func TestPreviewDoesNotClaimAllPaths(t *testing.T) {
	h := NewPreviewHandler()
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/missing", nil))
	if r.Code != http.StatusNotFound {
		t.Fatalf("missing route: %d", r.Code)
	}
}
