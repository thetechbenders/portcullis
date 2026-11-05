// Package portal contains an unprivileged, read-only guest portal preview.
// This is not a captive portal or a network authorization boundary.
package portal

import (
	"encoding/json"
	"net/http"
)

type status struct {
	Product       string `json:"product"`
	Mode          string `json:"mode"`
	Authorization string `json:"authorization"`
	Reason        string `json:"reason"`
}

func secureHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
}

// NewPreviewHandler provides a read-only preview. It deliberately exposes no
// mutation endpoint, generates no leases and cannot change firewall state.
func NewPreviewHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		secureHeaders(w)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	})
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		secureHeaders(w)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(status{
			Product: "Portcullis", Mode: "preview", Authorization: "denied",
			Reason: "No trusted client identity or enforcement controller is connected",
		})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secureHeaders(w)
		mux.ServeHTTP(w, r)
	})
}

const page = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Portcullis | Guest Access</title><style>
:root{color-scheme:dark;font:16px/1.55 system-ui,sans-serif;background:#0b1119;color:#e7f1f8}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:1.5rem}
main{width:min(100%,490px);border:1px solid #34465a;border-radius:24px;padding:2.2rem;background:#121e2b;box-shadow:0 24px 90px #0008}
mark{display:inline-block;background:#344354;color:#e4f0ff;padding:.25rem .75rem;border-radius:999px;font-size:.75rem;letter-spacing:.1em;text-transform:uppercase}
h1{font-size:2.25rem;letter-spacing:-.05em;margin:.5rem 0 0}p{color:#aec0d0}strong{color:#f7c88d}
.bar{background:#26384a;height:5px;border-radius:8px;overflow:hidden;margin:1.7rem 0}.bar>div{height:100%;width:0;background:#7dd3fc}
button{display:block;width:100%;font:inherit;padding:.85rem;border:0;border-radius:12px;background:#344354;color:#a5b9c7;cursor:not-allowed}
small{color:#9aafc1}footer{margin-top:1.5rem;border-top:1px solid #34465a;padding-top:1rem}
</style></head><body><main>
<mark>Isolated demo preview</mark><h1>Portcullis</h1><p>Guest network access, with a verified boundary.</p>
<p><strong>Access is not enabled.</strong> This visual preview cannot authorize network traffic.</p>
<div class="bar"><div></div></div><button disabled aria-disabled="true">Request access (not connected)</button>
<footer><small>Demo UI only. The enforcement controller, client binding and portal onboarding are not yet connected.</small></footer>
</main></body></html>`
