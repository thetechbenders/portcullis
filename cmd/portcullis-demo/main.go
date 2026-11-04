// Command portcullis-demo serves a local, unprivileged portal preview.
// It has no access to the packet filter or the lease authority.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/thetechbenders/portcullis/internal/portal"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:8787", "loopback-only preview listener")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected arguments")
		os.Exit(2)
	}
	host, _, err := net.SplitHostPort(*addr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		fmt.Fprintln(os.Stderr, "demo listener must use a numeric loopback address")
		os.Exit(2)
	}
	server := &http.Server{Addr: *addr, Handler: portal.NewPreviewHandler(), ReadHeaderTimeout: 5 * time.Second}
	log.Printf("Portcullis preview on http://%s (no access enforcement)", *addr)
	log.Fatal(server.ListenAndServe())
}
