// Command portcullisctl is the operator interface to portcullisd over the
// root-only operator socket.
//
//	portcullisctl -config F snapshot
//	portcullisctl -config F revoke MAC
//	portcullisctl -config F reset
//	portcullisctl -config F serve -listen 127.0.0.1:8788 -token-file P
//
// The dashboard listener is loopback-only and its API requires a bearer
// token; it must never be exposed on a guest-reachable address.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/thetechbenders/portcullis/internal/config"
	"github.com/thetechbenders/portcullis/internal/ipc"
	"github.com/thetechbenders/portcullis/internal/portal"
)

type operatorClient struct{ socket string }

func (c operatorClient) Call(ctx context.Context, req ipc.Request, guest net.Conn) (ipc.Response, error) {
	if guest != nil {
		return ipc.Response{}, errors.New("operator requests never carry a guest connection")
	}
	return ipc.Call(ctx, c.socket, req, nil)
}

func main() {
	global := flag.NewFlagSet("portcullisctl", flag.ExitOnError)
	configPath := global.String("config", "", "Portcullis configuration file")
	global.Usage = usage
	if err := global.Parse(os.Args[1:]); err != nil || *configPath == "" || global.NArg() == 0 {
		usage()
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fatal(err)
	}
	client := operatorClient{socket: cfg.OperatorSocket}
	args := global.Args()
	switch args[0] {
	case "snapshot":
		requireArgs(args, 1)
		call(client, ipc.Request{Op: ipc.OpSnapshot})
	case "revoke":
		requireArgs(args, 2)
		call(client, ipc.Request{Op: ipc.OpRevoke, Target: args[1]})
	case "reset":
		requireArgs(args, 1)
		call(client, ipc.Request{Op: ipc.OpReset})
	case "serve":
		serve(client, args[1:])
	default:
		usage()
	}
}

func call(client operatorClient, req ipc.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := client.Call(ctx, req, nil)
	if err != nil {
		fatal(err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
	if !resp.OK {
		os.Exit(1)
	}
}

func serve(client operatorClient, args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8788", "numeric loopback listener")
	tokenFile := fs.String("token-file", "", "bearer token file (created with mode 0600 if absent)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *tokenFile == "" {
		usage()
	}
	addr, err := netip.ParseAddrPort(*listen)
	if err != nil || !addr.Addr().IsLoopback() {
		fatal(errors.New("the operator dashboard must listen on a numeric loopback address"))
	}
	token, err := loadToken(*tokenFile)
	if err != nil {
		fatal(err)
	}
	handler, err := portal.NewOperatorHandler(client, token)
	if err != nil {
		fatal(err)
	}
	server := &http.Server{
		Addr: addr.String(), Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, MaxHeaderBytes: 8 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	fmt.Fprintf(os.Stderr, "operator dashboard on http://%s/ (token in %s)\n", addr, *tokenFile)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal(err)
	}
}

// loadToken reads an existing token or creates a fresh one. The token never
// appears in URLs, process arguments or logs.
func loadToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return "", err
		}
		token := hex.EncodeToString(raw[:])
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return "", err
		}
		defer f.Close()
		_, err = f.WriteString(token + "\n")
		return token, err
	}
	if err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("token file %s must not be accessible to group or others", path)
	}
	token := strings.TrimSpace(string(data))
	if len(token) < 32 {
		return "", errors.New("token file must contain at least 32 characters")
	}
	return token, nil
}

func requireArgs(args []string, n int) {
	if len(args) != n {
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: portcullisctl -config FILE {snapshot | revoke MAC | reset | serve -listen ADDR -token-file FILE}")
	os.Exit(2)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "portcullisctl:", err)
	os.Exit(1)
}
