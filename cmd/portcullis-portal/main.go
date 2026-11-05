// Command portcullis-portal serves the unprivileged guest portal (HTTP) and
// the static guest DNS responder on the gateway's guest address only. It
// holds no firewall privileges: every authorization decision is made by
// portcullisd from the guest TCP connection passed over the guest socket.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/thetechbenders/portcullis/internal/config"
	"github.com/thetechbenders/portcullis/internal/guestdns"
	"github.com/thetechbenders/portcullis/internal/ipc"
	"github.com/thetechbenders/portcullis/internal/portal"
)

// controllerClient forwards guest requests with the live connection.
type controllerClient struct{ socket string }

func (c controllerClient) Call(ctx context.Context, req ipc.Request, guest net.Conn) (ipc.Response, error) {
	return ipc.Call(ctx, c.socket, req, guest)
}

func main() {
	configPath := flag.String("config", "", "Portcullis configuration file")
	readyFile := flag.String("ready-file", "", "file written once HTTP and DNS are listening")
	flag.Parse()
	if flag.NArg() != 0 || *configPath == "" {
		fmt.Fprintln(os.Stderr, "usage: portcullis-portal -config FILE [-ready-file FILE]")
		os.Exit(2)
	}
	if os.Geteuid() == 0 || os.Getuid() == 0 {
		fatal(errors.New("refusing to run as root: the portal must be unprivileged"))
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fatal(err)
	}
	if uint32(os.Getuid()) != cfg.PortalUID {
		fatal(fmt.Errorf("running as uid %d but portal_uid is %d; the controller would reject this process", os.Getuid(), cfg.PortalUID))
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	handler, err := portal.NewGuestHandler(portal.GuestConfig{
		AllowedHosts: cfg.AllowedHosts(),
		PortalURL:    cfg.PortalURL(),
		ProbeHosts:   cfg.ProbeHostnames,
	}, controllerClient{socket: cfg.GuestSocket})
	if err != nil {
		fatal(err)
	}
	responder, err := guestdns.NewResponder(guestdns.ZoneFrom(cfg))
	if err != nil {
		fatal(err)
	}
	// Both listeners bind the gateway's guest address, never a wildcard.
	// MPTCP is disabled: the controller accepts only plain TCP guest sockets,
	// and extra MPTCP subflows could arrive from other addresses.
	var lc net.ListenConfig
	lc.SetMultipathTCP(false)
	ln, err := lc.Listen(context.Background(), "tcp4", cfg.PortalListen().String())
	if err != nil {
		fatal(err)
	}
	dnsConn, err := guestdns.ListenUDP(cfg.DNSListen())
	if err != nil {
		ln.Close()
		fatal(err)
	}
	server := &http.Server{
		Handler:           handler,
		ConnContext:       portal.ConnContext,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("portal HTTP stopped", "err", err)
		}
		cancel()
	}()
	go func() {
		defer wg.Done()
		if err := responder.Serve(ctx, dnsConn); err != nil {
			log.Error("guest DNS stopped", "err", err)
		}
		cancel()
	}()
	if *readyFile != "" {
		if err := os.WriteFile(*readyFile, []byte("ready\n"), 0o644); err != nil {
			log.Error("writing ready file", "err", err)
			cancel()
		}
	}
	log.Info("portal serving", "http", cfg.PortalListen().String(), "dns", cfg.DNSListen().String())
	<-ctx.Done()
	shutdown, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	_ = server.Shutdown(shutdown)
	dnsConn.Close()
	wg.Wait()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "portcullis-portal:", err)
	os.Exit(1)
}
