// Command portcullisd is the privileged Portcullis enforcement controller.
//
//	portcullisd bootstrap -config F   install the guard while the guest link is down
//	portcullisd attest -config F      verify guard, bypass paths and topology
//	portcullisd run -config F         serve DHCP and the control sockets
//
// It refuses to start serving unless the persistent guard attests, revokes
// every inherited grant on start, and never replaces hooked base chains.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/thetechbenders/portcullis/internal/config"
	"github.com/thetechbenders/portcullis/internal/controller"
	"github.com/thetechbenders/portcullis/internal/dhcp"
	"github.com/thetechbenders/portcullis/internal/enforce"
	"github.com/thetechbenders/portcullis/internal/gateway"
	"github.com/thetechbenders/portcullis/internal/identity"
	"github.com/thetechbenders/portcullis/internal/ipc"
	"github.com/thetechbenders/portcullis/internal/kernel"
)

const (
	commandTimeout     = 10 * time.Second
	reconcileInterval  = 2 * time.Second
	minRequestInterval = 5 * time.Second
	shutdownTimeout    = 5 * time.Second
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	configPath := fs.String("config", "", "Portcullis configuration file")
	readyFile := fs.String("ready-file", "", "file written once DHCP and control sockets are serving (run only)")
	if err := fs.Parse(os.Args[2:]); err != nil || fs.NArg() != 0 || *configPath == "" {
		usage()
	}
	if os.Geteuid() != 0 {
		fatal(errors.New("portcullisd must run as root in the gateway network namespace"))
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fatal(err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	k, flows, err := newKernel(cfg)
	if err != nil {
		fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	switch os.Args[1] {
	case "bootstrap":
		if err := k.Bootstrap(ctx); err != nil {
			fatal(err)
		}
		fmt.Println("guard installed and attested; guest interface may now be brought up")
	case "attest":
		state, err := k.Attest(ctx)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("guard attested: %d bound, %d granted, %d granted_dst elements\n",
			len(state.Bound), len(state.Granted), len(state.GrantedDst))
	case "run":
		if err := run(ctx, cfg, k, flows, log, *readyFile); err != nil {
			fatal(err)
		}
	default:
		usage()
	}
}

func newKernel(cfg *config.Config) (*gateway.Kernel, gateway.Flows, error) {
	nftExec, err := kernel.NewExec(cfg.NFTPath, commandTimeout)
	if err != nil {
		return nil, gateway.Flows{}, err
	}
	ipExec, err := kernel.NewExec(cfg.IPPath, commandTimeout)
	if err != nil {
		return nil, gateway.Flows{}, err
	}
	ctExec, err := kernel.NewExec(cfg.ConntrackPath, commandTimeout)
	if err != nil {
		return nil, gateway.Flows{}, err
	}
	guard := enforce.GuardConfigFrom(cfg)
	if err := guard.Validate(); err != nil {
		return nil, gateway.Flows{}, err
	}
	k := &gateway.Kernel{
		Guard:    guard,
		NFT:      kernel.NewNFT(nftExec),
		Link:     kernel.NewLink(ipExec),
		Topology: kernel.Topology{ProcRoot: "/proc"},
	}
	return k, gateway.Flows{Conntrack: kernel.NewConntrack(ctExec)}, nil
}

func run(ctx context.Context, cfg *config.Config, k *gateway.Kernel, flows gateway.Flows, log *slog.Logger, readyFile string) error {
	deps := controller.Deps{
		Kernel:   k,
		Flows:    flows,
		Evidence: identity.Corroborator{Source: identity.ProcARP{Path: "/proc/net/arp"}, Interface: cfg.GuestInterface},
		Now:      time.Now,
		Log:      log,
	}
	if cfg.FailsafeLinkDown {
		deps.Failsafe = gateway.LinkFailsafe{Link: k.Link, Interface: cfg.GuestInterface}
	}
	ctrl, err := controller.New(controller.Config{
		GuestSubnet:        cfg.GuestSubnetV4,
		Gateway:            cfg.GatewayV4,
		GrantDefault:       cfg.GrantDefault,
		GrantMax:           cfg.GrantMax,
		RevokeCooldown:     cfg.RevokeCooldown,
		MinRequestInterval: minRequestInterval,
		ReconcileInterval:  reconcileInterval,
		MaxEvents:          256,
	}, deps)
	if err != nil {
		return err
	}
	server, err := dhcp.NewServer(dhcp.ConfigFrom(cfg), ctrl, time.Now, log)
	if err != nil {
		return err
	}
	ctrl.SetBindings(server)
	// Attestation, inherited-grant revocation and binding adoption all happen
	// before any guest-facing or control socket exists.
	if err := ctrl.Start(ctx); err != nil {
		return fmt.Errorf("refusing to serve: %w", err)
	}

	dhcpConn, err := dhcp.ListenInterface(cfg.GuestInterface, 67)
	if err != nil {
		return err
	}
	guestSock, err := ipc.Listen(ipc.ServerConfig{
		Path: cfg.GuestSocket, Mode: 0o666, AllowedUIDs: []uint32{cfg.PortalUID},
		Guest: true, PortalAddr: cfg.PortalListen(),
		Ops: []ipc.Op{ipc.OpStatus, ipc.OpRequest, ipc.OpRelease},
	})
	if err != nil {
		dhcpConn.Close()
		return err
	}
	opSock, err := ipc.Listen(ipc.ServerConfig{
		Path: cfg.OperatorSocket, Mode: 0o600, AllowedUIDs: []uint32{0},
		Ops: []ipc.Op{ipc.OpSnapshot, ipc.OpRevoke, ipc.OpReset},
	})
	if err != nil {
		dhcpConn.Close()
		guestSock.Close()
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	serve := func(name string, f func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f(); err != nil && ctx.Err() == nil {
				errs <- fmt.Errorf("%s: %w", name, err)
			}
			cancel()
		}()
	}
	serve("dhcp", func() error { return server.Serve(ctx, dhcpConn) })
	serve("guest socket", func() error { return guestSock.Serve(ctx, ctrl.GuestHandler()) })
	serve("operator socket", func() error { return opSock.Serve(ctx, ctrl.OperatorHandler()) })
	serve("reconcile", func() error { return ctrl.Run(ctx) })

	if readyFile != "" {
		if err := os.WriteFile(readyFile, []byte("ready\n"), 0o644); err != nil {
			cancel()
		}
	}
	log.Info("portcullisd serving", "guest", cfg.GuestInterface, "portal", cfg.PortalListen().String())
	<-ctx.Done()
	dhcpConn.Close()
	guestSock.Close()
	opSock.Close()
	wg.Wait()

	// An orderly stop ends authority immediately rather than leaving grants
	// to their kernel timeouts. A crash cannot do this, which is why every
	// start revokes inherited grants as well.
	flushCtx, flushCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer flushCancel()
	if err := k.FlushGrants(flushCtx); err != nil {
		log.Error("flushing grants on shutdown failed; kernel timeouts still bound them", "err", err)
	}
	select {
	case err := <-errs:
		return err
	default:
		return nil
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: portcullisd {bootstrap|attest|run} -config FILE [-ready-file FILE]")
	os.Exit(2)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "portcullisd:", err)
	os.Exit(1)
}
