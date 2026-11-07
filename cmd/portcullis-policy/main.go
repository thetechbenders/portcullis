// Command portcullis-policy emits inert nftables rules text.
// It never executes nftables or grants guest network access.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/thetechbenders/portcullis/internal/config"
	"github.com/thetechbenders/portcullis/internal/enforce"
)

func main() {
	guest := flag.String("guest", "", "gateway guest interface")
	reconcile := flag.Bool("reconcile", false, "update rules inside existing persistent base chains; fails if absent")
	guardConfig := flag.String("guard-config", "", "validated gateway config for inert guard bootstrap output")
	guestIfIndex := flag.Int("guest-ifindex", 0, "private guest ifindex for offline guard rendering")
	flag.Parse()
	if flag.NArg() != 0 || (*guestIfIndex != 0 && *guardConfig == "") {
		fmt.Fprintln(os.Stderr, "unexpected arguments")
		os.Exit(2)
	}
	var rules string
	var err error
	switch {
	case *guardConfig != "":
		if *reconcile || *guest != "" {
			fmt.Fprintln(os.Stderr, "guard-config cannot be combined with guest or reconcile")
			os.Exit(2)
		}
		var cfg *config.Config
		cfg, err = config.Load(*guardConfig)
		if err == nil {
			guard := enforce.GuardConfigFrom(cfg)
			if *guestIfIndex != 0 {
				guard.GuestIfIndex = *guestIfIndex
			}
			rules, err = enforce.RenderGuardBootstrap(guard)
		}
	case *reconcile:
		rules, err = enforce.RenderReconcileDeny(*guest)
	default:
		rules, err = enforce.RenderDenyBaseline(*guest)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if _, err := fmt.Print(rules); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
