// Command portcullis-host emits a read-only, non-authorizing host preflight.
// It cannot install, start or change any network service or interface.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/thetechbenders/portcullis/internal/hostpreflight"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "preflight" {
		usage()
	}
	fs := flag.NewFlagSet("preflight", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	guest := fs.String("guest", "", "operator-nominated guest interface")
	uplink := fs.String("uplink", "", "operator-nominated uplink interface")
	management := fs.String("management", "", "operator-nominated management interface")
	mac := fs.String("pinned-guest-mac", "", "expected guest interface MAC (never autodetected as authority)")
	path := fs.String("pinned-guest-sysfs", "", "expected canonical guest /sys/class/net target")
	planPath := fs.String("plan", "", "versioned, operator-pinned JSON host plan (read-only)")
	dryRun := fs.Bool("dry-run", true, "read-only inventory; must stay true")
	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 0 || !*dryRun {
		fmt.Fprintln(os.Stderr, "portcullis-host: preflight accepts no positional arguments or mutation mode")
		os.Exit(2)
	}
	selected := hostpreflight.Selection{
		Guest: *guest, Uplink: *uplink, Management: *management,
		PinnedGuestMAC: *mac, PinnedGuestSysfs: *path,
	}
	if *planPath != "" {
		if *guest != "" || *uplink != "" || *management != "" || *mac != "" || *path != "" {
			fmt.Fprintln(os.Stderr, "portcullis-host: -plan cannot be combined with individual interface flags")
			os.Exit(2)
		}
		var err error
		selected, err = hostpreflight.LoadPlan(*planPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "portcullis-host: invalid host plan:", err)
			os.Exit(2)
		}
	}
	report := hostpreflight.Evaluate(hostpreflight.Collect(), selected)
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	if err := e.Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, "portcullis-host: cannot encode report:", err)
		os.Exit(1)
	}
	// Exit 3 is deliberate, even when all observational checks are clear:
	// physical isolation, live policy attestation and recovery are unverified.
	os.Exit(3)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: portcullis-host preflight [-dry-run] [-plan FILE] [-guest IFACE] [-uplink IFACE] [-management IFACE] [-pinned-guest-mac MAC] [-pinned-guest-sysfs PATH]")
	os.Exit(2)
}
