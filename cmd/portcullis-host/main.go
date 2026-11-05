// Command portcullis-host inspects a Linux host without mutating networking.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/thetechbenders/portcullis/internal/hostpreflight"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, hostpreflight.Collect))
}

// run is independently testable without invoking any privileged service or
// touching a live interface. Nothing from this CLI authorizes activation.
func run(args []string, out io.Writer, diag io.Writer, collect func() hostpreflight.Snapshot) int {
	if len(args) == 0 || (args[0] != "inventory" && args[0] != "check") {
		fmt.Fprintln(diag, "usage: portcullis-host inventory [-private] | check -plan FILE [-private]")
		return 2
	}
	mode := args[0]
	fs := flag.NewFlagSet(mode, flag.ContinueOnError)
	fs.SetOutput(diag)
	private := fs.Bool("private", false, "include sensitive device, network and plan identifiers in output")
	planPath := fs.String("plan", "", "strict versioned operator-pinned host plan (check only)")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		return 2
	}
	if mode == "inventory" && *planPath != "" {
		fmt.Fprintln(diag, "inventory cannot select or validate a deployment plan")
		return 2
	}
	if mode == "check" && *planPath == "" {
		fmt.Fprintln(diag, "check requires -plan FILE")
		return 2
	}
	var sel hostpreflight.Selection
	if mode == "check" {
		var err error
		sel, err = hostpreflight.LoadPlan(*planPath)
		if err != nil {
			fmt.Fprintln(diag, "invalid host plan:", err)
			return 2
		}
	}
	snapshot := collect()
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	if mode == "inventory" {
		if !*private {
			snapshot = hostpreflight.RedactSnapshot(snapshot)
		}
		if err := encoder.Encode(snapshot); err != nil {
			fmt.Fprintln(diag, "cannot encode inventory:", err)
			return 1
		}
		if len(snapshot.InventoryError) != 0 {
			return 1
		}
		return 0
	}
	report := hostpreflight.Evaluate(snapshot, sel)
	if !*private {
		report.Selection.PinnedGuestMAC = ""
		report.Selection.PinnedGuestSysfs = ""
		report.BootID = ""
	}
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(diag, "cannot encode assessment:", err)
		return 1
	}
	if len(report.Hazards) != 0 {
		return 1
	}
	// Zero observed hazards is NOT readiness to enable the interface.
	// See the independent unresolved gates in report.NotAssessed.
	return 0
}
