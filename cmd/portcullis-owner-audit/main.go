// Command portcullis-owner-audit only reads a pinned physical guest plan,
// Linux host observations and narrowly whitelisted nmcli device properties.
// This is NOT a guest exposure gate or a NetworkManager configuration tool.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/thetechbenders/portcullis/internal/hostpreflight"
	"github.com/thetechbenders/portcullis/internal/owneraudit"
)

const fields = "GENERAL.NM-MANAGED,GENERAL.AUTOCONNECT,GENERAL.CONNECTION"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, hostpreflight.Collect, readNMDevice))
}

// readNMDevice executes exactly one read-only, bounded nmcli device-show query.
// No connection/profile listing or show-secrets mode is permitted.
func readNMDevice(ifname string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/nmcli", "-t", "-f", fields, "device", "show", ifname)
	cmd.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/bin:/bin"}
	cmd.Stderr = io.Discard
	// nmcli output is bounded without ever including its connection name
	// in diagnostics. Excess data is an observation failure.
	collector := &limitedOutput{limit: 4096}
	cmd.Stdout = collector
	err := cmd.Run()
	if err != nil || collector.overflow {
		return nil, owneraudit.ErrObservation
	}
	return collector.data, nil
}

type limitedOutput struct {
	data     []byte
	limit    int
	overflow bool
}

func (b *limitedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if len(p) > b.limit-len(b.data) {
		b.overflow = true
		return 0, owneraudit.ErrObservation
	}
	b.data = append(b.data, p...)
	return n, nil
}

// run is injectable, so every unit test uses synthetic host and nmcli data.
// Exit 0 means only that no observed hazard was found, NOT permission for UP.
func run(args []string, out, diag io.Writer, collect func() hostpreflight.Snapshot, query func(string) ([]byte, error)) int {
	if len(args) == 0 || args[0] != "check" {
		fmt.Fprintln(diag, "usage: portcullis-owner-audit check -plan FILE")
		return 2
	}
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(diag)
	planPath := fs.String("plan", "", "private versioned pinned host plan")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || *planPath == "" {
		return 2
	}
	selection, err := hostpreflight.LoadPlan(*planPath)
	if err != nil {
		fmt.Fprintln(diag, "invalid private host plan")
		return 2
	}
	host := hostpreflight.Evaluate(collect(), selection)
	data, queryErr := query(selection.Guest)
	guest, parseErr := owneraudit.ParseNMDevice(data)
	result := owneraudit.Evaluate(guest, queryErr == nil && parseErr == nil, len(host.Hazards) != 0)
	// Never place raw nmcli output, profile names, MACs, paths, hostnames,
	// boot IDs, IP addresses or plan digests into either output stream.
	if err := json.NewEncoder(out).Encode(result); err != nil {
		fmt.Fprintln(diag, "cannot encode owner audit")
		return 3
	}
	if len(result.Hazards) != 0 {
		return 1
	}
	return 0
}
