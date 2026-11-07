// Command portcullis-hostprep renders offline Pi 5 first-pilot files.
// It NEVER modifies /etc, starts services, or changes a network interface.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/thetechbenders/portcullis/internal/hostpolicy"
)

func main() { os.Exit(run(os.Args[1:], os.Stderr)) }

func run(args []string, diag io.Writer) int {
	fs := flag.NewFlagSet("hostprep", flag.ContinueOnError)
	fs.SetOutput(diag)
	identityPath := fs.String("identities", "", "private JSON file containing guest/uplink/management permanent MACs")
	output := fs.String("out", "", "new private output directory (must not exist)")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *identityPath == "" || *output == "" {
		fmt.Fprintln(diag, "usage: portcullis-hostprep -identities PRIVATE_JSON -out NEW_DIRECTORY")
		return 2
	}
	if err := prepare(*identityPath, *output); err != nil {
		// Fail without printing private MACs or caller-controlled file contents.
		fmt.Fprintln(diag, "hostprep refused:", errors.Unwrap(err) != nil)
		return 1
	}
	fmt.Fprintln(diag, "private candidate files written; nothing installed or activated")
	return 0
}

func prepare(identityPath, output string) error {
	f, err := os.Open(identityPath)
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("identity: unsafe file permissions")
	}
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) > 4096 {
		return fmt.Errorf("identity: oversized file")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var ids hostpolicy.Identity
	if err := decoder.Decode(&ids); err != nil {
		return fmt.Errorf("identity: malformed JSON")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return fmt.Errorf("identity: trailing data")
	}
	nm, err := hostpolicy.RenderGuestExclusion(ids)
	if err != nil {
		return err
	}
	netplan, err := hostpolicy.RenderUplinkNetplanDefinition(ids)
	if err != nil {
		return err
	}
	output = filepath.Clean(output)
	if !filepath.IsAbs(output) {
		return fmt.Errorf("output: absolute path required")
	}
	if err := os.Mkdir(output, 0700); err != nil {
		return fmt.Errorf("output: cannot create private directory")
	}
	for filename, content := range map[string]string{
		"20-portcullis-ethernet-ownership.conf": nm,
		"uplink-netplan-fragment.yaml":           netplan,
		"nftables-service-override.candidate":    hostpolicy.RenderNftablesServiceOverride(),
	} {
		if err := os.WriteFile(filepath.Join(output, filename), []byte(content), 0600); err != nil {
			return fmt.Errorf("output: cannot write candidate")
		}
	}
	return nil
}
