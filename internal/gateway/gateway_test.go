package gateway

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thetechbenders/portcullis/internal/kernel"
)

// A successful ip link set exit is insufficient: the kernel must confirm
// administrative DOWN, otherwise we must report isolation unconfirmed.
func TestLinkFailsafeRequiresDownReadback(t *testing.T) {
	for _, tc := range []struct {
		name    string
		flags   string
		setExit int
		wantErr bool
		wantTop bool
	}{
		{"link-down-confirmed", `["BROADCAST"]`, 0, false, false},
		{"link-still-up", `["BROADCAST","UP"]`, 0, true, true},
		{"setdown-command-fails", `["BROADCAST"]`, 1, true, false},
		{"malformed-inspection", `{"bad":true}`, 0, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ip")
			script := fmt.Sprintf(`#!/bin/sh
if [ "$1" = "link" ]; then
  exit %d
fi
if [ "$1" = "-j" ]; then
  echo '[{"ifname":"guest0","flags":%s}]'
  exit 0
fi
exit 2
`, tc.setExit, tc.flags)
			if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			x, err := kernel.NewExec(path, time.Second, kernel.InsecureAllowNonRootForTests())
			if err != nil {
				t.Fatal(err)
			}
			l := LinkFailsafe{Link: kernel.NewLink(x), Interface: "guest0"}
			err = l.Engage(context.Background(), "test")
			if (err != nil) != tc.wantErr {
				t.Fatalf("Engage() error %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantTop && !errors.Is(err, kernel.ErrTopology) {
				t.Fatalf("link remained UP but returned %v", err)
			}
		})
	}
}
