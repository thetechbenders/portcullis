// Command portcullis-policy emits inert nftables rules text.
// It never executes nftables or grants guest network access.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/thetechbenders/portcullis/internal/enforce"
)

func main() {
	guest := flag.String("guest", "", "gateway guest interface")
	reconcile := flag.Bool("reconcile", false, "update rules inside existing persistent base chains; fails if absent")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}
	var rules string
	var err error
	if *reconcile {
		rules, err = enforce.RenderReconcileDeny(*guest)
	} else {
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
