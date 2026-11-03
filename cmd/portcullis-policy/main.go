// Command portcullis-policy emits nftables text only; it never executes nft.
// --test-fixture-timed-allow is exclusively for disposable network namespaces.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/thetechbenders/portcullis/internal/enforce"
)

func main() {
	guest := flag.String("guest", "", "gateway guest interface")
	uplink := flag.String("uplink", "", "fixture uplink interface")
	fixture := flag.Bool("test-fixture-timed-allow", false, "UNSAFE test-only source-IP authorization fixture")
	flag.Parse()

	var (
		rules string
		err   error
	)
	if *fixture {
		rules, err = enforce.RenderTimedFixturePolicy(*guest, *uplink)
	} else {
		if *uplink != "" {
			fmt.Fprintln(os.Stderr, "-uplink requires -test-fixture-timed-allow")
			os.Exit(2)
		}
		rules, err = enforce.RenderDenyBaseline(*guest)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Print(rules)
}
