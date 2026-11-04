//go:build netnslab

// Command portcullis-netns-policy emits an UNSAFE source-IP-based policy.
// This is compiled ONLY for disposable, privately isolated netns CI tests.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/thetechbenders/portcullis/internal/enforce"
)

func main() {
	guest := flag.String("guest", "", "fixture guest interface")
	uplink := flag.String("uplink", "", "fixture uplink interface")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}
	rules, err := enforce.RenderTimedFixturePolicy(*guest, *uplink)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if _, err := fmt.Print(rules); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
