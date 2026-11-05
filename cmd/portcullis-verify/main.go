// Command portcullis-verify checks observed nftables JSON without
// installing rules, changing network state, or invoking nft.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/thetechbenders/portcullis/internal/enforce"
)

func main() {
	guest := flag.String("guest", "", "expected guest interface")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20+1))
	if err == nil {
		err = enforce.VerifyDenyGuardJSON(data, *guest)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("guard matches expected deny-only snapshot")
}
