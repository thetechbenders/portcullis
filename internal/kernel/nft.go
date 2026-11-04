package kernel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"unicode/utf8"
)

// ErrTableAbsent reports that nft listed no guard table. Only the specific
// ENOENT diagnostic maps here; any other failure stays an ErrCommand so that
// a broken nft is never mistaken for a missing table.
var ErrTableAbsent = errors.New("nftables guard table does not exist")

// guardTable must equal enforce.GuardTable. It is duplicated so this
// package does not depend on the renderer.
const guardTable = "portcullis_guard"

const maxBatch = 256 << 10

// NFT runs nft with batches rendered from typed values by internal/enforce.
type NFT struct{ x *Exec }

// NewNFT wraps an Exec validated for the configured nft path.
func NewNFT(x *Exec) *NFT { return &NFT{x: x} }

func (n *NFT) exec() *Exec {
	if n == nil {
		return nil
	}
	return n.x
}

// checkBatch accepts only UTF-8 text without control bytes other than tab
// and newline: rendered batches never need more, and NUL or CR could make
// what nft parses differ from what was logged or reviewed.
func checkBatch(batch string) error {
	if batch == "" || len(batch) > maxBatch {
		return fmt.Errorf("%w: nft batch is empty or exceeds %d bytes", ErrArgument, maxBatch)
	}
	if !utf8.ValidString(batch) {
		return fmt.Errorf("%w: nft batch is not valid UTF-8", ErrArgument)
	}
	for _, r := range batch {
		if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f {
			return fmt.Errorf("%w: nft batch contains a control byte", ErrArgument)
		}
	}
	return nil
}

// Apply commits batch as one atomic nft transaction (nft -f -).
func (n *NFT) Apply(ctx context.Context, batch string) error {
	if err := checkBatch(batch); err != nil {
		return err
	}
	_, err := n.exec().Run(ctx, []byte(batch), "-f", "-")
	return err
}

// Check parses and validates batch against the kernel without committing
// it (nft -c -f -).
func (n *NFT) Check(ctx context.Context, batch string) error {
	if err := checkBatch(batch); err != nil {
		return err
	}
	_, err := n.exec().Run(ctx, []byte(batch), "-c", "-f", "-")
	return err
}

// ListGuard returns nft -j list table inet portcullis_guard. The output is
// unverified; callers must attest it.
func (n *NFT) ListGuard(ctx context.Context) ([]byte, error) {
	out, err := n.list(ctx, "-j", "list", "table", "inet", guardTable)
	if err != nil && tableAbsent(err) {
		return nil, fmt.Errorf("%w: inet %s: %w", ErrTableAbsent, guardTable, err)
	}
	return out, err
}

// ListRuleset returns nft -j list ruleset for bypass attestation.
func (n *NFT) ListRuleset(ctx context.Context) ([]byte, error) {
	return n.list(ctx, "-j", "list", "ruleset")
}

func (n *NFT) list(ctx context.Context, args ...string) ([]byte, error) {
	out, err := n.exec().Run(ctx, nil, args...)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, fmt.Errorf("%w: nft %s produced no output", ErrCommand, args[1])
	}
	return out, nil
}

// tableAbsent matches nft's exit status 1 with a first stderr line of
// "Error: No such file or directory" (optionally followed by a hint).
func tableAbsent(err error) bool {
	code, stderr, ok := exitStderr(err)
	if !ok || code != 1 {
		return false
	}
	first, _, _ := bytes.Cut(bytes.TrimSpace(stderr), []byte("\n"))
	return bytes.HasPrefix(first, []byte("Error: No such file or directory"))
}
