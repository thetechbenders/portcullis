# nft JSON fixtures

Captured from **nftables 1.0.9** (Ubuntu 24.04, kernel 6.18) inside a disposable
network namespace on a throwaway cloud runner, using the exact guard rendered for
`guest0`/`uplink0`/`10.203.0.1`, portal port 80, DNS port 53 and the default
protected prefixes. Element-bearing variants splice in the element shapes that the
same nft printed for `nft -j list set`:

- `guard_empty_nft-1.0.9.json`: verbatim `nft -j list table inet portcullis_guard` after bootstrap.
- `guard_elements_nft-1.0.9.json`: plus one bound, granted and granted_dst element (with timeouts).
- `guard_untimed_element_nft-1.0.9.json`: plus an element added **without** a timeout. nft 1.0.9
  accepts that on a `flags timeout` set, prints it as a bare value without an `elem` wrapper, and the
  kernel never expires it.
- `ruleset_dormant_truncated_nft-1.0.9.json`: verbatim `nft -j list ruleset` output when a dormant
  table exists. nft 1.0.9 truncates the JSON at the dormant table's `flags` and still exits 0.

Observed normalization: nft merged the adjacent protected prefixes `224.0.0.0/4` and
`240.0.0.0/4` into `224.0.0.0/3`. `expires` is typically one second below `timeout`
immediately after insertion.
