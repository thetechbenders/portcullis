package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/thetechbenders/portcullis/internal/hostpreflight"
)

// watch is a bounded observer, never a host exposure or safety interlock.
// Every observation is assessed against the same private selection, and
// interface continuity is checked against the very first observation.
func watch(sel hostpreflight.Selection, private bool, samples int, out, diag io.Writer, collect func() hostpreflight.Snapshot, pause func()) int {
	encoder := json.NewEncoder(out)
	var baseline hostpreflight.Snapshot
	for i := 0; i < samples; i++ {
		if i > 0 {
			pause()
		}
		current := collect()
		report := hostpreflight.Evaluate(current, sel)
		if i == 0 {
			baseline = current
		} else {
			report.Hazards = append(report.Hazards, hostpreflight.ContinuityFindings(baseline, current)...)
		}
		if !private {
			report = hostpreflight.RedactReport(report)
		}
		// A JSON line per sample is explicit about which observations ran.
		record := struct {
			Sample int                  `json:"sample"`
			Report hostpreflight.Report `json:"report"`
		}{Sample: i + 1, Report: report}
		if err := encoder.Encode(record); err != nil {
			fmt.Fprintln(diag, "cannot encode watch observation:", err)
			return 3
		}
		if len(report.Hazards) > 0 {
			return 1
		}
	}
	// Zero observed hazards does not establish that packets were blocked
	// between samples, that an NIC cannot re-enumerate under an unknown name,
	// or that NetworkManager/physical deployment safety is proven.
	return 0
}
