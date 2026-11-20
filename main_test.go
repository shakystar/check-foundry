package main

import (
	"github.com/shakystar/check-foundry/internal/osv"
	"testing"
)

func TestMissingPackageProducesPartialReport(t *testing.T) {
	r := report{}
	result := osv.Result{Eligible: 2, Evidence: osv.Evidence{Checked: 1, Findings: []osv.Finding{{ID: "GHSA-example"}}}}
	applyOSV(&r, result, nil)
	if r.Status != "partial" || r.Checked != 1 || len(r.Findings) != 1 || r.Reason != "matched 1/2 eligible versions; excluded 0 entries" {
		t.Fatalf("report: %+v", r)
	}
}
