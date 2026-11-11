// Package main converts CVEs to OSV format in bulk.
package main

import (
	"testing"

	"github.com/google/osv.dev/vulnfeeds/models"
)

func TestShouldSkipCVE(t *testing.T) {
	deniedCNAs := []string{"denied-cna", "another-denied"}

	tests := []struct {
		name     string
		state    string
		assigner string
		wantSkip bool
	}{
		{
			name:     "published and allowed CNA",
			state:    "PUBLISHED",
			assigner: "Linux",
			wantSkip: false,
		},
		{
			name:     "published and denied CNA",
			state:    "PUBLISHED",
			assigner: "denied-cna",
			wantSkip: true,
		},
		{
			name:     "rejected and allowed CNA",
			state:    "REJECTED",
			assigner: "Linux",
			wantSkip: false,
		},
		{
			name:     "rejected and denied CNA should still emit withdrawn tombstone",
			state:    "REJECTED",
			assigner: "denied-cna",
			wantSkip: false,
		},
		{
			name:     "reserved state skipped",
			state:    "RESERVED",
			assigner: "Linux",
			wantSkip: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cve := models.CVE5{
				Metadata: models.CVE5Metadata{
					CVEID:             "CVE-2026-1234",
					State:             tc.state,
					AssignerShortName: tc.assigner,
				},
			}
			if got := shouldSkipCVE(cve, deniedCNAs); got != tc.wantSkip {
				t.Errorf("shouldSkipCVE() = %v, want %v", got, tc.wantSkip)
			}
		})
	}
}
