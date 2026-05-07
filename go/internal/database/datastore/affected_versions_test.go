package datastore

import (
	"cmp"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestComputeAffectedVersions(t *testing.T) {
	vuln := &osvschema.Vulnerability{
		Id: "TEST-123",
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{
					Name:      "testjs",
					Ecosystem: "npm",
				},
				Versions: []string{"0.1.0", "0.2.0", "0.3.0", "2.0.0", "2.1.0", "2.2.0"},
				Ranges: []*osvschema.Range{
					{
						Type: osvschema.Range_ECOSYSTEM,
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{Fixed: "1.0.0"},
						},
					},
					{
						Type: osvschema.Range_ECOSYSTEM,
						Events: []*osvschema.Event{
							{Introduced: "2.0.0"},
							{LastAffected: "2.2.0"},
						},
					},
				},
			},
			{
				Package: &osvschema.Package{
					Name:      "test",
					Ecosystem: "Ubuntu:24.04:LTS",
				},
				Versions: []string{"1.0.0-1", "1.0.0-2"},
				Ranges: []*osvschema.Range{
					{
						Type: osvschema.Range_ECOSYSTEM,
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{Fixed: "1.0.0-3"},
						},
					},
				},
			},
		},
	}

	got := computeAffectedVersions(vuln)

	want := []AffectedVersions{
		{
			VulnID:    "TEST-123",
			Ecosystem: "npm",
			Name:      "testjs",
			Events: []AffectedEvent{
				{Type: "introduced", Value: "0"},
				{Type: "fixed", Value: "1.0.0"},
			},
			CoarseMin: "00:00000000.00000000.00000000",
			CoarseMax: "00:00000001.00000000.00000000",
		},
		{
			VulnID:    "TEST-123",
			Ecosystem: "npm",
			Name:      "testjs",
			Events: []AffectedEvent{
				{Type: "introduced", Value: "2.0.0"},
				{Type: "last_affected", Value: "2.2.0"},
			},
			CoarseMin: "00:00000002.00000000.00000000",
			CoarseMax: "00:00000002.00000002.00000000",
		},
		{
			VulnID:    "TEST-123",
			Ecosystem: "npm",
			Name:      "testjs",
			Versions:  []string{"0.1.0", "0.2.0", "0.3.0", "2.0.0", "2.1.0", "2.2.0"},
			CoarseMin: "00:00000000.00000001.00000000",
			CoarseMax: "00:00000002.00000002.00000000",
		},
		{
			VulnID:    "TEST-123",
			Ecosystem: "Ubuntu:24.04:LTS",
			Name:      "test",
			Events: []AffectedEvent{
				{Type: "introduced", Value: "0"},
				{Type: "fixed", Value: "1.0.0-3"},
			},
			CoarseMin: "00:00000000.00000000.00000000",
			CoarseMax: "00:00000001.00000000.00000000",
		},
		{
			VulnID:    "TEST-123",
			Ecosystem: "Ubuntu:24.04",
			Name:      "test",
			Events: []AffectedEvent{
				{Type: "introduced", Value: "0"},
				{Type: "fixed", Value: "1.0.0-3"},
			},
			CoarseMin: "00:00000000.00000000.00000000",
			CoarseMax: "00:00000001.00000000.00000000",
		},
		{
			VulnID:    "TEST-123",
			Ecosystem: "Ubuntu",
			Name:      "test",
			Events: []AffectedEvent{
				{Type: "introduced", Value: "0"},
				{Type: "fixed", Value: "1.0.0-3"},
			},
			CoarseMin: "00:00000000.00000000.00000000",
			CoarseMax: "00:00000001.00000000.00000000",
		},
		{
			VulnID:    "TEST-123",
			Ecosystem: "Ubuntu:24.04:LTS",
			Name:      "test",
			Versions:  []string{"1.0.0-1", "1.0.0-2"},
			CoarseMin: "00:00000001.00000000.00000000",
			CoarseMax: "00:00000001.00000000.00000000",
		},
		{
			VulnID:    "TEST-123",
			Ecosystem: "Ubuntu:24.04",
			Name:      "test",
			Versions:  []string{"1.0.0-1", "1.0.0-2"},
			CoarseMin: "00:00000001.00000000.00000000",
			CoarseMax: "00:00000001.00000000.00000000",
		},
		{
			VulnID:    "TEST-123",
			Ecosystem: "Ubuntu",
			Name:      "test",
			Versions:  []string{"1.0.0-1", "1.0.0-2"},
			CoarseMin: "00:00000001.00000000.00000000",
			CoarseMax: "00:00000001.00000000.00000000",
		},
	}

	sortOpt := cmpopts.SortSlices(func(a, b AffectedVersions) bool {
		return cmp.Or(
			cmp.Compare(a.Ecosystem, b.Ecosystem),
			cmp.Compare(len(a.Versions), len(b.Versions)),
			cmp.Compare(len(a.Events), len(b.Events)),
			cmp.Compare(a.CoarseMin, b.CoarseMin),
			cmp.Compare(a.CoarseMax, b.CoarseMax),
		) < 0
	})

	if diff := gocmp.Diff(want, got, cmpopts.EquateEmpty(), sortOpt); diff != "" {
		t.Errorf("computeAffectedVersions mismatch (-want +got):\n%s", diff)
	}
}

func TestNormalizeRepo(t *testing.T) {
	testCases := []struct {
		repoURL  string
		expected string
	}{
		{"http://git.musl-libc.org/git/musl", "git.musl-libc.org/git/musl"},
		{"https://git.musl-libc.org/git/musl", "git.musl-libc.org/git/musl"},
		{"git://git.musl-libc.org/git/musl", "git.musl-libc.org/git/musl"},
		{"http://github.com/user/repo", "github.com/user/repo"},
		{"https://github.com/user/repo", "github.com/user/repo"},
		{"git://github.com/user/repo", "github.com/user/repo"},
		{"https://github.com/user/repo/", "github.com/user/repo"},
		{"http://git.example.com/path/", "git.example.com/path"},
		{"https://github.com/user/repo.git", "github.com/user/repo"},
		{"http://git.example.com/repo.git", "git.example.com/repo"},
		{"", ""},
		{"http://", ""},
		{"https://hostname", "hostname"},
	}

	for _, tc := range testCases {
		t.Run(tc.repoURL, func(t *testing.T) {
			got := normalizeRepo(tc.repoURL)
			if got != tc.expected {
				t.Errorf("normalizeRepo(%q) = %q, want %q", tc.repoURL, got, tc.expected)
			}
		})
	}
}
