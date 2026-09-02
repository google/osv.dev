package website

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestFormatRelativeTime(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		val  time.Time
		want string
	}{
		{
			name: "Zero time",
			val:  time.Time{},
			want: "",
		},
		{
			name: "Just now",
			val:  now.Add(-10 * time.Second),
			want: "just now",
		},
		{
			name: "Minutes ago",
			val:  now.Add(-15 * time.Minute),
			want: "15 minutes ago",
		},
		{
			name: "Hours ago",
			val:  now.Add(-3 * time.Hour),
			want: "3 hours ago",
		},
		{
			name: "Yesterday",
			val:  now.Add(-26 * time.Hour),
			want: "yesterday",
		},
		{
			name: "Days ago",
			val:  now.Add(-4 * 24 * time.Hour),
			want: "4 days ago",
		},
		{
			name: "Date in same year",
			val:  time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC),
			want: "24 Jul",
		},
		{
			name: "Date in previous year",
			val:  time.Date(2024, 12, 6, 10, 0, 0, 0, time.UTC),
			want: "06 Dec 2024",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := formatRelativeTime(tt.val, now)
			if got != tt.want {
				t.Errorf("formatRelativeTime() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPrimarySeverity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		score      string
		wantLevel  string
		wantRating string
	}{
		{
			name:       "Critical CVSS 3.1 vector 9.8",
			score:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantLevel:  "critical",
			wantRating: "9.8 (Critical)",
		},
		{
			name:       "High CVSS 3.1 vector 7.5",
			score:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			wantLevel:  "high",
			wantRating: "7.5 (High)",
		},
		{
			name:       "Medium numeric score fallback 5.3",
			score:      "5.3",
			wantLevel:  "medium",
			wantRating: "5.3 (Medium)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			display := ListedVulnerabilityDisplay{
				Severities: []*osvschema.Severity{{Type: osvschema.Severity_CVSS_V3, Score: tt.score}},
			}

			sev := display.PrimarySeverity()
			if sev == nil {
				t.Fatalf("PrimarySeverity() = nil, want non-nil")
			}
			if sev.Level != tt.wantLevel {
				t.Errorf("PrimarySeverity().Level = %q, want %q", sev.Level, tt.wantLevel)
			}
			if sev.Rating != tt.wantRating {
				t.Errorf("PrimarySeverity().Rating = %q, want %q", sev.Rating, tt.wantRating)
			}
		})
	}
}

func TestPrimarySeverity_Ranking(t *testing.T) {
	t.Parallel()

	display := ListedVulnerabilityDisplay{
		Severities: []*osvschema.Severity{
			{Type: osvschema.Severity_CVSS_V2, Score: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
			{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		},
	}

	sev := display.PrimarySeverity()
	if sev == nil {
		t.Fatalf("PrimarySeverity() = nil, want non-nil")
	}

	if sev.Type != "CVSS_V3" {
		t.Errorf("PrimarySeverity().Type = %q, want %q", sev.Type, "CVSS_V3")
	}
	if sev.Level != "critical" {
		t.Errorf("PrimarySeverity().Level = %q, want %q", sev.Level, "critical")
	}
}

func TestDisplayPackages(t *testing.T) {
	t.Parallel()

	display := ListedVulnerabilityDisplay{
		Packages: []models.Package{
			{Package: &osvschema.Package{Ecosystem: "PyPI", Name: "requests"}},
			{Repo: "https://github.com/requests/requests"},
		},
	}

	got := display.DisplayPackages()
	want := []string{"PyPI/requests", "github.com/requests/requests"}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("DisplayPackages() = %v, want %v", got, want)
	}
}
