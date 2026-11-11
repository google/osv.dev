package gcs_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/osv.dev/go/internal/gcs"
	"github.com/google/osv.dev/go/internal/models"
)

func TestNewLinterStore(t *testing.T) {
	t.Parallel()

	s := gcs.NewLinterStore(nil, "")
	if s == nil {
		t.Fatal("expected non-nil LinterStore")
	}

	sWithPrefix := gcs.NewLinterStore(nil, "custom-prefix")
	if sWithPrefix == nil {
		t.Fatal("expected non-nil LinterStore")
	}
}

func TestGetFindings_InvalidSource(t *testing.T) {
	t.Parallel()

	s := gcs.NewLinterStore(nil, "")
	invalidSources := []string{"", ".", "../etc/passwd", "a/b", "..", "/root"}

	for _, src := range invalidSources {
		_, err := s.GetFindings(context.Background(), src)
		if !errors.Is(err, models.ErrNotFound) {
			t.Errorf("expected ErrNotFound for source %q, got %v", src, err)
		}
	}
}

func TestParseLinterResultObjectName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		prefix string
		name   string
		want   string
		wantOK bool
	}{
		{"linter-result/", "linter-result/ghsa/result.json", "ghsa", true},
		{"linter-result/", "linter-result/cve-osv/result.json", "cve-osv", true},
		{"linter-result/", "linter-result/result.json", "", false},
		{"linter-result/", "linter-result/ghsa/sub/result.json", "", false},
		{"linter-result/", "linter-result/ghsa/other.json", "", false},
		{"linter-result/", "other-prefix/ghsa/result.json", "", false},
		{"linter-result/", "linter-result/../result.json", "", false},
	}

	for _, tc := range tests {
		got, ok := gcs.ParseLinterResultObjectName(tc.prefix, tc.name)
		if ok != tc.wantOK || got != tc.want {
			t.Errorf("ParseLinterResultObjectName(%q, %q) = (%q, %v), want (%q, %v)",
				tc.prefix, tc.name, got, ok, tc.want, tc.wantOK)
		}
	}
}
