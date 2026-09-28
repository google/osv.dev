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
