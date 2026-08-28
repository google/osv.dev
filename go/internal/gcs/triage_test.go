package gcs_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/osv.dev/go/internal/gcs"
	"github.com/google/osv.dev/go/internal/models"
)

func TestNewTriageStore(t *testing.T) {
	t.Parallel()

	s := gcs.NewTriageStore(nil)
	if s == nil {
		t.Fatal("expected non-nil TriageStore")
	}
}

func TestTriageStore_GetFile_InvalidArgument(t *testing.T) {
	t.Parallel()

	s := gcs.NewTriageStore(nil)

	tests := []struct {
		name   string
		source string
		cveID  string
	}{
		{
			name:   "invalid cve format",
			source: "cve",
			cveID:  "INVALID-CVE",
		},
		{
			name:   "invalid source",
			source: "unknown-source",
			cveID:  "CVE-2024-1234",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := s.GetFile(context.Background(), tc.source, tc.cveID)
			if !errors.Is(err, models.ErrInvalidArgument) {
				t.Errorf("expected ErrInvalidArgument, got %v", err)
			}
		})
	}
}
