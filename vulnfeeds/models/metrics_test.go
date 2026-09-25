package models

import (
	"errors"
	"strings"
	"testing"
)

func TestConversionMetrics_SetError(t *testing.T) {
	metrics := &ConversionMetrics{
		CVEID: "CVE-2026-0001",
		CNA:   "test",
	}

	testErr := errors.New("rate limit reached: 429 Too Many Requests")
	metrics.SetError(testErr)

	if metrics.Outcome != Error {
		t.Errorf("expected Outcome to be Error, got %v", metrics.Outcome)
	}

	found := false
	for _, note := range metrics.Notes {
		if strings.Contains(note, "Conversion error:") && strings.Contains(note, "rate limit reached: 429 Too Many Requests") {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("expected error note in metrics.Notes, got notes: %v", metrics.Notes)
	}
}
