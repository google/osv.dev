package ecosystem

import (
	"errors"
	"slices"
	"testing"
)

func TestCRAN_GetVersions(t *testing.T) {
	setupHTTPClientForTest(t)
	ecosystem := cranEcosystem{}
	versions, err := ecosystem.GetVersions("readxl")
	if err != nil {
		t.Fatalf("failed to get CRAN versions for readxl: %v", err)
	}
	expectedVersions := []string{"0.1.0", "0.1.1", "1.0.0", "1.1.0", "1.2.0",
		"1.3.0", "1.3.1", "1.4.0", "1.4.1", "1.4.2", "1.4.3", "1.4.4", "1.4.5"}
	if !slices.Equal(versions, expectedVersions) {
		t.Errorf("expected versions %v, got %v", expectedVersions, versions)
	}

	// Test atypical versioned package
	versions, err = ecosystem.GetVersions("aqp")
	if err != nil {
		t.Fatalf("failed to get CRAN versions for aqp: %v", err)
	}
	expectedVersions = []string{"0.80", "0.85", "0.88", "0.90",
		"0.94", "0.94-1", "0.97", "0.98-3", "0.99-1", "0.99-5",
		"0.99-8", "0.99-8.1", "0.99-8.47", "0.99-8.56", "0.99-9", "0.99-9.1", "0.99-9.51",
		"1.0", "1.2-5", "1.2-7", "1.3", "1.4", "1.5", "1.5-2", "1.5-3", "1.6", "1.7", "1.7-7",
		"1.8", "1.8-6", "1.9.2", "1.9.3", "1.9.10", "1.9.14", "1.10", "1.15", "1.16", "1.16-3",
		"1.17", "1.18", "1.18.1", "1.19", "1.25", "1.27", "1.29", "1.30", "1.31", "1.32",
		"1.40", "1.41", "1.42", "2.0", "2.0.1", "2.0.2", "2.0.3", "2.0.4", "2.1.0", "2.2", "2.2-1", "2.3"}
	if !slices.Equal(versions, expectedVersions) {
		t.Errorf("expected versions %v, got %v", expectedVersions, versions)
	}
}

func TestCRAN_GetVersions_NotFound(t *testing.T) {
	setupHTTPClientForTest(t)
	ecosystem := cranEcosystem{}
	_, err := ecosystem.GetVersions("doesnotexist123456")
	if !errors.Is(err, ErrPackageNotFound) {
		t.Errorf("expected ErrPackageNotFound, got %v", err)
	}
}
