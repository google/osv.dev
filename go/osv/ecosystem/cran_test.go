package ecosystem

import (
	"errors"
	"testing"
)

func TestCRAN_GetVersions(t *testing.T) {
	t.Parallel()
	p := getTestProvider(t)
	e, ok := p.Get("CRAN")
	if !ok {
		t.Fatalf("Failed to retrieve CRAN ecosystem")
	}
	ecosystem := e.(Enumerable)

	t.Run("readxl", func(t *testing.T) {
		versions, err := ecosystem.GetVersions("readxl")
		if err != nil {
			t.Fatalf("failed to get CRAN versions for readxl: %v", err)
		}
		// Test typical semver X.Y.Z version
		checkNextVersion(t, versions, "0.1.0", "0.1.1")
		checkNextVersion(t, versions, "0.1.1", "1.0.0")
	})

	t.Run("aqp", func(t *testing.T) {
		// Test atypical versioned package
		versions, err := ecosystem.GetVersions("aqp")
		if err != nil {
			t.Fatalf("failed to get CRAN versions for aqp: %v", err)
		}
		checkNextVersion(t, versions, "0.99-8.1", "0.99-8.47")
	})
}

func TestCRAN_GetVersions_NotFound(t *testing.T) {
	t.Parallel()
	p := getTestProvider(t)
	e, ok := p.Get("CRAN")
	if !ok {
		t.Fatalf("Failed to retrieve CRAN ecosystem")
	}
	ecosystem := e.(Enumerable)
	_, err := ecosystem.GetVersions("doesnotexist123456")
	if !errors.Is(err, ErrPackageNotFound) {
		t.Errorf("expected ErrPackageNotFound, got %v", err)
	}
}
