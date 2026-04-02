package ecosystem

import (
	"errors"
	"testing"
)

func TestHackage_GetVersions(t *testing.T) {
	t.Parallel()
	p := getTestProvider(t)
	e, ok := p.Get("Hackage")
	if !ok {
		t.Fatalf("Failed to retrieve Hackage ecosystem")
	}
	ecosystem := e.(Enumerable)

	t.Run("aeson", func(t *testing.T) {
		versions, err := ecosystem.GetVersions("aeson")
		if err != nil {
			t.Fatalf("failed to get Hackage versions for aeson: %v", err)
		}
		// Verify succession from Python tests
		checkNextVersion(t, versions, "0.11.3.0", "1.0.0.0")
		checkNextVersion(t, versions, "1.0.0.0", "1.0.1.0")
	})
}

func TestHackage_GetVersions_NotFound(t *testing.T) {
	t.Parallel()
	p := getTestProvider(t)
	e, ok := p.Get("Hackage")
	if !ok {
		t.Fatalf("Failed to retrieve Hackage ecosystem")
	}
	ecosystem := e.(Enumerable)
	_, err := ecosystem.GetVersions("doesnotexist123456")
	if !errors.Is(err, ErrPackageNotFound) {
		t.Errorf("expected ErrPackageNotFound, got %v", err)
	}
}
