package ecosystem

import (
	"errors"
	"testing"
)

func TestHex_GetVersions(t *testing.T) {
	t.Parallel()
	p := getTestProvider(t)
	e, ok := p.Get("Hex")
	if !ok {
		t.Fatalf("Failed to retrieve Hex ecosystem")
	}
	ecosystem := e.(Enumerable)

	t.Run("ash", func(t *testing.T) {
		versions, err := ecosystem.GetVersions("ash")
		if err != nil {
			t.Fatalf("failed to get Hex versions for ash: %v", err)
		}
		// Verify succession from Python tests
		checkNextVersion(t, versions, "3.6.3", "3.7.0")
	})
}

func TestHex_GetVersions_NotFound(t *testing.T) {
	t.Parallel()
	p := getTestProvider(t)
	e, ok := p.Get("Hex")
	if !ok {
		t.Fatalf("Failed to retrieve Hex ecosystem")
	}
	ecosystem := e.(Enumerable)
	_, err := ecosystem.GetVersions("doesnotexist123456")
	if !errors.Is(err, ErrPackageNotFound) {
		t.Errorf("expected ErrPackageNotFound, got %v", err)
	}
}
