package ecosystem

import (
	"errors"
	"testing"
)

func TestPub_GetVersions(t *testing.T) {
	t.Parallel()
	p := getTestProvider(t)
	e, ok := p.Get("Pub")
	if !ok {
		t.Fatalf("Failed to retrieve Pub ecosystem")
	}
	ecosystem := e.(Enumerable)

	t.Run("pub_semver", func(t *testing.T) {
		versions, err := ecosystem.GetVersions("pub_semver")
		if err != nil {
			t.Fatalf("failed to get Pub versions for pub_semver: %v", err)
		}
		// Verify succession from Python tests
		checkNextVersion(t, versions, "1.4.4", "2.0.0-nullsafety.0")
		checkNextVersion(t, versions, "2.0.0-nullsafety.0", "2.0.0")
		checkNextVersion(t, versions, "2.0.0", "2.1.0")
	})

	t.Run("mockito", func(t *testing.T) {
		versions, err := ecosystem.GetVersions("mockito")
		if err != nil {
			t.Fatalf("failed to get Pub versions for mockito: %v", err)
		}
		checkNextVersion(t, versions, "3.0.0-alpha", "3.0.0-alpha+2")
	})
}

func TestPub_GetVersions_NotFound(t *testing.T) {
	t.Parallel()
	p := getTestProvider(t)
	e, ok := p.Get("Pub")
	if !ok {
		t.Fatalf("Failed to retrieve Pub ecosystem")
	}
	ecosystem := e.(Enumerable)
	_, err := ecosystem.GetVersions("doesnotexist123456")
	if !errors.Is(err, ErrPackageNotFound) {
		t.Errorf("expected ErrPackageNotFound, got %v", err)
	}
}
