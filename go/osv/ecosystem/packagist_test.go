package ecosystem

import (
	"errors"
	"slices"
	"testing"
)

func TestPackagist_GetVersions(t *testing.T) {
	t.Parallel()
	p := getTestProvider(t)
	e, ok := p.Get("Packagist")
	if !ok {
		t.Fatalf("Failed to retrieve Packagist ecosystem")
	}
	ecosystem := e.(Enumerable)

	t.Run("monolog/monolog", func(t *testing.T) {
		versions, err := ecosystem.GetVersions("monolog/monolog")
		if err != nil {
			t.Fatalf("GetVersions() err = %v", err)
		}
		if len(versions) == 0 {
			t.Errorf("GetVersions() returned 0 versions")
		}
		checkNextVersion(t, versions, "1.0.0", "1.0.1")
	})

	t.Run("neos/neos", func(t *testing.T) {
		versions, err := ecosystem.GetVersions("neos/neos")
		if err != nil {
			t.Fatalf("GetVersions() err = %v", err)
		}
		expected := []string{"4.3.19", "4.2.18", "3.3.1", "3.3.0"}
		for _, ex := range expected {
			if !slices.Contains(versions, ex) {
				t.Errorf("expected versions to contain %s", ex)
			}
		}
	})
}

func TestPackagist_GetVersions_NotFound(t *testing.T) {
	t.Parallel()
	p := getTestProvider(t)
	e, ok := p.Get("Packagist")
	if !ok {
		t.Fatalf("Failed to retrieve Packagist ecosystem")
	}
	ecosystem := e.(Enumerable)
	_, err := ecosystem.GetVersions("doesnotexist/doesnotexist")
	if !errors.Is(err, ErrPackageNotFound) {
		t.Errorf("expected ErrPackageNotFound, got %v", err)
	}
}
