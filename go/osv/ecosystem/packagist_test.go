package ecosystem

import (
	"errors"
	"testing"
)

func TestPackagist_GetVersions(t *testing.T) {
	setupHTTPClientForTest(t)
	e := packagistEcosystem{}

	t.Run("monolog/monolog", func(t *testing.T) {
		versions, err := e.GetVersions("monolog/monolog")
		if err != nil {
			t.Fatalf("GetVersions() err = %v", err)
		}
		if len(versions) == 0 {
			t.Errorf("GetVersions() returned 0 versions")
		}
		checkNextVersion(t, versions, "1.0.0", "1.0.1")
	})
}

func TestPackagist_GetVersions_NotFound(t *testing.T) {
	setupHTTPClientForTest(t)
	e := packagistEcosystem{}
	_, err := e.GetVersions("doesnotexist/doesnotexist")
	if !errors.Is(err, ErrPackageNotFound) {
		t.Errorf("expected ErrPackageNotFound, got %v", err)
	}
}
