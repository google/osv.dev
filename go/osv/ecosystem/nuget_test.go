package ecosystem

import (
	"errors"
	"testing"
)

func TestNuGet_GetVersions(t *testing.T) {
	setupHTTPClientForTest(t)
	e := nugetEcosystem{}

	t.Run("Newtonsoft.Json", func(t *testing.T) {
		versions, err := e.GetVersions("Newtonsoft.Json")
		if err != nil {
			t.Fatalf("GetVersions() err = %v", err)
		}
		if len(versions) == 0 {
			t.Errorf("GetVersions() returned 0 versions")
		}
		checkNextVersion(t, versions, "13.0.3", "13.0.4-beta1")
	})
}

func TestNuGet_GetVersions_NotFound(t *testing.T) {
	setupHTTPClientForTest(t)
	e := nugetEcosystem{}
	_, err := e.GetVersions("DoesNotExist.123456")
	if !errors.Is(err, ErrPackageNotFound) {
		t.Errorf("expected ErrPackageNotFound, got %v", err)
	}
}
