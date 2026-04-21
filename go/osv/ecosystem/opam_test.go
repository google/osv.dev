package ecosystem

import (
	"errors"
	"testing"
)

func TestOpam_getVersions(t *testing.T) {
	t.Parallel()
	p := getTestProvider(t)
	ecosystem := opamEcosystem{p: p}

	t.Run("zarith", func(t *testing.T) {
		versions, err := ecosystem.getVersions("zarith")
		if err != nil {
			t.Fatalf("getVersions() err = %v", err)
		}
		if len(versions) == 0 {
			t.Errorf("getVersions() returned 0 versions")
		}
		checkNextVersion(t, versions, "1.12", "1.13")
	})
}

func TestOpam_getVersions_NotFound(t *testing.T) {
	t.Parallel()
	p := getTestProvider(t)
	ecosystem := opamEcosystem{p: p}
	_, err := ecosystem.getVersions("doesnotexist123456")
	if !errors.Is(err, ErrPackageNotFound) {
		t.Errorf("expected ErrPackageNotFound, got %v", err)
	}
}
