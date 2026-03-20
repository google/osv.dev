package ecosystem

import (
	"errors"
	"testing"
)

func TestHackage_GetVersions(t *testing.T) {
	setupHTTPClientForTest(t)
	ecosystem := hackageEcosystem{}

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
	setupHTTPClientForTest(t)
	ecosystem := hackageEcosystem{}
	_, err := ecosystem.GetVersions("doesnotexist123456")
	if !errors.Is(err, ErrPackageNotFound) {
		t.Errorf("expected ErrPackageNotFound, got %v", err)
	}
}
