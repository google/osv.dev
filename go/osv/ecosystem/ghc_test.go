package ecosystem

import (
	"testing"
)

func TestGHC_GetVersions(t *testing.T) {
	t.Parallel()
	p := getTestProvider(t)
	ecosystem := ghcEcosystem{p: p}

	t.Run("ghc", func(t *testing.T) {
		versions, err := ecosystem.GetVersions("ghc")
		if err != nil {
			t.Fatalf("GetVersions() err = %v", err)
		}
		if len(versions) == 0 {
			t.Errorf("GetVersions() returned 0 versions")
		}
		checkNextVersion(t, versions, "0", "0.29")
		checkNextVersion(t, versions, "7.0.4-rc1", "7.0.4")
		checkNextVersion(t, versions, "7.0.4", "7.2.1")
	})
}
