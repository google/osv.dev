package ecosystem

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TODO(michaelkedar): See bioconductor.go for why these are skipped.

func TestBioconductor_GetBiocVersions(t *testing.T) {
	t.SkipNow()
	p := getTestProvider(t)
	versions, err := bioconductorEcosystem{p: p}.getBiocVersions()
	if err != nil {
		t.Errorf("getBiocVersions() error = %v", err)
		return
	}
	if len(versions) == 0 {
		t.Errorf("getBiocVersions() returned no versions")
		return
	}
	expectedVersions := []string{"3.23", "3.22", "3.21", "3.20", "3.19", "3.18", "3.17", "3.16", "3.15", "3.14", "3.13", "3.12", "3.11", "3.10", "3.9", "3.8", "3.7", "3.6", "3.5", "3.4", "3.3", "3.2", "3.1"}
	if diff := cmp.Diff(expectedVersions, versions); diff != "" {
		t.Errorf("getBiocVersions() diff: %s", diff)
	}
}

func TestBioconductor_GetVersions(t *testing.T) {
	t.SkipNow()
	p := getTestProvider(t)
	versions, err := bioconductorEcosystem{p: p}.getVersions("a4") // TODO(michaelkedar): getVersions -> GetVersions
	if err != nil {
		t.Errorf("GetVersions() error = %v", err)
		return
	}
	if len(versions) == 0 {
		t.Errorf("GetVersions() returned no versions")
		return
	}
	expectedVersions := []string{} // ???
	if diff := cmp.Diff(expectedVersions, versions); diff != "" {
		t.Errorf("GetVersions() diff: %s", diff)
	}
}

func TestBioconductor_GetVersionsNotFound(t *testing.T) {
	t.SkipNow()
	p := getTestProvider(t)
	_, err := bioconductorEcosystem{p: p}.getVersions("doesnotexist123456") // TODO(michaelkedar): getVersions -> GetVersions
	if !errors.Is(err, ErrPackageNotFound) {
		t.Errorf("GetVersions() error = %v, want %v", err, ErrPackageNotFound)
	}
}
