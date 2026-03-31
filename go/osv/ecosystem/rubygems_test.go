package ecosystem

import (
	"errors"
	"testing"
)

func TestRubyGems_GetVersions(t *testing.T) {
	t.Parallel()
	p := getTestProvider(t)
	e, ok := p.Get("RubyGems")
	if !ok {
		t.Fatalf("Failed to retrieve RubyGems ecosystem")
	}
	ecosystem := e.(Enumerable)
	versions, err := ecosystem.GetVersions("rails")
	if err != nil {
		t.Fatalf("failed to get RubyGems versions for rails: %v", err)
	}
	if len(versions) == 0 {
		t.Fatalf("expected versions, got empty list")
	}

	checkNextVersion(t, versions, "0", "0.8.0")
	checkNextVersion(t, versions, "0.9.4.1", "0.9.5")
	checkNextVersion(t, versions, "2.3.7", "2.3.8.pre1")
	checkNextVersion(t, versions, "4.0.0.beta1", "4.0.0.rc1")
	checkNextVersion(t, versions, "5.0.0.beta4", "5.0.0.racecar1")
}

func TestRubyGems_GetVersions_NotFound(t *testing.T) {
	t.Parallel()
	p := getTestProvider(t)
	e, ok := p.Get("RubyGems")
	if !ok {
		t.Fatalf("Failed to retrieve RubyGems ecosystem")
	}
	ecosystem := e.(Enumerable)
	_, err := ecosystem.GetVersions("doesnotexist123456")
	if !errors.Is(err, ErrPackageNotFound) {
		t.Errorf("expected ErrPackageNotFound, got %v", err)
	}
}
