package ecosystem

import (
	"errors"
	"testing"
)

func TestPyPI_GetVersions(t *testing.T) {
	t.Parallel()
	p := getTestProvider(t)
	e, ok := p.Get("PyPI")
	if !ok {
		t.Fatalf("Failed to retrieve PyPI ecosystem")
	}
	ecosystem := e.(Enumerable)

	t.Run("grpcio", func(t *testing.T) {
		versions, err := ecosystem.GetVersions("grpcio")
		if err != nil {
			t.Fatalf("failed to get PyPI versions for grpcio: %v", err)
		}
		checkNextVersion(t, versions, "1.35.0", "1.36.0rc1")
		checkNextVersion(t, versions, "1.36.0", "1.36.1")
	})
}

func TestPyPI_GetVersions_NotFound(t *testing.T) {
	t.Parallel()
	p := getTestProvider(t)
	e, ok := p.Get("PyPI")
	if !ok {
		t.Fatalf("Failed to retrieve PyPI ecosystem")
	}
	ecosystem := e.(Enumerable)
	_, err := ecosystem.GetVersions("doesnotexist123456")
	if !errors.Is(err, ErrPackageNotFound) {
		t.Errorf("expected ErrPackageNotFound, got %v", err)
	}
}
