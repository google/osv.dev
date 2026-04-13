package ecosystem

import (
	"errors"
	"testing"
)

func TestMaven_GetVersions(t *testing.T) {
	t.Parallel()
	p := getTestProvider(t)
	e, ok := p.Get("Maven")
	if !ok {
		t.Fatalf("Failed to retrieve Maven ecosystem")
	}
	ecosystem := e.(Enumerable)

	t.Run("com.google.guava:guava", func(t *testing.T) {
		versions, err := ecosystem.GetVersions("com.google.guava:guava")
		if err != nil {
			t.Fatalf("GetVersions() err = %v", err)
		}
		if len(versions) == 0 {
			t.Errorf("GetVersions() returned 0 versions")
		}
		checkNextVersion(t, versions, "10.0", "10.0.1")
	})

	t.Run("io.grpc:grpc-core", func(t *testing.T) {
		versions, err := ecosystem.GetVersions("io.grpc:grpc-core")
		if err != nil {
			t.Fatalf("GetVersions() err = %v", err)
		}
		checkNextVersion(t, versions, "0", "0.7.0")
		checkNextVersion(t, versions, "1.35.1", "1.36.0")
	})
}

func TestMaven_GetVersions_NotFound(t *testing.T) {
	t.Parallel()
	p := getTestProvider(t)
	e, ok := p.Get("Maven")
	if !ok {
		t.Fatalf("Failed to retrieve Maven ecosystem")
	}
	ecosystem := e.(Enumerable)
	_, err := ecosystem.GetVersions("doesnotexist:doesnotexist")
	if !errors.Is(err, ErrPackageNotFound) {
		t.Errorf("expected ErrPackageNotFound, got %v", err)
	}
}
