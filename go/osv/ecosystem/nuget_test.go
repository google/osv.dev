package ecosystem

import (
	"errors"
	"testing"
)

func TestNuGet_GetVersions(t *testing.T) {
	t.Parallel()
	p := getTestProvider(t)
	e, ok := p.Get("NuGet")
	if !ok {
		t.Fatalf("Failed to retrieve NuGet ecosystem")
	}
	ecosystem := e.(Enumerable)

	t.Run("Newtonsoft.Json", func(t *testing.T) {
		versions, err := ecosystem.GetVersions("Newtonsoft.Json")
		if err != nil {
			t.Fatalf("GetVersions() err = %v", err)
		}
		if len(versions) == 0 {
			t.Errorf("GetVersions() returned 0 versions")
		}
		checkNextVersion(t, versions, "13.0.3", "13.0.4-beta1")
	})

	t.Run("NuGet.Server.Core", func(t *testing.T) {
		versions, err := ecosystem.GetVersions("NuGet.Server.Core")
		if err != nil {
			t.Fatalf("GetVersions() err = %v", err)
		}
		checkNextVersion(t, versions, "3.0.0", "3.0.1")
	})

	t.Run("Castle.Core", func(t *testing.T) {
		versions, err := ecosystem.GetVersions("Castle.Core")
		if err != nil {
			t.Fatalf("GetVersions() err = %v", err)
		}
		checkNextVersion(t, versions, "3.0.0.3001", "3.0.0.4001")
		checkNextVersion(t, versions, "3.0.0.4001", "3.1.0-RC")
	})

	t.Run("Serilog", func(t *testing.T) {
		versions, err := ecosystem.GetVersions("Serilog")
		if err != nil {
			t.Fatalf("GetVersions() err = %v", err)
		}
		checkNextVersion(t, versions, "2.1.0-dev-00666", "2.1.0-dev-00668")
	})
}

func TestNuGet_GetVersions_NotFound(t *testing.T) {
	t.Parallel()
	p := getTestProvider(t)
	e, ok := p.Get("NuGet")
	if !ok {
		t.Fatalf("Failed to retrieve NuGet ecosystem")
	}
	ecosystem := e.(Enumerable)
	_, err := ecosystem.GetVersions("DoesNotExist.123456")
	if !errors.Is(err, ErrPackageNotFound) {
		t.Errorf("expected ErrPackageNotFound, got %v", err)
	}
}
