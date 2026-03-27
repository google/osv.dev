package ecosystem

import (
	"testing"
)

func TestDebian_GetVersions(t *testing.T) {
	setupHTTPClientForTest(t)
	e, ok := Get("Debian:11")
	if !ok {
		t.Fatalf("Failed to retrieve Debian ecosystem")
	}

	en, ok := e.(Enumerable)
	if !ok {
		t.Fatalf("Debian ecosystem does not implement Enumerable")
	}

	t.Run("curl", func(t *testing.T) {
		versions, err := en.GetVersions("curl")
		if err != nil {
			t.Fatalf("GetVersions() error = %v", err)
		}
		if len(versions) == 0 {
			t.Errorf("GetVersions() returned no versions")
		}
		checkNextVersion(t, versions, "7.74.0-1.3", "7.74.0-1.3+deb11u1")
	})

	e9, _ := Get("Debian:9")
	en9 := e9.(Enumerable)

	t.Run("nginx", func(t *testing.T) {
		versions, err := en9.GetVersions("nginx")
		if err != nil {
			t.Fatalf("GetVersions() error = %v", err)
		}
		checkNextVersion(t, versions, "1.13.5-1", "1.13.6-1")
		checkNextVersion(t, versions, "1.13.6-1", "1.13.6-2")
	})

	t.Run("blender", func(t *testing.T) {
		versions, err := en9.GetVersions("blender")
		if err != nil {
			t.Fatalf("GetVersions() error = %v", err)
		}
		checkNextVersion(t, versions, "3.0.1+dfsg-1", "3.0.1+dfsg-2")
	})
}
