package importer

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	// Create a temp dir to isolate HOME and XDG_CONFIG_HOME for all tests in this package.
	// This prevents go-git from reading files like ~/.config/git/config, which might cause non-deterministic test runs.
	dir, err := os.MkdirTemp("", "osv-importer-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create temp dir for TestMain: %v\n", err)
		return
	}

	os.Setenv("HOME", filepath.Join(dir, "home"))
	os.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "xdg"))

	m.Run()

	os.RemoveAll(dir)
}
