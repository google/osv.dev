package testutils

import (
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/dnaeon/go-vcr.v4/pkg/recorder"
)

// SetupVCR sets up and returns a go-vcr recorder for the current test.
// It handles adding a Cleanup hook for the recorder.
func SetupVCR(t *testing.T) *recorder.Recorder {
	t.Helper()
	cassetteName := t.Name()
	// These characters seem to be illegal in filenames for go modproxy
	// Strip replace them all with _ so this can actually be downloaded.
	// https://cs.opensource.google/go/x/mod/+/master:module/module.go;l=278
	const illegalChars = "\"'*/:;<>?\\`|"
	for _, c := range illegalChars {
		cassetteName = strings.ReplaceAll(cassetteName, string(c), "_")
	}
	r, err := recorder.New(filepath.Join("testdata", cassetteName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Stop(); err != nil {
			t.Error(err)
		}
	})

	return r
}
