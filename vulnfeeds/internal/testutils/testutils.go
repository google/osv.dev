// Package testutils provides some shared testing utility functions.
package testutils

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing/transport/client"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
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

// SetupGitVCR sets up go-vcr http & https capture and replay for go-git,
// as well as the Cleanup for the recorder.
//
// Tests using cannot be parallel - this function modifies the global go-git
// protocol clients.
//
// Note: this only affects http/https protocols - git:// and ssh:// connections
// cannot be routed through go-vcr.
func SetupGitVCR(t *testing.T) *recorder.Recorder {
	t.Helper()
	r := SetupVCR(t)
	httpClient := r.GetDefaultClient()
	client.InstallProtocol("http", githttp.NewClient(httpClient))
	client.InstallProtocol("https", githttp.NewClient(httpClient))

	t.Cleanup(func() {
		// Restore the protocols to their defaults in case another test needs them.
		client.InstallProtocol("http", githttp.DefaultClient)
		client.InstallProtocol("https", githttp.DefaultClient)
	})

	return r
}
