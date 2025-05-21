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

// SetupGitVCR sets up go-vcr http & https capture and replay for go-git,
// as well as the Cleanup for the recorder.
//
// Tests using cannot be parallel - this function modifies the global go-git
// protocol clients.
//
// Note: this only affects http/https protocols - git:// and ssh:// connections
// cannot be routed through go-vcr.
func SetupGitVCR(t *testing.T) {
	t.Helper()
	r, err := recorder.New(filepath.Join("testdata", strings.ReplaceAll(t.Name(), "/", "_")))
	if err != nil {
		t.Fatal(err)
	}
	httpClient := r.GetDefaultClient()
	client.InstallProtocol("http", githttp.NewClient(httpClient))
	client.InstallProtocol("https", githttp.NewClient(httpClient))

	t.Cleanup(func() {
		// Restore the protocols to their defaults in case another test needs them.
		client.InstallProtocol("http", githttp.DefaultClient)
		client.InstallProtocol("https", githttp.DefaultClient)
		if err := r.Stop(); err != nil {
			t.Error(err)
		}
	})
}
