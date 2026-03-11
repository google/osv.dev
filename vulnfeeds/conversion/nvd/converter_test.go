package nvd

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5/plumbing/transport/client"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/models"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestCVEToOSV_429(t *testing.T) {
	originalTransport := http.DefaultTransport
	requests := 0
	customTransport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Body:       http.NoBody,
			Request:    req,
		}, nil
	})
	http.DefaultTransport = customTransport
	defer func() { http.DefaultTransport = originalTransport }()

	customClient := &http.Client{Transport: customTransport}
	client.InstallProtocol("https", githttp.NewClient(customClient))
	defer client.InstallProtocol("https", githttp.DefaultClient)

	cve := models.NVDCVE{
		ID: "CVE-2025-12345",
		References: []models.Reference{
			{
				URL: "https://github.com/foo/bar/commit/1234567890abcdef1234567890abcdef12345678",
			},
		},
		Configurations: []models.Config{
			{
				Nodes: []models.Node{
					{
						Operator: "OR",
						CPEMatch: []models.CPEMatch{
							{
								Vulnerable: true,
								Criteria:   "cpe:2.3:a:foo:bar:1.5:*:*:*:*:*:*:*",
							},
						},
					},
				},
			},
		},
		Metrics: &models.CVEItemMetrics{},
	}

	metrics := &models.ConversionMetrics{}
	cache := &git.RepoTagsCache{}
	outDir := t.TempDir()

	outcome := CVEToOSV(cve, []string{"https://github.com/foo/bar"}, cache, outDir, metrics, false, false)

	// It should fail because of the 429 error causing unresolved fixes
	if outcome != models.Error {
		t.Errorf("Expected error from CVEToOSV due to 429, got %v", outcome)
	}

	// Verify that no OSV file was created
	files, _ := os.ReadDir(outDir)
	if len(files) > 0 {
		// It creates a directory for the vendor/product, let's check if any .json files exist
		err := filepath.Walk(outDir, func(path string, info os.FileInfo, _ error) error {
			if !info.IsDir() && filepath.Ext(path) == ".json" {
				t.Errorf("Expected no OSV file to be created, but found %s", path)
			}

			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
