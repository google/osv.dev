package nvd

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/go-cmp/cmp"
	"github.com/google/osv/vulnfeeds/conversion"
	"github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"
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

func TestNVDSnapshot(t *testing.T) {
	testPath := "test.json"
	file, err := os.Open(testPath)

	if err != nil {
		t.Fatalf("Failed to open test data from %s: %v", testPath, err)
	}
	defer file.Close()

	var nvd models.CVEAPIJSON20Schema
	err = json.NewDecoder(file).Decode(&nvd)
	if err != nil {
		t.Fatalf("Failed to decode %s: %v", testPath, err)
	}

	cpeData := "cpe_testdata.json"
	vpcache := conversion.NewVPRepoCache()
	err = conversion.LoadCPEDictionary(vpcache, cpeData)
	if err != nil {
		t.Fatalf("Failed to decode %s: %v", cpeData, err)
	}

	outDir := t.TempDir()
	metrics := &models.ConversionMetrics{}
	cache := &git.RepoTagsCache{}

	for _, vuln := range nvd.Vulnerabilities {
		CVEToOSV(vuln.CVE, []string{}, cache, outDir, metrics, false, false)
	}

	var fileContents []string
	err = filepath.Walk(outDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".json" {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			fileContents = append(fileContents, string(content))
		}

		return nil
	})
	if err != nil {
		t.Fatalf("Failed to walk outDir: %v", err)
	}

	// To make snapshot deterministic
	sort.Strings(fileContents)

	keys := make([]any, 0, len(fileContents))
	for _, c := range fileContents {
		keys = append(keys, c)
	}

	snaps.MatchSnapshot(t, keys...)
}

func TestCVEToOSV_ReferencesDeterminism(t *testing.T) {
	cve := models.NVDCVE{
		ID: "CVE-2025-12345",
		References: []models.Reference{
			{URL: "https://example.com/D"},
			{URL: "https://example.com/A"},
			{URL: "https://example.com/C", Tags: []string{"Patch"}},
			{URL: "https://example.com/C"},
			{URL: "https://example.com/B", Tags: []string{"Issue Tracking"}},
			{URL: "https://example.com/E"},
		},
		Metrics: &models.CVEItemMetrics{},
	}
	metrics := &models.ConversionMetrics{}
	outDir := t.TempDir()

	var firstResult []*osvschema.Reference
	for i := range 10 {
		cache := &git.RepoTagsCache{}
		CVEToOSV(cve, nil, cache, outDir, metrics, false, false)

		var b []byte
		err := filepath.Walk(outDir, func(path string, info os.FileInfo, _ error) error {
			if !info.IsDir() && filepath.Ext(path) == ".json" {
				var fileErr error
				b, fileErr = os.ReadFile(path)
				if fileErr != nil {
					return fileErr
				}
			}

			return nil
		})
		if err != nil {
			t.Fatalf("Failed to walk or read OSV file: %v", err)
		}

		if len(b) == 0 {
			t.Fatalf("Failed to find OSV file")
		}

		var vuln osvschema.Vulnerability
		err = protojson.Unmarshal(b, &vuln)
		if err != nil {
			t.Fatalf("Failed to unmarshal OSV: %v", err)
		}

		if i == 0 {
			firstResult = vuln.GetReferences()
			continue
		}

		if diff := cmp.Diff(firstResult, vuln.GetReferences(), protocmp.Transform()); diff != "" {
			t.Fatalf("Iteration %d produced different references result:\n%s", i, diff)
		}
	}
}
