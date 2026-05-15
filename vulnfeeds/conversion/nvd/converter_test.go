package nvd

import (
	"bytes"
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
	c "github.com/google/osv/vulnfeeds/conversion"
	"github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
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
	cache := &git.InMemoryRepoTagsCache{}
	outDir := t.TempDir()

	_, _, outcome := CVEToOSV(cve, []string{"https://github.com/foo/bar"}, nil, cache, metrics)

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

	var firstResult []*osvschema.Reference
	for i := range 10 {
		cache := &git.InMemoryRepoTagsCache{}
		vuln, _, _ := CVEToOSV(cve, nil, nil, cache, metrics)
		if vuln == nil {
			t.Fatalf("Iteration %d produced nil vulnerability", i)
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

func TestCVEToOSV_TestJsonSnapshots(t *testing.T) {
	originalTransport := http.DefaultTransport
	customTransport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       http.NoBody,
			Request:    req,
		}, nil
	})
	http.DefaultTransport = customTransport
	defer func() { http.DefaultTransport = originalTransport }()

	data, err := os.ReadFile(filepath.Join("testdata", "test.json"))
	if err != nil {
		t.Fatalf("Failed to read test.json: %v", err)
	}

	var parsed models.CVEAPIJSON20Schema
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal test.json: %v", err)
	}

	vpCache := c.NewVPRepoCache()
	if err := c.LoadCPEDictionary(vpCache, filepath.Join("testdata", "cpe_testdata.json")); err != nil {
		t.Fatalf("Failed to load cpe_testdata.json: %v", err)
	}
	vpCache.Set(c.VendorProduct{Vendor: "gitea", Product: "gitea"}, []string{"https://github.com/go-gitea/gitea"})

	gitCache := &git.InMemoryRepoTagsCache{}

	setupRepoCache := func(repo string, tagCommits map[string]string) {
		gitCache.SetCanonicalLink(repo, repo)
		tagMap := make(map[string]git.Tag)
		normMap := make(map[string]git.NormalizedTag)
		var keys []string
		for k := range tagCommits {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, ver := range keys {
			commit := tagCommits[ver]
			tagMap[ver] = git.Tag{Tag: ver, Commit: commit}
			norm, _ := git.NormalizeVersion(ver)
			if norm == "" {
				norm = ver
			}
			normMap[norm] = git.NormalizedTag{OriginalTag: ver, Commit: commit, MatchesVersionText: false}
		}
		gitCache.Set(repo, git.RepoTagsMap{Tag: tagMap, NormalizedTag: normMap})
	}

	tagsData, err := os.ReadFile(filepath.Join("testdata", "tags_testdata.json"))
	if err != nil {
		t.Fatalf("Failed to read tags_testdata.json: %v", err)
	}
	var repoTagsMapData map[string]map[string]string
	if err := json.Unmarshal(tagsData, &repoTagsMapData); err != nil {
		t.Fatalf("Failed to unmarshal tags_testdata.json: %v", err)
	}
	for repo, tagCommits := range repoTagsMapData {
		setupRepoCache(repo, tagCommits)
	}
	gitCache.SetCanonicalLink("https://github.com/behdad/harfbuzz", "https://github.com/harfbuzz/harfbuzz")
	gitCache.SetCanonicalLink("https://github.com/forcedotcom/SalesforceMobileSDK-Windows", "https://github.com/forcedotcom/salesforcemobilesdk-windows")

	cveMap := make(map[string]models.NVDCVE)
	for _, item := range parsed.Vulnerabilities {
		cveMap[string(item.CVE.ID)] = item.CVE
	}

	testCases := []struct {
		cveID           string
		description     string
		expectedOutcome models.ConversionOutcome
	}{
		{
			cveID:           "CVE-2026-20912",
			description:     "Tests repository derivation from pull request references and VPRepoCache resolution for Gitea",
			expectedOutcome: models.Successful,
		},
		{
			cveID:           "CVE-2023-22466",
			description:     "Tests multiple version ranges across multiple configuration nodes for Tokio",
			expectedOutcome: models.Successful,
		},
		{
			cveID:           "CVE-2026-23522",
			description:     "Tests record where commit comes from references but canonical link has changed from referenced repo.",
			expectedOutcome: models.Successful,
		},
		{
			cveID:           "CVE-2025-4565",
			description:     "Multiple ranges, with one introduced = 0, and a commit in the refs. (protobuf-python)",
			expectedOutcome: models.Successful,
		},
		{
			cveID:           "CVE-2018-14618",
			description:     "Complex multi-ecosystem CPE configurations and vendor/product cache matching (libcurl)",
			expectedOutcome: models.Successful,
		},
		{
			cveID:           "CVE-2023-1055",
			description:     "No repo exists for project, so should fail",
			expectedOutcome: models.NoRepos,
		},
		{
			cveID:           "CVE-2022-33068",
			description:     "Harfbuzz CPE has last_affected version from CPE, fixed from refs. Canonical link has changed.",
			expectedOutcome: models.Successful,
		},
		{
			cveID:           "CVE-2016-1897",
			description:     "ffmpeg record that enumerates versions",
			expectedOutcome: models.Successful,
		},
		{
			cveID:           "CVE-2024-2002",
			description:     "Tests deduplication and merging of overlapping git commit ranges across multiple references",
			expectedOutcome: models.Successful,
		},
		{
			cveID:           "CVE-2024-31497",
			description:     "Tests handling of linkrot/unresolvable repositories and alternative repository links",
			expectedOutcome: models.NoCommitRanges, // This could be successful, but is currently not.
		},
	}

	for _, tc := range testCases {
		t.Run(tc.cveID, func(t *testing.T) {
			cve, ok := cveMap[tc.cveID]
			if !ok {
				t.Fatalf("CVE %s not found in test.json", tc.cveID)
			}
			// tc.description explains what this record is testing.

			metrics := &models.ConversionMetrics{
				CVEID: cve.ID,
				CNA:   "nvd",
			}
			repos := FindRepos(cve, vpCache, gitCache, metrics, http.DefaultClient)
			metrics.Repos = repos

			vuln, _, outcome := CVEToOSV(cve, repos, vpCache, gitCache, metrics)
			if outcome != tc.expectedOutcome {
				t.Fatalf("Expected outcome %v, got %v during CVEToOSV for %s", tc.expectedOutcome, outcome, cve.ID)
			}

			if vuln != nil {
				buf := bytes.NewBuffer(nil)
				if err := vuln.ToJSON(buf); err != nil {
					t.Fatalf("Failed to marshal vuln to JSON: %v", err)
				}
				snaps.MatchSnapshot(t, buf.String())
			}
		})
	}
}

func TestIsLinuxKernelVulnerability(t *testing.T) {
	tests := []struct {
		name string
		cve  models.NVDCVE
		want bool
	}{
		{
			name: "regular CVE",
			cve: models.NVDCVE{
				ID: "CVE-2025-11111",
				Configurations: []models.Config{
					{
						Nodes: []models.Node{
							{
								Operator: "OR",
								CPEMatch: []models.CPEMatch{
									{
										Criteria:   "cpe:2.3:a:nginx:nginx:1.19.0:*:*:*:*:*:*:*",
										Vulnerable: true,
									},
								},
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "CVE with Linux kernel CPE",
			cve: models.NVDCVE{
				ID: "CVE-2025-22222",
				Configurations: []models.Config{
					{
						Nodes: []models.Node{
							{
								Operator: "OR",
								CPEMatch: []models.CPEMatch{
									{
										Criteria:   "cpe:2.3:o:linux:linux_kernel:5.10:*:*:*:*:*:*:*",
										Vulnerable: true,
									},
								},
							},
						},
					},
				},
			},
			want: true,
		},
		{
			name: "CVE with Linux kernel reference git.kernel.org stable",
			cve: models.NVDCVE{
				ID: "CVE-2025-33333",
				References: []models.Reference{
					{
						URL: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=abcdef",
					},
				},
			},
			want: true,
		},
		{
			name: "CVE with Linux kernel reference github torvalds",
			cve: models.NVDCVE{
				ID: "CVE-2025-44444",
				References: []models.Reference{
					{
						URL: "https://github.com/torvalds/linux/commit/abcdef",
					},
				},
			},
			want: true,
		},
		{
			name: "CVE with non-kernel git.kernel.org reference",
			cve: models.NVDCVE{
				ID: "CVE-2025-55555",
				References: []models.Reference{
					{
						URL: "https://git.kernel.org/pub/scm/libs/libcap/libcap.git/commit/?id=abcdef",
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsLinuxKernelVulnerability(tt.cve); got != tt.want {
				t.Errorf("IsLinuxKernelVulnerability() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsLinuxKernelURL(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git", true},
		{"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git", true},
		{"https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git", true},
		{"https://github.com/torvalds/linux", true},
		{"https://github.com/stable/linux", true},
		{"https://git.kernel.org/pub/scm/libs/libcap/libcap.git", false},
		{"https://github.com/foo/bar", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			if got := IsLinuxKernelURL(tt.url); got != tt.want {
				t.Errorf("IsLinuxKernelURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}
