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

	setupRepoCache("https://github.com/go-gitea/gitea", map[string]string{
		"1.25.4": "369830bada2fd8826a5135cb2fc66660a9bef708",
	})
	setupRepoCache("https://github.com/tokio-rs/tokio", map[string]string{
		"1.7.0":  "f64673580dfc649954eb744eb2734f2f118baa47",
		"1.18.4": "9241c3eddf4a6a218681b088d71f7191513e2376",
		"1.19.0": "674d77d4ef42bd99238521546b3b2cd60b26e50d",
		"1.20.3": "ba81945ffc2695b71f2bbcadbfb5e46ec55aaef3",
		"1.21.0": "50795e652ecb0747c8d048aeaa38a41dddb2da4b",
		"1.23.1": "1a997ffbd62334af2553775234e75ede2d7d949f",
	})
	setupRepoCache("https://github.com/protocolbuffers/protobuf", map[string]string{
		"4.25.8": "a4cbdd3ed0042e8f9b9c30e8b0634096d9532809",
		"5.26.0": "d6511091a0cab1ad13f676a02676ad2a0e5eb9ae",
		"5.29.5": "f5de0a0495faa63b4186fc767324f8b9a7bf4fc4",
		"6.30.0": "d295af5c3002c08e1bfd9d7f9e175d0a4d015f1e",
		"6.31.1": "74211c0dfc2777318ab53c2cd2c317a2ef9012de",
	})
	setupRepoCache("https://github.com/curl/curl", map[string]string{
		"7.32.0": "70812c2f32fc5734bcbbe572b9f61c380433ad6a",
		"7.61.1": "432eb5f5c254ee8383b2522ce597c9219877923e",
		"8.9.1":  "83bedbd730d62b83744cc26fa0433d3f6e2e4cd6",
	})
	setupRepoCache("https://github.com/harfbuzz/harfbuzz", map[string]string{
		"4.3.0": "aee123fc83388b8f5acfb301d87bd92eccc5b843",
	})
	setupRepoCache("https://github.com/davea42/libdwarf-code", map[string]string{
		"0.9.2": "5e43a5ab73cb00c8a46660b361366a8c9c3c93c9",
	})
	setupRepoCache("https://github.com/forcedotcom/salesforcemobilesdk-windows", map[string]string{
		"5.0.0": "e4dd3fa3182d0fd382e229e0c25d1bfd8b77a711",
	})
	setupRepoCache("https://github.com/ffmpeg/ffmpeg", map[string]string{
		"2.0":     "2b8b2ba19fe0ca6594cb09439b9ead2c328a79d8",
		"2.0.1":   "acf511de34e0b79fff0183e06ed37f1aa8dc3d94",
		"2.0.2":   "9d0bb7fc3991b030603acfe899e6f001e530c89a",
		"2.0.3":   "b4552cc9b8c37410f754af5d34d24e7b8a9b4b0e",
		"2.0.4":   "7de7bd4f563a1431bdac59dae5d8e930e71405e6",
		"2.0.5":   "205e2264c3d5b1a16a4493b9281b9167d09c3505",
		"2.0.6":   "3d91569c5e39f4062393fdb40b038e31df38473a",
		"2.0.7":   "0caff57c42cac0f80152187473b1ee753aca8257",
		"2.1":     "a37e42b3ee4226a4d2c69cd4eebf9c81e6df8ea5",
		"2.1.1":   "9422cd85a081f6e084731e87eda3e8e4df9f6827",
		"2.1.2":   "29353dd3f8159089ecf2fa0886f94f4cf32e75f2",
		"2.1.3":   "eda6effcabcf9c238e4635eb058d72371336e09b",
		"2.1.4":   "d3139c9733f1994fb86825e0d1fd2a5abf3be7b5",
		"2.1.5":   "e7873dfccad595e9d8fc65217ebffcf3686e1d34",
		"2.1.6":   "27172a5ca360e61a07ff16bf22f2ec91208f4e00",
		"2.1.7":   "41802887eb647bee21238e0a575a7c4bbf954b86",
		"2.1.8":   "68f89b8264d46d5812e710ca0f903d4d323ec899",
		"2.2":     "6baf9c4406bcdf1015c9ec8bd6b8c4aef77624ac",
		"2.2.1":   "e72c0a04664a9aab449b63135fe16ade51a99bb6",
		"2.2.2":   "c2eb668617555cb8b8bcfb9796241ada9471ac65",
		"2.2.3":   "f406bf3fa933be089bd76a95f75ea57b0942f8c5",
		"2.2.4":   "e0a03d1f9cb18139ede8c3d0263a21828494c951",
		"2.2.5":   "0edc79962641dd853cda187ee13b617701346061",
		"2.2.6":   "1b99667005156cadc8d3ae0099ef5d244e598ac5",
		"2.2.7":   "49fa398858df1a1e425740672de5fb4819b4d947",
		"2.2.8":   "5df02760dd2f050b996f931fa7cdf8871bfa5d96",
		"2.2.9":   "b05d3550407418aea53f2672463a8ebc8f75654e",
		"2.2.10":  "969aee07e68c5930782bc46f2ac2391db55b8d1b",
		"2.2.11":  "9f09bfe681259cfed7414f207c88f84c09d5b501",
		"2.2.12":  "86a01362c0e46d155fbfc1ef19f5ba17af3ee69d",
		"2.2.13":  "36cfee3adc70c6a78a07df4bb16349c4b0893ef4",
		"2.2.14":  "bf0d2ee92c33d802907e829f99c26a46578ed679",
		"2.2.15":  "1c14b09caf903f2e776dcd661085db49511bf531",
		"2.2.16":  "051cd7dc5f42542753f809109d00ec3cf19eb337",
		"2.3":     "3ec3f70ddb1b97fd6174ab3ca8617d8a1a6516ab",
		"2.3.1":   "7c2d152f562ab089ecf8262438e2f8e9cb9c546f",
		"2.3.2":   "b88de7b31a4a5c35d10b1392d2d86d93fc942b4c",
		"2.3.3":   "bc259185cb69c6532232be4b2ad57a70ef7ed946",
		"2.3.4":   "d005e2ecce5c8104679b39f2050a9d83e417d275",
		"2.3.5":   "b44506c393b176dc396502ad262ac18bec52a110",
		"2.3.6":   "db27f50e0658e91758e8a17fdcf390e6bc93c1d2",
		"2.4":     "13a72d9b08c914c3d3c99be1053e9d5cda8baa88",
		"2.4.1":   "e1ce4f805f31aecec83fc7c7ecaab623f3b6327f",
		"2.4.2":   "d61454e7c1de48f6a9059ca98f55e6beb52a618c",
		"2.4.3":   "043f32606046b1470218511ded151edfa7a126ee",
		"2.4.4":   "dd2394754d8cee3717b3e198c83cc382674cf126",
		"2.4.5":   "4afe2684d8f50b28ce6743c7ee999f3157c9857f",
		"2.4.6":   "1fd7fb9036fcfb1620068014d8a52112067d2d59",
		"2.4.7":   "3c63503792147a996997023694a3b45f27ab3f78",
		"2.4.8":   "2c8c55195da97ee45fb0daf6d68c22b942e14ade",
		"2.4.9":   "de7b74d2544d2cb5ff85db20a9853116ea72ed47",
		"2.4.10":  "1047c286fa20c79dde8ddd7577a3b87cc1effdb7",
		"2.4.11":  "0045969e411bcf946b2393e7bcb42032cb71a9a1",
		"2.4.12":  "5e4ec87720a64cd969120af60e82cbd55454ab8e",
		"2.5":     "da2186be81b5cb2d24da5671e25affbb8f09920d",
		"2.5.1":   "2c01dd2ea5e39238261945185d2b30e11979cf4b",
		"2.5.2":   "959ab06c68f8c74a0f31bcaf2692cbbdaf5702f6",
		"2.5.3":   "07d508e4f55f6045b83df3346448b149faab5d7d",
		"2.5.4":   "3429714f3d046f4e2235848a60b6f63bd084e01f",
		"2.5.5":   "d0599a3516c5da31c7009af7574abbff360b9ce6",
		"2.5.6":   "faac8e43315dae5818816bcebe52d11777b064b2",
		"2.5.7":   "21d0ae829f72ec327aff31b0cb1af1261b56596c",
		"2.5.8":   "1eb646ec9f87ed488f52561867e107eaee89e20c",
		"2.5.9":   "d52b5f85f2837b0de9bdefe2a650d8d1b0e02ec1",
		"2.6":     "f478bdabf2afcd5f709789347f8a3becc4ff17bc",
		"2.6.1":   "b2c9cd36d34c4157af10342ad3476dd9260bbefe",
		"2.6.2":   "04fd0250e1fd3fddcd7bc96c8ac95455f910637e",
		"2.6.3":   "af5917698bd44f136fd0ff00a9e5f8b5f92f2d58",
		"2.6.4":   "b17cec526214dff9d6ac1d97b70167d15a4e14d7",
		"2.6.5":   "48d388b03336d01e0db9b729f9f82cbadf3af7bd",
		"2.6.6":   "d6ce1cb14077891f3f6ac86cfd243835c92eb374",
		"2.7":     "0bcb6ac150690d1b799982efabc11cab3420f3e3",
		"2.7.1":   "620197d1ffea20e9168372c354438f1c1e926ecd",
		"2.7.2":   "15466db69e60f486c44e4c3e680d27c951f125d7",
		"2.7.3":   "93f3752b970cc7c9e1a360037fff1ddb9dcbb86e",
		"2.7.4":   "26241af6f8b291eed42c597ffa2b32802331f813",
		"2.8":     "58142a27ea96bf9246586a91a82db85e37646933",
		"2.8-dev": "58142a27ea96bf9246586a91a82db85e37646933",
		"2.8.1":   "40934e0e9b632fa6c6ec22ac03b530625a027c79",
		"2.8.2":   "c9b3451da3cf632424c07c35759c9ffbd537fa9e",
		"2.8.3":   "644296e736ee219cd02f7b7d7b7b4c7c5a464217",
		"2.8.4":   "644179e0d4155ae8f5ddd5c3f6bd003e2e13cf94",
	})
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
