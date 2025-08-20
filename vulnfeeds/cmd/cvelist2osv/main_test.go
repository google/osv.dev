package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func loadTestData(cveName string) cves.CVE5 {
	prefix := strings.Split(cveName, "-")[2]
	prefixpath := prefix[:len(prefix)-3] + "xxx"
	fileName := filepath.Join("..", "..", "test_data", "cvelistV5", "cves", cveName[4:8], prefixpath, fmt.Sprintf("%s.json", cveName))
	return loadTestCVE(fileName)
}

func loadTestCVE(path string) cves.CVE5 {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("Failed to load test data from %q: %v", path, err)
	}
	defer file.Close()
	var cve cves.CVE5
	err = json.NewDecoder(file).Decode(&cve)
	if err != nil {
		log.Fatalf("Failed to decode %q: %+v", path, err)
	}
	return cve
}

func TestIdentifyPossibleURLs(t *testing.T) {
	testCases := []struct {
		name         string
		cve          cves.CVE5
		expectedRefs []cves.Reference
	}{
		{
			name: "simple case with duplicates",
			cve: cves.CVE5{
				Containers: struct {
					CNA cves.CNA   `json:"cna"`
					ADP []cves.CNA `json:"adp,omitempty"`
				}{
					CNA: cves.CNA{
						References: []cves.Reference{
							{Url: "http://a.com"},
							{Url: "http://b.com"},
						},
						Affected: []cves.Affected{
							{
								CollectionUrl: "http://d.com",
								Repo:          "http://b.com",
							},
						},
					},
					ADP: []cves.CNA{
						{
							References: []cves.Reference{
								{Url: "http://c.com"},
								{Url: "http://a.com"},
							},
						},
					},
				},
			},
			expectedRefs: []cves.Reference{
				{Url: "http://a.com"},
				{Url: "http://b.com"},
				{Url: "http://c.com"},
				{Url: "http://d.com"},
			},
		},
		{
			name: "no references and CNA refs is nil",
			cve: cves.CVE5{
				Containers: struct {
					CNA cves.CNA   `json:"cna"`
					ADP []cves.CNA `json:"adp,omitempty"`
				}{
					CNA: cves.CNA{
						References: nil,
					},
				},
			},
			expectedRefs: nil,
		},
		{
			name: "no references and CNA refs is empty slice",
			cve: cves.CVE5{
				Containers: struct {
					CNA cves.CNA   `json:"cna"`
					ADP []cves.CNA `json:"adp,omitempty"`
				}{
					CNA: cves.CNA{
						References: []cves.Reference{},
					},
				},
			},
			expectedRefs: []cves.Reference{},
		},
		{
			name: "empty url string",
			cve: cves.CVE5{
				Containers: struct {
					CNA cves.CNA   `json:"cna"`
					ADP []cves.CNA `json:"adp,omitempty"`
				}{
					CNA: cves.CNA{
						Affected: []cves.Affected{
							{
								CollectionUrl: "",
							},
						},
						References: []cves.Reference{
							{Url: "http://a.com"},
							{Url: ""},
						},
					},
				},
			},
			expectedRefs: []cves.Reference{
				{Url: ""},
				{Url: "http://a.com"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			refs := identifyPossibleURLs(tc.cve)
			if diff := cmp.Diff(tc.expectedRefs, refs); diff != "" {
				t.Errorf("identifyPossibleURLs() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFromCVE5(t *testing.T) {
	cve1110Pub, _ := cves.ParseCVE5Timestamp("2025-05-22T14:02:31.385Z")
	cve1110Mod, _ := cves.ParseCVE5Timestamp("2025-05-22T14:17:44.379Z")
	cve21634Pub, _ := cves.ParseCVE5Timestamp("2024-01-03T22:46:03.585Z")
	cve21634Mod, _ := cves.ParseCVE5Timestamp("2025-06-16T19:45:37.088Z")
	cve21772Pub, _ := cves.ParseCVE5Timestamp("2025-02-27T02:18:19.528Z")
	cve21772Mod, _ := cves.ParseCVE5Timestamp("2025-05-04T07:20:46.575Z")

	testCases := []struct {
		name          string
		cve           cves.CVE5
		refs          []cves.Reference
		expectedVuln  *vulns.Vulnerability
		expectedNotes []string
	}{
		{
			name: "CVE-2025-1110",
			cve:  loadTestData("CVE-2025-1110"),
			refs: []cves.Reference{
				{Url: "https://gitlab.com/gitlab-org/gitlab/-/issues/517693", Tags: []string{"issue-tracking", "permissions-required"}},
				{Url: "https://hackerone.com/reports/2972576", Tags: []string{"technical-description", "exploit", "permissions-required"}},
			},
			expectedVuln: &vulns.Vulnerability{
				Vulnerability: osvschema.Vulnerability{
					ID:               "CVE-2025-1110",
					SchemaVersion:    osvschema.SchemaVersion,
					Published:        cve1110Pub,
					Modified:         cve1110Mod,
					Summary:          "Insufficient Granularity of Access Control in GitLab",
					Details:          "An issue has been discovered in GitLab CE/EE affecting all versions from 18.0 before 18.0.1. In certain circumstances, a user with limited permissions could access Job Data via a crafted GraphQL query.",
					Aliases:          nil,
					Related:          nil,
					DatabaseSpecific: map[string]any{},
					References: []osvschema.Reference{
						{Type: "WEB", URL: "https://gitlab.com/gitlab-org/gitlab/-/issues/517693"},
						{Type: "WEB", URL: "https://hackerone.com/reports/2972576"},
					},
					Severity: []osvschema.Severity{
						{
							Type:  "CVSS_V3",
							Score: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N",
						},
					},
					Affected: []osvschema.Affected{{
						// DatabaseSpecific: map[string]interface{}{
						// 	"CPE": []string{"cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*"},
						// },

						Ranges: []osvschema.Range{{Type: "ECOSYSTEM",
							Events: []osvschema.Event{{Introduced: "18.0"}, {Fixed: "18.0.1"}},
						}}}},
				},
			},
			expectedNotes: nil,
		},
		{
			name: "CVE-2024-21634",
			cve:  loadTestData("CVE-2024-21634"),
			refs: []cves.Reference{
				{Tags: []string{"x_refsource_CONFIRM"}, Url: "https://github.com/amazon-ion/ion-java/security/advisories/GHSA-264p-99wq-f4j6"},
			},
			expectedVuln: &vulns.Vulnerability{
				Vulnerability: osvschema.Vulnerability{
					ID:            "CVE-2024-21634",
					SchemaVersion: osvschema.SchemaVersion,
					Published:     cve21634Pub,
					Modified:      cve21634Mod,
					Summary:       "Ion Java StackOverflow vulnerability",
					Details:       "Amazon Ion is a Java implementation of the Ion data notation. Prior to version 1.10.5, a potential denial-of-service issue exists in\u00a0`ion-java`\u00a0for applications that use\u00a0`ion-java`\u00a0to deserialize Ion text encoded data, or deserialize Ion text or binary encoded data into the\u00a0`IonValue`\u00a0model and then invoke certain\u00a0`IonValue`\u00a0methods on that in-memory representation. An actor could craft Ion data that, when loaded by the affected application and/or processed using the\u00a0`IonValue`\u00a0model, results in a\u00a0`StackOverflowError`\u00a0originating from the\u00a0`ion-java`\u00a0library. The patch is included in `ion-java` 1.10.5. As a workaround, do not load data which originated from an untrusted source or that could have been tampered with.",
					Aliases:       []string{"GHSA-264p-99wq-f4j6"},
					Related:       nil,
					References: []osvschema.Reference{
						{Type: "ADVISORY", URL: "https://github.com/amazon-ion/ion-java/security/advisories/GHSA-264p-99wq-f4j6"},
					},
					Severity: []osvschema.Severity{
						{
							Type:  "CVSS_V3",
							Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
						},
					},
					Affected: []osvschema.Affected{{Ranges: []osvschema.Range{{
						Type:   "ECOSYSTEM",
						Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "1.10.5"}}}}}},
					DatabaseSpecific: make(map[string]interface{}),
				},
			},
			expectedNotes: nil,
		},
		{
			name: "CVE-2025-21772",
			cve:  loadTestData("CVE-2025-21772"),
			refs: []cves.Reference{
				{Url: "https://git.kernel.org/stable/c/a3e77da9f843e4ab93917d30c314f0283e28c124"},
				{Url: "https://git.kernel.org/stable/c/213ba5bd81b7e97ac6e6190b8f3bc6ba76123625"},
				{Url: "https://git.kernel.org/stable/c/40a35d14f3c0dc72b689061ec72fc9b193f37d1f"},
				{Url: "https://git.kernel.org/stable/c/27a39d006f85e869be68c1d5d2ce05e5d6445bf5"},
				{Url: "https://git.kernel.org/stable/c/92527100be38ede924768f4277450dfe8a40e16b"},
				{Url: "https://git.kernel.org/stable/c/6578717ebca91678131d2b1f4ba4258e60536e9f"},
				{Url: "https://git.kernel.org/stable/c/7fa9706722882f634090bfc9af642bf9ed719e27"},
				{Url: "https://git.kernel.org/stable/c/80e648042e512d5a767da251d44132553fe04ae0"},
			},
			expectedVuln: &vulns.Vulnerability{
				Vulnerability: osvschema.Vulnerability{
					ID:               "CVE-2025-21772",
					SchemaVersion:    osvschema.SchemaVersion,
					Published:        cve21772Pub,
					Modified:         cve21772Mod,
					Summary:          "partitions: mac: fix handling of bogus partition table",
					Details:          "In the Linux kernel, the following vulnerability has been resolved:\n\npartitions: mac: fix handling of bogus partition table\n\nFix several issues in partition probing:\n\n - The bailout for a bad partoffset must use put_dev_sector(), since the\n   preceding read_part_sector() succeeded.\n - If the partition table claims a silly sector size like 0xfff bytes\n   (which results in partition table entries straddling sector boundaries),\n   bail out instead of accessing out-of-bounds memory.\n - We must not assume that the partition table contains proper NUL\n   termination - use strnlen() and strncmp() instead of strlen() and\n   strcmp().",
					Aliases:          nil,
					Related:          nil,
					DatabaseSpecific: map[string]any{},
					Affected: []osvschema.Affected{
						{
							Package: osvschema.Package{Ecosystem: "Linux", Name: "Kernel"},
							Ranges: []osvschema.Range{
								{Type: "ECOSYSTEM", Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "5.4.291"}}},
								{Type: "ECOSYSTEM", Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "5.10.235"}}},
								{Type: "ECOSYSTEM", Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "5.15.179"}}},
								{Type: "ECOSYSTEM", Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "6.1.129"}}},
								{Type: "ECOSYSTEM", Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "6.6.79"}}},
								{Type: "ECOSYSTEM", Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "6.12.16"}}},
								{Type: "ECOSYSTEM", Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "6.13.4"}}},
								{Type: "ECOSYSTEM", Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "6.14"}}},
							},
							DatabaseSpecific: map[string]any{"CPEs": []string{"cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"}},
						},
						{
							Ranges: []osvschema.Range{{
								Type: "GIT",
								Events: []osvschema.Event{
									{Introduced: "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"},
									{Fixed: "a3e77da9f843e4ab93917d30c314f0283e28c124"},
								},
								Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
							},
								{
									Type: "GIT",
									Events: []osvschema.Event{
										{Introduced: "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"},
										{Fixed: "213ba5bd81b7e97ac6e6190b8f3bc6ba76123625"},
									},
									Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
								},
								{
									Type: "GIT",
									Events: []osvschema.Event{
										{Introduced: "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"},
										{Fixed: "40a35d14f3c0dc72b689061ec72fc9b193f37d1f"},
									},
									Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
								},
								{
									Type: "GIT",
									Events: []osvschema.Event{
										{Introduced: "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"},
										{Fixed: "27a39d006f85e869be68c1d5d2ce05e5d6445bf5"},
									},
									Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
								},
								{
									Type: "GIT",
									Events: []osvschema.Event{
										{Introduced: "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"},
										{Fixed: "92527100be38ede924768f4277450dfe8a40e16b"},
									},
									Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
								},
								{
									Type: "GIT",
									Events: []osvschema.Event{
										{Introduced: "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"},
										{Fixed: "6578717ebca91678131d2b1f4ba4258e60536e9f"},
									},
									Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
								},
								{
									Type: "GIT",
									Events: []osvschema.Event{
										{Introduced: "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"},
										{Fixed: "7fa9706722882f634090bfc9af642bf9ed719e27"},
									},
									Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
								},
								{
									Type: "GIT",
									Events: []osvschema.Event{
										{Introduced: "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"},
										{Fixed: "80e648042e512d5a767da251d44132553fe04ae0"},
									},
									Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
								}},
						}},
					References: []osvschema.Reference{
						{Type: "WEB", URL: "https://git.kernel.org/stable/c/a3e77da9f843e4ab93917d30c314f0283e28c124"},
						{Type: "WEB", URL: "https://git.kernel.org/stable/c/213ba5bd81b7e97ac6e6190b8f3bc6ba76123625"},
						{Type: "WEB", URL: "https://git.kernel.org/stable/c/40a35d14f3c0dc72b689061ec72fc9b193f37d1f"},
						{Type: "WEB", URL: "https://git.kernel.org/stable/c/27a39d006f85e869be68c1d5d2ce05e5d6445bf5"},
						{Type: "WEB", URL: "https://git.kernel.org/stable/c/92527100be38ede924768f4277450dfe8a40e16b"},
						{Type: "WEB", URL: "https://git.kernel.org/stable/c/6578717ebca91678131d2b1f4ba4258e60536e9f"},
						{Type: "WEB", URL: "https://git.kernel.org/stable/c/7fa9706722882f634090bfc9af642bf9ed719e27"},
						{Type: "WEB", URL: "https://git.kernel.org/stable/c/80e648042e512d5a767da251d44132553fe04ae0"},
					},
				},
			},
			expectedNotes: []string{"Skipping Linux Affected range versions in favour of CPE versions"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vuln, notes := FromCVE5(tc.cve, tc.refs)

			// Handle non-deterministic time.Now()
			if strings.Contains(tc.name, "invalid date") {
				if !vuln.Published.IsZero() {
					vuln.Published = time.Time{}
				}
				if !vuln.Modified.IsZero() && strings.Contains(tc.name, "invalid modified") {
					vuln.Modified = time.Time{}
				}
			}

			if diff := cmp.Diff(tc.expectedVuln, vuln); diff != "" {
				t.Errorf("FromCVE5() vuln mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.expectedNotes, notes); diff != "" {
				t.Errorf("FromCVE5() notes mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFindInverseAffectedRanges(t *testing.T) {
	testCases := []struct {
		name           string
		cve            cves.CVE5
		expectedRanges []osvschema.Range
	}{
		{
			name: "CVE-2025-21772",
			cve:  loadTestData("CVE-2025-21772"),
			expectedRanges: []osvschema.Range{
				{Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "5.4.291"}}},
				{Events: []osvschema.Event{{Introduced: "5.5.0"}, {Fixed: "5.10.235"}}},
				{Events: []osvschema.Event{{Introduced: "5.11.0"}, {Fixed: "5.15.179"}}},
				{Events: []osvschema.Event{{Introduced: "5.16.0"}, {Fixed: "6.1.129"}}},
				{Events: []osvschema.Event{{Introduced: "6.2.0"}, {Fixed: "6.6.79"}}},
				{Events: []osvschema.Event{{Introduced: "6.7.0"}, {Fixed: "6.12.16"}}},
				{Events: []osvschema.Event{{Introduced: "6.13.0"}, {Fixed: "6.13.4"}}},
			},
		},
		{
			name: "CVE-2025-21631",
			cve:  loadTestData("CVE-2025-21631"),
			expectedRanges: []osvschema.Range{
				{Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "5.15.177"}}},
				{Events: []osvschema.Event{{Introduced: "5.16.0"}, {Fixed: "6.1.125"}}},
				{Events: []osvschema.Event{{Introduced: "6.2.0"}, {Fixed: "6.6.72"}}},
				{Events: []osvschema.Event{{Introduced: "6.7.0"}, {Fixed: "6.12.10"}}},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var affectedBlock cves.Affected
			// Find the specific affected block with defaultStatus: "affected".
			for _, affected := range tc.cve.Containers.CNA.Affected {
				if affected.DefaultStatus == "affected" {
					affectedBlock = affected
					break
				}
			}

			if affectedBlock.Product == "" {
				t.Fatalf("Could not find the 'affected' block with defaultStatus 'affected' in the test file")
			}

			// Run the function under test.
			gotRanges, _ := findInverseAffectedRanges(affectedBlock)

			// Sort slices for deterministic comparison.
			sort.Slice(gotRanges, func(i, j int) bool {
				if len(gotRanges[i].Events) == 0 || len(gotRanges[j].Events) == 0 {
					return false
				}
				eventI := gotRanges[i].Events[0]
				eventJ := gotRanges[j].Events[0]
				if eventI.Introduced != "" && eventJ.Introduced != "" {
					return eventI.Introduced < eventJ.Introduced
				}
				if eventI.Fixed != "" && eventJ.Fixed != "" {
					return eventI.Fixed < eventJ.Fixed
				}
				return eventI.Introduced != ""
			})

			sort.Slice(tc.expectedRanges, func(i, j int) bool {
				if len(tc.expectedRanges[i].Events) == 0 || len(tc.expectedRanges[j].Events) == 0 {
					return false
				}
				eventI := tc.expectedRanges[i].Events[0]
				eventJ := tc.expectedRanges[j].Events[0]
				if eventI.Introduced != "" && eventJ.Introduced != "" {
					return eventI.Introduced < eventJ.Introduced
				}
				if eventI.Fixed != "" && eventJ.Fixed != "" {
					return eventI.Fixed < eventJ.Fixed
				}
				return eventI.Introduced != ""
			})

			if diff := cmp.Diff(tc.expectedRanges, gotRanges); diff != "" {
				t.Errorf("findInverseAffectedRanges() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
