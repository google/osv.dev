package cvelist2osv

import (
	"bytes"
	"encoding/json"
	"github.com/gkampitakis/go-snaps/snaps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func loadTestData(t *testing.T, cveName string) cves.CVE5 {
	t.Helper()
	prefix := strings.Split(cveName, "-")[2]
	prefixpath := prefix[:len(prefix)-3] + "xxx"
	fileName := filepath.Join("..", "test_data", "cvelistV5", "cves", cveName[4:8], prefixpath, cveName+".json")

	return loadTestCVE(t, fileName)
}

func loadTestCVE(t *testing.T, path string) cves.CVE5 {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Failed to load test data from %q: %v", path, err)
	}
	defer file.Close()
	var cve cves.CVE5
	err = json.NewDecoder(file).Decode(&cve)
	if err != nil {
		t.Fatalf("Failed to decode %q: %+v", path, err)
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
							{URL: "http://a.com"},
							{URL: "http://b.com"},
						},
						Affected: []cves.Affected{
							{
								CollectionURL: "http://d.com",
								Repo:          "http://b.com",
							},
						},
					},
					ADP: []cves.CNA{
						{
							References: []cves.Reference{
								{URL: "http://c.com"},
								{URL: "http://a.com"},
							},
						},
					},
				},
			},
			expectedRefs: []cves.Reference{
				{URL: "http://a.com"},
				{URL: "http://b.com"},
				{URL: "http://c.com"},
				{URL: "http://d.com"},
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
								CollectionURL: "",
							},
						},
						References: []cves.Reference{
							{URL: "http://a.com"},
							{URL: ""},
						},
					},
				},
			},
			expectedRefs: []cves.Reference{
				{URL: ""},
				{URL: "http://a.com"},
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
	cvePlaceholder, _ := cves.ParseCVE5Timestamp("2025-05-04T07:20:46.575Z")
	testCases := []struct {
		name         string
		cve          cves.CVE5
		refs         []cves.Reference
		expectedVuln *vulns.Vulnerability
	}{
		{
			name: "disputed record",
			cve: cves.CVE5{
				Metadata: cves.CVE5Metadata{
					CVEID:         "CVE-2025-9999",
					State:         "PUBLISHED",
					DatePublished: "2025-05-04T07:20:46.575Z",
					DateUpdated:   "2025-05-04T07:20:46.575Z",
				},
				Containers: struct {
					CNA cves.CNA   `json:"cna"`
					ADP []cves.CNA `json:"adp,omitempty"`
				}{
					CNA: cves.CNA{
						Tags: []string{"disputed"},
						Descriptions: []cves.LangString{
							{
								Lang:  "en",
								Value: "A disputed vulnerability.",
							},
						},
					},
				},
			},
			refs: []cves.Reference{},
			expectedVuln: &vulns.Vulnerability{
				Vulnerability: osvschema.Vulnerability{
					ID:               "CVE-2025-9999",
					SchemaVersion:    osvschema.SchemaVersion,
					Published:        cvePlaceholder,
					Modified:         cvePlaceholder,
					Details:          "A disputed vulnerability.",
					DatabaseSpecific: map[string]any{"isDisputed": true},
				},
			},
		},
		{
			name: "CVE-2025-1110",
			cve:  loadTestData(t, "CVE-2025-1110"),
			refs: []cves.Reference{
				{URL: "https://gitlab.com/gitlab-org/gitlab/-/issues/517693", Tags: []string{"issue-tracking", "permissions-required"}},
				{URL: "https://hackerone.com/reports/2972576", Tags: []string{"technical-description", "exploit", "permissions-required"}},
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
					DatabaseSpecific: map[string]any{"cwe_ids": []string{"CWE-1220"}},
					References: []osvschema.Reference{
						{Type: "ARTICLE", URL: "https://hackerone.com/reports/2972576"},
						{Type: "EVIDENCE", URL: "https://hackerone.com/reports/2972576"},
						{Type: "REPORT", URL: "https://gitlab.com/gitlab-org/gitlab/-/issues/517693"},
						{Type: "REPORT", URL: "https://hackerone.com/reports/2972576"},
					},
					Severity: []osvschema.Severity{
						{
							Type:  "CVSS_V3",
							Score: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N",
						},
					},
				},
			},
		},
		{
			name: "CVE-2024-21634",
			cve:  loadTestData(t, "CVE-2024-21634"),
			refs: []cves.Reference{
				{Tags: []string{"x_refsource_CONFIRM"}, URL: "https://github.com/amazon-ion/ion-java/security/advisories/GHSA-264p-99wq-f4j6"},
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
					DatabaseSpecific: map[string]any{"cwe_ids": []string{"CWE-770"}},
				},
			},
		},
		{
			name: "CVE-2025-21772",
			cve:  loadTestData(t, "CVE-2025-21772"),
			refs: []cves.Reference{
				{URL: "https://git.kernel.org/stable/c/a3e77da9f843e4ab93917d30c314f0283e28c124"},
				{URL: "https://git.kernel.org/stable/c/213ba5bd81b7e97ac6e6190b8f3bc6ba76123625"},
				{URL: "https://git.kernel.org/stable/c/40a35d14f3c0dc72b689061ec72fc9b193f37d1f"},
				{URL: "https://git.kernel.org/stable/c/27a39d006f85e869be68c1d5d2ce05e5d6445bf5"},
				{URL: "https://git.kernel.org/stable/c/92527100be38ede924768f4277450dfe8a40e16b"},
				{URL: "https://git.kernel.org/stable/c/6578717ebca91678131d2b1f4ba4258e60536e9f"},
				{URL: "https://git.kernel.org/stable/c/7fa9706722882f634090bfc9af642bf9ed719e27"},
				{URL: "https://git.kernel.org/stable/c/80e648042e512d5a767da251d44132553fe04ae0"},
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
					DatabaseSpecific: nil,
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
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metrics := &ConversionMetrics{}
			vuln := FromCVE5(tc.cve, tc.refs, metrics)

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
		})
	}
}

func TestConvertAndExportCVEToOSV(t *testing.T) {
	cve1110Pub, _ := cves.ParseCVE5Timestamp("2025-05-22T14:02:31.385Z")
	cve1110Mod, _ := cves.ParseCVE5Timestamp("2025-05-22T14:17:44.379Z")
	cve21634Pub, _ := cves.ParseCVE5Timestamp("2024-01-03T22:46:03.585Z")
	cve21634Mod, _ := cves.ParseCVE5Timestamp("2025-06-16T19:45:37.088Z")
	cve21772Pub, _ := cves.ParseCVE5Timestamp("2025-02-27T02:18:19.528Z")
	cve21772Mod, _ := cves.ParseCVE5Timestamp("2025-05-04T07:20:46.575Z")
	cvePlaceholder, _ := cves.ParseCVE5Timestamp("2025-05-04T07:20:46.575Z")
	testCases := []struct {
		name         string
		cve          cves.CVE5
		refs         []cves.Reference
		expectedVuln *vulns.Vulnerability
	}{
		{
			name: "disputed record",
			cve: cves.CVE5{
				Metadata: cves.CVE5Metadata{
					CVEID:         "CVE-2025-9999",
					State:         "PUBLISHED",
					DatePublished: "2025-05-04T07:20:46.575Z",
					DateUpdated:   "2025-05-04T07:20:46.575Z",
				},
				Containers: struct {
					CNA cves.CNA   `json:"cna"`
					ADP []cves.CNA `json:"adp,omitempty"`
				}{
					CNA: cves.CNA{
						Tags: []string{"disputed"},
						Descriptions: []cves.LangString{
							{
								Lang:  "en",
								Value: "A disputed vulnerability.",
							},
						},
					},
				},
			},
			refs: []cves.Reference{},
			expectedVuln: &vulns.Vulnerability{
				Vulnerability: osvschema.Vulnerability{
					ID:               "CVE-2025-9999",
					SchemaVersion:    osvschema.SchemaVersion,
					Published:        cvePlaceholder,
					Modified:         cvePlaceholder,
					Details:          "A disputed vulnerability.",
					DatabaseSpecific: map[string]any{"isDisputed": true},
				},
			},
		},
		{
			name: "CVE-2025-1110",
			cve:  loadTestData(t, "CVE-2025-1110"),
			refs: []cves.Reference{
				{URL: "https://gitlab.com/gitlab-org/gitlab/-/issues/517693", Tags: []string{"issue-tracking", "permissions-required"}},
				{URL: "https://hackerone.com/reports/2972576", Tags: []string{"technical-description", "exploit", "permissions-required"}},
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
					DatabaseSpecific: map[string]any{"cwe_ids": []string{"CWE-1220"}},
					References: []osvschema.Reference{
						{Type: "ARTICLE", URL: "https://hackerone.com/reports/2972576"},
						{Type: "EVIDENCE", URL: "https://hackerone.com/reports/2972576"},
						{Type: "REPORT", URL: "https://gitlab.com/gitlab-org/gitlab/-/issues/517693"},
						{Type: "REPORT", URL: "https://hackerone.com/reports/2972576"},
					},
					Severity: []osvschema.Severity{
						{
							Type:  "CVSS_V3",
							Score: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N",
						},
					},
				},
			},
		},
		{
			name: "CVE-2024-21634",
			cve:  loadTestData(t, "CVE-2024-21634"),
			refs: []cves.Reference{
				{Tags: []string{"x_refsource_CONFIRM"}, URL: "https://github.com/amazon-ion/ion-java/security/advisories/GHSA-264p-99wq-f4j6"},
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
					DatabaseSpecific: map[string]any{"cwe_ids": []string{"CWE-770"}},
				},
			},
		},
		{
			name: "CVE-2025-21772",
			cve:  loadTestData(t, "CVE-2025-21772"),
			refs: []cves.Reference{
				{URL: "https://git.kernel.org/stable/c/a3e77da9f843e4ab93917d30c314f0283e28c124"},
				{URL: "https://git.kernel.org/stable/c/213ba5bd81b7e97ac6e6190b8f3bc6ba76123625"},
				{URL: "https://git.kernel.org/stable/c/40a35d14f3c0dc72b689061ec72fc9b193f37d1f"},
				{URL: "https://git.kernel.org/stable/c/27a39d006f85e869be68c1d5d2ce05e5d6445bf5"},
				{URL: "https://git.kernel.org/stable/c/92527100be38ede924768f4277450dfe8a40e16b"},
				{URL: "https://git.kernel.org/stable/c/6578717ebca91678131d2b1f4ba4258e60536e9f"},
				{URL: "https://git.kernel.org/stable/c/7fa9706722882f634090bfc9af642bf9ed719e27"},
				{URL: "https://git.kernel.org/stable/c/80e648042e512d5a767da251d44132553fe04ae0"},
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
					DatabaseSpecific: nil,
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
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vWriter := bytes.NewBuffer(nil)
			mWriter := bytes.NewBuffer(nil)
			err := ConvertAndExportCVEToOSV(tc.cve, vWriter, mWriter)
			if err != nil {
				t.Errorf("Unexpected error from ConvertAndExportCVEToOSV: %v", err)
			}
			snaps.MatchSnapshot(t, vWriter.String())
		})
	}
}
