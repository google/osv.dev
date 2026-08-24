package cve5

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/vulnfeeds/git"
	"github.com/google/osv.dev/vulnfeeds/internal/testutils"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func loadTestData(t *testing.T, cveName string) models.CVE5 {
	t.Helper()
	prefix := strings.Split(cveName, "-")[2]
	prefixpath := prefix[:len(prefix)-3] + "xxx"
	fileName := filepath.Join("..", "..", "test_data", "cvelistV5", "cves", cveName[4:8], prefixpath, cveName+".json")

	return loadTestCVE(t, fileName)
}

func loadTestCVE(t *testing.T, path string) models.CVE5 {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Failed to load test data from %q: %v", path, err)
	}
	defer file.Close()
	var cve models.CVE5
	err = json.NewDecoder(file).Decode(&cve)
	if err != nil {
		t.Fatalf("Failed to decode %q: %+v", path, err)
	}

	return cve
}

func TestIdentifyPossibleURLs(t *testing.T) {
	testCases := []struct {
		name         string
		cve          models.CVE5
		expectedRefs []models.Reference
	}{
		{
			name: "simple case with duplicates",
			cve: models.CVE5{
				Containers: struct {
					CNA models.CNA   `json:"cna"`
					ADP []models.CNA `json:"adp,omitempty"`
				}{
					CNA: models.CNA{
						References: []models.Reference{
							{URL: "http://a.com"},
							{URL: "http://b.com"},
						},
						Affected: []models.Affected{
							{
								CollectionURL: "http://d.com",
								Repo:          "http://b.com",
							},
						},
					},
					ADP: []models.CNA{
						{
							References: []models.Reference{
								{URL: "http://c.com"},
								{URL: "http://a.com"},
							},
						},
					},
				},
			},
			expectedRefs: []models.Reference{
				{URL: "http://a.com"},
				{URL: "http://b.com"},
				{URL: "http://c.com"},
				{URL: "http://a.com"},
				{URL: "http://d.com"},
				{URL: "http://b.com"},
			},
		},
		{
			name: "no references and CNA refs is nil",
			cve: models.CVE5{
				Containers: struct {
					CNA models.CNA   `json:"cna"`
					ADP []models.CNA `json:"adp,omitempty"`
				}{
					CNA: models.CNA{
						References: nil,
					},
				},
			},
			expectedRefs: []models.Reference{},
		},
		{
			name: "no references and CNA refs is empty slice",
			cve: models.CVE5{
				Containers: struct {
					CNA models.CNA   `json:"cna"`
					ADP []models.CNA `json:"adp,omitempty"`
				}{
					CNA: models.CNA{
						References: []models.Reference{},
					},
				},
			},
			expectedRefs: []models.Reference{},
		},
		{
			name: "empty url string",
			cve: models.CVE5{
				Containers: struct {
					CNA models.CNA   `json:"cna"`
					ADP []models.CNA `json:"adp,omitempty"`
				}{
					CNA: models.CNA{
						Affected: []models.Affected{
							{
								CollectionURL: "",
							},
						},
						References: []models.Reference{
							{URL: "http://a.com"},
							{URL: ""},
						},
					},
				},
			},
			expectedRefs: []models.Reference{
				{URL: "http://a.com"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			refs := identifyPossibleURLs(tc.cve)
			if diff := cmp.Diff(tc.expectedRefs, refs); diff != "" {
				t.Errorf("identifyPossibleURLs() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGetCWEs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		cna      models.CNA
		wantCWEs []string
		wantNote bool
	}{
		{
			name: "empty problem types",
			cna: models.CNA{
				ProblemTypes: nil,
			},
			wantCWEs: nil,
			wantNote: false,
		},
		{
			name: "empty CWEID",
			cna: models.CNA{
				ProblemTypes: models.ProblemTypes{
					{
						Descriptions: []struct {
							CWEID       string `json:"cweId,omitempty"`
							Type        string `json:"type,omitempty"`
							Lang        string `json:"lang,omitempty"`
							Description string `json:"description,omitempty"`
						}{
							{CWEID: ""},
						},
					},
				},
			},
			wantCWEs: nil,
			wantNote: false,
		},
		{
			name: "duplicates and unsorted CWEs",
			cna: models.CNA{
				ProblemTypes: models.ProblemTypes{
					{
						Descriptions: []struct {
							CWEID       string `json:"cweId,omitempty"`
							Type        string `json:"type,omitempty"`
							Lang        string `json:"lang,omitempty"`
							Description string `json:"description,omitempty"`
						}{
							{CWEID: "CWE-79"},
							{CWEID: "CWE-20"},
						},
					},
					{
						Descriptions: []struct {
							CWEID       string `json:"cweId,omitempty"`
							Type        string `json:"type,omitempty"`
							Lang        string `json:"lang,omitempty"`
							Description string `json:"description,omitempty"`
						}{
							{CWEID: "CWE-79"},
							{CWEID: "CWE-125"},
						},
					},
				},
			},
			wantCWEs: []string{"CWE-125", "CWE-20", "CWE-79"},
			wantNote: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			metrics := &models.ConversionMetrics{}
			got := getCWEs(tt.cna, metrics)
			if diff := cmp.Diff(tt.wantCWEs, got); diff != "" {
				t.Errorf("getCWEs() mismatch (-want +got):\n%s", diff)
			}
			hasNote := len(metrics.Notes) > 0
			if hasNote != tt.wantNote {
				t.Errorf("getCWEs() note presence = %v, want %v", hasNote, tt.wantNote)
			}
		})
	}
}

func TestExtractConversionMetrics(t *testing.T) {
	t.Parallel()
	cve := models.CVE5{
		Metadata: models.CVE5Metadata{
			CVEID:             "CVE-2025-1234",
			AssignerShortName: "mitre",
		},
	}
	refs := []*osvschema.Reference{
		{Type: osvschema.Reference_ADVISORY, Url: "https://example.com/advisory1"},
		{Type: osvschema.Reference_ADVISORY, Url: "https://example.com/advisory2"},
		{Type: osvschema.Reference_FIX, Url: "https://example.com/fix1"},
		{Type: osvschema.Reference_REPORT, Url: "https://example.com/report1"},
	}

	metrics := &models.ConversionMetrics{}
	extractConversionMetrics(cve, refs, metrics)

	if metrics.CNA != "mitre" {
		t.Errorf("metrics.CNA = %q, want %q", metrics.CNA, "mitre")
	}

	expectedCounts := map[osvschema.Reference_Type]int{
		osvschema.Reference_ADVISORY: 2,
		osvschema.Reference_FIX:      1,
		osvschema.Reference_REPORT:   1,
	}
	if diff := cmp.Diff(expectedCounts, metrics.RefTypesCount); diff != "" {
		t.Errorf("metrics.RefTypesCount mismatch (-want +got):\n%s", diff)
	}

	if len(metrics.Notes) != 3 {
		t.Errorf("Expected 3 notes for 3 ref types, got %d: %v", len(metrics.Notes), metrics.Notes)
	}
}

func TestBuildDBSpecific(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		cve        models.CVE5
		sourceLink string
		want       map[string]any
	}{
		{
			name: "all fields present",
			cve: models.CVE5{
				Metadata: models.CVE5Metadata{
					AssignerShortName: "redhat",
				},
				Containers: struct {
					CNA models.CNA   `json:"cna"`
					ADP []models.CNA `json:"adp,omitempty"`
				}{
					CNA: models.CNA{
						Tags: []string{"disputed"},
						ProblemTypes: models.ProblemTypes{
							{
								Descriptions: []struct {
									CWEID       string `json:"cweId,omitempty"`
									Type        string `json:"type,omitempty"`
									Lang        string `json:"lang,omitempty"`
									Description string `json:"description,omitempty"`
								}{
									{CWEID: "CWE-79"},
								},
							},
						},
					},
				},
			},
			sourceLink: "https://example.com/source.json",
			want: map[string]any{
				"osv_generated_from": "https://example.com/source.json",
				"cna_assigner":       "redhat",
				"isDisputed":         true,
				"cwe_ids":            []string{"CWE-79"},
			},
		},
		{
			name: "minimal fields defaults to unknown source",
			cve: models.CVE5{
				Metadata: models.CVE5Metadata{
					AssignerShortName: "",
				},
			},
			sourceLink: "",
			want: map[string]any{
				"osv_generated_from": "unknown",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			metrics := &models.ConversionMetrics{}
			got := buildDBSpecific(tt.cve, metrics, tt.sourceLink)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("buildDBSpecific() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFromCVE5(t *testing.T) {
	t.Parallel()
	cve1110Pub, _ := models.ParseCVE5Timestamp("2025-05-22T14:02:31.385Z")
	cve1110Mod, _ := models.ParseCVE5Timestamp("2025-05-22T14:17:44.379Z")
	cve21634Pub, _ := models.ParseCVE5Timestamp("2024-01-03T22:46:03.585Z")
	cve21634Mod, _ := models.ParseCVE5Timestamp("2025-06-16T19:45:37.088Z")
	cve21772Pub, _ := models.ParseCVE5Timestamp("2025-02-27T02:18:19.528Z")
	cve21772Mod, _ := models.ParseCVE5Timestamp("2025-05-04T07:20:46.575Z")
	cvePlaceholder, _ := models.ParseCVE5Timestamp("2025-05-04T07:20:46.575Z")
	testCases := []struct {
		name string
		cve  models.CVE5

		refs         []models.Reference
		expectedVuln *vulns.Vulnerability
	}{
		{
			name: "disputed record",
			cve: models.CVE5{
				Metadata: models.CVE5Metadata{
					CVEID:         "CVE-2025-9999",
					State:         "PUBLISHED",
					DatePublished: "2025-05-04T07:20:46.575Z",
					DateUpdated:   "2025-05-04T07:20:46.575Z",
				},
				Containers: struct {
					CNA models.CNA   `json:"cna"`
					ADP []models.CNA `json:"adp,omitempty"`
				}{
					CNA: models.CNA{
						Tags: []string{"disputed"},
						Descriptions: []models.LangString{
							{
								Lang:  "en",
								Value: "A disputed vulnerability.",
							},
						},
					},
				},
			},
			refs: []models.Reference{},
			expectedVuln: &vulns.Vulnerability{
				Vulnerability: &osvschema.Vulnerability{
					Id:            "CVE-2025-9999",
					SchemaVersion: "1.7.5",
					Published:     timestamppb.New(cvePlaceholder),
					Modified:      timestamppb.New(cvePlaceholder),
					Details:       "A disputed vulnerability.",
					DatabaseSpecific: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"isDisputed":         structpb.NewBoolValue(true),
							"osv_generated_from": structpb.NewStringValue("unknown"),
						},
					},
				},
			},
		},
		{
			name: "rejected record",
			cve: models.CVE5{
				Metadata: models.CVE5Metadata{
					CVEID:         "CVE-2025-8888",
					State:         "REJECTED",
					DatePublished: "2025-05-04T07:20:46.575Z",
					DateUpdated:   "2025-05-04T07:20:46.575Z",
				},
			},
			refs: []models.Reference{},
			expectedVuln: &vulns.Vulnerability{
				Vulnerability: &osvschema.Vulnerability{
					Id:            "CVE-2025-8888",
					SchemaVersion: "1.7.5",
					Published:     timestamppb.New(cvePlaceholder),
					Modified:      timestamppb.New(cvePlaceholder),
					Withdrawn:     timestamppb.New(cvePlaceholder),
					DatabaseSpecific: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"osv_generated_from": structpb.NewStringValue("unknown"),
						},
					},
				},
			},
		},
		{
			name: "CVE-2025-1110",
			cve:  loadTestData(t, "CVE-2025-1110"),
			refs: []models.Reference{
				{URL: "https://gitlab.com/gitlab-org/gitlab/-/issues/517693", Tags: []string{"issue-tracking", "permissions-required"}},
				{URL: "https://hackerone.com/reports/2972576", Tags: []string{"technical-description", "exploit", "permissions-required"}},
			},
			expectedVuln: &vulns.Vulnerability{
				Vulnerability: &osvschema.Vulnerability{
					Id:            "CVE-2025-1110",
					SchemaVersion: "1.7.5",
					Published:     timestamppb.New(cve1110Pub),
					Modified:      timestamppb.New(cve1110Mod),
					Summary:       "Insufficient Granularity of Access Control in GitLab",
					Details:       "An issue has been discovered in GitLab CE/EE affecting all versions from 18.0 before 18.0.1. In certain circumstances, a user with limited permissions could access Job Data via a crafted GraphQL query.",
					Aliases:       nil,
					Related:       nil,
					DatabaseSpecific: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"cna_assigner":       structpb.NewStringValue("GitLab"),
							"osv_generated_from": structpb.NewStringValue("unknown"),
							"cwe_ids": structpb.NewListValue(&structpb.ListValue{
								Values: []*structpb.Value{
									structpb.NewStringValue("CWE-1220"),
								},
							}),
						},
					},
					References: []*osvschema.Reference{
						{Type: osvschema.Reference_REPORT, Url: "https://hackerone.com/reports/2972576"},
						{Type: osvschema.Reference_REPORT, Url: "https://gitlab.com/gitlab-org/gitlab/-/issues/517693"},
					},
					Severity: []*osvschema.Severity{
						{
							Type:  osvschema.Severity_CVSS_V3,
							Score: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N",
						},
					},
				},
			},
		},
		{
			name: "CVE-2024-21634",
			cve:  loadTestData(t, "CVE-2024-21634"),
			refs: []models.Reference{
				{Tags: []string{"x_refsource_CONFIRM"}, URL: "https://github.com/amazon-ion/ion-java/security/advisories/GHSA-264p-99wq-f4j6"},
			},
			expectedVuln: &vulns.Vulnerability{
				Vulnerability: &osvschema.Vulnerability{
					Id:            "CVE-2024-21634",
					SchemaVersion: "1.7.5",
					Published:     timestamppb.New(cve21634Pub),
					Modified:      timestamppb.New(cve21634Mod),
					Summary:       "Ion Java StackOverflow vulnerability",
					Details:       "Amazon Ion is a Java implementation of the Ion data notation. Prior to version 1.10.5, a potential denial-of-service issue exists in\u00a0`ion-java`\u00a0for applications that use\u00a0`ion-java`\u00a0to deserialize Ion text encoded data, or deserialize Ion text or binary encoded data into the\u00a0`IonValue`\u00a0model and then invoke certain\u00a0`IonValue`\u00a0methods on that in-memory representation. An actor could craft Ion data that, when loaded by the affected application and/or processed using the\u00a0`IonValue`\u00a0model, results in a\u00a0`StackOverflowError`\u00a0originating from the\u00a0`ion-java`\u00a0library. The patch is included in `ion-java` 1.10.5. As a workaround, do not load data which originated from an untrusted source or that could have been tampered with.",
					Aliases:       []string{"GHSA-264p-99wq-f4j6"},
					Related:       nil,
					References: []*osvschema.Reference{
						{Type: osvschema.Reference_ADVISORY, Url: "https://github.com/amazon-ion/ion-java/security/advisories/GHSA-264p-99wq-f4j6"},
					},
					Severity: []*osvschema.Severity{
						{
							Type:  osvschema.Severity_CVSS_V3,
							Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
						},
					},
					DatabaseSpecific: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"cna_assigner": structpb.NewStringValue("GitHub_M"),
							"cwe_ids": structpb.NewListValue(
								&structpb.ListValue{
									Values: []*structpb.Value{
										structpb.NewStringValue("CWE-770"),
									},
								},
							),
							"osv_generated_from": structpb.NewStringValue("unknown"),
						},
					},
				},
			},
		},
		{
			name: "CVE-2025-21772",
			cve:  loadTestData(t, "CVE-2025-21772"),
			refs: []models.Reference{
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
				Vulnerability: &osvschema.Vulnerability{
					Id:            "CVE-2025-21772",
					SchemaVersion: "1.7.5",
					Published:     timestamppb.New(cve21772Pub),
					Modified:      timestamppb.New(cve21772Mod),
					Summary:       "partitions: mac: fix handling of bogus partition table",
					Details:       "In the Linux kernel, the following vulnerability has been resolved:\n\npartitions: mac: fix handling of bogus partition table\n\nFix several issues in partition probing:\n\n - The bailout for a bad partoffset must use put_dev_sector(), since the\n   preceding read_part_sector() succeeded.\n - If the partition table claims a silly sector size like 0xfff bytes\n   (which results in partition table entries straddling sector boundaries),\n   bail out instead of accessing out-of-bounds memory.\n - We must not assume that the partition table contains proper NUL\n   termination - use strnlen() and strncmp() instead of strlen() and\n   strcmp().",
					Aliases:       nil,
					Related:       nil,
					DatabaseSpecific: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"cna_assigner":       structpb.NewStringValue("Linux"),
							"osv_generated_from": structpb.NewStringValue("unknown"),
						},
					},
					References: []*osvschema.Reference{
						{Type: osvschema.Reference_WEB, Url: "https://git.kernel.org/stable/c/a3e77da9f843e4ab93917d30c314f0283e28c124"},
						{Type: osvschema.Reference_WEB, Url: "https://git.kernel.org/stable/c/213ba5bd81b7e97ac6e6190b8f3bc6ba76123625"},
						{Type: osvschema.Reference_WEB, Url: "https://git.kernel.org/stable/c/40a35d14f3c0dc72b689061ec72fc9b193f37d1f"},
						{Type: osvschema.Reference_WEB, Url: "https://git.kernel.org/stable/c/27a39d006f85e869be68c1d5d2ce05e5d6445bf5"},
						{Type: osvschema.Reference_WEB, Url: "https://git.kernel.org/stable/c/92527100be38ede924768f4277450dfe8a40e16b"},
						{Type: osvschema.Reference_WEB, Url: "https://git.kernel.org/stable/c/6578717ebca91678131d2b1f4ba4258e60536e9f"},
						{Type: osvschema.Reference_WEB, Url: "https://git.kernel.org/stable/c/7fa9706722882f634090bfc9af642bf9ed719e27"},
						{Type: osvschema.Reference_WEB, Url: "https://git.kernel.org/stable/c/80e648042e512d5a767da251d44132553fe04ae0"},
					},
				},
			},
		},
		{
			name: "invalid date fallback",
			cve: models.CVE5{
				Metadata: models.CVE5Metadata{
					CVEID:         "CVE-2025-0001",
					State:         "PUBLISHED",
					DatePublished: "invalid-date",
					DateUpdated:   "not-a-timestamp",
				},
				Containers: struct {
					CNA models.CNA   `json:"cna"`
					ADP []models.CNA `json:"adp,omitempty"`
				}{
					CNA: models.CNA{
						Descriptions: []models.LangString{
							{
								Lang:  "en",
								Value: "Invalid dates fallback test.",
							},
						},
					},
				},
			},
			refs: []models.Reference{},
			expectedVuln: &vulns.Vulnerability{
				Vulnerability: &osvschema.Vulnerability{
					Id:            "CVE-2025-0001",
					SchemaVersion: "1.7.5",
					Details:       "Invalid dates fallback test.",
					DatabaseSpecific: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"osv_generated_from": structpb.NewStringValue("unknown"),
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			metrics := &models.ConversionMetrics{}
			vuln := FromCVE5(tc.cve, tc.refs, metrics, "")
			vuln.SchemaVersion = tc.expectedVuln.SchemaVersion

			// Handle non-deterministic time.Now() and verify date parse error notes
			if strings.Contains(tc.name, "invalid date") {
				if vuln.Published == nil || vuln.Modified == nil {
					t.Errorf("Expected non-nil Published and Modified dates for invalid date fallback")
				}
				vuln.Published = nil
				vuln.Modified = nil
				if len(metrics.Notes) < 2 {
					t.Errorf("Expected at least 2 notes for date parse errors, got %d", len(metrics.Notes))
				}
			}
			sort.Slice(vuln.References, func(i, j int) bool {
				if vuln.References[i].GetUrl() != vuln.References[j].GetUrl() {
					return vuln.References[i].GetUrl() < vuln.References[j].GetUrl()
				}

				return vuln.References[i].GetType() < vuln.References[j].GetType()
			})

			sort.Slice(tc.expectedVuln.References, func(i, j int) bool {
				if tc.expectedVuln.References[i].GetUrl() != tc.expectedVuln.References[j].GetUrl() {
					return tc.expectedVuln.References[i].GetUrl() < tc.expectedVuln.References[j].GetUrl()
				}

				return tc.expectedVuln.References[i].GetType() < tc.expectedVuln.References[j].GetType()
			})

			if diff := cmp.Diff(tc.expectedVuln, vuln, protocmp.Transform()); diff != "" {
				t.Errorf("FromCVE5() vuln mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFromCVE5_SourceLink(t *testing.T) {
	t.Parallel()
	cve := models.CVE5{
		Metadata: models.CVE5Metadata{
			CVEID: "CVE-2025-0002",
		},
	}
	metrics := &models.ConversionMetrics{}
	sourceLink := "https://github.com/CVEProject/cvelistV5/blob/main/cves/2025/0xxx/CVE-2025-0002.json"
	vuln := FromCVE5(cve, nil, metrics, sourceLink)

	if vuln.DatabaseSpecific == nil {
		t.Fatalf("Expected DatabaseSpecific to be non-nil")
	}
	got := vuln.DatabaseSpecific.GetFields()["osv_generated_from"].GetStringValue()
	if got != sourceLink {
		t.Errorf("osv_generated_from = %q, want %q", got, sourceLink)
	}
}

func TestFromCVE5_SeverityMerging(t *testing.T) {
	t.Parallel()
	cveWithCNAAndADP := models.CVE5{
		Metadata: models.CVE5Metadata{
			CVEID: "CVE-2025-5555",
		},
		Containers: struct {
			CNA models.CNA   `json:"cna"`
			ADP []models.CNA `json:"adp,omitempty"`
		}{
			CNA: models.CNA{
				Metrics: []models.Metrics{
					{
						CVSSv3_1: models.BaseCVSS{
							VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
						},
					},
				},
			},
			ADP: []models.CNA{
				{
					Metrics: []models.Metrics{
						{
							CVSSv3_0: models.BaseCVSS{
								VectorString: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H",
							},
						},
					},
				},
			},
		},
	}

	metrics := &models.ConversionMetrics{}
	vuln := FromCVE5(cveWithCNAAndADP, nil, metrics, "")
	if len(vuln.Severity) == 0 {
		t.Fatalf("Expected severity to be populated")
	}
	// CVSS v3.1 from CNA should take precedence over CVSS v3.0 from ADP
	if vuln.Severity[0].GetScore() != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" {
		t.Errorf("vuln.Severity[0].Score = %q, want CVSS 3.1 score", vuln.Severity[0].GetScore())
	}
}

func TestFromCVE5_ReferencesDeterminism(t *testing.T) {
	t.Parallel()
	cve := models.CVE5{}
	metrics := &models.ConversionMetrics{}
	refData := []models.Reference{
		{URL: "https://example.com/D"},
		{URL: "https://example.com/A"},
		{URL: "https://example.com/C", Tags: []string{"patch"}},
		{URL: "https://example.com/C"},
		{URL: "https://example.com/B", Tags: []string{"issue-tracking"}},
		{URL: "https://example.com/E"},
	}

	var firstResult []*osvschema.Reference
	for i := range 10 {
		vuln := FromCVE5(cve, refData, metrics, "")
		if i == 0 {
			firstResult = vuln.References
			continue
		}

		if diff := cmp.Diff(firstResult, vuln.References, protocmp.Transform()); diff != "" {
			t.Fatalf("Iteration %d produced different references result:\n%s", i, diff)
		}
	}
}

func TestConvertAndExportCVEToOSV(t *testing.T) {
	r := testutils.SetupGitVCR(t)
	cve := loadTestData(t, "CVE-2025-1110")
	cache := &git.InMemoryRepoTagsCache{}

	vWriter := bytes.NewBuffer(nil)
	mWriter := bytes.NewBuffer(nil)
	sourceLink := "https://example.com/CVE-2025-1110.json"

	metrics, err := ConvertAndExportCVEToOSV(cve, vWriter, mWriter, sourceLink, cache, r.GetDefaultClient())
	if err != nil {
		t.Fatalf("Unexpected error from ConvertAndExportCVEToOSV: %v", err)
	}

	if metrics == nil {
		t.Fatal("Expected non-nil metrics")
	}
	if metrics.CVEID != "CVE-2025-1110" {
		t.Errorf("metrics.CVEID = %q, want CVE-2025-1110", metrics.CVEID)
	}

	// Verify vulnSink wrote valid JSON
	var parsedVuln map[string]any
	if err := json.Unmarshal(vWriter.Bytes(), &parsedVuln); err != nil {
		t.Fatalf("vulnSink did not contain valid JSON: %v", err)
	}
	if parsedVuln["id"] != "CVE-2025-1110" {
		t.Errorf("parsedVuln id = %v, want CVE-2025-1110", parsedVuln["id"])
	}

	// Verify sourceLink is present in database_specific
	if dbSpec, ok := parsedVuln["database_specific"].(map[string]any); ok {
		if dbSpec["osv_generated_from"] != sourceLink {
			t.Errorf("osv_generated_from = %v, want %s", dbSpec["osv_generated_from"], sourceLink)
		}
	} else {
		t.Error("database_specific missing in parsed vulnerability")
	}

	// Verify metricsSink wrote valid JSON matching returned metrics
	var parsedMetrics models.ConversionMetrics
	if err := json.Unmarshal(mWriter.Bytes(), &parsedMetrics); err != nil {
		t.Fatalf("metricsSink did not contain valid JSON: %v", err)
	}
	if parsedMetrics.CVEID != metrics.CVEID || parsedMetrics.CNA != metrics.CNA {
		t.Errorf("metricsSink content mismatch: got %+v, want %+v", parsedMetrics, metrics)
	}
}

func TestConvertAndExportCVEToOSV_NilSinks(t *testing.T) {
	cve := loadTestData(t, "CVE-2025-1110")
	cache := &git.InMemoryRepoTagsCache{}
	r := testutils.SetupGitVCR(t)

	// 1. Untyped nil metricsSink
	vWriter := bytes.NewBuffer(nil)
	metrics, err := ConvertAndExportCVEToOSV(cve, vWriter, nil, "", cache, r.GetDefaultClient())
	if err != nil {
		t.Fatalf("Unexpected error with untyped nil metricsSink: %v", err)
	}
	if metrics == nil {
		t.Fatalf("Expected non-nil metrics return")
	}

	// 2. Untyped nil vulnSink
	mWriter := bytes.NewBuffer(nil)
	metrics, err = ConvertAndExportCVEToOSV(cve, nil, mWriter, "", cache, r.GetDefaultClient())
	if err != nil {
		t.Fatalf("Unexpected error with untyped nil vulnSink: %v", err)
	}
	if metrics == nil {
		t.Fatalf("Expected non-nil metrics return")
	}
	if mWriter.Len() == 0 {
		t.Fatalf("Expected non-empty metricsSink output")
	}

	// 3. Both sinks nil
	metrics, err = ConvertAndExportCVEToOSV(cve, nil, nil, "", cache, r.GetDefaultClient())
	if err != nil {
		t.Fatalf("Unexpected error with both sinks nil: %v", err)
	}
	if metrics == nil {
		t.Fatalf("Expected non-nil metrics return")
	}
}

type errWriter struct{}

func (errWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("simulated write error")
}

func TestConvertAndExportCVEToOSV_WriterErrors(t *testing.T) {
	cve := loadTestData(t, "CVE-2025-1110")
	cache := &git.InMemoryRepoTagsCache{}
	r := testutils.SetupGitVCR(t)

	// 1. Error on vulnSink
	_, err := ConvertAndExportCVEToOSV(cve, errWriter{}, nil, "", cache, r.GetDefaultClient())
	if err == nil {
		t.Error("Expected error when vulnSink fails to write, got nil")
	}

	// 2. Error on metricsSink
	vWriter := bytes.NewBuffer(nil)
	_, err = ConvertAndExportCVEToOSV(cve, vWriter, errWriter{}, "", cache, r.GetDefaultClient())
	if err == nil {
		t.Error("Expected error when metricsSink fails to write, got nil")
	}
}

func TestCVE5Snapshot(t *testing.T) {
	r := testutils.SetupGitVCR(t)
	testDir := "../../test_data/cve5"
	files, err := os.ReadDir(testDir)
	if err != nil {
		t.Fatalf("Failed to read test directory %s: %v", testDir, err)
	}

	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}

		t.Run(file.Name(), func(t *testing.T) {
			t.Parallel()
			cache := &git.InMemoryRepoTagsCache{}

			path := filepath.Join(testDir, file.Name())
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("Failed to read %s: %v", path, err)
			}

			var cve models.CVE5
			err = json.Unmarshal(content, &cve)
			if err != nil {
				t.Fatalf("Failed to unmarshal %s: %v", path, err)
			}

			vWriter := bytes.NewBuffer(nil)
			mWriter := bytes.NewBuffer(nil)
			_, err = ConvertAndExportCVEToOSV(cve, vWriter, mWriter, "", cache, r.GetDefaultClient())
			if err != nil {
				t.Fatalf("Failed to convert %s: %v", path, err)
			}

			var vuln map[string]any
			if err := json.Unmarshal(vWriter.Bytes(), &vuln); err != nil {
				t.Fatalf("Failed to unmarshal converted output %s: %v", path, err)
			}
			delete(vuln, "schema_version")
			cleanJSON, err := json.MarshalIndent(vuln, "", "  ")
			if err != nil {
				t.Fatalf("Failed to marshal output %s: %v", path, err)
			}

			snaps.MatchSnapshot(t, string(cleanJSON))
		})
	}
}
