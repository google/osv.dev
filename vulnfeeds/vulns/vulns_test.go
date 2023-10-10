package vulns

import (
	"cmp"
	"encoding/json"
	"errors"
	"log"
	"os"
	"reflect"
	"testing"

	"golang.org/x/exp/slices"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/google/osv/vulnfeeds/utility"

	"github.com/google/osv/vulnfeeds/cves"
)

func TestClassifyReferenceLink(t *testing.T) {
	tables := []struct {
		refLink string
		refTag  string
		refType string
	}{
		{"https://example.com", "", "WEB"},
		{"https://github.com/google/osv/commit/cd4e934d0527e5010e373e7fed54ef5daefba2f5", "", "FIX"},
		{"https://github.com/advisories/GHSA-fr26-qjc8-mvjx", "", "ADVISORY"},
		{"https://github.com/dpgaspar/Flask-AppBuilder/security/advisories/GHSA-624f-cqvr-3qw4", "", "ADVISORY"},
		{"https://github.com/Netflix/lemur/issues/117", "", "REPORT"},
		{"https://snyk.io/vuln/SNYK-PYTHON-TRYTOND-1730329", "", "ADVISORY"},
		{"https://nvd.nist.gov/vuln/detail/CVE-2021-23336", "", "ADVISORY"},
		{"https://www.debian.org/security/2021/dsa-4878", "", "ADVISORY"},
		{"https://usn.ubuntu.com/usn/usn-4661-1", "", "ADVISORY"},
		{"http://www.ubuntu.com/usn/USN-2915-2", "", "ADVISORY"},
		{"https://ubuntu.com/security/notices/USN-5124-1", "", "ADVISORY"},
		{"http://rhn.redhat.com/errata/RHSA-2016-0504.html", "", "ADVISORY"},
		{"https://access.redhat.com/errata/RHSA-2017:1499", "", "ADVISORY"},
		{"https://security.gentoo.org/glsa/202003-45", "", "ADVISORY"},
		{"https://pypi.org/project/flask", "", "PACKAGE"},
		{"https://bugzilla.redhat.com/show_bug.cgi?id=684877", "", "REPORT"},
		{"https://github.com/log4js-node/log4js-node/pull/1141/commits/8042252861a1b65adb66931fdf702ead34fa9b76", "Patch", "FIX"},
	}

	for _, table := range tables {
		refType := ClassifyReferenceLink(table.refLink, table.refTag)
		if refType != table.refType {
			t.Errorf("ClassifyReferenceLink for %s was incorrect, got: %s, expected: %s.", table.refLink, refType, table.refType)
		}
	}
}

func TestClassifyReferences(t *testing.T) {
	testcases := []struct {
		refData    cves.CVEReferences
		references []Reference
	}{
		{cves.CVEReferences{
			ReferenceData: []cves.CVEReferenceData{
				{URL: "https://example.com", Name: "https://example.com", RefSource: "MISC", Tags: nil},
			},
		},
			[]Reference{{URL: "https://example.com", Type: "WEB"}}},
		{cves.CVEReferences{
			ReferenceData: []cves.CVEReferenceData{
				{URL: "https://github.com/Netflix/lemur/issues/117", Name: "https://github.com/Netflix/lemur/issues/117", RefSource: "MISC", Tags: []string{"Issue Tracking"}},
			},
		},
			[]Reference{{URL: "https://github.com/Netflix/lemur/issues/117", Type: "REPORT"}}},
		{cves.CVEReferences{
			ReferenceData: []cves.CVEReferenceData{
				{URL: "https://github.com/curl/curl/issues/9271", Name: "https://github.com/curl/curl/issues/9271", RefSource: "MISC", Tags: []string{"Exploit", "Issue Tracking", "Third Party Advisory"}},
			},
		},
			[]Reference{{URL: "https://github.com/curl/curl/issues/9271", Type: "EVIDENCE"}, {URL: "https://github.com/curl/curl/issues/9271", Type: "REPORT"}}},
	}
	for _, tc := range testcases {
		references := ClassifyReferences(tc.refData)
		if !reflect.DeepEqual(references, tc.references) {
			t.Errorf("ClassifyReferences for %+v was incorrect, got: %+v, expected: %+v", tc.refData, references, tc.references)
		}
	}
}

func loadTestData(cveName string) cves.CVEItem {
	file, err := os.Open("../test_data/nvdcve-1.1-test-data.json")
	if err != nil {
		log.Fatalf("Failed to load test data")
	}
	var nvdCves cves.NVDCVE
	json.NewDecoder(file).Decode(&nvdCves)
	for _, item := range nvdCves.CVEItems {
		if item.CVE.CVEDataMeta.ID == cveName {
			return item
		}
	}
	log.Fatalf("test data doesn't contain specified CVE")
	return cves.CVEItem{}
}

func TestExtractAliases(t *testing.T) {
	cveItem := loadTestData("CVE-2022-36037")
	aliases := extractAliases(cveItem.CVE.CVEDataMeta.ID, cveItem.CVE)
	if !utility.SliceEqual(aliases, []string{"GHSA-3f89-869f-5w76"}) {
		t.Errorf("Aliases not extracted, got %v, but expected %v.", aliases, []string{"GHSA-3f89-869f-5w76"})
	}
	cveItem = loadTestData("CVE-2022-36749")
	aliases = extractAliases(cveItem.CVE.CVEDataMeta.ID, cveItem.CVE)
	if !utility.SliceEqual(aliases, []string{}) {
		t.Errorf("Aliases not extracted, got %v, but expected %v.", aliases, []string{"GHSA-3f89-869f-5w76"})
	}
}

func TestEnglishDescription(t *testing.T) {
	cveItem := loadTestData("CVE-2022-36037")
	description := cves.EnglishDescription(cveItem.CVE)
	expectedDescription := "kirby is a content management system (CMS) that adapts to many different projects and helps you build your own ideal interface. Cross-site scripting (XSS) is a type of vulnerability that allows execution of any kind of JavaScript code inside the Panel session of the same or other users. In the Panel, a harmful script can for example trigger requests to Kirby's API with the permissions of the victim. If bad actors gain access to your group of authenticated Panel users they can escalate their privileges via the Panel session of an admin user. Depending on your site, other JavaScript-powered attacks are possible. The multiselect field allows selection of tags from an autocompleted list. Unfortunately, the Panel in Kirby 3.5 used HTML rendering for the raw option value. This allowed **attackers with influence on the options source** to store HTML code. The browser of the victim who visited a page with manipulated multiselect options in the Panel will then have rendered this malicious HTML code when the victim opened the autocomplete dropdown. Users are *not* affected by this vulnerability if you don't use the multiselect field or don't use it with options that can be manipulated by attackers. The problem has been patched in Kirby 3.5.8.1."
	if description != expectedDescription {
		t.Errorf("Description not extracted, got %v, but expected %v", description, expectedDescription)
	}
}

func TestAddPkgInfo(t *testing.T) {
	cveItem := loadTestData("CVE-2022-36037")
	vuln := Vulnerability{
		ID: cveItem.CVE.CVEDataMeta.ID,
	}
	testPkgInfoNameEco := PackageInfo{
		PkgName:   "TestName",
		Ecosystem: "TestEco",
		VersionInfo: cves.VersionInfo{
			AffectedVersions: []cves.AffectedVersion{
				{
					Fixed: "1.2.3-4",
				},
			},
		},
	}
	testPkgInfoPURL := PackageInfo{
		PkgName:   "nginx",
		Ecosystem: "Debian",
		PURL:      "pkg:deb/debian/nginx@1.1.2-1",
		VersionInfo: cves.VersionInfo{
			AffectedVersions: []cves.AffectedVersion{
				{
					Fixed: "1.2.3-4",
				},
			},
		},
	}
	testPkgInfoCommits := PackageInfo{
		VersionInfo: cves.VersionInfo{
			AffectedCommits: []cves.AffectedCommit{
				{
					Fixed: "dsafwefwfe370a9e65d68d62ef37345597e4100b0e87021dfb",
					Repo:  "github.com/foo/bar",
				},
			},
		},
	}
	testPkgInfoHybrid := PackageInfo{
		PkgName:   "apackage",
		Ecosystem: "Debian",
		PURL:      "pkg:deb/debian/apackage@1.2.3-4",
		VersionInfo: cves.VersionInfo{
			AffectedVersions: []cves.AffectedVersion{
				{
					Fixed: "1.2.3-4",
				},
			},
			AffectedCommits: []cves.AffectedCommit{
				{
					Fixed: "0xdeadbeef",
					Repo:  "github.com/foo/bar",
				},
				{
					Fixed: "0xdeadbeef",
					Repo:  "github.com/baz/quux",
				},
			},
		},
	}
	vuln.AddPkgInfo(testPkgInfoNameEco)
	vuln.AddPkgInfo(testPkgInfoPURL)
	vuln.AddPkgInfo(testPkgInfoCommits)
	vuln.AddPkgInfo(testPkgInfoHybrid)

	// testPkgInfoNameEco vvvvvvvvvvvvvvv
	if vuln.Affected[0].Package.Name != testPkgInfoNameEco.PkgName {
		t.Errorf("AddPkgInfo has not correctly added package name.")
	}

	if vuln.Affected[0].Package.Ecosystem != testPkgInfoNameEco.Ecosystem {
		t.Errorf("AddPkgInfo has not correctly added package ecosystem.")
	}

	if vuln.Affected[0].Ranges[0].Type != "ECOSYSTEM" {
		t.Errorf("AddPkgInfo has not correctly added ranges type.")
	}

	if vuln.Affected[0].Ranges[0].Events[1].Fixed != testPkgInfoNameEco.VersionInfo.AffectedVersions[0].Fixed {
		t.Errorf("AddPkgInfo has not correctly added ranges fixed.")
	}
	// testPkgInfoNameEco ^^^^^^^^^^^^^^^

	// testPkgInfoPURL vvvvvvvvvvvvvvv
	if vuln.Affected[1].Package.Purl != testPkgInfoPURL.PURL {
		t.Errorf("AddPkgInfo has not correctly added package PURL.")
	}
	if vuln.Affected[1].Ranges[0].Type != "ECOSYSTEM" {
		t.Errorf("AddPkgInfo has not correctly added ranges type.")
	}
	if vuln.Affected[1].Ranges[0].Events[1].Fixed != testPkgInfoPURL.VersionInfo.AffectedVersions[0].Fixed {
		t.Errorf("AddPkgInfo has not correctly added ranges fixed.")
	}
	// testPkgInfoPURL ^^^^^^^^^^^^^^^

	// testPkgInfoCommits vvvvvvvvvvvvvv
	if vuln.Affected[2].Ranges[0].Repo != "github.com/foo/bar" {
		t.Errorf("AddPkgInfo has not corrected add ranges repo. %#v", vuln.Affected[2])
	}

	if vuln.Affected[2].Ranges[0].Type != "GIT" {
		t.Errorf("AddPkgInfo has not correctly added ranges type.")
	}
	if vuln.Affected[2].Ranges[0].Events[1].Fixed != testPkgInfoCommits.VersionInfo.AffectedCommits[0].Fixed {
		t.Errorf("AddPkgInfo has not correctly added ranges fixed.")
	}
	if vuln.Affected[2].Package != nil {
		t.Errorf("AddPkgInfo has not correctly avoided setting a package field for an ecosystem-less vulnerability.")
	}
	if !slices.IsSortedFunc(vuln.Affected[3].Ranges, func(a, b AffectedRange) int {
		if n := cmp.Compare(a.Type, b.Type); n != 0 {
			return n
		}
		return cmp.Compare(a.Repo, b.Repo)
	}) {
		t.Errorf("AddPkgInfo has not generated a correctly sorted range.")
	}
	// testPkgInfoCommits ^^^^^^^^^^^^^^^

	for _, a := range vuln.Affected {
		perRepoZeroIntroducedCommitHashCount := make(map[string]int)
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if r.Type == "GIT" && e.Introduced == "0" {
					// zeroIntroducedCommitHashCount++
					if _, ok := perRepoZeroIntroducedCommitHashCount[r.Repo]; !ok {
						perRepoZeroIntroducedCommitHashCount[r.Repo] = 1
					} else {
						perRepoZeroIntroducedCommitHashCount[r.Repo]++
					}
				}
			}
		}
		for repo, zeroIntroducedCommitHashCount := range perRepoZeroIntroducedCommitHashCount {
			if zeroIntroducedCommitHashCount > 1 {
				t.Errorf("AddPkgInfo has synthesized more than one zero-valued introduced field for the repo %s.", repo)
			}
		}
	}
}

func TestAddSeverity(t *testing.T) {
	tests := []struct {
		description    string
		inputCVE       cves.CVEItem
		expectedResult []Severity
	}{
		{
			description: "Successful CVE severity extraction and attachment",
			inputCVE:    loadTestData("CVE-2022-34668"),
			expectedResult: []Severity{
				{
					Type:  "CVSS_V3",
					Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				},
			},
		},
		{
			description:    "CVE with no impact information",
			inputCVE:       loadTestData("CVE-2022-36037"),
			expectedResult: nil,
		},
	}

	for _, tc := range tests {
		vuln, _ := FromCVE(tc.inputCVE.CVE.CVEDataMeta.ID, tc.inputCVE)

		got := vuln.Severity
		if diff := gocmp.Diff(got, tc.expectedResult); diff != "" {
			t.Errorf("test %q: Incorrect result: %s", tc.description, diff)
		}
	}
}

func TestCVEIsDisputed(t *testing.T) {
	tests := []struct {
		description       string
		inputVulnId       string
		expectedWithdrawn bool
		expectedError     error
	}{
		{
			description:       "A non-CVE vulnerability",
			inputVulnId:       "OSV-1234",
			expectedWithdrawn: false,
			expectedError:     ErrVulnNotACVE,
		},
		{
			description:       "A disputed CVE vulnerability",
			inputVulnId:       "CVE-2023-23127",
			expectedWithdrawn: true,
			expectedError:     nil,
		},
		{
			description:       "A disputed CVE vulnerability",
			inputVulnId:       "CVE-2021-26917",
			expectedWithdrawn: true,
			expectedError:     nil,
		},
		{
			description:       "An undisputed CVE vulnerability",
			inputVulnId:       "CVE-2023-38408",
			expectedWithdrawn: false,
			expectedError:     nil,
		},
	}

	for _, tc := range tests {
		inputVuln := &Vulnerability{
			ID: tc.inputVulnId,
		}

		modified, err := CVEIsDisputed(inputVuln, "../test_data/cvelistV5")

		if err != nil && err != tc.expectedError {
			var verr *VulnsCVEListError
			if errors.As(err, &verr) {
				t.Errorf("test %q: unexpectedly errored: %#v", tc.description, verr.Err)
			} else {
				t.Errorf("test %q: unexpectedly errored: %#v", tc.description, err)
			}
		}

		if err == nil && tc.expectedError != nil {
			t.Errorf("test %q: did not error as expected, wanted: %#v", tc.description, tc.expectedError)
		}

		if modified == "" && tc.expectedWithdrawn {
			t.Errorf("test: %q: withdrawn (%s) not set as expected", tc.description, modified)
		}
	}
}
