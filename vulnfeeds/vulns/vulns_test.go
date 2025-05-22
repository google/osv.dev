package vulns

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"reflect"
	"testing"

	"golang.org/x/exp/slices"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/google/osv/vulnfeeds/utility"

	"github.com/google/osv/vulnfeeds/common"
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
		refData    []cves.Reference
		references References
	}{
		{
			refData: []cves.Reference{
				{
					Source: "https://example.com", Tags: []string{"MISC"}, Url: "https://example.com",
				},
			},
			references: References{{URL: "https://example.com", Type: "WEB"}},
		},
		{
			refData: []cves.Reference{
				{
					Source: "https://github.com/Netflix/lemur/issues/117", Url: "https://github.com/Netflix/lemur/issues/117", Tags: []string{"MISC", "Issue Tracking"},
				},
			},
			references: References{{URL: "https://github.com/Netflix/lemur/issues/117", Type: "REPORT"}},
		},
		{
			refData: []cves.Reference{
				{
					Source: "https://github.com/curl/curl/issues/9271", Url: "https://github.com/curl/curl/issues/9271", Tags: []string{"MISC", "Exploit", "Issue Tracking", "Third Party Advisory"},
				},
			},
			references: References{{URL: "https://github.com/curl/curl/issues/9271", Type: "EVIDENCE"}, {URL: "https://github.com/curl/curl/issues/9271", Type: "REPORT"}},
		},
	}
	for _, tc := range testcases {
		references := ClassifyReferences(tc.refData)
		if !reflect.DeepEqual(references, tc.references) {
			t.Errorf("ClassifyReferences for %+v was incorrect, got: %+v, expected: %+v", tc.refData, references, tc.references)
		}
	}
}

func loadTestData2(cveName string) cves.Vulnerability {
	fileName := fmt.Sprintf("../test_data/nvdcve-2.0/%s.json", cveName)
	file, err := os.Open(fileName)
	if err != nil {
		log.Fatalf("Failed to load test data from %q", fileName)
	}
	var nvdCves cves.CVEAPIJSON20Schema
	err = json.NewDecoder(file).Decode(&nvdCves)
	if err != nil {
		log.Fatalf("Failed to decode %q: %+v", fileName, err)
	}
	for _, vulnerability := range nvdCves.Vulnerabilities {
		if string(vulnerability.CVE.ID) == cveName {
			return vulnerability
		}
	}
	log.Fatalf("test data doesn't contain %q", cveName)
	return cves.Vulnerability{}
}

func TestExtractAliases(t *testing.T) {
	// TODO: convert to table based test
	cveItem := loadTestData2("CVE-2022-36037")
	aliases, related := extractReferencedVulns(cveItem.CVE.ID, cveItem.CVE)
	if !utility.SliceEqual(aliases, []string{"GHSA-3f89-869f-5w76"}) || !utility.SliceEqual(related, []string{}) {
		t.Errorf("Aliases not extracted, got %v, but expected %v.", aliases, []string{"GHSA-3f89-869f-5w76"})
	}
	cveItem = loadTestData2("CVE-2022-36749")
	aliases, related = extractReferencedVulns(cveItem.CVE.ID, cveItem.CVE)
	if !utility.SliceEqual(aliases, []string{}) || !utility.SliceEqual(related, []string{}) {
		t.Errorf("Aliases not extracted, got %v, but expected %v.", aliases, []string{"GHSA-3f89-869f-5w76"})
	}
	cveItem = loadTestData2("CVE-2024-47177")
	aliases, related = extractReferencedVulns(cveItem.CVE.ID, cveItem.CVE)
	expectedRelated := []string{"GHSA-7xfx-47qg-grp6", "GHSA-p9rh-jxmq-gq47", "GHSA-rj88-6mr5-rcw8", "GHSA-w63j-6g73-wmg5"}
	if !utility.SliceEqual(aliases, []string{}) || !utility.SliceEqualUnordered(related, expectedRelated) {
		t.Errorf("Aliases not extracted, got %v, but expected %v.", aliases, []string{})
		t.Errorf("Related not extracted, got %v, but expected %v.", related, expectedRelated)
	}
}

func TestEnglishDescription(t *testing.T) {
	cveItem := loadTestData2("CVE-2022-36037")
	description := cves.EnglishDescription(cveItem.CVE)
	expectedDescription := "kirby is a content management system (CMS) that adapts to many different projects and helps you build your own ideal interface. Cross-site scripting (XSS) is a type of vulnerability that allows execution of any kind of JavaScript code inside the Panel session of the same or other users. In the Panel, a harmful script can for example trigger requests to Kirby's API with the permissions of the victim. If bad actors gain access to your group of authenticated Panel users they can escalate their privileges via the Panel session of an admin user. Depending on your site, other JavaScript-powered attacks are possible. The multiselect field allows selection of tags from an autocompleted list. Unfortunately, the Panel in Kirby 3.5 used HTML rendering for the raw option value. This allowed **attackers with influence on the options source** to store HTML code. The browser of the victim who visited a page with manipulated multiselect options in the Panel will then have rendered this malicious HTML code when the victim opened the autocomplete dropdown. Users are *not* affected by this vulnerability if you don't use the multiselect field or don't use it with options that can be manipulated by attackers. The problem has been patched in Kirby 3.5.8.1."
	if description != expectedDescription {
		t.Errorf("Description not extracted, got %v, but expected %v", description, expectedDescription)
	}
}

func TestAddPkgInfo(t *testing.T) {
	cveItem := loadTestData2("CVE-2022-36037")
	vuln := Vulnerability{
		ID: string(cveItem.CVE.ID),
	}
	testPkgInfoNameEco := PackageInfo{
		PkgName:   "TestName",
		Ecosystem: "TestEco",
		VersionInfo: common.VersionInfo{
			AffectedVersions: []common.AffectedVersion{
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
		VersionInfo: common.VersionInfo{
			AffectedVersions: []common.AffectedVersion{
				{
					Fixed: "1.2.3-4",
				},
			},
		},
	}
	testPkgInfoCommits := PackageInfo{
		VersionInfo: common.VersionInfo{
			AffectedCommits: []common.AffectedCommit{
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
		VersionInfo: common.VersionInfo{
			AffectedVersions: []common.AffectedVersion{
				{
					Fixed: "1.2.3-4",
				},
			},
			AffectedCommits: []common.AffectedCommit{
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
	testPkgInfoCommitsMultiple := PackageInfo{
		VersionInfo: common.VersionInfo{
			AffectedCommits: []common.AffectedCommit{
				{
					Introduced: "0xdeadbeef",
					Fixed:      "dsafwefwfe370a9e65d68d62ef37345597e4100b0e87021dfb",
					Repo:       "github.com/foo/bar",
				},
				{
					Fixed: "658fe213",
					Repo:  "github.com/foo/bar",
				},
				{
					LastAffected: "0xdeadf00d",
					Repo:         "github.com/foo/baz",
				},
			},
		},
	}
	testPkgInfoEcoMultiple := PackageInfo{
		PkgName:   "TestNameWithIntroduced",
		Ecosystem: "TestEco",
		VersionInfo: common.VersionInfo{
			AffectedVersions: []common.AffectedVersion{
				{
					Introduced: "1.0.0-1",
					Fixed:      "1.2.3-4",
				},
			},
		},
	}
	vuln.AddPkgInfo(testPkgInfoNameEco)         // This will end up in vuln.Affected[0]
	vuln.AddPkgInfo(testPkgInfoPURL)            // This will end up in vuln.Affected[1]
	vuln.AddPkgInfo(testPkgInfoCommits)         // This will end up in vuln.Affected[2]
	vuln.AddPkgInfo(testPkgInfoHybrid)          // This will end up in vuln.Affected[3]
	vuln.AddPkgInfo(testPkgInfoCommitsMultiple) // This will end up in vuln.Affected[4]
	vuln.AddPkgInfo(testPkgInfoEcoMultiple)     // This will end up in vuln.Affected[5]

	t.Logf("Resulting vuln: %+v", vuln)

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

	if vuln.Affected[0].Ranges[0].Events[0].Introduced != "0" {
		t.Errorf("AddPkgInfo has not correctly added zero introduced commit.")
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

	// testPkgInfoCommitsMultiple vvvvvvvvvvvvv
	if len(vuln.Affected[4].Ranges[0].Events) != 3 {
		t.Errorf("AddPkgInfo has not correctly added distinct range events from commits: %+v", vuln.Affected[4].Ranges)
	}
	// testPkgInfoCommitsMultiple ^^^^^^^^^^^^^

	// testPkgInfoEcoMultiple vvvvvvvvvvvvv
	if len(vuln.Affected[5].Ranges[0].Events) != 2 {
		t.Errorf("AddPkgInfo has not correctly added distinct range events from versions: %+v", vuln.Affected[5].Ranges)
	}
	// testPkgInfoEcoMultiple ^^^^^^^^^^^^^

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
				if e == (Event{}) {
					t.Errorf("Empty event detected for the repo %s", r.Repo)
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
		inputCVE       cves.Vulnerability
		expectedResult []Severity
	}{
		{
			description: "Successful CVE severity extraction and attachment",
			inputCVE:    loadTestData2("CVE-2022-34668"),
			expectedResult: []Severity{
				{
					Type:  "CVSS_V3",
					Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				},
			},
		},
		{
			description:    "CVE with no impact information",
			inputCVE:       loadTestData2("CVE-2023-5341"),
			expectedResult: nil,
		},
	}

	for _, tc := range tests {
		vuln, _ := FromCVE(tc.inputCVE.CVE.ID, tc.inputCVE.CVE)

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

func TestNVD2(t *testing.T) {
	cve := loadTestData2("CVE-2023-4863")
	t.Logf("Loaded CVE: %#v", cve)
}
