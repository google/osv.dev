package vulns

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	"golang.org/x/exp/slices"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/utility"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestClassifyReferenceLink(t *testing.T) {
	tables := []struct {
		refLink string
		refTag  string
		refType osvschema.ReferenceType
	}{
		{"https://example.com", "", osvschema.ReferenceWeb},
		{"https://github.com/google/osv/commit/cd4e934d0527e5010e373e7fed54ef5daefba2f5", "", osvschema.ReferenceFix},
		{"https://github.com/advisories/GHSA-fr26-qjc8-mvjx", "", osvschema.ReferenceAdvisory},
		{"https://github.com/dpgaspar/Flask-AppBuilder/security/advisories/GHSA-624f-cqvr-3qw4", "", osvschema.ReferenceAdvisory},
		{"https://github.com/Netflix/lemur/issues/117", "", osvschema.ReferenceReport},
		{"https://snyk.io/vuln/SNYK-PYTHON-TRYTOND-1730329", "", osvschema.ReferenceAdvisory},
		{"https://nvd.nist.gov/vuln/detail/CVE-2021-23336", "", osvschema.ReferenceAdvisory},
		{"https://www.debian.org/security/2021/dsa-4878", "", osvschema.ReferenceAdvisory},
		{"https://usn.ubuntu.com/usn/usn-4661-1", "", osvschema.ReferenceAdvisory},
		{"http://www.ubuntu.com/usn/USN-2915-2", "", osvschema.ReferenceAdvisory},
		{"https://ubuntu.com/security/notices/USN-5124-1", "", osvschema.ReferenceAdvisory},
		{"http://rhn.redhat.com/errata/RHSA-2016-0504.html", "", osvschema.ReferenceAdvisory},
		{"https://access.redhat.com/errata/RHSA-2017:1499", "", osvschema.ReferenceAdvisory},
		{"https://security.gentoo.org/glsa/202003-45", "", osvschema.ReferenceAdvisory},
		{"https://pypi.org/project/flask", "", osvschema.ReferencePackage},
		{"https://bugzilla.redhat.com/show_bug.cgi?id=684877", "", osvschema.ReferenceReport},
		{"https://github.com/log4js-node/log4js-node/pull/1141/commits/8042252861a1b65adb66931fdf702ead34fa9b76", "Patch", osvschema.ReferenceFix},
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
		references []osvschema.Reference
	}{
		{
			refData: []cves.Reference{
				{
					Source: "https://example.com", Tags: []string{"MISC"}, Url: "https://example.com",
				},
			},
			references: []osvschema.Reference{{URL: "https://example.com", Type: osvschema.ReferenceWeb}},
		},
		{
			refData: []cves.Reference{
				{
					Source: "https://github.com/Netflix/lemur/issues/117", Url: "https://github.com/Netflix/lemur/issues/117", Tags: []string{"MISC", "Issue Tracking"},
				},
			},
			references: []osvschema.Reference{{URL: "https://github.com/Netflix/lemur/issues/117", Type: osvschema.ReferenceReport}},
		},
		{
			refData: []cves.Reference{
				{
					Source: "https://github.com/curl/curl/issues/9271", Url: "https://github.com/curl/curl/issues/9271", Tags: []string{"MISC", "Exploit", "Issue Tracking", "Third Party Advisory"},
				},
			},
			references: []osvschema.Reference{
				{URL: "https://github.com/curl/curl/issues/9271", Type: osvschema.ReferenceAdvisory},
				{URL: "https://github.com/curl/curl/issues/9271", Type: osvschema.ReferenceEvidence},
				{URL: "https://github.com/curl/curl/issues/9271", Type: osvschema.ReferenceReport},
			},
		},
	}
	for _, tc := range testcases {
		references := ClassifyReferences(tc.refData)
		sort.SliceStable(tc.references, func(i, j int) bool {
			return tc.references[i].Type < tc.references[j].Type
		})
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
	aliases, related := ExtractReferencedVulns(cveItem.CVE.ID, cveItem.CVE.ID, cveItem.CVE.References)
	if !utility.SliceEqual(aliases, []string{"GHSA-3f89-869f-5w76"}) || !utility.SliceEqual(related, []string{}) {
		t.Errorf("Aliases not extracted, got %v, but expected %v.", aliases, []string{"GHSA-3f89-869f-5w76"})
	}
	cveItem = loadTestData2("CVE-2022-36749")
	aliases, related = ExtractReferencedVulns(cveItem.CVE.ID, cveItem.CVE.ID, cveItem.CVE.References)
	if !utility.SliceEqual(aliases, []string{}) || !utility.SliceEqual(related, []string{}) {
		t.Errorf("Aliases not extracted, got %v, but expected %v.", aliases, []string{"GHSA-3f89-869f-5w76"})
	}
	cveItem = loadTestData2("CVE-2024-47177")
	aliases, related = ExtractReferencedVulns(cveItem.CVE.ID, cveItem.CVE.ID, cveItem.CVE.References)
	expectedRelated := []string{"GHSA-7xfx-47qg-grp6", "GHSA-p9rh-jxmq-gq47", "GHSA-rj88-6mr5-rcw8", "GHSA-w63j-6g73-wmg5"}
	if !utility.SliceEqual(aliases, []string{}) || !utility.SliceEqualUnordered(related, expectedRelated) {
		t.Errorf("Aliases not extracted, got %v, but expected %v.", aliases, []string{})
		t.Errorf("Related not extracted, got %v, but expected %v.", related, expectedRelated)
	}
}

func TestEnglishDescription(t *testing.T) {
	cveItem := loadTestData2("CVE-2022-36037")
	description := cves.EnglishDescription(cveItem.CVE.Descriptions)
	expectedDescription := "kirby is a content management system (CMS) that adapts to many different projects and helps you build your own ideal interface. Cross-site scripting (XSS) is a type of vulnerability that allows execution of any kind of JavaScript code inside the Panel session of the same or other users. In the Panel, a harmful script can for example trigger requests to Kirby's API with the permissions of the victim. If bad actors gain access to your group of authenticated Panel users they can escalate their privileges via the Panel session of an admin user. Depending on your site, other JavaScript-powered attacks are possible. The multiselect field allows selection of tags from an autocompleted list. Unfortunately, the Panel in Kirby 3.5 used HTML rendering for the raw option value. This allowed **attackers with influence on the options source** to store HTML code. The browser of the victim who visited a page with manipulated multiselect options in the Panel will then have rendered this malicious HTML code when the victim opened the autocomplete dropdown. Users are *not* affected by this vulnerability if you don't use the multiselect field or don't use it with options that can be manipulated by attackers. The problem has been patched in Kirby 3.5.8.1."
	if description != expectedDescription {
		t.Errorf("Description not extracted, got %v, but expected %v", description, expectedDescription)
	}
}

func TestAddPkgInfo(t *testing.T) {
	cveItem := loadTestData2("CVE-2022-36037")
	vuln := Vulnerability{}
	vuln.ID = string(cveItem.CVE.ID)

	testPkgInfoNameEco := PackageInfo{
		PkgName:   "TestName",
		Ecosystem: "TestEco",
		VersionInfo: models.VersionInfo{
			AffectedVersions: []models.AffectedVersion{
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
		VersionInfo: models.VersionInfo{
			AffectedVersions: []models.AffectedVersion{
				{
					Fixed: "1.2.3-4",
				},
			},
		},
	}
	testPkgInfoCommits := PackageInfo{
		VersionInfo: models.VersionInfo{
			AffectedCommits: []models.AffectedCommit{
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
		VersionInfo: models.VersionInfo{
			AffectedVersions: []models.AffectedVersion{
				{
					Fixed: "1.2.3-4",
				},
			},
			AffectedCommits: []models.AffectedCommit{
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
		VersionInfo: models.VersionInfo{
			AffectedCommits: []models.AffectedCommit{
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
		VersionInfo: models.VersionInfo{
			AffectedVersions: []models.AffectedVersion{
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

	if vuln.Affected[0].Ranges[0].Type != osvschema.RangeEcosystem {
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
	if vuln.Affected[1].Ranges[0].Type != osvschema.RangeEcosystem {
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

	if vuln.Affected[2].Ranges[0].Type != osvschema.RangeGit {
		t.Errorf("AddPkgInfo has not correctly added ranges type.")
	}
	if vuln.Affected[2].Ranges[0].Events[1].Fixed != testPkgInfoCommits.VersionInfo.AffectedCommits[0].Fixed {
		t.Errorf("AddPkgInfo has not correctly added ranges fixed.")
	}
	if vuln.Affected[2].Package != (osvschema.Package{}) {
		t.Errorf("AddPkgInfo has not correctly avoided setting a package field for an ecosystem-less vulnerability.")
	}
	if !slices.IsSortedFunc(vuln.Affected[3].Ranges, func(a, b osvschema.Range) int {
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
				if r.Type == osvschema.RangeGit && e.Introduced == "0" {
					// zeroIntroducedCommitHashCount++
					if _, ok := perRepoZeroIntroducedCommitHashCount[r.Repo]; !ok {
						perRepoZeroIntroducedCommitHashCount[r.Repo] = 1
					} else {
						perRepoZeroIntroducedCommitHashCount[r.Repo]++
					}
				}
				if e == (osvschema.Event{}) {
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
		expectedResult []osvschema.Severity
	}{
		{
			description: "Successful CVE severity extraction and attachment",
			inputCVE:    loadTestData2("CVE-2022-34668"),
			expectedResult: []osvschema.Severity{
				{
					Type:  osvschema.SeverityCVSSV3,
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
		id := tc.inputCVE.CVE.ID
		vuln := FromNVDCVE(id, tc.inputCVE.CVE)

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
		inputVuln := &Vulnerability{}
		inputVuln.ID = tc.inputVulnId

		withdrawnTime, err := CVEIsDisputed(inputVuln, "../test_data/cvelistV5")

		if !errors.Is(err, tc.expectedError) {
			var verr *VulnsCVEListError
			if errors.As(err, &verr) {
				t.Errorf("test %q: unexpectedly errored: %#v", tc.description, verr.Err)
			} else {
				t.Errorf("test %q: unexpectedly errored: %#v, expected: %#v", tc.description, err, tc.expectedError)
			}
		}

		if withdrawnTime.IsZero() && tc.expectedWithdrawn {
			t.Errorf("test: %q: withdrawn time not set as expected", tc.description)
		}

		if !withdrawnTime.IsZero() && !tc.expectedWithdrawn {
			t.Errorf("test: %q: withdrawn time (%s) set unexpectedly", tc.description, withdrawnTime)
		}
	}
}

func TestNVD2(t *testing.T) {
	cve := loadTestData2("CVE-2023-4863")
	t.Logf("Loaded CVE: %#v", cve)
}
