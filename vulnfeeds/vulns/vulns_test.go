package vulns

import (
	"encoding/json"
	"github.com/google/osv/vulnfeeds/utility"
	"log"
	"os"
	"testing"

	"github.com/google/osv/vulnfeeds/cves"
)

func TestClassifyReferenceLink(t *testing.T) {
	tables := []struct {
		refLink string
		refType string
	}{
		{"https://example.com", "WEB"},
		{"https://github.com/google/osv/commit/cd4e934d0527e5010e373e7fed54ef5daefba2f5", "FIX"},
		{"https://github.com/advisories/GHSA-fr26-qjc8-mvjx", "ADVISORY"},
		{"https://github.com/dpgaspar/Flask-AppBuilder/security/advisories/GHSA-624f-cqvr-3qw4", "ADVISORY"},
		{"https://github.com/Netflix/lemur/issues/117", "REPORT"},
		{"https://snyk.io/vuln/SNYK-PYTHON-TRYTOND-1730329", "ADVISORY"},
		{"https://nvd.nist.gov/vuln/detail/CVE-2021-23336", "ADVISORY"},
		{"https://www.debian.org/security/2021/dsa-4878", "ADVISORY"},
		{"https://usn.ubuntu.com/usn/usn-4661-1", "ADVISORY"},
		{"http://www.ubuntu.com/usn/USN-2915-2", "ADVISORY"},
		{"https://ubuntu.com/security/notices/USN-5124-1", "ADVISORY"},
		{"http://rhn.redhat.com/errata/RHSA-2016-0504.html", "ADVISORY"},
		{"https://access.redhat.com/errata/RHSA-2017:1499", "ADVISORY"},
		{"https://security.gentoo.org/glsa/202003-45", "ADVISORY"},
		{"https://pypi.org/project/flask", "PACKAGE"},
		{"https://bugzilla.redhat.com/show_bug.cgi?id=684877", "REPORT"},
	}

	for _, table := range tables {
		refType := ClassifyReferenceLink(table.refLink)
		if refType != table.refType {
			t.Errorf("ClassifyReferenceLink for %s was incorrect, got: %s, expected: %s.", table.refLink, refType, table.refType)
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
		PkgName:      "TestName",
		Ecosystem:    "TestEco",
		FixedVersion: "1.2.3-4",
	}
	testPkgInfoPURL := PackageInfo{
		PURL:         "pkg:deb/debian/nginx@1.1.2-1",
		FixedVersion: "1.2.3-4",
	}
	testPkgInfoCommits := PackageInfo{
		Repo:        "github.com/foo/bar",
		FixedCommit: "dsafwefwfe370a9e65d68d62ef37345597e4100b0e87021dfb",
	}
	vuln.AddPkgInfo(testPkgInfoNameEco)
	vuln.AddPkgInfo(testPkgInfoPURL)
	vuln.AddPkgInfo(testPkgInfoCommits)

	// testPkgInfoNameEco vvvvvvvvvvvvvvv
	if vuln.Affected[0].Package.Name != testPkgInfoNameEco.PkgName {
		t.Errorf("AddPkgInfo has not corrected added package name.")
	}

	if vuln.Affected[0].Package.Ecosystem != testPkgInfoNameEco.Ecosystem {
		t.Errorf("AddPkgInfo has not corrected added package ecosystem.")
	}

	if vuln.Affected[0].Ranges[0].Type != "ECOSYSTEM" {
		t.Errorf("AddPkgInfo has not corrected added ranges type.")
	}

	if vuln.Affected[0].Ranges[0].Events[1].Fixed != testPkgInfoNameEco.FixedVersion {
		t.Errorf("AddPkgInfo has not corrected added ranges fixed.")
	}
	// testPkgInfoNameEco ^^^^^^^^^^^^^^^

	// testPkgInfoPURL vvvvvvvvvvvvvvv
	if vuln.Affected[1].Package.Purl != testPkgInfoPURL.PURL {
		t.Errorf("AddPkgInfo has not corrected added package PURL.")
	}
	if vuln.Affected[1].Ranges[0].Type != "ECOSYSTEM" {
		t.Errorf("AddPkgInfo has not corrected added ranges type.")
	}
	if vuln.Affected[1].Ranges[0].Events[1].Fixed != testPkgInfoPURL.FixedVersion {
		t.Errorf("AddPkgInfo has not corrected added ranges fixed.")
	}
	// testPkgInfoPURL ^^^^^^^^^^^^^^^

	// testPkgInfoCommits vvvvvvvvvvvvvv
	// TODO: Where is the Repo field suppose to go?

	if vuln.Affected[2].Ranges[0].Type != "GIT" {
		t.Errorf("AddPkgInfo has not corrected added ranges type.")
	}
	if vuln.Affected[2].Ranges[0].Events[1].Fixed != testPkgInfoCommits.FixedCommit {
		t.Errorf("AddPkgInfo has not corrected added ranges fixed.")
	}
	// testPkgInfoCommits ^^^^^^^^^^^^^^^
}
