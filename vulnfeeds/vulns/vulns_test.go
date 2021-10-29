package vulns

import "testing"

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
