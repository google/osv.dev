package main

import "testing"

func TestResolveLinterConfig(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		project, osvURL, legacyURL string
		wantURL                    string
		wantRedirect               bool
	}{
		{"oss-vdb", "", "", "api.osv.dev", true},
		{"oss-vdb-test", "", "", "api.test.osv.dev", false},
		{"my-dev-sandbox", "", "", "api.osv.dev", false},
		{"my-dev-sandbox", "", "https://api.osv.dev/", "api.osv.dev", true},
		{"oss-vdb-test", "http://api.test.osv.dev/", "api.osv.dev", "api.test.osv.dev", false},
	} {
		gotURL, gotRedirect := resolveLinterConfig(tc.project, tc.osvURL, tc.legacyURL)
		if gotURL != tc.wantURL || gotRedirect != tc.wantRedirect {
			t.Errorf("resolveLinterConfig(%q, %q, %q) = (%q, %v), want (%q, %v)",
				tc.project, tc.osvURL, tc.legacyURL, gotURL, gotRedirect, tc.wantURL, tc.wantRedirect)
		}
	}
}
