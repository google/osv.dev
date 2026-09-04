package main

import (
	"testing"

	"github.com/google/osv.dev/vulnfeeds/models"
)

func TestCpeMatchesAlpinePackage(t *testing.T) {
	tests := []struct {
		name      string
		product   string
		targetSW  string
		alpinePkg string
		want      bool
	}{
		{"direct match", "xz", "", "xz", true},
		{"direct match case-insensitive", "OpenSSL", "", "openssl", true},
		// Direct match on the full prefixed name takes priority over prefix rewriting.
		{"direct match beats prefix logic", "py3-foo", "python", "py3-foo", true},
		{"direct mismatch no targetSW", "openssl", "", "xz", false},

		// Python
		{"python prefix exact", "pillow", "python", "py3-pillow", true},
		{"python prefix uppercase product", "Pillow", "python", "py3-pillow", true},
		{"python prefix underscore product", "python_pillow", "python", "py3-python-pillow", true},
		{"python prefix different package name", "pillow", "python", "py3-imaging", false},
		{"python prefix case-insensitive targetSW", "certifi", "Python", "py3-certifi", true},
		{"python prefix cpython in targetSW", "certifi", "cpython", "py3-certifi", true},

		// Ruby
		{"ruby prefix", "bigdecimal", "ruby", "ruby-bigdecimal", true},
		{"ruby prefix underscore", "some_gem", "ruby", "ruby-some-gem", true},

		// Perl
		{"perl prefix simple", "json", "perl", "perl-json", true},
		{"perl prefix double-colon namespace", "CGI::Session", "perl", "perl-cgi-session", true},

		// Lua
		{"lua prefix", "luaossl", "lua", "lua-luaossl", true},

		// VSCode
		{"vscode prefix", "python", "visual_studio_code", "vscode-python", true},

		// Unknown / unhandled targetSW
		{"java targetSW product mismatch", "log4j", "java", "log4j-core", false},
		{"unknown targetSW product mismatch", "foo", "java", "bar", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed := &models.CPEString{Product: tc.product, TargetSW: tc.targetSW}
			got := cpeMatchesAlpinePackage(parsed, tc.alpinePkg)
			if got != tc.want {
				t.Errorf("cpeMatchesAlpinePackage({Product:%q, TargetSW:%q}, %q) = %v, want %v",
					tc.product, tc.targetSW, tc.alpinePkg, got, tc.want)
			}
		})
	}
}

func TestFindIntroducedVersion(t *testing.T) {
	// A valid CPE 2.3 string whose product is "xz" with no target_sw.
	const xzCPE = "cpe:2.3:a:tukaani:xz:*:*:*:*:*:*:*:*"
	// A valid CPE 2.3 string whose product is "foo".
	const fooCPE = "cpe:2.3:a:example:foo:*:*:*:*:*:*:*:*"
	// A valid CPE 2.3 string for a python package.
	const pillowCPE = "cpe:2.3:a:python-pillow:pillow:*:*:*:*:*:python:*:*"

	tests := []struct {
		name         string
		cve          models.NVDCVE
		alpinePkg    string
		fixedVersion string
		want         string
	}{
		{
			name:         "no configurations",
			cve:          models.NVDCVE{},
			alpinePkg:    "xz",
			fixedVersion: "5.6.1-r0",
			want:         "0",
		},
		{
			name: "match with VersionStartIncluding",
			cve: models.NVDCVE{
				Configurations: []models.Config{{
					Nodes: []models.Node{{
						CPEMatch: []models.CPEMatch{{
							Criteria:              xzCPE,
							Vulnerable:            true,
							VersionStartIncluding: new("5.6.0"),
						}},
					}},
				}},
			},
			alpinePkg:    "xz",
			fixedVersion: "5.6.1-r0",
			want:         "5.6.0",
		},
		{
			name: "non-vulnerable CPE skipped",
			cve: models.NVDCVE{
				Configurations: []models.Config{{
					Nodes: []models.Node{{
						CPEMatch: []models.CPEMatch{{
							Criteria:              xzCPE,
							Vulnerable:            false,
							VersionStartIncluding: new("5.6.0"),
						}},
					}},
				}},
			},
			alpinePkg:    "xz",
			fixedVersion: "5.6.1-r0",
			want:         "0",
		},
		{
			name: "VersionStartIncluding nil returns 0",
			cve: models.NVDCVE{
				Configurations: []models.Config{{
					Nodes: []models.Node{{
						CPEMatch: []models.CPEMatch{{
							Criteria:   xzCPE,
							Vulnerable: true,
						}},
					}},
				}},
			},
			alpinePkg:    "xz",
			fixedVersion: "5.6.1-r0",
			want:         "0",
		},
		{
			// Known gap: VersionStartExcluding is not handled; falls back to "0".
			name: "VersionStartExcluding only falls back to 0",
			cve: models.NVDCVE{
				Configurations: []models.Config{{
					Nodes: []models.Node{{
						CPEMatch: []models.CPEMatch{{
							Criteria:              xzCPE,
							Vulnerable:            true,
							VersionStartExcluding: new("5.5.0"),
						}},
					}},
				}},
			},
			alpinePkg:    "xz",
			fixedVersion: "5.6.1-r0",
			want:         "0",
		},
		{
			name: "invalid CPE criteria skipped",
			cve: models.NVDCVE{
				Configurations: []models.Config{{
					Nodes: []models.Node{{
						CPEMatch: []models.CPEMatch{{
							Criteria:              "not-a-cpe",
							Vulnerable:            true,
							VersionStartIncluding: new("1.0.0"),
						}},
					}},
				}},
			},
			alpinePkg:    "xz",
			fixedVersion: "5.6.1-r0",
			want:         "0",
		},
		{
			name: "match found in second node",
			cve: models.NVDCVE{
				Configurations: []models.Config{{
					Nodes: []models.Node{
						{
							CPEMatch: []models.CPEMatch{{
								Criteria:              xzCPE,
								Vulnerable:            true,
								VersionStartIncluding: new("0.9.0"),
							}},
						},
						{
							CPEMatch: []models.CPEMatch{{
								Criteria:              fooCPE,
								Vulnerable:            true,
								VersionStartIncluding: new("1.0.0"),
							}},
						},
					},
				}},
			},
			alpinePkg:    "foo",
			fixedVersion: "1.2.0-r0",
			want:         "1.0.0",
		},
		{
			name: "python package prefix match",
			cve: models.NVDCVE{
				Configurations: []models.Config{{
					Nodes: []models.Node{{
						CPEMatch: []models.CPEMatch{{
							Criteria:              pillowCPE,
							Vulnerable:            true,
							VersionStartIncluding: new("9.0.0"),
						}},
					}},
				}},
			},
			alpinePkg:    "py3-pillow",
			fixedVersion: "9.1.0-r0",
			want:         "9.0.0",
		},
		{
			// Among multiple qualifying candidates, the one closest to (just
			// below) the fixed version is preferred as the tightest bound.
			name: "closest qualifying match wins when multiple CPEs match",
			cve: models.NVDCVE{
				Configurations: []models.Config{{
					Nodes: []models.Node{{
						CPEMatch: []models.CPEMatch{
							{
								Criteria:              xzCPE,
								Vulnerable:            true,
								VersionStartIncluding: new("5.0.0"),
							},
							{
								Criteria:              xzCPE,
								Vulnerable:            true,
								VersionStartIncluding: new("5.6.0"),
							},
						},
					}},
				}},
			},
			alpinePkg:    "xz",
			fixedVersion: "5.6.1-r0",
			want:         "5.6.0",
		},
		{
			// Regression test for https://github.com/google/osv.dev/issues/5634:
			// NVD's CPE configuration for perl CVE-2018-18311 describes two
			// independently fixed branches (< 5.26.3 and [5.28.0, 5.28.1)).
			// Alpine's secfix is 5.26.3-r0, on the first branch, so the
			// 5.28.0 VersionStartIncluding from the unrelated second branch
			// must not be used as introduced: it would invert the range.
			name: "unrelated higher branch is not used as introduced",
			cve: models.NVDCVE{
				Configurations: []models.Config{{
					Nodes: []models.Node{{
						CPEMatch: []models.CPEMatch{
							{
								Criteria:            "cpe:2.3:a:perl:perl:*:*:*:*:*:*:*:*",
								Vulnerable:          true,
								VersionEndExcluding: new("5.26.3"),
							},
							{
								Criteria:              "cpe:2.3:a:perl:perl:*:*:*:*:*:*:*:*",
								Vulnerable:            true,
								VersionStartIncluding: new("5.28.0"),
								VersionEndExcluding:   new("5.28.1"),
							},
						},
					}},
				}},
			},
			alpinePkg:    "perl",
			fixedVersion: "5.26.3-r0",
			want:         "0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := findIntroducedVersion(tc.cve, tc.alpinePkg, tc.fixedVersion)
			if got != tc.want {
				t.Errorf("findIntroducedVersion(..., %q, %q) = %q, want %q", tc.alpinePkg, tc.fixedVersion, got, tc.want)
			}
		})
	}
}

func TestVersionLess(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"5.28.0", "5.26.3-r0", false},
		{"0", "5.26.3-r0", true},
		{"5.0.0", "5.6.1-r0", true},
		{"5.6.0", "5.6.1-r0", true},
		{"5.6.1", "5.6.1-r0", false},
		{"1.0.2", "1.0.2a", false},
		{"9.0.0", "9.1.0-r0", true},
		{"1.2.0", "1.2.0-r0", false},
	}

	for _, tc := range tests {
		t.Run(tc.a+"_vs_"+tc.b, func(t *testing.T) {
			got := versionLess(tc.a, tc.b)
			if got != tc.want {
				t.Errorf("versionLess(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestGenerateAlpineOSV(t *testing.T) {
	const xzCPE = "cpe:2.3:a:tukaani:xz:*:*:*:*:*:*:*:*"
	const fooCPE = "cpe:2.3:a:example:foo:*:*:*:*:*:*:*:*"

	allAlpineSecDb := map[string][]VersionAndPkg{
		"CVE-2024-1": {
			{Pkg: "xz", Ver: "5.6.1", AlpineVer: "v3.19"},
			{Pkg: "xz", Ver: "5.4.6", AlpineVer: "v3.18"},
			{Pkg: "foo", Ver: "1.2.3", AlpineVer: "v3.19"},
			{Pkg: "bar", Ver: "0", AlpineVer: "v3.19"}, // Should be skipped
		},
	}

	allCVEs := map[models.CVEID]models.Vulnerability{
		"CVE-2024-1": {
			CVE: models.NVDCVE{
				ID: "CVE-2024-1",
				Configurations: []models.Config{{
					Nodes: []models.Node{{
						CPEMatch: []models.CPEMatch{
							{
								Criteria:              xzCPE,
								Vulnerable:            true,
								VersionStartIncluding: new("5.6.0"),
							},
							{
								Criteria:              fooCPE,
								Vulnerable:            true,
								VersionStartIncluding: new("1.0.0"),
							},
						},
					}},
				}},
			},
		},
	}

	got := generateAlpineOSV(allAlpineSecDb, allCVEs)

	if len(got) != 1 {
		t.Fatalf("generateAlpineOSV() returned %d vulnerabilities, want 1", len(got))
	}

	vuln := got[0]
	if vuln.Id != "ALPINE-CVE-2024-1" {
		t.Errorf("Expected ID ALPINE-CVE-2024-1, got %q", vuln.Id)
	}

	// We expect 3 affected packages: xz (v3.19), xz (v3.18), foo (v3.19)
	if len(vuln.Affected) != 3 {
		t.Fatalf("Expected 3 affected packages, got %d", len(vuln.Affected))
	}

	// Verify details of affected packages
	// Order should be: foo (v3.19), xz (v3.18), xz (v3.19)
	if vuln.Affected[0].GetPackage().GetName() != "foo" {
		t.Errorf("Expected first affected package to be foo, got %s", vuln.Affected[0].GetPackage().GetName())
	}
	if vuln.Affected[1].GetPackage().GetName() != "xz" || vuln.Affected[1].GetPackage().GetEcosystem() != "Alpine:v3.18" {
		t.Errorf("Expected second affected package to be xz (v3.18), got %s (%s)", vuln.Affected[1].GetPackage().GetName(), vuln.Affected[1].GetPackage().GetEcosystem())
	}
	if vuln.Affected[2].GetPackage().GetName() != "xz" || vuln.Affected[2].GetPackage().GetEcosystem() != "Alpine:v3.19" {
		t.Errorf("Expected third affected package to be xz (v3.19), got %s (%s)", vuln.Affected[2].GetPackage().GetName(), vuln.Affected[2].GetPackage().GetEcosystem())
	}

	// Verify versions for xz (v3.19)
	// It should have Introduced: 5.6.0 (from NVDCVE) and Fixed: 5.6.1 (from VersionAndPkg)
	xz319Ranges := vuln.Affected[2].GetRanges()
	if len(xz319Ranges) != 1 {
		t.Fatalf("Expected 1 range for xz (v3.19), got %d", len(xz319Ranges))
	}
	events := xz319Ranges[0].GetEvents()
	if len(events) != 2 {
		t.Fatalf("Expected 2 events for xz (v3.19), got %d", len(events))
	}

	var introduced, fixed string
	for _, e := range events {
		if e.GetIntroduced() != "" {
			introduced = e.GetIntroduced()
		}
		if e.GetFixed() != "" {
			fixed = e.GetFixed()
		}
	}
	if introduced != "5.6.0" {
		t.Errorf("Expected introduced 5.6.0 for xz (v3.19), got %s", introduced)
	}
	if fixed != "5.6.1" {
		t.Errorf("Expected fixed 5.6.1 for xz (v3.19), got %s", fixed)
	}
}
