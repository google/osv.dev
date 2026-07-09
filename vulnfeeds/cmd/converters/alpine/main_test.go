package main

import (
	"testing"

	"github.com/google/osv/vulnfeeds/models"
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
		name      string
		cve       models.NVDCVE
		alpinePkg string
		want      string
	}{
		{
			name:      "no configurations",
			cve:       models.NVDCVE{},
			alpinePkg: "xz",
			want:      "0",
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
			alpinePkg: "xz",
			want:      "5.6.0",
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
			alpinePkg: "xz",
			want:      "0",
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
			alpinePkg: "xz",
			want:      "0",
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
			alpinePkg: "xz",
			want:      "0",
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
			alpinePkg: "xz",
			want:      "0",
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
			alpinePkg: "foo",
			want:      "1.0.0",
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
			alpinePkg: "py3-pillow",
			want:      "9.0.0",
		},
		{
			name: "first match wins when multiple CPEs match",
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
			alpinePkg: "xz",
			want:      "5.0.0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := findIntroducedVersion(tc.cve, tc.alpinePkg)
			if got != tc.want {
				t.Errorf("findIntroducedVersion(..., %q) = %q, want %q", tc.alpinePkg, got, tc.want)
			}
		})
	}
}
