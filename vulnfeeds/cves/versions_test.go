package cves

import (
	"reflect"
	"testing"
)

func TestParseCPE(t *testing.T) {
	tests := []struct {
		description       string
		inputCPEString    string
		expectedCPEStruct *CPE
		expectedOk        bool
	}{
		{
			description: "invalid input (empty string)", inputCPEString: "", expectedCPEStruct: nil, expectedOk: true,
		},

		{
			description: "invalid input (corrupt)", inputCPEString: "fnord:2.3:h:intel:core_i3-1005g1:-:*:*:*:*:*:*:*", expectedCPEStruct: nil, expectedOk: true,
		},
		{
			description: "invalid input (truncated)", inputCPEString: "cpe:2.3:h:intel:core_i3-1005g1:", expectedCPEStruct: nil, expectedOk: true,
		},
		{
			description: "valid input (hardware)", inputCPEString: "cpe:2.3:h:intel:core_i3-1005g1:-:*:*:*:*:*:*:*", expectedCPEStruct: &CPE{
				CPEVersion: "2.3", Part: "h", Vendor: "intel", Product: "core_i3-1005g1", Version: "-", Update: "*", Edition: "*", Language: "*", SWEdition: "*", TargetSW: "*", TargetHW: "*", Other: "*"}, expectedOk: false,
		},
		{
			description: "valid input (software)", inputCPEString: "cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:*", expectedCPEStruct: &CPE{CPEVersion: "2.3", Part: "a", Vendor: "gitlab", Product: "gitlab", Version: "*", Update: "*", Edition: "*", Language: "*", SWEdition: "community", TargetSW: "*", TargetHW: "*", Other: "*"}, expectedOk: false,
		},
	}

	for _, tc := range tests {
		got, ok := ParseCPE(tc.inputCPEString)
		if !ok && !tc.expectedOk {
			t.Errorf("test %q: ParseCPE for %q unexpectedly failed", tc.description, tc.inputCPEString)
		}
		if !reflect.DeepEqual(got, tc.expectedCPEStruct) {
			t.Errorf("test %q: ParseCPE for %q was incorrect, got: %#v, expected: %#v", tc.description, tc.inputCPEString, got, tc.expectedCPEStruct)
		}
	}
}

func TestExtractGitCommit(t *testing.T) {
	tests := []struct {
		description       string
		inputLink         string
		expectedFixCommit *FixCommit
	}{
		{
			description: "Valid GitHub commit URL",
			inputLink:   "https://github.com/google/osv/commit/cd4e934d0527e5010e373e7fed54ef5daefba2f5",
			expectedFixCommit: &FixCommit{
				Repo:   "https://github.com/google/osv",
				Commit: "cd4e934d0527e5010e373e7fed54ef5daefba2f5",
			},
		},
		{
			description:       "Unsupported GitHub PR URL",
			inputLink:         "https://github.com/google/osv/pull/123",
			expectedFixCommit: nil,
		},
		{
			description:       "Unsupported GitHub tag URL",
			inputLink:         "https://github.com/google/osv.dev/releases/tag/v0.0.14",
			expectedFixCommit: nil,
		},
		{
			description:       "Unsupported Gitlab URL",
			inputLink:         "https://gitlab.freedesktop.org/virgl/virglrenderer/-/commit/b05bb61f454eeb8a85164c8a31510aeb9d79129c",
			expectedFixCommit: nil,
		},
		{
			description:       "Completely invalid input",
			inputLink:         "",
			expectedFixCommit: nil,
		},
	}

	for _, tc := range tests {
		got := extractGitCommit(tc.inputLink)
		if !reflect.DeepEqual(got, tc.expectedFixCommit) {
			t.Errorf("test %q: extractGitCommit for %q was incorrect, got: %#v, expected: %#v", tc.description, tc.inputLink, got, tc.expectedFixCommit)
		}
	}
}
