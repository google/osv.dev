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
			description:       "invalid input (empty string)",
			inputCPEString:    "",
			expectedCPEStruct: nil,
			expectedOk:        false,
		},

		{
			description:       "invalid input (corrupt)",
			inputCPEString:    "fnord:2.3:h:intel:core_i3-1005g1:-:*:*:*:*:*:*:*",
			expectedCPEStruct: nil,
			expectedOk:        false,
		},
		{
			description:       "invalid input (truncated)",
			inputCPEString:    "cpe:2.3:h:intel:core_i3-1005g1:",
			expectedCPEStruct: nil,
			expectedOk:        false,
		},
		{
			description: "valid input (hardware)", inputCPEString: "cpe:2.3:h:intel:core_i3-1005g1:-:*:*:*:*:*:*:*",
			expectedCPEStruct: &CPE{
				CPEVersion: "2.3",
				Part:       "h",
				Vendor:     "intel",
				Product:    "core_i3-1005g1",
				Version:    "NA",
				Update:     "ANY",
				Edition:    "ANY",
				Language:   "ANY",
				SWEdition:  "ANY",
				TargetSW:   "ANY",
				TargetHW:   "ANY",
				Other:      "ANY",
			},
			expectedOk: true,
		},
		{
			description:    "valid input (software)",
			inputCPEString: "cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:*",
			expectedCPEStruct: &CPE{
				CPEVersion: "2.3",
				Part:       "a",
				Vendor:     "gitlab",
				Product:    "gitlab",
				Version:    "ANY",
				Update:     "ANY",
				Edition:    "ANY",
				Language:   "ANY",
				SWEdition:  "community",
				TargetSW:   "ANY",
				TargetHW:   "ANY",
				Other:      "ANY",
			},
			expectedOk: true,
		},
		{
			description:    "valid input (software) with embedded colons",
			inputCPEString: "cpe:2.3:a:http\\:\\:daemon_project:http\\:\\:daemon:*:*:*:*:*:*:*:*",
			expectedCPEStruct: &CPE{
				CPEVersion: "2.3",
				Part:       "a",
				Vendor:     "http::daemon_project",
				Product:    "http::daemon",
				Version:    "ANY",
				Update:     "ANY",
				Edition:    "ANY",
				Language:   "ANY",
				SWEdition:  "ANY",
				TargetSW:   "ANY",
				TargetHW:   "ANY",
				Other:      "ANY",
			},
			expectedOk: true,
		},
		{
			description:    "valid input (software) with escaped characters",
			inputCPEString: "cpe:2.3:a:bloodshed:dev-c\\+\\+:4.9.9.2:*:*:*:*:*:*:*",
			expectedCPEStruct: &CPE{
				CPEVersion: "2.3",
				Part:       "a",
				Vendor:     "bloodshed",
				Product:    "dev-c++",
				Version:    "4.9.9.2",
				Update:     "ANY",
				Edition:    "ANY",
				Language:   "ANY",
				SWEdition:  "ANY",
				TargetSW:   "ANY",
				TargetHW:   "ANY",
				Other:      "ANY",
			},
			expectedOk: true,
		},
	}

	for _, tc := range tests {
		got, err := ParseCPE(tc.inputCPEString)
		if err != nil && tc.expectedOk {
			t.Errorf("test %q: ParseCPE for %q unexpectedly failed: %+v", tc.description, tc.inputCPEString, err)
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
			description: "Valid GitLab commit URL",
			inputLink:   "https://gitlab.freedesktop.org/virgl/virglrenderer/-/commit/b05bb61f454eeb8a85164c8a31510aeb9d79129c",
			expectedFixCommit: &FixCommit{
				Repo:   "https://gitlab.freedesktop.org/virgl/virglrenderer",
				Commit: "b05bb61f454eeb8a85164c8a31510aeb9d79129c",
			},
		},
		{
			description: "Valid GitLab.com commit URL",
			inputLink:   "https://gitlab.com/mayan-edms/mayan-edms/commit/9ebe80595afe4fdd1e2c74358d6a9421f4ce130e",
			expectedFixCommit: &FixCommit{
				Repo:   "https://gitlab.com/mayan-edms/mayan-edms",
				Commit: "9ebe80595afe4fdd1e2c74358d6a9421f4ce130e",
			},
		},
		{
			description: "Valid bitbucket.org commit URL",
			inputLink:   "https://bitbucket.org/openpyxl/openpyxl/commits/3b4905f428e1",
			expectedFixCommit: &FixCommit{
				Repo:   "https://bitbucket.org/openpyxl/openpyxl",
				Commit: "3b4905f428e1",
			},
		},
		{
			description: "Valid bitbucket.org commit URL with trailing slash",
			inputLink:   "https://bitbucket.org/jespern/django-piston/commits/91bdaec89543/",
			expectedFixCommit: &FixCommit{
				Repo:   "https://bitbucket.org/jespern/django-piston",
				Commit: "91bdaec89543",
			},
		},
		{
			description: "Valid cGit commit URL",
			inputLink:   "https://git.dpkg.org/cgit/dpkg/dpkg.git/commit/?id=faa4c92debe45412bfcf8a44f26e827800bb24be",
			expectedFixCommit: &FixCommit{
				Repo:   "https://git.dpkg.org/cgit/dpkg/dpkg.git",
				Commit: "faa4c92debe45412bfcf8a44f26e827800bb24be",
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
