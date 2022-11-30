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

func TestRepo(t *testing.T) {
	tests := []struct {
		description     string // human-readable description of test case
		inputLink       string // a possible repository URL to call Repo() with
		expectedRepoURL string // The expected  repository URL to get back from Repo()
		expectedOk      bool   // If an error is expected
	}{
		{
			description:     "GitHub compare URL",
			inputLink:       "https://github.com/kovidgoyal/kitty/compare/v0.26.1...v0.26.2",
			expectedRepoURL: "https://github.com/kovidgoyal/kitty",
			expectedOk:      true,
		},
		{
			description:     "GitLab compare URL",
			inputLink:       "https://gitlab.com/mayan-edms/mayan-edms/-/compare/development...master?from_project_id=396557&straight=false",
			expectedRepoURL: "https://gitlab.com/mayan-edms/mayan-edms",
			expectedOk:      true,
		},
		{
			description:     "GitHub releases URL",
			inputLink:       "https://github.com/apache/activemq-artemis/releases",
			expectedRepoURL: "https://github.com/apache/activemq-artemis",
			expectedOk:      true,
		},
		{
			description:     "GitHub releases URL",
			inputLink:       "https://github.com/apache/activemq-artemis/tags",
			expectedRepoURL: "https://github.com/apache/activemq-artemis",
			expectedOk:      true,
		},
		{
			description:     "Ambiguous GitLab compare URL",
			inputLink:       "https://git.drupalcode.org/project/views/-/compare/7.x-3.21...7.x-3.x",
			expectedRepoURL: "https://git.drupalcode.org/project/views",
			expectedOk:      true,
		},
		{
			description:     "Exact repository URL",
			inputLink:       "https://github.com/apache/activemq-artemis",
			expectedRepoURL: "https://github.com/apache/activemq-artemis",
			expectedOk:      true,
		},
		{
			description:     "Freedesktop cGit mirror",
			inputLink:       "https://cgit.freedesktop.org/xorg/lib/libXRes/commit/?id=c05c6d918b0e2011d4bfa370c321482e34630b17",
			expectedRepoURL: "https://gitlab.freedesktop.org/xorg/lib/libXRes",
			expectedOk:      true,
		},
		{
			description:     "Exact Freedesktop cGit mirror",
			inputLink:       "https://cgit.freedesktop.org/xorg/lib/libXRes",
			expectedRepoURL: "https://gitlab.freedesktop.org/xorg/lib/libXRes",
			expectedOk:      true,
		},
		{
			description:     "Freedesktop cGit mirror refs/tags URL",
			inputLink:       "http://cgit.freedesktop.org/spice/spice/refs/tags",
			expectedRepoURL: "https://gitlab.freedesktop.org/spice/spice",
			expectedOk:      true,
		},
		{
			description:     "Exact repo URL with a trailing slash",
			inputLink:       "https://github.com/pyca/pyopenssl/",
			expectedRepoURL: "https://github.com/pyca/pyopenssl",
			expectedOk:      true,
		},
	}

	for _, tc := range tests {
		got, err := Repo(tc.inputLink)
		if err != nil && tc.expectedOk {
			t.Errorf("test %q: Repo(%q) unexpectedly failed: %+v", tc.description, tc.inputLink, err)
		}
		if !reflect.DeepEqual(got, tc.expectedRepoURL) {
			t.Errorf("test %q: Repo(%q) was incorrect, got: %#v, expected: %#v", tc.description, tc.inputLink, got, tc.expectedRepoURL)
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
