package cves

import (
	"encoding/json"
	"log"
	"os"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// Helper function to load in a specific CVE from sample data.
func loadTestData(CVEID string) CVEItem {
	file, err := os.Open("../test_data/nvdcve-1.1-test-data.json")
	if err != nil {
		log.Fatalf("Failed to load test data")
	}
	var nvdCves NVDCVE
	json.NewDecoder(file).Decode(&nvdCves)
	for _, item := range nvdCves.CVEItems {
		if item.CVE.CVEDataMeta.ID == CVEID {
			return item
		}
	}
	log.Fatalf("test data doesn't contain specified %q", CVEID)
	return CVEItem{}
}

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
			description:     "GitHub advisory URL",
			inputLink:       "https://github.com/ballcat-projects/ballcat-codegen/security/advisories/GHSA-fv3m-xhqw-9m79",
			expectedRepoURL: "https://github.com/ballcat-projects/ballcat-codegen",
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
			description: "cGit cgi-bin URL",
			inputLink:   "https://git.gnupg.org/cgi-bin/gitweb.cgi?p=libksba.git;a=commit;h=f61a5ea4e0f6a80fd4b28ef0174bee77793cf070",
			// Note to future selves: this isn't valid for this
			// host, but we have no way of knowing this via purely
			// URL mangling, so are probably going to need a
			// mapping table for known odd cases
			expectedRepoURL: "https://git.gnupg.org/libksba.git",
			expectedOk:      true,
		},
		{
			description:     "Exact repo URL with a trailing slash",
			inputLink:       "https://github.com/pyca/pyopenssl/",
			expectedRepoURL: "https://github.com/pyca/pyopenssl",
			expectedOk:      true,
		},
		{
			description:     "Bitbucket download URL",
			inputLink:       "https://bitbucket.org/snakeyaml/snakeyaml/downloads/?tab=tags",
			expectedRepoURL: "https://bitbucket.org/snakeyaml/snakeyaml",
			expectedOk:      true,
		},
		{
			description:     "Bitbucket wiki URL",
			inputLink:       "https://bitbucket.org/snakeyaml/snakeyaml/wiki/Home",
			expectedRepoURL: "https://bitbucket.org/snakeyaml/snakeyaml",
			expectedOk:      true,
		},
		{
			description:     "Bitbucket security URL",
			inputLink:       "https://bitbucket.org/snakeyaml/snakeyaml/security",
			expectedRepoURL: "https://bitbucket.org/snakeyaml/snakeyaml",
			expectedOk:      true,
		},
		{
			description:     "Bitbucket pull-request URL",
			inputLink:       "https://bitbucket.org/snakeyaml/snakeyaml/pull-requests/35",
			expectedRepoURL: "https://bitbucket.org/snakeyaml/snakeyaml",
			expectedOk:      true,
		},
		{
			description:     "Bitbucket commit URL",
			inputLink:       "https://bitbucket.org/snakeyaml/snakeyaml/commits/6e8cd890716dfe22d5ba56f9a592225fb7fa2803",
			expectedRepoURL: "https://bitbucket.org/snakeyaml/snakeyaml",
			expectedOk:      true,
		},
		{
			description:     "Bitbucket issue URL with title",
			inputLink:       "https://bitbucket.org/snakeyaml/snakeyaml/issues/566/build-android",
			expectedRepoURL: "https://bitbucket.org/snakeyaml/snakeyaml",
			expectedOk:      true,
		},
		{
			description:     "Bitbucket bare issue URL",
			inputLink:       "https://bitbucket.org/snakeyaml/snakeyaml/issues/566",
			expectedRepoURL: "https://bitbucket.org/snakeyaml/snakeyaml",
			expectedOk:      true,
		},
		{
			description:     "Valid URL but not wanted (by denylist)",
			inputLink:       "https://github.com/orangecertcc/security-research/security/advisories/GHSA-px2c-q384-5wxc",
			expectedRepoURL: "",
			expectedOk:      false,
		},
		{
			description:     "Valid URL but not wanted (by deny regexp)",
			inputLink:       "https://github.com/Ko-kn3t/CVE-2020-29156",
			expectedRepoURL: "",
			expectedOk:      false,
		},
		{
			description:     "Valid URL but not wanted (by deny regexp)",
			inputLink:       "https://github.com/GitHubAssessments/CVE_Assessment_04_2018",
			expectedRepoURL: "",
			expectedOk:      false,
		},
		{
			description:     "Valid URL but not wanted (by deny regexp)",
			inputLink:       "https://github.com/jenaye/cve",
			expectedRepoURL: "",
			expectedOk:      false,
		},
		{
			description:     "Valid URL (unnormalized) but not wanted (by deny regexp)",
			inputLink:       "https://github.com/vlakhani28/CVE-2022-22296/blob/main/README.md",
			expectedRepoURL: "",
			expectedOk:      false,
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
		expectedGitCommit *GitCommit
	}{
		{
			description: "Valid GitHub commit URL",
			inputLink:   "https://github.com/google/osv/commit/cd4e934d0527e5010e373e7fed54ef5daefba2f5",
			expectedGitCommit: &GitCommit{
				Repo:   "https://github.com/google/osv",
				Commit: "cd4e934d0527e5010e373e7fed54ef5daefba2f5",
			},
		},
		{
			description: "Valid GitLab commit URL",
			inputLink:   "https://gitlab.freedesktop.org/virgl/virglrenderer/-/commit/b05bb61f454eeb8a85164c8a31510aeb9d79129c",
			expectedGitCommit: &GitCommit{
				Repo:   "https://gitlab.freedesktop.org/virgl/virglrenderer",
				Commit: "b05bb61f454eeb8a85164c8a31510aeb9d79129c",
			},
		},
		{
			description: "Valid GitLab.com commit URL",
			inputLink:   "https://gitlab.com/mayan-edms/mayan-edms/commit/9ebe80595afe4fdd1e2c74358d6a9421f4ce130e",
			expectedGitCommit: &GitCommit{
				Repo:   "https://gitlab.com/mayan-edms/mayan-edms",
				Commit: "9ebe80595afe4fdd1e2c74358d6a9421f4ce130e",
			},
		},
		{
			description: "Valid bitbucket.org commit URL",
			inputLink:   "https://bitbucket.org/openpyxl/openpyxl/commits/3b4905f428e1",
			expectedGitCommit: &GitCommit{
				Repo:   "https://bitbucket.org/openpyxl/openpyxl",
				Commit: "3b4905f428e1",
			},
		},
		{
			description: "Valid bitbucket.org commit URL with trailing slash",
			inputLink:   "https://bitbucket.org/jespern/django-piston/commits/91bdaec89543/",
			expectedGitCommit: &GitCommit{
				Repo:   "https://bitbucket.org/jespern/django-piston",
				Commit: "91bdaec89543",
			},
		},
		{
			description: "Valid cGit commit URL",
			inputLink:   "https://git.dpkg.org/cgit/dpkg/dpkg.git/commit/?id=faa4c92debe45412bfcf8a44f26e827800bb24be",
			expectedGitCommit: &GitCommit{
				Repo:   "https://git.dpkg.org/cgit/dpkg/dpkg.git",
				Commit: "faa4c92debe45412bfcf8a44f26e827800bb24be",
			},
		},
		{
			description: "Valid GitWeb commit URL",
			inputLink:   "https://git.gnupg.org/cgi-bin/gitweb.cgi?p=libksba.git;a=commit;h=f61a5ea4e0f6a80fd4b28ef0174bee77793cf070",
			expectedGitCommit: &GitCommit{
				Repo:   "https://git.gnupg.org/libksba.git",
				Commit: "f61a5ea4e0f6a80fd4b28ef0174bee77793cf070",
			},
		},
		{
			description:       "Unsupported GitHub PR URL",
			inputLink:         "https://github.com/google/osv/pull/123",
			expectedGitCommit: nil,
		},
		{
			description:       "Unsupported GitHub tag URL",
			inputLink:         "https://github.com/google/osv.dev/releases/tag/v0.0.14",
			expectedGitCommit: nil,
		},
		{
			description:       "Completely invalid input",
			inputLink:         "",
			expectedGitCommit: nil,
		},
	}

	for _, tc := range tests {
		got := extractGitCommit(tc.inputLink)
		if !reflect.DeepEqual(got, tc.expectedGitCommit) {
			t.Errorf("test %q: extractGitCommit for %q was incorrect, got: %#v, expected: %#v", tc.description, tc.inputLink, got, tc.expectedGitCommit)
		}
	}
}

func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		description               string
		inputVersion              string
		expectedNormalizedVersion string
		expectedOk                bool
	}{
		{
			description:               "Empty string",
			inputVersion:              "",
			expectedNormalizedVersion: "",
			expectedOk:                false,
		},
		{
			description:               "Garbage version",
			inputVersion:              "hjlk;gfdhjkgf",
			expectedNormalizedVersion: "",
			expectedOk:                false,
		},
		{
			description:               "Valid supported version #1",
			inputVersion:              "1.0",
			expectedNormalizedVersion: "1-0",
			expectedOk:                true,
		},
		{
			description:               "Valid supported version #2",
			inputVersion:              "22.3rc1",
			expectedNormalizedVersion: "22-3-rc1",
			expectedOk:                true,
		},
		{
			description:               "Valid supported version #3",
			inputVersion:              "1.2.3.4.5-rc1",
			expectedNormalizedVersion: "1-2-3-4-5-rc1",
			expectedOk:                true,
		},
		{
			description:               "Valid supported version #4",
			inputVersion:              ".1",
			expectedNormalizedVersion: "1",
			expectedOk:                true,
		},
		{
			description:               "Valid supported version #5",
			inputVersion:              "0.1.11.1",
			expectedNormalizedVersion: "0-1-11-1",
			expectedOk:                true,
		},
		{
			description:               "Valid supported version #6",
			inputVersion:              "project-123-1",
			expectedNormalizedVersion: "123-1",
			expectedOk:                true,
		},
		{
			description:               "Valid supported version #7",
			inputVersion:              "project-123-1RC",
			expectedNormalizedVersion: "123-1-RC",
			expectedOk:                true,
		},
		{
			description:               "Valid supported version #8",
			inputVersion:              "project-123-1RC5",
			expectedNormalizedVersion: "123-1-RC5",
			expectedOk:                true,
		},
		{
			description:               "Valid supported version #9",
			inputVersion:              "arc-20200101",
			expectedNormalizedVersion: "20200101",
			expectedOk:                true,
		},
		{
			description:               "Valid supported version #10",
			inputVersion:              "php-8.0.0beta",
			expectedNormalizedVersion: "8-0-0-beta",
			expectedOk:                true,
		},
		{
			description:               "Valid supported version #11",
			inputVersion:              "php-8.0.0beta",
			expectedNormalizedVersion: "8-0-0-beta",
			expectedOk:                true,
		},
		{
			description:               "Valid supported version #12",
			inputVersion:              "v6.0.0-alpha1",
			expectedNormalizedVersion: "6-0-0-alpha1",
			expectedOk:                true,
		},
		{
			description:               "Valid supported version #13",
			inputVersion:              "android-10.0.0_r10",
			expectedNormalizedVersion: "10-0-0-10",
			expectedOk:                true,
		},
	}
	for _, tc := range tests {
		got, err := NormalizeVersion(tc.inputVersion)
		if err != nil && tc.expectedOk {
			t.Errorf("test %q: Normalize(%q) unexpectedly errored: %#v", tc.description, tc.inputVersion, err)
		}
		if !reflect.DeepEqual(got, tc.expectedNormalizedVersion) {
			t.Errorf("test %q: normalized version for %q was incorrect, got: %q, expected %q", tc.description, tc.inputVersion, got, tc.expectedNormalizedVersion)
		}
	}
}

func TestExtractVersionInfo(t *testing.T) {
	tests := []struct {
		description         string
		inputCVEItem        CVEItem
		inputValidVersions  []string
		expectedVersionInfo VersionInfo
		expectedNotes       []string
	}{
		{
			description:        "A CVE with multiple affected versions",
			inputCVEItem:       loadTestData("CVE-2022-32746"),
			inputValidVersions: []string{},
			expectedVersionInfo: VersionInfo{
				FixCommits:          []GitCommit(nil),
				LimitCommits:        []GitCommit(nil),
				LastAffectedCommits: []GitCommit(nil),
				AffectedVersions: []AffectedVersion{
					AffectedVersion{
						Introduced:   "4.16.0",
						Fixed:        "4.16.4",
						LastAffected: "",
					},
					AffectedVersion{
						Introduced:   "4.15.0",
						Fixed:        "4.15.9",
						LastAffected: "",
					},
					AffectedVersion{
						Introduced:   "4.3.0",
						Fixed:        "4.14.14",
						LastAffected: "",
					},
				},
			},
			expectedNotes: []string{},
		},
		{
			description:        "A CVE with duplicate affected versions squashed",
			inputCVEItem:       loadTestData("CVE-2022-0090"),
			inputValidVersions: []string{},
			expectedVersionInfo: VersionInfo{
				FixCommits:          []GitCommit(nil),
				LimitCommits:        []GitCommit(nil),
				LastAffectedCommits: []GitCommit(nil),
				AffectedVersions: []AffectedVersion{
					AffectedVersion{
						Introduced:   "14.6.0",
						Fixed:        "14.6.1",
						LastAffected: "",
					},
					AffectedVersion{
						Introduced:   "14.5.0",
						Fixed:        "14.5.3",
						LastAffected: "",
					},
					AffectedVersion{
						Introduced:   "",
						Fixed:        "14.4.5",
						LastAffected: "",
					},
				},
			},
			expectedNotes: []string{},
		},
	}

	for _, tc := range tests {
		gotVersionInfo, _ := ExtractVersionInfo(tc.inputCVEItem, tc.inputValidVersions)
		if diff := cmp.Diff(gotVersionInfo, tc.expectedVersionInfo); diff != "" {
			t.Errorf("test %q: VersionInfo for %#v was incorrect: %s", tc.description, tc.inputCVEItem, diff)
		}
	}
}
