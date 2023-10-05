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
			description:     "Freedesktop GitLab commit URL observed in CVE-2022-46285",
			inputLink:       "https://gitlab.freedesktop.org/xorg/lib/libxpm/-/commit/a3a7c6dcc3b629d7650148",
			expectedRepoURL: "https://gitlab.freedesktop.org/xorg/lib/libxpm",
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
		{
			description:     "Valid repo previously being discarded",
			inputLink:       "https://gitlab.com/bgermann/unrar-free",
			expectedRepoURL: "https://gitlab.com/bgermann/unrar-free",
			expectedOk:      true,
		},
		{
			description:     "Valid repo previously being discarded",
			inputLink:       "https://gitlab.xiph.org/xiph/ezstream",
			expectedRepoURL: "https://gitlab.xiph.org/xiph/ezstream",
			expectedOk:      true,
		},
		{
			description:     "Valid repo previously being discarded",
			inputLink:       "https://gitlab.freedesktop.org/xdg/xdg-utils",
			expectedRepoURL: "https://gitlab.freedesktop.org/xdg/xdg-utils",
			expectedOk:      true,
		},
		{
			description:     "Valid repo previously being discarded",
			inputLink:       "http://git.linuxtv.org/xawtv3.git",
			expectedRepoURL: "http://git.linuxtv.org/xawtv3.git",
			expectedOk:      true,
		},
		{
			description:     "Valid repo previously being discarded",
			inputLink:       "https://git.savannah.gnu.org/git/emacs.git",
			expectedRepoURL: "https://git.savannah.gnu.org/git/emacs.git",
			expectedOk:      true,
		},
		{
			description:     "Valid repo previously being discarded",
			inputLink:       "https://git.libssh.org/projects/libssh.git",
			expectedRepoURL: "https://git.libssh.org/projects/libssh.git",
			expectedOk:      true,
		},
		{
			description:     "Valid repo previously being discarded",
			inputLink:       "https://pagure.io/libaio.git",
			expectedRepoURL: "https://pagure.io/libaio.git",
			expectedOk:      true,
		},
		{
			description:     "Valid repo previously being discarded",
			inputLink:       "git://git.infradead.org/mtd-utils.git",
			expectedRepoURL: "git://git.infradead.org/mtd-utils.git",
			expectedOk:      true,
		},
		{
			description:     "Valid repo previously being discarded",
			inputLink:       "https://git.savannah.nongnu.org/git/davfs2.git",
			expectedRepoURL: "https://git.savannah.nongnu.org/git/davfs2.git",
			expectedOk:      true,
		},
		{
			description:     "Valid repo previously being discarded",
			inputLink:       "https://git.kernel.org/pub/scm/linux/kernel/git/jaegeuk/f2fs-tools.git",
			expectedRepoURL: "https://git.kernel.org/pub/scm/linux/kernel/git/jaegeuk/f2fs-tools.git",
			expectedOk:      true,
		},
		{
			description:     "Valid repo previously being discarded",
			inputLink:       "https://xenbits.xen.org/git-http/xen.git",
			expectedRepoURL: "https://xenbits.xen.org/git-http/xen.git",
			expectedOk:      true,
		},
		{
			description:     "Valid repo previously being discarded",
			inputLink:       "https://opendev.org/x/sqlalchemy-migrate.git",
			expectedRepoURL: "https://opendev.org/x/sqlalchemy-migrate.git",
			expectedOk:      true,
		},
		{
			description:     "Valid repo previously being discarded",
			inputLink:       "https://git.netfilter.org/libnftnl",
			expectedRepoURL: "https://git.netfilter.org/libnftnl",
			expectedOk:      true,
		},
		{
			description:     "Valid repo previously being discarded",
			inputLink:       "https://gitlab.com/ubports/development/core/click/",
			expectedRepoURL: "https://gitlab.com/ubports/development/core/click",
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
		description            string
		inputLink              string
		inputCommitType        CommitType
		expectedAffectedCommit AffectedCommit
		expectFailure          bool
	}{
		{
			description:     "Valid GitHub commit URL",
			inputLink:       "https://github.com/google/osv/commit/cd4e934d0527e5010e373e7fed54ef5daefba2f5",
			inputCommitType: Fixed,
			expectedAffectedCommit: AffectedCommit{
				Repo:  "https://github.com/google/osv",
				Fixed: "cd4e934d0527e5010e373e7fed54ef5daefba2f5",
			},
		},
		{
			description:     "Undesired GitHub commit URL", // TODO(apollock): be able to parse this a a LastAffected commit
			inputLink:       "https://github.com/Budibase/budibase/commits/develop?after=93d6939466aec192043d8ac842e754f65fdf2e8a+594\u0026branch=develop\u0026qualified_name=refs%2Fheads%2Fdevelop",
			inputCommitType: Fixed,
			expectFailure:   true,
		},
		{
			description:     "Valid GitLab commit URL",
			inputLink:       "https://gitlab.freedesktop.org/virgl/virglrenderer/-/commit/b05bb61f454eeb8a85164c8a31510aeb9d79129c",
			inputCommitType: Fixed,
			expectedAffectedCommit: AffectedCommit{
				Repo:  "https://gitlab.freedesktop.org/virgl/virglrenderer",
				Fixed: "b05bb61f454eeb8a85164c8a31510aeb9d79129c",
			},
		},
		{
			description:     "Valid GitLab.com commit URL",
			inputLink:       "https://gitlab.com/mayan-edms/mayan-edms/commit/9ebe80595afe4fdd1e2c74358d6a9421f4ce130e",
			inputCommitType: Fixed,
			expectedAffectedCommit: AffectedCommit{
				Repo:  "https://gitlab.com/mayan-edms/mayan-edms",
				Fixed: "9ebe80595afe4fdd1e2c74358d6a9421f4ce130e",
			},
		},
		{
			description:     "Valid bitbucket.org commit URL",
			inputLink:       "https://bitbucket.org/openpyxl/openpyxl/commits/3b4905f428e1",
			inputCommitType: Fixed,
			expectedAffectedCommit: AffectedCommit{
				Repo:  "https://bitbucket.org/openpyxl/openpyxl",
				Fixed: "3b4905f428e1",
			},
		},
		{
			description:     "Valid bitbucket.org commit URL with trailing slash",
			inputLink:       "https://bitbucket.org/jespern/django-piston/commits/91bdaec89543/",
			inputCommitType: Fixed,
			expectedAffectedCommit: AffectedCommit{
				Repo:  "https://bitbucket.org/jespern/django-piston",
				Fixed: "91bdaec89543",
			},
		},
		{
			description:     "Valid cGit commit URL",
			inputLink:       "https://git.dpkg.org/cgit/dpkg/dpkg.git/commit/?id=faa4c92debe45412bfcf8a44f26e827800bb24be",
			inputCommitType: Fixed,
			expectedAffectedCommit: AffectedCommit{
				Repo:  "https://git.dpkg.org/cgit/dpkg/dpkg.git",
				Fixed: "faa4c92debe45412bfcf8a44f26e827800bb24be",
			},
		},
		{
			description:     "Valid GitWeb commit URL",
			inputLink:       "https://git.gnupg.org/cgi-bin/gitweb.cgi?p=libksba.git;a=commit;h=f61a5ea4e0f6a80fd4b28ef0174bee77793cf070",
			inputCommitType: Fixed,
			expectedAffectedCommit: AffectedCommit{
				Repo:  "https://git.gnupg.org/libksba.git",
				Fixed: "f61a5ea4e0f6a80fd4b28ef0174bee77793cf070",
			},
		},
		{
			description:            "Unsupported GitHub PR URL",
			inputLink:              "https://github.com/google/osv/pull/123",
			inputCommitType:        Fixed,
			expectedAffectedCommit: AffectedCommit{},
			expectFailure:          true,
		},
		{
			description:            "Unsupported GitHub tag URL",
			inputLink:              "https://github.com/google/osv.dev/releases/tag/v0.0.14",
			inputCommitType:        Fixed,
			expectedAffectedCommit: AffectedCommit{},
			expectFailure:          true,
		},
		{
			description:            "Completely invalid input",
			inputLink:              "",
			inputCommitType:        Fixed,
			expectedAffectedCommit: AffectedCommit{},
			expectFailure:          true,
		},
	}

	for _, tc := range tests {
		got, err := extractGitCommit(tc.inputLink, tc.inputCommitType)
		if err != nil && !tc.expectFailure {
			t.Errorf("test %q: extractGitCommit for %q (%q) errored unexpectedly: %#v", tc.description, tc.inputLink, tc.inputCommitType, err)
		}
		if !reflect.DeepEqual(got, tc.expectedAffectedCommit) {
			t.Errorf("test %q: extractGitCommit for %q was incorrect, got: %#v, expected: %#v", tc.description, tc.inputLink, got, tc.expectedAffectedCommit)
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
				AffectedCommits: []AffectedCommit(nil),
				AffectedVersions: []AffectedVersion{
					{
						Introduced:   "4.16.0",
						Fixed:        "4.16.4",
						LastAffected: "",
					},
					{
						Introduced:   "4.15.0",
						Fixed:        "4.15.9",
						LastAffected: "",
					},
					{
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
				AffectedCommits: []AffectedCommit(nil),
				AffectedVersions: []AffectedVersion{
					{
						Introduced:   "14.6.0",
						Fixed:        "14.6.1",
						LastAffected: "",
					},
					{
						Introduced:   "14.5.0",
						Fixed:        "14.5.3",
						LastAffected: "",
					},
					{
						Introduced:   "",
						Fixed:        "14.4.5",
						LastAffected: "",
					},
				},
			},
			expectedNotes: []string{},
		},
		{
			description:        "A CVE with no explicit versions",
			inputCVEItem:       loadTestData("CVE-2022-1122"),
			inputValidVersions: []string{},
			expectedVersionInfo: VersionInfo{
				AffectedCommits: []AffectedCommit(nil),
				AffectedVersions: []AffectedVersion{
					{
						Introduced:   "",
						Fixed:        "",
						LastAffected: "2.4.0",
					},
				},
			},
			expectedNotes: []string{},
		},
		{
			description:        "A CVE with fix commits in references and CPE match info",
			inputCVEItem:       loadTestData("CVE-2022-25929"),
			inputValidVersions: []string{},
			expectedVersionInfo: VersionInfo{
				AffectedCommits: []AffectedCommit{
					{
						Repo:  "https://github.com/joewalnes/smoothie",
						Fixed: "8e0920d50da82f4b6e605d56f41b69fbb9606a98",
					},
				},
				AffectedVersions: []AffectedVersion{
					{
						Introduced:   "1.31.0",
						Fixed:        "1.36.1",
						LastAffected: "",
					},
				},
			},
			expectedNotes: []string{},
		},
		{
			description:        "A CVE with fix commits in references and (more complex) CPE match info",
			inputCVEItem:       loadTestData("CVE-2022-29194"),
			inputValidVersions: []string{},
			expectedVersionInfo: VersionInfo{
				AffectedCommits: []AffectedCommit{
					{
						Repo:  "https://github.com/tensorflow/tensorflow",
						Fixed: "cff267650c6a1b266e4b4500f69fbc49cdd773c5",
					},
				},
				AffectedVersions: []AffectedVersion{
					{
						Introduced:   "2.7.0",
						Fixed:        "2.7.2",
						LastAffected: "",
					},
					{
						Introduced:   "",
						Fixed:        "2.6.4",
						LastAffected: "",
					},
					{
						Introduced:   "2.8.0",
						Fixed:        "2.8.1",
						LastAffected: "",
					},
				},
			},
			expectedNotes: []string{},
		},
		{
			description:        "A CVE with undesired wildcards and no versions",
			inputCVEItem:       loadTestData("CVE-2022-2956"),
			inputValidVersions: []string{},
			expectedVersionInfo: VersionInfo{
				AffectedCommits:  []AffectedCommit(nil),
				AffectedVersions: []AffectedVersion(nil),
			},
			expectedNotes: []string{},
		},
		{
			description:        "A CVE with a weird GitLab reference that breaks version enumeration in the worker",
			inputCVEItem:       loadTestData("CVE-2022-46285"),
			inputValidVersions: []string{},
			expectedVersionInfo: VersionInfo{
				AffectedCommits:  []AffectedCommit{{Repo: "https://gitlab.freedesktop.org/xorg/lib/libxpm", Fixed: "a3a7c6dcc3b629d7650148"}},
				AffectedVersions: []AffectedVersion{{Fixed: "3.5.15"}},
			},
			expectedNotes: []string{},
		},
	}

	for _, tc := range tests {
		gotVersionInfo, _ := ExtractVersionInfo(tc.inputCVEItem, tc.inputValidVersions)
		if diff := cmp.Diff(tc.expectedVersionInfo, gotVersionInfo); diff != "" {
			t.Errorf("test %q: VersionInfo for %#v was incorrect: %s", tc.description, tc.inputCVEItem, diff)
		}
	}
}

func TestCPEs(t *testing.T) {
	tests := []struct {
		description  string
		inputCVEItem CVEItem
		expectedCPEs []string
	}{
		{
			description:  "A CVE with child CPEs",
			inputCVEItem: loadTestData("CVE-2023-24256"),
			expectedCPEs: []string{"cpe:2.3:o:nio:aspen:*:*:*:*:*:*:*:*", "cpe:2.3:h:nio:ec6:-:*:*:*:*:*:*:*"},
		},
		{
			description:  "A CVE without child CPEs",
			inputCVEItem: loadTestData("CVE-2022-33745"),
			expectedCPEs: []string{"cpe:2.3:o:xen:xen:*:*:*:*:*:*:x86:*", "cpe:2.3:o:fedoraproject:fedora:36:*:*:*:*:*:*:*"},
		},
	}

	for _, tc := range tests {
		gotCPEs := CPEs(tc.inputCVEItem)
		if diff := cmp.Diff(gotCPEs, tc.expectedCPEs); diff != "" {
			t.Errorf("test %q: CPEs for %#v were incorrect: %s", tc.description, tc.inputCVEItem.Configurations, diff)
		}
	}
}
