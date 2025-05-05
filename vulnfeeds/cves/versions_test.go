package cves

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func loadTestData2(cveName string) Vulnerability {
	fileName := fmt.Sprintf("../test_data/nvdcve-2.0/%s.json", cveName)
	file, err := os.Open(fileName)
	if err != nil {
		log.Fatalf("Failed to load test data from %q", fileName)
	}
	var nvdCves CVEAPIJSON20Schema
	err = json.NewDecoder(file).Decode(&nvdCves)
	if err != nil {
		log.Fatalf("Failed to decode %q: %+v", fileName, err)
	}
	for _, vulnerability := range nvdCves.Vulnerabilities {
		if string(vulnerability.CVE.ID) == cveName {
			return vulnerability
		}
	}
	log.Fatalf("test data doesn't contain %q", cveName)
	return Vulnerability{}
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
		t.Run(tc.description, func(t *testing.T) {
			t.Parallel()
			got, err := ParseCPE(tc.inputCPEString)
			if err != nil && tc.expectedOk {
				t.Errorf("test %q: ParseCPE for %q unexpectedly failed: %+v", tc.description, tc.inputCPEString, err)
			}
			if !reflect.DeepEqual(got, tc.expectedCPEStruct) {
				t.Errorf("test %q: ParseCPE for %q was incorrect, got: %#v, expected: %#v", tc.description, tc.inputCPEString, got, tc.expectedCPEStruct)
			}
		})
	}
}

func TestRepo(t *testing.T) {
	tests := []struct {
		description       string    // human-readable description of test case
		inputLink         string    // a possible repository URL to call Repo() with
		expectedRepoURL   string    // The expected  repository URL to get back from Repo()
		expectedOk        bool      // If an error is expected
		disableExpiryDate time.Time // If test needs to be disabled due to known outage.
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
			description:     "GitWeb URL, remapped to something cloneable (CVE-2022-47629)",
			inputLink:       "https://git.gnupg.org/cgi-bin/gitweb.cgi?p=libksba.git;a=commit;h=f61a5ea4e0f6a80fd4b28ef0174bee77793cf070",
			expectedRepoURL: "git://git.gnupg.org/libksba.git",
			expectedOk:      true,
		},
		{
			description:     "GitWeb URL, remapped to something cloneable (CVE-2023-1579)",
			inputLink:       "https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;h=11d171f1910b508a81d21faa087ad1af573407d8",
			expectedRepoURL: "https://sourceware.org/git/binutils-gdb.git",
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
		{
			description:     "cGit URL on git.kernel.org remapped to be cloneable",
			inputLink:       "https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=ee1fee900537b5d9560e9f937402de5ddc8412f3",
			expectedRepoURL: "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
			expectedOk:      true,
		},
		{
			description:       "Valid Gitweb repo",
			inputLink:         "https://git.ffmpeg.org/gitweb/ffmpeg.git/commitdiff/c94875471e3ba3dc396c6919ff3ec9b14539cd71",
			expectedRepoURL:   "https://git.ffmpeg.org/ffmpeg.git",
			expectedOk:        true,
			disableExpiryDate: time.Date(2025, 3, 31, 12, 30, 0, 0, time.Local),
		},
		{
			description:     "Undesired researcher repo (by deny regex)",
			inputLink:       "https://github.com/bigzooooz/CVE-2023-26692#readme",
			expectedRepoURL: "",
			expectedOk:      false,
		},
		{
			description:     "GNU glibc GitWeb repo (with no distinguishing marks)",
			inputLink:       "https://sourceware.org/git/?p=glibc.git",
			expectedRepoURL: "https://sourceware.org/git/glibc.git",
			expectedOk:      true,
		},
		{
			description:     "GNU glibc GitWeb repo (with distinguishing marks)",
			inputLink:       "https://sourceware.org/git/gitweb.cgi?p=glibc.git",
			expectedRepoURL: "https://sourceware.org/git/glibc.git",
			expectedOk:      true,
		},
		{
			description:     "GnuPG GitWeb repo that doesn't talk https",
			inputLink:       "https://git.gnupg.org/cgi-bin/gitweb.cgi?p=libksba.git;a=commit;h=f61a5ea4e0f6a80fd4b28ef0174bee77793cf070",
			expectedRepoURL: "git://git.gnupg.org/libksba.git",
			expectedOk:      true,
		},
		{
			description:     "high profile repo encountered on CVE-2024-3094",
			inputLink:       "https://git.tukaani.org/?p=xz.git;a=tags",
			expectedRepoURL: "https://git.tukaani.org/xz.git",
			expectedOk:      true,
		},
		{
			description:     "PostgreSQL repo",
			inputLink:       "https://git.postgresql.org/gitweb/?p=postgresql.git;a=summary",
			expectedRepoURL: "https://git.postgresql.org/git/postgresql.git",
			expectedOk:      true,
		},
		{
			description:     "libcap repo on kernel.org (with a trailing slash)",
			inputLink:       "https://git.kernel.org/pub/scm/libs/libcap/libcap.git/",
			expectedRepoURL: "https://git.kernel.org/pub/scm/libs/libcap/libcap.git",
			expectedOk:      true,
		},
		{
			description:     "Linux kernel URL that doesn't require remapping to be cloneable",
			inputLink:       "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ee1fee900537b5d9560e9f937402de5ddc8412f3",
			expectedRepoURL: "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
			expectedOk:      true,
		},
		{
			description:     "musl-libc repo that requires remapping",
			inputLink:       "https://git.musl-libc.org/cgit/musl/commit/?id=c47ad25ea3b484e10326f933e927c0bc8cded3da",
			expectedRepoURL: "https://git.musl-libc.org/git/musl",
			expectedOk:      true,
		},
		{
			description:     "Savannah repo that requires remapping",
			inputLink:       "https://git.savannah.gnu.org/cgit/wget.git/commit/?id=c419542d956a2607bbce5df64b9d378a8588d778",
			expectedRepoURL: "https://git.savannah.gnu.org/git/wget.git",
			expectedOk:      true,
		},
	}

	for _, tc := range tests {

		t.Run(tc.description, func(t *testing.T) {
			t.Parallel()
			if time.Now().Before(tc.disableExpiryDate) {
				t.Skipf("test %q: Repo(%q) has been skipped due to known outage and will be reenabled on %s.", tc.description, tc.inputLink, tc.disableExpiryDate)
			}
			if !tc.disableExpiryDate.IsZero() && time.Now().After(tc.disableExpiryDate) {
				t.Logf("test %q: Repo(%q) has been enabled on %s.", tc.description, tc.inputLink, tc.disableExpiryDate)
			}
			got, err := Repo(tc.inputLink)
			if err != nil && tc.expectedOk {
				t.Errorf("test %q: Repo(%q) unexpectedly failed: %+v", tc.description, tc.inputLink, err)
			}
			if !reflect.DeepEqual(got, tc.expectedRepoURL) {
				t.Errorf("test %q: Repo(%q) was incorrect, got: %#v, expected: %#v", tc.description, tc.inputLink, got, tc.expectedRepoURL)
			}
		})
	}
}

func TestExtractGitCommit(t *testing.T) {
	tests := []struct {
		description            string
		inputLink              string
		inputCommitType        CommitType
		expectedAffectedCommit AffectedCommit
		expectFailure          bool
		skipOnCloudBuild       bool
		disableExpiryDate      time.Time // If test needs to be disabled due to known outage.
	}{
		{
			description:     "Valid GitHub commit URL",
			inputLink:       "https://github.com/google/osv/commit/cd4e934d0527e5010e373e7fed54ef5daefba2f5",
			inputCommitType: Fixed,
			expectedAffectedCommit: AffectedCommit{
				Repo:  "https://github.com/google/osv.dev",
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
			description:     "Valid GitHub commit URL with .patch extension",
			inputLink:       "https://github.com/pimcore/customer-data-framework/commit/e3f333391582d9309115e6b94e875367d0ea7163.patch",
			inputCommitType: Fixed,
			expectedAffectedCommit: AffectedCommit{
				Repo:  "https://github.com/pimcore/customer-data-framework",
				Fixed: "e3f333391582d9309115e6b94e875367d0ea7163",
			},
		},
		{
			description:     "Undesired GitHub PR commit URL",
			inputLink:       "https://github.com/OpenZeppelin/cairo-contracts/pull/542/commits/6d4cb750478fca2fd916f73297632f899aca9299",
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
			disableExpiryDate: time.Date(2025, 3, 22, 12, 30, 0, 0, time.Local),
		},
		{
			description:     "Valid GitLab commit URL with .patch extension",
			inputLink:       "https://gitlab.com/muttmua/mutt/-/commit/452ee330e094bfc7c9a68555e5152b1826534555.patch",
			inputCommitType: Fixed,
			expectedAffectedCommit: AffectedCommit{
				Repo:  "https://gitlab.com/muttmua/mutt",
				Fixed: "452ee330e094bfc7c9a68555e5152b1826534555",
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
			inputLink:       "https://bitbucket.org/utmandrew/pcrs/commits/5f18bcb/",
			inputCommitType: Fixed,
			expectedAffectedCommit: AffectedCommit{
				Repo:  "https://bitbucket.org/utmandrew/pcrs",
				Fixed: "5f18bcb",
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
				Repo:  "git://git.gnupg.org/libksba.git",
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
		{
			description:     "cGit reference from CVE-2022-30594, remapped to be cloneable",
			inputLink:       "https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=ee1fee900537b5d9560e9f937402de5ddc8412f3",
			inputCommitType: Fixed,
			expectedAffectedCommit: AffectedCommit{
				Repo:  "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
				Fixed: "ee1fee900537b5d9560e9f937402de5ddc8412f3",
			},
			skipOnCloudBuild: true, // observing indications of IP denylisting as at 2025-02-13
		},
		{
			description:     "Valid GitWeb commit URL",
			inputLink:       "https://git.ffmpeg.org/gitweb/ffmpeg.git/commitdiff/c94875471e3ba3dc396c6919ff3ec9b14539cd71",
			inputCommitType: Fixed,
			expectedAffectedCommit: AffectedCommit{
				Repo:  "https://git.ffmpeg.org/ffmpeg.git",
				Fixed: "c94875471e3ba3dc396c6919ff3ec9b14539cd71",
			},
		},
		{
			description:     "A GitHub repo that has been renamed (as seen on CVE-2016-10544)",
			inputLink:       "https://github.com/uWebSockets/uWebSockets/commit/37deefd01f0875e133ea967122e3a5e421b8fcd9",
			inputCommitType: Fixed,
			expectedAffectedCommit: AffectedCommit{
				Repo:  "https://github.com/unetworking/uwebsockets",
				Fixed: "37deefd01f0875e133ea967122e3a5e421b8fcd9",
			},
		},
		{
			description:     "A GitHub repo that should be working (as seen on CVE-2021-23568)",
			inputLink:       "https://github.com/eggjs/extend2/commit/aa332a59116c8398976434b57ea477c6823054f8",
			inputCommitType: Fixed,
			expectedAffectedCommit: AffectedCommit{
				Repo:  "https://github.com/eggjs/extend2",
				Fixed: "aa332a59116c8398976434b57ea477c6823054f8",
			},
		},
		{
			description:            "A GitHub commit link that is 404'ing (as seen on CVE-2019-8375)",
			inputLink:              "https://github.com/WebKit/webkit/commit/6f9b511a115311b13c06eb58038ddc2c78da5531",
			inputCommitType:        Fixed,
			expectedAffectedCommit: AffectedCommit{},
			expectFailure:          true,
		},
	}

	for _, tc := range tests {

		t.Run(tc.description, func(t *testing.T) {
			t.Parallel()
			if _, ok := os.LookupEnv("BUILD_ID"); ok && tc.skipOnCloudBuild {
				t.Skipf("test %q: running on Cloud Build", tc.description)
			}
			if time.Now().Before(tc.disableExpiryDate) {
				t.Skipf("test %q: extractGitCommit for %q (%q) has been skipped due to known outage and will be reenabled on %s.", tc.description, tc.inputLink, tc.inputCommitType, tc.disableExpiryDate)
			}
			if !tc.disableExpiryDate.IsZero() && time.Now().After(tc.disableExpiryDate) {
				t.Logf("test %q: extractGitCommit(%q, %q) has been enabled on %s.", tc.description, tc.inputLink, tc.inputCommitType, tc.disableExpiryDate)
			}
			got, err := extractGitCommit(tc.inputLink, tc.inputCommitType)
			if err != nil && !tc.expectFailure {
				t.Errorf("test %q: extractGitCommit for %q (%q) errored unexpectedly: %#v", tc.description, tc.inputLink, tc.inputCommitType, err)
			}
			if err == nil && tc.expectFailure {
				t.Errorf("test %q: extractGitCommit for %q (%q) did not error as unexpected!", tc.description, tc.inputLink, tc.inputCommitType)
			}
			if !reflect.DeepEqual(got, tc.expectedAffectedCommit) {
				t.Errorf("test %q: extractGitCommit for %q was incorrect, got: %#v, expected: %#v", tc.description, tc.inputLink, got, tc.expectedAffectedCommit)
			}
		})
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

		t.Run(tc.description, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeVersion(tc.inputVersion)
			if err != nil && tc.expectedOk {
				t.Errorf("test %q: Normalize(%q) unexpectedly errored: %#v", tc.description, tc.inputVersion, err)
			}
			if !reflect.DeepEqual(got, tc.expectedNormalizedVersion) {
				t.Errorf("test %q: normalized version for %q was incorrect, got: %q, expected %q", tc.description, tc.inputVersion, got, tc.expectedNormalizedVersion)
			}
		})
	}
}

func TestExtractVersionInfo(t *testing.T) {
	tests := []struct {
		description         string
		inputCVEItem        Vulnerability
		inputValidVersions  []string
		expectedVersionInfo VersionInfo
		expectedNotes       []string
		disableExpiryDate   time.Time // If test needs to be disabled due to known outage.
	}{
		{
			description:        "A CVE with multiple affected versions",
			inputCVEItem:       loadTestData2("CVE-2022-32746"),
			inputValidVersions: []string{},
			expectedVersionInfo: VersionInfo{
				AffectedCommits: []AffectedCommit(nil),
				AffectedVersions: []AffectedVersion{
					{
						Introduced:   "4.3.0",
						Fixed:        "4.14.14",
						LastAffected: "",
					},
					{
						Introduced:   "4.15.0",
						Fixed:        "4.15.9",
						LastAffected: "",
					},
					{
						Introduced:   "4.16.0",
						Fixed:        "4.16.4",
						LastAffected: "",
					},
				},
			},
			expectedNotes: []string{},
		},
		{
			description:        "A CVE with duplicate affected versions squashed",
			inputCVEItem:       loadTestData2("CVE-2022-0090"),
			inputValidVersions: []string{},
			expectedVersionInfo: VersionInfo{
				AffectedCommits: []AffectedCommit(nil),
				AffectedVersions: []AffectedVersion{
					{
						Introduced:   "",
						Fixed:        "14.4.5",
						LastAffected: "",
					},
					{
						Introduced:   "14.5.0",
						Fixed:        "14.5.3",
						LastAffected: "",
					},
					{
						Introduced:   "14.6.0",
						Fixed:        "14.6.1",
						LastAffected: "",
					},
				},
			},
			expectedNotes: []string{},
		},
		{
			description:        "A CVE with no explicit versions",
			inputCVEItem:       loadTestData2("CVE-2022-1122"),
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
			disableExpiryDate:  time.Date(2025, 6, 1, 0, 0, 0, 0, time.Local),
			inputCVEItem:       loadTestData2("CVE-2022-25929"),
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
			disableExpiryDate:  time.Date(2025, 6, 1, 0, 0, 0, 0, time.Local),
			inputCVEItem:       loadTestData2("CVE-2022-29194"),
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
						Introduced:   "",
						Fixed:        "2.6.4",
						LastAffected: "",
					},
					{
						Introduced:   "2.7.0",
						Fixed:        "2.7.2",
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
			inputCVEItem:       loadTestData2("CVE-2022-2956"),
			inputValidVersions: []string{},
			expectedVersionInfo: VersionInfo{
				AffectedCommits:  []AffectedCommit(nil),
				AffectedVersions: []AffectedVersion(nil),
			},
			expectedNotes: []string{},
		},
		{
			description:        "A CVE with a weird GitLab reference that breaks version enumeration in the worker",
			inputCVEItem:       loadTestData2("CVE-2022-46285"),
			inputValidVersions: []string{},
			expectedVersionInfo: VersionInfo{
				AffectedCommits:  []AffectedCommit{{Repo: "https://gitlab.freedesktop.org/xorg/lib/libxpm", Fixed: "a3a7c6dcc3b629d7650148"}},
				AffectedVersions: []AffectedVersion{{Fixed: "3.5.15"}},
			},
			expectedNotes:     []string{},
			disableExpiryDate: time.Date(2025, 3, 22, 12, 30, 0, 0, time.Local),
		},
		{
			description:  "A CVE with a different GitWeb reference URL that was not previously being extracted successfully",
			inputCVEItem: loadTestData2("CVE-2021-28429"),
			expectedVersionInfo: VersionInfo{
				AffectedCommits:  []AffectedCommit{{Repo: "https://git.ffmpeg.org/ffmpeg.git", Fixed: "c94875471e3ba3dc396c6919ff3ec9b14539cd71"}},
				AffectedVersions: []AffectedVersion{{LastAffected: "4.3.2"}},
			},
		},
		{
			description:  "A CVE with a configuration unsupported by ExtractVersionInfo and a limit version in the description",
			inputCVEItem: loadTestData2("CVE-2020-13595"),
			expectedVersionInfo: VersionInfo{
				AffectedVersions: []AffectedVersion{{Introduced: "4.0.0", LastAffected: "4.2"}},
			},
		},
	}

	for _, tc := range tests {

		t.Run(tc.description, func(t *testing.T) {
			t.Parallel()
			if time.Now().Before(tc.disableExpiryDate) {
				t.Skipf("test %q: VersionInfo for %#v has been skipped due to known outage and will be reenabled on %s.", tc.description, tc.inputCVEItem, tc.disableExpiryDate)
			}
			if !tc.disableExpiryDate.IsZero() && time.Now().After(tc.disableExpiryDate) {
				t.Logf("test %q: VersionInfo for %#v has been enabled on %s.", tc.description, tc.inputCVEItem, tc.disableExpiryDate)
			}
			gotVersionInfo, _ := ExtractVersionInfo(tc.inputCVEItem.CVE, tc.inputValidVersions)
			if diff := cmp.Diff(tc.expectedVersionInfo, gotVersionInfo); diff != "" {
				t.Errorf("test %q: VersionInfo for %#v was incorrect: %s", tc.description, tc.inputCVEItem, diff)
			}
		})
	}
}

func TestCPEs(t *testing.T) {
	tests := []struct {
		description  string
		inputCVEItem Vulnerability
		expectedCPEs []string
	}{
		{
			description:  "A CVE with child CPEs",
			inputCVEItem: loadTestData2("CVE-2023-24256"),
			expectedCPEs: []string{"cpe:2.3:o:nio:aspen:*:*:*:*:*:*:*:*", "cpe:2.3:h:nio:ec6:-:*:*:*:*:*:*:*"},
		},
		{
			description:  "A CVE without child CPEs",
			inputCVEItem: loadTestData2("CVE-2022-33745"),
			expectedCPEs: []string{"cpe:2.3:o:xen:xen:*:*:*:*:*:*:x86:*", "cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*", "cpe:2.3:o:fedoraproject:fedora:35:*:*:*:*:*:*:*", "cpe:2.3:o:fedoraproject:fedora:36:*:*:*:*:*:*:*"},
		},
	}

	for _, tc := range tests {

		t.Run(tc.description, func(t *testing.T) {
			t.Parallel()
			gotCPEs := CPEs(tc.inputCVEItem.CVE)
			if diff := cmp.Diff(gotCPEs, tc.expectedCPEs); diff != "" {
				t.Errorf("test %q: CPEs for %#v were incorrect: %s", tc.description, tc.inputCVEItem.CVE.Configurations, diff)
			}
		})
	}
}

func TestVersionInfoDuplicateDetection(t *testing.T) {
	tests := []struct {
		description         string
		inputVersionInfo    VersionInfo
		inputAffectedCommit AffectedCommit
		expectedResult      bool
	}{
		{
			description:         "An empty VersionInfo and AffectedCommit",
			inputVersionInfo:    VersionInfo{},
			inputAffectedCommit: AffectedCommit{},
			expectedResult:      false,
		},
		{
			description:         "A populated VersionInfo and empty AffectedCommit",
			inputVersionInfo:    VersionInfo{AffectedCommits: []AffectedCommit{{Repo: "https://github.com/foo/bar", Introduced: "4089bd6080d41450adab1e0ac0d63cfeab4a78e7", Fixed: "4089bd6080d41450adab1e0ac0d63cfeab4a78e7"}}},
			inputAffectedCommit: AffectedCommit{},
			expectedResult:      false,
		},
		{
			description:         "An empty VersionInfo and a populated AffectedCommit",
			inputVersionInfo:    VersionInfo{},
			inputAffectedCommit: AffectedCommit{Repo: "https://github.com/foo/bar", Introduced: "4089bd6080d41450adab1e0ac0d63cfeab4a78e7", Fixed: "4089bd6080d41450adab1e0ac0d63cfeab4a78e7"},
			expectedResult:      false,
		},
		{
			description:         "A bonafide full duplicate",
			inputVersionInfo:    VersionInfo{AffectedCommits: []AffectedCommit{{Repo: "https://github.com/foo/bar", Introduced: "4089bd6080d41450adab1e0ac0d63cfeab4a78e7", Fixed: "4089bd6080d41450adab1e0ac0d63cfeab4a78e7"}}},
			inputAffectedCommit: AffectedCommit{Repo: "https://github.com/foo/bar", Introduced: "4089bd6080d41450adab1e0ac0d63cfeab4a78e7", Fixed: "4089bd6080d41450adab1e0ac0d63cfeab4a78e7"},
			expectedResult:      true,
		},
		{
			description:         "Duplication across introduced and fixed",
			inputVersionInfo:    VersionInfo{AffectedCommits: []AffectedCommit{{Repo: "https://github.com/foo/bar", Introduced: "4089bd6080d41450adab1e0ac0d63cfeab4a78e7"}}},
			inputAffectedCommit: AffectedCommit{Repo: "https://github.com/foo/bar", Fixed: "4089bd6080d41450adab1e0ac0d63cfeab4a78e7"},
			expectedResult:      true,
		},
	}

	for _, tc := range tests {

		t.Run(tc.description, func(t *testing.T) {
			t.Parallel()
			result := tc.inputVersionInfo.Duplicated(tc.inputAffectedCommit)
			if diff := cmp.Diff(result, tc.expectedResult); diff != "" {
				t.Errorf("test %q: HasDuplicateAffectedVersions for %#v was incorrect: %s", tc.description, tc.inputVersionInfo, diff)
			}
		})
	}
}

func TestInvalidRangeDetection(t *testing.T) {
	tests := []struct {
		description         string
		inputAffectedCommit AffectedCommit
		expectedResult      bool
	}{
		{
			description:         "An empty AffectedCommit",
			inputAffectedCommit: AffectedCommit{},
			expectedResult:      false,
		},
		{
			description:         "Only an introduced commit",
			inputAffectedCommit: AffectedCommit{Repo: "https://github.com/foo/bar", Introduced: "4089bd6080d41450adab1e0ac0d63cfeab4a78e7"},
			expectedResult:      false,
		},
		{
			description:         "Only a fixed commit",
			inputAffectedCommit: AffectedCommit{Repo: "https://github.com/foo/bar", Fixed: "4089bd6080d41450adab1e0ac0d63cfeab4a78e7"},
			expectedResult:      false,
		},
		{
			description:         "Only a last_affected commit",
			inputAffectedCommit: AffectedCommit{Repo: "https://github.com/foo/bar", LastAffected: "4089bd6080d41450adab1e0ac0d63cfeab4a78e7"},
			expectedResult:      false,
		},
		{
			description:         "Non-overlapping introduced and fixed range",
			inputAffectedCommit: AffectedCommit{Repo: "https://github.com/foo/bar", Introduced: "4089bd6080d41450adab1e0ac0d63cfeab4a78e7", Fixed: "b48ff2aa1e57e761fa0825e3dc78105a0d016e16"},
			expectedResult:      false,
		},
		{
			description:         "Non-overlapping introduced and last_affected range",
			inputAffectedCommit: AffectedCommit{Repo: "https://github.com/foo/bar", Introduced: "4089bd6080d41450adab1e0ac0d63cfeab4a78e7", LastAffected: "b48ff2aa1e57e761fa0825e3dc78105a0d016e16"},
			expectedResult:      false,
		},
		{
			description:         "Overlapping introduced and fixed range",
			inputAffectedCommit: AffectedCommit{Repo: "https://github.com/foo/bar", Introduced: "4089bd6080d41450adab1e0ac0d63cfeab4a78e7", Fixed: "4089bd6080d41450adab1e0ac0d63cfeab4a78e7"},
			expectedResult:      true,
		},
		{
			description:         "Overlapping introduced and last_affected range",
			inputAffectedCommit: AffectedCommit{Repo: "https://github.com/foo/bar", Introduced: "4089bd6080d41450adab1e0ac0d63cfeab4a78e7", LastAffected: "4089bd6080d41450adab1e0ac0d63cfeab4a78e7"},
			expectedResult:      true,
		},
	}

	for _, tc := range tests {

		t.Run(tc.description, func(t *testing.T) {
			t.Parallel()
			result := tc.inputAffectedCommit.InvalidRange()
			if diff := cmp.Diff(result, tc.expectedResult); diff != "" {
				t.Errorf("test %q: Duplicated() for %#v was incorrect: %s", tc.description, tc.inputAffectedCommit, diff)
			}
		})
	}
}

func TestValidateAndCanonicalizeLink(t *testing.T) {
	type args struct {
		link string
	}
	tests := []struct {
		name              string
		args              args
		wantCanonicalLink string
		wantErr           bool
		skipOnCloudBuild  bool
		disableExpiryDate time.Time // If test needs to be disabled due to known outage.
	}{
		{
			name: "A link that 404's",
			args: args{
				link: "https://github.com/WebKit/webkit/commit/6f9b511a115311b13c06eb58038ddc2c78da5531",
			},
			wantCanonicalLink: "https://github.com/WebKit/webkit/commit/6f9b511a115311b13c06eb58038ddc2c78da5531",
			wantErr:           true,
		},
		{
			name: "A functioning link",
			args: args{
				link: "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ee1fee900537b5d9560e9f937402de5ddc8412f3",
			},
			wantCanonicalLink: "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ee1fee900537b5d9560e9f937402de5ddc8412f3",
			wantErr:           false,
			skipOnCloudBuild:  true, // observing indications of IP denylisting as at 2025-02-13

		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if time.Now().Before(tt.disableExpiryDate) {
				t.Skipf("test %q has been skipped due to known outage and will be reenabled on %s.", tt.name, tt.disableExpiryDate)
			}
			if _, ok := os.LookupEnv("BUILD_ID"); ok && tt.skipOnCloudBuild {
				t.Skipf("test %q: running on Cloud Build", tt.name)
			}
			gotCanonicalLink, err := ValidateAndCanonicalizeLink(tt.args.link)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAndCanonicalizeLink() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotCanonicalLink != tt.wantCanonicalLink {
				t.Errorf("ValidateAndCanonicalizeLink() = %v, want %v", gotCanonicalLink, tt.wantCanonicalLink)
			}
		})
	}
}

func TestCommit(t *testing.T) {
	type args struct {
		u string
	}
	tests := []struct {
		name              string
		args              args
		want              string
		wantErr           bool
		disableExpiryDate time.Time // If test needs to be disabled due to known outage.
	}{
		{
			name: "a canoncalized kernel.org cGit URL",
			args: args{
				u: "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ee1fee900537b5d9560e9f937402de5ddc8412f3",
			},
			want:    "ee1fee900537b5d9560e9f937402de5ddc8412f3",
			wantErr: false,
		},
		{
			name: "an unusual and technically valid GitHub commit URL based on a tag (with ancestry)",
			args: args{
				u: "https://github.com/curl/curl/commit/curl-7_50_2~32",
			},
			want:    "", // Ideally it would be 7700fcba64bf5806de28f6c1c7da3b4f0b38567d but this isn't `git rev-parse`
			wantErr: true,
		},
		{
			name: "Valid GitHub commit URL",
			args: args{
				u: "https://github.com/MariaDB/server/commit/b1351c15946349f9daa7e5297fb2ac6f3139e4a",
			},
			want:    "b1351c15946349f9daa7e5297fb2ac6f3139e4a",
			wantErr: false,
		},
		{
			name: "Valid FreeDesktop GitLab commit URL",
			args: args{
				u: "https://gitlab.freedesktop.org/virgl/virglrenderer/-/commit/b05bb61f454eeb8a85164c8a31510aeb9d79129",
			},
			want:    "b05bb61f454eeb8a85164c8a31510aeb9d79129",
			wantErr: false,
		},
		{
			name: "Valid GitLab commit URL with a shorter hash",
			args: args{
				u: "https://gitlab.com/qemu-project/qemu/-/commit/4367a20cc",
			},
			want:    "4367a20cc",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if time.Now().Before(tt.disableExpiryDate) {
				t.Skipf("test %q has been skipped due to known outage and will be reenabled on %s.", tt.name, tt.disableExpiryDate)
			}
			got, err := Commit(tt.args.u)
			if (err != nil) != tt.wantErr {
				t.Errorf("Commit() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Commit() = %v, want %v", got, tt.want)
			}
		})
	}
}
