package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"cloud.google.com/go/logging"
	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/utility"
	"github.com/google/osv/vulnfeeds/vulns"
	"golang.org/x/exp/slices"
)

const (
	projectId = "oss-vdb"
	extension = ".json"
)

var Logger utility.LoggerWrapper

// Checks if a URL is to a supported repo.
func IsRepoURL(url string) bool {
	re := regexp.MustCompile(`http[s]?:\/\/(?:c?git(?:hub|lab)?)\.|\.git$`)

	return re.MatchString(url)
}

// Returns the base repository URL
func Repo(u string) (string, bool) {
	parsedURL, err := url.Parse(u)
	if err != nil {
		Logger.Fatalf("%v", err)
	}
	// GitHub and GitLab commit and blob URLs are structured one way, e.g.
	// https://github.com/MariaDB/server/commit/b1351c15946349f9daa7e5297fb2ac6f3139e4a8
	// https://github.com/tensorflow/tensorflow/blob/master/tensorflow/core/ops/math_ops.cc
	// https://gitlab.freedesktop.org/virgl/virglrenderer/-/commit/b05bb61f454eeb8a85164c8a31510aeb9d79129c
	// https://gitlab.com/qemu-project/qemu/-/commit/4367a20cc4
	// https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-2501.json
	//
	// This also supports GitHub tag URLs, e.g.
	// https://github.com/JonMagon/KDiskMark/releases/tag/3.1.0
	//
	// This also supports GitHub and Gitlab issue URLs, e.g.:
	// https://github.com/axiomatic-systems/Bento4/issues/755
	// https://gitlab.com/wireshark/wireshark/-/issues/18307
	if strings.Contains(parsedURL.Path, "commit") || strings.Contains(parsedURL.Path, "blob") || strings.Contains(parsedURL.Path, "releases/tag") || strings.Contains(parsedURL.Path, "issues") {
		return fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Hostname(), strings.Join(strings.Split(parsedURL.Path, "/")[0:3], "/")), true
	}

	// GitHub pull request URLs are structured differently, e.g.
	// https://github.com/google/osv.dev/pull/738
	if parsedURL.Hostname() == "github.com" && strings.Contains(parsedURL.Path, "pull") {
		return fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Hostname(), strings.Join(strings.Split(parsedURL.Path, "/")[0:3], "/")), true
	}

	// Gitlab merge request URLs are structured differently, e.g.
	// https://gitlab.com/libtiff/libtiff/-/merge_requests/378
	if strings.Contains(parsedURL.Hostname(), "gitlab") && strings.Contains(parsedURL.Path, "merge_requests") {
		return fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Hostname(), strings.Join(strings.Split(parsedURL.Path, "/")[0:3], "/")), true
	}

	// GitWeb URLs are structured another way, e.g.
	// https://git.dpkg.org/cgit/dpkg/dpkg.git/commit/?id=faa4c92debe45412bfcf8a44f26e827800bb24be
	// https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=817b8b9c5396d2b2d92311b46719aad5d3339dbe
	if parsedURL.Path == "/" && strings.Contains(parsedURL.RawQuery, "commit") {
		repo := strings.Split(strings.Split(parsedURL.RawQuery, ";")[0], "=")[1]
		return fmt.Sprintf("%s://%s/%s", parsedURL.Scheme, parsedURL.Hostname(), repo), true
	}

	// If we get to here we've encountered an unsupported URL
	return "", false

}

// Checks if a URL relates to the FSF.
func IsGNUURL(url string) bool {
	re := regexp.MustCompile(`^https?://.*\.(?:non)?gnu\.org/`)

	return re.MatchString(url)
}

// Tries to translate Savannah URLs to their corresponding Git repository URL.
func MaybeTranslateSavannahURL(u string) (string, bool) {
	type GNUPlaceholder struct {
		GNUOrNonGNU string
		Path        string
	}
	var tpl bytes.Buffer

	supportedHostnames := []string{
		"download.savannah.gnu.org",
		"savannah.gnu.org",
		"download.savannah.gnu.org",
		"download-mirror.savannah.gnu.org",
		"download.savannah.nongnu.org",
		"savannah.nongnu.org",
		"download.savannah.nongnu.org",
		"download-mirror.savannah.nongnu.org",
	}

	// Get hostname out of URL
	parsedURL, err := url.Parse(u)
	if err != nil {
		panic(err)
	}

	if slices.Contains(supportedHostnames, parsedURL.Hostname()) {
		hostnameParts := strings.Split(parsedURL.Hostname(), ".")
		// Pull out the "nongnu" or "gnu" part of the hostname
		domain := GNUPlaceholder{hostnameParts[len(hostnameParts)-2], path.Base(parsedURL.Path)}
		savannahGitRepoTemplate, err := template.New("SavannahGitRepoURL").Parse("https://git.savannah.{{ .GNUOrNonGNU }}.org/git/{{ .Path }}.git")
		if err != nil {
			panic(err)
		}
		err = savannahGitRepoTemplate.Execute(&tpl, domain)
		return tpl.String(), true
	}

	// Return the original URL unmodified
	return u, false
}

// Returns the data associated with the ^Source: line of a machine-readable Debian copyright file
// See https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
func MaybeGetSourceFromDebianCopyright(copyrightFile string) (string, bool) {
	re := regexp.MustCompile(`^Source: (.*)$`)

	file, err := os.Open(copyrightFile)
	if err != nil {
		Logger.Fatalf("%v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// Check the first line to see if we have a machine-readable copyright file
	scanner.Scan()
	if scanner.Text() != "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/" {
		return "", false
	}

	for scanner.Scan() {
		line := scanner.Text()
		match := re.FindStringSubmatch(line)
		if match != nil {
			return match[1], true
		}
	}

	return "", false
}

// Tries to find a Debian copyright file for the package and returns the source URL if IsRepoURL() agrees.
func MaybeGetSourceRepoFromDebian(mdir string, pkg string) string {
	var metadata string
	if strings.HasPrefix(pkg, "lib") {
		metadata = path.Join(mdir, "changelogs/main", string(pkg[0:4]), pkg, "unstable_copyright")
	} else {
		metadata = path.Join(mdir, "changelogs/main", string(pkg[0]), pkg, "unstable_copyright")
	}
	if _, err := os.Stat(metadata); err == nil {
		// parse the copyright file and go from here
		Logger.Infof("FYI: Will look at %s", metadata)
		possibleRepo, ok := MaybeGetSourceFromDebianCopyright(metadata)
		if !ok {
			return ""
		}
		if IsRepoURL(possibleRepo) {
			return possibleRepo
		}
		// Incorporate Savannah URL to Git translation here
		if IsGNUURL(possibleRepo) {
			repo, translated := MaybeTranslateSavannahURL(possibleRepo)
			if translated {
				return repo
			}
		}
		Logger.Infof("FYI: Disregarding %s", possibleRepo)
	}
	return ""
}

// Use the GitHub API to query the repository's language metadata to make the determination.
func InScopeGitHubRepo(repoURL string) bool {
	// TODO(apollock): Implement
	return true
}

// Clone the repo and look for C/C++ files to make the determination.
func InScopeGitRepo(repoURL string) bool {
	// TODO(apollock): Implement
	return true
}

// Looks at what the repo to determine if it contains code using an in-scope language
func InScopeRepo(repoURL string) bool {
	parsedURL, err := url.Parse(repoURL)
	if err != nil {
		Logger.Infof("Warning: %s failed to parse, skipping", repoURL)
		return false
	}

	switch parsedURL.Hostname() {
	case "github.com":
		return InScopeGitHubRepo(repoURL)
	default:
		return InScopeGitRepo(repoURL)
	}
}

// Takes an NVD CVE record and outputs an OSV file in the specified directory.
func CVEToOSV(cve cves.CVEItem, directory string) {
	CPEs := cves.CPEs(cve)
	CPE, ok := cves.ParseCPE(CPEs[0])
	if !ok {
		Logger.Fatalf("Can't generate an OSV record for %s without CPE data", cve.CVE.CVEDataMeta.ID)
	}
	v, _ := vulns.FromCVE(cve.CVE.CVEDataMeta.ID, cve)
	vulnDir := filepath.Join(directory, CPE.Product)
	err := os.MkdirAll(vulnDir, 0755)
	if err != nil {
		Logger.Fatalf("Failed to create dir: %v", err)
	}
	outputFile := filepath.Join(vulnDir, v.ID+extension)
	f, err := os.Create(outputFile)
	if err != nil {
		Logger.Fatalf("Failed to open %s for writing: %v", outputFile, err)
	}
	defer f.Close()
	err = v.ToJSON(f)
	if err != nil {
		Logger.Fatalf("Failed to write %s: %v", outputFile, err)
	}
}

func main() {
	jsonPath := flag.String("nvd_json", "", "Path to NVD CVE JSON to examine.")
	debianMetadataPath := flag.String("debian_metadata_path", "", "Path to Debian copyright metadata")
	outDir := flag.String("out_dir", "", "Path to output results.")

	flag.Parse()

	client, err := logging.NewClient(context.Background(), projectId)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	Logger.GCloudLogger = client.Logger("cpp-osv")

	data, err := ioutil.ReadFile(*jsonPath)
	if err != nil {
		Logger.Fatalf("Failed to open file: %v", err) // double check this is best practice output
	}

	var parsed cves.NVDCVE
	err = json.Unmarshal(data, &parsed)
	if err != nil {
		Logger.Fatalf("Failed to parse NVD CVE JSON: %v", err)
	}

	for _, cve := range parsed.CVEItems {
		refs := cve.CVE.References.ReferenceData
		patchRefCount := 0
		CPEs := cves.CPEs(cve)
		repos := make(map[string]string)

		if len(refs) == 0 && len(CPEs) == 0 {
			Logger.Infof("FYI: skipping %s due to:", cve.CVE.CVEDataMeta.ID)
			Logger.Infof("\t * lack of CPEs")
			Logger.Infof("\t * lack of references")
			continue
		}

		// Does it have any application CPEs?
		appCPECount := 0
		for _, CPEstr := range cves.CPEs(cve) {
			CPE, ok := cves.ParseCPE(CPEstr)
			if ok {
				if CPE.Part == "a" {
					appCPECount += 1
				}
			} else {
				Logger.Fatalf("Failed to parse CPE %s: %v", CPEstr, err)
			}
		}

		if appCPECount == 0 {
			// Not software, skip.
			continue
		}

		Logger.Infof("%s", cve.CVE.CVEDataMeta.ID)
		for _, ref := range refs {
			// Are any of the reference's tags 'Patch'?
			for _, tag := range ref.Tags {
				if tag == "Third Party Advisory" {
					continue
				}
				// Alternative to the above:
				// if tag == "Patch" && IsRepoURL(ref.URL) {
				if IsRepoURL(ref.URL) {
					Logger.Infof("\t * %s", ref.URL)
					// CVE entries have one set of references, but can have multiple CPEs
					for _, CPEstr := range cves.CPEs(cve) {
						CPE, ok := cves.ParseCPE(CPEstr)
						if !ok {
							Logger.Infof("Failed to parse CPE %s: %v", CPEstr, err)
							continue
						}
						// Avoid unnecessary calls to Repo() if we already have the repo
						if _, ok := repos[CPE.Product]; !ok {
							repo, ok := Repo(ref.URL)
							if ok {
								repos[CPE.Product] = repo
							}
						}
						if _, ok := repos[cve.CVE.CVEDataMeta.ID]; !ok {
							repo, ok := Repo(ref.URL)
							if ok {
								repos[cve.CVE.CVEDataMeta.ID] = repo
							}
						}
					}
					patchRefCount += 1
				}
			}
		}

		for _, CPEstr := range cves.CPEs(cve) {
			CPE, ok := cves.ParseCPE(CPEstr)
			if !ok {
				Logger.Infof("Failed to parse CPE %s: %v", CPEstr, err)
			}
			if CPE.Part == "a" {
				Logger.Infof("\t * vendor=%s, product=%s", CPE.Vendor, CPE.Product)
				if patchRefCount == 0 {
					repo := MaybeGetSourceRepoFromDebian(*debianMetadataPath, CPE.Product)
					if repo != "" {
						Logger.Infof("Derived repo: %s", repo)
						repos[CPE.Product] = repo
					}
				}

			}
		}
		Logger.Infof("Summary for %s: [CPEs=%d AppCPEs=%d patches=%d DerivedRepos=%d]", cve.CVE.CVEDataMeta.ID, len(CPEs), appCPECount, patchRefCount, len(repos))
		Logger.Infof("Repos: %#v", repos)

		// If we've made it to here, we may have:
		// * a CVE that has Application-related CPEs (so applies to software)
		// * has one or more patches with a known repository URL patch reference
		// OR
		// * a derived repository for the software
		//
		// We do not yet have:
		// * any knowledge of the language used
		// * definitive version information

		if patchRefCount == 0 && len(repos) == 0 {
			// We have nothing useful to work with, so we'll assume it's out of scope
			Logger.Infof("FYI: Passing on %s due to lack of viable information", cve.CVE.CVEDataMeta.ID)
			continue
		}

		if !InScopeRepo(repos[cve.CVE.CVEDataMeta.ID]) {
			continue
		}

		CVEToOSV(cve, *outDir)
	}
}
