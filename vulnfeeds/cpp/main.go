package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
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
func CVEToOSV(CVE cves.CVEItem, repo, directory string) {
	CPEs := cves.CPEs(CVE)
	CPE, err := cves.ParseCPE(CPEs[0])
	if err != nil {
		Logger.Fatalf("Can't generate an OSV record for %s without valid CPE data", CVE.CVE.CVEDataMeta.ID)
	}
	v, _ := vulns.FromCVE(CVE.CVE.CVEDataMeta.ID, CVE)
	versions, _ := cves.ExtractVersionInfo(CVE, nil)
	affected := vulns.Affected{}
	affected.AttachExtractedVersionInfo(versions)
	v.Affected = append(v.Affected, affected)

	if len(v.Affected[0].Ranges) == 0 {
		Logger.Infof("No affected versions detected for %s for %q", CVE.CVE.CVEDataMeta.ID, CPE.Product)
	} else {

		vulnDir := filepath.Join(directory, CPE.Product)
		err = os.MkdirAll(vulnDir, 0755)
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
		Logger.Infof("Processed %s for %q", CVE.CVE.CVEDataMeta.ID, CPE.Product)
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
			CPE, err := cves.ParseCPE(CPEstr)
			if err != nil {
				Logger.Warnf("Failed to parse CPE %q: %+v", CPEstr, err)
				continue
			}
			if CPE.Part == "a" {
				appCPECount += 1
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
						CPE, err := cves.ParseCPE(CPEstr)
						if err != nil {
							Logger.Warnf("Failed to parse CPE %q: %+v", CPEstr, err)
							continue
						}
						// Avoid unnecessary calls to cves.Repo() if we already have the repo
						if _, ok := repos[CPE.Product]; !ok {
							repo, err := cves.Repo(ref.URL)
							if err != nil {
								Logger.Warnf("Failed to parse %q for %q: %+v", ref.URL, CPE.Product, err)
								continue
							}
							repos[CPE.Product] = repo
						}
						if _, ok := repos[cve.CVE.CVEDataMeta.ID]; !ok {
							repo, err := cves.Repo(ref.URL)
							if err != nil {
								Logger.Warnf("Failed to parse %q for %q: %+v", ref.URL, CPE.Product, err)
								continue
							}
							repos[cve.CVE.CVEDataMeta.ID] = repo
						}
					}
					patchRefCount += 1
				}
			}
		}

		for _, CPEstr := range cves.CPEs(cve) {
			CPE, err := cves.ParseCPE(CPEstr)
			if err != nil {
				Logger.Warnf("Failed to parse CPE %q: %+v", CPEstr, err)
			}
			if CPE.Part == "a" {
				Logger.Infof("\t * vendor=%q, product=%q", CPE.Vendor, CPE.Product)
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

		CVEToOSV(cve, repos[cve.CVE.CVEDataMeta.ID], *outDir)
	}
}
