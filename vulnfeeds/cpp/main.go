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
	"regexp"
	"strings"
	"text/template"

	"cloud.google.com/go/logging"
	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/utility"
	"golang.org/x/exp/slices"
)

const projectId = "oss-vdb"

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

func main() {
	jsonPath := flag.String("nvd_json", "", "Path to NVD CVE JSON to examine.")
	debianMetadataPath := flag.String("debian_metadata_path", "", "Path to Debian copyright metadata")

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
		patchRefs := 0
		cpes := cves.CPEs(cve)

		if len(refs) == 0 && len(cpes) == 0 {
			Logger.Infof("FYI: skipping %s due to:", cve.CVE.CVEDataMeta.ID)
			Logger.Infof("\t * lack of CPEs")
			Logger.Infof("\t * lack of references")
			continue
		}

		// Does it have any application CPEs?
		appCpes := 0
		for _, cpeStr := range cves.CPEs(cve) {
			cpe, ok := cves.ParseCPE(cpeStr)
			if ok {
				if cpe.Part == "a" {
					appCpes += 1
				}
			} else {
				Logger.Fatalf("Failed to parse CPE %s: %v", cpeStr, err)
			}
		}

		if appCpes == 0 {
			Logger.Infof("FYI: skipping %s due to:", cve.CVE.CVEDataMeta.ID)
			Logger.Infof("\t * believed non-software")
			continue
		}

		Logger.Infof("%s", cve.CVE.CVEDataMeta.ID)
		for _, ref := range refs {
			// Are any of the reference's tags 'Patch'?
			for _, tag := range ref.Tags {
				// TODO(apollock): determine rate of false negatives
				if tag == "Patch" && IsRepoURL(ref.URL) {
					Logger.Infof("\t * %s", ref.URL)
					patchRefs += 1
				}
			}
		}

		if patchRefs == 0 {
			Logger.Infof("FYI: Will need to rely on CPE exclusively")
		}

		for _, cpeStr := range cves.CPEs(cve) {
			cpe, ok := cves.ParseCPE(cpeStr)
			if !ok {
				Logger.Infof("Failed to parse CPE %s: %v", cpeStr, err)
			}
			if cpe.Part == "a" {
				Logger.Infof("\t * vendor=%s, product=%s", cpe.Vendor, cpe.Product)
				if patchRefs == 0 {
					repo := MaybeGetSourceRepoFromDebian(*debianMetadataPath, cpe.Product)
					if repo != "" {
						Logger.Infof("Derived repo: %s", repo)
					}
				}
			}
		}
	}
}
