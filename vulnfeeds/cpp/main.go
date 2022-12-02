package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path/filepath"

	"cloud.google.com/go/logging"
	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/utility"
	"github.com/google/osv/vulnfeeds/vulns"
)

const (
	projectId = "oss-vdb"
	extension = ".json"
)

var Logger utility.LoggerWrapper
var Metrics struct {
	TotalCVEs           int
	CVEsForApplications int
	CVEsForKnownRepos   int
	OSVRecordsGenerated int
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

// Takes an NVD CVE record and outputs an OSV file in the specified directory.
func CVEToOSV(CVE cves.CVEItem, directory string) error {
	CPEs := cves.CPEs(CVE)
	CPE, err := cves.ParseCPE(CPEs[0])
	if err != nil {
		return fmt.Errorf("Can't generate an OSV record for %s without valid CPE data", CVE.CVE.CVEDataMeta.ID)
	}
	v, _ := vulns.FromCVE(CVE.CVE.CVEDataMeta.ID, CVE)
	versions, _ := cves.ExtractVersionInfo(CVE, nil)
	affected := vulns.Affected{}
	affected.AttachExtractedVersionInfo(versions)
	v.Affected = append(v.Affected, affected)

	if len(v.Affected[0].Ranges) == 0 {
		return fmt.Errorf("No affected versions detected for %s for %q", CVE.CVE.CVEDataMeta.ID, CPE.Product)
	}

	vulnDir := filepath.Join(directory, CPE.Vendor, CPE.Product)
	err = os.MkdirAll(vulnDir, 0755)
	if err != nil {
		Logger.Warnf("Failed to create dir: %v", err)
		return fmt.Errorf("Failed to create dir: %v", err)
	}
	outputFile := filepath.Join(vulnDir, v.ID+extension)
	f, err := os.Create(outputFile)
	if err != nil {
		Logger.Warnf("Failed to open %s for writing: %v", outputFile, err)
		return fmt.Errorf("Failed to open %s for writing: %v", outputFile, err)
	}
	defer f.Close()
	err = v.ToJSON(f)
	if err != nil {
		Logger.Warnf("Failed to write %s: %v", outputFile, err)
		return fmt.Errorf("Failed to write %s: %v", outputFile, err)
	}
	Logger.Infof("Processed %s for %q", CVE.CVE.CVEDataMeta.ID, CPE.Product)
	return nil
}

func main() {
	jsonPath := flag.String("nvd_json", "", "Path to NVD CVE JSON to examine.")
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

	// TODO(apollock): preload with CPE Dictionary preprocessed JSON
	VPRepoCache := make(map[string]map[string]string)

	for _, cve := range parsed.CVEItems {
		refs := cve.CVE.References.ReferenceData
		CPEs := cves.CPEs(cve)
		ReposForCVE := make(map[string]string)

		if len(refs) == 0 && len(CPEs) == 0 {
			Logger.Infof("FYI: skipping %s due to:", cve.CVE.CVEDataMeta.ID)
			Logger.Infof("\t * lack of CPEs and lack of references")
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

		Metrics.CVEsForApplications++

		Logger.Infof("%s", cve.CVE.CVEDataMeta.ID)
		for _, ref := range refs {
			// Are any of the reference's tags 'Patch'?
			for _, tag := range ref.Tags {
				if tag == "Third Party Advisory" {
					continue
				}
				if utility.IsRepoURL(ref.URL) {
					Logger.Infof("\t * %s", ref.URL)
					// CVE entries have one set of references, but can have multiple CPEs
					for _, CPEstr := range cves.CPEs(cve) {
						CPE, err := cves.ParseCPE(CPEstr)
						if err != nil {
							Logger.Warnf("Failed to parse CPE %q: %+v", CPEstr, err)
							continue
						}
						if _, ok := VPRepoCache[CPE.Vendor][CPE.Product]; !ok {
							repo, err := cves.Repo(ref.URL)
							if err != nil {
								Logger.Warnf("Failed to parse %q for %q: %+v", ref.URL, CPE.Product, err)
								continue
							}
							VPRepoCache[CPE.Vendor] = map[string]string{CPE.Product: repo}
						}
						// Avoid unnecessary calls to cves.Repo() if we already have the repo
						if _, ok := ReposForCVE[cve.CVE.CVEDataMeta.ID]; !ok {
							ReposForCVE[cve.CVE.CVEDataMeta.ID] = VPRepoCache[CPE.Vendor][CPE.Product]
						}
					}
				}
			}
		}

		Logger.Infof("Summary for %s: [CPEs=%d AppCPEs=%d DerivedRepos=%d]", cve.CVE.CVEDataMeta.ID, len(CPEs), appCPECount, len(ReposForCVE))
		Logger.Infof("Repos: %#v", ReposForCVE)

		// If we've made it to here, we may have a CVE:
		// * that has Application-related CPEs (so applies to software)
		// * has a reference that is a known repository URL
		// OR
		// * a derived repository for the software package
		//
		// We do not yet have:
		// * any knowledge of the language used
		// * definitive version information

		if _, ok := ReposForCVE[cve.CVE.CVEDataMeta.ID]; !ok {
			// We have nothing useful to work with, so we'll assume it's out of scope
			Logger.Infof("FYI: Passing on %s due to lack of viable repository", cve.CVE.CVEDataMeta.ID)
			continue
		}

		if !InScopeRepo(ReposForCVE[cve.CVE.CVEDataMeta.ID]) {
			continue
		}

		err := CVEToOSV(cve, *outDir)
		if err != nil {
			// Could we have potentially generated an OSV record by further analysis of a repo?
			if _, ok := ReposForCVE[cve.CVE.CVEDataMeta.ID]; ok {
				Metrics.CVEsForKnownRepos++
			}
			Logger.Warnf("Failed to generate an OSV record for %s: %+v", cve.CVE.CVEDataMeta.ID, err)
			continue
		}
		Metrics.OSVRecordsGenerated++
	}
	Metrics.TotalCVEs = len(parsed.CVEItems)
	Logger.Infof("Metrics: %+v", Metrics)
}
