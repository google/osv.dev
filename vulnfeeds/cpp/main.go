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
	"path"
	"path/filepath"
	"strings"

	"cloud.google.com/go/logging"
	"github.com/go-git/go-git/v5"
	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/utility"
	"github.com/google/osv/vulnfeeds/vulns"
)

type VendorProduct struct {
	Vendor  string
	Product string
}

type VendorProductToRepoMap map[VendorProduct][]string

func (vp *VendorProduct) UnmarshalText(text []byte) error {
	s := strings.Split(string(text), ":")
	vp.Vendor = s[0]
	vp.Product = s[1]
	return nil
}

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

func GetRepoDir(repoURL string, repobasedir string) string {
	parsedURL, err := url.Parse(repoURL)
	if err != nil {
		return ""
	}
	return path.Join(repobasedir, parsedURL.Hostname(), parsedURL.Path)
}

// Either clones the repository or returns the one previously cloned.
func GetRepo(repoURL string, repobasedir string) (r *git.Repository, e error) {
	repodir := GetRepoDir(repoURL, repobasedir)
	// TODO: reorder to open, then clone, once behaviour and failure modes understood
	Logger.Infof("Cloning %s", repoURL)
	r, err := git.PlainClone(repodir, false, &git.CloneOptions{
		URL: repoURL,
	})
	if err != nil && err != git.ErrRepositoryAlreadyExists {
		return nil, err
	}
	r, err = git.PlainOpen(repodir)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Examines repos and tries to convert version tags to commits
func GitVersionToCommit(versions cves.VersionInfo, repos []string, repobasedir string) (v cves.VersionInfo, e error) {
	// versions is a VersionInfo with AffectedVersions and no FixCommits
	// v is a VersionInfo with FixCommits included
	v = versions
	for _, repo := range repos {
		r, err := GetRepo(repo, repobasedir)
		if err != nil {
			Logger.Warnf("Failed to get %s: %v", repo, err)
			continue
		}
		for _, av := range versions.AffectedVersions {
			// We can't map a non-existent version to a tag and commit, so skip.
			if av.Fixed == "" {
				continue
			}
			// TODO: add more sophisticated (fuzzy) version to tag matching.
			ref, err := r.Tag("v" + av.Fixed)
			if err != nil {
				Logger.Warnf("Failed to find a tag for %q in %s: %v", av.Fixed, repo, err)
				continue
			}
			fc := cves.FixCommit{
				Repo:   repo,
				Commit: ref.Hash().String(),
			}
			v.FixCommits = append(v.FixCommits, fc)
		}
	}
	return v, nil
}

// Takes an NVD CVE record and outputs an OSV file in the specified directory.
func CVEToOSV(CVE cves.CVEItem, repos []string, repobasedir string, directory string) error {
	CPEs := cves.CPEs(CVE)
	CPE, err := cves.ParseCPE(CPEs[0])
	if err != nil {
		return fmt.Errorf("Can't generate an OSV record for %s without valid CPE data", CVE.CVE.CVEDataMeta.ID)
	}
	v, notes := vulns.FromCVE(CVE.CVE.CVEDataMeta.ID, CVE)
	versions, versionNotes := cves.ExtractVersionInfo(CVE, nil)
	notes = append(notes, versionNotes...)

	if len(versions.FixCommits) == 0 && len(versions.AffectedVersions) != 0 {
		// We have some versions to try and convert to commits
		if len(repos) == 0 {
			return fmt.Errorf("No affected ranges for %s for %q, and no repos to try and convert %+v to tags with", CVE.CVE.CVEDataMeta.ID, CPE.Product, versions.AffectedVersions)
		}
		if repobasedir != "" {
			Logger.Infof("[%s]: Trying to convert version tags %+v to commits using %v", CVE.CVE.CVEDataMeta.ID, versions.AffectedVersions, repos)
			versions, err = GitVersionToCommit(versions, repos, repobasedir)
		}
	}

	affected := vulns.Affected{}
	affected.AttachExtractedVersionInfo(versions)
	v.Affected = append(v.Affected, affected)

	if len(v.Affected[0].Ranges) == 0 {
		return fmt.Errorf("No affected ranges detected for %s for %q", CVE.CVE.CVEDataMeta.ID, CPE.Product)
	}

	vulnDir := filepath.Join(directory, CPE.Vendor, CPE.Product)
	err = os.MkdirAll(vulnDir, 0755)
	if err != nil {
		Logger.Warnf("Failed to create dir: %v", err)
		return fmt.Errorf("Failed to create dir: %v", err)
	}
	outputFile := filepath.Join(vulnDir, v.ID+extension)
	notesFile := filepath.Join(vulnDir, v.ID+".notes")
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
	Logger.Infof("Generated OSV record from %s for %q", CVE.CVE.CVEDataMeta.ID, CPE.Product)
	if len(notes) > 0 {
		err = os.WriteFile(notesFile, []byte(strings.Join(notes, "\n")), 0660)
		if err != nil {
			Logger.Warnf("Failed to write %s: %v", notesFile, err)
		}
	}
	return nil
}

func loadCPEDictionary(ProductToRepo *VendorProductToRepoMap, f string) error {
	data, err := ioutil.ReadFile(f)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &ProductToRepo)
}

func main() {
	jsonPath := flag.String("nvd_json", "", "Path to NVD CVE JSON to examine.")
	parsedCPEDictionary := flag.String("cpe_repos", "", "Path to JSON mapping of CPEs to repos generated by cperepos")
	repoDir := flag.String("repo_dir", "", "Directory to use for repo clones.")
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

	VPRepoCache := make(VendorProductToRepoMap)

	if *parsedCPEDictionary != "" {
		err = loadCPEDictionary(&VPRepoCache, *parsedCPEDictionary)
		if err != nil {
			Logger.Fatalf("Failed to load parsed CPE dictionary: %v", err)
		}
		Logger.Infof("VendorProductToRepoMap cache has %d entries preloaded", len(VPRepoCache))
	}

	for _, cve := range parsed.CVEItems {
		refs := cve.CVE.References.ReferenceData
		CPEs := cves.CPEs(cve)
		ReposForCVE := make(map[string][]string)

		if len(refs) == 0 && len(CPEs) == 0 {
			Logger.Infof("[%s]: skipping due to lack of CPEs and lack of references", cve.CVE.CVEDataMeta.ID)
			continue
		}

		// Does it have any application CPEs? Look for pre-computed repos.
		appCPECount := 0
		for _, CPEstr := range cves.CPEs(cve) {
			CPE, err := cves.ParseCPE(CPEstr)
			if err != nil {
				Logger.Warnf("[%s]: Failed to parse CPE %q: %+v", cve.CVE.CVEDataMeta.ID, CPEstr, err)
				continue
			}
			if CPE.Part == "a" {
				appCPECount += 1
			}
			if _, ok := VPRepoCache[VendorProduct{CPE.Vendor, CPE.Product}]; ok {
				Logger.Infof("[%s]: Pre-references, derived %q for %q %q using cache", cve.CVE.CVEDataMeta.ID, VPRepoCache[VendorProduct{CPE.Vendor, CPE.Product}], CPE.Vendor, CPE.Product)
				ReposForCVE[cve.CVE.CVEDataMeta.ID] = VPRepoCache[VendorProduct{CPE.Vendor, CPE.Product}]
			}
		}

		if appCPECount == 0 {
			// Not software, skip.
			continue
		}

		Metrics.CVEsForApplications++

		// We only need to do this if we didn't get a repo from the CPE Dictionary.
		if _, ok := ReposForCVE[cve.CVE.CVEDataMeta.ID]; !ok {
			for _, ref := range refs {
				for _, tag := range ref.Tags {
					// Third Party Advisories often reference
					// completely unrelated repositories and can be
					// misleading as to the software's repository,
					// so disregard these references.
					if tag == "Third Party Advisory" {
						continue
					}
					if !utility.IsRepoURL(ref.URL) {
						continue
					}
					Logger.Infof("[%s]: examining %q [%q]", cve.CVE.CVEDataMeta.ID, ref.URL, tag)
					// CVE entries have one set of
					// references, but can have multiple
					// CPEs, so we have to consider them
					// all for each reference.
					for _, CPEstr := range cves.CPEs(cve) {
						CPE, err := cves.ParseCPE(CPEstr)
						if err != nil {
							Logger.Warnf("[%s]: Failed to parse CPE %q: %+v", cve.CVE.CVEDataMeta.ID, CPEstr, err)
							continue
						}
						// Continue to only focus on application CPEs.
						if CPE.Part != "a" {
							continue
						}
						// TODO: there's an opportunity to skip this
						repo, err := cves.Repo(ref.URL)
						if err != nil {
							Logger.Warnf("[%s]: Failed to parse %q for %q: %+v", cve.CVE.CVEDataMeta.ID, ref.URL, CPE.Product, err)
							continue
						}
						Logger.Infof("[%s]: Derived %q for %q %q from %q", cve.CVE.CVEDataMeta.ID, repo, CPE.Vendor, CPE.Product, ref.URL)
						VPRepoCache[VendorProduct{CPE.Vendor, CPE.Product}] = append(VPRepoCache[VendorProduct{CPE.Vendor, CPE.Product}], repo)
						if _, ok := ReposForCVE[cve.CVE.CVEDataMeta.ID]; !ok {
							ReposForCVE[cve.CVE.CVEDataMeta.ID] = VPRepoCache[VendorProduct{CPE.Vendor, CPE.Product}]
						}
					}
				}
			}
		}

		Logger.Infof("Summary for %s: [CPEs=%d AppCPEs=%d DerivedRepos=%d]", cve.CVE.CVEDataMeta.ID, len(CPEs), appCPECount, len(ReposForCVE[cve.CVE.CVEDataMeta.ID]))
		Logger.Infof("[%s]: Repos: %#v", cve.CVE.CVEDataMeta.ID, ReposForCVE)

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

		for _, repo := range ReposForCVE[cve.CVE.CVEDataMeta.ID] {
			if !InScopeRepo(repo) {
				continue
			}
		}

		Metrics.CVEsForKnownRepos++

		err := CVEToOSV(cve, ReposForCVE[cve.CVE.CVEDataMeta.ID], *repoDir, *outDir)
		if err != nil {
			Logger.Warnf("Failed to generate an OSV record for %s: %+v", cve.CVE.CVEDataMeta.ID, err)
			continue
		}
		Metrics.OSVRecordsGenerated++
	}
	Metrics.TotalCVEs = len(parsed.CVEItems)
	Logger.Infof("Metrics: %+v", Metrics)
}
