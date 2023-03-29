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
	"strings"

	"cloud.google.com/go/logging"

	"golang.org/x/exp/slices"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/git"
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
var RepoTagsCache git.RepoTagsCache
var Metrics struct {
	TotalCVEs           int
	CVEsForApplications int
	CVEsForKnownRepos   int
	OSVRecordsGenerated int
}

// References with these tags have been found to contain completely unrelated
// repositories and can be misleading as to the software's true repository,
// Currently empty due to undesired false positives reducing the number of
// valid records successfully converted.
var RefTagDenyList = []string{
	// "Exploit",
	// "Third Party Advisory",
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

// Examines repos and tries to convert versions to commits by treating them as Git tags.
// Takes a CVE ID string (for logging), cves.VersionInfo with AffectedVersions and
// no FixCommits and attempts to add FixCommits.
func GitVersionsToCommit(CVE string, versions cves.VersionInfo, repos []string, cache git.RepoTagsCache) (v cves.VersionInfo, e error) {
	// versions is a VersionInfo with AffectedVersions and no FixCommits
	// v is a VersionInfo with FixCommits included
	v = versions
	for _, repo := range repos {
		normalizedTags, err := git.NormalizeRepoTags(repo, cache)
		if err != nil {
			Logger.Warnf("[%s]: Failed to normalize tags for %s: %v", CVE, repo, err)
			continue
		}
		for _, av := range versions.AffectedVersions {
			if av.Introduced != "" {
				gc, err := git.VersionToCommit(av.Introduced, repo, normalizedTags)
				if err != nil {
					Logger.Warnf("[%s]: Failed to get a Git commit for introduced version %q from %q: %v", CVE, av.Introduced, repo, err)
					continue
				}
				Logger.Infof("[%s]: Successfully derived %+v for introduced version %q", CVE, gc, av.Introduced)
				v.IntroducedCommits = append(v.IntroducedCommits, gc)
			}
			if av.Fixed != "" {
				gc, err := git.VersionToCommit(av.Fixed, repo, normalizedTags)
				if err != nil {
					Logger.Warnf("[%s]: Failed to get a Git commit for fixed version %q from %q: %v", CVE, av.Fixed, repo, err)
					continue
				}
				Logger.Infof("[%s]: Successfully derived %+v for fixed version %q", CVE, gc, av.Fixed)
				v.FixCommits = append(v.FixCommits, gc)
			}
			if av.LastAffected != "" {
				gc, err := git.VersionToCommit(av.LastAffected, repo, normalizedTags)
				if err != nil {
					Logger.Warnf("[%s]: Failed to get a Git commit for last_affected version %q from %q: %v", CVE, av.LastAffected, repo, err)
					continue
				}
				Logger.Infof("[%s]: Successfully derived %+v for last_affected version %q", CVE, gc, av.LastAffected)
				v.LastAffectedCommits = append(v.LastAffectedCommits, gc)
			}
		}
	}
	return v, nil
}

func refAcceptable(ref cves.CVEReferenceData, tagDenyList []string) bool {
	for _, deniedTag := range tagDenyList {
		if slices.Contains(ref.Tags, deniedTag) {
			return false
		}
	}
	return true
}

// Examines the CVE references for a CVE's CPE and derives repos for it.
func ReposForCPE(CVE string, cache VendorProductToRepoMap, vp VendorProduct, refs []cves.CVEReferenceData, tagDenyList []string) (repos []string) {
	// This currently only gets called for cache misses, but make it not rely on that assumption.
	if cachedRepos, ok := cache[vp]; ok {
		return cachedRepos
	}
	for _, ref := range refs {
		// If any of the denylist tags are in the ref's tag set, it's out of consideration.
		if !refAcceptable(ref, tagDenyList) {
			// Also remove it if previously added under an acceptable tag.
			maybeRemoveFromVPRepoCache(cache, vp, ref.URL)
			Logger.Infof("[%s]: disregarding %q for %q due to a denied tag in %q", CVE, ref.URL, vp, ref.Tags)
			break
		}
		repo, err := cves.Repo(ref.URL)
		if err != nil {
			// Failed to parse as a valid repo.
			continue
		}
		repos = append(repos, repo)
		maybeUpdateVPRepoCache(cache, vp, repo)
	}
	return repos
}

// Takes an NVD CVE record and outputs an OSV file in the specified directory.
func CVEToOSV(CVE cves.CVEItem, repos []string, cache git.RepoTagsCache, directory string) error {
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
		Logger.Infof("[%s]: Trying to convert version tags %+v to commits using %v", CVE.CVE.CVEDataMeta.ID, versions.AffectedVersions, repos)
		versions, err = GitVersionsToCommit(CVE.CVE.CVEDataMeta.ID, versions, repos, cache)
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

// Adds the repo to the cache for the Vendor/Product combination if not already present.
func maybeUpdateVPRepoCache(cache VendorProductToRepoMap, vp VendorProduct, repo string) {
	if slices.Contains(cache[vp], repo) {
		return
	}
	cache[vp] = append(cache[vp], repo)
}

// Removes the repo from the cache for the Vendor/Product combination if already present.
func maybeRemoveFromVPRepoCache(cache VendorProductToRepoMap, vp VendorProduct, repo string) {
	cacheEntry, ok := cache[vp]
	if !ok {
		return
	}
	if !slices.Contains(cacheEntry, repo) {
		return
	}
	i := slices.Index(cacheEntry, repo)
	if i == -1 {
		return
	}
	// If there is only one entry, delete the entry cache entry.
	if len(cacheEntry) == 1 {
		delete(cache, vp)
		return
	}
	slices.Delete(cacheEntry, i, i)
	cache[vp] = cacheEntry
}

func main() {
	jsonPath := flag.String("nvd_json", "", "Path to NVD CVE JSON to examine.")
	parsedCPEDictionary := flag.String("cpe_repos", "", "Path to JSON mapping of CPEs to repos generated by cperepos")
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
			// This CVE is not for software, skip.
			continue
		}

		Metrics.CVEsForApplications++

		// We only need to do this if we didn't get a repo from the CPE Dictionary.
		// TODO: check if this can be merged into the CPE loop above.
		if _, ok := ReposForCVE[cve.CVE.CVEDataMeta.ID]; !ok && len(refs) > 0 {
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
				repos := ReposForCPE(cve.CVE.CVEDataMeta.ID, VPRepoCache, VendorProduct{CPE.Vendor, CPE.Product}, refs, RefTagDenyList)
				if len(repos) == 0 {
					Logger.Warnf("[%s]: Failed to derive any repos for %q %q", cve.CVE.CVEDataMeta.ID, CPE.Vendor, CPE.Product)
					continue
				}
				Logger.Infof("[%s]: Derived %q for %q %q", cve.CVE.CVEDataMeta.ID, repos, CPE.Vendor, CPE.Product)
				ReposForCVE[cve.CVE.CVEDataMeta.ID] = repos
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

		err := CVEToOSV(cve, ReposForCVE[cve.CVE.CVEDataMeta.ID], RepoTagsCache, *outDir)
		if err != nil {
			Logger.Warnf("Failed to generate an OSV record for %s: %+v", cve.CVE.CVEDataMeta.ID, err)
			continue
		}
		Metrics.OSVRecordsGenerated++
	}
	Metrics.TotalCVEs = len(parsed.CVEItems)
	Logger.Infof("Metrics: %+v", Metrics)
}
