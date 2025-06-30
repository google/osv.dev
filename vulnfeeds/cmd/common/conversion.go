package common

import (
	"slices"
	"strings"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/utility"
)

// References with these tags have been found to contain completely unrelated
// repositories and can be misleading as to the software's true repository,
// Currently not used for this purpose due to undesired false positives
// reducing the number of valid records successfully converted.
var RefTagDenyList = []string{
	// "Exploit",
	// "Third Party Advisory",
	"Broken Link", // Actively ignore these though.
}

// VendorProducts known not to be Open Source software and causing
// cross-contamination of repo derivation between CVEs.
var VendorProductDenyList = []VendorProduct{
	// Causes a chain reaction of incorrect associations from CVE-2022-2068
	// {"netapp", "ontap_select_deploy_administration_utility"},
	// Causes misattribution for Python, e.g. CVE-2022-26488
	// {"netapp", "active_iq_unified_manager"},
	// Causes misattribution for OpenSSH, e.g. CVE-2021-28375
	// {"netapp", "cloud_backup"},
	// Three strikes and the entire netapp vendor is out...
	{"netapp", ""},
	// [CVE-2021-28957]: Incorrectly associates with github.com/lxml/lxml
	{"oracle", "zfs_storage_appliance_kit"},
	{"gradle", "enterprise"}, // The OSS repo gets mis-attributed via CVE-2020-15767
}

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

func RefAcceptable(ref cves.Reference, tagDenyList []string) bool {
	for _, deniedTag := range tagDenyList {
		if slices.Contains(ref.Tags, deniedTag) {
			return false
		}
	}
	return true
}

// Adds the repo to the cache for the Vendor/Product combination if not already present.
func MaybeUpdateVPRepoCache(cache VendorProductToRepoMap, vp *VendorProduct, repo string) {
	if cache == nil || vp == nil {
		return
	}
	if slices.Contains(cache[*vp], repo) {
		return
	}
	// Avoid poluting the cache with existant-but-useless repos.
	if git.ValidRepoAndHasUsableRefs(repo) {
		cache[*vp] = append(cache[*vp], repo)
	}
}

// Removes the repo from the cache for the Vendor/Product combination if already present.
func MaybeRemoveFromVPRepoCache(cache VendorProductToRepoMap, vp *VendorProduct, repo string) {
	if cache == nil || vp == nil {
		return
	}
	cacheEntry, ok := cache[*vp]
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
		delete(cache, *vp)
		return
	}
	cacheEntry = slices.Delete(cacheEntry, i, i+1)
	cache[*vp] = cacheEntry
}

// Examines repos and tries to convert versions to commits by treating them as Git tags.
// Takes a CVE ID string (for logging), cves.VersionInfo with AffectedVersions and
// typically no AffectedCommits and attempts to add AffectedCommits (including Fixed commits) where there aren't any.
// Refuses to add the same commit to AffectedCommits more than once.
func GitVersionsToCommits(CVE cves.CVEID, versions models.VersionInfo, repos []string, cache git.RepoTagsCache, Logger utility.LoggerWrapper) (v models.VersionInfo, e error) {
	// versions is a VersionInfo with AffectedVersions and typically no AffectedCommits
	// v is a VersionInfo with AffectedCommits (containing Fixed commits) included
	v = versions
	for _, repo := range repos {
		normalizedTags, err := git.NormalizeRepoTags(repo, cache)
		if err != nil {
			Logger.Warnf("[%s]: Failed to normalize tags for %s: %v", CVE, repo, err)
			continue
		}
		for _, av := range versions.AffectedVersions {
			Logger.Infof("[%s]: Attempting version resolution for %+v using %q", CVE, av, repo)
			introducedEquivalentCommit := ""
			if av.Introduced != "" {
				ac, err := git.VersionToCommit(av.Introduced, repo, models.Introduced, normalizedTags)
				if err != nil {
					Logger.Warnf("[%s]: Failed to get a Git commit for introduced version %q from %q: %v", CVE, av.Introduced, repo, err)
				} else {
					Logger.Infof("[%s]: Successfully derived %+v for introduced version %q", CVE, ac, av.Introduced)
					introducedEquivalentCommit = ac.Introduced
				}
			}
			// Only try and convert fixed versions to commits via tags if there aren't any Fixed commits already.
			// cves.ExtractVersionInfo() opportunistically returns
			// AffectedCommits (with Fixed commits) when the CVE has appropriate references, and assuming these references are indeed
			// Fixed commits, they're also assumed to be more precise than what may be derived from tag to commit mapping.
			fixedEquivalentCommit := ""
			if v.HasFixedCommits(repo) && av.Fixed != "" {
				Logger.Infof("[%s]: Using preassumed fixed commits %+v instead of deriving from fixed version %q", CVE, v.FixedCommits(repo), av.Fixed)
			} else if av.Fixed != "" {
				ac, err := git.VersionToCommit(av.Fixed, repo, models.Fixed, normalizedTags)
				if err != nil {
					Logger.Warnf("[%s]: Failed to get a Git commit for fixed version %q from %q: %v", CVE, av.Fixed, repo, err)
				} else {
					Logger.Infof("[%s]: Successfully derived %+v for fixed version %q", CVE, ac, av.Fixed)
					fixedEquivalentCommit = ac.Fixed
				}
			}
			// Only try and convert last_affected versions to commits via tags if there aren't any Fixed commits already (to maintain schema compliance).
			// cves.ExtractVersionInfo() opportunistically returns
			// AffectedCommits (with Fixed commits) when the CVE has appropriate references.
			lastAffectedEquivalentCommit := ""
			if !v.HasFixedCommits(repo) && av.LastAffected != "" {
				ac, err := git.VersionToCommit(av.LastAffected, repo, models.LastAffected, normalizedTags)
				if err != nil {
					Logger.Warnf("[%s]: Failed to get a Git commit for last_affected version %q from %q: %v", CVE, av.LastAffected, repo, err)
				} else {
					Logger.Infof("[%s]: Successfully derived %+v for last_affected version %q", CVE, ac, av.LastAffected)
					lastAffectedEquivalentCommit = ac.LastAffected
				}
			}
			// Assemble a single AffectedCommit from what was resolved, iff it
			// doesn't result in a half-resolved (false positive-causing)
			// situation with a successfully resolved introduced version and an
			// unsuccessfully resolved fixed or last_affected version.
			ac := models.AffectedCommit{}
			if fixedEquivalentCommit != "" || lastAffectedEquivalentCommit != "" {
				ac.SetRepo(repo)
				if introducedEquivalentCommit != "" {
					ac.SetIntroduced(introducedEquivalentCommit)
				}
				ac.SetFixed(fixedEquivalentCommit)
				ac.SetLastAffected(lastAffectedEquivalentCommit)
			}
			if ac == (models.AffectedCommit{}) {
				// Nothing resolved, move on to the next AffectedVersion
				Logger.Warnf("[%s]: Sufficient resolution not possible for %+v", CVE, av)
				continue
			}
			if ac.InvalidRange() {
				Logger.Warnf("[%s]: Invalid range: %#v", CVE, ac)
				continue
			}
			if v.Duplicated(ac) {
				Logger.Warnf("[%s]: Duplicate: %#v already present in %#v", CVE, ac, v)
				continue
			}
			v.AffectedCommits = append(v.AffectedCommits, ac)
		}
	}
	return v, nil
}

// Examines the CVE references for a CVE and derives repos for it, optionally caching it.
func ReposFromReferences(CVE string, cache VendorProductToRepoMap, vp *VendorProduct, refs []cves.Reference, tagDenyList []string, Logger utility.LoggerWrapper) (repos []string) {
	for _, ref := range refs {
		// If any of the denylist tags are in the ref's tag set, it's out of consideration.
		if !RefAcceptable(ref, tagDenyList) {
			// Also remove it if previously added under an acceptable tag.
			MaybeRemoveFromVPRepoCache(cache, vp, ref.Url)
			Logger.Infof("[%s]: disregarding %q for %q due to a denied tag in %q", CVE, ref.Url, vp, ref.Tags)
			continue
		}
		repo, err := cves.Repo(ref.Url)
		if err != nil {
			// Failed to parse as a valid repo.
			continue
		}
		if slices.Contains(repos, repo) {
			continue
		}
		// If the reference is a commit URL, the repo is inherently useful (but only if the repo still ultimately works).
		_, err = cves.Commit(ref.Url)
		// If it's any other repo-shaped URL, it's only useful if it has tags.
		if (err == nil && !git.ValidRepo(repo)) || (err != nil && !git.ValidRepoAndHasUsableRefs(repo)) {
			continue
		}
		repos = append(repos, repo)
		MaybeUpdateVPRepoCache(cache, vp, repo)
	}
	if vp != nil {
		Logger.Infof("[%s]: Derived %q for %q %q using references", CVE, repos, vp.Vendor, vp.Product)
	} else {
		Logger.Infof("[%s]: Derived %q (no CPEs) using references", CVE, repos)
	}

	return repos
}
