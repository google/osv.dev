// Package git implements utility routines for operating on remote Git repositories.
package git

import (
	"sort"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/google/osv/vulnfeeds/cves"
)

// A version holds a tag and corresponding commit hash.
type Version struct {
	Tag    string // Git tag
	Commit string // Git commit hash
}

// Versions is an ordered array of Version.
type Versions []Version

func (v Versions) Len() int           { return len(v) }
func (v Versions) Less(i, j int) bool { return v[i].Tag < v[j].Tag }
func (v Versions) Swap(i, j int)      { v[i], v[j] = v[j], v[i] }

// RepoTagsMap acts as a cache for RepoTags results, keyed on the repo's URL.
type RepoTagsMap map[string]Versions

// NormalizedRepoTagsMap allows for looking up a repo's tags by normalized values.
// A composite struct key of repo and normalized tag is not used to allow for
// fuzzy matches on all available normalized versions for a given repo
type NormalizedRepoTagsMap map[string]map[string]Version

// RepoTags returns an array of Versions being the tags and associated commits in repoURL.
// An optional repoTagsCache can be supplied to reduce repeated remote connections to the same repo.
func RepoTags(repoURL string, repoTagsCache *RepoTagsMap) (versions Versions, e error) {
	if repoTagsCache != nil {
		versions, ok := (*repoTagsCache)[repoURL]
		if ok {
			return versions, nil
		}
	}
	// Cache miss.
	remoteConfig := &config.RemoteConfig{
		Name: "source",
		URLs: []string{
			repoURL,
		},
	}
	repo := git.NewRemote(memory.NewStorage(), remoteConfig)
	refs, err := repo.List(&git.ListOptions{})
	if err != nil {
		return versions, err
	}
	for _, ref := range refs {
		if !ref.Name().IsTag() {
			continue
		}
		v := Version{Tag: ref.Name().Short(), Commit: ref.Hash().String()}
		versions = append(versions, v)
	}
	// Sort so that we get consistently ordered output for test validation purposes.
	sort.Sort(versions)
	if repoTagsCache != nil {
		*repoTagsCache = make(map[string]Versions)
		(*repoTagsCache)[repoURL] = versions
	}
	return versions, nil
}

// NormalizeRepoTags populates a durable mapping of tags to Versions for lookup by normalized tag.
func NormalizeRepoTags(repoURL string, normalizedRepoTags NormalizedRepoTagsMap, repoTagsCache *RepoTagsMap) (e error) {
	versions, err := RepoTags(repoURL, repoTagsCache)
	if err != nil {
		return err
	}
	repoVersion, ok := normalizedRepoTags[repoURL]
	if !ok {
		repoVersion = make(map[string]Version)
		normalizedRepoTags[repoURL] = repoVersion
	}
	for _, v := range versions {
		normalizedVersion, err := cves.Normalize(v.Tag)
		if err != nil {
			// It's conceivable that not all tags are normalizable or potentially versions.
			continue
		}
		repoVersion, _ := normalizedRepoTags[repoURL]
		repoVersion[normalizedVersion] = v
	}
	return nil
}

// Validate the repo by attempting to query it's references.
func ValidRepo(repoURL string) (valid bool, e error) {
	remoteConfig := &config.RemoteConfig{
		Name: "source",
		URLs: []string{
			repoURL,
		},
	}
	r := git.NewRemote(memory.NewStorage(), remoteConfig)
	_, err := r.List(&git.ListOptions{})
	if err != nil && err == transport.ErrAuthenticationRequired {
		// somewhat strangely, we get an authentication prompt via Git on non-existent repos.
		return false, nil
	}
	if err != nil {
		return false, nil
	}
	return true, nil
}
