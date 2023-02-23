// Package git implements utility routines for operating on remote Git repositories.
package git

import (
	"sort"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/storage/memory"

	"golang.org/x/exp/maps"

	"github.com/google/osv/vulnfeeds/cves"
)

// A GitTag holds a Git tag and corresponding commit hash.
type Tag struct {
	Tag    string // Git tag
	Commit string // Git commit hash
}

type Tags []Tag

func (t Tags) Len() int           { return len(t) }
func (t Tags) Less(i, j int) bool { return t[i].Tag < t[j].Tag }
func (t Tags) Swap(i, j int)      { t[i], t[j] = t[j], t[i] }

type NormalizedTag struct {
	OriginalTag string
	Commit      string
}

// RepoTagsMap acts as a cache for RepoTags results, keyed on the repo's URL.
// repo URL -> Tag -> GitTag
type RepoTagsMap struct {
	Tag           map[string]Tag
	NormalizedTag map[string]NormalizedTag
}

// RepoTags acts as a cache for RepoTags results, keyed on the repo's URL.
type RepoTagsCache map[string]RepoTagsMap

// RepoTags returns an array of Tag being the tags and associated commits in repoURL.
// An optional repoTagsCache can be supplied to reduce repeated remote connections to the same repo.
func RepoTags(repoURL string, repoTagsCache RepoTagsCache) (tags Tags, e error) {
	if repoTagsCache != nil {
		tags, ok := repoTagsCache[repoURL]
		if ok {
			return maps.Values(tags.Tag), nil
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
		return tags, err
	}
	tagsMap := make(map[string]Tag)
	for _, ref := range refs {
		if !ref.Name().IsTag() {
			continue
		}
		tags = append(tags, Tag{Tag: ref.Name().Short(), Commit: ref.Hash().String()})
		tagsMap[ref.Name().Short()] = Tag{Tag: ref.Name().Short(), Commit: ref.Hash().String()}
	}
	// Sort so that we get consistently ordered output for test validation purposes.
	sort.Sort(tags)
	if repoTagsCache != nil {
		repoTagsCache[repoURL] = RepoTagsMap{Tag: tagsMap, NormalizedTag: nil}
	}
	return tags, nil
}

// NormalizeRepoTags returns a map of normalized tags mapping back to original tags and also commit hashes.
// An optional repoTagsCache can be supplied to reduce repeated remote connections to the same repo.
func NormalizeRepoTags(repoURL string, repoTagsCache RepoTagsCache) (NormalizedTags map[string]NormalizedTag, e error) {
	if repoTagsCache != nil {
		tags, ok := repoTagsCache[repoURL]
		if ok && tags.NormalizedTag != nil {
			return tags.NormalizedTag, nil
		}
	}
	// Cache miss.
	tags, err := RepoTags(repoURL, repoTagsCache)
	if err != nil {
		return nil, err
	}
	NormalizedTags = make(map[string]NormalizedTag)
	for _, t := range tags {
		normalizedTag, err := cves.Normalize(t.Tag)
		if err != nil {
			// It's conceivable that not all tags are normalizable or potentially versions.
			continue
		}
		NormalizedTags[normalizedTag] = NormalizedTag{OriginalTag: t.Tag, Commit: t.Commit}
	}
	if repoTagsCache != nil {
		// The RepoTags() call above will have cached the Tag map already
		tagsMap := repoTagsCache[repoURL].Tag
		repoTagsCache[repoURL] = RepoTagsMap{Tag: tagsMap, NormalizedTag: NormalizedTags}
	}
	return NormalizedTags, nil
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
