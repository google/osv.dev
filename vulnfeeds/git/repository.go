// Package git implements utility routines for operating on remote Git repositories.
package git

import (
	"sort"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/storage/memory"
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
	sort.Sort(versions)
	if repoTagsCache != nil {
		*repoTagsCache = make(map[string]Versions)
		(*repoTagsCache)[repoURL] = versions
	}
	return versions, nil
}
