// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package git implements utility routines for operating on remote Git repositories and metadata.
package git

import (
	"context"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/sethvargo/go-retry"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"github.com/google/osv/vulnfeeds/cves"
)

const (
	peeledSuffix = "^{}"
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

// NormalizedTag holds a normalized (as by NormalizeRepoTags) tag and corresponding commit hash.
type NormalizedTag struct {
	OriginalTag string
	Commit      string
}

// RepoTagsMap holds all of the tags (naturally occurring and normalized) for a Git repo.
type RepoTagsMap struct {
	Tag           map[string]Tag           // The key is the original tag as seen on the repo.
	NormalizedTag map[string]NormalizedTag // The key is the normalized (as by NormalizeRepoTags) original tag.
}

// RepoTags acts as a cache for RepoTags results, keyed on the repo's URL.
type RepoTagsCache map[string]RepoTagsMap

// RemoteRepoRefsWithRetry will exponentially retry listing the peeled references of the repoURL up to retries times.
func RemoteRepoRefsWithRetry(repoURL string, retries uint64) (refs []*plumbing.Reference, err error) {
	remoteConfig := &config.RemoteConfig{
		Name: "source",
		URLs: []string{
			repoURL,
		},
	}
	repo := git.NewRemote(memory.NewStorage(), remoteConfig)

	ctx := context.Background()

	backoff := retry.NewExponential(1 * time.Second)
	backoff = retry.WithMaxRetries(retries, backoff)

	if err := retry.Do(ctx, backoff, func(ctx context.Context) error {
		refs, err = repo.List(&git.ListOptions{PeelingOption: git.AppendPeeled})
		if err != nil {
			if err == context.DeadlineExceeded {
				return retry.RetryableError(err)
			}
			return err
		}
		return nil
	}); err != nil {
		return refs, err
	}
	return refs, nil
}

// RepoName returns name of a repo based off the URL for it.
func RepoName(repoURL string) (name string, e error) {
	u, err := url.Parse(repoURL)
	if err != nil {
		return "", err
	}
	assumedReponame := strings.ToLower(path.Base(u.Path))
	name = strings.TrimSuffix(assumedReponame, ".git")
	return name, nil
}

// RepoTags returns an array of Tag being the (unpeeled, if annotated) tags and associated commits in repoURL.
// An optional repoTagsCache can be supplied to reduce repeated remote connections to the same repo.
func RepoTags(repoURL string, repoTagsCache RepoTagsCache) (tags Tags, e error) {
	if repoTagsCache != nil {
		tags, ok := repoTagsCache[repoURL]
		if ok {
			return maps.Values(tags.Tag), nil
		}
	}
	// Cache miss.
	refs, err := RemoteRepoRefsWithRetry(repoURL, 3)
	if err != nil {
		return tags, err
	}
	tagsMap := make(map[string]Tag)
	for _, ref := range refs {
		if !ref.Name().IsTag() {
			continue
		}
		// This is used for caching and direct lookup by tag name.
		tagsMap[ref.Name().Short()] = Tag{Tag: ref.Name().Short(), Commit: ref.Hash().String()}
	}
	// Use the unpeeled tag commit where available.
	for tagName, tagInfo := range tagsMap {
		if _, ok := tagsMap[tagName+peeledSuffix]; ok {
			// There exists an equivalent peeled tag, skip the unpeeled one.
			continue
		}
		if strings.HasSuffix(tagName, peeledSuffix) {
			// Use the peeled tag name, but the unpeeled tag's commit.
			tags = append(tags, Tag{Tag: strings.TrimSuffix(tagInfo.Tag, peeledSuffix), Commit: tagInfo.Commit})
			continue
		}
		// It's a lightweight tag, and if not already present (as an unpeeled tag, add it)
		if !slices.Contains(tags, Tag{Tag: tagInfo.Tag, Commit: tagInfo.Commit}) {
			tags = append(tags, Tag{Tag: tagInfo.Tag, Commit: tagInfo.Commit})
		}
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
	assumedReponame, err := RepoName(repoURL)
	if err != nil {
		return nil, err
	}
	tags, err := RepoTags(repoURL, repoTagsCache)
	if err != nil {
		return nil, err
	}
	NormalizedTags = make(map[string]NormalizedTag)
	for _, t := range tags {
		// Opportunistically remove parts determined to match the repo name,
		// to ease particularly difficult to normalize cases like 'openj9-0.38.0'.
		prenormalizedTag := strings.TrimPrefix(strings.ToLower(t.Tag), assumedReponame)
		prenormalizedTag = strings.TrimPrefix(prenormalizedTag, "-")
		normalizedTag, err := cves.NormalizeVersion(prenormalizedTag)
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
func ValidRepo(repoURL string) (valid bool) {
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
		return false
	}
	if err != nil {
		return false
	}
	return true
}
