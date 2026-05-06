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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/sethvargo/go-retry"
)

const (
	peeledSuffix = "^{}"
)

var ErrRateLimit = errors.New("rate limit exceeded")

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
	OriginalTag        string
	Commit             string
	MatchesVersionText bool
}

// RepoTagsMap holds all of the tags (naturally occurring and normalized) for a Git repo.
type RepoTagsMap struct {
	Tag           map[string]Tag           // The key is the original tag as seen on the repo.
	NormalizedTag map[string]NormalizedTag // The key is the normalized (as by NormalizeRepoTags) original tag.
}

// RepoTagsCache acts as a cache for RepoTags results, keyed on the repo's URL.
type RepoTagsCache struct {
	sync.RWMutex

	m             map[string]RepoTagsMap
	invalid       map[string]bool
	canonicalLink map[string]string
}

func (c *RepoTagsCache) Get(repo string) (RepoTagsMap, bool) {
	c.RLock()
	defer c.RUnlock()
	if c.m == nil {
		return RepoTagsMap{}, false
	}
	tags, ok := c.m[repo]

	return tags, ok
}

func (c *RepoTagsCache) Set(repo string, tags RepoTagsMap) {
	c.Lock()
	defer c.Unlock()
	if c.m == nil {
		c.m = make(map[string]RepoTagsMap)
	}
	c.m[repo] = tags
}

func (c *RepoTagsCache) SetInvalid(repo string) {
	c.Lock()
	defer c.Unlock()
	if c.invalid == nil {
		c.invalid = make(map[string]bool)
	}
	c.invalid[repo] = true
}

func (c *RepoTagsCache) IsInvalid(repo string) bool {
	c.RLock()
	defer c.RUnlock()
	if c.invalid == nil {
		return false
	}

	return c.invalid[repo]
}

func (c *RepoTagsCache) SetCanonicalLink(repo string, canonicalLink string) {
	c.Lock()
	defer c.Unlock()
	if c.canonicalLink == nil {
		c.canonicalLink = make(map[string]string)
	}
	c.canonicalLink[repo] = canonicalLink
}

func (c *RepoTagsCache) GetCanonicalLink(repo string) (string, bool) {
	c.RLock()
	defer c.RUnlock()
	if c.canonicalLink == nil {
		return "", false
	}
	canonicalLink, ok := c.canonicalLink[repo]

	return canonicalLink, ok
}

type GitterRef struct {
	Label string `json:"label"`
	Hash  string `json:"hash"` // base64-encoded bytes
}

type GitterTagsResponse struct {
	Tags []GitterRef `json:"tags"`
}

func gitterRepoRefs(repoURL string) ([]*plumbing.Reference, error) {
	gitterHost := os.Getenv("GITTER_HOST")
	if gitterHost == "" {
		return nil, errors.New("GITTER_HOST not set")
	}

	getTagsURL, err := url.JoinPath(gitterHost, "tags")
	if err != nil {
		return nil, fmt.Errorf("failed to join path: %w", err)
	}

	u, err := url.Parse(getTagsURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("url", repoURL)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("gitter request failed with status %s: %s", resp.Status, string(body))
	}

	var tagsResp GitterTagsResponse
	if err := json.NewDecoder(resp.Body).Decode(&tagsResp); err != nil {
		return nil, fmt.Errorf("failed to decode gitter response: %w", err)
	}

	refs := make([]*plumbing.Reference, 0, len(tagsResp.Tags))
	for _, t := range tagsResp.Tags {
		decodedHash, err := base64.StdEncoding.DecodeString(t.Hash)
		if err != nil {
			logger.Warn("failed to decode base64 hash from gitter", slog.String("tag", t.Label), slog.String("hash", t.Hash))
			continue
		}
		name := plumbing.ReferenceName("refs/tags/" + t.Label)
		ref := plumbing.NewHashReference(name, plumbing.NewHash(hex.EncodeToString(decodedHash)))
		refs = append(refs, ref)
	}

	return refs, nil
}

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
	backoff = newLoggingBackoff(backoff, "RemoteRepoRefs")

	if err := retry.Do(ctx, backoff, func(_ context.Context) error {
		refs, err = repo.List(&git.ListOptions{PeelingOption: git.AppendPeeled})
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return retry.RetryableError(err)
			}
			if strings.Contains(err.Error(), "429") || strings.Contains(err.Error(), "Too Many Requests") {
				return ErrRateLimit
			}

			return err
		}

		return nil
	}); err != nil {
		logger.Warn("Error: "+err.Error(), slog.Any("repo", repo))
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
// *** Does external calls to verify repos ***
func RepoTags(repoURL string, repoTagsCache *RepoTagsCache) (tags Tags, e error) {
	if repoTagsCache != nil {
		tagsRepoMap, ok := repoTagsCache.Get(repoURL)
		if ok {
			return slices.Collect(maps.Values(tagsRepoMap.Tag)), nil
		}
		if repoTagsCache.IsInvalid(repoURL) {
			return tags, errors.New("repo previously found to be invalid")
		}
	}
	// Cache miss.
	var refs []*plumbing.Reference
	var err error
	if os.Getenv("GITTER_HOST") != "" {
		refs, err = gitterRepoRefs(repoURL)
		if err != nil {
			logger.Warn("Failed to fetch tags from gitter, falling back to legacy enumeration", slog.String("repo", repoURL), slog.Any("error", err))
			refs, err = RemoteRepoRefsWithRetry(repoURL, 3)
		}
	} else {
		refs, err = RemoteRepoRefsWithRetry(repoURL, 3)
	}
	if err != nil {
		if repoTagsCache != nil {
			repoTagsCache.SetInvalid(repoURL)
		}

		return tags, err
	}
	tagsMap := make(map[string]Tag)
	for _, ref := range RefTags(refs) {
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
		repoTagsCache.Set(repoURL, RepoTagsMap{Tag: tagsMap, NormalizedTag: nil})
	}

	return tags, nil
}

// normalizeRepoTag returns a repo tag normalized.
// It is:
//   - lowercased,
//   - the repo name, if present is removed
//   - any Java package name prefix, if present is removed
//
// finally, it is run through the standard version normalizing treatment
func normalizeRepoTag(tag string, reponame string) (normalizedTag string, err error) {
	// Match the likes of "org.apache.sling.i18n-2.0.2" as seen in github.com/apache/sling-org-apache-sling-i18n
	var javaPackageRegex = regexp.MustCompile(`(?i)^(?:[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]+)+[a-z0-9_])-(.*)$`)
	// Opportunistically remove parts determined to match the repo name,
	// to ease particularly difficult to normalize cases like 'openj9-0.38.0'.
	prenormalizedTag := strings.TrimPrefix(strings.ToLower(tag), reponame)
	// Deal with the reponame being in the *middle* of the tag like 'hudson-yui2-2800'
	if strings.Contains(prenormalizedTag, reponame) {
		_, after, found := strings.Cut(prenormalizedTag, reponame)
		if found {
			prenormalizedTag = after
		}
	}
	if javaPackageRegex.MatchString(prenormalizedTag) {
		prenormalizedTag = javaPackageRegex.FindStringSubmatch(prenormalizedTag)[1]
	}
	prenormalizedTag = strings.TrimPrefix(prenormalizedTag, "-")
	normalizedTag, err = NormalizeVersion(prenormalizedTag)

	return normalizedTag, err
}

// NormalizeRepoTags returns a map of normalized tags mapping back to original tags and also commit hashes.
// An optional repoTagsCache can be supplied to reduce repeated remote connections to the same repo.
func NormalizeRepoTags(repoURL string, repoTagsCache *RepoTagsCache) (normalizedTags map[string]NormalizedTag, e error) {
	if repoTagsCache != nil {
		tags, ok := repoTagsCache.Get(repoURL)
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
	normalizedTags = make(map[string]NormalizedTag)
	for _, t := range tags {
		normalizedTag, err := normalizeRepoTag(strings.ToLower(t.Tag), assumedReponame)
		if err != nil {
			// It's conceivable that not all tags are normalizable or potentially versions.
			continue
		}
		normalizedTags[normalizedTag] = NormalizedTag{
			OriginalTag:        t.Tag,
			Commit:             t.Commit,
			MatchesVersionText: validVersionText.MatchString(normalizedTag),
		}
	}
	if repoTagsCache != nil {
		// The RepoTags() call above will have cached the Tag map already
		repoTagsMap, _ := repoTagsCache.Get(repoURL)
		repoTagsCache.Set(repoURL, RepoTagsMap{Tag: repoTagsMap.Tag, NormalizedTag: normalizedTags})
	}

	return normalizedTags, nil
}

// Return a list of just the references that are tags.
func RefTags(refs []*plumbing.Reference) (tags []*plumbing.Reference) {
	for _, ref := range refs {
		if ref.Name().IsTag() {
			tags = append(tags, ref)
		}
	}

	return tags
}

// Return a list of just the references that are branches.
func RefBranches(refs []*plumbing.Reference) (branches []*plumbing.Reference) {
	for _, ref := range refs {
		if ref.Name().IsBranch() {
			branches = append(branches, ref)
		}
	}

	return branches
}

// Validate the repo by attempting to query it's references.
// *** Does external calls to verify repos ***
func ValidRepo(repoURL string) (valid bool) {
	if os.Getenv("GITTER_HOST") != "" {
		_, err := gitterRepoRefs(repoURL)
		if err == nil {
			return true
		}
		logger.Warn("Failed to validate repo through gitter, falling back to legacy check", slog.String("repo", repoURL), slog.Any("error", err))
	}
	_, err := RemoteRepoRefsWithRetry(repoURL, 3)
	if err != nil && errors.Is(err, transport.ErrAuthenticationRequired) {
		// somewhat strangely, we get an authentication prompt via Git on non-existent repos.
		return false
	}
	if err != nil {
		return false
	}

	return true
}

// Otherwise functional repos that don't have any tags are not valid.
// *** Does external calls to verify repos ***
func ValidRepoAndHasUsableRefs(repoURL string) (valid bool) {
	if os.Getenv("GITTER_HOST") != "" {
		refs, err := gitterRepoRefs(repoURL)
		if err == nil {
			return len(refs) > 0
		}
		logger.Warn("Failed to validate repo through gitter, falling back to legacy check", slog.String("repo", repoURL), slog.Any("error", err))
	}
	refs, err := RemoteRepoRefsWithRetry(repoURL, 3)
	if err != nil && errors.Is(err, transport.ErrAuthenticationRequired) {
		// somewhat strangely, we get an authentication prompt via Git on non-existent repos.
		return false
	}
	if err != nil {
		return false
	}
	if len(refs) == 0 {
		return false
	}
	// Repos with no tags aren't useful.
	if len(RefTags(refs)) == 0 {
		return false
	}

	return true
}
