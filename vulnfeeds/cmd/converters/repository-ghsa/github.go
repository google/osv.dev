// Copyright 2026 Google LLC
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

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/osv.dev/vulnfeeds/utility/logger"
	"github.com/sethvargo/go-retry"
)

// GHSAAdvisory represents a repository-level security advisory payload from GitHub REST API.
type GHSAAdvisory struct {
	GHSAID          string              `json:"ghsa_id"`
	CVEID           *string             `json:"cve_id"`
	URL             string              `json:"url"`
	HTMLURL         string              `json:"html_url"`
	Summary         string              `json:"summary"`
	Description     *string             `json:"description"`
	Severity        *string             `json:"severity"`
	Author          *GHSAUser           `json:"author"`
	Publisher       *GHSAUser           `json:"publisher"`
	Identifiers     []GHSAIdentifier    `json:"identifiers"`
	State           string              `json:"state"`
	CreatedAt       *time.Time          `json:"created_at"`
	UpdatedAt       *time.Time          `json:"updated_at"`
	PublishedAt     *time.Time          `json:"published_at"`
	ClosedAt        *time.Time          `json:"closed_at"`
	WithdrawnAt     *time.Time          `json:"withdrawn_at"`
	Vulnerabilities []GHSAVulnerability `json:"vulnerabilities"`
	CVSSSeverities  *GHSACVSSSeverities `json:"cvss_severities"`
	CWEs            []GHSACWE           `json:"cwes"`
	CWEIDs          []string            `json:"cwe_ids"`
	Credits         []GHSACredit        `json:"credits"`
}

type GHSAUser struct {
	Login string `json:"login"`
}

type GHSAIdentifier struct {
	Type  string `json:"type"` // "CVE" or "GHSA"
	Value string `json:"value"`
}

type GHSAVulnerability struct {
	Package                *GHSAPackage `json:"package"`
	VulnerableVersionRange *string      `json:"vulnerable_version_range"`
	PatchedVersions        *string      `json:"patched_versions"`
	VulnerableFunctions    []string     `json:"vulnerable_functions"`
}

type GHSAPackage struct {
	Ecosystem string  `json:"ecosystem"`
	Name      *string `json:"name"`
}

type GHSACVSSSeverities struct {
	CVSSV3 *GHSACVSS `json:"cvss_v3"`
	CVSSV4 *GHSACVSS `json:"cvss_v4"`
}

type GHSACVSS struct {
	VectorString *string  `json:"vector_string"`
	Score        *float64 `json:"score"`
}

type GHSACWE struct {
	CWEID string `json:"cwe_id"`
	Name  string `json:"name"`
}

type GHSACredit struct {
	Login string `json:"login"`
	Type  string `json:"type"`
}

// RepoTarget contains the parsed owner, repository name, and canonical URL.
type RepoTarget struct {
	Owner        string
	Repo         string
	CanonicalURL string
}

// ParseRepoTarget parses a repository identifier into a RepoTarget.
// Handles formats such as "owner/repo", "https://github.com/owner/repo",
// "github.com/owner/repo", and "git@github.com:owner/repo.git".
func ParseRepoTarget(raw string) (RepoTarget, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return RepoTarget{}, errors.New("empty repository identifier")
	}

	// Remove common SSH and URL prefixes
	if after, ok := strings.CutPrefix(trimmed, "git@github.com:"); ok {
		trimmed = after
	} else if after, ok := strings.CutPrefix(trimmed, "https://github.com/"); ok {
		trimmed = after
	} else if after, ok := strings.CutPrefix(trimmed, "http://github.com/"); ok {
		trimmed = after
	} else if after, ok := strings.CutPrefix(trimmed, "github.com/"); ok {
		trimmed = after
	}

	trimmed = strings.Trim(trimmed, "/")
	trimmed = strings.TrimSuffix(trimmed, ".git")

	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 {
		return RepoTarget{}, fmt.Errorf("invalid repository format %q: expected owner/repo", raw)
	}

	owner, repo := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	repo = strings.TrimSuffix(repo, ".git")
	if owner == "" || repo == "" {
		return RepoTarget{}, fmt.Errorf("invalid owner or repo in %q", raw)
	}

	return RepoTarget{
		Owner:        owner,
		Repo:         repo,
		CanonicalURL: fmt.Sprintf("https://github.com/%s/%s", owner, repo),
	}, nil
}

// GitHubClient handles HTTP communication with the GitHub REST API.
type GitHubClient struct {
	client  *http.Client
	baseURL string
	token   string
}

// NewGitHubClient creates a new GitHubClient.
func NewGitHubClient(token string, client *http.Client) *GitHubClient {
	if client == nil {
		client = http.DefaultClient
	}

	return &GitHubClient{
		client:  client,
		baseURL: "https://api.github.com",
		token:   token,
	}
}

// SetBaseURL overrides the base API URL (primarily for testing).
func (c *GitHubClient) SetBaseURL(baseURL string) {
	c.baseURL = strings.TrimRight(baseURL, "/")
}

// FetchAdvisories retrieves all security advisories for a given repository, handling pagination and retries.
func (c *GitHubClient) FetchAdvisories(ctx context.Context, owner, repo, state string) ([]GHSAAdvisory, error) {
	reqURL := fmt.Sprintf("%s/repos/%s/%s/security-advisories?per_page=100", c.baseURL, url.PathEscape(owner), url.PathEscape(repo))
	if state != "" && state != "all" {
		reqURL += "&state=" + url.QueryEscape(state)
	}

	var allAdvisories []GHSAAdvisory

	for reqURL != "" {
		advisories, nextURL, err := c.fetchAdvisoriesPage(ctx, reqURL)
		if err != nil {
			return nil, fmt.Errorf("fetching advisories for %s/%s from %s: %w", owner, repo, reqURL, err)
		}

		allAdvisories = append(allAdvisories, advisories...)
		reqURL = nextURL
	}

	return allAdvisories, nil
}

func (c *GitHubClient) fetchAdvisoriesPage(ctx context.Context, requestURL string) ([]GHSAAdvisory, string, error) {
	var (
		advisories []GHSAAdvisory
		nextURL    string
	)

	b := retry.NewExponential(1 * time.Second)
	b = retry.WithMaxRetries(3, b)

	err := retry.Do(ctx, b, func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
		if err != nil {
			return err
		}

		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-Github-Api-Version", "2022-11-28")
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}

		resp, err := c.client.Do(req)
		if err != nil {
			return retry.RetryableError(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode >= 500 && resp.StatusCode < 600) {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			return retry.RetryableError(fmt.Errorf("temporary HTTP error status %d: %s", resp.StatusCode, string(body)))
		}

		if resp.StatusCode == http.StatusNotFound {
			logger.Warn("Repository security advisories returned 404", slog.String("url", requestURL))
			return nil
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			return fmt.Errorf("GitHub API request failed with status %d: %s", resp.StatusCode, string(body))
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed reading GitHub API response: %w", err)
		}

		if err := json.Unmarshal(bodyBytes, &advisories); err != nil {
			return fmt.Errorf("failed decoding advisories JSON: %w", err)
		}

		nextURL = parseNextLink(resp.Header.Get("Link"))

		return nil
	})

	if err != nil {
		return nil, "", err
	}

	return advisories, nextURL, nil
}

var linkNextRegex = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// parseNextLink extracts the URL from a Link header where rel="next".
func parseNextLink(linkHeader string) string {
	if linkHeader == "" {
		return ""
	}

	for part := range strings.SplitSeq(linkHeader, ",") {
		subparts := strings.Split(part, ";")
		if len(subparts) < 2 {
			continue
		}

		isNext := false
		for _, param := range subparts[1:] {
			param = strings.TrimSpace(param)
			if param == `rel="next"` || param == `rel='next'` || param == `rel=next` {
				isNext = true
				break
			}
		}

		if isNext {
			urlPart := strings.TrimSpace(subparts[0])
			urlPart = strings.TrimPrefix(urlPart, "<")
			urlPart = strings.TrimSuffix(urlPart, ">")

			return urlPart
		}
	}

	matches := linkNextRegex.FindStringSubmatch(linkHeader)
	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}
