// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ecosystem

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

type ghcEcosystem struct {
	semverLikeEcosystem

	p *Provider
}

var _ Enumerable = ghcEcosystem{}

// Historical versions do not have tags in the Git repo, so we hardcode the list.
var ghcHistoricalVersions = []string{
	"0.29", "2.10", "3.02", "3.03", "4.02", "4.04", "4.06", "4.08", "4.08.1", "4.08.2",
	"5.00", "5.00.1", "5.00.2", "5.02", "5.02.1", "5.02.2", "5.02.3",
	"5.04", "5.04.1", "5.04.2", "5.04.3",
	"6.0", "6.0.1", "6.2", "6.2.1", "6.2.2",
	"6.4", "6.4.1", "6.4.2", "6.4.3",
	"6.6", "6.6.1", "6.8.1", "6.8.3",
	"6.10.1", "6.10.2-rc1", "6.10.2", "6.10.3", "6.10.4-rc1", "6.10.4",
	"6.12.1-rc1", "6.12.1", "6.12.2-rc1", "6.12.2", "6.12.3-rc1", "6.12.3",
	"7.0.1-rc1", "7.0.1-rc2", "7.0.1", "7.0.2-rc1", "7.0.2-rc2", "7.0.2",
	"7.0.3", "7.0.4-rc1", "7.0.4",
}

const ghcAPIURL = "https://gitlab.haskell.org/api/v4/projects/3561/repository/tags?per_page=100"

var ghcLinkNextRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// GetVersions enumerates GHC versions.
// Different components of GHC are part of the same software release, so we ignore the package name.
func (e ghcEcosystem) GetVersions(_ string) ([]string, error) {
	// Versions come from tags from the GitLab API, which are paginated.
	var versions []string
	versions = append(versions, ghcHistoricalVersions...)

	urlStr := ghcAPIURL
	for urlStr != "" {
		req, err := http.NewRequest(http.MethodGet, urlStr, nil)
		if err != nil {
			return nil, err
		}

		resp, err := e.p.Client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusNotFound {
			resp.Body.Close()
			return nil, fmt.Errorf("GHC tag list not found at %s", urlStr)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to get GHC versions from: %s with: HTTP %s", urlStr, resp.Status)
		}

		var tags []struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
			resp.Body.Close()
			return nil, err
		}
		resp.Body.Close()

		for _, tag := range tags {
			if v := tagToGHCVersion(tag.Name); v != "" {
				versions = append(versions, v)
			}
		}

		urlStr = ""
		if linkHeader := resp.Header.Get("Link"); linkHeader != "" {
			match := ghcLinkNextRe.FindStringSubmatch(linkHeader)
			if len(match) > 1 {
				urlStr = match[1]
			}
		}
	}

	return sortVersions(e, versions)
}

func tagToGHCVersion(tag string) string {
	parts := strings.Split(tag, "-")
	if len(parts) == 3 && parts[0] == "ghc" && isGHCMajorMinorPatch(parts[1]) {
		if strings.HasPrefix(parts[2], "alpha") || strings.HasPrefix(parts[2], "rc") {
			return parts[1] + "-" + parts[2]
		}
		if parts[2] == "release" {
			return parts[1]
		}
	}

	return ""
}

func isGHCMajorMinorPatch(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}

	return true
}
