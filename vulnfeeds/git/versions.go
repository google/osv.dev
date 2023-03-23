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

package git

import (
	"fmt"

	"github.com/google/osv/vulnfeeds/cves"
)

// Take an unnormalized version string, a repo, the pre-normalized mapping of tags to commits and return a GitCommit.
func VersionToCommit(version string, repo string, normalizedTags map[string]NormalizedTag) (gc cves.GitCommit, e error) {
	normalizedVersion, err := cves.NormalizeVersion(version)
	if err != nil {
		return gc, err
	}
	// Try a straight out match first.
	// TODO try fuzzy prefix matches also.
	normalizedTag, ok := normalizedTags[normalizedVersion]
	if !ok {
		return gc, fmt.Errorf("Failed to find a commit for version %q normalized as %q", version, normalizedVersion)
	}
	return cves.GitCommit{
		Repo:   repo,
		Commit: normalizedTag.Commit,
	}, nil
}
