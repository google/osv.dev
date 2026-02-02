// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package datastore contains definitions of Datastore entities for OSV.dev.
package datastore

import (
	"time"

	"cloud.google.com/go/datastore"
	"github.com/google/osv.dev/go/internal/models"
)

type Vulnerability struct {
	Key         *datastore.Key `datastore:"__key__"`
	SourceID    string         `datastore:"source_id"`
	Modified    time.Time      `datastore:"modified"`
	IsWithdrawn bool           `datastore:"is_withdrawn"`
	ModifiedRaw time.Time      `datastore:"modified_raw"`
	AliasRaw    []string       `datastore:"alias_raw"`
	RelatedRaw  []string       `datastore:"related_raw"`
	UpstreamRaw []string       `datastore:"upstream_raw"`
}

type AliasGroup struct {
	VulnIDs  []string  `datastore:"bug_ids"`
	Modified time.Time `datastore:"last_modified"`
}

type UpstreamGroup struct {
	Key               *datastore.Key `datastore:"__key__"`
	VulnID            string         `datastore:"db_id"`
	UpstreamIDs       []string       `datastore:"upstream_ids"`
	Modified          time.Time      `datastore:"last_modified"`
	UpstreamHierarchy []byte         `datastore:"upstream_hierarchy,noindex"`
}

type RelatedGroup struct {
	Key        *datastore.Key `datastore:"__key__"`
	RelatedIDs []string       `datastore:"related_ids"`
	Modified   time.Time      `datastore:"modified"`
}

type AliasAllowListEntry struct {
	VulnID string `datastore:"bug_id"`
}

type AliasDenyListEntry struct {
	VulnID string `datastore:"bug_id"`
}

type Severity struct {
	Type  string `datastore:"type"`
	Score string `datastore:"score"`
}

type ListedVulnerability struct {
	Key              *datastore.Key `datastore:"__key__"`
	Published        time.Time      `datastore:"published"`
	Ecosystems       []string       `datastore:"ecosystems"`
	Packages         []string       `datastore:"packages,noindex"`
	Summary          string         `datastore:"summary,noindex"`
	IsFixed          bool           `datastore:"is_fixed,noindex"`
	Severities       []Severity     `datastore:"severities"`
	AutocompleteTags []string       `datastore:"autocomplete_tags"`
	SearchIndices    []string       `datastore:"search_indices"`
}

type SourceRepository struct {
	Type                    models.SourceRepositoryType `datastore:"type"`
	Name                    string                      `datastore:"name"`
	RepoURL                 string                      `datastore:"repo_url"`
	RepoUsername            string                      `datastore:"repo_username"`
	RepoBranch              string                      `datastore:"repo_branch"`
	RestApiUrl              string                      `datastore:"rest_api_url"`
	Bucket                  string                      `datastore:"bucket"`
	DirectoryPath           string                      `datastore:"directory_path"`
	LastSyncedHash          string                      `datastore:"last_synced_hash"`
	LastUpdateDate          *time.Time                  `datastore:"last_update_date"`
	IgnorePatterns          []string                    `datastore:"ignore_patterns"`
	Editable                bool                        `datastore:"editable"`
	Extension               string                      `datastore:"extension"`
	KeyPath                 string                      `datastore:"key_path"`
	IgnoreGit               bool                        `datastore:"ignore_git"`
	DetectCherrypicks       bool                        `datastore:"detect_cherrypicks"`
	ConsiderAllBranches     bool                        `datastore:"consider_all_branches"`
	VersionsFromRepo        bool                        `datastore:"versions_from_repo"`
	IgnoreLastImportTime    bool                        `datastore:"ignore_last_import_time"`
	IgnoreDeletionThreshold bool                        `datastore:"ignore_deletion_threshold"`
	Link                    string                      `datastore:"link"`
	HumanLink               string                      `datastore:"human_link"`
	DBPrefix                []string                    `datastore:"db_prefix"`
	StrictValidation        bool                        `datastore:"strict_validation"`
}
