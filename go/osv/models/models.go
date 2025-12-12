// Copyright 2025 Google LLC
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

// Package models contains definitions of Datastore entities for OSV.dev.
package models

import (
	"time"

	"cloud.google.com/go/datastore"
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

type ImportFindings int

const (
	ImportFindingsUnknown         ImportFindings = -1
	ImportFindingsNone            ImportFindings = 0
	ImportFindingsDeleted         ImportFindings = 1
	ImportFindingsInvalidJSON     ImportFindings = 2
	ImportFindingsInvalidPackage  ImportFindings = 3
	ImportFindingsInvalidPURL     ImportFindings = 4
	ImportFindingsInvalidVersion  ImportFindings = 5
	ImportFindingsInvalidCommit   ImportFindings = 6
	ImportFindingsInvalidRange    ImportFindings = 7
	ImportFindingsInvalidRecord   ImportFindings = 8
	ImportFindingsInvalidAliases  ImportFindings = 9
	ImportFindingsInvalidUpstream ImportFindings = 10
	ImportFindingsInvalidRelated  ImportFindings = 11
	ImportFindingsBadAliasedCVE   ImportFindings = 12
)

type ImportFinding struct {
	Key         *datastore.Key   `datastore:"__key__"`
	BugID       string           `datastore:"bug_id"`
	Source      string           `datastore:"source"`
	Findings    []ImportFindings `datastore:"findings"`
	FirstSeen   time.Time        `datastore:"first_seen"`
	LastAttempt time.Time        `datastore:"last_attempt"`
}

type SourceRepository struct {
	Key                  *datastore.Key `datastore:"__key__"`
	Name                 string         `datastore:"name"`
	Type                 int            `datastore:"type"`
	Bucket               string         `datastore:"bucket"`
	DBPrefix             []string       `datastore:"db_prefix"`
	Link                 string         `datastore:"link"`
	HumanLink            string         `datastore:"human_link"`
	IgnoreGit            bool           `datastore:"ignore_git"`
	Editable             bool           `datastore:"editable"`
	LastSynced           string         `datastore:"last_synced_hash"`
	Extension            string         `datastore:"extension"`
	IgnorePatterns       []string       `datastore:"ignore_patterns"`
	StrictValidation     bool           `datastore:"strict_validation"`
	DirectoryPath        string         `datastore:"directory_path"`
	RepoBranch           string         `datastore:"repo_branch"`
	RepoURL              string         `datastore:"repo_url"`
	RepoUsername         string         `datastore:"repo_username"`
	LastUpdateDate       time.Time      `datastore:"last_update_date"`
	RestAPIURL           string         `datastore:"rest_api_url"`
	ConsiderAllBranches  bool           `datastore:"consider_all_branches"`
	KeyPath              string         `datastore:"key_path"`
	DetectCherrypicks    bool           `datastore:"detect_cherrypicks"`
	VersionsFromRepo     bool           `datastore:"versions_from_repo"`
	IgnoreLastImportTime bool           `datastore:"ignore_last_import_time"`
}
