package conversion

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestBuildVersionRange(t *testing.T) {
	tests := []struct {
		name    string
		intro   string
		lastAff string
		fixed   string
		want    *osvschema.Range
	}{
		{
			name:  "intro and fixed",
			intro: "1.0.0",
			fixed: "1.0.1",
			want: &osvschema.Range{
				Events: []*osvschema.Event{
					{Introduced: "1.0.0"},
					{Fixed: "1.0.1"},
				},
			},
		},
		{
			name:    "intro and last_affected",
			intro:   "1.0.0",
			lastAff: "1.0.0",
			want: &osvschema.Range{
				Events: []*osvschema.Event{
					{Introduced: "1.0.0"},
					{LastAffected: "1.0.0"},
				},
			},
		},
		{
			name:  "only intro",
			intro: "1.0.0",
			want: &osvschema.Range{
				Events: []*osvschema.Event{
					{Introduced: "1.0.0"},
				},
			},
		},
		{
			name: "empty intro",
			want: &osvschema.Range{
				Events: []*osvschema.Event{
					{Introduced: "0"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildVersionRange(tt.intro, tt.lastAff, tt.fixed)
			if diff := cmp.Diff(tt.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("BuildVersionRange() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMergeTwoRanges(t *testing.T) {
	tests := []struct {
		name   string
		range1 *osvschema.Range
		range2 *osvschema.Range
		want   *osvschema.Range
	}{
		{
			name: "Merge identical ranges",
			range1: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://github.com/example/repo",
				Events: []*osvschema.Event{
					{Introduced: "0"},
				},
			},
			range2: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://github.com/example/repo",
				Events: []*osvschema.Event{
					{Fixed: "1.0.0"},
				},
			},
			want: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://github.com/example/repo",
				Events: []*osvschema.Event{
					{Introduced: "0"},
					{Fixed: "1.0.0"},
				},
			},
		},
		{
			name: "Different repos should return nil",
			range1: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://github.com/example/repo1",
			},
			range2: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://github.com/example/repo2",
			},
			want: nil,
		},
		{
			name: "Different types should return nil",
			range1: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://github.com/example/repo",
			},
			range2: &osvschema.Range{
				Type: osvschema.Range_ECOSYSTEM,
				Repo: "https://github.com/example/repo",
			},
			want: nil,
		},
		{
			name: "Merge with DatabaseSpecific",
			range1: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://github.com/example/repo",
				DatabaseSpecific: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"key1": structpb.NewStringValue("value1"),
					},
				},
			},
			range2: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://github.com/example/repo",
				DatabaseSpecific: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"key2": structpb.NewStringValue("value2"),
					},
				},
			},
			want: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://github.com/example/repo",
				DatabaseSpecific: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"key1": structpb.NewStringValue("value1"),
						"key2": structpb.NewStringValue("value2"),
					},
				},
			},
		},
		{
			name: "Merge DatabaseSpecific lists",
			range1: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://github.com/example/repo",
				DatabaseSpecific: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"list": structpb.NewListValue(&structpb.ListValue{
							Values: []*structpb.Value{structpb.NewStringValue("item1")},
						}),
					},
				},
			},
			range2: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://github.com/example/repo",
				DatabaseSpecific: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"list": structpb.NewListValue(&structpb.ListValue{
							Values: []*structpb.Value{structpb.NewStringValue("item2")},
						}),
					},
				},
			},
			want: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://github.com/example/repo",
				DatabaseSpecific: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"list": structpb.NewListValue(&structpb.ListValue{
							Values: []*structpb.Value{
								structpb.NewStringValue("item1"),
								structpb.NewStringValue("item2"),
							},
						}),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeTwoRanges(tt.range1, tt.range2)
			if diff := cmp.Diff(tt.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("mergeTwoRanges() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAddAffected(t *testing.T) {
	tests := []struct {
		name             string
		initialAffected  []*osvschema.Affected
		newAffected      *osvschema.Affected
		expectedAffected []*osvschema.Affected
	}{
		{
			name:            "Add to empty",
			initialAffected: nil,
			newAffected: &osvschema.Affected{
				Package: &osvschema.Package{Name: "pkg1"},
				Ranges: []*osvschema.Range{
					{Type: osvschema.Range_GIT, Repo: "repo1", Events: []*osvschema.Event{{Introduced: "0"}, {Fixed: "1.0.0"}}},
				},
			},
			expectedAffected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{Name: "pkg1"},
					Ranges: []*osvschema.Range{
						{Type: osvschema.Range_GIT, Repo: "repo1", Events: []*osvschema.Event{{Introduced: "0"}, {Fixed: "1.0.0"}}},
					},
				},
			},
		},
		{
			name: "Add unique range",
			initialAffected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{Name: "pkg1"},
					Ranges: []*osvschema.Range{
						{Type: osvschema.Range_GIT, Repo: "repo1", Events: []*osvschema.Event{{Introduced: "0"}, {Fixed: "1.0.0"}}},
					},
				},
			},
			newAffected: &osvschema.Affected{
				Package: &osvschema.Package{Name: "pkg1"},
				Ranges: []*osvschema.Range{
					{Type: osvschema.Range_GIT, Repo: "repo1", Events: []*osvschema.Event{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}},
				},
			},
			expectedAffected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{Name: "pkg1"},
					Ranges: []*osvschema.Range{
						{Type: osvschema.Range_GIT, Repo: "repo1", Events: []*osvschema.Event{{Introduced: "0"}, {Fixed: "1.0.0"}}},
					},
				},
				{
					Package: &osvschema.Package{Name: "pkg1"},
					Ranges: []*osvschema.Range{
						{Type: osvschema.Range_GIT, Repo: "repo1", Events: []*osvschema.Event{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}},
					},
				},
			},
		},
		{
			name: "Add duplicate range",
			initialAffected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{Name: "pkg1"},
					Ranges: []*osvschema.Range{
						{Type: osvschema.Range_GIT, Repo: "repo1", Events: []*osvschema.Event{{Introduced: "0"}, {Fixed: "1.0.0"}}},
					},
				},
			},
			newAffected: &osvschema.Affected{
				Package: &osvschema.Package{Name: "pkg1"},
				Ranges: []*osvschema.Range{
					{Type: osvschema.Range_GIT, Repo: "repo1", Events: []*osvschema.Event{{Introduced: "0"}, {Fixed: "1.0.0"}}},
				},
			},
			expectedAffected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{Name: "pkg1"},
					Ranges: []*osvschema.Range{
						{Type: osvschema.Range_GIT, Repo: "repo1", Events: []*osvschema.Event{{Introduced: "0"}, {Fixed: "1.0.0"}}},
					},
				},
			},
		},
		{
			name: "Add mixed duplicate and unique ranges",
			initialAffected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{Name: "pkg1"},
					Ranges: []*osvschema.Range{
						{Type: osvschema.Range_GIT, Repo: "repo1", Events: []*osvschema.Event{{Introduced: "0"}, {Fixed: "1.0.0"}}},
					},
				},
			},
			newAffected: &osvschema.Affected{
				Package: &osvschema.Package{Name: "pkg1"},
				Ranges: []*osvschema.Range{
					{Type: osvschema.Range_GIT, Repo: "repo1", Events: []*osvschema.Event{{Introduced: "0"}, {Fixed: "1.0.0"}}},
					{Type: osvschema.Range_GIT, Repo: "repo1", Events: []*osvschema.Event{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}},
				},
			},
			expectedAffected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{Name: "pkg1"},
					Ranges: []*osvschema.Range{
						{Type: osvschema.Range_GIT, Repo: "repo1", Events: []*osvschema.Event{{Introduced: "0"}, {Fixed: "1.0.0"}}},
					},
				},
				{
					Package: &osvschema.Package{Name: "pkg1"},
					Ranges: []*osvschema.Range{
						{Type: osvschema.Range_GIT, Repo: "repo1", Events: []*osvschema.Event{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &vulns.Vulnerability{
				Vulnerability: &osvschema.Vulnerability{
					Affected: tt.initialAffected,
				},
			}
			metrics := &models.ConversionMetrics{}
			AddAffected(v, tt.newAffected, metrics)

			if diff := cmp.Diff(tt.expectedAffected, v.Affected, protocmp.Transform()); diff != "" {
				t.Errorf("AddAffected() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDeduplicateRefs(t *testing.T) {
	tests := []struct {
		name string
		refs []models.Reference
		want []models.Reference
	}{
		{
			name: "No duplicates",
			refs: []models.Reference{
				{URL: "http://example.com/1"},
				{URL: "http://example.com/2"},
			},
			want: []models.Reference{
				{URL: "http://example.com/1"},
				{URL: "http://example.com/2"},
			},
		},
		{
			name: "Duplicates",
			refs: []models.Reference{
				{URL: "http://example.com/1"},
				{URL: "http://example.com/1"},
			},
			want: []models.Reference{
				{URL: "http://example.com/1"},
			},
		},
		{
			name: "Mixed",
			refs: []models.Reference{
				{URL: "http://example.com/1"},
				{URL: "http://example.com/2"},
				{URL: "http://example.com/1"},
			},
			want: []models.Reference{
				{URL: "http://example.com/1"},
				{URL: "http://example.com/2"},
			},
		},
		{
			name: "Empty",
			refs: []models.Reference{},
			want: []models.Reference{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DeduplicateRefs(tt.refs)
			// Sort want and got by URL to ensure deterministic comparison, although DeduplicateRefs sorts them.
			// DeduplicateRefs sorts by URL, so we expect sorted output.
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("DeduplicateRefs() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGitVersionsToCommits(t *testing.T) {
	// Setup cache with a mock repo
	cache := &git.RepoTagsCache{}
	repoURL := "https://github.com/example/repo"
	
	// Populate cache with normalized tags
	normalizedTags := map[string]git.NormalizedTag{
		"1-0-0": {
			OriginalTag:        "v1.0.0",
			Commit:             "commit1",
			MatchesVersionText: true,
		},
		"1-0-1": {
			OriginalTag:        "v1.0.1",
			Commit:             "commit2",
			MatchesVersionText: true,
		},
		"2-0-0": {
			OriginalTag:        "v2.0.0",
			Commit:             "commit3",
			MatchesVersionText: true,
		},
	}
	
	// We need to set the cache such that NormalizeRepoTags returns our normalizedTags.
	// NormalizeRepoTags calls RepoTags, which checks the cache.
	// If we set the cache correctly, we can avoid network calls.
	// The cache stores RepoTagsMap which has both Tag and NormalizedTag maps.
	
	repoTagsMap := git.RepoTagsMap{
		Tag: map[string]git.Tag{
			"v1.0.0": {Tag: "v1.0.0", Commit: "commit1"},
			"v1.0.1": {Tag: "v1.0.1", Commit: "commit2"},
			"v2.0.0": {Tag: "v2.0.0", Commit: "commit3"},
		},
		NormalizedTag: normalizedTags,
	}
	
	cache.Set(repoURL, repoTagsMap)
	// Mark invalid repo as invalid in cache to avoid network call
	cache.SetInvalid("https://github.com/invalid/repo")

	tests := []struct {
		name                 string
		versionRanges        []*osvschema.Range
		repos                []string
		wantResolved         []*osvschema.Range
		wantUnresolved       []*osvschema.Range
		wantSuccessfulRepos  []string
		wantOutcome          models.ConversionOutcome
	}{
		{
			name: "Resolve simple range",
			versionRanges: []*osvschema.Range{
				{
					Events: []*osvschema.Event{
						{Introduced: "1.0.0"},
						{Fixed: "1.0.1"},
					},
				},
			},
			repos: []string{repoURL},
			wantResolved: []*osvschema.Range{
				{
					Type: osvschema.Range_GIT,
					Repo: repoURL,
					Events: []*osvschema.Event{
						{Introduced: "commit1"},
						{Fixed: "commit2"},
					},
					DatabaseSpecific: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"versions": structpb.NewListValue(&structpb.ListValue{
								Values: []*structpb.Value{
									structpb.NewStructValue(&structpb.Struct{
										Fields: map[string]*structpb.Value{
											"introduced": structpb.NewStringValue("1.0.0"),
										},
									}),
									structpb.NewStructValue(&structpb.Struct{
										Fields: map[string]*structpb.Value{
											"fixed": structpb.NewStringValue("1.0.1"),
										},
									}),
								},
							}),
						},
					},
				},
			},
			wantUnresolved:      nil,
			wantSuccessfulRepos: []string{repoURL},
			wantOutcome:         models.Successful,
		},
		{
			name: "Resolve with last_affected",
			versionRanges: []*osvschema.Range{
				{
					Events: []*osvschema.Event{
						{Introduced: "1.0.0"},
						{LastAffected: "2.0.0"},
					},
				},
			},
			repos: []string{repoURL},
			wantResolved: []*osvschema.Range{
				{
					Type: osvschema.Range_GIT,
					Repo: repoURL,
					Events: []*osvschema.Event{
						{Introduced: "commit1"},
						{LastAffected: "commit3"},
					},
					DatabaseSpecific: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"versions": structpb.NewListValue(&structpb.ListValue{
								Values: []*structpb.Value{
									structpb.NewStructValue(&structpb.Struct{
										Fields: map[string]*structpb.Value{
											"introduced": structpb.NewStringValue("1.0.0"),
										},
									}),
									structpb.NewStructValue(&structpb.Struct{
										Fields: map[string]*structpb.Value{
											"last_affected": structpb.NewStringValue("2.0.0"),
										},
									}),
								},
							}),
						},
					},
				},
			},
			wantUnresolved:      nil,
			wantSuccessfulRepos: []string{repoURL},
			wantOutcome:         models.Successful,
		},
		{
			name: "Partial resolution (some versions missing)",
			versionRanges: []*osvschema.Range{
				{
					Events: []*osvschema.Event{
						{Introduced: "1.0.0"},
						{Fixed: "9.9.9"}, // Missing
					},
				},
			},
			repos:               []string{repoURL},
			wantResolved:        nil,
			wantUnresolved: []*osvschema.Range{
				{
					Events: []*osvschema.Event{
						{Introduced: "1.0.0"},
						{Fixed: "9.9.9"},
					},
				},
			},
			wantSuccessfulRepos: nil,
			wantOutcome:         models.NoCommitRanges,
		},
		{
			name: "Invalid repo",
			versionRanges: []*osvschema.Range{
				{
					Events: []*osvschema.Event{
						{Introduced: "1.0.0"},
					},
				},
			},
			repos:               []string{"https://github.com/invalid/repo"},
			wantResolved:        nil,
			wantUnresolved: []*osvschema.Range{
				{
					Events: []*osvschema.Event{
						{Introduced: "1.0.0"},
					},
				},
			},
			wantSuccessfulRepos: nil,
			wantOutcome:         models.NoCommitRanges,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := &models.ConversionMetrics{}
			gotResolved, gotUnresolved, gotSuccessfulRepos := GitVersionsToCommits(tt.versionRanges, tt.repos, metrics, cache)

			if diff := cmp.Diff(tt.wantResolved, gotResolved, protocmp.Transform()); diff != "" {
				t.Errorf("GitVersionsToCommits() resolved mismatch (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(tt.wantUnresolved, gotUnresolved, protocmp.Transform()); diff != "" {
				t.Errorf("GitVersionsToCommits() unresolved mismatch (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(tt.wantSuccessfulRepos, gotSuccessfulRepos); diff != "" {
				t.Errorf("GitVersionsToCommits() successfulRepos mismatch (-want +got):\n%s", diff)
			}
			
			if metrics.Outcome != tt.wantOutcome {
				t.Errorf("GitVersionsToCommits() outcome mismatch want %v, got %v", tt.wantOutcome, metrics.Outcome)
			}
		})
	}
}
