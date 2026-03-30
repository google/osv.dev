package conversion

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestGroupAffectedRanges(t *testing.T) {
	tests := []struct {
		name     string
		affected []*osvschema.Affected
		want     []*osvschema.Affected
	}{
		{
			name: "Merge same introduced",
			affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
						},
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.2"},
							},
						},
					},
				},
			},
			want: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
								{Fixed: "1.2"},
							},
						},
					},
				},
			},
		},
		{
			name: "Different introduced - no merge",
			affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
						},
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "1.1"},
								{Fixed: "1.2"},
							},
						},
					},
				},
			},
			want: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
						},
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "1.1"},
								{Fixed: "1.2"},
							},
						},
					},
				},
			},
		},
		{
			name: "Different type - no merge",
			affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
						},
						{
							Type: osvschema.Range_SEMVER,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
						},
					},
				},
			},
			want: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
						},
						{
							Type: osvschema.Range_SEMVER,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
						},
					},
				},
			},
		},
		{
			name: "Different repo - no merge",
			affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: "repo1",
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
						},
						{
							Type: osvschema.Range_GIT,
							Repo: "repo2",
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
						},
					},
				},
			},
			want: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: "repo1",
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
						},
						{
							Type: osvschema.Range_GIT,
							Repo: "repo2",
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
						},
					},
				},
			},
		},
		{
			name: "Mixed merge",
			affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
						},
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "2.0"},
								{Fixed: "3.0"},
							},
						},
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.2"},
							},
						},
					},
				},
			},
			want: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
								{Fixed: "1.2"},
							},
						},
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "2.0"},
								{Fixed: "3.0"},
							},
						},
					},
				},
			},
		},
		{
			name: "Different DatabaseSpecific (non-versions) - merge properly",
			affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"foo": structpb.NewStringValue("bar"),
								},
							},
						},
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.2"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"foo": structpb.NewStringValue("baz"),
								},
							},
						},
					},
				},
			},
			want: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
								{Fixed: "1.2"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"foo": structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("bar"),
											structpb.NewStringValue("baz"),
										},
									}),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Merge DatabaseSpecific versions",
			affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"versions": structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("v1"),
										},
									}),
								},
							},
						},
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.2"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"versions": structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("v2"),
										},
									}),
								},
							},
						},
					},
				},
			},
			want: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
								{Fixed: "1.2"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"versions": structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("v1"),
											structpb.NewStringValue("v2"),
										},
									}),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Deduplicate DatabaseSpecific versions",
			affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"versions": structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("v1"),
										},
									}),
								},
							},
						},
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.2"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"versions": structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("v1"),
											structpb.NewStringValue("v2"),
										},
									}),
								},
							},
						},
					},
				},
			},
			want: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Events: []*osvschema.Event{
								{Introduced: "0"},
								{Fixed: "1.0"},
								{Fixed: "1.2"},
							},
							DatabaseSpecific: &structpb.Struct{
								Fields: map[string]*structpb.Value{
									"versions": structpb.NewListValue(&structpb.ListValue{
										Values: []*structpb.Value{
											structpb.NewStringValue("v1"),
											structpb.NewStringValue("v2"),
										},
									}),
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			GroupAffectedRanges(tt.affected)
			if diff := cmp.Diff(tt.want, tt.affected, protocmp.Transform()); diff != "" {
				t.Errorf("groupAffectedRanges() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMergeRangesAndCreateAffected(t *testing.T) {
	tests := []struct {
		name            string
		resolvedRanges  []*osvschema.Range
		commits         []models.AffectedCommit
		successfulRepos []string
		want            *osvschema.Affected
	}{
		{
			name: "Merge existing ranges with commits for the same repo",
			resolvedRanges: []*osvschema.Range{
				{
					Type: osvschema.Range_GIT,
					Repo: "repo1",
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{Fixed: "1.0"},
					},
				},
			},
			commits: []models.AffectedCommit{
				{
					Repo:       "repo1",
					Introduced: "1.1",
				},
				{
					Repo:  "repo1",
					Fixed: "1.2",
				},
			},
			successfulRepos: []string{"repo1"},
			want: &osvschema.Affected{
				Ranges: []*osvschema.Range{
					{
						Type: osvschema.Range_GIT,
						Repo: "repo1",
						Events: []*osvschema.Event{
							{Introduced: "1.1"},
							{Introduced: "0"},
							{Fixed: "1.0"},
							{Fixed: "1.2"},
						},
						DatabaseSpecific: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								"source": structpb.NewStringValue("REFERENCES"),
							},
						},
					},
				},
			},
		},
		{
			name:           "No resolved ranges, only commits",
			resolvedRanges: nil,
			commits: []models.AffectedCommit{
				{
					Repo:       "repo2",
					Introduced: "0",
					Fixed:      "1.0",
				},
			},
			successfulRepos: []string{"repo2"},
			want: &osvschema.Affected{
				Ranges: []*osvschema.Range{
					{
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{Fixed: "1.0"},
						},
						Repo: "repo2",
						Type: osvschema.Range_GIT,
						DatabaseSpecific: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								"source": structpb.NewStringValue("REFERENCES"),
							},
						},
					},
				},
			},
		},
		{
			name: "Duplicate events are deduplicated",
			resolvedRanges: []*osvschema.Range{
				{
					Type: osvschema.Range_GIT,
					Repo: "repo3",
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{Fixed: "1.0"},
					},
				},
			},
			commits: []models.AffectedCommit{
				// duplicate fixed
				{
					Repo:  "repo3",
					Fixed: "1.0",
				},
				// duplicate introduced
				{
					Repo:       "repo3",
					Introduced: "0",
				},
				// new last affected
				{
					Repo:         "repo3",
					LastAffected: "0.5",
				},
			},
			successfulRepos: []string{"repo3"},
			want: &osvschema.Affected{
				Ranges: []*osvschema.Range{
					{
						Type: osvschema.Range_GIT,
						Repo: "repo3",
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{Fixed: "1.0"},
							{LastAffected: "0.5"},
						},
						DatabaseSpecific: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								"source": structpb.NewStringValue("REFERENCES"),
							},
						},
					},
				},
			},
		},
		{
			name: "Commits for repos not in successfulRepos are ignored when resolvedRanges exist",
			resolvedRanges: []*osvschema.Range{
				{
					Type: osvschema.Range_GIT,
					Repo: "repo4",
					Events: []*osvschema.Event{
						{Introduced: "0"},
					},
				},
			},
			commits: []models.AffectedCommit{
				{
					Repo:       "repo_ignored",
					Introduced: "1.1",
				},
			},
			successfulRepos: []string{"repo4"}, // repo_ignored is absent
			want: &osvschema.Affected{
				Ranges: []*osvschema.Range{
					{
						Type: osvschema.Range_GIT,
						Repo: "repo4",
						Events: []*osvschema.Event{
							{Introduced: "0"},
						},
					},
				},
			},
		},
		{
			name: "Multiple resolved ranges for same repo are merged and commits appended",
			resolvedRanges: []*osvschema.Range{
				{
					Type: osvschema.Range_GIT,
					Repo: "repo5",
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{Fixed: "1.0"},
					},
				},
				{
					Type: osvschema.Range_GIT,
					Repo: "repo5",
					Events: []*osvschema.Event{
						{Introduced: "2.0"},
						{Fixed: "3.0"},
					},
				},
			},
			commits: []models.AffectedCommit{
				{
					Repo:  "repo5",
					Fixed: "4.0",
				},
			},
			successfulRepos: []string{"repo5"},
			want: &osvschema.Affected{
				Ranges: []*osvschema.Range{
					{
						Type: osvschema.Range_GIT,
						Repo: "repo5",
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{Fixed: "1.0"},
							{Introduced: "2.0"},
							{Fixed: "3.0"},
							{Fixed: "4.0"},
						},
						DatabaseSpecific: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								"source": structpb.NewStringValue("REFERENCES"),
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rwms []models.RangeWithMetadata
			for _, r := range tt.resolvedRanges {
				rwms = append(rwms, models.RangeWithMetadata{Range: r})
			}
			got := MergeRangesAndCreateAffected(rwms, tt.commits, tt.successfulRepos, &models.ConversionMetrics{})
			if diff := cmp.Diff(tt.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("MergeRangesAndCreateAffected() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
