package cvelist2osv

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			groupAffectedRanges(tt.affected)
			if diff := cmp.Diff(tt.want, tt.affected, protocmp.Transform()); diff != "" {
				t.Errorf("groupAffectedRanges() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
