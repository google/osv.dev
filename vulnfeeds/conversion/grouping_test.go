package conversion

import (
	"testing"

	"github.com/google/go-cmp/cmp"
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
			name: "Different DatabaseSpecific (non-versions) - merge, second gets overwritten",
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
									"foo": structpb.NewStringValue("bar"),
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
