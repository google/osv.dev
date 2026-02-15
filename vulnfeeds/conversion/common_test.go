package conversion

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
)

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
