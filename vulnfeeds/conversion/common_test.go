package conversion

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
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
