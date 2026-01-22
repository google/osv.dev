package cvelist2osv

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv/vulnfeeds/conversion"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestAddAffected(t *testing.T) {
	v := &vulns.Vulnerability{
		Vulnerability: &osvschema.Vulnerability{
			Affected: []*osvschema.Affected{
				{
					Package: &osvschema.Package{
						Name:      "my-package",
						Ecosystem: "my-ecosystem",
					},
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_SEMVER,
							Events: []*osvschema.Event{
								{Introduced: "1.0.0"},
								{Fixed: "1.0.1"},
							},
						},
					},
				},
			},
		},
	}
	aff := &osvschema.Affected{
		Package: &osvschema.Package{
			Name:      "my-package",
			Ecosystem: "my-ecosystem",
		},
		Ranges: []*osvschema.Range{
			{
				// Duplicate range
				Type: osvschema.Range_SEMVER,
				Events: []*osvschema.Event{
					{Introduced: "1.0.0"},
					{Fixed: "1.0.1"},
				},
			},
			{
				// New range
				Type: osvschema.Range_SEMVER,
				Events: []*osvschema.Event{
					{Introduced: "2.0.0"},
					{Fixed: "2.0.1"},
				},
			},
		},
	}
	metrics := &models.ConversionMetrics{}

	conversion.AddAffected(v, aff, metrics)

	expectedAffected := []*osvschema.Affected{
		{
			Package: &osvschema.Package{
				Name:      "my-package",
				Ecosystem: "my-ecosystem",
			},
			Ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_SEMVER,
					Events: []*osvschema.Event{
						{Introduced: "1.0.0"},
						{Fixed: "1.0.1"},
					},
				},
			},
		},
		{
			Package: &osvschema.Package{
				Name:      "my-package",
				Ecosystem: "my-ecosystem",
			},
			Ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_SEMVER,
					Events: []*osvschema.Event{
						{Introduced: "2.0.0"},
						{Fixed: "2.0.1"},
					},
				},
			},
		},
	}

	if diff := cmp.Diff(expectedAffected, v.Affected, protocmp.Transform()); diff != "" {
		t.Errorf("addAffected() mismatch (-want +got):\n%s", diff)
	}

	if len(metrics.Notes) != 1 {
		t.Errorf("Expected 1 note, got %d", len(metrics.Notes))
	}
}
