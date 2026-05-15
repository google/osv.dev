package purl

import (
	"context"
	"testing"

	"github.com/google/osv.dev/go/internal/worker/pipeline"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestEnricher_Enrich(t *testing.T) {
	enricher := &Enricher{}
	ctx := context.Background()

	tests := []struct {
		name         string
		ecosystem    string
		pkgName      string
		initialPurl  string
		expectedPurl string
	}{
		{
			name:         "Generate PURL when missing",
			ecosystem:    "PyPI",
			pkgName:      "atomicwrites",
			initialPurl:  "",
			expectedPurl: "pkg:pypi/atomicwrites",
		},
		{
			name:         "Strip version from valid PURL",
			ecosystem:    "PyPI",
			pkgName:      "atomicwrites",
			initialPurl:  "pkg:pypi/atomicwrites@1.4.1",
			expectedPurl: "pkg:pypi/atomicwrites",
		},
		{
			name:         "Discard invalid PURL and regenerate",
			ecosystem:    "PyPI",
			pkgName:      "atomicwrites",
			initialPurl:  "invalid::purl!!!",
			expectedPurl: "pkg:pypi/atomicwrites",
		},
		{
			name:         "Generate Go PURL with namespace",
			ecosystem:    "Go",
			pkgName:      "github.com/gorilla/mux",
			initialPurl:  "",
			expectedPurl: "pkg:golang/github.com/gorilla/mux",
		},
		{
			name:         "Generate Maven PURL with group and artifact",
			ecosystem:    "Maven",
			pkgName:      "org.apache.commons:commons-lang3",
			initialPurl:  "",
			expectedPurl: "pkg:maven/org.apache.commons/commons-lang3",
		},
		{
			name:         "Generate Debian PURL with distro qualifier",
			ecosystem:    "Debian:11",
			pkgName:      "curl",
			initialPurl:  "",
			expectedPurl: "pkg:deb/debian/curl?arch=source&distro=bullseye",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vuln := &osvschema.Vulnerability{
				Id: "TEST-123",
				Affected: []*osvschema.Affected{
					{
						Package: &osvschema.Package{
							Ecosystem: tc.ecosystem,
							Name:      tc.pkgName,
							Purl:      tc.initialPurl,
						},
					},
				},
			}

			if err := enricher.Enrich(ctx, vuln, &pipeline.EnrichParams{}); err != nil {
				t.Fatalf("Enrich failed: %v", err)
			}

			affected := vuln.GetAffected()[0]
			if affected.GetPackage().GetPurl() != tc.expectedPurl {
				t.Errorf("Expected PURL %q, got %q", tc.expectedPurl, affected.GetPackage().GetPurl())
			}
		})
	}
}
