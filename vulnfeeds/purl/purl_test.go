package purl

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestToOSVPackage(t *testing.T) {
	tests := []struct {
		name string
		purl string
		want *osvschema.Package
	}{
		{
			name: "maven joins group and artifact with a colon",
			purl: "pkg:maven/org.apache.logging.log4j/log4j-core",
			want: &osvschema.Package{Ecosystem: "Maven", Name: "org.apache.logging.log4j:log4j-core", Purl: "pkg:maven/org.apache.logging.log4j/log4j-core"},
		},
		{
			name: "npm unscoped",
			purl: "pkg:npm/lodash",
			want: &osvschema.Package{Ecosystem: "npm", Name: "lodash", Purl: "pkg:npm/lodash"},
		},
		{
			name: "npm scope with a literal at sign",
			purl: "pkg:npm/@fastify/jwt",
			want: &osvschema.Package{Ecosystem: "npm", Name: "@fastify/jwt", Purl: "pkg:npm/%40fastify/jwt"},
		},
		{
			name: "npm scope with a percent-encoded at sign",
			purl: "pkg:npm/%40fastify/jwt",
			want: &osvschema.Package{Ecosystem: "npm", Name: "@fastify/jwt", Purl: "pkg:npm/%40fastify/jwt"},
		},
		{
			name: "pypi names are normalized",
			purl: "pkg:pypi/Django_Allauth",
			want: &osvschema.Package{Ecosystem: "PyPI", Name: "django-allauth", Purl: "pkg:pypi/django-allauth"},
		},
		{
			name: "golang keeps the full module path",
			purl: "pkg:golang/github.com/gohugoio/hugo",
			want: &osvschema.Package{Ecosystem: "Go", Name: "github.com/gohugoio/hugo", Purl: "pkg:golang/github.com/gohugoio/hugo"},
		},
		{
			name: "golang preserves the case of the module path",
			purl: "pkg:golang/github.com/Masterminds/goutils@v1.1.1?type=mod#sub",
			want: &osvschema.Package{Ecosystem: "Go", Name: "github.com/Masterminds/goutils", Purl: "pkg:golang/github.com/masterminds/goutils"},
		},
		{
			name: "composer names are lowercase",
			purl: "pkg:composer/Apache/Superset",
			want: &osvschema.Package{Ecosystem: "Packagist", Name: "apache/superset", Purl: "pkg:composer/apache/superset"},
		},
		{
			name: "composer",
			purl: "pkg:composer/apache/superset",
			want: &osvschema.Package{Ecosystem: "Packagist", Name: "apache/superset", Purl: "pkg:composer/apache/superset"},
		},
		{
			name: "version, qualifiers and subpath are dropped",
			purl: "pkg:cargo/hickory-recursor@0.25.0?arch=x86#src",
			want: &osvschema.Package{Ecosystem: "crates.io", Name: "hickory-recursor", Purl: "pkg:cargo/hickory-recursor"},
		},
		{
			name: "conan",
			purl: "pkg:conan/thrift",
			want: &osvschema.Package{Ecosystem: "ConanCenter", Name: "thrift", Purl: "pkg:conan/thrift"},
		},
		{
			name: "gem",
			purl: "pkg:gem/resolv",
			want: &osvschema.Package{Ecosystem: "RubyGems", Name: "resolv", Purl: "pkg:gem/resolv"},
		},
		{
			name: "nuget",
			purl: "pkg:nuget/UmbracoForms",
			want: &osvschema.Package{Ecosystem: "NuGet", Name: "UmbracoForms", Purl: "pkg:nuget/UmbracoForms"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToOSVPackage(tt.purl)
			if err != nil {
				t.Fatalf("ToOSVPackage(%q) returned error: %v", tt.purl, err)
			}
			if diff := cmp.Diff(tt.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("ToOSVPackage(%q) mismatch (-want +got):\n%s", tt.purl, diff)
			}
		})
	}
}

func TestToOSVPackage_Errors(t *testing.T) {
	tests := []struct {
		name        string
		purl        string
		unsupported bool
	}{
		{name: "empty", purl: ""},
		{name: "not a purl", purl: "https://example.com/foo"},
		{name: "no name", purl: "pkg:npm/"},
		{name: "github is not an ecosystem", purl: "pkg:github/apache/logging-log4j2", unsupported: true},
		{name: "opam", purl: "pkg:opam/cohttp", unsupported: true},
		{name: "cpan", purl: "pkg:cpan/Lucy", unsupported: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToOSVPackage(tt.purl)
			if err == nil {
				t.Fatalf("ToOSVPackage(%q) = %v, want error", tt.purl, got)
			}
			if errors.Is(err, ErrUnsupported) != tt.unsupported {
				t.Errorf("ToOSVPackage(%q) error = %v, want unsupported = %v", tt.purl, err, tt.unsupported)
			}
		})
	}
}
