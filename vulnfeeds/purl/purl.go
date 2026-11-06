// Package purl maps Package URLs (purls) found in CVE records to OSV packages.
//
// The main go module has a more complete purl package, but vulnfeeds is a
// separate module, so this only covers the purl types the CVE5 converter needs.
package purl

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	packageurl "github.com/package-url/packageurl-go"
)

// ErrUnsupported is returned for purl types that do not map to an OSV ecosystem.
var ErrUnsupported = errors.New("unsupported purl type")

// ecosystems maps a purl type to the OSV ecosystem it identifies.
var ecosystems = map[string]osvconstants.Ecosystem{
	"cargo":    osvconstants.EcosystemCratesIO,
	"composer": osvconstants.EcosystemPackagist,
	"conan":    osvconstants.EcosystemConanCenter,
	"gem":      osvconstants.EcosystemRubyGems,
	"golang":   osvconstants.EcosystemGo,
	"maven":    osvconstants.EcosystemMaven,
	"npm":      osvconstants.EcosystemNPM,
	"nuget":    osvconstants.EcosystemNuGet,
	"pypi":     osvconstants.EcosystemPyPI,
}

// ToOSVPackage converts a purl to an OSV package. The returned package carries the
// canonical purl with any version, qualifiers, and subpath removed.
//
// Scoped npm packages are accepted with a literal or percent-encoded "@" in the scope.
func ToOSVPackage(s string) (*osvschema.Package, error) {
	p, err := packageurl.FromString(s)
	if err != nil {
		return nil, fmt.Errorf("parsing purl %q: %w", s, err)
	}

	eco, ok := ecosystems[p.Type]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupported, p.Type)
	}
	if p.Name == "" {
		return nil, fmt.Errorf("purl %q has no package name", s)
	}

	name := p.Name
	if p.Namespace != "" {
		sep := "/"
		if p.Type == packageurl.TypeMaven {
			sep = ":"
		}
		name = p.Namespace + sep + p.Name
	}

	if p.Type == packageurl.TypeGolang {
		name = goModulePath(s, name)
	}

	canonical := packageurl.PackageURL{Type: p.Type, Namespace: p.Namespace, Name: p.Name}

	return &osvschema.Package{
		Ecosystem: string(eco),
		Name:      name,
		Purl:      canonical.ToString(),
	}, nil
}

// goModulePath returns the module path as written in the purl. packageurl-go lowercases golang
// purls, but Go module paths are case-sensitive, so a lowercased path would never match.
func goModulePath(raw, parsed string) string {
	path := strings.TrimPrefix(raw, "pkg:golang/")
	path, _, _ = strings.Cut(path, "#")
	path, _, _ = strings.Cut(path, "?")
	if i := strings.LastIndex(path, "@"); i >= 0 {
		path = path[:i]
	}
	if unescaped, err := url.PathUnescape(path); err == nil {
		path = unescaped
	}
	if strings.EqualFold(path, parsed) {
		return path
	}

	return parsed
}
