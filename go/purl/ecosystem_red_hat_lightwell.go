package purl

import (
	"fmt"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/package-url/packageurl-go"
)

//nolint:gochecknoinits // init is used here to register the ecosystem with the global PURL registry.
func init() {
	registerGenerator(osvconstants.EcosystemRedHatLightwell, generatorFunc(redHatLightwellGenerator))
	// No reverse parser is registered on purpose: Red Hat Lightwell records carry
	// pkg:maven / pkg:pypi PURLs, whose types are already owned by the Maven/PyPI
	// parsers (registerParser panics on collision). PURL -> ecosystem resolution
	// for Lightwell is done via explicit ecosystem queries rather than the shared
	// pkg:maven/pkg:pypi types, which belong to the upstream ecosystems.
}

// redHatLightwellGenerator builds the PURL for a "Red Hat Lightwell:<base>"
// package by delegating to the base ecosystem's registered generator, named by
// the ":" suffix (e.g. "Red Hat Lightwell:Maven" -> pkg:maven, ":PyPI" -> pkg:pypi).
func redHatLightwellGenerator(ecosystem, packageName string) (packageurl.PackageURL, error) {
	_, suffix, _ := strings.Cut(ecosystem, ":")
	base := osvconstants.Ecosystem(suffix)

	switch base {
	case osvconstants.EcosystemMaven, osvconstants.EcosystemPyPI:
		gen, ok := generators[base]
		if !ok {
			return packageurl.PackageURL{}, fmt.Errorf("no PURL generator registered for base ecosystem %q", base)
		}

		return gen.generate(string(base), packageName)
	default:
		return packageurl.PackageURL{}, fmt.Errorf("unsupported Red Hat Lightwell ecosystem suffix %q", suffix)
	}
}
