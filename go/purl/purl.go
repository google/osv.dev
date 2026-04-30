// Package purl provides utilities for converting between OSV ecosystems and Package URLs (PURLs).
package purl

import (
	"fmt"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	packageurl "github.com/package-url/packageurl-go"
)

// Generate converts an ecosystem and package name to a PURL string.
func Generate(ecosystem, packageName string) (string, error) {
	baseEcosystem, _, _ := strings.Cut(ecosystem, ":")

	gen, ok := generators[osvconstants.Ecosystem(baseEcosystem)]
	if !ok {
		return "", fmt.Errorf("unknown ecosystem: %s", ecosystem)
	}

	purl, err := gen.generate(ecosystem, packageName)
	if err != nil {
		return "", err
	}

	return purl.ToString(), nil
}

// Parse parses a PURL string and returns the ecosystem, package, and version.
func Parse(purlStr string) (ecosystem, packageName, version string, err error) {
	purl, err := packageurl.FromString(purlStr)
	if err != nil {
		return "", "", "", err
	}

	key := purl.Type
	if purl.Namespace != "" {
		key = purl.Type + "/" + purl.Namespace
	}

	parser, ok := parsers[key]
	if !ok {
		// Try fallback without namespace
		parser, ok = parsers[purl.Type]
		if !ok {
			return "", "", "", fmt.Errorf("unknown PURL type: %s", purl.Type)
		}
	}

	packageName, ecosystem, err = parser.parse(purl)
	if err != nil {
		return "", "", "", err
	}

	return ecosystem, packageName, purl.Version, nil
}

var (
	generators = make(map[osvconstants.Ecosystem]purlGenerator)
	parsers    = make(map[string]purlParser) // "type/namespace" -> purlParser
)

// registerGenerator adds a new configuration for OSV -> PURL generation.
func registerGenerator(name osvconstants.Ecosystem, gen purlGenerator) {
	generators[name] = gen
}

// registerParser adds a mapping for PURL -> OSV parsing.
func registerParser(purlType string, namespace string, parser purlParser) {
	key := purlType
	if namespace != "" {
		key = purlType + "/" + namespace
	}

	// Collision detection
	if _, ok := parsers[key]; ok {
		panic(fmt.Sprintf("PURL collision: %s is already registered", key))
	}

	parsers[key] = parser
}

// purlGenerator transforms a package name into a PURL.
type purlGenerator interface {
	generate(ecosystem, packageName string) (packageurl.PackageURL, error)
}

// generatorFunc allows simple functions to implement purlGenerator.
type generatorFunc func(ecosystem, packageName string) (packageurl.PackageURL, error)

func (f generatorFunc) generate(ecosystem, packageName string) (packageurl.PackageURL, error) {
	return f(ecosystem, packageName)
}

// purlParser transforms a parsed PURL back into an OSV package name and ecosystem.
type purlParser interface {
	parse(purl packageurl.PackageURL) (packageName string, ecosystem string, err error)
}

// parserFunc allows simple functions to implement purlParser.
type parserFunc func(purl packageurl.PackageURL) (packageName string, ecosystem string, err error)

func (f parserFunc) parse(purl packageurl.PackageURL) (packageName string, ecosystem string, err error) {
	return f(purl)
}
