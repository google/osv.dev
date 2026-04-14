// Package purl provides utilities for converting between OSV ecosystems and Package URLs (PURLs).
package purl

import (
	"fmt"
	"strings"
	"sync"

	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	packageurl "github.com/package-url/packageurl-go"
)

// Adapter transforms a package name into PURL components.
type Adapter func(ecosystem, packageName string) (namespace, name string, qualifiers packageurl.Qualifiers)

// Parser transforms a parsed PURL back into an OSV package name and ecosystem.
type Parser func(purl packageurl.PackageURL) (packageName string, ecosystem string, err error)

// EcosystemConfig holds the configuration and special logic for an ecosystem.
type EcosystemConfig struct {
	Type       string
	Namespace  string
	Qualifiers packageurl.Qualifiers
	Adapter    Adapter
	Reverse    Parser
}

var (
	ecosystemConfigs = make(map[osvconstants.Ecosystem]EcosystemConfig)
	reverseLookup    = make(map[string]osvconstants.Ecosystem) // "type/namespace" -> "EcosystemName"
	registryOnce     sync.Once
)

func ensureRegistryPopulated() {
	registryOnce.Do(func() {
		registerSimpleEcosystems()
		registerDebian()
		registerGo()
		registerMaven()
	})
}

// register adds a new ecosystem configuration.
func register(name osvconstants.Ecosystem, config EcosystemConfig) {
	ecosystemConfigs[name] = config

	// Build reverse lookup key
	key := config.Type
	if config.Namespace != "" {
		key = config.Type + "/" + config.Namespace
	}

	// Collision detection
	if existingEco, collision := reverseLookup[key]; collision {
		// We panic on collision to ensure developer awareness during init
		panic(fmt.Sprintf("PURL collision: %s and %s both map to %s", name, existingEco, key))
	}

	reverseLookup[key] = name
}

// PackageToPURL converts an ecosystem and package name to a PURL string.
func PackageToPURL(ecosystem, packageName string) (string, error) {
	ensureRegistryPopulated()
	baseEcosystem, _, _ := strings.Cut(ecosystem, ":")

	config, ok := ecosystemConfigs[osvconstants.Ecosystem(baseEcosystem)]
	if !ok {
		return "", fmt.Errorf("unknown ecosystem: %s", ecosystem)
	}

	namespace := config.Namespace
	name := packageName
	qualifiers := config.Qualifiers

	if config.Adapter != nil {
		ns, n, q := config.Adapter(ecosystem, packageName)
		if ns != "" {
			namespace = ns
		}
		if n != "" {
			name = n
		}
		if len(q) > 0 {
			qualifiers = append(qualifiers, q...)
		}
	}

	purl := packageurl.NewPackageURL(config.Type, namespace, name, "", qualifiers, "")

	return purl.ToString(), nil
}

// ParsePURL parses a PURL string and returns the ecosystem, package, and version.
func ParsePURL(purlStr string) (ecosystem, packageName, version string, err error) {
	ensureRegistryPopulated()
	purl, err := packageurl.FromString(purlStr)
	if err != nil {
		return "", "", "", err
	}

	key := purl.Type
	if purl.Namespace != "" {
		key = purl.Type + "/" + purl.Namespace
	}

	ecoName, ok := reverseLookup[key]
	if !ok {
		// Try fallback without namespace
		ecoName, ok = reverseLookup[purl.Type]
		if !ok {
			return "", "", "", fmt.Errorf("unknown PURL type: %s", purl.Type)
		}
	}

	config := ecosystemConfigs[ecoName]
	packageName = purl.Name
	ecosystem = string(ecoName)

	if config.Reverse != nil {
		pName, eco, err := config.Reverse(purl)
		if err != nil {
			return "", "", "", err
		}
		packageName = pName
		ecosystem = eco
	} else if purl.Namespace != "" && key == purl.Type {
		// Default fallback for implicit namespaces (e.g. NPM scopes)
		packageName = purl.Namespace + "/" + purl.Name
	}

	return ecosystem, packageName, purl.Version, nil
}
