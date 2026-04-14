package purl

import (
	"strings"

	"github.com/package-url/packageurl-go"
)

func registerMaven() {
	register("Maven", EcosystemConfig{
		Type:    "maven",
		Adapter: mavenAdapter,
		Reverse: mavenParser,
	})
	// Add Gradle alias for reverse lookup
	reverseLookup["gradle"] = "Maven"
}

func mavenAdapter(_, packageName string) (string, string, packageurl.Qualifiers) {
	parts := strings.SplitN(packageName, ":", 2)
	if len(parts) == 2 {
		return parts[0], parts[1], nil
	}

	return "", packageName, nil
}

func mavenParser(purl packageurl.PackageURL) (string, string, error) {
	packageName := purl.Name
	if purl.Namespace != "" {
		packageName = purl.Namespace + ":" + purl.Name
	}

	return packageName, "Maven", nil
}
