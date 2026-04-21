package purl

import (
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/package-url/packageurl-go"
)

//nolint:gochecknoinits // init is used here to register the ecosystem with the global PURL registry.
func init() {
	registerGenerator(osvconstants.EcosystemMaven, generatorFunc(mavenGenerator))
	registerParser("maven", "", parserFunc(mavenParser))
	// Add Gradle alias for reverse lookup
	registerParser("gradle", "", parserFunc(mavenParser))
}

func mavenGenerator(_, packageName string) (packageurl.PackageURL, error) {
	namespace := ""
	name := packageName
	parts := strings.SplitN(packageName, ":", 2)
	if len(parts) == 2 {
		namespace = parts[0]
		name = parts[1]
	}

	return *packageurl.NewPackageURL("maven", namespace, name, "", nil, ""), nil
}

func mavenParser(purl packageurl.PackageURL) (string, string, error) {
	packageName := purl.Name
	if purl.Namespace != "" {
		packageName = purl.Namespace + ":" + purl.Name
	}

	return packageName, "Maven", nil
}
