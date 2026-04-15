package purl

import (
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/package-url/packageurl-go"
)

//nolint:gochecknoinits // init is used here to register the ecosystem with the global PURL registry.
func init() {
	registerGenerator(osvconstants.EcosystemGo, generatorFunc(goGenerator))
	registerParser("golang", "", parserFunc(goParser))
}

func goGenerator(_, packageName string) (packageurl.PackageURL, error) {
	namespace := ""
	name := packageName
	if strings.Contains(packageName, "/") {
		parts := strings.Split(packageName, "/")
		name = parts[len(parts)-1]
		namespace = strings.Join(parts[:len(parts)-1], "/")
	}

	return *packageurl.NewPackageURL("golang", namespace, name, "", nil, ""), nil
}

func goParser(purl packageurl.PackageURL) (string, string, error) {
	packageName := purl.Name
	if purl.Namespace != "" {
		packageName = purl.Namespace + "/" + purl.Name
	}
	if purl.Subpath != "" {
		packageName = packageName + "/" + purl.Subpath
	}

	return packageName, "Go", nil
}
