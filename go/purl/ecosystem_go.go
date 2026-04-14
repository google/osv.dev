package purl

import (
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/package-url/packageurl-go"
)

func init() {
	Register(osvconstants.EcosystemGo, EcosystemConfig{
		Type:    "golang",
		Adapter: goAdapter,
		Reverse: goParser,
	})
}

func goAdapter(ecosystem, packageName string) (string, string, packageurl.Qualifiers) {
	if strings.Contains(packageName, "/") {
		parts := strings.Split(packageName, "/")
		name := parts[len(parts)-1]
		namespace := strings.Join(parts[:len(parts)-1], "/")
		return namespace, name, nil
	}
	return "", packageName, nil
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
