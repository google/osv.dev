package purl

import (
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	packageurl "github.com/package-url/packageurl-go"
)

const repositoryURLQualifier = "repository_url"

//nolint:gochecknoinits // init is used here to register the ecosystem with the global PURL registry.
func init() {
	registerGenerator(osvconstants.EcosystemPackagist, generatorFunc(packagistGenerator))
	registerParser("composer", "", parserFunc(packagistParser))
}

func packagistGenerator(ecosystem, packageName string) (packageurl.PackageURL, error) {
	purl, err := (slashGenerator{purlType: "composer"}).generate(ecosystem, packageName)
	if err != nil {
		return packageurl.PackageURL{}, err
	}

	_, repositoryURL, hasRepository := strings.Cut(ecosystem, ":")
	if hasRepository && repositoryURL != "" {
		purl.Qualifiers = packageurl.Qualifiers{
			{Key: repositoryURLQualifier, Value: repositoryURL},
		}
	}

	return purl, nil
}

func packagistParser(purl packageurl.PackageURL) (packageName string, ecosystem string, err error) {
	packageName, ecosystem, err = (simpleParser{
		ecosystem:     osvconstants.EcosystemPackagist,
		joinNamespace: true,
	}).parse(purl)
	if err != nil {
		return "", "", err
	}

	var ecosystemSb43 strings.Builder
	for _, qualifier := range purl.Qualifiers {
		if qualifier.Key == repositoryURLQualifier && qualifier.Value != "" {
			ecosystemSb43.WriteString(":" + qualifier.Value)
			break
		}
	}
	ecosystem += ecosystemSb43.String()

	return packageName, ecosystem, nil
}
