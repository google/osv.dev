package purl

import (
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/package-url/packageurl-go"
)

var debianCodenames = map[string]string{
	"1.1": "buzz",
	"1.2": "rex",
	"1.3": "bo",
	"2":   "hamm",
	"2.1": "slink",
	"2.2": "potato",
	"3":   "woody",
	"3.1": "sarge",
	"4":   "etch",
	"5":   "lenny",
	"6":   "squeeze",
	"7":   "wheezy",
	"8":   "jessie",
	"9":   "stretch",
	"10":  "buster",
	"11":  "bullseye",
	"12":  "bookworm",
	"13":  "trixie",
	"14":  "forky",
	"15":  "duke",
}

var debianVersions = map[string]string{}

//nolint:gochecknoinits // init is used here to register the ecosystem with the global PURL registry.
func init() {
	// Invert the map for reverse lookup
	for version, codename := range debianCodenames {
		debianVersions[codename] = version
	}

	registerGenerator(osvconstants.EcosystemDebian, generatorFunc(debianGenerator))
	registerParser("deb", "debian", parserFunc(debianParser))
}

func debianGenerator(ecosystem, packageName string) (packageurl.PackageURL, error) {
	var qualifiers packageurl.Qualifiers

	if strings.Contains(ecosystem, ":") {
		parts := strings.SplitN(ecosystem, ":", 2)
		version := parts[1]
		if codename, ok := debianCodenames[version]; ok {
			qualifiers = append(qualifiers, packageurl.Qualifier{Key: "distro", Value: codename})
		} else {
			// Fallback to using the version number directly
			qualifiers = append(qualifiers, packageurl.Qualifier{Key: "distro", Value: version})
		}
	}

	// Add static qualifiers
	qualifiers = append(qualifiers, packageurl.Qualifier{Key: "arch", Value: "source"})

	return *packageurl.NewPackageURL("deb", "debian", packageName, "", qualifiers, ""), nil
}

func debianParser(purl packageurl.PackageURL) (string, string, error) {
	ecosystem := "Debian"

	for _, q := range purl.Qualifiers {
		if q.Key == "distro" {
			distroVal := strings.ToLower(q.Value)
			// Lenient mapping: check if it's a codename
			if version, ok := debianVersions[distroVal]; ok {
				ecosystem = "Debian:" + version
			} else {
				// Or if it's already a version number (e.g., distro=11)
				ecosystem = "Debian:" + distroVal
			}
		}
	}

	return purl.Name, ecosystem, nil
}
