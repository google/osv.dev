package purl

import (
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/package-url/packageurl-go"
)

var debianCodenames = map[string]string{
	"7":  "wheezy",
	"8":  "jessie",
	"9":  "stretch",
	"10": "buster",
	"11": "bullseye",
	"12": "bookworm",
	"13": "trixie",
	"14": "forky",
}

var debianVersions = map[string]string{}

func init() {
	// Invert the map for reverse lookup
	for version, codename := range debianCodenames {
		debianVersions[codename] = version
	}

	Register(osvconstants.EcosystemDebian, EcosystemConfig{
		Type:       "deb",
		Namespace:  "debian",
		Qualifiers: packageurl.Qualifiers{packageurl.Qualifier{Key: "arch", Value: "source"}},
		Adapter:    debianAdapter,
		Reverse:    debianParser,
	})
}

func debianAdapter(ecosystem, packageName string) (string, string, packageurl.Qualifiers) {
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

	return "debian", packageName, qualifiers
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
