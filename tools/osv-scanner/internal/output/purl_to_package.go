package output

import (
	"github.com/package-url/packageurl-go"
)

func PurlToPackage(purl string) (Package, error) {
	parsedPURL, err := packageurl.FromString(purl)
	if err != nil {
		// log.Printf("Failed to parse purl: %s, with error: %s", purl, err)
		return Package{}, err
	}
	return Package{
		Name:      parsedPURL.Name,
		Ecosystem: parsedPURL.Type, // TODO: Might want some mapping here to properly cased ecosystems
		Version:   parsedPURL.Version,
	}, nil
}
