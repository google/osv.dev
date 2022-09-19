package output

import (
	"log"

	"github.com/package-url/packageurl-go"
)

func PurlToPackage(purl string) Package {
	parsedPURL, err := packageurl.FromString(purl)
	if err != nil {
		log.Fatalf("Failed to parse purl: %s, with error: %s", purl, err)
	}
	return Package{
		Name:      parsedPURL.Name,
		Ecosystem: parsedPURL.Namespace,
		Version:   parsedPURL.Version,
	}
}
