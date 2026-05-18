package purl

import (
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/package-url/packageurl-go"
)

// simpleGenerator handles standard PURL mappings without special logic.
type simpleGenerator struct {
	purlType   string
	namespace  string
	qualifiers packageurl.Qualifiers
}

func (g simpleGenerator) generate(_, packageName string) (packageurl.PackageURL, error) {
	return *packageurl.NewPackageURL(g.purlType, g.namespace, packageName, "", g.qualifiers, ""), nil
}

// simpleParser handles standard PURL mappings without special logic.
type simpleParser struct {
	ecosystem     osvconstants.Ecosystem
	joinNamespace bool
}

func (p simpleParser) parse(purl packageurl.PackageURL) (packageName string, ecosystem string, err error) {
	packageName = purl.Name
	if p.joinNamespace && purl.Namespace != "" {
		packageName = purl.Namespace + "/" + purl.Name
	}

	return packageName, string(p.ecosystem), nil
}

func registerSimple(ecosystem osvconstants.Ecosystem, purlType string, namespace string, qualifiers packageurl.Qualifiers) {
	registerGenerator(ecosystem, simpleGenerator{purlType: purlType, namespace: namespace, qualifiers: qualifiers})
	registerParser(purlType, namespace, simpleParser{ecosystem: ecosystem})
}

//nolint:gochecknoinits // init is used here to register simple ecosystems with the global PURL registry.
func init() {
	// Language Ecosystems (No namespace)
	registerSimple(osvconstants.EcosystemBitnami, "bitnami", "", nil)
	registerSimple(osvconstants.EcosystemCRAN, "cran", "", nil)
	registerSimple(osvconstants.EcosystemConanCenter, "conan", "", nil)
	registerSimple(osvconstants.EcosystemDockerHardenedImages, "dhi", "", nil)
	registerSimple(osvconstants.EcosystemHackage, "hackage", "", nil)
	registerSimple(osvconstants.EcosystemHex, "hex", "", nil)
	registerSimple(osvconstants.EcosystemJulia, "julia", "", nil)
	registerSimple(osvconstants.EcosystemNuGet, "nuget", "", nil)
	registerSimple(osvconstants.EcosystemOSSFuzz, "generic", "", nil)
	registerSimple(osvconstants.EcosystemPackagist, "composer", "", nil)
	registerSimple(osvconstants.EcosystemPub, "pub", "", nil)
	registerSimple(osvconstants.EcosystemPyPI, "pypi", "", nil)
	registerSimple(osvconstants.EcosystemRubyGems, "gem", "", nil)
	registerSimple(osvconstants.EcosystemSwiftURL, "swift", "", nil)
	registerSimple(osvconstants.EcosystemCratesIO, "cargo", "", nil)
	registerGenerator(osvconstants.EcosystemNPM, simpleGenerator{purlType: "npm"})
	registerParser("npm", "", simpleParser{ecosystem: osvconstants.EcosystemNPM, joinNamespace: true})
	registerSimple(osvconstants.EcosystemOpam, "opam", "", nil)

	// OS Ecosystems (With static namespace)
	registerSimple(osvconstants.EcosystemChainguard, "apk", "chainguard", nil)
	registerSimple(osvconstants.EcosystemMinimOS, "apk", "minimos", nil)
	registerSimple(osvconstants.EcosystemWolfi, "apk", "wolfi", nil)
	registerSimple(osvconstants.EcosystemEcho, "deb", "echo", nil)
	registerSimple(osvconstants.EcosystemUbuntu, "deb", "ubuntu", nil)
	registerSimple(osvconstants.EcosystemAlmaLinux, "rpm", "almalinux", nil)
	registerSimple(osvconstants.EcosystemAzureLinux, "rpm", "azure-linux", nil)
	registerSimple(osvconstants.EcosystemMageia, "rpm", "mageia", nil)
	registerSimple(osvconstants.EcosystemOpenEuler, "rpm", "openeuler", nil)
	registerSimple(osvconstants.EcosystemOpenSUSE, "rpm", "opensuse", nil)
	registerSimple(osvconstants.EcosystemRedHat, "rpm", "redhat", nil)
	registerSimple(osvconstants.EcosystemRockyLinux, "rpm", "rocky-linux", nil)
	registerSimple(osvconstants.EcosystemSUSE, "rpm", "suse", nil)

	// OS Ecosystems requiring static qualifiers
	sourceArchQualifiers := packageurl.Qualifiers{packageurl.Qualifier{Key: "arch", Value: "source"}}

	registerSimple(osvconstants.EcosystemAlpaquita, "apk", "alpaquita", sourceArchQualifiers)
	registerSimple(osvconstants.EcosystemAlpine, "apk", "alpine", sourceArchQualifiers)
	registerSimple(osvconstants.EcosystemBellSoftHardenedContainers, "apk", "bellsoft-hardened-containers", sourceArchQualifiers)
}
