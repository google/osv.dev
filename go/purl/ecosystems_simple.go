package purl

import (
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/package-url/packageurl-go"
)

func registerSimpleEcosystems() {
	// Language Ecosystems (No namespace)
	register(osvconstants.EcosystemBitnami, EcosystemConfig{Type: "bitnami"})
	register(osvconstants.EcosystemCRAN, EcosystemConfig{Type: "cran"})
	register(osvconstants.EcosystemConanCenter, EcosystemConfig{Type: "conan"})
	register(osvconstants.EcosystemDockerHardenedImages, EcosystemConfig{Type: "dhi"})
	register(osvconstants.EcosystemHackage, EcosystemConfig{Type: "hackage"})
	register(osvconstants.EcosystemHex, EcosystemConfig{Type: "hex"})
	register(osvconstants.EcosystemJulia, EcosystemConfig{Type: "julia"})
	register(osvconstants.EcosystemNuGet, EcosystemConfig{Type: "nuget"})
	register(osvconstants.EcosystemOSSFuzz, EcosystemConfig{Type: "generic"})
	register(osvconstants.EcosystemPackagist, EcosystemConfig{Type: "composer"})
	register(osvconstants.EcosystemPub, EcosystemConfig{Type: "pub"})
	register(osvconstants.EcosystemPyPI, EcosystemConfig{Type: "pypi"})
	register(osvconstants.EcosystemRubyGems, EcosystemConfig{Type: "gem"})
	register(osvconstants.EcosystemSwiftURL, EcosystemConfig{Type: "swift"})
	register(osvconstants.EcosystemCratesIO, EcosystemConfig{Type: "cargo"})
	register(osvconstants.EcosystemNPM, EcosystemConfig{Type: "npm"})
	register(osvconstants.EcosystemOpam, EcosystemConfig{Type: "opam"})

	// OS Ecosystems (With static namespace)
	register(osvconstants.EcosystemChainguard, EcosystemConfig{Type: "apk", Namespace: "chainguard"})
	register(osvconstants.EcosystemMinimOS, EcosystemConfig{Type: "apk", Namespace: "minimos"})
	register(osvconstants.EcosystemWolfi, EcosystemConfig{Type: "apk", Namespace: "wolfi"})
	register(osvconstants.EcosystemEcho, EcosystemConfig{Type: "deb", Namespace: "echo"})
	register(osvconstants.EcosystemUbuntu, EcosystemConfig{Type: "deb", Namespace: "ubuntu"})
	register(osvconstants.EcosystemAlmaLinux, EcosystemConfig{Type: "rpm", Namespace: "almalinux"})
	register(osvconstants.EcosystemAzureLinux, EcosystemConfig{Type: "rpm", Namespace: "azure-linux"})
	register(osvconstants.EcosystemMageia, EcosystemConfig{Type: "rpm", Namespace: "mageia"})
	register(osvconstants.EcosystemOpenEuler, EcosystemConfig{Type: "rpm", Namespace: "openeuler"})
	register(osvconstants.EcosystemOpenSUSE, EcosystemConfig{Type: "rpm", Namespace: "opensuse"})
	register(osvconstants.EcosystemRedHat, EcosystemConfig{Type: "rpm", Namespace: "redhat"})
	register(osvconstants.EcosystemRockyLinux, EcosystemConfig{Type: "rpm", Namespace: "rocky-linux"})
	register(osvconstants.EcosystemSUSE, EcosystemConfig{Type: "rpm", Namespace: "suse"})

	// OS Ecosystems requiring static qualifiers
	sourceArchQualifiers := packageurl.Qualifiers{packageurl.Qualifier{Key: "arch", Value: "source"}}

	register(osvconstants.EcosystemAlpaquita, EcosystemConfig{Type: "apk", Namespace: "alpaquita", Qualifiers: sourceArchQualifiers})
	register(osvconstants.EcosystemAlpine, EcosystemConfig{Type: "apk", Namespace: "alpine", Qualifiers: sourceArchQualifiers})
	register(osvconstants.EcosystemBellSoftHardenedContainers, EcosystemConfig{Type: "apk", Namespace: "bellsoft-hardened-containers", Qualifiers: sourceArchQualifiers})
}
