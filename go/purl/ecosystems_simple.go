package purl

import (
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/package-url/packageurl-go"
)

func init() {
	// Language Ecosystems (No namespace)
	Register(osvconstants.EcosystemBitnami, EcosystemConfig{Type: "bitnami"})
	Register(osvconstants.EcosystemCRAN, EcosystemConfig{Type: "cran"})
	Register(osvconstants.EcosystemConanCenter, EcosystemConfig{Type: "conan"})
	Register(osvconstants.EcosystemDockerHardenedImages, EcosystemConfig{Type: "dhi"})
	Register(osvconstants.EcosystemHackage, EcosystemConfig{Type: "hackage"})
	Register(osvconstants.EcosystemHex, EcosystemConfig{Type: "hex"})
	Register(osvconstants.EcosystemJulia, EcosystemConfig{Type: "julia"})
	Register(osvconstants.EcosystemNuGet, EcosystemConfig{Type: "nuget"})
	Register(osvconstants.EcosystemOSSFuzz, EcosystemConfig{Type: "generic"})
	Register(osvconstants.EcosystemPackagist, EcosystemConfig{Type: "composer"})
	Register(osvconstants.EcosystemPub, EcosystemConfig{Type: "pub"})
	Register(osvconstants.EcosystemPyPI, EcosystemConfig{Type: "pypi"})
	Register(osvconstants.EcosystemRubyGems, EcosystemConfig{Type: "gem"})
	Register(osvconstants.EcosystemSwiftURL, EcosystemConfig{Type: "swift"})
	Register(osvconstants.EcosystemCratesIO, EcosystemConfig{Type: "cargo"})
	Register(osvconstants.EcosystemNPM, EcosystemConfig{Type: "npm"})
	Register(osvconstants.EcosystemOpam, EcosystemConfig{Type: "opam"})

	// OS Ecosystems (With static namespace)
	Register(osvconstants.EcosystemChainguard, EcosystemConfig{Type: "apk", Namespace: "chainguard"})
	Register(osvconstants.EcosystemMinimOS, EcosystemConfig{Type: "apk", Namespace: "minimos"})
	Register(osvconstants.EcosystemWolfi, EcosystemConfig{Type: "apk", Namespace: "wolfi"})
	Register(osvconstants.EcosystemEcho, EcosystemConfig{Type: "deb", Namespace: "echo"})
	Register(osvconstants.EcosystemUbuntu, EcosystemConfig{Type: "deb", Namespace: "ubuntu"})
	Register(osvconstants.EcosystemAlmaLinux, EcosystemConfig{Type: "rpm", Namespace: "almalinux"})
	Register(osvconstants.EcosystemAzureLinux, EcosystemConfig{Type: "rpm", Namespace: "azure-linux"})
	Register(osvconstants.EcosystemMageia, EcosystemConfig{Type: "rpm", Namespace: "mageia"})
	Register(osvconstants.EcosystemOpenEuler, EcosystemConfig{Type: "rpm", Namespace: "openeuler"})
	Register(osvconstants.EcosystemOpenSUSE, EcosystemConfig{Type: "rpm", Namespace: "opensuse"})
	Register(osvconstants.EcosystemRedHat, EcosystemConfig{Type: "rpm", Namespace: "redhat"})
	Register(osvconstants.EcosystemRockyLinux, EcosystemConfig{Type: "rpm", Namespace: "rocky-linux"})
	Register(osvconstants.EcosystemSUSE, EcosystemConfig{Type: "rpm", Namespace: "suse"})

	// OS Ecosystems requiring static qualifiers
	sourceArchQualifiers := packageurl.Qualifiers{packageurl.Qualifier{Key: "arch", Value: "source"}}

	Register(osvconstants.EcosystemAlpaquita, EcosystemConfig{Type: "apk", Namespace: "alpaquita", Qualifiers: sourceArchQualifiers})
	Register(osvconstants.EcosystemAlpine, EcosystemConfig{Type: "apk", Namespace: "alpine", Qualifiers: sourceArchQualifiers})
	Register(osvconstants.EcosystemBellSoftHardenedContainers, EcosystemConfig{Type: "apk", Namespace: "bellsoft-hardened-containers", Qualifiers: sourceArchQualifiers})
}
