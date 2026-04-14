package purl

import "github.com/package-url/packageurl-go"

func init() {
	// Language Ecosystems (No namespace)
	Register("Bitnami", EcosystemConfig{Type: "bitnami"})
	Register("ConanCenter", EcosystemConfig{Type: "conan"})
	Register("CRAN", EcosystemConfig{Type: "cran"})
	Register("crates.io", EcosystemConfig{Type: "cargo"})
	Register("Docker Hardened Images", EcosystemConfig{Type: "dhi"})
	Register("Hackage", EcosystemConfig{Type: "hackage"})
	Register("Hex", EcosystemConfig{Type: "hex"})
	Register("Julia", EcosystemConfig{Type: "julia"})
	Register("npm", EcosystemConfig{Type: "npm"})
	Register("NuGet", EcosystemConfig{Type: "nuget"})
	Register("opam", EcosystemConfig{Type: "opam"})
	Register("OSS-Fuzz", EcosystemConfig{Type: "generic"})
	Register("Packagist", EcosystemConfig{Type: "composer"})
	Register("Pub", EcosystemConfig{Type: "pub"})
	Register("PyPI", EcosystemConfig{Type: "pypi"})
	Register("RubyGems", EcosystemConfig{Type: "gem"})
	Register("SwiftURL", EcosystemConfig{Type: "swift"})

	// OS Ecosystems (With static namespace)
	Register("Chainguard", EcosystemConfig{Type: "apk", Namespace: "chainguard"})
	Register("MinimOS", EcosystemConfig{Type: "apk", Namespace: "minimos"})
	Register("Wolfi", EcosystemConfig{Type: "apk", Namespace: "wolfi"})
	Register("Echo", EcosystemConfig{Type: "deb", Namespace: "echo"})
	Register("Ubuntu", EcosystemConfig{Type: "deb", Namespace: "ubuntu"})
	Register("AlmaLinux", EcosystemConfig{Type: "rpm", Namespace: "almalinux"})
	Register("Azure Linux", EcosystemConfig{Type: "rpm", Namespace: "azure-linux"})
	Register("Mageia", EcosystemConfig{Type: "rpm", Namespace: "mageia"})
	Register("openEuler", EcosystemConfig{Type: "rpm", Namespace: "openeuler"})
	Register("openSUSE", EcosystemConfig{Type: "rpm", Namespace: "opensuse"})
	Register("Red Hat", EcosystemConfig{Type: "rpm", Namespace: "redhat"})
	Register("Rocky Linux", EcosystemConfig{Type: "rpm", Namespace: "rocky-linux"})
	Register("SUSE", EcosystemConfig{Type: "rpm", Namespace: "suse"})

	// OS Ecosystems requiring static qualifiers
	sourceArchQualifiers := packageurl.Qualifiers{packageurl.Qualifier{Key: "arch", Value: "source"}}

	Register("Alpaquita", EcosystemConfig{Type: "apk", Namespace: "alpaquita", Qualifiers: sourceArchQualifiers})
	Register("Alpine", EcosystemConfig{Type: "apk", Namespace: "alpine", Qualifiers: sourceArchQualifiers})
	Register("BellSoft Hardened Containers", EcosystemConfig{Type: "apk", Namespace: "bellsoft-hardened-containers", Qualifiers: sourceArchQualifiers})
}
