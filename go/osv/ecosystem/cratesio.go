package ecosystem

import "strings"

// cratesEcosystem is the crates.io ecosystem. crates.io compares crate names
// case-insensitively and treats '-' and '_' as equivalent (a crate named
// "foo-bar" and one named "foo_bar" cannot both exist), so names are folded to
// lowercase with '_' mapped to '-' for matching.
type cratesEcosystem struct {
	semverEcosystem
}

// NormalizePackageName folds a crates.io name to lowercase and maps '_' to '-'.
func (e cratesEcosystem) NormalizePackageName(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), "_", "-")
}

var (
	_ Ecosystem             = cratesEcosystem{}
	_ PackageNameNormalizer = cratesEcosystem{}
)
