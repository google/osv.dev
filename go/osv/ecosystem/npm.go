package ecosystem

import "strings"

// npmEcosystem is the npm ecosystem. npm package names are case-insensitive:
// the registry treats names in lowercase and rejects a new name that differs
// from an existing one only in case, so names are folded to lowercase for
// matching.
type npmEcosystem struct {
	semverEcosystem
}

// NormalizePackageName folds an npm package name to lowercase.
func (e npmEcosystem) NormalizePackageName(name string) string {
	return strings.ToLower(name)
}

var (
	_ Ecosystem             = npmEcosystem{}
	_ PackageNameNormalizer = npmEcosystem{}
)
