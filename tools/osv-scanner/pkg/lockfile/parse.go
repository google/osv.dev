package lockfile

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
)

func FindParser(pathToLockfile string, parseAs string) (PackageDetailsParser, string) {
	if parseAs == "" {
		parseAs = path.Base(pathToLockfile)
	}

	return parsers[parseAs], parseAs
}

//nolint:gochecknoglobals // this is an optimisation and read-only
var parsers = map[string]PackageDetailsParser{
	"Cargo.lock":        ParseCargoLock,
	"composer.lock":     ParseComposerLock,
	"Gemfile.lock":      ParseGemfileLock,
	"go.mod":            ParseGoLock,
	"mix.lock":          ParseMixLock,
	"package-lock.json": ParseNpmLock,
	"pnpm-lock.yaml":    ParsePnpmLock,
	"poetry.lock":       ParsePoetryLock,
	"pom.xml":           ParseMavenLock,
	"pubspec.lock":      ParsePubspecLock,
	"requirements.txt":  ParseRequirementsTxt,
	"yarn.lock":         ParseYarnLock,
}

func ListParsers() []string {
	ps := make([]string, 0, len(parsers))

	for s := range parsers {
		ps = append(ps, s)
	}

	sort.Slice(ps, func(i, j int) bool {
		return strings.ToLower(ps[i]) < strings.ToLower(ps[j])
	})

	return ps
}

var ErrParserNotFound = errors.New("could not determine parser")

type Packages []PackageDetails

func toSliceOfEcosystems(ecosystemsMap map[Ecosystem]struct{}) []Ecosystem {
	ecosystems := make([]Ecosystem, 0, len(ecosystemsMap))

	for ecosystem := range ecosystemsMap {
		if ecosystem == "" {
			continue
		}

		ecosystems = append(ecosystems, ecosystem)
	}

	return ecosystems
}

func (ps Packages) Ecosystems() []Ecosystem {
	ecosystems := make(map[Ecosystem]struct{})

	for _, pkg := range ps {
		ecosystems[pkg.Ecosystem] = struct{}{}
	}

	slicedEcosystems := toSliceOfEcosystems(ecosystems)

	sort.Slice(slicedEcosystems, func(i, j int) bool {
		return slicedEcosystems[i] < slicedEcosystems[j]
	})

	return slicedEcosystems
}

type Lockfile struct {
	FilePath string   `json:"filePath"`
	ParsedAs string   `json:"parsedAs"`
	Packages Packages `json:"packages"`
}

func (l Lockfile) String() string {
	lines := make([]string, 0, len(l.Packages))

	for _, details := range l.Packages {
		ecosystem := details.Ecosystem

		if ecosystem == "" {
			ecosystem = "<unknown>"
		}

		ln := fmt.Sprintf("  %s: %s", ecosystem, details.Name)

		if details.Version != "" {
			ln += "@" + details.Version
		}

		if details.Commit != "" {
			ln += " (" + details.Commit + ")"
		}

		lines = append(lines, ln)
	}

	return strings.Join(lines, "\n")
}

// Parse attempts to extract a collection of package details from a lockfile,
// using one of the native parsers.
//
// The parser is selected based on the name of the file, which can be overridden
// with the "parseAs" parameter.
func Parse(pathToLockfile string, parseAs string) (Lockfile, error) {
	parser, parsedAs := FindParser(pathToLockfile, parseAs)

	if parser == nil {
		return Lockfile{}, fmt.Errorf("%w for %s", ErrParserNotFound, pathToLockfile)
	}

	packages, err := parser(pathToLockfile)

	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].Version < packages[j].Version
		}

		return packages[i].Name < packages[j].Name
	})

	return Lockfile{
		FilePath: pathToLockfile,
		ParsedAs: parsedAs,
		Packages: packages,
	}, err
}
