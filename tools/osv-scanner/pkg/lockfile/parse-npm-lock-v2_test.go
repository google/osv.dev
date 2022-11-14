package lockfile_test

import (
	"github.com/google/osv.dev/tools/osv-scanner/pkg/lockfile"
	"testing"
)

func TestParseNpmLock_v2_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/does-not-exist")

	expectErrContaining(t, err, "could not read")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseNpmLock_v2_InvalidJson(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/not-json.txt")

	expectErrContaining(t, err, "could not parse")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseNpmLock_v2_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/empty.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseNpmLock_v2_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/one-package.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "wrappy",
			Version:   "1.0.2",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
	})
}

func TestParseNpmLock_v2_OnePackageDev(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/one-package-dev.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "wrappy",
			Version:   "1.0.2",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
	})
}

func TestParseNpmLock_v2_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/two-packages.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "wrappy",
			Version:   "1.0.2",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
		{
			Name:      "supports-color",
			Version:   "5.5.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
	})
}

func TestParseNpmLock_v2_ScopedPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/scoped-packages.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "wrappy",
			Version:   "1.0.2",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
		{
			Name:      "@babel/code-frame",
			Version:   "7.0.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
	})
}

func TestParseNpmLock_v2_NestedDependencies(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/nested-dependencies.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "postcss",
			Version:   "6.0.23",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
		{
			Name:      "postcss",
			Version:   "7.0.16",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
		{
			Name:      "postcss-calc",
			Version:   "7.0.1",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
		{
			Name:      "supports-color",
			Version:   "6.1.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
		{
			Name:      "supports-color",
			Version:   "5.5.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
	})
}

func TestParseNpmLock_v2_NestedDependenciesDup(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/nested-dependencies-dup.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "supports-color",
			Version:   "6.1.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
		{
			Name:      "supports-color",
			Version:   "2.0.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
		},
	})
}

func TestParseNpmLock_v2_Commits(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/commits.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "@segment/analytics.js-integration-facebook-pixel",
			Version:   "2.4.1",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "3b1bb80b302c2e552685dc8a029797ec832ea7c9",
		},
		{
			Name:      "ansi-styles",
			Version:   "1.0.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "",
		},
		{
			Name:      "babel-preset-php",
			Version:   "1.1.1",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "c5a7ba5e0ad98b8db1cb8ce105403dd4b768cced",
		},
		{
			Name:      "is-number-1",
			Version:   "3.0.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "af885e2e890b9ef0875edd2b117305119ee5bdc5",
		},
		{
			Name:      "is-number-1",
			Version:   "3.0.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "be5935f8d2595bcd97b05718ef1eeae08d812e10",
		},
		{
			Name:      "is-number-2",
			Version:   "2.0.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
		},
		{
			Name:      "is-number-2",
			Version:   "2.0.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "82dcc8e914dabd9305ab9ae580709a7825e824f5",
		},
		{
			Name:      "is-number-3",
			Version:   "2.0.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
		},
		{
			Name:      "is-number-3",
			Version:   "3.0.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "82ae8802978da40d7f1be5ad5943c9e550ab2c89",
		},
		{
			Name:      "is-number-4",
			Version:   "3.0.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "af885e2e890b9ef0875edd2b117305119ee5bdc5",
		},
		{
			Name:      "is-number-5",
			Version:   "3.0.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "af885e2e890b9ef0875edd2b117305119ee5bdc5",
		},
		{
			Name:      "postcss-calc",
			Version:   "7.0.1",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "",
		},
		{
			Name:      "raven-js",
			Version:   "",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "c2b377e7a254264fd4a1fe328e4e3cfc9e245570",
		},
		{
			Name:      "slick-carousel",
			Version:   "1.7.1",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "280b560161b751ba226d50c7db1e0a14a78c2de0",
		},
	})
}

func TestParseNpmLock_v2_Files(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/files.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "etag",
			Version:   "1.8.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "",
		},
		{
			Name:      "abbrev",
			Version:   "1.0.9",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "",
		},
		{
			Name:      "abbrev",
			Version:   "2.3.4",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "",
		},
	})
}
