# OSV Ecosystem Version Logic

Package `ecosystem` implements version parsing, comparison, coarse versions, and (for some ecosystems) version enumeration for [OSV ecosystems](https://ossf.github.io/osv-schema/#affectedpackage-field). Its companion package [`go/purl`](../../purl/) maps ecosystems and package names to and from [Package URLs](https://github.com/package-url/purl-spec).

This guide is for contributors (human or AI) who are adding or changing an ecosystem.

## Who uses it

- **Worker** ([`internal/worker/`](../../internal/worker/)): sorts range events, enumerates affected versions for `ECOSYSTEM` ranges ([`enumerateversions`](../../internal/worker/pipeline/enumerateversions/)), converts `SEMVER` ranges ([`makesemver`](../../internal/worker/pipeline/makesemver/)), normalizes package names ([`namenormalize`](../../internal/worker/pipeline/namenormalize/)), and generates PURLs ([`pipeline/purl`](../../internal/worker/pipeline/purl/)).
- **Database** ([`internal/database/datastore/`](../../internal/database/datastore/), [`internal/database/postgres/`](../../internal/database/postgres/)): computes `coarse_min`/`coarse_max` on `AffectedVersions` entities, and uses `Parse`/`Compare` and `Coarse` to match API queries. If an ecosystem isn't registered, or a version doesn't parse, matching falls back to plain string comparison.
- **API** ([`internal/api/`](../../internal/api/)): resolves PURLs in queries with `purl.Parse`.
- **Website** ([`internal/website/`](../../internal/website/)): sorts and groups versions for display.

Many ecosystems wrap [osv-scalibr's `semantic` package](https://github.com/google/osv-scalibr/tree/main/semantic), which osv-scanner also uses.

## Key types

All defined in [`ecosystem.go`](ecosystem.go) and [`provider.go`](provider.go):

| Identifier | Purpose |
| --- | --- |
| `Ecosystem` | Required interface: `Parse(string) (Version, error)`, `Coarse(string) (string, error)`, `IsSemver() bool`. |
| `Version` | A parsed version with `Compare(Version) (int, error)`. `SemanticVersionWrapper[V]` adapts a `semantic.Version`. |
| `Enumerable` | Optional: an `Ecosystem` that also implements `GetVersions(pkg) ([]string, error)` (ascending order). |
| `PackageNameNormalizer` | Optional: the normalized name is written into published records. Only for ecosystems whose OSV schema entry defines normalization (e.g. PyPI). |
| `MatchNameNormalizer` | Optional: folds names only for indexing and querying. Changing it requires rebuilding the `AffectedVersions` index. |
| `Provider` | Holds the `*http.Client` used by `Enumerable` ecosystems. `DefaultProvider` uses `http.DefaultClient`. |
| `ErrCoarseNotSupported`, `ErrPackageNotFound`, `ErrVersionEcosystemMismatch` | Sentinel errors. |

### Registration and lookup

Ecosystems are registered in the `ecosystems` map in [`ecosystem.go`](ecosystem.go), keyed by an `osvconstants.Ecosystem` constant from [osv-schema's Go bindings](https://github.com/ossf/osv-schema/tree/main/bindings/go). Each value is an `ecosystemFactory`, `func(p *Provider, suffix string) Ecosystem`:

- `statelessFactory[T]`: for ecosystems that need no state (for example, `statelessFactory[semverEcosystem]` or `statelessFactory[rpmEcosystem]`).
- `func(p *Provider, _ string) Ecosystem { return fooEcosystem{p: p} }`: for ecosystems that fetch versions over HTTP.
- A named factory that reads the suffix after `:`. For example, `debianFactory` takes the release from `Debian:12`. `echoFactory` and `redHatLightwellFactory` pick a base ecosystem from the suffix (for example, `Echo:PyPI` or `Red Hat Lightwell:Maven`). A factory can return `nil` to reject an unsupported suffix.

`Provider.Get("Name:suffix")` splits on the first `:`, calls the factory, and wraps the result so that the version `"0"` parses as lower than every other version. Individual `Parse` implementations don't need to handle `"0"`. `Get` returns `(nil, false)` if the ecosystem isn't registered or its factory returns `nil`.

Reusable building blocks:

- [`semver.go`](semver.go): `semverEcosystem` (`SEMVER` range type) and `semverLikeEcosystem` (SemVer ordering, `ECOSYSTEM` range type, e.g. VSCode).
- [`util.go`](util.go): `CoarseVersioner` (regex-driven coarse formatting) and `sortVersions`.
- `Provider` helpers in [`provider.go`](provider.go): `fetchJSON`, `fetchJSONPaths` (GJSON paths), and `getVersionsDepsDev`. All of them translate HTTP 404 into `ErrPackageNotFound`.
- Examples: [`dpkg.go`](dpkg.go) (non-SemVer `Parse` + custom `Coarse`), [`debian.go`](debian.go) (`Enumerable` with a release suffix), [`pypi.go`](pypi.go) (`Enumerable` + `PackageNameNormalizer`), [`echo.go`](echo.go) (suffix variants that wrap other ecosystems).

### Coarse versions

`Coarse` returns a lexicographically sortable string `EE:XXXXXXXX.YYYYYYYY.ZZZZZZZZ` (epoch, major, minor, patch). The database uses it for range filters (`coarse_min <= v <= coarse_max`). It must be **monotonically non-decreasing** with respect to `Compare`. `"0"` must map to `00:00000000.00000000.00000000`. Return `ErrCoarseNotSupported` if a safe mapping isn't possible (as `apkEcosystem` does). Entities then get the full min/max range, and matching still works, just without the index optimization.

## Adding a new ecosystem

For a minimal end-to-end example, see commit [`bbcdee51`](https://github.com/google/osv.dev/commit/bbcdee518b1d5e6e599185852b996c066f5665d1) (Red Hat Lightwell: [`red_hat_lightwell.go`](red_hat_lightwell.go), [`ecosystem_red_hat_lightwell.go`](../../purl/ecosystem_red_hat_lightwell.go), and their tests).

1. **Define the ecosystem in osv-schema first.** If the `osvconstants.Ecosystem` constant doesn't exist yet, add it upstream and bump `github.com/ossf/osv-schema/bindings/go` in [`go/go.mod`](../../go.mod). See also [Adding a new source](../../../docs/new_source.md).
2. **Implement the version logic** in `<name>.go`:
   - Reuse an existing type if the versioning matches (e.g. `semverEcosystem`, `rpmEcosystem`, `apkEcosystem`, `dpkgEcosystem`). Many ecosystems are a single map entry.
   - Otherwise implement `Ecosystem`, preferably on top of an osv-scalibr `semantic` parser via `SemanticVersionWrapper`. Add a compile-time assertion such as `var _ Ecosystem = fooEcosystem{}`.
   - Return `true` from `IsSemver()` only if the ecosystem uses the OSV `SEMVER` range type.
   - Implement `GetVersions` (making it `Enumerable`) only if a registry can list versions. Use the `Provider` HTTP helpers so tests can inject a recording client.
   - Implement `PackageNameNormalizer` or `MatchNameNormalizer` only when the registry's naming rules require it (read their doc comments first).
3. **Register it** in the `ecosystems` map in [`ecosystem.go`](ecosystem.go).
4. **Add PURL support** in [`go/purl`](../../purl/):
   - For simple mappings, add a `registerSimple(...)` or `registerSlash(...)` call to `init()` in [`ecosystems_simple.go`](../../purl/ecosystems_simple.go).
   - For anything more complex, add `ecosystem_<name>.go` with its own `init()` that calls `registerGenerator` and/or `registerParser`.
   - `registerParser` panics if a PURL `type[/namespace]` is already claimed. Ecosystems that reuse another ecosystem's PURL type (like Red Hat Lightwell with `pkg:maven`) register only a generator.
5. **Write tests** (see [Testing](#testing)): `Provider.Get` lookups (including bad suffixes), version ordering, `Coarse` output, `GetVersions` with VCR cassettes, and PURL round-trips.
6. **Python parity (usually not needed).** The legacy Python helpers in [`osv/ecosystems/`](../../../osv/ecosystems/) are still used by the OSS-Fuzz worker and `osv/impact.py`. Update them only when that code needs the change. Commit [`351680be`](https://github.com/google/osv.dev/commit/351680bebad000f79867b9daac5bb734dee9840f) (Echo:NuGet) is an example that updated both Go and Python.

## Testing

From the `go/` directory:

```bash
go test ./osv/ecosystem/... ./purl/...
```

- **Network fetches use go-vcr cassettes.** In tests, `getTestProvider(t)` ([`testutils.go`](testutils.go)) builds a `Provider` whose client replays `testdata/<TestName>.yaml` through [`testutils.SetupVCR`](../../testutils/vcr.go). The cassette name comes from `t.Name()`, so call `getTestProvider` in the top-level test, before any `t.Run`. A cassette is recorded only if it's missing. To re-record, delete the YAML file and rerun the test with network access, then commit the new cassette. `checkNextVersion` helps check version ordering. Add a `_NotFound` test that asserts `errors.Is(err, ErrPackageNotFound)`.
- **Coarse monotonicity.** [`coarse_fuzz_test.go`](coarse_fuzz_test.go) has a `Fuzz<Name>Monotonicity` target per coarse implementation, with seed corpora under `testdata/fuzz/`. Add one for a new `Coarse` implementation and run it with, for example, `go test ./osv/ecosystem -run '^$' -fuzz FuzzDpkgMonotonicity -fuzztime 30s`.
- **Large coarse test.** `TestCoarseMonotonicityLarge` in [`coarse_large_test.go`](coarse_large_test.go) is skipped by default. It needs `testdata/all_versions.txt`, which [`testdata/regen_coarse_test_data.sh`](testdata/regen_coarse_test_data.sh) generates from the public `all.zip`:

  ```bash
  ./osv/ecosystem/testdata/regen_coarse_test_data.sh
  RUN_COARSE_LARGE_TEST=1 go test ./osv/ecosystem -run TestCoarseMonotonicityLarge
  ```

  To have this test cover a new ecosystem, add it to `ecosystemsToTest`.

Before sending a PR, run `poetry run tools/lint_and_format.sh` from the repository root.
