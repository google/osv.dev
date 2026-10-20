package cve5

import (
	"net/http"
	"slices"

	c "github.com/google/osv.dev/vulnfeeds/conversion"
	"github.com/google/osv.dev/vulnfeeds/conversion/cve5/strategies"
	"github.com/google/osv.dev/vulnfeeds/git"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/purl"
	"github.com/google/osv.dev/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// PackageVersionExtractor adds package-based affected entries for CNAs that identify the
// affected package with a purl in the CVE record.
//
// Git ranges are still produced by the Base extractor. For each affected block with a
// supported packageURL, this additionally emits an affected entry carrying the OSV package
// and ECOSYSTEM ranges taken straight from the record's version fields, so that the record
// can be matched by package name and version.
//
// Base defaults to the DefaultVersionExtractor, and Strategies to strategies.Package().
type PackageVersionExtractor struct {
	Base       VersionExtractor
	Strategies []strategies.VersionStrategy
}

var _ VersionExtractor = &PackageVersionExtractor{}

func (p *PackageVersionExtractor) getBase() VersionExtractor {
	if p.Base != nil {
		return p.Base
	}

	return &DefaultVersionExtractor{}
}

func (p *PackageVersionExtractor) getStrategies() []strategies.VersionStrategy {
	if len(p.Strategies) > 0 {
		return p.Strategies
	}

	return strategies.Package()
}

// ExtractVersions for PackageVersionExtractor.
func (p *PackageVersionExtractor) ExtractVersions(cve models.CVE5, v *vulns.Vulnerability, metrics *models.ConversionMetrics, repos []string, cache git.RepoTagsCache, httpClient *http.Client) {
	p.getBase().ExtractVersions(cve, v, metrics, repos, cache, httpClient)

	p.addPackageAffected(cve.Containers.CNA.Affected, v, metrics)
}

// addPackageAffected appends one affected entry per distinct package found in the affected blocks.
// Blocks that share a package, such as one block per release branch, are combined into one entry.
func (p *PackageVersionExtractor) addPackageAffected(affected []models.Affected, v *vulns.Vulnerability, metrics *models.ConversionMetrics) {
	byPackage := make(map[string]*osvschema.Affected)
	// Keep the order of first appearance so the output is deterministic.
	var order []string

	for _, cveAff := range affected {
		if cveAff.PackageURL == "" {
			continue
		}
		pkg, err := purl.ToOSVPackage(cveAff.PackageURL)
		if err != nil {
			metrics.AddNotef("Skipping package versions for %q: %v", cveAff.PackageURL, err)
			continue
		}
		ranges := p.packageRanges(cveAff, metrics)
		if len(ranges) == 0 {
			continue
		}

		key := pkg.GetEcosystem() + ":" + pkg.GetName()
		aff, ok := byPackage[key]
		if !ok {
			aff = &osvschema.Affected{Package: pkg}
			byPackage[key] = aff
			order = append(order, key)
		}
		aff.Ranges = append(aff.Ranges, ranges...)
	}

	if len(order) > 0 {
		markSuccessful(metrics)
	}

	for _, key := range order {
		aff := byPackage[key]
		// This is deliberately not c.AddAffected, which drops any range already present on
		// another affected entry. Distinct packages commonly share an identical range.
		v.Affected = append(v.Affected, aff)
		metrics.ResolvedRangesCount += len(aff.GetRanges())
		metrics.AddSource(models.VersionSourceAffected)
	}
}

// markSuccessful records that usable ranges exist even if the base extractor could not resolve
// Git ranges, which would otherwise leave an outcome that rejects the record.
func markSuccessful(metrics *models.ConversionMetrics) {
	switch metrics.Outcome {
	case models.ConversionUnknown, models.NoRepos, models.NoCommitRanges, models.NoRanges:
		metrics.Outcome = models.Successful
	default:
	}
}

// packageRanges extracts ECOSYSTEM ranges from an affected block, ignoring any Git versions.
func (p *PackageVersionExtractor) packageRanges(cveAff models.Affected, metrics *models.ConversionMetrics) []*osvschema.Range {
	cveAff.Versions = slices.DeleteFunc(slices.Clone(cveAff.Versions), isGitVersion)

	var ranges []*osvschema.Range
	for _, r := range ExtractAffectedRanges(cveAff, p.getStrategies(), metrics) {
		if r.Range.GetType() == osvschema.Range_GIT || c.IsDirectGitRange(r) {
			continue
		}
		r.Range.Type = osvschema.Range_ECOSYSTEM
		r.Range.Repo = ""
		ranges = append(ranges, r.Range)
	}

	return ranges
}
