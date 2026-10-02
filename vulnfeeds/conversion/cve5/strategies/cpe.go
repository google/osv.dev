package strategies

import (
	"errors"
	"strings"

	c "github.com/google/osv.dev/vulnfeeds/conversion"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// extractRangeFromCPEString parses a single CPE string and builds a standalone OSV range if valid.
func extractRangeFromCPEString(cpeStr string, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, bool) {
	if !strings.HasPrefix(cpeStr, "cpe:") {
		return nil, false
	}

	parsedCPE, err := c.ParseCPE(cpeStr)
	if err != nil || parsedCPE.Version == "" || parsedCPE.Version == "*" || parsedCPE.Version == "-" || parsedCPE.Version == "ANY" || parsedCPE.Version == "NA" {
		return nil, false
	}

	version := parsedCPE.Version
	if parsedCPE.Update != "" && parsedCPE.Update != "*" && parsedCPE.Update != "-" && parsedCPE.Update != "ANY" && parsedCPE.Update != "NA" {
		version += "." + parsedCPE.Update
	}

	if !vulns.CheckQuality(version).AtLeast(acceptableQuality) {
		return nil, false
	}

	if metrics != nil {
		metrics.AddNotef("Extracted version %s from CPE %s", version, cpeStr)
	}

	vr := []*osvschema.Range{c.BuildVersionRange(version, version, "")}
	rwms := c.ToRangeWithMetadata(vr, models.VersionSourceCPE)
	for i := range rwms {
		rwms[i].Metadata.CPE = cpeStr
		rwms[i].Metadata.Strategy = "CPEVersionString"
		rwms[i].Metadata.Versions = []string{version}
	}

	return rwms, true
}

// CPEVersionStringStrategy extracts version ranges from version entries where vers.Version is formatted as a CPE string.
// Placed before single-version strategies so CPE strings are consumed without coupling single-version strategies to CPE prefixes.
type CPEVersionStringStrategy struct{}

func (s *CPEVersionStringStrategy) Name() string {
	return "CPEVersionString"
}

func (s *CPEVersionStringStrategy) Extract(state *ExtractionState, metrics *models.ConversionMetrics) {
	ExtractPerVersion(state, metrics, s.extractVersion)
}

func (s *CPEVersionStringStrategy) extractVersion(vers models.Versions, _ models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, bool) {
	return extractRangeFromCPEString(vers.Version, metrics)
}

// CPEVersionStrategy extracts version ranges from the CVE's CPE applicability statements
// as well as any CPE lists attached to affected blocks (affected[].cpes).
//
// Example CVE Record:
//
//	"cpeApplicability": [
//	    {
//	        "nodes": [{
//	            "operator": "OR",
//	            "cpeMatch": [{
//	                "vulnerable": true,
//	                "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
//	                "versionStartIncluding": "1.0.0",
//	                "versionEndExcluding": "2.0.0"
//	            }]
//	        }]
//	    }
//	]
//
// Resulting OSV Range: [introduced: "1.0.0", fixed: "2.0.0"]
type CPEVersionStrategy struct{}

func (s *CPEVersionStrategy) Name() string {
	return "CPEApplicability"
}

func (s *CPEVersionStrategy) Extract(cve models.CVE5, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, error) {
	cpeRanges, cpeStrings, err := findCPEVersionRanges(cve, metrics)
	if err == nil && len(cpeRanges) > 0 {
		for i := range cpeRanges {
			if cpeRanges[i].Metadata.Strategy == "" {
				cpeRanges[i].Metadata.Strategy = s.Name()
			}
		}
		metrics.AddNotef("Strategy successful: %s", s.Name())
		metrics.VersionSources = append(metrics.VersionSources, models.VersionSourceCPE)
		metrics.CPEs = vulns.Unique(cpeStrings)

		return cpeRanges, nil
	} else if err != nil {
		metrics.AddNotef("%s", err.Error())
	}

	return nil, err
}

// CPEVersionExtraction runs the CPEVersionStrategy on a CVE5 record.
func CPEVersionExtraction(cve models.CVE5, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, error) {
	return (&CPEVersionStrategy{}).Extract(cve, metrics)
}

// findCPEVersionRanges extracts version ranges and CPE strings from the CNA's
// CPE applicability statements and affected[].cpes lists in a CVE record.
func findCPEVersionRanges(cve models.CVE5, metrics *models.ConversionMetrics) (versionRanges []models.RangeWithMetadata, cpes []string, err error) {
	for _, cpe := range cve.Containers.CNA.CPEApplicability {
		for _, node := range cpe.Nodes {
			if node.Operator != "OR" {
				continue
			}
			for _, match := range node.CPEMatch {
				if !match.Vulnerable {
					continue
				}
				cpes = append(cpes, match.Criteria)

				// If no start version is given, assume the vulnerability starts from version "0".
				if match.VersionStartIncluding == "" {
					match.VersionStartIncluding = "0"
				}
				var nr []*osvschema.Range
				if match.VersionEndExcluding != "" {
					nr = append(nr, c.BuildVersionRange(match.VersionStartIncluding, "", match.VersionEndExcluding))
				} else if match.VersionEndIncluding != "" {
					nr = append(nr, c.BuildVersionRange(match.VersionStartIncluding, match.VersionEndIncluding, ""))
				}
				if nr != nil {
					versionRanges = append(versionRanges, c.ToRangeWithMetadata(nr, models.VersionSourceCPE)...)
				}
			}
		}
	}

	// Also extract from any CPE strings listed in cve.Containers.CNA.Affected[].Cpes
	for _, affected := range cve.Containers.CNA.Affected {
		for _, cpeStr := range affected.Cpes {
			if rwms, ok := extractRangeFromCPEString(cpeStr, metrics); ok {
				cpes = append(cpes, cpeStr)
				versionRanges = append(versionRanges, rwms...)
			}
		}
	}

	if len(versionRanges) == 0 {
		return nil, nil, errors.New("no versions extracted from CPEs")
	}

	return versionRanges, cpes, nil
}
