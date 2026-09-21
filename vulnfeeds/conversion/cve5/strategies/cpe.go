package strategies

import (
	"errors"
	"strings"

	c "github.com/google/osv.dev/vulnfeeds/conversion"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// AffectedCPEStrategy extracts version ranges from CPE strings specified in affected.Cpes or version strings formatted as CPEs.
//
// Example CVE Record:
//
//	"affected": [
//	    {
//	        "cpes": ["cpe:2.3:a:vendor:product:1.2.3:*:*:*:*:*:*:*"],
//	        "versions": [{ "status": "affected" }]
//	    }
//	]
//
// Resulting OSV Range: [introduced: "1.2.3", last_affected: "1.2.3"]
type AffectedCPEStrategy struct{}

func (s *AffectedCPEStrategy) Name() string {
	return "AffectedCPE"
}

func (s *AffectedCPEStrategy) Extract(vers models.Versions, affected models.Affected, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, VersionRangeType, bool) {
	cpeStr := ""
	if strings.HasPrefix(vers.Version, "cpe:") {
		cpeStr = vers.Version
	} else if len(affected.Cpes) > 0 {
		for _, cpe := range affected.Cpes {
			if strings.HasPrefix(cpe, "cpe:") {
				cpeStr = cpe
				break
			}
		}
	}

	if cpeStr == "" {
		return nil, VersionRangeTypeUnknown, false
	}

	parsedCPE, err := c.ParseCPE(cpeStr)
	if err != nil || parsedCPE.Version == "" || parsedCPE.Version == "*" || parsedCPE.Version == "-" || parsedCPE.Version == "ANY" || parsedCPE.Version == "NA" {
		return nil, VersionRangeTypeUnknown, false
	}

	version := parsedCPE.Version
	if parsedCPE.Update != "" && parsedCPE.Update != "*" && parsedCPE.Update != "-" && parsedCPE.Update != "ANY" && parsedCPE.Update != "NA" {
		version += "." + parsedCPE.Update
	}

	if !vulns.CheckQuality(version).AtLeast(acceptableQuality) {
		return nil, VersionRangeTypeUnknown, false
	}

	metrics.AddNote("Extracted version %s from CPE %s", version, cpeStr)
	currentVersionType := ToVersionRangeType(vers.VersionType)
	vr := []*osvschema.Range{c.BuildVersionRange(version, version, "")}
	rwms := c.ToRangeWithMetadata(vr, models.VersionSourceCPE)
	for i := range rwms {
		rwms[i].Metadata.CPE = cpeStr
		rwms[i].Metadata.Versions = []string{version}
	}

	return rwms, currentVersionType, true
}

// CPEVersionStrategy extracts version ranges from the CVE's CPE applicability statements.
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
	cpeRanges, cpeStrings, err := findCPEVersionRanges(cve)
	if err == nil && len(cpeRanges) > 0 {
		metrics.AddNote("Strategy successful: %s", s.Name())
		metrics.VersionSources = append(metrics.VersionSources, models.VersionSourceCPE)
		metrics.CPEs = vulns.Unique(cpeStrings)

		return cpeRanges, nil
	} else if err != nil {
		metrics.AddNote("%s", err.Error())
	}

	return nil, err
}

// CPEVersionExtraction runs the CPEVersionStrategy on a CVE5 record.
func CPEVersionExtraction(cve models.CVE5, metrics *models.ConversionMetrics) ([]models.RangeWithMetadata, error) {
	return (&CPEVersionStrategy{}).Extract(cve, metrics)
}

// findCPEVersionRanges extracts version ranges and CPE strings from the CNA's
// CPE applicability statements in a CVE record.
func findCPEVersionRanges(cve models.CVE5) (versionRanges []models.RangeWithMetadata, cpes []string, err error) {
	// TODO(jesslowe): Add logic to also extract CPEs from the 'affected' field (e.g., CVE-2025-1110).
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
	if len(versionRanges) == 0 {
		return nil, nil, errors.New("no versions extracted from CPEs")
	}

	return versionRanges, cpes, nil
}
