package main

import (
	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func handleLinuxCVE(cve cves.CVE5, v *vulns.Vulnerability) (notes []string) {
	pkg := osvschema.Package{
		Ecosystem: string(osvschema.EcosystemLinux),
		Name:      "Kernel",
	}

	cpeRanges, cpeStrings, err := findCPEVersionRanges(cve)
	if err != nil {
		notes = append(notes, err.Error())
	}
	if cpeRanges != nil {
		affected := osvschema.Affected{
			Package: pkg,
		}
		for _, r := range cpeRanges {
			r.Type = osvschema.RangeEcosystem
			affected.Ranges = append(affected.Ranges, r)
		}
		affected.DatabaseSpecific = make(map[string]interface{})
		affected.DatabaseSpecific["CPEs"] = vulns.Unique(cpeStrings)
		v.Affected = append(v.Affected, affected)
	}

	return notes
}
